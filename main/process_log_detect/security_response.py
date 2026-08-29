"""การตอบสนองอัตโนมัติเมื่อ detector เจอการโจมตี — ใช้ร่วมกันทุก detector (auth/web/firewall)"""

import ipaddress
import time
from datetime import datetime

from database.connection import AsyncSessionLocal
from database.crud import (
    get_whitelist_by_ip,
    get_blacklist_by_ip,
    save_ip_blacklist,
    reactivate_blacklist,
    upgrade_blacklist_severity,
    get_ip_whitelist,
)
from blacklist_ttl_cache import compute_expiry, get_ttl
from alerts import SECURITY_ALERTS_STREAM_CHANNEL
from redis_client import publish_json


GLOBAL_COMMAND_CHANNEL = "global_commands"


# IP ที่ห้าม block เด็ดขาด — ไม่ใช่ address ของเครื่องจริงสักเครื่อง แต่โผล่ในทราฟฟิก
NON_BLOCKABLE_IPS = frozenset({
    "0.0.0.0",
    "255.255.255.255",
})


def is_non_blockable_ip(ip: str | None) -> bool:
    """True ถ้า ip เป็น address พิเศษที่ห้าม block (unspecified/broadcast)"""
    if not ip:
        return False

    try:
        return str(ipaddress.ip_address(str(ip).strip())) in NON_BLOCKABLE_IPS
    except ValueError:
        return False


def _severity_rank(ttl_seconds: int | None) -> float:
    """อันดับความรุนแรงของการ block จาก TTL: None (ถาวร) = รุนแรงสุด (∞),"""
    return float("inf") if ttl_seconds is None else float(ttl_seconds)


def base_command_payload(command: str, ip_address: str, event: str | None, source: str) -> dict:
    """โครง payload มาตรฐานของคำสั่งถึง agent (ip ใส่ซ้ำ 2 key ตามที่ agent เดิมรองรับ)"""
    return {
        "command": command,
        "ip_address": ip_address,
        "ip": ip_address,
        "event": event,
        "source": source,
        "timestamp": time.time(),
        "timestamp_text": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


def publish_alert_event(alert_summary: dict) -> None:
    """ส่ง alert ที่เพิ่งบันทึกลง DB ขึ้น Redis pub/sub เพื่อให้ dashboard (SSE) เห็นแบบ real-time"""
    publish_json(SECURITY_ALERTS_STREAM_CHANNEL, alert_summary, log_prefix="ALERT-STREAM")


def publish_block_ip_command(ip_address: str, event: str) -> dict:
    """Broadcast คำสั่ง block_ip ไปยังทุก Agent"""
    payload = base_command_payload("block_ip", ip_address, event, source="auto_detect")
    result = publish_json(GLOBAL_COMMAND_CHANNEL, payload, log_prefix="AUTO-BLOCK")

    if result["ok"]:
        print(
            f"[AUTO-BLOCK] ส่ง block_ip ไปที่ {GLOBAL_COMMAND_CHANNEL} | "
            f"IP={ip_address} | receivers={result['receiver_count']}"
        )
    return result


def publish_unblock_ip_command(ip_address: str, event: str = "expired") -> dict:
    """Broadcast คำสั่ง unblock_ip ไปทุก Agent (ใช้ตอน blacklist หมดอายุ ให้ agent ลบ ufw rule)"""
    payload = base_command_payload("unblock_ip", ip_address, event, source="auto_expiry")
    result = publish_json(GLOBAL_COMMAND_CHANNEL, payload, log_prefix="AUTO-EXPIRY")

    if result["ok"]:
        print(
            f"[AUTO-EXPIRY] ส่ง unblock_ip ไปที่ {GLOBAL_COMMAND_CHANNEL} | "
            f"IP={ip_address} | receivers={result['receiver_count']}"
        )
    return result


def publish_sync_whitelist_command(ip_addresses: list[str]) -> dict:
    """Broadcast whitelist ปัจจุบันไปทุก Agent ให้ใช้เป็น never-block list"""
    payload = {
        "command": "sync_whitelist",
        "ips": ip_addresses,
        "source": "central",
        "timestamp": time.time(),
        "timestamp_text": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    result = publish_json(GLOBAL_COMMAND_CHANNEL, payload, log_prefix="SYNC-WHITELIST")

    if result["ok"]:
        print(
            f"[SYNC-WHITELIST] broadcast whitelist {len(ip_addresses)} IP ไปที่ "
            f"{GLOBAL_COMMAND_CHANNEL} | receivers={result['receiver_count']}"
        )
    return result


async def broadcast_whitelist_from_db() -> None:
    """โหลด whitelist ล่าสุดจาก DB แล้ว broadcast ให้ทุก Agent (เรียกหลัง admin แก้ whitelist)"""
    try:
        async with AsyncSessionLocal() as db:
            rows = await get_ip_whitelist(db)
            ip_addresses = [row.ip_address for row in rows]

        publish_sync_whitelist_command(ip_addresses)

    except Exception as e:
        print(f"[SYNC-WHITELIST] โหลด/broadcast whitelist จาก DB ไม่สำเร็จ: {e}")


async def handle_attack_ip(source_ip: str | None, detection_type: str) -> str:
    """ตัดสินใจว่า source_ip ที่ detector ตรวจจับได้ควรถูก block หรือไม่"""
    if not source_ip:
        return "no_ip"

    if is_non_blockable_ip(source_ip):
        # ทราฟฟิก broadcast ปกติ ไม่ใช่การโจมตีของ host ใด block ไปก็ไม่มีผล
        print(f"[AUTO-BLOCK] IP {source_ip} เป็น address พิเศษ (broadcast/unspecified) -> ไม่ block (เก็บแค่ alert)")
        return "not_blockable"

    async with AsyncSessionLocal() as db:
        whitelist_ip = await get_whitelist_by_ip(db, source_ip)
        if whitelist_ip:
            print(f"[AUTO-BLOCK] IP {source_ip} อยู่ใน Whitelist -> ไม่ block (เก็บแค่ alert)")
            return "whitelisted"

        blacklist_ip = await get_blacklist_by_ip(db, source_ip)

        if blacklist_ip and blacklist_ip.is_active:
            # block ปัจจุบันเป็นถาวรอยู่แล้ว (expires_at=None) = รุนแรงสุด ไม่มีชนิดไหน upgrade ได้
            if blacklist_ip.expires_at is None:
                print(f"[AUTO-BLOCK] IP {source_ip} อยู่ใน Blacklist ถาวรอยู่แล้ว -> ไม่แตะ")
                return "already_blacklisted"

            # ยัง block อยู่แต่ไม่ถาวร -> เทียบความรุนแรง (base TTL) ของชนิดใหม่กับของเดิม
            current_ttl = (await get_ttl(blacklist_ip.event)).get("ttl_seconds")
            new_ttl = (await get_ttl(detection_type)).get("ttl_seconds")

            if _severity_rank(new_ttl) > _severity_rank(current_ttl):
                old_event = blacklist_ip.event
                new_expiry = await compute_expiry(detection_type, blacklist_ip.block_count)
                await upgrade_blacklist_severity(
                    db, blacklist_ip, event=detection_type, expires_at=new_expiry,
                    actor=f"detector:{detection_type}",
                )
                exp_text = "ถาวร" if new_expiry is None else new_expiry.strftime("%Y-%m-%d %H:%M:%S")
                print(
                    f"[AUTO-BLOCK] IP {source_ip} โดนชนิดรุนแรงกว่า ({old_event} -> {detection_type}) "
                    f"-> upgrade block (หมดอายุ: {exp_text}) ไม่ต้อง block ซ้ำที่ agent"
                )
                return "already_blacklisted"

            print(
                f"[AUTO-BLOCK] IP {source_ip} อยู่ใน Blacklist (active) อยู่แล้ว "
                f"({detection_type} ไม่รุนแรงกว่า {blacklist_ip.event}) -> ไม่แตะ"
            )
            return "already_blacklisted"

        if blacklist_ip and not blacklist_ip.is_active:
            # เคยโดน block แต่หมดอายุไปแล้ว กลับมาโจมตีอีก -> re-block + escalate
            new_count = blacklist_ip.block_count + 1
            expires_at = await compute_expiry(detection_type, new_count)
            await reactivate_blacklist(
                db,
                blacklist_ip,
                event=detection_type,
                expires_at=expires_at,
                block_count=new_count,
                actor=f"detector:{detection_type}",
            )
            publish_block_ip_command(source_ip, detection_type)
            expiry_text = "ถาวร" if expires_at is None else expires_at.strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"[AUTO-BLOCK] IP {source_ip} หมดอายุแล้วโจมตีซ้ำ -> re-block "
                f"(ครั้งที่ {new_count}, หมดอายุ: {expiry_text}) เหตุ: {detection_type}"
            )
            return "blocked"

        # ไม่เคยมีใน blacklist -> block ใหม่ครั้งแรก
        expires_at = await compute_expiry(detection_type, 1)
        await save_ip_blacklist(
            db,
            {
                "source_ip": source_ip,
                "attack_type": detection_type,
                "expires_at": expires_at,
                "block_count": 1,
                # ไม่มีคนกด — บอกให้ชัดว่ามาจาก detector ตัวไหน จะได้ไม่ปนกับที่แอดมินเพิ่มเอง
                "created_by": f"detector:{detection_type}",
            },
        )

    publish_block_ip_command(source_ip, detection_type)

    expiry_text = "ถาวร" if expires_at is None else expires_at.strftime("%Y-%m-%d %H:%M:%S")
    print(
        f"[AUTO-BLOCK] เพิ่ม IP {source_ip} เข้า Blacklist และสั่ง block แล้ว "
        f"(หมดอายุ: {expiry_text}, เหตุ: {detection_type})"
    )
    return "blocked"
