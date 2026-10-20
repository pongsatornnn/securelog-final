

import ipaddress
import time
from datetime import datetime

from database.connection import AsyncSessionLocal
from database.crud import (
    find_whitelist_covering,
    get_blacklist_by_ip,
    save_ip_blacklist,
    reactivate_blacklist,
    upgrade_blacklist_severity,
    get_ip_whitelist,
)
from blacklist_ttl_cache import compute_expiry, get_ttl, should_auto_block
from ip_match import parse_entry
from alerts import SECURITY_ALERTS_STREAM_CHANNEL
from redis_client import publish_json
from central_ips import is_central_ip


GLOBAL_COMMAND_CHANNEL = "global_commands"


NON_BLOCKABLE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("0.0.0.0/32", "255.255.255.255/32", "127.0.0.0/8", "::1/128")
)


def overlapping_non_blockable(value):


    net = parse_entry(value)

    if net is None:
        return []

    return [
        other for other in NON_BLOCKABLE_NETWORKS
        if net.version == other.version and net.overlaps(other)
    ]


def is_non_blockable_ip(value) -> bool:

    return bool(overlapping_non_blockable(value))


def non_blockable_reason(value) -> str:

    hits = overlapping_non_blockable(value)

    if not hits:
        return "ไม่ใช่ IP ที่บล็อกได้"

    net = parse_entry(value)
    is_range = net is not None and net.num_addresses > 1

    if any(other.is_loopback for other in hits):
        return "ครอบ loopback ของเครื่องเอง" if is_range else "เป็น loopback"

    if is_range:
        return "ครอบ address พิเศษของทราฟฟิก broadcast ซึ่งไม่ใช่เครื่องจริง"

    return "เป็น address พิเศษของทราฟฟิก broadcast ไม่ใช่เครื่องจริง"


def _severity_rank(ttl_seconds: int | None) -> float:

    return float("inf") if ttl_seconds is None else float(ttl_seconds)


def base_command_payload(command: str, ip_address: str, event: str | None, source: str) -> dict:

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

    publish_json(SECURITY_ALERTS_STREAM_CHANNEL, alert_summary, log_prefix="ALERT-STREAM")


def publish_block_ip_command(ip_address: str, event: str) -> dict:

    payload = base_command_payload("block_ip", ip_address, event, source="auto_detect")
    result = publish_json(GLOBAL_COMMAND_CHANNEL, payload, log_prefix="AUTO-BLOCK")

    if result["ok"]:
        print(
            f"[AUTO-BLOCK] ส่ง block_ip ไปที่ {GLOBAL_COMMAND_CHANNEL} | "
            f"IP={ip_address} | receivers={result['receiver_count']}"
        )
    return result


def publish_unblock_ip_command(ip_address: str, event: str = "expired") -> dict:

    payload = base_command_payload("unblock_ip", ip_address, event, source="auto_expiry")
    result = publish_json(GLOBAL_COMMAND_CHANNEL, payload, log_prefix="AUTO-EXPIRY")

    if result["ok"]:
        print(
            f"[AUTO-EXPIRY] ส่ง unblock_ip ไปที่ {GLOBAL_COMMAND_CHANNEL} | "
            f"IP={ip_address} | receivers={result['receiver_count']}"
        )
    return result


def publish_sync_whitelist_command(ip_addresses: list[str]) -> dict:

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

    try:
        async with AsyncSessionLocal() as db:
            rows = await get_ip_whitelist(db)
            ip_addresses = [row.ip_address for row in rows]

        publish_sync_whitelist_command(ip_addresses)

    except Exception as e:
        print(f"[SYNC-WHITELIST] โหลด/broadcast whitelist จาก DB ไม่สำเร็จ: {e}")


async def handle_attack_ip(source_ip: str | None, detection_type: str) -> str:

    if not source_ip:
        return "no_ip"

    if is_non_blockable_ip(source_ip):

        print(f"[AUTO-BLOCK] IP {source_ip} {non_blockable_reason(source_ip)} -> ไม่ block (เก็บแค่ alert)")
        return "not_blockable"

    if is_central_ip(source_ip):


        print(f"[AUTO-BLOCK] IP {source_ip} เป็นของ Central Server -> ไม่ block (เก็บแค่ alert)")
        return "not_blockable"


    if not await should_auto_block(detection_type):
        print(
            f"[AUTO-BLOCK] {detection_type} ตั้งไว้เป็นแจ้งเตือนอย่างเดียว "
            f"-> ไม่ block IP {source_ip} (เก็บแค่ alert)"
        )
        return "alert_only"

    async with AsyncSessionLocal() as db:
        whitelist_ip = await find_whitelist_covering(db, source_ip)
        if whitelist_ip:

            via = "" if whitelist_ip.ip_address == source_ip else f" (อยู่ในวง {whitelist_ip.ip_address})"
            print(f"[AUTO-BLOCK] IP {source_ip} อยู่ใน Whitelist{via} -> ไม่ block (เก็บแค่ alert)")
            return "whitelisted"

        blacklist_ip = await get_blacklist_by_ip(db, source_ip)

        if blacklist_ip and blacklist_ip.is_active:

            if blacklist_ip.expires_at is None:
                print(f"[AUTO-BLOCK] IP {source_ip} อยู่ใน Blacklist ถาวรอยู่แล้ว -> ไม่แตะ")
                return "already_blacklisted"


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


        expires_at = await compute_expiry(detection_type, 1)
        await save_ip_blacklist(
            db,
            {
                "source_ip": source_ip,
                "attack_type": detection_type,
                "expires_at": expires_at,
                "block_count": 1,

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
