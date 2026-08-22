"""
Agent auth cache — verify token ของ agent โดยเช็ค Redis cache ก่อน (TTL 60s)
miss แล้วค่อยโหลด hash จาก DB, เทียบ token ด้วย hmac.compare_digest,
อัปเดต last_seen ลง DB ไม่ถี่กว่าทุก 30s

นอกจาก token แล้วยังตรวจ "IP ที่ agent รายงานมา" ให้ตรงกับที่ผูกไว้ใน agents.ip_address ด้วย
(ดู verify_agent_ip) — agent ที่ยังไม่เคยผูกจะถูกผูกอัตโนมัติจากรอบแรกที่ auth ผ่าน
"""

import time
import hmac
from datetime import datetime
from zoneinfo import ZoneInfo

from database.connection import AsyncSessionLocal
from database.crud import (
    get_agent_by_agent_id,
    bind_agent_ip,
    record_agent_ip_mismatch,
)
from manage_agent.token_utils import hash_token
from redis_client import cache_get_json, cache_set_json, cache_delete


TZ = ZoneInfo("Asia/Bangkok")

AUTH_CACHE_TTL_SECONDS = 60
DB_LAST_SEEN_UPDATE_SECONDS = 30

# ถี่สุดที่ยอมให้เขียน pending_ip ลง DB ต่อ agent หนึ่งตัว — log ที่ถูกปฏิเสธมาเป็นชุด
# (filebeat ส่งทีละหลายร้อยบรรทัด) ถ้าเขียนทุกบรรทัดจะกลายเป็นการถล่ม DB ด้วยค่าเดิมซ้ำ ๆ
IP_MISMATCH_RECORD_SECONDS = 60

CACHE_KEY_PREFIX = "agent_auth:"

LOG_PREFIX = "CACHE"


def now_thai_naive() -> datetime:
    return datetime.now(TZ).replace(tzinfo=None)


def agent_auth_cache_key(agent_id: str) -> str:
    return f"{CACHE_KEY_PREFIX}{agent_id}"


def clear_agent_auth_cache(agent_id: str) -> None:
    cache_delete(agent_auth_cache_key(agent_id), log_prefix=LOG_PREFIX)


async def load_agent_auth_from_db(agent_id: str) -> dict | None:
    async with AsyncSessionLocal() as db:
        agent = await get_agent_by_agent_id(db, agent_id)

        if not agent:
            print(f"[AUTH] ไม่พบ Agent ใน DB: {agent_id}")
            clear_agent_auth_cache(agent_id)
            return None

        cache_data = {
            "agent_id": agent.agent_id,
            "secret_token_hash": agent.secret_token_hash,
            "is_active": bool(agent.is_active),
            # None = ยังไม่เคยผูก IP (จะผูกให้รอบแรกที่ auth ผ่าน)
            "ip_address": agent.ip_address or None,
            "last_db_update": 0,
            "last_ip_mismatch_record": 0,
        }

        cache_set_json(
            agent_auth_cache_key(agent_id),
            cache_data,
            AUTH_CACHE_TTL_SECONDS,
            log_prefix=LOG_PREFIX,
        )
        return cache_data


async def update_agent_last_seen(agent_id: str) -> bool:
    async with AsyncSessionLocal() as db:
        agent = await get_agent_by_agent_id(db, agent_id)

        if not agent:
            print(f"[AUTH] ไม่พบ Agent ตอน update last_seen: {agent_id}")
            clear_agent_auth_cache(agent_id)
            return False

        if not agent.is_active:
            print(f"[AUTH] Agent ถูกปิดใช้งานแล้ว: {agent_id}")
            clear_agent_auth_cache(agent_id)
            return False

        agent.status = "online"
        agent.last_seen = now_thai_naive()
        agent.updated_at = now_thai_naive()

        await db.commit()
        return True


async def verify_agent_ip(
    agent_id: str,
    cache_data: dict,
    reported_ip: str | None,
    ip_interface: str | None = None,
) -> bool:
    """
    ตรวจว่า IP ที่ agent รายงานมาตรงกับที่ผูกไว้กับ agent_id นี้หรือไม่

    3 กรณี:
      1. ยังไม่เคยผูก (ip_address ว่าง) -> ผูกด้วย IP ที่รายงานมาเลย (trust-on-first-use)
      2. ตรงกับที่ผูกไว้ -> ผ่าน
      3. ไม่ตรง -> ปฏิเสธ + บันทึก pending_ip ให้แอดมินเห็นในหน้า Agents

    reported_ip ว่าง (agent เวอร์ชันเก่าที่ยังไม่ส่ง IP มา / log ที่ไม่มี host.ip) -> ผ่าน
    ไม่งั้นการอัปเดต central ก่อน agent จะตัดทุก agent ที่ยังไม่ได้อัปเดตทิ้งทันที

    ⚠️ IP นี้เป็นค่าที่ agent ประกาศเอง ไม่ใช่ค่าที่ network layer ยืนยัน — คนที่ถือ
    secret_token + cert แล้วตั้งใจแก้โค้ด agent ยังปลอมได้ ตัวยืนยันตัวตนจริงยังเป็น
    secret_token + mTLS เหมือนเดิม ชั้นนี้กันเคส "ยกไฟล์ทั้งชุดไปรันอีกเครื่อง" ซึ่งจะรายงาน
    IP ของเครื่องใหม่ออกมาเอง (agent_core อ่านจาก interface ตอนรัน ไม่ได้อ่านจากไฟล์ที่ยกไป)
    """
    if not reported_ip:
        return True

    pinned_ip = cache_data.get("ip_address")

    if not pinned_ip:
        async with AsyncSessionLocal() as db:
            bound = await bind_agent_ip(db, agent_id, reported_ip, ip_interface)

        if not bound:
            clear_agent_auth_cache(agent_id)
            return False

        cache_data["ip_address"] = reported_ip
        cache_set_json(
            agent_auth_cache_key(agent_id),
            cache_data,
            AUTH_CACHE_TTL_SECONDS,
            log_prefix=LOG_PREFIX,
        )

        print(f"[AUTH] ผูก IP ให้ {agent_id} ครั้งแรก: {reported_ip} ({ip_interface or 'ไม่ระบุ interface'})")
        return True

    if pinned_ip == reported_ip:
        return True

    print(
        f"[AUTH] ปฏิเสธ {agent_id}: IP ไม่ตรงกับที่ผูกไว้ "
        f"(ผูกไว้ {pinned_ip} แต่รายงานมา {reported_ip})"
    )

    now_ts = time.time()
    last_record = cache_data.get("last_ip_mismatch_record", 0)

    if now_ts - last_record >= IP_MISMATCH_RECORD_SECONDS:
        async with AsyncSessionLocal() as db:
            await record_agent_ip_mismatch(db, agent_id, reported_ip)

        cache_data["last_ip_mismatch_record"] = now_ts
        cache_set_json(
            agent_auth_cache_key(agent_id),
            cache_data,
            AUTH_CACHE_TTL_SECONDS,
            log_prefix=LOG_PREFIX,
        )

    return False


async def verify_agent_token(
    agent_id: str,
    secret_token: str | None,
    reported_ip: str | None = None,
    ip_interface: str | None = None,
) -> bool:
    if not agent_id or not secret_token:
        print("[AUTH] ไม่มี agent_id หรือ secret_token")
        return False

    cache_data = cache_get_json(agent_auth_cache_key(agent_id), log_prefix=LOG_PREFIX)

    if not cache_data:
        cache_data = await load_agent_auth_from_db(agent_id)

        if not cache_data:
            return False

    if not cache_data.get("is_active"):
        print(f"[AUTH] Agent ถูกปิดใช้งาน: {agent_id}")
        clear_agent_auth_cache(agent_id)
        return False

    incoming_hash = hash_token(secret_token)
    stored_hash = cache_data.get("secret_token_hash") or ""

    if not hmac.compare_digest(incoming_hash, stored_hash):
        print(f"[AUTH] Token ไม่ตรง: {agent_id}")
        clear_agent_auth_cache(agent_id)
        return False

    # ตรวจ IP หลังผ่าน token แล้วเท่านั้น — ถ้าตรวจก่อน คนที่ยังไม่มี token ที่ถูกต้องจะใช้
    # ข้อความ error ต่างกันไล่เดาได้ว่า agent_id ไหนมีอยู่จริงและผูกกับ IP อะไร
    if not await verify_agent_ip(agent_id, cache_data, reported_ip, ip_interface):
        return False

    now_ts = time.time()
    last_db_update = cache_data.get("last_db_update", 0)

    if now_ts - last_db_update >= DB_LAST_SEEN_UPDATE_SECONDS:
        updated = await update_agent_last_seen(agent_id)

        if not updated:
            return False

        cache_data["last_db_update"] = now_ts
        cache_set_json(
            agent_auth_cache_key(agent_id),
            cache_data,
            AUTH_CACHE_TTL_SECONDS,
            log_prefix=LOG_PREFIX,
        )

    return True
