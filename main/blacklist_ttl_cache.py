"""Cache + DB layer สำหรับ TTL ของ blacklist (ระยะเวลา block ก่อนหมดอายุ ต่อ detection_type)"""

from datetime import datetime, timedelta

from database.connection import AsyncSessionLocal
from database.crud import get_blacklist_ttl, upsert_blacklist_ttl
from database.defaults import snapshot_ttl
from redis_client import cache_get_json, cache_set_json, cache_delete
from settings_cache import get_int_setting_async
from blacklist_policy import (
    BASE_TTL_SECONDS,
    MANUAL_EVENT,
    base_ttl_for,
    escalated_ttl_seconds,
)

# คีย์ของนโยบาย escalation ใน app_settings (แอดมินปรับได้ที่หน้า Rules)
ESCALATION_MULTIPLIER_KEY = "escalation_multiplier"
ESCALATION_MAX_BLOCK_COUNT_KEY = "escalation_max_block_count"


TTL_CACHE_TTL_SECONDS = 300
CACHE_KEY_PREFIX = "blacklist_ttl:"

LOG_PREFIX = "TTL-CACHE"


def ttl_cache_key(detection_type: str) -> str:
    return f"{CACHE_KEY_PREFIX}{detection_type}"


async def load_ttl_from_db(detection_type: str) -> dict:
    """อ่าน TTL จาก DB; ถ้ายังไม่มีแถวนี้ seed ค่า default (จาก blacklist_policy) ลง DB ก่อน"""
    async with AsyncSessionLocal() as db:
        row = await get_blacklist_ttl(db, detection_type)

        if not row:
            # snapshot (database/seed_data.json) มาก่อน — ต้องได้ค่าเดียวกับตอน startup seed
            snap = snapshot_ttl(detection_type)

            if snap is not None:
                default_ttl = snap.get("ttl_seconds")
                description = snap.get("description")
            else:
                default_ttl = base_ttl_for(detection_type)
                description = None
                if detection_type in BASE_TTL_SECONDS and BASE_TTL_SECONDS[detection_type] is None:
                    description = "ถาวร (default)"
            row = await upsert_blacklist_ttl(
                db,
                detection_type,
                ttl_seconds=default_ttl,
                description=description,
            )
            print(f"[{LOG_PREFIX}] seed default TTL ลง DB: {detection_type} = {default_ttl}")

        data = {
            "detection_type": row.detection_type,
            "ttl_seconds": row.ttl_seconds,
        }

    cache_set_json(ttl_cache_key(detection_type), data, TTL_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)
    return data


async def get_ttl(detection_type: str) -> dict:
    """Entry point: คืน {'detection_type', 'ttl_seconds'} (ttl_seconds=None -> ถาวร)"""
    cached = cache_get_json(ttl_cache_key(detection_type), log_prefix=LOG_PREFIX)
    if cached is not None:
        return cached
    return await load_ttl_from_db(detection_type)


async def update_ttl(detection_type: str, ttl_seconds: int | None) -> dict:
    """แก้ TTL (จาก CLI/API): เขียน DB แล้วเคลียร์ cache ทันที (มีผลรอบถัดไปเลย)"""
    async with AsyncSessionLocal() as db:
        row = await upsert_blacklist_ttl(db, detection_type, ttl_seconds=ttl_seconds)
        result = {
            "detection_type": row.detection_type,
            "ttl_seconds": row.ttl_seconds,
        }

    cache_delete(ttl_cache_key(detection_type), log_prefix=LOG_PREFIX)
    label = "ถาวร" if ttl_seconds is None else f"{ttl_seconds}s"
    print(f"[{LOG_PREFIX}] อัปเดต TTL {detection_type} = {label} (เคลียร์ cache แล้ว)")
    return result


async def get_escalation_policy() -> dict:
    """นโยบาย escalation ที่ใช้จริงตอนรัน — อ่านจาก app_settings (cache-first เหมือนค่าอื่น)"""
    return {
        "multiplier": await get_int_setting_async(ESCALATION_MULTIPLIER_KEY, minimum=1),
        "max_block_count": await get_int_setting_async(ESCALATION_MAX_BLOCK_COUNT_KEY, minimum=1),
    }


async def compute_expiry(detection_type: str | None, block_count: int) -> datetime | None:
    """คำนวณ expires_at จาก detection_type + block_count โดยดึง base TTL จาก DB/cache"""
    if not detection_type or detection_type == MANUAL_EVENT:
        return None

    data = await get_ttl(detection_type)
    base = data.get("ttl_seconds")

    policy = await get_escalation_policy()

    ttl = escalated_ttl_seconds(
        base,
        block_count,
        multiplier=policy["multiplier"],
        max_block_count=policy["max_block_count"],
    )
    if ttl is None:
        return None

    return datetime.now() + timedelta(seconds=ttl)
