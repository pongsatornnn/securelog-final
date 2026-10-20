

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


ESCALATION_MULTIPLIER_KEY = "escalation_multiplier"
ESCALATION_MAX_BLOCK_COUNT_KEY = "escalation_max_block_count"


TTL_CACHE_TTL_SECONDS = 300
CACHE_KEY_PREFIX = "blacklist_ttl:"

LOG_PREFIX = "TTL-CACHE"


def ttl_cache_key(detection_type: str) -> str:
    return f"{CACHE_KEY_PREFIX}{detection_type}"


async def load_ttl_from_db(detection_type: str) -> dict:

    async with AsyncSessionLocal() as db:
        row = await get_blacklist_ttl(db, detection_type)

        if not row:

            snap = snapshot_ttl(detection_type)

            if snap is not None:
                default_ttl = snap.get("ttl_seconds")
                description = snap.get("description")
                default_auto_block = snap.get("auto_block", True)
                default_notify_line = snap.get("notify_line", True)
            else:
                default_ttl = base_ttl_for(detection_type)
                description = None
                default_auto_block = True
                default_notify_line = True
                if detection_type in BASE_TTL_SECONDS and BASE_TTL_SECONDS[detection_type] is None:
                    description = "ถาวร (default)"
            row = await upsert_blacklist_ttl(
                db,
                detection_type,
                ttl_seconds=default_ttl,
                description=description,
                auto_block=default_auto_block,
                notify_line=default_notify_line,
            )
            print(f"[{LOG_PREFIX}] seed default TTL ลง DB: {detection_type} = {default_ttl}")

        data = {
            "detection_type": row.detection_type,
            "ttl_seconds": row.ttl_seconds,
            "auto_block": bool(row.auto_block),
            "notify_line": bool(row.notify_line),
        }

    cache_set_json(ttl_cache_key(detection_type), data, TTL_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)
    return data


async def get_ttl(detection_type: str) -> dict:

    cached = cache_get_json(ttl_cache_key(detection_type), log_prefix=LOG_PREFIX)


    if cached is not None and "auto_block" in cached and "notify_line" in cached:
        return cached

    return await load_ttl_from_db(detection_type)


async def should_auto_block(detection_type: str | None) -> bool:


    if not detection_type or detection_type == MANUAL_EVENT:
        return True

    data = await get_ttl(detection_type)
    return bool(data.get("auto_block", True))


async def should_notify_line(detection_type: str | None) -> bool:


    if not detection_type or detection_type == MANUAL_EVENT:
        return True

    data = await get_ttl(detection_type)

    if bool(data.get("auto_block", True)):
        return True

    return bool(data.get("notify_line", True))


async def update_ttl(
    detection_type: str,
    ttl_seconds: int | None,
    auto_block: bool | None = None,
    notify_line: bool | None = None,
) -> dict:

    async with AsyncSessionLocal() as db:
        row = await upsert_blacklist_ttl(
            db,
            detection_type,
            ttl_seconds=ttl_seconds,
            auto_block=auto_block,
            notify_line=notify_line,
        )
        result = {
            "detection_type": row.detection_type,
            "ttl_seconds": row.ttl_seconds,
            "auto_block": bool(row.auto_block),
            "notify_line": bool(row.notify_line),
        }

    cache_delete(ttl_cache_key(detection_type), log_prefix=LOG_PREFIX)
    label = "ถาวร" if ttl_seconds is None else f"{ttl_seconds}s"
    mode = "block อัตโนมัติ" if result["auto_block"] else "แจ้งเตือนอย่างเดียว (ไม่ block)"
    line_mode = (
        "ส่ง LINE" if result["auto_block"] or result["notify_line"]
        else "ไม่ส่ง LINE"
    )
    print(
        f"[{LOG_PREFIX}] อัปเดต {detection_type}: TTL={label} · ตอบสนอง={mode} · "
        f"{line_mode} (เคลียร์ cache แล้ว)"
    )
    return result


async def get_escalation_policy() -> dict:

    return {
        "multiplier": await get_int_setting_async(ESCALATION_MULTIPLIER_KEY, minimum=1),
        "max_block_count": await get_int_setting_async(ESCALATION_MAX_BLOCK_COUNT_KEY, minimum=1),
    }


async def compute_expiry(detection_type: str | None, block_count: int) -> datetime | None:

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
