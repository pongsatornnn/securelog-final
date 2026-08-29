# Migration ครั้งเดียว: รวม ssh_brute_force_fast + ssh_brute_force_slow เป็น ssh_brute_force

import asyncio

from sqlalchemy import delete, select

from database.connection import AsyncSessionLocal
from database.models import AlertSeverity, DetectionRule
from rule_cache import get_rule, rule_cache_key
from severity_cache import get_severity, severity_cache_key
from redis_client import cache_delete


LOG_PREFIX = "MIGRATE-SSH-RULE"

OLD_RULE_KEYS = ("ssh_brute_force_fast", "ssh_brute_force_slow")
OLD_SEVERITY_KEYS = ("ssh_brute_force:fast", "ssh_brute_force:slow")

NEW_RULE_KEY = "ssh_brute_force"


async def migrate() -> None:
    async with AsyncSessionLocal() as db:
        # เก็บค่าเก่าไว้ print ให้เห็นว่าลบอะไรไป (เผื่อแอดมินเคยปรับ threshold ไว้เอง)
        old_rules = (
            await db.execute(
                select(DetectionRule).where(DetectionRule.rule_key.in_(OLD_RULE_KEYS))
            )
        ).scalars().all()

        for rule in old_rules:
            print(
                f"[{LOG_PREFIX}] ลบ rule เก่า: {rule.rule_key} "
                f"(window={rule.window_seconds}s threshold={rule.threshold} is_active={rule.is_active})"
            )

        await db.execute(
            delete(DetectionRule).where(DetectionRule.rule_key.in_(OLD_RULE_KEYS))
        )

        old_severities = (
            await db.execute(
                select(AlertSeverity).where(AlertSeverity.severity_key.in_(OLD_SEVERITY_KEYS))
            )
        ).scalars().all()

        for row in old_severities:
            print(f"[{LOG_PREFIX}] ลบ severity เก่า: {row.severity_key} = {row.severity}")

        await db.execute(
            delete(AlertSeverity).where(AlertSeverity.severity_key.in_(OLD_SEVERITY_KEYS))
        )

        await db.commit()

    for rule_key in OLD_RULE_KEYS:
        cache_delete(rule_cache_key(rule_key), log_prefix=LOG_PREFIX)

    for severity_key in OLD_SEVERITY_KEYS:
        cache_delete(severity_cache_key(severity_key), log_prefix=LOG_PREFIX)

    # เรียก get_rule/get_severity เพื่อ seed แถวใหม่ลง DB ให้ทันที (ปกติ startup seed ให้อยู่แล้ว
    new_rule = await get_rule(NEW_RULE_KEY)
    new_severity = await get_severity(NEW_RULE_KEY)

    print(
        f"[{LOG_PREFIX}] เสร็จแล้ว: ลบ rule เก่า {len(old_rules)} แถว / severity เก่า "
        f"{len(old_severities)} แถว — ที่ใช้จริงตอนนี้: {NEW_RULE_KEY} "
        f"window={new_rule['window_seconds']}s threshold={new_rule['threshold']} "
        f"severity={new_severity}"
    )


if __name__ == "__main__":
    asyncio.run(migrate())
