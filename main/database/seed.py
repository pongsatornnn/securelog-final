"""Seed ค่าเริ่มต้นลง DB ตอน start (เรียกจาก `main.py` lifespan ครั้งเดียวต่อการ start)"""

from database.connection import AsyncSessionLocal
from database.crud import (
    get_detection_rule,
    upsert_detection_rule,
    get_blacklist_ttl,
    upsert_blacklist_ttl,
    get_alert_severity,
    upsert_alert_severity,
    get_detection_signatures,
    create_detection_signature,
    get_all_users,
    create_user,
)
from database.defaults import (
    snapshot_section,
    snapshot_rule,
    snapshot_severity,
    snapshot_ttl,
    snapshot_signatures,
    snapshot_info,
)

from rule_cache import DEFAULT_RULES
from severity_cache import DEFAULT_SEVERITY
from signature_cache import DEFAULT_SIGNATURES, CATEGORY_BY_TYPE
from blacklist_policy import BASE_TTL_SECONDS


LOG_PREFIX = "SEED"


def _merged_keys(section: str, code_defaults) -> list[str]:
    """key ทั้งหมดที่ต้อง seed = ของใน snapshot (มาก่อน คงลำดับตามไฟล์) + ของในโค้ดที่ snapshot ไม่มี"""
    keys = list(snapshot_section(section).keys())
    keys += [k for k in code_defaults if k not in keys]
    return keys


async def seed_detection_rules(db) -> int:
    """threshold/window ของ detector แต่ละตัว — เดิมถูก seed แบบ lazy ตอน detector เจอ log ตัวแรก"""
    created = 0

    for rule_key in _merged_keys("detection_rules", DEFAULT_RULES):
        if await get_detection_rule(db, rule_key):
            continue

        snap = snapshot_rule(rule_key) or {}
        code = DEFAULT_RULES.get(rule_key, {})

        window_seconds = snap.get("window_seconds", code.get("window_seconds"))
        threshold = snap.get("threshold", code.get("threshold"))

        if window_seconds is None or threshold is None:
            print(f"[{LOG_PREFIX}] ข้าม rule {rule_key}: ไม่มีค่า window/threshold ทั้งใน snapshot และในโค้ด")
            continue

        await upsert_detection_rule(
            db,
            rule_key,
            category=snap.get("category") or code.get("category") or "auth",
            window_seconds=window_seconds,
            threshold=threshold,
            description=snap.get("description", code.get("description")),
            is_active=snap.get("is_active", True),
        )
        created += 1

    return created


async def seed_blacklist_ttl(db) -> int:
    """ระยะเวลา block ต่อ detection_type (ttl_seconds = None คือถาวร)"""
    created = 0

    for detection_type in _merged_keys("blacklist_ttl", BASE_TTL_SECONDS):
        if await get_blacklist_ttl(db, detection_type):
            continue

        snap = snapshot_ttl(detection_type)

        if snap is not None:
            ttl_seconds = snap.get("ttl_seconds")
            description = snap.get("description")
        else:
            ttl_seconds = BASE_TTL_SECONDS.get(detection_type)
            # ป้ายกำกับเดิมจาก blacklist_ttl_cache.load_ttl_from_db — คงข้อความให้เหมือนกัน
            description = "ถาวร (default)" if ttl_seconds is None else None

        await upsert_blacklist_ttl(
            db,
            detection_type,
            ttl_seconds=ttl_seconds,
            description=description,
        )
        created += 1

    return created


async def seed_alert_severity(db) -> int:
    """ระดับความรุนแรงของ alert ต่อ severity_key"""
    created = 0

    for severity_key in _merged_keys("alert_severity", DEFAULT_SEVERITY):
        if await get_alert_severity(db, severity_key):
            continue

        snap = snapshot_severity(severity_key) or {}
        code = DEFAULT_SEVERITY.get(severity_key, {})

        severity = snap.get("severity") or code.get("severity")

        if not severity:
            print(f"[{LOG_PREFIX}] ข้าม severity {severity_key}: ไม่มีค่าทั้งใน snapshot และในโค้ด")
            continue

        await upsert_alert_severity(
            db,
            severity_key,
            severity=severity,
            description=snap.get("description", code.get("description")),
        )
        created += 1

    return created


async def seed_detection_signatures(db) -> int:
    """regex ของ signature-based detector — seed "ทั้งชนิด" เฉพาะชนิดที่ยังไม่มีสักแถวเลย"""
    created = 0

    for detection_type in _merged_keys("detection_signatures", DEFAULT_SIGNATURES):
        existing = await get_detection_signatures(db, detection_type=detection_type)

        if existing:
            continue

        snap = snapshot_signatures(detection_type)

        if snap is not None:
            rows = snap
        else:
            rows = [
                {"pattern": pattern, "category": CATEGORY_BY_TYPE.get(detection_type, "web")}
                for pattern in DEFAULT_SIGNATURES.get(detection_type, [])
            ]

        added = 0

        for row in rows:
            pattern = row.get("pattern")

            if not pattern:
                continue

            await create_detection_signature(
                db,
                detection_type=detection_type,
                pattern=pattern,
                category=row.get("category") or CATEGORY_BY_TYPE.get(detection_type, "web"),
                description=row.get("description"),
                is_active=row.get("is_active", True),
            )
            added += 1

        if added:
            print(f"[{LOG_PREFIX}] seed signature ชนิด {detection_type} จำนวน {added} รายการ")
            created += added

    return created


async def seed_admin_user(db) -> bool:
    """สร้าง admin/admin ตอน users ว่างเปล่าเท่านั้น (เครื่อง deploy ใหม่ที่ยังไม่เคยมี user เลย)"""
    # import ตรงนี้เพื่อไม่ให้ database/ ผูกกับ auth ตอน import module (auth ใช้แค่ตอน seed จริง)
    from auth import hash_password

    if await get_all_users(db):
        return False

    await create_user(
        db, "admin", hash_password("admin"),
        role="admin", must_change_password=True,
    )
    print(f"[{LOG_PREFIX}] ไม่มี user ในระบบเลย — สร้างบัญชีเริ่มต้น admin/admin ให้แล้ว (ต้องเปลี่ยนรหัสตอน login ครั้งแรก)")
    return True


async def seed_defaults() -> None:
    """เรียกจาก lifespan ตอน start — เงียบถ้าไม่มีอะไรต้องเติม"""
    async with AsyncSessionLocal() as db:
        rules = await seed_detection_rules(db)
        ttls = await seed_blacklist_ttl(db)
        severities = await seed_alert_severity(db)
        signatures = await seed_detection_signatures(db)
        admin_created = await seed_admin_user(db)

    total = rules + ttls + severities + signatures

    if total or admin_created:
        print(
            f"[{LOG_PREFIX}] เติมค่าเริ่มต้นลง DB ({snapshot_info()}): "
            f"rule={rules} ttl={ttls} severity={severities} signature={signatures} "
            f"admin={'สร้างใหม่' if admin_created else 'มีอยู่แล้ว'}"
        )
