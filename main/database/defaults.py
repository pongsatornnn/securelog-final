# ค่าเริ่มต้นที่ "ใช้จริง" ตอน seed DB — snapshot จาก `database/seed_data.json` มาก่อน

import json
from pathlib import Path


SEED_DATA_PATH = Path(__file__).resolve().parent / "seed_data.json"

LOG_PREFIX = "SEED-DATA"


def _load_snapshot() -> dict:
    # อ่าน snapshot จากไฟล์ (ครั้งเดียวตอน import) — ไม่มีไฟล์ = ไม่ใช่ error
    if not SEED_DATA_PATH.exists():
        return {}

    try:
        with SEED_DATA_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:
        # ไฟล์พังไม่ควรทำให้ระบบ start ไม่ขึ้น — เตือนแล้วถอยไปใช้ค่าในโค้ด
        print(f"[{LOG_PREFIX}] อ่าน {SEED_DATA_PATH.name} ไม่ได้ ({exc}) — ใช้ค่า default ในโค้ดแทน")
        return {}

    if not isinstance(data, dict):
        print(f"[{LOG_PREFIX}] {SEED_DATA_PATH.name} ไม่ใช่ JSON object — ใช้ค่า default ในโค้ดแทน")
        return {}

    return data


SNAPSHOT = _load_snapshot()


def snapshot_section(section: str) -> dict:
    # คืนทั้ง section ของ snapshot (dict ว่างถ้าไม่มี) — ใช้ตอนวน seed ทุก key
    value = SNAPSHOT.get(section)
    return value if isinstance(value, dict) else {}


def snapshot_rule(rule_key: str) -> dict | None:
    return snapshot_section("detection_rules").get(rule_key)


def snapshot_severity(severity_key: str) -> dict | None:
    return snapshot_section("alert_severity").get(severity_key)


def snapshot_ttl(detection_type: str) -> dict | None:
    return snapshot_section("blacklist_ttl").get(detection_type)


def snapshot_signatures(detection_type: str) -> list[dict] | None:
    # คืน list ของ signature ({'pattern','category','description','is_active'}) หรือ None ถ้าไม่มีชนิดนี้
    value = snapshot_section("detection_signatures").get(detection_type)
    return value if isinstance(value, list) else None


def snapshot_info() -> str:
    # บรรทัดสรุปว่า snapshot ที่โหลดมาเป็นของเมื่อไหร่ (ไว้ print ตอน startup)
    if not SNAPSHOT:
        return "ไม่มี snapshot (ใช้ค่า default ในโค้ด)"
    return f"snapshot จาก {SNAPSHOT.get('generated_at', 'ไม่ทราบเวลา')}"
