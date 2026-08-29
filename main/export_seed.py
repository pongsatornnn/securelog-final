"""Export ค่า config ปัจจุบันใน DB ออกเป็น snapshot (`database/seed_data.json`)"""

import asyncio
import json
import os
import sys
from datetime import datetime
from pathlib import Path

from database.connection import AsyncSessionLocal
from database.crud import (
    get_all_detection_rules,
    get_all_alert_severity,
    get_all_blacklist_ttl,
    get_detection_signatures,
)
from database.defaults import SEED_DATA_PATH


# section -> ชื่อไทยไว้ print สรุป
SECTION_LABELS = {
    "detection_rules": "detection rule",
    "alert_severity": "severity",
    "blacklist_ttl": "blacklist TTL",
    "detection_signatures": "signature",
}


async def collect() -> dict:
    """อ่าน config ทั้ง 4 ตารางจาก DB ปัจจุบัน แล้วจัดรูปเป็น dict พร้อมเขียนเป็น JSON"""
    async with AsyncSessionLocal() as db:
        rules = await get_all_detection_rules(db)
        severities = await get_all_alert_severity(db)
        ttls = await get_all_blacklist_ttl(db)
        signatures = await get_detection_signatures(db)

    detection_signatures: dict[str, list[dict]] = {}
    for row in signatures:
        detection_signatures.setdefault(row.detection_type, []).append({
            "pattern": row.pattern,
            "category": row.category,
            "description": row.description,
            "is_active": bool(row.is_active),
        })

    return {
        "generated_at": datetime.now().isoformat(timespec="seconds"),
        "source": f"{os.getenv('DB_NAME', '?')}@{os.getenv('DB_HOST', '?')}",
        "detection_rules": {
            row.rule_key: {
                "category": row.category,
                "window_seconds": row.window_seconds,
                "threshold": row.threshold,
                "description": row.description,
                "is_active": bool(row.is_active),
            }
            for row in rules
        },
        "alert_severity": {
            row.severity_key: {
                "severity": row.severity,
                "description": row.description,
            }
            for row in severities
        },
        "blacklist_ttl": {
            row.detection_type: {
                "ttl_seconds": row.ttl_seconds,
                "description": row.description,
            }
            for row in ttls
        },
        "detection_signatures": detection_signatures,
    }


def load_previous() -> dict:
    """snapshot เดิม (ถ้ามี) ไว้เทียบว่ารอบนี้เปลี่ยนอะไรบ้าง"""
    if not SEED_DATA_PATH.exists():
        return {}

    try:
        with SEED_DATA_PATH.open(encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def print_diff(old: dict, new: dict) -> bool:
    """print สิ่งที่ต่างจาก snapshot เดิมทีละ section — คืน True ถ้ามีอะไรเปลี่ยน"""
    changed = False

    for section, label in SECTION_LABELS.items():
        old_section = old.get(section, {}) or {}
        new_section = new.get(section, {}) or {}

        added = [k for k in new_section if k not in old_section]
        removed = [k for k in old_section if k not in new_section]
        edited = [
            k for k in new_section
            if k in old_section and old_section[k] != new_section[k]
        ]

        if not (added or removed or edited):
            continue

        changed = True
        print(f"\n  [{label}]")

        for key in added:
            print(f"    + เพิ่ม   {key}")
        for key in removed:
            print(f"    - หายไป  {key}")
        for key in edited:
            print(f"    ~ แก้ไข   {key}")
            # section signature เป็น list ของ pattern — บอกแค่จำนวน ไม่ต้องพ่น regex ทั้งก้อน
            if section == "detection_signatures":
                print(f"        {len(old_section[key])} -> {len(new_section[key])} รายการ")
                continue
            for field, new_value in new_section[key].items():
                old_value = old_section[key].get(field)
                if old_value != new_value:
                    print(f"        {field}: {old_value!r} -> {new_value!r}")

    return changed


async def main():
    dry_run = "--dry-run" in sys.argv

    data = await collect()
    previous = load_previous()

    print(f"อ่าน config จาก DB {data['source']}:")
    for section, label in SECTION_LABELS.items():
        section_data = data[section]
        if section == "detection_signatures":
            total = sum(len(v) for v in section_data.values())
            print(f"  {label:<16} {total} รายการ ({len(section_data)} ชนิด)")
        else:
            print(f"  {label:<16} {len(section_data)} รายการ")

    if previous:
        print(f"\nเทียบกับ snapshot เดิม ({previous.get('generated_at', 'ไม่ทราบเวลา')}):")
        if not print_diff(previous, data):
            print("  ไม่มีอะไรเปลี่ยน")
    else:
        print(f"\nยังไม่เคยมี snapshot มาก่อน — จะสร้าง {SEED_DATA_PATH.name} ใหม่")

    if dry_run:
        print("\n--dry-run: ไม่ได้เขียนไฟล์")
        return

    # เขียนผ่านไฟล์ชั่วคราวแล้วค่อย replace กันไฟล์พังถ้าเขียนไม่จบ (ระบบอ่านไฟล์นี้ตอน start)
    tmp_path = SEED_DATA_PATH.with_suffix(".json.tmp")
    with tmp_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
        f.write("\n")
    Path(tmp_path).replace(SEED_DATA_PATH)

    print(f"\nเขียน {SEED_DATA_PATH} เรียบร้อย")
    print("อย่าลืม commit ไฟล์นี้ด้วย — เครื่องใหม่ใช้ไฟล์นี้ seed ค่าเริ่มต้นตอน start ครั้งแรก")


if __name__ == "__main__":
    asyncio.run(main())
