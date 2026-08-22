"""
Export ค่า config ปัจจุบันใน DB ออกเป็น snapshot (`database/seed_data.json`)
เพื่อให้เครื่องที่ติดตั้งใหม่ (DB เปล่า) ได้ค่าชุดเดียวกันตั้งแต่ start ครั้งแรก
โดยไม่ต้องมานั่งปรับใหม่ทีละหน้า — ตอน start `database/seed.py` จะอ่านไฟล์นี้ไป seed ให้

วิธีใช้ (รันในโฟลเดอร์ main/):

    ../venv/bin/python export_seed.py            # เขียนทับ database/seed_data.json
    ../venv/bin/python export_seed.py --dry-run  # ดูว่าจะเปลี่ยนอะไรบ้าง ไม่เขียนไฟล์

แล้ว **commit `database/seed_data.json` ตามไปด้วย** ไฟล์นี้คือตัวที่พาค่าไปเครื่องใหม่

--------------------------------------------------------------------------------
เก็บเฉพาะ "การตั้งค่า" ที่ตั้งใจให้ติดไปเครื่องใหม่:
    detection_rules · alert_severity · blacklist_ttl · detection_signatures

**ไม่เก็บ** (เป็นข้อมูลเฉพาะของเครื่องนั้น ไม่ใช่ค่าเริ่มต้น):
    security_alerts / alert_reads   ประวัติการโจมตี
    ip_black_list / ip_white_list   IP ของเครือข่ายเครื่องเดิม
    line_recipients                 ผู้รับแจ้งเตือน LINE (ผูกกับ OA/คนใช้งานจริง)
    users                           เครื่องใหม่ seed admin/admin ให้เองตอน DB ว่าง
    agents / agent_downloads        มี secret token + path cert ของเครื่องเดิม เอาไปใช้ต่อ
                                    ไม่ได้ และไม่ควรให้ token หลุดข้ามเครื่อง — agent บนเครื่อง
                                    ใหม่ต้องลงทะเบียนใหม่ผ่านหน้า /agents
    app_settings                    ⚠️ **ห้าม export เด็ดขาด** — มีคีย์ LINE/Gemini และรหัส Redis
                                    ของ agent เก็บเป็น plaintext · ไฟล์นี้ถูก commit ขึ้น git
                                    ถ้าเผลอใส่เข้ามา = secret หลุดขึ้น repo ทันที
                                    เครื่องใหม่ให้กรอกเองที่หน้า /settings (ว่างไว้ตั้งแต่ต้น
                                    เหมือนที่ setup-server.sh เว้น LINE/GEMINI ใน .env ไว้ว่าง)

**ผลต่อปุ่ม "คืนค่า default" ในหน้า Rules/Signatures:** ไฟล์นี้คือ "ค่า default ที่ใช้จริง"
ของเครื่อง (signature_cache.effective_default_signatures / rule_cache.effective_default อ่านจาก
ที่นี่ก่อนค่าในโค้ด) — รันสคริปต์นี้ตอนที่มี signature ที่เพิ่มเองอยู่ใน DB = **ยกระดับ pattern
เหล่านั้นให้กลายเป็นค่า default ไปด้วย** ครั้งต่อไปที่กดคืนค่า default มันจะถูกคืนกลับมาเหมือน
ของระบบ (ตั้งใจให้เป็นแบบนี้: สคริปต์นี้แปลว่า "เอาค่าที่ตั้งไว้ตอนนี้เป็นค่าตั้งต้นชุดใหม่")
ถ้าไม่ต้องการแบบนั้น ให้ลบ pattern ที่ไม่อยากให้ติดไปออกก่อนรัน

**หมายเหตุ — ไฟล์นี้ไม่ใช่ backup ของฐานข้อมูล:** เป็น snapshot ของ "ค่าตั้งที่อยากให้ติดไปเครื่องใหม่"
เท่านั้น ถ้าวันหลังทำ backup จริงด้วย pg_dump ตาราง app_settings จะติดไปด้วยแน่นอน (secret อยู่ในนั้น)
ตอนนั้นต้องตัดสินใจแยกต่างหากว่าจะ exclude ตารางนี้ หรือเข้ารหัสค่าก่อนเก็บ
--------------------------------------------------------------------------------
"""

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
                "ttl_seconds": row.ttl_seconds,   # None = ถาวร
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
