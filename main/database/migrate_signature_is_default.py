"""
Migration ครั้งเดียว: เพิ่มคอลัมน์ detection_signatures.is_default + backfill ให้แถวเดิม

ใช้กับเครื่องที่เคยรันระบบเวอร์ชันก่อนหน้ามาแล้ว — ตารางเดิมไม่มีคอลัมน์นี้ (Base.metadata
.create_all สร้างเฉพาะตารางที่ยังไม่มี ไม่ ALTER ตารางเดิมให้) เครื่องที่ติดตั้งใหม่ไม่ต้องรัน

สิ่งที่ทำ:
  1. ADD COLUMN is_default boolean NOT NULL DEFAULT false (+ index) ถ้ายังไม่มี
  2. backfill: แถวที่ pattern ตรงกับชุด default ของ detection_type นั้น -> is_default = true
     ที่เหลือถือว่าแอดมินเพิ่มเอง (คงเป็น false)
  3. เคลียร์ cache ของทุก detection_type ที่แตะ (กันหน้าเว็บ/detector อ่านค่าเก่าต่ออีก 5 นาที)

ชุด default ที่ใช้เทียบคือชุดเดียวกับที่ seed ใช้จริง (snapshot จาก seed_data.json มาก่อน
ถ้าไม่มีค่อยใช้ DEFAULT_SIGNATURES ในโค้ด) — ดู signature_cache.default_signature_patterns()

รันด้วย (จากโฟลเดอร์ main/): python -m database.migrate_signature_is_default
"""

import asyncio

from sqlalchemy import text

from database.connection import AsyncSessionLocal
from signature_cache import (
    DEFAULT_SIGNATURES,
    default_signature_patterns,
    signature_cache_key,
)
from redis_client import cache_delete


LOG_PREFIX = "MIGRATE-SIG-DEFAULT"

TABLE = "detection_signatures"
COLUMN = "is_default"


async def column_exists(db) -> bool:
    result = await db.execute(text(
        "SELECT 1 FROM information_schema.columns "
        "WHERE table_name = :t AND column_name = :c"
    ), {"t": TABLE, "c": COLUMN})
    return result.first() is not None


async def migrate() -> None:
    async with AsyncSessionLocal() as db:
        if await column_exists(db):
            print(f"[{LOG_PREFIX}] มีคอลัมน์ {COLUMN} อยู่แล้ว — ข้ามขั้นเพิ่มคอลัมน์")
        else:
            await db.execute(text(
                f"ALTER TABLE {TABLE} ADD COLUMN {COLUMN} BOOLEAN NOT NULL DEFAULT false"
            ))
            await db.execute(text(
                f"CREATE INDEX IF NOT EXISTS ix_{TABLE}_{COLUMN} ON {TABLE} ({COLUMN})"
            ))
            await db.commit()
            print(f"[{LOG_PREFIX}] เพิ่มคอลัมน์ {TABLE}.{COLUMN} แล้ว")

        # ── backfill ──────────────────────────────────────────────────────
        # ทำทุกครั้งที่รัน (idempotent) — เผื่อเคยรันตอนที่ยังไม่มีข้อมูลครบ
        touched = {}

        for detection_type in DEFAULT_SIGNATURES:
            patterns = default_signature_patterns(detection_type)

            if not patterns:
                continue

            result = await db.execute(text(
                f"UPDATE {TABLE} SET {COLUMN} = true "
                "WHERE detection_type = :dt AND pattern = ANY(:patterns) "
                f"AND {COLUMN} IS NOT true "
                "RETURNING id"
            ), {"dt": detection_type, "patterns": list(patterns)})

            marked = len(result.fetchall())
            if marked:
                touched[detection_type] = marked

        await db.commit()

    if touched:
        for detection_type, marked in touched.items():
            print(f"[{LOG_PREFIX}] {detection_type}: mark เป็น default {marked} แถว")
            cache_delete(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)
    else:
        print(f"[{LOG_PREFIX}] ไม่มีแถวไหนต้อง mark เพิ่ม (backfill ครบอยู่แล้ว)")

    print(f"[{LOG_PREFIX}] เสร็จแล้ว")


if __name__ == "__main__":
    asyncio.run(migrate())
