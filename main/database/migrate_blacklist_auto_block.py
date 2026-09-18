# Migration ครั้งเดียว: เพิ่มคอลัมน์เลือกโหมดตอบสนองต่อการโจมตีแต่ละชนิด
#   auto_block = true  -> block IP อัตโนมัติ (พฤติกรรมเดิม — ค่าตั้งต้นของทุกแถว)
#   auto_block = false -> แจ้งเตือนอย่างเดียว ไม่แตะ blacklist และไม่สั่ง agent
#
# รันครั้งเดียวต่อเครื่อง: cd main && ../venv/bin/python -m database.migrate_blacklist_auto_block

import asyncio

from sqlalchemy import text

from database.connection import AsyncSessionLocal


LOG_PREFIX = "MIGRATE-AUTO-BLOCK"

TABLE = "blacklist_ttl"
COLUMN = "auto_block"
COLUMN_TYPE = "BOOLEAN NOT NULL DEFAULT TRUE"


async def migrate() -> None:
    async with AsyncSessionLocal() as db:
        existing = set(
            (
                await db.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = :table"
                    ),
                    {"table": TABLE},
                )
            ).scalars().all()
        )

        if COLUMN in existing:
            print(f"[{LOG_PREFIX}] มี {TABLE}.{COLUMN} อยู่แล้ว ข้าม")
        else:
            # DEFAULT TRUE ทำให้แถวเดิมทุกแถวได้ค่า true ไปในตัว = พฤติกรรมเดิมไม่เปลี่ยน
            await db.execute(
                text(
                    f"ALTER TABLE {TABLE} ADD COLUMN IF NOT EXISTS {COLUMN} {COLUMN_TYPE}"
                )
            )
            await db.commit()
            print(f"[{LOG_PREFIX}] เพิ่มคอลัมน์ {TABLE}.{COLUMN} ({COLUMN_TYPE})")

        rows = (
            await db.execute(
                text(
                    f"SELECT detection_type, ttl_seconds, {COLUMN} "
                    f"FROM {TABLE} ORDER BY detection_type"
                )
            )
        ).all()

        for row in rows:
            if not row.auto_block:
                mode = "แจ้งเตือนอย่างเดียว (ไม่ block)"
            elif row.ttl_seconds is None:
                mode = "block ถาวร"
            else:
                mode = f"block {row.ttl_seconds}s"
            print(f"[{LOG_PREFIX}] {row.detection_type}: {mode}")

        alert_only = [r for r in rows if not r.auto_block]
        print(
            f"[{LOG_PREFIX}] เสร็จแล้ว: ทั้งหมด {len(rows)} ชนิด "
            f"(block อัตโนมัติ {len(rows) - len(alert_only)} / แจ้งเตือนอย่างเดียว {len(alert_only)})"
        )

        # cache ฝั่ง Redis ที่ค้างอยู่ไม่มีคีย์ auto_block — get_ttl โหลดใหม่ให้เองอยู่แล้ว
        print(f"[{LOG_PREFIX}] cache เดิมใน Redis ไม่ต้องล้าง (get_ttl โหลดใหม่ให้เองเมื่อไม่มีคีย์)")


if __name__ == "__main__":
    asyncio.run(migrate())
