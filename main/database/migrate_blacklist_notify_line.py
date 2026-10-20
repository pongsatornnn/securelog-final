


import asyncio

from sqlalchemy import text

from database.connection import AsyncSessionLocal


LOG_PREFIX = "MIGRATE-NOTIFY-LINE"

TABLE = "blacklist_ttl"
COLUMN = "notify_line"
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

        if "auto_block" not in existing:


            print(f"[{LOG_PREFIX}] หยุด: ยังไม่มี {TABLE}.auto_block — "
                  f"ต้องรัน database.migrate_blacklist_auto_block ก่อน")
            return

        if COLUMN in existing:
            print(f"[{LOG_PREFIX}] มี {TABLE}.{COLUMN} อยู่แล้ว ข้าม")
        else:

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
                    f"SELECT detection_type, ttl_seconds, auto_block, {COLUMN} "
                    f"FROM {TABLE} ORDER BY detection_type"
                )
            )
        ).all()

        for row in rows:
            if row.auto_block:
                block = "block ถาวร" if row.ttl_seconds is None else f"block {row.ttl_seconds}s"
                mode = f"{block} · ส่ง LINE (โหมด block แจ้งเสมอ)"
            else:
                line = "ส่ง LINE" if row.notify_line else "ไม่ส่ง LINE"
                mode = f"แจ้งเตือนอย่างเดียว (ไม่ block) · {line}"
            print(f"[{LOG_PREFIX}] {row.detection_type}: {mode}")

        notified = [r for r in rows if r.auto_block or r.notify_line]
        print(
            f"[{LOG_PREFIX}] เสร็จแล้ว: ทั้งหมด {len(rows)} ชนิด "
            f"(ส่ง LINE {len(notified)} / ไม่ส่ง {len(rows) - len(notified)})"
        )


        print(f"[{LOG_PREFIX}] cache เดิมใน Redis ไม่ต้องล้าง (get_ttl โหลดใหม่ให้เองเมื่อไม่มีคีย์)")


if __name__ == "__main__":
    asyncio.run(migrate())
