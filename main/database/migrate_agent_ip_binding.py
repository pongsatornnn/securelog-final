# Migration ครั้งเดียว: เพิ่มคอลัมน์สำหรับผูก IP เข้ากับ Agent

import asyncio

from sqlalchemy import text

from database.connection import AsyncSessionLocal


LOG_PREFIX = "MIGRATE-AGENT-IP"

NEW_COLUMNS = (
    ("ip_interface", "VARCHAR(50)"),
    ("pending_ip", "VARCHAR(50)"),
    ("pending_ip_at", "TIMESTAMP"),
)


async def migrate() -> None:
    async with AsyncSessionLocal() as db:
        existing = set(
            (
                await db.execute(
                    text(
                        "SELECT column_name FROM information_schema.columns "
                        "WHERE table_name = 'agents'"
                    )
                )
            ).scalars().all()
        )

        for name, column_type in NEW_COLUMNS:
            if name in existing:
                print(f"[{LOG_PREFIX}] มี agents.{name} อยู่แล้ว ข้าม")
                continue

            await db.execute(
                text(f"ALTER TABLE agents ADD COLUMN IF NOT EXISTS {name} {column_type}")
            )
            print(f"[{LOG_PREFIX}] เพิ่มคอลัมน์ agents.{name} ({column_type})")

        await db.commit()

        # สรุปสถานะการผูก IP ของ agent ที่มีอยู่ ให้เห็นว่าหลัง migration ตัวไหนล็อกแล้ว
        rows = (
            await db.execute(
                text("SELECT agent_id, ip_address FROM agents ORDER BY agent_id")
            )
        ).all()

        pinned = [r for r in rows if r.ip_address]
        waiting = [r for r in rows if not r.ip_address]

        for row in pinned:
            print(f"[{LOG_PREFIX}] {row.agent_id} ผูกกับ IP {row.ip_address} แล้ว")

        for row in waiting:
            print(
                f"[{LOG_PREFIX}] {row.agent_id} ยังไม่มี IP — "
                f"จะผูกอัตโนมัติจากที่ agent รายงานมาครั้งแรก"
            )

        print(
            f"[{LOG_PREFIX}] เสร็จแล้ว: agent ทั้งหมด {len(rows)} ตัว "
            f"(ผูก IP แล้ว {len(pinned)} / รอผูก {len(waiting)})"
        )


if __name__ == "__main__":
    asyncio.run(migrate())
