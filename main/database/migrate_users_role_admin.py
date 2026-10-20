


import asyncio

from sqlalchemy import text

from database.connection import AsyncSessionLocal


LOG_PREFIX = "MIGRATE-USER-ROLE"


async def migrate() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(text(
            "UPDATE users SET role = 'admin', updated_at = NOW() "
            "WHERE role IS DISTINCT FROM 'admin' AND role IS DISTINCT FROM 'viewer' "
            "RETURNING id, username"
        ))
        rows = result.fetchall()
        await db.commit()

    if rows:
        for user_id, username in rows:
            print(f"[{LOG_PREFIX}] {username} (id={user_id}) -> admin")
        print(f"[{LOG_PREFIX}] อัปเดต {len(rows)} บัญชี")
    else:
        print(f"[{LOG_PREFIX}] ทุกบัญชีเป็น admin อยู่แล้ว — ไม่มีอะไรต้องแก้")

    print(f"[{LOG_PREFIX}] เสร็จแล้ว")


if __name__ == "__main__":
    asyncio.run(migrate())
