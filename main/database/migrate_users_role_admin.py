# Migration ครั้งเดียว: ระบบเลิกใช้ role แล้ว — ดันแถว users ที่ยังเป็น role อื่น (เช่น "user")
# ให้เป็น "admin" ทั้งหมด เพื่อให้ค่าในตารางตรงกับพฤติกรรมจริง (ทุกบัญชีมีสิทธิ์เท่ากัน)
#
# คอลัมน์ users.role ยังไม่ถูกลบทิ้ง (ไม่อยากแตะ schema ของตารางที่ใช้ login อยู่) แต่โค้ดไม่ได้
# อ่านค่าจากมันแล้ว — สคริปต์นี้จึงเป็นแค่การล้างข้อมูลเก่าให้สะอาด รันซ้ำได้ ไม่มีผลข้างเคียง
#
# วิธีรัน:  cd main && ../venv/bin/python -m database.migrate_users_role_admin

import asyncio

from sqlalchemy import text

from database.connection import AsyncSessionLocal


LOG_PREFIX = "MIGRATE-USER-ROLE"


async def migrate() -> None:
    async with AsyncSessionLocal() as db:
        result = await db.execute(text(
            "UPDATE users SET role = 'admin', updated_at = NOW() "
            "WHERE role IS DISTINCT FROM 'admin' "
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
