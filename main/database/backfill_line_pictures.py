"""
Backfill รูปโปรไฟล์ LINE ของผู้รับแจ้งเตือนที่ลงทะเบียนไว้ก่อนมีคอลัมน์ picture_url

ทำไมต้องมี: webhook เติมรูปให้เองอยู่แล้ว แต่เติมได้เฉพาะตอนคนนั้น "มี event เข้ามา"
(follow ใหม่ / ส่งข้อความ) — คนที่แอด OA และถูกอนุมัติไปนานแล้วอาจไม่ส่งอะไรมาอีกเลย
รูปก็จะไม่ขึ้นสักที สคริปต์นี้ยิง get profile ให้ทีเดียวจบ

รันครั้งเดียวหลัง deploy เวอร์ชันที่มี picture_url (จากโฟลเดอร์ main/):
    ../venv/bin/python -m database.backfill_line_pictures

ปลอดภัยกับการรันซ้ำ — ข้ามคนที่ดึง profile ไปแล้ว (picture_url ไม่ใช่ NULL)
ยกเว้นสั่ง --all ให้ดึงใหม่ทุกคน (ใช้ตอนอยากอัปเดตรูป/ชื่อที่เจ้าตัวเปลี่ยนไปแล้ว)

ค่าที่เขียนลง picture_url: URL ของรูป หรือ '' ถ้าเจ้าตัวไม่ได้ตั้งรูป
(ดูความหมายของ NULL / '' / URL ใน database.models.LineRecipient.picture_url)
"""

import asyncio
import sys

from sqlalchemy import select

from database.connection import AsyncSessionLocal
from database.models import LineRecipient
from LINE_API import config, line_client
from settings_cache import ensure_loaded


LOG_PREFIX = "BACKFILL-LINE-PIC"


async def backfill(refresh_all: bool = False) -> None:
    # อ่านค่าจาก DB เข้า cache ก่อน — สคริปต์นี้รันเป็น process แยก cache ยังว่างอยู่เสมอ
    await ensure_loaded()

    if not config.channel_access_token():
        print(f"[{LOG_PREFIX}] ยังไม่ได้ตั้ง Channel Access Token (หน้า System Settings หรือ .env) — ดึง profile ไม่ได้")
        return

    async with AsyncSessionLocal() as db:
        query = select(LineRecipient).order_by(LineRecipient.id)
        if not refresh_all:
            query = query.where(LineRecipient.picture_url.is_(None))

        recipients = (await db.execute(query)).scalars().all()

        if not recipients:
            print(f"[{LOG_PREFIX}] ไม่มีแถวที่ต้องเติม (ทุกคนดึง profile ไปแล้ว)")
            return

        print(f"[{LOG_PREFIX}] ต้องดึง profile {len(recipients)} คน")
        updated = failed = 0

        for r in recipients:
            # get_profile เป็น urllib แบบ blocking — จำนวนผู้รับหลักสิบ ไม่คุ้มที่จะทำ async
            profile = await asyncio.to_thread(line_client.get_profile, r.line_user_id)

            if profile is None:
                # ปกติเกิดตอนเจ้าตัวบล็อก OA ไปแล้ว (LINE ตอบ 404) — ปล่อย NULL ไว้เหมือนเดิม
                # ให้ webhook ลองใหม่เองถ้าวันหลังเขากลับมา follow
                print(f"[{LOG_PREFIX}] ดึง profile ไม่สำเร็จ: id={r.id} {r.display_name or r.line_user_id}")
                failed += 1
                continue

            r.display_name = profile.get("displayName") or r.display_name
            r.picture_url = profile.get("pictureUrl") or ""

            has_pic = "มีรูป" if r.picture_url else "ไม่ได้ตั้งรูป"
            print(f"[{LOG_PREFIX}] id={r.id} {r.display_name} -> {has_pic}")
            updated += 1

        await db.commit()
        print(f"[{LOG_PREFIX}] เสร็จ — อัปเดต {updated} คน, ดึงไม่สำเร็จ {failed} คน")


if __name__ == "__main__":
    asyncio.run(backfill(refresh_all="--all" in sys.argv))
