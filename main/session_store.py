# session ฝั่ง server ของ dashboard — JWT ใน cookie ถือแค่ sub + jti แล้วต้องมีแถวใน auth_sessions ที่
# ยังไม่ถูกตัดและยังไม่หมดอายุ ถึงจะผ่าน require_login
#
# - logout          -> end_session(jti)            ตัดเฉพาะ session นั้น (บัญชี View ใช้ร่วมกันหลายจอ จึงห้ามตัดทั้งบัญชี)
# - เปลี่ยน/reset รหัส -> end_user_sessions(user_id)  ตัดทุก session ของบัญชีนั้น (session ที่อาจถูกขโมยไปตายตาม)
# - ปิดใช้งาน/ลบบัญชี -> require_login เช็ค is_active อยู่แล้ว · ลบบัญชี = แถวหายตาม (ON DELETE CASCADE)
# อายุ session = JWT_EXPIRE_MIN (ค่าเริ่มต้น 30 นาที)

import secrets
from datetime import datetime, timedelta

from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from auth import EXPIRE_MIN, create_access_token
from database.models import AuthSession


async def start_session(db: AsyncSession, user) -> str:
    # สร้าง session ใหม่ แล้วคืน JWT ที่ผูกกับมัน — ใช้แทน create_access_token ทุกจุดที่ login
    now = datetime.now()
    jti = secrets.token_urlsafe(24)

    # เก็บกวาดแถวที่หมดอายุแล้ว (ทำตอน login ซึ่งเกิดไม่ถี่ — ตารางจึงไม่โตเรื่อย ๆ)
    await db.execute(delete(AuthSession).where(AuthSession.expires_at < now))
    db.add(AuthSession(
        jti=jti,
        user_id=user.id,
        created_at=now,
        expires_at=now + timedelta(minutes=EXPIRE_MIN),
    ))
    await db.commit()

    return create_access_token({"sub": user.username, "jti": jti})


async def session_is_active(db: AsyncSession, jti: str | None, user_id: int) -> bool:
    if not jti:
        return False  # token รุ่นก่อนมีตาราง session (ไม่มี jti) — ให้ login ใหม่ครั้งเดียว
    result = await db.execute(
        select(AuthSession.jti).where(
            AuthSession.jti == jti,
            AuthSession.user_id == user_id,
            AuthSession.revoked_at.is_(None),
            AuthSession.expires_at > datetime.now(),
        )
    )
    return result.scalar_one_or_none() is not None


async def end_session(db: AsyncSession, jti: str | None) -> None:
    if not jti:
        return
    await db.execute(
        update(AuthSession)
        .where(AuthSession.jti == jti, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now())
    )
    await db.commit()


async def end_user_sessions(db: AsyncSession, user_id: int) -> int:
    result = await db.execute(
        update(AuthSession)
        .where(AuthSession.user_id == user_id, AuthSession.revoked_at.is_(None))
        .values(revoked_at=datetime.now())
    )
    await db.commit()
    return result.rowcount or 0
