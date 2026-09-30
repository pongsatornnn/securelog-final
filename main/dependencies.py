from fastapi import Request, HTTPException, status, Depends

from auth import decode_token
from database.connection import AsyncSessionLocal
from database.crud import get_user, get_first_user
from base_path import strip_base, rel_url, cookie_name_for, AUTH_COOKIE_BASE


def _redirect_login(request: Request) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Location": rel_url(request, "/login")},
    )


async def require_login(request: Request):
    # ยืนยันตัวตนจาก JWT cookie แล้ว "โหลดสถานะสดจาก DB" ทุก request — ไม่เชื่อค่า is_active/
    token = request.cookies.get(cookie_name_for(request, AUTH_COOKIE_BASE))
    if not token:
        raise _redirect_login(request)

    payload = decode_token(token)
    if not payload:
        raise _redirect_login(request)

    username = payload.get("sub")
    if not username:
        raise _redirect_login(request)

    async with AsyncSessionLocal() as db:
        user = await get_user(db, username)
        first_user = await get_first_user(db)

    # ถูกลบออกจากระบบ หรือถูกปิดใช้งาน -> session ตายทันที เด้งไปหน้า login
    if not user or not user.is_active:
        raise _redirect_login(request)

    return {
        # id ไว้ให้ endpoint ที่เก็บสถานะรายบัญชี (เช่น สถานะอ่านแล้วของ alert) อ้างถึง user
        "id": user.id,
        "username": user.username,
        # ระบบไม่มี role แล้ว — ทุกบัญชีที่ login ได้มีสิทธิ์เท่ากันหมด คีย์นี้เลยตอบ "admin"
        # ตายตัว ไม่ได้อ่านจาก DB (บัญชีเก่าที่ยังเป็น role=user ในตารางจึงได้สิทธิ์เท่ากันทันที)
        "role": "admin",
        "name": user.name,
        "is_active": user.is_active,
        # บัญชี admin เริ่มต้น (id น้อยสุด) — คนเดียวที่จัดการ user ได้ (หน้า Manage Users)
        "is_primary_admin": bool(first_user and first_user.id == user.id),
        "must_change_password": bool(user.must_change_password),
    }


async def require_login_page(request: Request, user=Depends(require_login)):
    # ใช้กับ page route (render HTML) — เหมือน require_login แต่เพิ่ม redirect ไป /change-password
    if user["must_change_password"] and strip_base(request.url.path) != "/change-password":
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": rel_url(request, "/change-password")},
        )
    return user


async def require_admin(user=Depends(require_login)):
    # เดิมกันไว้ให้เฉพาะ role=admin — ตอนนี้ระบบไม่มี role แล้ว ทุกบัญชีที่ login ได้เรียกได้หมด
    # (คงชื่อเดิมไว้เพราะมี endpoint เรียกใช้อยู่หลายสิบจุด ความหมาย = ต้อง login เท่านั้น)
    return user


async def require_admin_page(user=Depends(require_login_page)):
    # เหมือน require_admin แต่ใช้กับ page route — เช็คเรื่องบังคับเปลี่ยนรหัสด้วย (require_login_page)
    return user


async def require_primary_admin(user=Depends(require_login)):
    # จัดการ user ได้เฉพาะบัญชี admin เริ่มต้น — user อื่นที่ถูกเพิ่มเข้ามาใช้งานส่วนอื่นได้ครบ แต่จัดการ user ไม่ได้
    if not user["is_primary_admin"]:
        raise HTTPException(status_code=403, detail="เฉพาะบัญชี admin เท่านั้นที่จัดการ user ได้")
    return user


async def require_primary_admin_page(request: Request, user=Depends(require_login_page)):
    # เหมือน require_primary_admin แต่ใช้กับ page route — ไม่ใช่ admin ให้เด้งกลับหน้าแรก
    if not user["is_primary_admin"]:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": rel_url(request, "/dashboard")},
        )
    return user
