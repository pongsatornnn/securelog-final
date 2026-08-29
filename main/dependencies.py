from fastapi import Request, HTTPException, status, Depends

from auth import decode_token
from database.connection import AsyncSessionLocal
from database.crud import get_user


def _redirect_login() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_303_SEE_OTHER,
        headers={"Location": "/login"},
    )


async def require_login(request: Request):
    """ยืนยันตัวตนจาก JWT cookie แล้ว "โหลดสถานะสดจาก DB" ทุก request — ไม่เชื่อค่า role/is_active/"""
    token = request.cookies.get("access_token")
    if not token:
        raise _redirect_login()

    payload = decode_token(token)
    if not payload:
        raise _redirect_login()

    username = payload.get("sub")
    if not username:
        raise _redirect_login()

    async with AsyncSessionLocal() as db:
        user = await get_user(db, username)

    # ถูกลบออกจากระบบ หรือถูกปิดใช้งาน -> session ตายทันที เด้งไปหน้า login
    if not user or not user.is_active:
        raise _redirect_login()

    return {
        # id ไว้ให้ endpoint ที่เก็บสถานะรายบัญชี (เช่น สถานะอ่านแล้วของ alert) อ้างถึง user
        "id": user.id,
        "username": user.username,
        "role": user.role,
        "name": user.name,
        "is_active": user.is_active,
        "must_change_password": bool(user.must_change_password),
    }


async def require_login_page(request: Request, user=Depends(require_login)):
    """ใช้กับ page route (render HTML) — เหมือน require_login แต่เพิ่ม redirect ไป /change-password"""
    if user["must_change_password"] and request.url.path != "/change-password":
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": "/change-password"},
        )
    return user


async def require_admin(user=Depends(require_login)):
    """ใช้กับ API ที่เฉพาะ role=admin เรียกได้ (เช่น /api/users) — ไม่เช็ค must_change_password"""
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ต้องเป็น admin เท่านั้น")
    return user


async def require_admin_page(user=Depends(require_login_page)):
    """ใช้กับ page route ที่เฉพาะ admin เข้าได้ (หน้า Manage Users) — เช็คทั้งสองอย่าง"""
    if user["role"] != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="ต้องเป็น admin เท่านั้น")
    return user
