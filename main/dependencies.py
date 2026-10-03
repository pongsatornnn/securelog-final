from fastapi import Request, HTTPException, status, Depends

from auth import decode_token
from database.connection import AsyncSessionLocal
from database.crud import get_user, get_first_user
from base_path import strip_base, rel_url, cookie_name_for, AUTH_COOKIE_BASE
from view_account import is_view_role, view_may
from session_store import session_is_active

# ระหว่างที่ยังต้องเปลี่ยนรหัส (บัญชีใหม่ / โดน reset / admin/admin ของเครื่องติดตั้งใหม่) เรียกได้แค่นี้
# เดิมกันไว้แค่หน้าเว็บ (require_login_page) แต่ API ยังใช้ได้ครบด้วยรหัสชั่วคราว
MUST_CHANGE_ALLOWED = {
    ("GET", "/change-password"),
    ("POST", "/api/change-password"),
    ("GET", "/api/password-policy"),
}


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
        # session ต้องยังอยู่ใน auth_sessions (ไม่ถูก logout / ตัดตอนเปลี่ยนรหัส / ไม่หมดอายุ)
        session_ok = bool(user) and await session_is_active(db, payload.get("jti"), user.id)

    # ถูกลบออกจากระบบ หรือถูกปิดใช้งาน -> session ตายทันที เด้งไปหน้า login
    if not user or not user.is_active or not session_ok:
        raise _redirect_login(request)

    # บัญชี View: ห้ามทุกอย่าง ยกเว้นรายการใน view_account.VIEW_ALLOWED (Dashboard / Alerts แบบอ่าน)
    # หน้าเว็บที่ไม่อนุญาต = เด้งกลับ Dashboard · API = 403
    is_viewer = is_view_role(user.role)
    if is_viewer:
        path = strip_base(request.url.path)
        if not view_may(request.method, path):
            if path.startswith("/api/"):
                raise HTTPException(status_code=403, detail="บัญชี View ดูได้อย่างเดียว")
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": rel_url(request, "/dashboard")},
            )

    # ยังต้องเปลี่ยนรหัส: นอกจากหน้า/API เปลี่ยนรหัส ห้ามหมด — หน้าเว็บเด้งไปเปลี่ยนรหัส · API = 403
    if user.must_change_password:
        path = strip_base(request.url.path).rstrip("/") or "/"
        if (request.method.upper(), path) not in MUST_CHANGE_ALLOWED:
            if path.startswith("/api/"):
                raise HTTPException(status_code=403, detail="ต้องเปลี่ยนรหัสผ่านก่อนใช้งาน")
            raise HTTPException(
                status_code=status.HTTP_303_SEE_OTHER,
                headers={"Location": rel_url(request, "/change-password")},
            )

    return {
        # id ไว้ให้ endpoint ที่เก็บสถานะรายบัญชี (เช่น สถานะอ่านแล้วของ alert) อ้างถึง user
        "id": user.id,
        "username": user.username,
        # ระบบไม่มี role แล้ว — ทุกบัญชีที่ login ได้มีสิทธิ์เท่ากันหมด คีย์นี้เลยตอบ "admin"
        # ตายตัว ไม่ได้อ่านจาก DB (บัญชีเก่าที่ยังเป็น role=user ในตารางจึงได้สิทธิ์เท่ากันทันที)
        # ยกเว้นบัญชี View ตอบ "viewer" — template ใช้ซ่อนเมนู/ปุ่มที่บัญชีนี้ใช้ไม่ได้
        "role": "viewer" if is_viewer else "admin",
        "name": user.name,
        "is_active": user.is_active,
        # บัญชี admin เริ่มต้น (id น้อยสุด) — คนเดียวที่จัดการ user ได้ (หน้า Manage Users)
        "is_primary_admin": bool(first_user and first_user.id == user.id) and not is_viewer,
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
    # บัญชี View ถูกกันที่ require_login แล้ว — กันซ้ำอีกชั้นเผื่อวันหนึ่งมีคนเพิ่ม path ลง VIEW_ALLOWED พลาด
    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="บัญชี View ดูได้อย่างเดียว")
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
