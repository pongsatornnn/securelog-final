from fastapi import Request, HTTPException, status, Depends

from auth import decode_token
from database.connection import AsyncSessionLocal
from database.crud import get_user, get_first_user
from base_path import strip_base, rel_url, cookie_name_for, AUTH_COOKIE_BASE
from view_account import is_view_role, view_may
from session_store import session_is_active


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

        session_ok = bool(user) and await session_is_active(db, payload.get("jti"), user.id)


    if not user or not user.is_active or not session_ok:
        raise _redirect_login(request)


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

        "id": user.id,
        "username": user.username,


        "role": "viewer" if is_viewer else "admin",
        "name": user.name,
        "is_active": user.is_active,

        "is_primary_admin": bool(first_user and first_user.id == user.id) and not is_viewer,
        "must_change_password": bool(user.must_change_password),
    }


async def require_login_page(request: Request, user=Depends(require_login)):

    if user["must_change_password"] and strip_base(request.url.path) != "/change-password":
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": rel_url(request, "/change-password")},
        )
    return user


async def require_admin(user=Depends(require_login)):


    if user["role"] == "viewer":
        raise HTTPException(status_code=403, detail="บัญชี View ดูได้อย่างเดียว")
    return user


async def require_admin_page(user=Depends(require_login_page)):

    return user


async def require_primary_admin(user=Depends(require_login)):

    if not user["is_primary_admin"]:
        raise HTTPException(status_code=403, detail="เฉพาะบัญชี admin เท่านั้นที่จัดการ user ได้")
    return user


async def require_primary_admin_page(request: Request, user=Depends(require_login_page)):

    if not user["is_primary_admin"]:
        raise HTTPException(
            status_code=status.HTTP_303_SEE_OTHER,
            headers={"Location": rel_url(request, "/dashboard")},
        )
    return user
