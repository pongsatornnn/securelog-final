# เส้นทางล็อกอิน/ล็อกเอาต์ + หน้าแรกที่ redirect ตามสถานะ login

import os

from fastapi import APIRouter, Request, Response, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from slowapi.util import get_remote_address

from database.connection import get_db
from database.crud import get_user, set_user_password, set_user_name
from auth import authenticate_user_db, create_access_token, decode_token, hash_password, verify_password
from login_lockout import check_locked, record_failure, reset_failures
from dependencies import require_login, require_login_page
from shared import templates, limiter

from schemas.user_schema import ChangePasswordRequest, UpdateProfileRequest


router = APIRouter()

SESSION_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "60"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"


def locked_message(retry_after: int) -> str:
    # แปลงวินาทีที่เหลือเป็นข้อความไทยบอกให้รอ
    minutes = (retry_after + 59) // 60
    if minutes >= 1:
        return f"บัญชีถูกล็อกชั่วคราวเนื่องจากใส่รหัสผิดหลายครั้ง กรุณาลองใหม่ในอีก {minutes} นาที"
    return "บัญชีถูกล็อกชั่วคราวเนื่องจากใส่รหัสผิดหลายครั้ง กรุณาลองใหม่ในอีกสักครู่"

COOKIE_CONFIG = {
    "key": "access_token",
    "httponly": True,
    "samesite": "lax",
    "max_age": SESSION_EXPIRE_MIN * 60,
    "secure": COOKIE_SECURE,
}


def clear_auth_cookie(response: Response):
    response.delete_cookie(
        key="access_token",
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
    )


@router.get("/")
async def root(request: Request):
    token = request.cookies.get("access_token")

    if token:
        payload = decode_token(token)
        if payload and payload.get("sub"):
            return RedirectResponse(url="/dashboard", status_code=302)

    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get("access_token")

    if token:
        payload = decode_token(token)

        if payload and payload.get("sub"):
            return RedirectResponse(url="/dashboard", status_code=302)

        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context={},
        )
        clear_auth_cookie(response)
        return response

    return templates.TemplateResponse(
        request=request,
        name="login.html",
        context={},
    )


@router.post("/api/login")
@limiter.limit("5/minute")
async def do_login(
    request: Request,
    response: Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
):
    # login lockout: ล็อกตาม IP (กันคนไม่หวังดีจงใจใส่รหัส user จริงผิดเพื่อล็อกเจ้าตัวออก)
    client_ip = get_remote_address(request)

    # ถ้า IP นี้ถูกล็อกอยู่ ปฏิเสธก่อน ไม่ต้องเสียเวลา authenticate
    locked, retry_after = await check_locked(client_ip)
    if locked:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=locked_message(retry_after),
            headers={"Retry-After": str(retry_after)},
        )

    user = await authenticate_user_db(
        db,
        form_data.username,
        form_data.password,
    )

    if not user:
        # นับ fail ต่อ IP (นับทุกความพยายามที่รหัสผิด ไม่ว่า username จะมีจริงหรือไม่)
        result = await record_failure(client_ip)

        if result["locked"]:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=locked_message(result["retry_after"]),
                headers={"Retry-After": str(result["retry_after"])},
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง",
        )

    if hasattr(user, "is_active") and not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="บัญชีนี้ถูกปิดใช้งาน",
        )

    # login สำเร็จ — เคลียร์ตัวนับ fail ของ IP นี้
    await reset_failures(client_ip)

    token = create_access_token(
        {
            "sub": user.username,
            "role": user.role,
            "must_change_password": bool(user.must_change_password),
            "name": user.name,
        }
    )

    response.set_cookie(
        value=token,
        **COOKIE_CONFIG,
    )

    return {"status": "ok"}


@router.post("/api/logout")
async def logout():
    response = RedirectResponse(
        url="/login",
        status_code=302,
    )
    clear_auth_cookie(response)
    return response


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(
    request: Request,
    user=Depends(require_login),
):
    # หน้านี้ใช้เฉพาะเคส "ถูกบังคับเปลี่ยนรหัส" (login ครั้งแรก / โดน admin reset) — ตั้งรหัสใหม่
    if not user["must_change_password"]:
        return RedirectResponse(url="/profile", status_code=303)
    return templates.TemplateResponse(
        request=request,
        name="change_password.html",
        context={"user": user},
    )


@router.post("/api/change-password")
@limiter.limit("5/minute")
async def do_change_password(
    request: Request,
    payload: ChangePasswordRequest,
    response: Response,
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    # เปลี่ยนรหัสผ่านของตัวเอง — เปลี่ยนสำเร็จแล้ว ออก JWT cookie ใหม่ทันที
    db_user = await get_user(db, user["username"])

    if not db_user:
        raise HTTPException(status_code=401, detail="ไม่พบบัญชีผู้ใช้")

    if db_user.must_change_password:
        if verify_password(payload.new_password, db_user.hashed_password):
            raise HTTPException(status_code=400, detail="รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสเดิม")
    else:
        if not payload.current_password or not verify_password(payload.current_password, db_user.hashed_password):
            raise HTTPException(status_code=401, detail="รหัสผ่านเดิมไม่ถูกต้อง")
        if payload.new_password == payload.current_password:
            raise HTTPException(status_code=400, detail="รหัสผ่านใหม่ต้องไม่ซ้ำกับรหัสเดิม")

    await set_user_password(db, db_user, hash_password(payload.new_password), must_change_password=False)

    token = create_access_token(
        {
            "sub": db_user.username,
            "role": db_user.role,
            "must_change_password": False,
            "name": db_user.name,
        }
    )
    response.set_cookie(value=token, **COOKIE_CONFIG)

    return {"status": "ok"}


@router.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    user=Depends(require_login_page),
    db: AsyncSession = Depends(get_db),
):
    # หน้า Profile Setting — แก้ชื่อที่แสดง (name) + ปุ่มเปลี่ยนรหัสผ่านที่เด้งเป็น popup
    db_user = await get_user(db, user["username"])
    return templates.TemplateResponse(
        request=request,
        name="profile.html",
        context={
            "user": user,
            "page": "profile",
            "profile_name": db_user.name if db_user else "",
        },
    )


@router.post("/api/profile/name")
async def update_profile_name(
    payload: UpdateProfileRequest,
    response: Response,
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    # แก้ชื่อที่แสดงของบัญชีตัวเอง (self-service) — ทุก role ทำได้เหมือน change-password
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="กรุณากรอกชื่อ")

    db_user = await get_user(db, user["username"])
    if not db_user:
        raise HTTPException(status_code=404, detail="ไม่พบบัญชีผู้ใช้")

    await set_user_name(db, db_user, name)

    token = create_access_token(
        {
            "sub": db_user.username,
            "role": db_user.role,
            "must_change_password": bool(db_user.must_change_password),
            "name": db_user.name,
        }
    )
    response.set_cookie(value=token, **COOKIE_CONFIG)

    return {"status": "ok", "name": name}
