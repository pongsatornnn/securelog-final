# เส้นทางล็อกอิน/ล็อกเอาต์ + หน้าแรกที่ redirect ตามสถานะ login

import os

from fastapi import APIRouter, Request, Response, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from slowapi.util import get_remote_address

from database.connection import get_db, AsyncSessionLocal
from database.crud import get_user, set_user_password, set_user_name, get_view_user
from auth import (
    authenticate_user_db,
    decode_token,
    hash_password,
    verify_password,
)
from login_lockout import check_locked, record_failure, reset_failures
from session_store import start_session, session_is_active, end_session, end_user_sessions
from dependencies import require_login, require_login_page
from shared import templates, limiter
from base_path import (
    rel_url,
    cookie_name_for,
    cookie_path_for,
    LEGACY_COOKIE_PATH,
    AUTH_COOKIE_BASE,
    CSRF_COOKIE_BASE,
)
from csrf import verify_csrf

from schemas.user_schema import ChangePasswordRequest, UpdateProfileRequest
import password_policy


router = APIRouter()

SESSION_EXPIRE_MIN = int(os.getenv("JWT_EXPIRE_MIN", "60"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"


def locked_message(retry_after: int) -> str:
    # แปลงวินาทีที่เหลือเป็นข้อความไทยบอกให้รอ
    minutes = (retry_after + 59) // 60
    if minutes >= 1:
        return f"บัญชีถูกล็อกชั่วคราวเนื่องจากใส่รหัสผิดหลายครั้ง กรุณาลองใหม่ในอีก {minutes} นาที"
    return "บัญชีถูกล็อกชั่วคราวเนื่องจากใส่รหัสผิดหลายครั้ง กรุณาลองใหม่ในอีกสักครู่"

def auth_cookie_config(request) -> dict:
    # ชื่อ + path ของ cookie ผูกกับ prefix ของ request นี้ — ไม่หลุดไปหา service อื่นที่อยู่
    # โฮสต์+พอร์ตเดียวกัน และไม่ถูก cookie ชื่อซ้ำของ service นั้นทับ
    return {
        "key": cookie_name_for(request, AUTH_COOKIE_BASE),
        "httponly": True,
        "samesite": "lax",
        "max_age": SESSION_EXPIRE_MIN * 60,
        "secure": COOKIE_SECURE,
        "path": cookie_path_for(request),
    }

# cookie ชุดที่เวอร์ชันก่อนหน้าตั้งไว้ที่ราก ("/") ด้วยชื่อเดิม — ถ้าไม่ล้างทิ้ง browser จะส่งมา
# ทั้งใบเก่าและใบใหม่ (ชื่อซ้ำ คนละ path) แล้วฝั่ง server อ่านใบท้ายสุดซึ่งอาจเป็นใบเก่า
LEGACY_COOKIE_NAMES = (AUTH_COOKIE_BASE, CSRF_COOKIE_BASE)


def _is_our_cookie(name: str, value: str) -> bool:
    # ใบของเราเซ็นด้วยกุญแจของระบบนี้ — ของ service อื่นที่ชื่อบังเอิญซ้ำจะไม่ผ่านด่านนี้
    if name == AUTH_COOKIE_BASE:
        return decode_token(value) is not None
    if name == CSRF_COOKIE_BASE:
        return verify_csrf(value)
    return False


def clear_legacy_cookies(request: Request, response: Response):
    for name in LEGACY_COOKIE_NAMES:
        if cookie_name_for(request, name) == name and cookie_path_for(request) == LEGACY_COOKIE_PATH:
            continue  # ไม่ได้ใช้ prefix/suffix = ใบที่ใช้อยู่กับใบเก่าเป็นใบเดียวกัน ห้ามลบ

        value = request.cookies.get(name)
        if not value or not _is_our_cookie(name, value):
            continue  # ไม่มีของค้าง หรือเป็นของ service อื่นที่แชร์โฮสต์+พอร์ตกัน — ห้ามแตะ

        response.delete_cookie(
            key=name,
            path=LEGACY_COOKIE_PATH,
            samesite="lax",
            secure=COOKIE_SECURE,
        )


def clear_shadow_cookies(request: Request, response: Response):
    # ใบ "ชื่อเดียวกับที่ใช้อยู่" แต่ค้างที่ราก — เกิดตอนย้าย ROOT_PATH (เคยเสิร์ฟที่ราก -> ย้ายมาใต้ prefix)
    # browser ส่งมาให้ทั้งสองใบ แล้ว starlette อ่านใบท้ายสุดชนะ = ใบเก่าที่รากบังใบใหม่
    # อาการที่เจอ: กด logout แล้วไม่ออก (ลบได้เฉพาะใบใต้ prefix) และ CSRF อาจไม่ตรงกัน
    path = cookie_path_for(request)
    if path == LEGACY_COOKIE_PATH:
        return
    for base in (AUTH_COOKIE_BASE, CSRF_COOKIE_BASE):
        name = cookie_name_for(request, base)
        if name == base:
            continue  # ชื่อกลาง ๆ ไม่มี suffix = อาจเป็นของ service อื่นบนโฮสต์เดียวกัน ห้ามแตะ
        response.delete_cookie(
            key=name,
            path=LEGACY_COOKIE_PATH,
            samesite="lax",
            secure=COOKIE_SECURE,
        )


def set_auth_cookie(request: Request, response: Response, token: str):
    response.set_cookie(value=token, **auth_cookie_config(request))
    clear_legacy_cookies(request, response)
    clear_shadow_cookies(request, response)


def clear_auth_cookie(request: Request, response: Response):
    response.delete_cookie(
        key=cookie_name_for(request, AUTH_COOKIE_BASE),
        path=cookie_path_for(request),
        httponly=True,
        samesite="lax",
        secure=COOKIE_SECURE,
    )
    clear_legacy_cookies(request, response)
    clear_shadow_cookies(request, response)


async def token_has_live_session(token: str | None) -> bool:
    # cookie ที่ยัง "ใช้ได้จริง" — ลายเซ็น/อายุ JWT ผ่าน และ session ยังไม่ถูกตัด
    # (เช็คแค่ JWT ไม่พอ: cookie ที่ถูกตัดตอนเปลี่ยนรหัสจะพา /login -> /dashboard -> /login วนไม่จบ)
    payload = decode_token(token) if token else None
    if not payload or not payload.get("sub"):
        return False
    try:
        async with AsyncSessionLocal() as db:
            user = await get_user(db, payload["sub"])
            return bool(user and user.is_active) and await session_is_active(db, payload.get("jti"), user.id)
    except Exception:
        return False


@router.get("/")
async def root(request: Request):
    token = request.cookies.get(cookie_name_for(request, AUTH_COOKIE_BASE))

    if await token_has_live_session(token):
        return RedirectResponse(url=rel_url(request, "/dashboard"), status_code=302)

    return RedirectResponse(url=rel_url(request, "/login"), status_code=302)


async def view_login_enabled() -> bool:
    # ปุ่ม View ที่หน้า login โชว์เฉพาะตอนที่บัญชี View เปิดใช้งานอยู่
    # DB ล่มก็ยังต้องเปิดหน้า login ได้ (เดิมหน้านี้ไม่แตะ DB เลย) -> ถือว่าปิดไว้
    try:
        async with AsyncSessionLocal() as db:
            view_user = await get_view_user(db)
        return bool(view_user and view_user.is_active)
    except Exception:
        return False


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    token = request.cookies.get(cookie_name_for(request, AUTH_COOKIE_BASE))
    context = {"view_enabled": await view_login_enabled()}

    if token:
        if await token_has_live_session(token):
            return RedirectResponse(url=rel_url(request, "/dashboard"), status_code=302)

        response = templates.TemplateResponse(
            request=request,
            name="login.html",
            context=context,
        )
        clear_auth_cookie(request, response)
        return response

    response = templates.TemplateResponse(
        request=request,
        name="login.html",
        context=context,
    )
    clear_legacy_cookies(request, response)
    clear_shadow_cookies(request, response)
    return response


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

    token = await start_session(db, user)

    set_auth_cookie(request, response, token)

    return {"status": "ok"}


@router.post("/api/login/view")
@limiter.limit("10/minute")
async def do_view_login(
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    # ปุ่ม View ที่หน้า login — เข้าบัญชี View (ดูได้อย่างเดียว) โดยไม่ต้องกรอกรหัส
    # ได้เฉพาะตอนที่ admin เปิดบัญชีนี้ไว้ · สิทธิ์ของ session นี้ถูกจำกัดที่ dependencies.require_login
    view_user = await get_view_user(db)

    if not view_user or not view_user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="โหมด View ถูกปิดใช้งานอยู่",
        )

    token = await start_session(db, view_user)

    set_auth_cookie(request, response, token)

    return {"status": "ok"}


@router.post("/api/logout")
async def logout(request: Request):
    # ตัด session นี้ฝั่ง server ด้วย ไม่ใช่แค่ลบ cookie — token ที่ถูกคัดลอกไปจะใช้ต่อไม่ได้
    # (ตัดเฉพาะ session นี้ บัญชีเดียวกันที่ login อยู่เครื่องอื่นไม่โดน)
    payload = decode_token(request.cookies.get(cookie_name_for(request, AUTH_COOKIE_BASE)) or "")
    if payload:
        try:
            async with AsyncSessionLocal() as db:
                await end_session(db, payload.get("jti"))
        except Exception as e:
            print(f"[AUTH] logout: ตัด session ไม่สำเร็จ: {e}")

    response = RedirectResponse(
        url=rel_url(request, "/login"),
        status_code=302,
    )
    clear_auth_cookie(request, response)
    return response


@router.get("/api/password-policy")
async def api_password_policy(user=Depends(require_login)):
    # หน้าเว็บดึงกฎไปทำ checklist สด ๆ ตอนผู้ใช้พิมพ์ — กฎชุดเดียวกับที่ server บังคับ
    return password_policy.policy_for_client()


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(
    request: Request,
    user=Depends(require_login),
):
    # หน้านี้ใช้เฉพาะเคส "ถูกบังคับเปลี่ยนรหัส" (login ครั้งแรก / โดน admin reset) — ตั้งรหัสใหม่
    if not user["must_change_password"]:
        return RedirectResponse(url=rel_url(request, "/profile"), status_code=303)
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

    # นโยบายรหัสผ่าน — ตรวจด้วยกฎชุดเดียวกับที่หน้าเว็บใช้ทำ checklist
    failed = password_policy.failed_rules(payload.new_password)
    if failed:
        raise HTTPException(
            status_code=400,
            detail=password_policy.error_detail(failed),
            headers={"X-Password-Policy-Failed": ",".join(r["id"] for r in failed)},
        )

    await set_user_password(db, db_user, hash_password(payload.new_password), must_change_password=False)

    # รหัสเปลี่ยน = ตัดทุก session ของบัญชีนี้ (รวมที่อาจถูกขโมยไป) แล้วเปิด session ใหม่ให้เครื่องที่กดอยู่
    await end_user_sessions(db, db_user.id)
    token = await start_session(db, db_user)
    set_auth_cookie(request, response, token)

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
    request: Request,
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

    # ไม่ต้องออก token ใหม่ — require_login อ่านชื่อจาก DB ทุก request อยู่แล้ว
    return {"status": "ok", "name": name}
