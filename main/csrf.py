"""CSRF protection แบบ signed double-submit cookie — ครอบ "ทุก" endpoint ที่เปลี่ยนข้อมูล"""

import os
import hmac

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


CSRF_SECRET = os.getenv("CSRF_SECRET")
if not CSRF_SECRET:
    raise RuntimeError("กรุณากำหนด CSRF_SECRET ในไฟล์ .env")

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"
CSRF_MAX_AGE = int(os.getenv("JWT_EXPIRE_MIN", "60")) * 60
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})

# path ที่ยกเว้น CSRF (ไม่ใช่ request จาก browser ของผู้ใช้ — verify ด้วยวิธีอื่น)
EXEMPT_PREFIXES = ("/line/webhook",)

_signer = URLSafeTimedSerializer(CSRF_SECRET)


def generate_csrf() -> str:
    return _signer.dumps("csrf")


def verify_csrf(token: str) -> bool:
    if not token:
        return False
    try:
        _signer.loads(token, max_age=CSRF_MAX_AGE)
        return True
    except (BadSignature, SignatureExpired):
        return False


def _is_exempt(path: str) -> bool:
    return any(path.startswith(p) for p in EXEMPT_PREFIXES)


def _csrf_set_cookie_header(token: str) -> tuple[bytes, bytes]:
    """สร้าง header ('set-cookie', ...) สำหรับ cookie csrf_token โดยยืม logic ของ Response.set_cookie"""
    tmp = Response()
    tmp.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=CSRF_MAX_AGE,
        httponly=False,
        samesite="lax",
        secure=COOKIE_SECURE,
        path="/",
    )
    return (b"set-cookie", tmp.headers["set-cookie"].encode("latin-1"))


class CSRFMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        method = request.method.upper()
        path = request.url.path
        cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")

        # ---- ด่านตรวจ: request ที่เปลี่ยนข้อมูล ต้องมี CSRF token ที่ถูกต้อง ----
        if method not in SAFE_METHODS and not _is_exempt(path):
            header_token = request.headers.get(CSRF_HEADER_NAME, "")
            # เทียบเป็น bytes ไม่ใช่ str — compare_digest โยน TypeError ถ้า str ฝั่งใดมีอักขระ
            valid = (
                bool(cookie_token)
                and bool(header_token)
                and hmac.compare_digest(
                    header_token.encode("utf-8", "surrogateescape"),
                    cookie_token.encode("utf-8", "surrogateescape"),
                )
                and verify_csrf(header_token)
            )
            if not valid:
                response = JSONResponse(
                    status_code=403,
                    content={"detail": "CSRF token ไม่ถูกต้องหรือหมดอายุ กรุณารีเฟรชหน้าแล้วลองใหม่"},
                )
                await response(scope, receive, send)
                return

        # ---- ตั้ง cookie csrf_token ให้ใหม่ (บน request ปลอดภัย, self-heal, race-free) ----
        need_set_cookie = (
            method in SAFE_METHODS
            and not _is_exempt(path)
            and not (cookie_token and verify_csrf(cookie_token))
        )

        if not need_set_cookie:
            await self.app(scope, receive, send)
            return

        new_cookie_header = _csrf_set_cookie_header(generate_csrf())

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"].append(new_cookie_header)
            await send(message)

        await self.app(scope, receive, send_wrapper)
