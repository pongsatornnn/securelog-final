

import os
import hmac

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from base_path import (
    strip_base,
    cookie_name_for,
    cookie_path_for,
    CSRF_COOKIE_BASE,
    LINE_WEBHOOK_PATH,
)


CSRF_SECRET = os.getenv("CSRF_SECRET")
if not CSRF_SECRET:
    raise RuntimeError("กรุณากำหนด CSRF_SECRET ในไฟล์ .env")

CSRF_HEADER_NAME = "x-csrf-token"
CSRF_MAX_AGE = int(os.getenv("JWT_EXPIRE_MIN", "60")) * 60
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "false").lower() == "true"

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS", "TRACE"})


EXEMPT_PATHS = frozenset({LINE_WEBHOOK_PATH})

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

    path = strip_base(path).rstrip("/") or "/"
    return path in EXEMPT_PATHS


def _csrf_set_cookie_header(token: str, name: str, path: str) -> tuple[bytes, bytes]:

    tmp = Response()
    tmp.set_cookie(
        key=name,
        value=token,
        max_age=CSRF_MAX_AGE,
        httponly=False,
        samesite="lax",
        secure=COOKIE_SECURE,
        path=path,
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

        cookie_key = cookie_name_for(request, CSRF_COOKIE_BASE)
        cookie_token = request.cookies.get(cookie_key, "")


        if method not in SAFE_METHODS and not _is_exempt(path):
            header_token = request.headers.get(CSRF_HEADER_NAME, "")

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
                    content={"detail": "เซสชันหมดอายุ กรุณารีเฟรชหน้าแล้วลองใหม่อีกครั้ง"},
                )
                await response(scope, receive, send)
                return


        need_set_cookie = (
            method in SAFE_METHODS
            and not _is_exempt(path)
            and not (cookie_token and verify_csrf(cookie_token))
        )

        if not need_set_cookie:
            await self.app(scope, receive, send)
            return

        new_cookie_header = _csrf_set_cookie_header(
            generate_csrf(), cookie_key, cookie_path_for(request)
        )

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                message.setdefault("headers", [])
                message["headers"].append(new_cookie_header)
            await send(message)

        await self.app(scope, receive, send_wrapper)
