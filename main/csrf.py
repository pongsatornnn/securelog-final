"""
CSRF protection แบบ signed double-submit cookie — ครอบ "ทุก" endpoint ที่เปลี่ยนข้อมูล
(เดิมบังคับแค่หน้า login) ทำเป็น middleware กลาง = secure by default ไม่ต้องไปใส่ทีละ endpoint

หลักการ:
- request ที่ "ปลอดภัย" (GET/HEAD/OPTIONS): ปล่อยผ่าน + ตั้ง cookie `csrf_token` ให้ถ้ายังไม่มี
  (readable โดย JS = ไม่ httponly เพราะ frontend ต้องอ่านไปแนบ header — cookie นี้ไม่ใช่ session)
- request ที่ "เปลี่ยนข้อมูล" (POST/PUT/PATCH/DELETE): ต้องมี header X-CSRF-Token ที่
  (1) ตรงกับ cookie `csrf_token` (double submit) และ (2) เซ็นถูกต้อง+ไม่หมดอายุ ไม่งั้น 403
  ยกเว้น path ใน EXEMPT_PREFIXES (เช่น /line/webhook ที่ verify ด้วย LINE signature ของตัวเองอยู่แล้ว)

ทำไม header กัน CSRF ได้: เว็บต่างโดเมนตั้ง custom header (X-CSRF-Token) ไม่ได้ถ้าไม่ผ่าน CORS
preflight (ซึ่งเราไม่เปิด CORS ให้) + อ่าน cookie ของเหยื่อข้ามโดเมนก็ไม่ได้ → ปลอม request ไม่ได้

เขียนเป็น pure ASGI middleware (ไม่ใช่ BaseHTTPMiddleware) เพื่อไม่ให้รบกวน SSE/streaming
response (`/api/stream/alerts`) — แตะแค่ header ตอน response.start ไม่ buffer body
"""

import os
import hmac

from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from starlette.requests import Request
from starlette.responses import JSONResponse, Response


CSRF_SECRET = os.getenv("CSRF_SECRET")
if not CSRF_SECRET:
    raise RuntimeError("กรุณากำหนด CSRF_SECRET ในไฟล์ .env")

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "x-csrf-token"          # Headers ของ Starlette เทียบแบบ case-insensitive
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
        httponly=False,        # ต้องให้ JS อ่านไปใส่ header ได้ (ไม่ใช่ session token — ไม่ลับ)
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
            # นอก ASCII ซึ่งผู้เรียกใส่มาใน header/cookie ได้เต็มที่ (ASGI decode เป็น latin-1
            # ไบต์ >0x7F จึงกลายเป็นอักขระนอก ASCII) ทำให้ทุก POST ที่แนบค่าแบบนั้นได้ 500
            # พร้อม traceback แทนที่จะโดนปฏิเสธด้วย 403 ตามปกติ
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
        #
        # เงื่อนไขคือ "ยังไม่มี **หรือมีแต่ใช้ไม่ได้แล้ว**" ไม่ใช่แค่ "ยังไม่มี"
        #
        # ⚠️ ของเดิมออก cookie ให้เฉพาะตอนที่ยังไม่มี cookie เลย -> cookie ที่ค้างอยู่แต่ verify
        #    ไม่ผ่านจะไม่มีวันถูกแทน ผู้ใช้ติดหล่ม 403 ทุก POST จนกว่าจะไปลบ cookie เอง ทั้งที่
        #    ข้อความ error บอกให้ "รีเฟรชหน้าแล้วลองใหม่" ซึ่งรีเฟรชกี่ครั้งก็ไม่มีทางหาย
        #    เจอจริงตอน **ติดตั้งใหม่ทับของเดิม**: .env ใบใหม่ได้ CSRF_SECRET ที่สุ่มใหม่ แต่เบราว์เซอร์
        #    ยังถือ cookie ที่เซ็นด้วย secret เก่า (โดเมน/พอร์ตเดิม อายุ cookie = JWT_EXPIRE_MIN นาที)
        #    -> `POST /api/login` โดน 403 = **ล็อกอินเข้าระบบที่เพิ่งลงเสร็จไม่ได้เลย**
        #    อีกเคสคือ cookie หมดอายุระหว่างเปิดหน้าค้างไว้ ซึ่งก็ค้างแบบเดียวกัน
        #
        # cookie ที่ยัง verify ผ่านจะไม่ถูกแตะ — ยัง race-free เหมือนเดิม (GET พร้อมกันหลายเส้น
        # ไม่แย่งกันออก token ใหม่ทับของที่ใช้งานได้อยู่) ส่วนใบที่ใช้ไม่ได้แล้วยังไงก็ต้องทิ้ง
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
