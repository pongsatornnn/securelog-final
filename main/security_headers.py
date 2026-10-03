# header ความปลอดภัยที่ใส่ให้ทุก response ของ dashboard
#
# - X-Frame-Options + CSP frame-ancestors: ห้ามเว็บอื่นฝังหน้า dashboard ใน iframe (กัน clickjacking —
#   หลอกให้แอดมินกดปุ่มปลด block / เพิ่ม whitelist ผ่านหน้าเว็บที่ซ้อนทับไว้)
# - CSP ส่วนอื่นตั้งเฉพาะที่ไม่กระทบหน้าเว็บเดิม: ห้าม <object>/<embed>, ห้ามเปลี่ยน <base>, ฟอร์มส่งได้แค่เว็บเราเอง
#   (ยังไม่จำกัด script-src — template มี inline script และ Alpine ต้องใช้ eval ถ้าล็อกจะทำหน้าเว็บพัง)
# - nosniff: browser ต้องเชื่อ Content-Type ไม่เดาชนิดไฟล์เอง
# - Referrer-Policy: ไม่ส่ง URL ของ dashboard (มี path/ตัวกรอง) ไปให้เว็บภายนอก
# ไม่ใส่ HSTS — เข้าด้วย IP + cert ที่ออกเอง browser ไม่จำ HSTS ของ IP อยู่แล้ว
# header "server: uvicorn" ตัดที่ unit (--no-server-header ใน systemd/_gen.sh) ไม่ใช่ที่นี่

SECURITY_HEADERS = [
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy", b"frame-ancestors 'none'; base-uri 'self'; object-src 'none'; form-action 'self'"),
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"same-origin"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
]
_NAMES = {name for name, _ in SECURITY_HEADERS}


class SecurityHeadersMiddleware:
    # ASGI ล้วน (ไม่ใช้ BaseHTTPMiddleware) — แก้แค่ header ตอนเริ่มส่ง ไม่ไปแตะ body
    # สตรีมแจ้งเตือนสด (SSE) จึงยังไหลได้ตามปกติ
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message):
            if message["type"] == "http.response.start":
                headers = [h for h in message.get("headers", []) if h[0].lower() not in _NAMES]
                message["headers"] = headers + SECURITY_HEADERS
            await send(message)

        await self.app(scope, receive, send_with_headers)
