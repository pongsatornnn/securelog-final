# บัญชี View — บัญชีเบื้องหลังที่ระบบสร้างให้เอง ใช้ดู Dashboard / Alerts ได้อย่างเดียว
#
# - ไม่มีรหัสผ่านที่ใครรู้ (hash ของค่าสุ่ม) login ด้วยฟอร์มชื่อ/รหัสไม่ได้ — เข้าได้ทางเดียวคือปุ่ม View
#   ที่หน้า login (POST /api/login/view) และเฉพาะตอนที่บัญชีเปิดใช้งานอยู่
# - ค่าเริ่มต้น "ปิด" — admin เริ่มต้นเปิด/ปิดได้ที่หน้า Manage Users · ปิดแล้ว session ที่ค้างอยู่ตายทันที
#   (require_login เช็ค is_active จาก DB ทุก request)
# - ไม่โผล่ในรายชื่อ user และ reset รหัส / ลบ / แก้ผ่านหน้า Manage Users ไม่ได้
# - สิทธิ์แบบ "ห้ามทุกอย่าง ยกเว้นที่อนุญาต" (VIEW_ALLOWED) — endpoint ที่เพิ่มในอนาคตถูกกันไว้ก่อนเสมอ
#
# แยกบัญชีนี้ด้วย role = "viewer" (คอลัมน์ users.role ที่เหลือจากระบบ role เดิม) ไม่ใช่ด้วยชื่อ

import re
import secrets

VIEW_USERNAME = "view"
VIEW_ROLE = "viewer"
VIEW_DISPLAY_NAME = "View mode"

# (method, path ที่ตัด ROOT_PATH ออกแล้ว) ที่บัญชี View เรียกได้ — นอกนั้นปฏิเสธหมด
VIEW_ALLOWED = {
    ("GET", "/dashboard"),
    ("GET", "/alerts"),
    ("GET", "/api/alerts"),
    ("GET", "/api/alerts_filter_options"),
    ("GET", "/api/alerts_unread_count"),
    # บัญชี View ถือว่า "อ่านแล้วทั้งหมด" (ใช้ร่วมกันหลายจอ สถานะอ่านแล้วร่วมกันไม่มีความหมาย)
    # GET ตอบว่าอ่านแล้วทุกตัว · ไม่มี POST — บัญชี View จึงไม่เขียนอะไรลง DB เลย
    ("GET", "/api/alerts_read_state"),
    ("GET", "/api/stream/alerts"),
    # Dashboard ใช้นับจำนวน Client Server ที่ออนไลน์
    ("GET", "/api/agents"),
}

# รายละเอียด alert รายตัว (/api/alerts/123) — ไม่รวม /api/alerts/123/ai-summary (กดวิเคราะห์ AI ไม่ได้)
_ALERT_DETAIL_RE = re.compile(r"/api/alerts/\d+")


def is_view_role(role: str | None) -> bool:
    return role == VIEW_ROLE


def view_may(method: str, path: str) -> bool:
    method = method.upper()
    path = path.rstrip("/") or "/"

    if (method, path) in VIEW_ALLOWED:
        return True

    return method == "GET" and bool(_ALERT_DETAIL_RE.fullmatch(path))


def unusable_password() -> str:
    # ค่าสุ่มที่ไม่มีใครรู้ — เก็บแค่ hash ของมันลง DB จึงไม่มีรหัสไหน login ด้วยฟอร์มได้
    # (authenticate_user_db ปฏิเสธ role นี้อีกชั้นอยู่แล้ว)
    return secrets.token_urlsafe(48)
