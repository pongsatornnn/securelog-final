

# Instance ที่ต้องใช้ร่วมกันระหว่าง main.py กับ routes/*.py

from datetime import datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address

from base_path import BASE_PATH, with_base, cookie_name, RELATIVE_URLS



BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def static_url(path: str) -> str:
    # URL ของไฟล์ static + `?v=<mtime>` เพื่อ bust cache ของ browser
    try:
        version = int((STATIC_DIR / path).stat().st_mtime)
    except OSError:
        version = 0

    if RELATIVE_URLS:
        # URL สัมพัทธ์กับหน้าที่กำลังเปิดอยู่ — browser เติม prefix ของ proxy ให้เอง
        return f"static/{path}?v={version}"

    return with_base(f"/static/{path}?v={version}")


def url(path: str) -> str:
    # ลิงก์ที่ template สร้าง — โหมดปกติเติม prefix ให้ · โหมด relative คืนแบบสัมพัทธ์
    # (หน้าเว็บทุกหน้าอยู่ชั้นเดียวกัน ลิงก์ "dashboard" จาก /xxx/agents จึงได้ /xxx/dashboard)
    if RELATIVE_URLS:
        return path.lstrip("/")
    return with_base(path)


templates.env.globals["static_url"] = static_url
templates.env.globals["url"] = url
# prefix ของเว็บ (ROOT_PATH) ให้ template เอาไปต่อหน้า URL เอง เช่น href="{{ base_path }}/agents"
templates.env.globals["base_path"] = BASE_PATH
# ชื่อ cookie csrf เปลี่ยนตาม prefix — csrf.js ต้องรู้ว่าจะอ่านใบไหน
templates.env.globals["csrf_cookie_name"] = "" if RELATIVE_URLS else cookie_name("csrf_token")

limiter = Limiter(key_func=get_remote_address)


def iso_utc(dt: datetime | None) -> str | None:
    # เซิร์ฟเวอร์รันเวลาแบบ UTC และ DB เก็บ datetime.now() แบบ naive (ไม่มี timezone)
    return dt.isoformat() + "Z" if dt else None
