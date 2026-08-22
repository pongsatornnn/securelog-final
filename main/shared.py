

"""
Instance ที่ต้องใช้ร่วมกันระหว่าง main.py กับ routes/*.py
แยกมาไว้ที่นี่เพื่อกัน circular import (main.py include routers, routers ก็ต้องใช้ instance เดียวกันนี้)
"""

from datetime import datetime
from pathlib import Path

from fastapi.templating import Jinja2Templates
from slowapi import Limiter
from slowapi.util import get_remote_address



BASE_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def static_url(path: str) -> str:
    """
    URL ของไฟล์ static + `?v=<mtime>` เพื่อ bust cache ของ browser

    เดิมใช้ `url_for('static', path=...)` เฉย ๆ ซึ่งไม่มีเลขเวอร์ชัน — พอ deploy ทับ
    browser ที่ cache css/js เก่าไว้จะใช้ของเก่าต่อจนกว่าจะ hard refresh
    ใช้ mtime ต่อไฟล์ (ไม่ใช่เวอร์ชันรวม) เพื่อให้ไฟล์ที่ไม่ได้แก้ยัง cache ได้ตามเดิม
    """
    try:
        version = int((STATIC_DIR / path).stat().st_mtime)
    except OSError:
        version = 0

    return f"/static/{path}?v={version}"


templates.env.globals["static_url"] = static_url

limiter = Limiter(key_func=get_remote_address)


def iso_utc(dt: datetime | None) -> str | None:
    """
    เซิร์ฟเวอร์รันเวลาแบบ UTC และ DB เก็บ datetime.now() แบบ naive (ไม่มี timezone)
    ต่อ "Z" ให้ตอน serialize เพื่อบอก frontend ชัดเจนว่าค่านี้คือ UTC
    ไม่งั้น JS `new Date(...)` จะตีความ string ที่ไม่มี timezone เป็นเวลา local ของ browser เอง ทำให้เวลาที่แสดงผิด
    """
    return dt.isoformat() + "Z" if dt else None
