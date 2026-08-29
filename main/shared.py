

"""Instance ที่ต้องใช้ร่วมกันระหว่าง main.py กับ routes/*.py"""

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
    """URL ของไฟล์ static + `?v=<mtime>` เพื่อ bust cache ของ browser"""
    try:
        version = int((STATIC_DIR / path).stat().st_mtime)
    except OSError:
        version = 0

    return f"/static/{path}?v={version}"


templates.env.globals["static_url"] = static_url

limiter = Limiter(key_func=get_remote_address)


def iso_utc(dt: datetime | None) -> str | None:
    """เซิร์ฟเวอร์รันเวลาแบบ UTC และ DB เก็บ datetime.now() แบบ naive (ไม่มี timezone)"""
    return dt.isoformat() + "Z" if dt else None
