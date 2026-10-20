


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

    try:
        version = int((STATIC_DIR / path).stat().st_mtime)
    except OSError:
        version = 0

    if RELATIVE_URLS:

        return f"static/{path}?v={version}"

    return with_base(f"/static/{path}?v={version}")


def url(path: str) -> str:


    if RELATIVE_URLS:
        return path.lstrip("/")
    return with_base(path)


templates.env.globals["static_url"] = static_url
templates.env.globals["url"] = url

templates.env.globals["base_path"] = BASE_PATH

templates.env.globals["csrf_cookie_name"] = "" if RELATIVE_URLS else cookie_name("csrf_token")

limiter = Limiter(key_func=get_remote_address)


def iso_utc(dt: datetime | None) -> str | None:

    return dt.isoformat() + "Z" if dt else None
