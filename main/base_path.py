


import os
import re

from dotenv import load_dotenv

load_dotenv()


def _normalize(raw: str) -> str:


    value = (raw or "").strip().strip('"').strip("'")
    parts = [p for p in value.split("/") if p]
    return "/" + "/".join(parts) if parts else ""


BASE_PATH = _normalize(os.getenv("ROOT_PATH", ""))


STRIPPED_BY_PROXY = os.getenv("ROOT_PATH_STRIPPED", "").strip().lower() in ("1", "true", "yes")


COOKIE_PATH = BASE_PATH or "/"


LEGACY_COOKIE_PATH = "/"


def _cookie_suffix(raw: str) -> str:

    slug = re.sub(r"[^A-Za-z0-9_-]", "_", (raw or "").strip().strip("/").replace("/", "_"))
    slug = slug.strip("_")
    return "_" + slug if slug else ""


LINE_WEBHOOK_PATH = _normalize(os.getenv("LINE_WEBHOOK_PATH", "")) or "/line/webhook"


APP_NAME = "securelog"


_RAW_COOKIE_SUFFIX = (os.getenv("COOKIE_SUFFIX") or "").strip()

if _RAW_COOKIE_SUFFIX.lower() in ("off", "none", "no", "false", "0"):
    COOKIE_SUFFIX = ""
elif _RAW_COOKIE_SUFFIX:
    COOKIE_SUFFIX = _cookie_suffix(_RAW_COOKIE_SUFFIX)
else:
    COOKIE_SUFFIX = _cookie_suffix(BASE_PATH) or _cookie_suffix(APP_NAME)


AUTH_COOKIE_BASE = "access_token"
CSRF_COOKIE_BASE = "csrf_token"


def cookie_name(name: str) -> str:


    return name + COOKIE_SUFFIX


RELATIVE_URLS = os.getenv("RELATIVE_URLS", "").strip().lower() in ("1", "true", "yes")

PREFIX_HEADER = "x-forwarded-prefix"


def request_prefix(request) -> str:

    if not RELATIVE_URLS:
        return BASE_PATH
    return _normalize(request.headers.get(PREFIX_HEADER, ""))


def cookie_path_for(request) -> str:
    return request_prefix(request) or "/"


def cookie_name_for(request, name: str) -> str:
    if not RELATIVE_URLS or _RAW_COOKIE_SUFFIX:
        return cookie_name(name)  # ตั้ง COOKIE_SUFFIX เองไว้ = ใช้ค่านั้นทุก request

    return name + (_cookie_suffix(request_prefix(request)) or _cookie_suffix(APP_NAME))


def rel_url(request, target: str) -> str:


    if not RELATIVE_URLS:
        return with_base(target)
    depth = max(len([s for s in request.url.path.split("/") if s]) - 1, 0)
    return "../" * depth + target.lstrip("/")


def with_base(path: str) -> str:

    if not BASE_PATH:
        return path
    return BASE_PATH + path


def strip_base(path: str) -> str:

    if not BASE_PATH:
        return path
    if path == BASE_PATH:
        return "/"
    if path.startswith(BASE_PATH + "/"):
        return path[len(BASE_PATH):]
    return path
