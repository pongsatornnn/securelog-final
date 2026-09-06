# URL prefix ของทั้งเว็บ (root path) — ตั้งค่าที่ ROOT_PATH ใน .env เช่น ROOT_PATH=/securelog
# ค่าว่าง = เสิร์ฟที่รากเหมือนเดิม ไม่มีอะไรเปลี่ยน

import os
import re

from dotenv import load_dotenv

load_dotenv()


def _normalize(raw: str) -> str:
    # รับได้ทุกแบบที่คนพิมพ์จริง: "xxx" / "/xxx" / "/xxx/" / "//a//b//" -> "/xxx", "/a/b"
    # ค่าว่างหรือ "/" ถือว่าไม่ใช้ prefix
    value = (raw or "").strip().strip('"').strip("'")
    parts = [p for p in value.split("/") if p]
    return "/" + "/".join(parts) if parts else ""


BASE_PATH = _normalize(os.getenv("ROOT_PATH", ""))

# true = มี reverse proxy ตัด prefix ออกให้ก่อนส่งมาถึงแล้ว (nginx `proxy_pass .../;`)
# app จึงรับ path แบบไม่มี prefix เหมือนเดิม แต่ URL ที่ส่งออกไปหา browser ยังต้องมี prefix
STRIPPED_BY_PROXY = os.getenv("ROOT_PATH_STRIPPED", "").strip().lower() in ("1", "true", "yes")

# cookie ผูกกับ prefix: browser ส่ง cookie ของเราไปเฉพาะ URL ที่อยู่ใต้ prefix
# ไม่หลุดไปหา service อื่นที่แชร์โฮสต์+พอร์ตเดียวกัน (nginx หลาย service พอร์ตเดียว)
COOKIE_PATH = BASE_PATH or "/"

# path ที่เวอร์ชันก่อนหน้า (ตอนยังเสิร์ฟที่ราก) ใช้ตั้ง cookie ไว้ — ไว้ล้างของค้าง
LEGACY_COOKIE_PATH = "/"


def _cookie_suffix(raw: str) -> str:
    # "/xxx" -> "_xxx" · "/a/b" -> "_a_b" · "" -> "" (อักขระที่ใช้ในชื่อ cookie ไม่ได้ -> _)
    slug = re.sub(r"[^A-Za-z0-9_-]", "_", (raw or "").strip().strip("/").replace("/", "_"))
    slug = slug.strip("_")
    return "_" + slug if slug else ""


# ชื่อของระบบนี้ — ใช้ต่อท้าย cookie เมื่อเสิร์ฟที่ราก (ไม่มี prefix ให้เอามาตั้งชื่อ)
APP_NAME = "securelog"

# ต่อท้ายชื่อ cookie ให้ไม่ซ้ำกับ service อื่นเสมอ:
#   มี prefix  -> เอาจาก prefix   (/xxx      -> access_token_xxx)
#   อยู่ที่ราก -> เอาชื่อระบบ      (ROOT_PATH="" -> access_token_securelog)
# เหตุผล: browser ส่ง cookie ชื่อซ้ำมาให้ทั้งของเราและของ service อื่นที่แชร์โฮสต์+พอร์ตกัน
# แล้วฝั่ง server อ่านใบท้ายสุดชนะ — ถ้าชื่อไม่ซ้ำตั้งแต่แรกก็ไม่มีทางทับกันได้
# ตั้งเองก็ได้ (COOKIE_SUFFIX=prod) · ตั้งเป็น off/none = ใช้ชื่อเดิมล้วน ๆ ไม่เติมอะไร
_RAW_COOKIE_SUFFIX = (os.getenv("COOKIE_SUFFIX") or "").strip()

if _RAW_COOKIE_SUFFIX.lower() in ("off", "none", "no", "false", "0"):
    COOKIE_SUFFIX = ""
elif _RAW_COOKIE_SUFFIX:
    COOKIE_SUFFIX = _cookie_suffix(_RAW_COOKIE_SUFFIX)
else:
    COOKIE_SUFFIX = _cookie_suffix(BASE_PATH) or _cookie_suffix(APP_NAME)


# ชื่อตั้งต้นของ cookie ทั้งสองใบ (ตัวจริงคือชื่อนี้ + suffix ตาม prefix)
AUTH_COOKIE_BASE = "access_token"
CSRF_COOKIE_BASE = "csrf_token"


def cookie_name(name: str) -> str:
    # path ช่วยแค่ตอน "ส่ง" — ตอนอ่าน browser ส่ง cookie ชื่อซ้ำมาให้ทั้งของเราและของ service อื่น
    # (คนละ path) แล้ว starlette อ่านใบท้ายสุดชนะ ชื่อจึงต้องไม่ซ้ำกันตั้งแต่แรก
    return name + COOKIE_SUFFIX


# ---------------------------------------------------------------------------
# โหมด relative: หน้าเว็บใช้ URL แบบสัมพัทธ์ทั้งหมด (browser เป็นคนประกอบ prefix ให้)
# app จึงไม่ต้องรู้ prefix ของตัวเอง — ใช้คู่กับ proxy ที่ "ตัด prefix ออกให้แล้ว" เท่านั้น
# ย้าย service ไป prefix ไหนก็แค่แก้ที่ nginx ไม่ต้องแตะ .env ไม่ต้อง restart
#
# ข้อยกเว้นที่ browser ช่วยไม่ได้คือ cookie (ต้องระบุ Path/ชื่อจากฝั่ง server) จึงให้ proxy
# บอก prefix มาทาง header X-Forwarded-Prefix — ไม่ส่งมาก็ยังทำงานได้ แค่ cookie จะกลับไป
# อยู่ที่ราก (ชนกับ service อื่นที่ใช้ชื่อ cookie เดียวกันได้)
RELATIVE_URLS = os.getenv("RELATIVE_URLS", "").strip().lower() in ("1", "true", "yes")

PREFIX_HEADER = "x-forwarded-prefix"


def request_prefix(request) -> str:
    # prefix ที่ browser เห็นอยู่จริงสำหรับ request นี้
    if not RELATIVE_URLS:
        return BASE_PATH
    return _normalize(request.headers.get(PREFIX_HEADER, ""))


def cookie_path_for(request) -> str:
    return request_prefix(request) or "/"


def cookie_name_for(request, name: str) -> str:
    if not RELATIVE_URLS or _RAW_COOKIE_SUFFIX:
        return cookie_name(name)  # ตั้ง COOKIE_SUFFIX เองไว้ = ใช้ค่านั้นทุก request
    # proxy ไม่ได้บอก prefix มา = เท่ากับอยู่ที่ราก -> ใช้ชื่อระบบเหมือนโหมดปกติ
    return name + (_cookie_suffix(request_prefix(request)) or _cookie_suffix(APP_NAME))


def rel_url(request, target: str) -> str:
    # URL ที่ส่งกลับไปให้ browser (Location ของ redirect เป็นหลัก)
    # โหมดปกติ = เติม prefix ตรง ๆ · โหมด relative = นับความลึกของ path ที่ request เข้ามา
    # แล้วถอยขึ้นเท่านั้นชั้น ("/api/logout" -> "../login") ให้ browser ประกอบกับ prefix เอง
    if not RELATIVE_URLS:
        return with_base(target)
    depth = max(len([s for s in request.url.path.split("/") if s]) - 1, 0)
    return "../" * depth + target.lstrip("/")


def with_base(path: str) -> str:
    # "/login" -> "/securelog/login" (ใช้กับ URL ที่ส่งออกไปให้ browser)
    if not BASE_PATH:
        return path
    return BASE_PATH + path


def strip_base(path: str) -> str:
    # "/securelog/api/x" -> "/api/x" (ใช้ตอนเทียบ path ที่ request ส่งเข้ามา)
    if not BASE_PATH:
        return path
    if path == BASE_PATH:
        return "/"
    if path.startswith(BASE_PATH + "/"):
        return path[len(BASE_PATH):]
    return path
