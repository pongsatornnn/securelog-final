# หน้า error ของระบบ — แปลง HTTPException/exception ที่หลุดออกมา ให้เป็น

import logging

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from shared import templates
from base_path import strip_base, RELATIVE_URLS


logger = logging.getLogger("securelog.errors")


# ข้อความของ 500 ฝั่ง JSON — บั๊กภายในไม่มี detail ให้ส่งต่อ และห้ามส่ง traceback ออกไป
INTERNAL_ERROR_DETAIL = "ระบบทำงานผิดพลาดระหว่างประมวลผลคำขอนี้"

# ต่อฐานข้อมูลไม่ติด (postgres ดับ / ย้ายเครื่องแล้ว DB_HOST ยังชี้ที่เดิม / ไฟร์วอลล์ปิด) ไม่ใช่บั๊ก
# ของแอป — ของเดิมตอบ 500 ข้อความกลาง ๆ เหมือนกันหมด แอดมินต้องไปไล่ดู log เองถึงจะรู้ว่าติดที่ฐาน
DB_DOWN_DETAIL = "ติดต่อฐานข้อมูลไม่ได้ — ตรวจว่า PostgreSQL ตามที่ตั้งไว้ใน .env (DB_HOST/DB_PORT) ยังทำงานอยู่"


def _is_db_unreachable(exc: BaseException) -> bool:
    # ไล่ตามสายเหตุ (__cause__/__context__) หา error ระดับ socket — asyncpg/sqlalchemy ห่อไว้อีกที
    seen: set[int] = set()

    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))

        # ConnectionRefusedError / gaierror / ENETUNREACH ฯลฯ ล้วนเป็น OSError ทั้งหมด
        if isinstance(exc, (OSError, TimeoutError)):
            return True

        exc = exc.__cause__ or exc.__context__

    return False


def _wants_html(request: Request) -> bool:
    # หน้าเว็บ (browser navigation) รับ HTML ส่วน fetch ของ frontend เรียกแต่ /api/* และรับ JSON
    path = strip_base(request.url.path)

    if path.startswith("/api/") or path.startswith("/line/webhook"):
        return False

    return "text/html" in request.headers.get("accept", "")


def _asset_prefix(request: Request) -> str:
    # โหมด relative: หน้า error โผล่ที่ path ลึกแค่ไหนก็ได้ (เช่น /a/b/c ที่ไม่มีจริง)
    # ต้องถอยขึ้นให้ static ชี้ถูก ไม่งั้นหน้า error จะโหลด css ไม่ขึ้น
    if not RELATIVE_URLS:
        return ""
    depth = max(len([s for s in request.url.path.split("/") if s]) - 1, 0)
    return "../" * depth


def _render_error(request: Request, status_code: int):
    # หน้า error แสดงแค่หมายเลข status — ไม่บอกสาเหตุหรือคำแนะนำใด ๆ ออกไปฝั่งผู้ใช้
    return templates.TemplateResponse(
        request,
        "error.html",
        {"status_code": status_code, "asset_prefix": _asset_prefix(request)},
        status_code=status_code,
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # redirect ของ auth (303 + Location) ต้องทำงานเหมือนเดิม ห้ามกลายเป็นหน้า error
    location = (exc.headers or {}).get("Location")
    if 300 <= exc.status_code < 400 and location:
        return RedirectResponse(url=location, status_code=exc.status_code)

    if _wants_html(request):
        return _render_error(request, exc.status_code)

    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=exc.headers,
    )


async def unhandled_exception_handler(request: Request, exc: Exception):
    # บั๊กที่หลุดออกมาถึงตรงนี้ = 500 — เขียน traceback ลง log ฝั่งเซิร์ฟเวอร์ให้ครบ
    logger.exception("unhandled error ที่ %s %s", request.method, request.url.path)

    # ฐานข้อมูลต่อไม่ติด = 503 (ปลายทางไม่พร้อม) พร้อมบอกว่าให้ไปดูตรงไหน ไม่ใช่ 500 เหมือนบั๊กทั่วไป
    if _is_db_unreachable(exc):
        status_code, detail = 503, DB_DOWN_DETAIL
    else:
        status_code, detail = 500, INTERNAL_ERROR_DETAIL

    if _wants_html(request):
        return _render_error(request, status_code)

    return JSONResponse(
        status_code=status_code,
        content={"detail": detail},
    )


def register_error_handlers(app):
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
