"""หน้า error ของระบบ — แปลง HTTPException/exception ที่หลุดออกมา ให้เป็น"""

import logging

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from shared import templates


logger = logging.getLogger("securelog.errors")


# ข้อความของ 500 ฝั่ง JSON — บั๊กภายในไม่มี detail ให้ส่งต่อ และห้ามส่ง traceback ออกไป
INTERNAL_ERROR_DETAIL = "ระบบทำงานผิดพลาดระหว่างประมวลผลคำขอนี้"


def _wants_html(request: Request) -> bool:
    """หน้าเว็บ (browser navigation) รับ HTML ส่วน fetch ของ frontend เรียกแต่ /api/* และรับ JSON"""
    path = request.url.path

    if path.startswith("/api/") or path.startswith("/line/webhook"):
        return False

    return "text/html" in request.headers.get("accept", "")


def _render_error(request: Request, status_code: int):
    # หน้า error แสดงแค่หมายเลข status — ไม่บอกสาเหตุหรือคำแนะนำใด ๆ ออกไปฝั่งผู้ใช้
    return templates.TemplateResponse(
        request,
        "error.html",
        {"status_code": status_code},
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
    """บั๊กที่หลุดออกมาถึงตรงนี้ = 500 — เขียน traceback ลง log ฝั่งเซิร์ฟเวอร์ให้ครบ"""
    logger.exception("unhandled error ที่ %s %s", request.method, request.url.path)

    if _wants_html(request):
        return _render_error(request, 500)

    return JSONResponse(
        status_code=500,
        content={"detail": INTERNAL_ERROR_DETAIL},
    )


def register_error_handlers(app):
    app.add_exception_handler(StarletteHTTPException, http_exception_handler)
    app.add_exception_handler(Exception, unhandled_exception_handler)
