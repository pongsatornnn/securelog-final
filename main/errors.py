

import logging

from fastapi import Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from shared import templates
from base_path import strip_base, RELATIVE_URLS, LINE_WEBHOOK_PATH


logger = logging.getLogger("securelog.errors")


INTERNAL_ERROR_DETAIL = "ระบบทำงานผิดพลาดระหว่างประมวลผลคำขอนี้"


DB_DOWN_DETAIL = "ติดต่อฐานข้อมูลไม่ได้ — ตรวจว่า PostgreSQL ตามที่ตั้งไว้ใน .env (DB_HOST/DB_PORT) ยังทำงานอยู่"


def _is_db_unreachable(exc: BaseException) -> bool:

    seen: set[int] = set()

    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))


        if isinstance(exc, (OSError, TimeoutError)):
            return True

        exc = exc.__cause__ or exc.__context__

    return False


def _wants_html(request: Request) -> bool:

    path = strip_base(request.url.path)


    if path.startswith("/api/") or path.rstrip("/") == LINE_WEBHOOK_PATH:
        return False

    return "text/html" in request.headers.get("accept", "")


def _asset_prefix(request: Request) -> str:


    if not RELATIVE_URLS:
        return ""
    depth = max(len([s for s in request.url.path.split("/") if s]) - 1, 0)
    return "../" * depth


def _render_error(request: Request, status_code: int):

    return templates.TemplateResponse(
        request,
        "error.html",
        {"status_code": status_code, "asset_prefix": _asset_prefix(request)},
        status_code=status_code,
    )


async def http_exception_handler(request: Request, exc: StarletteHTTPException):

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

    logger.exception("unhandled error ที่ %s %s", request.method, request.url.path)


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
