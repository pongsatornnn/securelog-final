# เส้นทางหน้าเว็บที่ต้อง login (render HTML template อย่างเดียว ไม่มี logic ทางธุรกิจ)

from fastapi import APIRouter, Request, Depends
from fastapi.responses import HTMLResponse, RedirectResponse

from dependencies import require_login_page, require_admin_page
from shared import templates


router = APIRouter()


@router.get("/dashboard", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user=Depends(require_login_page),
):
    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "user": user,
            "page": "dashboard",
        },
    )


@router.get("/alerts", response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    user=Depends(require_login_page),
):
    return templates.TemplateResponse(
        request=request,
        name="alerts.html",
        context={
            "user": user,
            "page": "alerts",
        },
    )


@router.get("/agents", response_class=HTMLResponse)
async def agents_page(
    request: Request,
    user=Depends(require_login_page),
):
    return templates.TemplateResponse(
        request=request,
        name="agents.html",
        context={
            "user": user,
            "page": "agents",
        },
    )


@router.get("/ipblacklist", response_class=HTMLResponse)
async def ip_blacklist_page(request: Request, user=Depends(require_login_page)):
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="blacklist.html",
        context={"user": user, "page": "blacklist"})


@router.get("/whitelist", response_class=HTMLResponse)
async def ip_whitelist_page(request: Request, user=Depends(require_login_page)):
    if isinstance(user, RedirectResponse):
        return user
    return templates.TemplateResponse(
        request=request,
        name="whitelist.html",
        context={"user": user, "page": "whitelist"})


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request, user=Depends(require_admin_page)):
    return templates.TemplateResponse(
        request=request,
        name="rules.html",
        context={"user": user, "page": "rules"},
    )


@router.get("/signatures", response_class=HTMLResponse)
async def signatures_page(request: Request, user=Depends(require_admin_page)):
    return templates.TemplateResponse(
        request=request,
        name="signatures.html",
        context={"user": user, "page": "signatures"},
    )


@router.get("/line-recipients", response_class=HTMLResponse)
async def line_recipients_page(request: Request, user=Depends(require_admin_page)):
    return templates.TemplateResponse(
        request=request,
        name="line_recipients.html",
        context={"user": user, "page": "line_recipients"},
    )


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, user=Depends(require_admin_page)):
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"user": user, "page": "settings"},
    )


@router.get("/manage-users", response_class=HTMLResponse)
async def manage_users_page(request: Request, user=Depends(require_admin_page)):
    return templates.TemplateResponse(
        request=request,
        name="manage_users.html",
        context={"user": user, "page": "manage_users"},
    )
