

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_all_line_recipients,
    upsert_pending_line_recipient,
    get_line_recipient_by_user_id,
    set_line_recipient_status,
    delete_line_recipient,
)
from base_path import LINE_WEBHOOK_PATH
from dependencies import require_admin
from shared import iso_utc

from settings_cache import ensure_loaded

from LINE_API import config as line_config, line_client


router = APIRouter()


webhook_router = APIRouter()


@webhook_router.post(LINE_WEBHOOK_PATH)
async def line_webhook(request: Request, db: AsyncSession = Depends(get_db)):

    await ensure_loaded()

    body = await request.body()
    signature = request.headers.get("X-Line-Signature")


    if not line_client.verify_signature(body, signature):
        raise HTTPException(status_code=403, detail="invalid signature")

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid body")

    for event in payload.get("events", []):
        event_type = event.get("type")
        source = event.get("source", {})
        user_id = source.get("userId")

        if not user_id:
            continue

        if event_type == "unfollow":
            recipient = await get_line_recipient_by_user_id(db, user_id)
            if recipient:
                await set_line_recipient_status(db, recipient.id, "rejected")
            continue


        existing = await get_line_recipient_by_user_id(db, user_id)
        display_name = existing.display_name if existing else None
        picture_url = existing.picture_url if existing else None


        if display_name is None or picture_url is None:
            profile = line_client.get_profile(user_id)

            if profile:
                display_name = profile.get("displayName") or display_name

                picture_url = profile.get("pictureUrl") or ""

        await upsert_pending_line_recipient(db, user_id, display_name, picture_url)


    return {"status": "ok"}


def _serialize(recipient) -> dict:
    return {
        "id": recipient.id,
        "line_user_id": recipient.line_user_id,
        "display_name": recipient.display_name,

        "picture_url": recipient.picture_url or None,
        "status": recipient.status,
        "created_at": iso_utc(recipient.created_at),
        "updated_at": iso_utc(recipient.updated_at),
        "approved_at": iso_utc(recipient.approved_at) if recipient.approved_at else None,
    }


@router.get("/api/line/oa")
async def api_line_oa(user=Depends(require_admin)):

    await ensure_loaded()

    oa_id = (line_config.oa_id() or "").strip()


    link_id = oa_id if oa_id.startswith("@") else f"@{oa_id}"

    return {
        "oa_id": oa_id,
        "add_friend_url": f"https://line.me/R/ti/p/{link_id}" if oa_id else None,
    }


@router.get("/api/line/recipients")
async def api_list_recipients(
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    recipients = await get_all_line_recipients(db)
    return [_serialize(r) for r in recipients]


@router.post("/api/line/recipients/{recipient_id}/approve")
async def api_approve_recipient(
    recipient_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await set_line_recipient_status(db, recipient_id, "approved")
    if not result:
        raise HTTPException(status_code=404, detail=f"ไม่พบผู้รับ id={recipient_id}")
    return {"status": "ok", "recipient": _serialize(result)}


@router.post("/api/line/recipients/{recipient_id}/reject")
async def api_reject_recipient(
    recipient_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await set_line_recipient_status(db, recipient_id, "rejected")
    if not result:
        raise HTTPException(status_code=404, detail=f"ไม่พบผู้รับ id={recipient_id}")
    return {"status": "ok", "recipient": _serialize(result)}


@router.delete("/api/line/recipients/{recipient_id}")
async def api_delete_recipient(
    recipient_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await delete_line_recipient(db, recipient_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"ไม่พบผู้รับ id={recipient_id}")
    return {"status": "ok"}
