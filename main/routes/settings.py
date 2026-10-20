

import asyncio
import hmac
import re

from fastapi import APIRouter, Depends, HTTPException

from dependencies import require_admin
from redis_admin_password import (
    RotationError,
    generate_password,
    preflight,
    rotate_admin_password,
    validate_password,
)
from service_status import restart_status
from settings_cache import (
    SETTING_DEFS,
    all_settings_for_admin,
    ensure_loaded,
    get_setting_async,
    log_external_setting_change,
    setting_history,
    setting_page,
    update_setting,
)
from shared import iso_utc

from schemas.settings_schema import RotateRedisAdminPasswordRequest, UpdateSettingsRequest


router = APIRouter()


@router.get("/api/settings")
async def api_get_settings(user=Depends(require_admin)):

    items = await all_settings_for_admin()

    return {
        "items": [
            {
                **item,
                "updated_at": iso_utc(item["updated_at"]) if item["updated_at"] else None,
                "last_changed_at": iso_utc(item["last_changed_at"]) if item["last_changed_at"] else None,
            }
            for item in items
        ],
    }


async def _check_protected_values(payload: UpdateSettingsRequest) -> None:

    for key, value in payload.values.items():
        spec = SETTING_DEFS[key]

        if spec.get("confirm_current"):
            current = await get_setting_async(key)

            if current and not hmac.compare_digest(
                payload.current_values.get(key, "").encode("utf-8"), current.encode("utf-8")
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"{spec['label']}: รหัสเดิมไม่ถูกต้อง",
                )

        if spec.get("password_rules"):
            try:
                validate_password(value)
            except ValueError as e:
                raise HTTPException(status_code=400, detail=f"{spec['label']}: {e}")


        pattern = spec.get("pattern")
        if pattern and not re.fullmatch(pattern, value or ""):
            raise HTTPException(
                status_code=400,
                detail=f"{spec['label']}: {spec['pattern_error']}",
            )


@router.post("/api/settings")
async def api_update_settings(
    payload: UpdateSettingsRequest,
    user=Depends(require_admin),
):

    unknown = [key for key in payload.values if key not in SETTING_DEFS]
    if unknown:
        raise HTTPException(status_code=404, detail=f"ไม่รู้จักค่าตั้ง: {', '.join(unknown)}")


    foreign = [key for key in payload.values if setting_page(key) != "settings"]
    if foreign:
        raise HTTPException(
            status_code=400,
            detail=f"ค่าเหล่านี้ตั้งจากหน้าอื่น ไม่ใช่หน้า System Settings: {', '.join(foreign)}",
        )


    locked = [key for key in payload.values if SETTING_DEFS[key].get("readonly")]
    if locked:
        labels = ", ".join(SETTING_DEFS[k]["label"] for k in locked)
        raise HTTPException(
            status_code=400,
            detail=f"ค่าเหล่านี้ถูกล็อกไว้ แก้จากหน้าเว็บไม่ได้: {labels}",
        )


    await _check_protected_values(payload)

    for key, value in payload.values.items():
        await update_setting(
            key, value,
            actor=user["username"], actor_id=user["id"], source="settings",
        )

    return {
        "status": "ok",
        "updated": sorted(payload.values.keys()),
        "acl_updated": [],
        "message": f"บันทึก {len(payload.values)} รายการแล้ว (มีผลทันที ไม่ต้องรีสตาร์ต)",
    }


@router.get("/api/settings/history")
async def api_setting_history(
    user=Depends(require_admin),
    setting_key: str | None = None,
    limit: int = 100,
):

    if setting_key and setting_key not in SETTING_DEFS:
        raise HTTPException(status_code=404, detail=f"ไม่รู้จักค่าตั้ง: {setting_key}")

    limit = max(1, min(limit, 500))
    rows = await setting_history(setting_key, limit)

    return {
        "items": [
            {**row, "changed_at": iso_utc(row["changed_at"]) if row["changed_at"] else None}
            for row in rows
        ]
    }


@router.get("/api/settings/gemini/models")
async def api_gemini_models(user=Depends(require_admin)):

    await ensure_loaded()

    from AI_API import gemini_client

    ok, result = await asyncio.to_thread(gemini_client.list_models)

    if not ok:
        return {"ok": False, "models": [], "message": result}

    return {
        "ok": True,
        "models": result,
        "message": f"คีย์นี้ใช้ได้ {len(result)} โมเดล จากรายการที่ระบบรองรับ",
    }


@router.get("/api/settings/redis-admin-password")
async def api_redis_admin_password_status(user=Depends(require_admin)):

    return await asyncio.to_thread(preflight)


@router.post("/api/settings/redis-admin-password/generate")
async def api_generate_redis_admin_password(user=Depends(require_admin)):

    return {"password": generate_password()}


@router.post("/api/settings/redis-admin-password")
async def api_rotate_redis_admin_password(
    payload: RotateRedisAdminPasswordRequest,
    user=Depends(require_admin),
):

    try:
        result = await asyncio.to_thread(
            rotate_admin_password, payload.password, payload.current_password
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RotationError as e:
        raise HTTPException(status_code=409, detail=str(e))


    await log_external_setting_change(
        "redis_admin_password", "rotate", user["username"],
        source="settings", actor_id=user["id"],
    )


    return {
        "status": "ok",
        **result,
        "restart_command": "sudo systemctl restart securelog.target",
        "message": "เปลี่ยนรหัส Redis ของ admin แล้ว — ต้องรีสตาร์ต service ที่เหลือทันที",
    }


@router.get("/api/settings/restart-status")
async def api_restart_status(user=Depends(require_admin)):

    return await asyncio.to_thread(restart_status)


@router.post("/api/settings/test/{service}")
async def api_test_service(service: str, user=Depends(require_admin)):

    await ensure_loaded()

    if service == "line":
        from LINE_API import config as line_config, line_client

        if not line_config.channel_access_token():
            return {"ok": False, "message": "ยังไม่ได้ตั้ง Channel Access Token"}


        status, body = await asyncio.to_thread(
            line_client.get_bot_info,
        )

        if status == 200:
            name = body.get("displayName") or "-"
            basic_id = body.get("basicId") or "-"
            return {
                "ok": True,
                "message": f"เชื่อมต่อได้ — OA: {name} ({basic_id})",
                "detail": {"basic_id": basic_id, "display_name": name},
            }


        detail = body.get("message") or ""
        detail = f"\nLINE ตอบกลับ: {detail}" if detail else ""

        if status == 401:
            return {"ok": False, "message": f"Channel Access Token ไม่ถูกต้องหรือหมดอายุ (HTTP 401){detail}"}

        if status == 0:
            return {"ok": False, "message": f"ต่อ LINE API ไม่ได้{detail}"}

        return {"ok": False, "message": f"เรียก LINE API ไม่สำเร็จ (HTTP {status}){detail}"}

    if service == "gemini":
        from AI_API import gemini_client


        return await asyncio.to_thread(gemini_client.test_connection)

    raise HTTPException(status_code=404, detail=f"ไม่รู้จักบริการ: {service}")
