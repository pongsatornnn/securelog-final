"""
System Settings — ค่าตั้งของระบบที่แก้ได้ตอนรัน (คีย์ LINE / Gemini / ค่าที่ฝังลงชุดติดตั้ง agent)

ทุก endpoint เป็น **admin only** เพราะค่าที่แก้ได้ในนี้คือคีย์ของบริการภายนอกและรหัสผ่าน Redis
ของ agent — ค่าที่เป็น secret จะไม่ถูกส่งกลับเต็ม ๆ ออกจากเซิร์ฟเวอร์เลย (mask ก่อนเสมอ)

ค่า bootstrap (DB / Redis ของ central / cert / JWT / CSRF / IP-port) **ไม่มีในนี้โดยตั้งใจ**
เพราะแอปต้องใช้ค่าพวกนั้นก่อนจะเปิดหน้าเว็บได้ — ยังคงอยู่ที่ setup-server.sh + .env
(ดูเหตุผลเต็มใน problem.md ข้อ 5)

**สองจุดที่ไม่ใช่แค่ "บันทึกค่า" แต่ลงมือแก้ของจริง** (ตรรกะทั้งหมดอยู่ใน redis_admin_password.py)
- รหัส Redis ของ user admin (`/api/settings/redis-admin-password`) — ไม่ได้เก็บลง app_settings
  เลย (ทำไม่ได้ — ไก่กับไข่) ไปแก้ users.acl + .env ของจริงแล้วสั่ง ACL LOAD ให้
- รหัส Redis ของ Client Server (คีย์ที่ตั้ง `apply_to_redis_acl`) — เก็บค่าลง app_settings
  เหมือนคีย์อื่น (ต้องเอาไปฝังใน site.conf) **และ** ไปเขียน users.acl ทั้งสองบรรทัดให้ด้วย
"""

import asyncio
import hmac
import re

from fastapi import APIRouter, Depends, HTTPException

from dependencies import require_admin
from redis_admin_password import (
    RotationError,
    apply_agent_password,
    generate_password,
    preflight,
    restore_agent_acl,
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
    """ค่าทั้งหมด — secret ถูก mask แล้ว (โชว์ 4 ตัวท้ายพอให้เทียบได้ว่าใช่ตัวที่ตั้งไว้)"""
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
    """
    ด่านของคีย์ที่แก้พลาดแล้วเจ็บ (`confirm_current` / `password_rules` ใน SETTING_DEFS)

    - **ยืนยันรหัสเดิม**: เทียบกับค่าที่เก็บไว้จริง ด้วย compare_digest · ข้ามให้เฉพาะตอนที่
      ยังไม่เคยตั้งค่า (ตั้งครั้งแรกไม่มีรหัสเดิมให้ยืนยัน) — ตรงกับ flag `confirm_current`
      ที่ส่งไปให้หน้าเว็บ จะได้ไม่ขอในสิ่งที่ผู้ใช้ให้ไม่ได้
    - **เงื่อนไขรหัส**: ใช้ตัวเดียวกับรหัสของ central (redis_password_rules)

    ผิดข้อไหนโยน 400 พร้อมข้อความไทยที่เอาไปโชว์ใต้ช่องกรอกได้เลย
    """
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

        # ค่าที่ถูกเอาไปต่อเป็น URL/พารามิเตอร์ของบริการภายนอก (ชื่อโมเดล Gemini) —
        # ต้องตรงรูปแบบก่อนถึงจะบันทึก ไม่งั้นไปพังตอนเรียกใช้จริงแล้วอ่าน error ไม่ออก
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
    """
    บันทึกหลายค่าพร้อมกัน — ส่งมาเฉพาะคีย์ที่แก้จริงเท่านั้น

    ค่าที่เป็น secret: หน้าเว็บส่งมาเฉพาะตอนที่ผู้ใช้พิมพ์ค่าใหม่ ถ้าไม่ได้แตะจะไม่ส่งคีย์นั้นมาเลย
    (ไม่งั้นค่าที่ mask ไว้ '••••••••abcd' จะถูกบันทึกทับของจริง)
    """
    unknown = [key for key in payload.values if key not in SETTING_DEFS]
    if unknown:
        raise HTTPException(status_code=404, detail=f"ไม่รู้จักค่าตั้ง: {', '.join(unknown)}")

    # ค่าที่เป็นของหน้าอื่น (เช่น escalation ที่หน้า Rules) ต้องแก้ผ่าน endpoint ของหน้านั้น
    # เพราะแต่ละหน้ามี validation ของตัวเอง — ปล่อยให้ลอดมาทางนี้จะข้าม validation ไปเฉย ๆ
    foreign = [key for key in payload.values if setting_page(key) != "settings"]
    if foreign:
        raise HTTPException(
            status_code=400,
            detail=f"ค่าเหล่านี้ตั้งจากหน้าอื่น ไม่ใช่หน้า System Settings: {', '.join(foreign)}",
        )

    # ค่าที่ตั้ง confirm_current / password_rules ไว้ (ตอนนี้คือรหัส Redis ของ Client Server)
    # ต้องผ่านสองด่านนี้ก่อน — ทำก่อนเขียนคีย์ใดๆ ทั้ง batch จะได้ไม่บันทึกครึ่งเดียวแล้วค่อยพัง
    await _check_protected_values(payload)

    # ── ค่าที่ต้องไปแก้ users.acl ด้วย (รหัส Redis ของ Client Server) ──
    # ทำก่อนบันทึกค่า: ถ้า Redis ไม่ยอมรับก็ไม่ควรมีค่าใหม่ค้างใน DB · เก็บชื่อไฟล์สำรองไว้
    # ถอยคืนถ้าบันทึกลง DB ไม่ผ่าน ไม่งั้นจะเหลือสถานะ "Redis เปลี่ยนแล้วแต่ชุดติดตั้งยังรหัสเก่า"
    applied = []
    for key, value in payload.values.items():
        if not SETTING_DEFS[key].get("apply_to_redis_acl"):
            continue

        try:
            applied.append(await asyncio.to_thread(apply_agent_password, value))
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"{SETTING_DEFS[key]['label']}: {e}")
        except RotationError as e:
            raise HTTPException(status_code=409, detail=str(e))

    try:
        for key, value in payload.values.items():
            await update_setting(
                key, value,
                actor=user["username"], actor_id=user["id"], source="settings",
            )
    except Exception as e:
        if not applied:
            raise

        # แก้ ACL ไปแล้วแต่บันทึกค่าไม่ผ่าน = ชุดติดตั้งครั้งหน้าจะฝังรหัสเก่าไปทั้งที่ Redis
        # เปลี่ยนแล้ว -> ถอย ACL กลับ แล้วบอกให้ชัดว่าตอนนี้ระบบอยู่สถานะไหน
        print(f"[SETTINGS] บันทึกค่าไม่สำเร็จหลังแก้ ACL แล้ว — ถอย ACL กลับ: {e}")

        rolled_back = all(
            await asyncio.gather(*[
                asyncio.to_thread(restore_agent_acl, result["acl_path"], result["acl_backup"])
                for result in applied
            ])
        )
        hint = (
            "ถอยรหัสใน users.acl กลับเป็นตัวเดิมให้แล้ว"
            if rolled_back else
            "ถอย users.acl กลับไม่สำเร็จ — ตรวจไฟล์แล้วสั่ง ACL LOAD เองก่อนใช้งานต่อ"
        )
        raise HTTPException(status_code=500, detail=f"บันทึกค่าไม่สำเร็จ ({e}) — {hint}")

    if applied:
        users = ", ".join(user for result in applied for user in result["users"])
        message = (
            f"เปลี่ยนรหัสใน users.acl ({users}) และสั่ง ACL LOAD ให้แล้ว — "
            "ต้องออกชุดติดตั้งใหม่ไปลงให้ครบทุกเครื่อง"
        )
    else:
        message = f"บันทึก {len(payload.values)} รายการแล้ว (มีผลทันที ไม่ต้องรีสตาร์ต)"

    return {
        "status": "ok",
        "updated": sorted(payload.values.keys()),
        "acl_updated": [user for result in applied for user in result["users"]],
        "message": message,
    }


@router.get("/api/settings/history")
async def api_setting_history(
    user=Depends(require_admin),
    setting_key: str | None = None,
    limit: int = 100,
):
    """
    ประวัติการแก้ค่าตั้ง — ใครแก้คีย์ไหน จากค่าอะไรเป็นอะไร เมื่อไหร่ ผ่านหน้าไหน

    ค่าที่เป็น secret ถูก mask ตั้งแต่ตอนบันทึกลงตารางแล้ว (ไม่ใช่ mask ตอนส่งออก)
    จึงไม่มีคีย์จริงอยู่ใน DB ให้หลุดตั้งแต่แรก
    """
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
    """
    โมเดลที่ **คีย์ที่ตั้งไว้ตอนนี้** เรียกได้จริง — หน้าเว็บเอาไปเป็นตัวเลือกในช่อง Model

    ต้องถาม Google ทุกครั้งเพราะคีย์แต่ละใบเห็นโมเดลไม่เท่ากัน (คีย์ที่ออกใหม่ใช้รุ่น 2.5
    ไม่ได้แล้ว) และรายชื่อฝั่ง Google เปลี่ยนเองเรื่อย ๆ · ดึงไม่ได้ไม่ถือเป็น error ของ
    endpoint — คืน ok=false พร้อมเหตุผล ให้หน้าเว็บตกไปใช้รายชื่อตั้งต้นแทน
    """
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
    """
    ความพร้อมของการเปลี่ยนรหัส — หน้าเว็บเรียกตอนโหลดเพื่อบอกล่วงหน้าว่าติดอะไรไหม
    (ต่อ Redis ไม่ได้ / ไม่เจอบรรทัด user ใน users.acl / เขียนไฟล์ไม่ได้) ดีกว่าให้กดปุ่มแล้วค่อยรู้
    ไม่ส่งรหัสปัจจุบันออกไปแม้แต่ตัวเดียว — บอกแค่ชื่อ user กับ path ของไฟล์ที่จะถูกแก้
    """
    return await asyncio.to_thread(preflight)


@router.post("/api/settings/redis-admin-password/generate")
async def api_generate_redis_admin_password(user=Depends(require_admin)):
    """
    สุ่มรหัสให้ — แค่คืนค่าไปโชว์บนหน้าเว็บ **ยังไม่เปลี่ยนอะไรทั้งนั้น**
    (แอดมินต้องกดปุ่มเปลี่ยนอีกที) · สุ่มฝั่ง server ด้วย secrets เพื่อให้ได้ค่าคุณภาพเดียวกับ
    คำสั่ง python3 -c "import secrets; ..." ที่เขียนไว้ใน redis/README.md
    """
    return {"password": generate_password()}


@router.post("/api/settings/redis-admin-password")
async def api_rotate_redis_admin_password(
    payload: RotateRedisAdminPasswordRequest,
    user=Depends(require_admin),
):
    """
    เปลี่ยนรหัส Redis ของ user admin ของจริง: เขียน users.acl -> ACL LOAD -> ตรวจว่ารหัสใหม่
    ล็อกอินได้ -> เขียน .env · ล้มเหลวตรงไหนระบบคืนสถานะเดิมให้ (รายละเอียดอยู่ในข้อความ error)

    รันใน thread เพราะเป็น blocking IO ทั้งเส้น (ไฟล์ + คำสั่ง Redis แบบ sync)

    HTTP code: 400 = ยืนยันรหัสเดิมไม่ผ่าน หรือรหัสใหม่ไม่เข้าเงื่อนไข (ยังไม่แตะอะไรเลย)
    · 409 = ลงมือแล้วไม่สำเร็จ
    """
    try:
        result = await asyncio.to_thread(
            rotate_admin_password, payload.password, payload.current_password
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except RotationError as e:
        raise HTTPException(status_code=409, detail=str(e))

    # ค่านี้ไม่ได้อยู่ใน app_settings (ไก่กับไข่) แต่เป็นการเปลี่ยนค่าตั้งของระบบจริง ๆ —
    # บันทึกไว้ในประวัติเดียวกันว่าใครสั่งเมื่อไหร่ (ไม่เก็บค่ารหัสทั้งเก่าและใหม่)
    await log_external_setting_change(
        "redis_admin_password", "rotate", user["username"],
        source="settings", actor_id=user["id"],
    )

    # service อื่นถือรหัสเก่าไว้ในหน่วยความจำ และเพิ่งถูก Redis ตัด connection ทิ้งไปพร้อมกันตอน
    # ACL LOAD — ตัวมันไม่ crash เอง (Restart=always จึงไม่ช่วย) ต้องสั่ง restart ให้อ่าน .env ใหม่
    #
    # บอกคำสั่งเดียวตายตัวคือ restart ทั้ง target — เคยคำนวณรายชื่อ unit ที่ค้างจาก service_status
    # เพื่อเลี่ยงการรีสตาร์ตตัวเว็บเอง แต่คำสั่งยาวและต่างไปเรื่อยตามสถานการณ์ จำยากกว่าที่ได้คืนมา
    # (รีสตาร์ตตัวเว็บด้วยไม่เสียหาย รหัสใหม่โชว์อยู่ในหน้าจอฝั่ง browser แล้ว)
    return {
        "status": "ok",
        **result,
        "restart_command": "sudo systemctl restart securelog.target",
        "message": "เปลี่ยนรหัส Redis ของ admin แล้ว — ต้องรีสตาร์ต service ที่เหลือทันที",
    }


@router.get("/api/settings/restart-status")
async def api_restart_status(user=Depends(require_admin)):
    """
    service ตัวไหนยังรันด้วยค่าเก่าจาก `.env` — หน้าเว็บใช้ขึ้นแถบเตือนค้างไว้จนกว่าจะรีสตาร์ตจริง

    ไม่ผูกกับการเปลี่ยนรหัส Redis โดยเฉพาะ: แก้ `.env` ด้วยมือแล้วลืมรีสตาร์ตก็เตือนเหมือนกัน
    เป็นการอ่านอย่างเดียวทั้งหมด (`systemctl show`) จึงไม่ต้องใช้สิทธิ์ root — เว็บ **ไม่มี**
    สิทธิ์สั่งรีสตาร์ตเอง โดยตั้งใจ (ดู work.md 2026-08-05)
    """
    return await asyncio.to_thread(restart_status)


@router.post("/api/settings/test/{service}")
async def api_test_service(service: str, user=Depends(require_admin)):
    """
    ยิงของจริงไปเช็คว่าคีย์ที่ตั้งไว้ใช้ได้ไหม — ตรวจก่อนดีกว่ามารู้ตอนเกิดเหตุจริงแล้วแจ้งเตือนไม่ออก
    ใช้ endpoint ที่ไม่มีผลข้างเคียง (ไม่ส่งข้อความหาใคร ไม่สร้างอะไรทิ้งไว้)

    **ข้อความที่ปลายทางตอบมาต้องติดกลับไปด้วยเสมอ** — บอกแค่ "HTTP 404" แอดมินเดาไม่ออกว่า
    ต้องไปแก้อะไร ทั้งที่ Google/LINE เขียนสาเหตุมาให้ครบแล้วใน body
    """
    await ensure_loaded()

    if service == "line":
        from LINE_API import config as line_config, line_client

        if not line_config.channel_access_token():
            return {"ok": False, "message": "ยังไม่ได้ตั้ง Channel Access Token"}

        # bot info = ข้อมูลของ OA ตัวเอง เรียกได้ด้วย token อย่างเดียว ไม่ต้องมี userId ของใคร
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

        # LINE ตอบ error เป็น {"message": "..."} — เอาข้อความนั้นต่อท้ายให้แอดมินอ่านเอง
        detail = body.get("message") or ""
        detail = f"\nLINE ตอบกลับ: {detail}" if detail else ""

        if status == 401:
            return {"ok": False, "message": f"Channel Access Token ไม่ถูกต้องหรือหมดอายุ (HTTP 401){detail}"}

        if status == 0:
            return {"ok": False, "message": f"ต่อ LINE API ไม่ได้{detail}"}

        return {"ok": False, "message": f"เรียก LINE API ไม่สำเร็จ (HTTP {status}){detail}"}

    if service == "gemini":
        from AI_API import gemini_client

        # test_connection คืนทั้งผล ข้อความไทย และคำตอบดิบจาก Google มาให้ครบในตัวแล้ว
        return await asyncio.to_thread(gemini_client.test_connection)

    raise HTTPException(status_code=404, detail=f"ไม่รู้จักบริการ: {service}")
