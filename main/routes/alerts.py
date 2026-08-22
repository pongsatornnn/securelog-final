"""
เส้นทาง Security Alert สำหรับ dashboard: list ล่าสุด, ดูรายละเอียด, SSE stream
แบบ real-time (subscribe Redis channel security_alerts_stream ที่ detector publish เข้ามา)
และ AI summary แบบ on-demand (กดปุ่มถึงเรียก Gemini — ไม่วิเคราะห์อัตโนมัติ)
"""

import asyncio
from datetime import datetime, timezone

import redis.asyncio as aioredis
from fastapi import APIRouter, Request, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_security_alerts,
    count_security_alerts,
    get_alert_filter_facets,
    count_security_alerts_since,
    get_security_alert_by_id,
    get_agents_by_agent_ids,
    get_agent_by_agent_id,
    set_security_alert_ai_summary,
    get_all_alert_severity,
    get_alert_read_ids,
    mark_alerts_read,
    get_user_last_seen_alert_id,
    set_user_last_seen_alert_id,
)

from dependencies import require_login, require_admin
from redis_config import REDIS_CONFIG
from settings_cache import ensure_loaded
from shared import iso_utc, limiter
from alerts import (
    build_alert_summary,
    build_alert_detail,
    get_attack_type_label,
    get_severity,
    SECURITY_ALERTS_STREAM_CHANNEL,
)
from severity_cache import DEFAULT_SEVERITY, VALID_SEVERITIES, update_severity
from AI_API import summarizer

from schemas.alert_severity_schema import UpdateAlertSeverityRequest
from schemas.alert_read_schema import UpdateAlertReadStateRequest


router = APIRouter()

# จำนวนแถวต่อหน้าเริ่มต้น + เพดานที่ยอมให้ขอได้ (กันยิง ?per_page=100000 แล้วลากทั้งตาราง
# ขึ้น memory พร้อม related_logs ที่เป็น JSONB ก้อนใหญ่ของทุกแถว)
DEFAULT_PER_PAGE = 50
MAX_PER_PAGE = 200


def parse_filter_time(value: str | None, field: str) -> datetime | None:
    """
    แปลงเวลาที่ browser ส่งมาเป็น datetime แบบ naive-UTC ให้ตรงกับที่ DB เก็บ

    browser ส่งมาเป็น ISO ที่มี timezone ติดมาด้วยเสมอ (คำนวณขอบวันตามเวลาไทยแล้วแปลงเป็น
    UTC ตั้งแต่ฝั่งหน้าเว็บ) — server จึงไม่ต้องเดาว่า "วันที่" ที่ผู้ใช้เลือกอยู่โซนไหน
    """
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status_code=400, detail=f"รูปแบบเวลาของ {field} ไม่ถูกต้อง")

    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)

    return parsed


async def detection_types_by_severity(db: AsyncSession, severity: str) -> list[str]:
    """
    detection_type ทั้งหมดที่ระดับความรุนแรงตรงกับที่เลือก

    severity ไม่ได้เก็บเป็นคอลัมน์ในตาราง alert แต่ผูกอยู่กับ (detection_type, mode) ผ่าน
    severity_cache ซึ่งแอดมินแก้ได้ตลอด — การกรองจึงต้องแปลงกลับเป็นชุด detection_type
    ก่อนแล้วค่อยกรองที่ DB (ถ้ากรองหลังดึงมา 200 แถวจะได้ผลไม่ครบ เพราะ 200 แถวนั้นถูก
    ตัดมาก่อนกรองแล้ว)
    """
    facets = await get_alert_filter_facets(db)

    matched = []
    for detection_type in facets["detection_types"]:
        if await get_severity(detection_type, None) == severity:
            matched.append(detection_type)

    return matched


@router.get("/api/alerts")
async def api_get_alerts(
    page: int = 1,
    per_page: int = DEFAULT_PER_PAGE,
    start: str | None = None,
    end: str | None = None,
    host: str | None = None,
    attack_type: str | None = None,
    severity: str | None = None,
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    หนึ่งหน้าของตาราง Alerts พร้อมจำนวนรวม — คืนเป็น object ไม่ใช่ list เปล่า
    (`{items, page, per_page, total, pages}`) เพราะ browser ต้องรู้จำนวนรวมถึงจะวาดเลขหน้าได้

    ทั้งกรองและแบ่งหน้าทำที่ DB ไม่ใช่ที่ browser — ถ้าดึงมาทั้งตารางแล้วค่อยตัดหน้าเอง
    ตัวกรองวันที่ย้อนหลังจะเห็นได้แค่ส่วนที่ติดมากับก้อนแรก และยิ่งข้อมูลสะสมยิ่งช้าลงเรื่อย ๆ
    """
    if severity and severity not in VALID_SEVERITIES:
        raise HTTPException(status_code=400, detail=f"ไม่รู้จักระดับความรุนแรง: {severity}")

    # ค่าที่ไม่สมเหตุสมผล (page=0, per_page=-5) บีบเข้าช่วงที่ใช้ได้แทนการโยน error —
    # ผู้ใช้แก้ URL เองแล้วเจอหน้าพังไม่ได้ช่วยอะไร ขอแค่อย่าให้ offset ติดลบ
    per_page = max(1, min(per_page, MAX_PER_PAGE))
    page = max(1, page)

    detection_types = [attack_type] if attack_type else None

    if severity:
        matched = await detection_types_by_severity(db, severity)
        # เลือกทั้งประเภทและความรุนแรงพร้อมกัน = ต้องเข้าทั้งสองเงื่อนไข
        detection_types = (
            [t for t in detection_types if t in matched]
            if detection_types is not None
            else matched
        )

    filters = {
        "start": parse_filter_time(start, "วันที่เริ่มต้น"),
        "end": parse_filter_time(end, "วันที่สิ้นสุด"),
        "agent_id": host,
        "detection_types": detection_types,
    }

    total = await count_security_alerts(db, **filters)
    pages = max(1, -(-total // per_page))   # ปัดขึ้น; ไม่มีข้อมูลเลยก็ยังนับเป็น 1 หน้า (หน้าว่าง)

    # ขอหน้าที่เลยจากที่มีจริง (ข้อมูลเปลี่ยนไปแล้ว / แก้ URL เอง) -> คืนหน้าสุดท้ายที่มีจริง
    # พร้อมบอก page ที่ใช้จริงกลับไป ให้ฝั่ง browser ปรับตามได้โดยไม่ต้องยิงซ้ำ
    page = min(page, pages)

    security_alerts = await get_security_alerts(
        db,
        limit=per_page,
        offset=(page - 1) * per_page,
        **filters,
    )

    agent_ids = list({alert.agent_id for alert in security_alerts if alert.agent_id})
    agents = await get_agents_by_agent_ids(db, agent_ids)
    agents_map = {agent.agent_id: agent for agent in agents}

    return {
        "items": [
            await build_alert_summary(alert, agents_map.get(alert.agent_id))
            for alert in security_alerts
        ],
        "page": page,
        "per_page": per_page,
        "total": total,
        "pages": pages,
    }


@router.get("/api/alerts_filter_options")
async def api_get_alerts_filter_options(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    ตัวเลือกของ dropdown ตัวกรองหน้า Alerts (เครื่อง / ประเภทการโจมตี / ความรุนแรง)

    ชื่อ path แบนแบบเดียวกับ /api/alerts_unread_count เพราะ /api/alerts/{alert_id} รับ
    alert_id เป็น int — ถ้าตั้งเป็น /api/alerts/filter_options จะโดน route นั้นดักแล้วได้ 422
    """
    facets = await get_alert_filter_facets(db)

    agents = await get_agents_by_agent_ids(db, facets["agent_ids"])
    agents_map = {agent.agent_id: agent for agent in agents}

    hosts = [
        {
            "agent_id": agent_id,
            # ชื่อเครื่องอ่านง่ายกว่า agent_id แต่ agent ที่ถูกลบไปแล้วจะไม่มีแถวให้ดึงชื่อ
            # — ยังต้องแสดงเป็นตัวเลือกอยู่ เพราะ alert เก่าของเครื่องนั้นยังอยู่ในตาราง
            "hostname": (
                agents_map[agent_id].hostname
                if agent_id in agents_map and agents_map[agent_id].hostname
                else agent_id
            ),
        }
        for agent_id in facets["agent_ids"]
    ]

    attack_types = [
        {
            "value": detection_type,
            "label": get_attack_type_label(detection_type, None),
            "severity": await get_severity(detection_type, None),
        }
        for detection_type in facets["detection_types"]
    ]

    return {
        "hosts": sorted(hosts, key=lambda h: h["hostname"].lower()),
        "attack_types": sorted(attack_types, key=lambda t: t["label"].lower()),
        "severities": list(VALID_SEVERITIES),
    }


@router.get("/api/alerts_unread_count")
async def api_get_alerts_unread_count(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    จำนวน alert ที่ใหม่กว่า id ที่ผู้ใช้เห็นล่าสุด — ใช้ทำ badge "ยังไม่ได้อ่าน" ที่เมนู Alerts

    "เห็นถึงไหนแล้ว" อ่านจาก users.last_seen_alert_id ไม่ใช่จากค่าที่ browser ส่งมา badge
    จึงตรงกันทุกเครื่องที่ login ด้วยบัญชีเดียวกัน (เดิมเก็บใน localStorage = ผูกกับเครื่อง)

    last_seen_alert_id = NULL คือบัญชีนี้ยังไม่เคยเปิดหน้าไหนเลย -> ตั้งให้เท่ากับ alert
    ล่าสุด ณ ตอนนั้นแล้วคืน 0 (ถือว่าของเก่าเห็นหมดแล้ว) ไม่งั้น badge จะเด้งเป็นจำนวน alert
    ทั้งตารางตั้งแต่วินาทีแรกที่เข้าใช้ ซึ่งไม่ได้บอกอะไรว่า "มีอะไรใหม่"

    ตั้งชื่อ path เป็น /api/alerts_unread_count ไม่ใช่ /api/alerts/unread เพราะจะชนกับ
    /api/alerts/{alert_id} ที่ alert_id เป็น int (จะได้ 422 ไม่ใช่ตกมาเข้า route นี้)

    ฝั่ง frontend ยังใช้ endpoint นี้เป็นตัวเช็คว่า session ยังไม่หมดอายุก่อนต่อ SSE ใหม่ด้วย
    (EventSource ไม่ได้วิ่งผ่าน window.fetch จึงไม่โดน session guard — ดู alert-stream.js)
    """
    last_seen_id = await get_user_last_seen_alert_id(db, user["id"])

    count, latest_id = await count_security_alerts_since(db, last_seen_id or 0)

    if last_seen_id is None:
        await set_user_last_seen_alert_id(db, user["id"], latest_id)
        return {"count": 0, "last_seen_id": latest_id}

    return {"count": count, "last_seen_id": last_seen_id}


@router.get("/api/alerts_read_state")
async def api_get_alerts_read_state(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    id ของ alert ที่บัญชีนี้กดดูรายละเอียดไปแล้ว — browser เอาไปวาดจุด "ยังไม่ได้อ่าน" หน้าแถว

    ไม่รวมจุด "เห็นรายการถึงไหนแล้ว" (users.last_seen_alert_id) เพราะ browser ได้ค่านั้นติดมา
    กับ /api/alerts_unread_count ที่เรียกคู่กันอยู่แล้ว

    ชื่อ path แบนเหมือน /api/alerts_unread_count ด้วยเหตุผลเดียวกัน (กันชนกับ /api/alerts/{id})
    """
    return {"opened_ids": await get_alert_read_ids(db, user["id"])}


@router.post("/api/alerts_read_state")
async def api_update_alerts_read_state(
    payload: UpdateAlertReadStateRequest,
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    บันทึกสถานะ "อ่านแล้ว" ของบัญชีที่กำลัง login — เครื่องอื่นที่ login อยู่จะเห็นตรงกันรอบถัดไป

    รับ opened_ids เป็น list ไม่ใช่ตัวเดียว เพราะ browser ใช้ endpoint นี้สองจังหวะ:
    ตอนกดดูรายละเอียด (ส่งตัวเดียว) และตอนซิงค์รอบแรกที่ต้องดันของที่ค้างใน localStorage
    ขึ้นมาทั้งชุด (POST ที่เคยพลาดตอนเน็ตหลุด หรือของเก่าจากก่อนมีตาราง alert_reads)
    """
    if payload.opened_ids:
        await mark_alerts_read(db, user["id"], payload.opened_ids)

    if payload.last_seen_id:
        await set_user_last_seen_alert_id(db, user["id"], payload.last_seen_id)

    return {"status": "ok"}


@router.get("/api/alerts/{alert_id}")
async def api_get_alert_detail(
    alert_id: int,
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    alert = await get_security_alert_by_id(db, alert_id)

    if not alert:
        raise HTTPException(status_code=404, detail="ไม่พบ Alert นี้")

    agent = await get_agent_by_agent_id(db, alert.agent_id) if alert.agent_id else None

    return await build_alert_detail(alert, agent)


@router.get("/api/alert_severity")
async def api_get_alert_severity(
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """ระดับความรุนแรง (LOW/MEDIUM/HIGH/CRITICAL) ต่อประเภทการโจมตี — seed default ครบก่อนคืนค่า"""
    for severity_key in DEFAULT_SEVERITY:
        detection_type, _, mode = severity_key.partition(":")
        await get_severity(detection_type, mode or None)

    rows = await get_all_alert_severity(db)
    return {
        "items": [
            {
                "severity_key": r.severity_key,
                "severity": r.severity,
                "description": r.description,
                "updated_at": iso_utc(r.updated_at),
            }
            for r in rows
        ],
    }


@router.post("/api/alert_severity/{severity_key}")
async def api_update_alert_severity(
    severity_key: str,
    payload: UpdateAlertSeverityRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    if severity_key not in DEFAULT_SEVERITY:
        raise HTTPException(status_code=404, detail=f"ไม่รู้จัก severity_key: {severity_key}")

    updated = await update_severity(severity_key, payload.severity)

    return {
        "status": "ok",
        "message": f"อัปเดต severity ของ {severity_key} สำเร็จ",
        "item": updated,
    }


@router.post("/api/alerts/{alert_id}/ai-summary")
@limiter.limit("10/minute")
async def api_generate_alert_ai_summary(
    request: Request,
    alert_id: int,
    force: bool = False,
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    วิเคราะห์ log ของ alert นี้ด้วย AI — เรียกตอนผู้ใช้ที่ login แล้ว (admin หรือ user) กดปุ่มเท่านั้น
    (require_login: ไม่จำกัดเฉพาะ admin แต่ยังต้อง login — เสียเงินจริงต่อครั้ง + เขียน DB ไม่ใช่แค่ view)

    ถ้าเคยวิเคราะห์ไว้แล้วจะคืนของเดิม (cached=True) ไม่เรียก AI ซ้ำ
    ส่ง ?force=true เมื่ออยากวิเคราะห์ใหม่ (เช่น log ในเหตุการณ์นี้ merge เพิ่มเข้ามาอีก)

    rate limit 10/นาที: การกดแต่ละครั้งเสียเงินจริง + ใช้เวลาหลายวินาที
    """
    alert = await get_security_alert_by_id(db, alert_id)

    if not alert:
        raise HTTPException(status_code=404, detail="ไม่พบ Alert นี้")

    if alert.ai_summary and not force:
        return {
            "ai_summary": alert.ai_summary,
            "ai_summary_at": iso_utc(alert.ai_summary_at),
            "cached": True,
        }

    agent = await get_agent_by_agent_id(db, alert.agent_id) if alert.agent_id else None
    # ต้องดึงมาก่อนโยนเข้า thread — severity_cache.get_severity เป็น async (ต้องมี event loop),
    # เทรดที่ asyncio.to_thread สร้างให้ไม่มี event loop ของตัวเอง
    severity = await get_severity(alert.detection_type, alert.mode)

    # gemini_client ใช้ urllib (blocking) — ต้องโยนออก thread ไม่งั้น request อื่น
    # ของทั้ง app จะค้างรอ AI ตอบไปด้วย
    # summarize_alert เป็นโค้ด sync ที่อ่าน API key จาก cache — เติมให้ก่อนโยนเข้า thread
    await ensure_loaded()

    ok, result = await asyncio.to_thread(summarizer.summarize_alert, alert, agent, severity)

    if not ok:
        # 502: ปลายทาง (Gemini) มีปัญหา ไม่ใช่ผู้ใช้ทำผิด — ข้อความไทยจาก gemini_client
        raise HTTPException(status_code=502, detail=result)

    await set_security_alert_ai_summary(db, alert, result)

    return {
        "ai_summary": alert.ai_summary,
        "ai_summary_at": iso_utc(alert.ai_summary_at),
        "cached": False,
    }


async def alert_event_stream(request: Request):
    r = aioredis.Redis(**REDIS_CONFIG)
    pubsub = r.pubsub()
    await pubsub.subscribe(SECURITY_ALERTS_STREAM_CHANNEL)

    try:
        yield ": connected\n\n"

        while True:
            if await request.is_disconnected():
                break

            # ⚠️ ลูปนี้จบเองไม่ได้ตอน server ปิด — `is_disconnected()` เป็น False อยู่ดี
            # เพราะฝั่ง client ไม่ได้ตัด uvicorn จึงรอ connection นี้ตอน `systemctl restart`
            # ทางแก้อยู่ที่ `--timeout-graceful-shutdown` ใน systemd/securelog-web.service
            # (ตั้งธงใน lifespan ไม่ช่วย เพราะ uvicorn ปิด connection ให้หมด "ก่อน" รัน
            #  lifespan shutdown — ธงจะถูกตั้งหลังจากที่มันรอไปแล้วเสมอ)
            message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=5)

            if message is None:
                yield ": heartbeat\n\n"
                continue

            data = message.get("data")

            if isinstance(data, bytes):
                data = data.decode()

            yield f"data: {data}\n\n"

    finally:
        try:
            await pubsub.unsubscribe(SECURITY_ALERTS_STREAM_CHANNEL)
            await pubsub.close()
        except Exception:
            pass

        try:
            await r.close()
        except Exception:
            pass


@router.get("/api/stream/alerts")
async def stream_alerts(
    request: Request,
    user=Depends(require_login),
):
    return StreamingResponse(
        alert_event_stream(request),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
