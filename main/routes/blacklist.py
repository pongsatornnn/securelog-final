"""
เส้นทางจัดการ IP Blacklist (manual, ผ่านหน้าเว็บ) — ต่างจาก auto-block ที่มาจาก
detector (main/process_log_detect/security_response.py) ซึ่งเขียนลง DB โดยตรงไม่ผ่าน API นี้
ทุกครั้งที่เพิ่ม/ลบ blacklist จะ publish คำสั่ง block_ip/unblock_ip ไปหา Agent ด้วย
"""

import ipaddress
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_ip_blacklist,
    get_active_blacklist,
    get_ip_blacklist_by_id,
    manual_unblock_blacklist,
    save_ip_blacklist,
    reactivate_blacklist,
    get_whitelist_by_ip,
    get_blacklist_by_ip,
    get_agent_by_agent_id,
    get_all_blacklist_ttl,
    upgrade_blacklist_severity,
    set_blacklist_actor,
    save_ip_whitelist,
    get_ip_whitelist_by_id,
    delete_ip_whitelist_by_id,
)
from blacklist_policy import BASE_TTL_SECONDS, MAX_TTL_SECONDS
from blacklist_ttl_cache import (
    ESCALATION_MAX_BLOCK_COUNT_KEY,
    ESCALATION_MULTIPLIER_KEY,
    get_escalation_policy,
    get_ttl,
    update_ttl,
)

from dependencies import require_login, require_admin
from redis_client import publish_json
from settings_cache import update_setting
from process_log_detect.security_response import (
    base_command_payload,
    is_non_blockable_ip,
    broadcast_whitelist_from_db,
    GLOBAL_COMMAND_CHANNEL,
)
from shared import iso_utc

from schemas.blacklist_schema import (
    CreateBlacklistRequest,
    CreateBlacklistBulkRequest,
    MoveToBlacklistRequest,
)
from schemas.blacklist_ttl_schema import (
    UpdateBlacklistTtlRequest,
    UpdateEscalationPolicyRequest,
)


router = APIRouter()


def agent_command_channel(agent_id: str) -> str:
    return f"agent_commands:{agent_id}"


def resolve_block_expiry(duration_seconds: int | None) -> datetime | None:
    """
    แปลงระยะเวลาที่แอดมินกรอก (วินาที) -> เวลาหมดอายุของการบล็อก · None = ถาวร

    ที่เดียวสำหรับ **ทุกทาง** ที่ตั้งเวลาบล็อกเองได้ (เพิ่มทีละ IP / เพิ่มหลาย IP /
    ย้ายจาก Whitelist มา Blacklist) เพื่อให้ด่านตรวจเหมือนกันหมด

    เพดาน 10 ปีเท่ากับ MAX_TTL_SECONDS ของฝั่ง auto-block — เกินกว่านั้น
    `timedelta` รับไม่ไหวแล้วโยน OverflowError ออกไปเป็น 500 (ดูเหตุผลเต็มใน
    blacklist_policy.py) ที่นี่ตอบ 400 บอกให้เลือก "ถาวร" แทน
    """
    if duration_seconds is None:
        return None

    if duration_seconds <= 0:
        raise HTTPException(
            status_code=400,
            detail="duration_seconds ต้องมากกว่า 0 หรือเว้นว่าง (ถาวร)",
        )

    if duration_seconds > MAX_TTL_SECONDS:
        raise HTTPException(
            status_code=400,
            detail="ระยะเวลาบล็อกยาวเกินไป (สูงสุด 10 ปี) — ถ้าต้องการนานกว่านี้ให้เลือกบล็อกถาวร",
        )

    return datetime.now() + timedelta(seconds=duration_seconds)


def describe_duration(duration_seconds: int | None) -> str:
    """ระยะเวลาเป็นข้อความไทยสำหรับข้อความตอบกลับ (หน่วยใหญ่สุดที่หารลงตัว)"""
    if duration_seconds is None:
        return "ถาวร"

    for unit_seconds, unit_name in ((86400, "วัน"), (3600, "ชั่วโมง"), (60, "นาที")):
        if duration_seconds % unit_seconds == 0:
            return f"{duration_seconds // unit_seconds} {unit_name}"

    return f"{duration_seconds} วินาที"


def is_longer_block(new_expires_at: datetime | None, current_expires_at: datetime | None) -> bool:
    """
    True ถ้าเวลาหมดอายุใหม่ 'บล็อกนานกว่า' ของเดิม (None = ถาวร = นานที่สุด)

    ใช้ตอนแอดมินกดเพิ่ม IP ที่กำลังถูกบล็อกอยู่ซ้ำ: ยืดเวลาได้อย่างเดียว ไม่ย่อ
    กันเผลอกดเพิ่มแบบ 30 นาทีไปทับ block ถาวรที่ระบบตั้งไว้จากการโจมตีจริง
    (กติกาเดียวกับ auto-block ที่ upgrade เฉพาะชนิดที่รุนแรงกว่า)
    """
    if current_expires_at is None:
        return False

    if new_expires_at is None:
        return True

    return new_expires_at > current_expires_at


def publish_agent_command(
    command: str,
    ip_address: str,
    event: str | None = None,
    agent_id: str | None = None,
) -> dict:
    """ส่งคำสั่งถึง agent เจาะจงตัว (มี agent_id) หรือ broadcast ทุกตัว (ไม่มี)"""
    payload = base_command_payload(command, ip_address, event, source="central_api")

    if agent_id:
        payload["agent_id"] = agent_id
        channel = agent_command_channel(agent_id)
    else:
        channel = GLOBAL_COMMAND_CHANNEL

    result = publish_json(channel, payload, log_prefix="COMMAND")

    if result["ok"]:
        print(
            f"[COMMAND] ส่ง {command} ไปที่ {channel} | "
            f"IP={ip_address} | receivers={result['receiver_count']}"
        )
    return result


@router.get("/api/get_blacklist")
async def api_get_blacklist(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    # แสดงเฉพาะ IP ที่ยัง block อยู่จริง (ไม่รวมที่หมดอายุไปแล้ว)
    ips = await get_active_blacklist(db)

    return [
        {
            "id": item.id,
            "ip_address": item.ip_address,
            "event": item.event,
            "created_at": iso_utc(item.created_at),
            "expires_at": iso_utc(item.expires_at),   # None = ถาวร
            "block_count": item.block_count,
            # ใครเพิ่ม: ชื่อผู้ใช้ที่กดเอง หรือ detector:<ชนิด> เมื่อระบบบล็อกเอง
            # None = แถวเก่าที่มีอยู่ก่อนเก็บข้อมูลนี้
            "created_by": item.created_by,
            "created_by_user_id": item.created_by_user_id,   # ไว้ลิงก์ไปหน้าโปรไฟล์ผู้ใช้ · NULL = ระบบทำเอง/ผู้ใช้ถูกลบ
        }
        for item in ips
    ]


@router.get("/api/blacklist_ttl")
async def api_get_blacklist_ttl(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    """
    TTL (ระยะเวลา block) ต่อ detection_type — seed default ครบก่อนแล้วคืนทั้งหมด
    พร้อมนโยบาย escalation ที่ใช้จริงตอนนี้ (แอดมินแก้ได้ที่ POST /api/escalation_policy)
    """
    for dt in BASE_TTL_SECONDS:
        await get_ttl(dt)   # seed default ถ้ายังไม่มี

    rows = await get_all_blacklist_ttl(db)
    policy = await get_escalation_policy()

    return {
        "items": [
            {
                "detection_type": r.detection_type,
                "ttl_seconds": r.ttl_seconds,   # None = ถาวร
                "description": r.description,
                "updated_at": iso_utc(r.updated_at),
            }
            for r in rows
        ],
        "escalation_multiplier": policy["multiplier"],
        "max_block_count_before_permanent": policy["max_block_count"],
    }


@router.post("/api/escalation_policy")
async def api_set_escalation_policy(
    payload: UpdateEscalationPolicyRequest,
    user=Depends(require_admin),
):
    """
    แก้นโยบาย escalation — body: {"multiplier": 2, "max_block_count": 5}

    มีผลกับการบล็อก **ครั้งถัดไป** เท่านั้น แถวที่บล็อกไปแล้วมี `expires_at` ตายตัวอยู่ใน DB
    การเปลี่ยนค่าที่นี่จึงไม่ย้อนไปยืด/หดเวลาของ IP ที่กำลังโดนบล็อกอยู่
    """
    if payload.multiplier < 1:
        raise HTTPException(
            status_code=400,
            detail="ตัวคูณต้องเป็น 1 ขึ้นไป (1 = ไม่ทวีคูณ ใช้เวลาเท่าเดิมทุกครั้ง)",
        )

    # กันตั้งค่าที่ทำให้ TTL บานจนล้น: 10^9 ชั่วโมงก็ไม่มีความหมายอยู่แล้ว
    if payload.multiplier > 100:
        raise HTTPException(status_code=400, detail="ตัวคูณมากเกินไป (สูงสุด 100)")

    if payload.max_block_count < 1:
        raise HTTPException(
            status_code=400,
            detail="จำนวนครั้งก่อนบล็อกถาวรต้องเป็น 1 ขึ้นไป",
        )

    if payload.max_block_count > 1000:
        raise HTTPException(status_code=400, detail="จำนวนครั้งมากเกินไป (สูงสุด 1000)")

    # source="rules" เพราะสองคีย์นี้ตั้งจากหน้า Rules ไม่ใช่หน้า System Settings —
    # ประวัติจะได้บอกถูกว่าคนแก้กดมาจากหน้าไหน
    await update_setting(
        ESCALATION_MULTIPLIER_KEY, str(payload.multiplier),
        actor=user["username"], actor_id=user["id"], source="rules",
    )
    await update_setting(
        ESCALATION_MAX_BLOCK_COUNT_KEY, str(payload.max_block_count),
        actor=user["username"], actor_id=user["id"], source="rules",
    )

    return {
        "status": "ok",
        "message": "บันทึกนโยบาย escalation แล้ว (มีผลกับการบล็อกครั้งถัดไป)",
        "policy": await get_escalation_policy(),
    }


@router.post("/api/blacklist_ttl/{detection_type}")
async def api_set_blacklist_ttl(
    detection_type: str,
    payload: UpdateBlacklistTtlRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """แก้ TTL ของ detection_type — body: {"ttl_seconds": 3600} หรือ {"ttl_seconds": null} (ถาวร)"""
    # จำกัดเฉพาะ detection_type ที่ระบบรู้จัก กันพิมพ์ผิดสร้างแถวขยะที่ไม่มี detector ตัวไหนอ้างถึงเลย
    if detection_type not in BASE_TTL_SECONDS:
        raise HTTPException(status_code=404, detail=f"ไม่รู้จัก detection_type: {detection_type}")

    if payload.ttl_seconds is not None and payload.ttl_seconds <= 0:
        raise HTTPException(status_code=400, detail="ttl_seconds ต้องมากกว่า 0 (หรือเว้นว่างไว้ = ถาวร)")

    # เพดานเดียวกับการบล็อกด้วยมือ — ค่านี้เป็น "ฐาน" ที่ escalation จะเอาไปคูณต่ออีก
    # (ตัวคูณมีเพดาน MAX_TTL_SECONDS อยู่แล้ว แต่ฐานเองก็ไม่ควรเกินไปกว่านั้นตั้งแต่แรก)
    if payload.ttl_seconds is not None and payload.ttl_seconds > MAX_TTL_SECONDS:
        raise HTTPException(
            status_code=400,
            detail="ระยะเวลา Block ยาวเกินไป (สูงสุด 10 ปี) — ถ้าต้องการนานกว่านี้ให้เลือกบล็อกถาวร",
        )

    result = await update_ttl(detection_type, payload.ttl_seconds)
    return {"status": "ok", "message": f"อัปเดต TTL ของ {detection_type} สำเร็จ", "ttl": result}


@router.post("/api/add_blacklist")
async def api_add_blacklist(
    payload: CreateBlacklistRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    ip_address = payload.ip_address.strip()

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="รูปแบบ IP Address ไม่ถูกต้อง",
        )

    if is_non_blockable_ip(ip_address):
        raise HTTPException(
            status_code=400,
            detail=f"IP {ip_address} เป็น address พิเศษของทราฟฟิก broadcast ไม่ใช่เครื่องจริง จึงบล็อกไม่ได้",
        )

    whitelist_ip = await get_whitelist_by_ip(db, ip_address)
    if whitelist_ip:
        raise HTTPException(
            status_code=409,
            detail=f"IP {ip_address} อยู่ใน Whitelist ไม่สามารถเพิ่มเข้า Blacklist ได้",
        )

    if payload.agent_id:
        agent = await get_agent_by_agent_id(db, payload.agent_id)
        if not agent:
            raise HTTPException(
                status_code=404,
                detail="ไม่พบ Client Server ที่ต้องการส่งคำสั่ง",
            )

    event = payload.event or "manual_blacklist"

    # ระยะเวลา block: None = ถาวร, มีค่า = block ชั่วคราวหมดอายุตาม admin เลือก
    expires_at = resolve_block_expiry(payload.duration_seconds)

    blacklist_ip = await get_blacklist_by_ip(db, ip_address)

    message = "เพิ่ม IP Blacklist สำเร็จ และส่งคำสั่งไปยัง Client Server แล้ว"

    if blacklist_ip and blacklist_ip.is_active:
        # DB บอกว่ายัง block อยู่ — ไม่ตอบ 409 ทิ้ง เพราะเหตุผลที่แอดมินกดเพิ่มซ้ำมักคือ
        # ฝั่ง agent ไม่มี rule แล้ว (agent ลง ufw ใหม่ / offline ตอน central broadcast /
        # ถูกปลดบล็อกที่เครื่องเอง) แล้ว state สองฝั่งหลุดจากกัน ถ้าปฏิเสธไปเลยแอดมิน
        # จะไม่มีทางสั่ง block ซ้ำจากหน้าเว็บได้ ต้องไปแก้ ufw ที่เครื่องเอง
        # -> ส่งคำสั่ง block ใหม่ให้ agent กลับมาตรงกับ DB (ufw insert rule ซ้ำไม่ error)
        if is_longer_block(expires_at, blacklist_ip.expires_at):
            ip = await upgrade_blacklist_severity(
                db, blacklist_ip, event=event, expires_at=expires_at,
                actor=user["username"], actor_id=user["id"],
            )
            message = (
                f"IP {ip_address} ถูกบล็อกอยู่แล้ว — ต่ออายุการบล็อกตามที่เลือก "
                "และส่งคำสั่งบล็อกซ้ำไปยัง Client Server แล้ว"
            )
        else:
            ip = await set_blacklist_actor(db, blacklist_ip, user["username"], user["id"])
            message = (
                f"IP {ip_address} ถูกบล็อกอยู่แล้ว — ส่งคำสั่งบล็อกซ้ำไปยัง Client Server แล้ว "
                "(ระยะเวลาเดิมนานกว่าหรือเท่าที่เลือก จึงคงของเดิมไว้)"
            )

    elif blacklist_ip:
        # เคยถูก block แล้วหมดอายุ -> admin เพิ่มมือใหม่ (ถาวรหรือกำหนดเวลาเองก็ได้)
        #
        # ไม่เพิ่มตัวนับ เพราะแอดมินเป็นคนสั่งเอง ไม่ใช่ IP นั้นกลับมาโจมตีซ้ำ
        # แต่ยกพื้นเป็นอย่างน้อย 1 เพราะแถวนี้กำลังถูกบล็อกอยู่จริง — ค่า 0 ใช้กับ
        # แถวที่แอดมินเพิ่งปลดบล็อกเองเท่านั้น (ดู manual_unblock_blacklist)
        ip = await reactivate_blacklist(
            db,
            blacklist_ip,
            event=event,
            expires_at=expires_at,
            block_count=max(blacklist_ip.block_count, 1),
            actor=user["username"], actor_id=user["id"],
        )
    else:
        ip = await save_ip_blacklist(
            db,
            {
                "source_ip": ip_address,
                "attack_type": event,
                "expires_at": expires_at,
                "created_by": user["username"],
                "created_by_user_id": user["id"],
            },
        )

    command_result = publish_agent_command(
        command="block_ip",
        ip_address=ip.ip_address,
        event=ip.event,
        agent_id=None,
    )

    return {
        "status": "ok",
        "message": message,
        "blacklist": {
            "id": ip.id,
            "ip_address": ip.ip_address,
            "event": ip.event,
            "created_at": iso_utc(ip.created_at),
        },
        "command": command_result,
    }


@router.post("/api/delete_blacklist/{blacklist_id}")
async def api_delete_blacklist(
    blacklist_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    ip = await get_ip_blacklist_by_id(db, blacklist_id)

    if not ip:
        raise HTTPException(
            status_code=404,
            detail="ไม่พบ IP ใน Blacklist",
        )

    ip_address = ip.ip_address
    event = ip.event

    await manual_unblock_blacklist(db, ip)

    command_result = publish_agent_command(
        command="unblock_ip",
        ip_address=ip_address,
        event=event,
        agent_id=None,
    )

    return {
        "status": "ok",
        "message": (
            "ปลดบล็อก IP สำเร็จ ส่งคำสั่งไปยัง Client Server แล้ว "
            "— ล้างจำนวนครั้งที่เคยถูกบล็อกเป็น 0 (ถ้ากลับมาโจมตีอีกจะนับเป็นครั้งที่ 1)"
        ),
        "ip_address": ip_address,
        "command": command_result,
    }


# ---------------------------------------------------------------------------
# ย้าย IP ข้ามลิสต์ (ปุ่ม "ย้ายไป Whitelist" / "ย้ายไป Blacklist" ในตารางของแต่ละหน้า)
#
# ทำสองอย่างที่เดิมต้องกดแยกกันคนละหน้าให้จบในคลิกเดียว และที่สำคัญคือ **บังคับลำดับ
# ให้ถูก** — สองลิสต์นี้กันกันเองอยู่ (IP ที่อยู่ Blacklist เพิ่มเข้า Whitelist ไม่ได้
# และกลับกัน) ถ้ากดเองทีละหน้าโดยสลับลำดับจะติดเงื่อนไขกันเองจนทำไม่สำเร็จ
#
# ทั้งสองเส้นทางอยู่ไฟล์นี้เพราะต้องใช้ publish_agent_command ร่วมกัน
# (routes/whitelist.py ดูแลเฉพาะ CRUD ของ whitelist ล้วน ๆ)
# ---------------------------------------------------------------------------

@router.post("/api/move_to_whitelist/{blacklist_id}")
async def api_move_to_whitelist(
    blacklist_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """ปลดบล็อก IP แล้วย้ายเข้า Whitelist ในคลิกเดียว (= กด Unblock + เพิ่ม Whitelist)"""
    ip = await get_ip_blacklist_by_id(db, blacklist_id)

    if not ip:
        raise HTTPException(status_code=404, detail="ไม่พบ IP ใน Blacklist")

    ip_address = ip.ip_address
    event = ip.event

    # 1) ปลดบล็อกก่อน — ต้องทำก่อนเพิ่ม whitelist เพราะ add_whitelist กัน IP ที่ยัง block อยู่
    #    (ล้าง block_count เป็น 0 เหมือนกดปุ่ม Unblock ปกติ = อภัยโทษให้เริ่มนับใหม่)
    await manual_unblock_blacklist(db, ip)

    command_result = publish_agent_command(
        command="unblock_ip",
        ip_address=ip_address,
        event=event,
        agent_id=None,
    )

    # 2) เพิ่มเข้า whitelist (ถ้ามีอยู่แล้วก็ถือว่าถึงปลายทางแล้ว ไม่ต้องเพิ่มซ้ำ)
    whitelist_ip = await get_whitelist_by_ip(db, ip_address)

    if not whitelist_ip:
        whitelist_ip = await save_ip_whitelist(
            db,
            {
                "source_ip": ip_address,
                "description": f"ย้ายมาจาก Blacklist ({event})",
                "created_by": user["username"],
                "created_by_user_id": user["id"],
            },
        )

    # 3) อัปเดต never-block list ให้ทุก agent จะได้ไม่โดน auto-block ซ้ำอีก
    await broadcast_whitelist_from_db()

    return {
        "status": "ok",
        "message": (
            f"ปลดบล็อก {ip_address} และย้ายเข้า Whitelist แล้ว "
            "— ต่อไประบบจะไม่บล็อก IP นี้อัตโนมัติอีก"
        ),
        "ip_address": ip_address,
        "whitelist": {
            "id": whitelist_ip.id,
            "ip_address": whitelist_ip.ip_address,
            "description": whitelist_ip.description,
            "created_at": iso_utc(whitelist_ip.created_at),
        },
        "command": command_result,
    }


@router.post("/api/move_to_blacklist/{whitelist_id}")
async def api_move_to_blacklist(
    whitelist_id: int,
    payload: MoveToBlacklistRequest | None = None,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    เอา IP ออกจาก Whitelist แล้วบล็อกทันทีในคลิกเดียว

    body ไม่บังคับ — `{"duration_seconds": 3600}` = บล็อก 1 ชั่วโมง, เว้นว่าง/ไม่ส่ง body = ถาวร
    (หน้าเว็บให้เลือกหน่วยเป็นนาที/ชั่วโมง/วัน/ถาวร แล้วแปลงเป็นวินาทีมาที่นี่)
    """
    whitelist_ip = await get_ip_whitelist_by_id(db, whitelist_id)

    if not whitelist_ip:
        raise HTTPException(status_code=404, detail="ไม่พบ IP ใน Whitelist")

    ip_address = whitelist_ip.ip_address

    if is_non_blockable_ip(ip_address):
        raise HTTPException(
            status_code=400,
            detail=f"IP {ip_address} เป็น address พิเศษของทราฟฟิก broadcast ไม่ใช่เครื่องจริง จึงบล็อกไม่ได้",
        )

    # ตรวจระยะเวลา **ก่อน** ลบออกจาก whitelist — ถ้าไปตอบ 400 ทีหลัง แถวใน whitelist
    # จะหายไปแล้วโดยที่ยังไม่ได้บล็อกอะไรเลย (กติกาเดียวกับด่าน is_non_blockable_ip ข้างบน)
    duration_seconds = payload.duration_seconds if payload else None
    expires_at = resolve_block_expiry(duration_seconds)

    # 1) เอาออกจาก whitelist + broadcast never-block list ใหม่ให้ agent **ก่อน** สั่ง block
    #    ลำดับนี้สำคัญ: agent เช็ค is_never_block() ทุกครั้งก่อนลง ufw rule ถ้าสั่ง block
    #    ไปก่อนที่ never-block list จะอัปเดต agent จะข้ามคำสั่งทิ้งไปเฉย ๆ
    #    (คำสั่งทั้งสองวิ่งผ่าน channel เดียวกัน ลำดับที่ agent ได้รับจึงตรงกับที่ส่ง)
    await delete_ip_whitelist_by_id(db, whitelist_id)
    await broadcast_whitelist_from_db()

    # 2) เพิ่ม/ปลุกแถวใน blacklist
    blacklist_ip = await get_blacklist_by_ip(db, ip_address)

    if blacklist_ip:
        ip = await reactivate_blacklist(
            db,
            blacklist_ip,
            event="manual_blacklist",
            expires_at=expires_at,
            block_count=max(blacklist_ip.block_count, 1),
            actor=user["username"], actor_id=user["id"],
        )
    else:
        ip = await save_ip_blacklist(
            db,
            {
                "source_ip": ip_address,
                "attack_type": "manual_blacklist",
                "expires_at": expires_at,
                "created_by": user["username"],
                "created_by_user_id": user["id"],
            },
        )

    command_result = publish_agent_command(
        command="block_ip",
        ip_address=ip.ip_address,
        event=ip.event,
        agent_id=None,
    )

    block_label = (
        "บล็อกถาวร" if duration_seconds is None else f"บล็อก {describe_duration(duration_seconds)}"
    )

    return {
        "status": "ok",
        "message": (
            f"เอา {ip_address} ออกจาก Whitelist และ{block_label}แล้ว "
            "ส่งคำสั่งไปยัง Client Server ทุกเครื่องแล้ว"
        ),
        "ip_address": ip_address,
        "blacklist": {
            "id": ip.id,
            "ip_address": ip.ip_address,
            "event": ip.event,
            "created_at": iso_utc(ip.created_at),
            "expires_at": iso_utc(ip.expires_at),   # None = ถาวร
        },
        "command": command_result,
    }


@router.post("/api/add_blacklist_bulk")
async def api_add_blacklist_bulk(
    payload: CreateBlacklistBulkRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    results = {
        "added": [],
        "reblocked": [],       # มีอยู่ใน Blacklist อยู่แล้ว -> ส่งคำสั่ง block ซ้ำให้ agent
        "skipped": [],
        "invalid": [],
        "blocked_by_whitelist": [],
    }

    clean_items = []
    seen_ips = set()

    for item in payload.items:
        ip_address = item.ip_address.strip()
        event = (item.event or "manual_blacklist").strip()

        if not ip_address:
            continue

        # กัน IP ซ้ำใน request เดียวกัน
        if ip_address in seen_ips:
            results["skipped"].append({
                "ip_address": ip_address,
                "event": event,
                "reason": "IP ซ้ำในรายการที่ส่งมา",
            })
            continue

        seen_ips.add(ip_address)

        clean_items.append({
            "ip_address": ip_address,
            "event": event,
        })

    if not clean_items:
        raise HTTPException(
            status_code=400,
            detail="กรุณากรอก IP อย่างน้อย 1 รายการ",
        )

    bulk_expires_at = resolve_block_expiry(payload.duration_seconds)

    if payload.agent_id:
        agent = await get_agent_by_agent_id(db, payload.agent_id)
        if not agent:
            raise HTTPException(
                status_code=404,
                detail="ไม่พบ Client Server ที่ต้องการส่งคำสั่ง",
            )

    for item in clean_items:
        ip_address = item["ip_address"]
        event = item["event"]

        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            results["invalid"].append({
                "ip_address": ip_address,
                "event": event,
                "reason": "รูปแบบ IP Address ไม่ถูกต้อง",
            })
            continue

        if is_non_blockable_ip(ip_address):
            results["invalid"].append({
                "ip_address": ip_address,
                "event": event,
                "reason": "เป็น address ของทราฟฟิก broadcast ไม่ใช่เครื่องจริง จึงบล็อกไม่ได้",
            })
            continue

        whitelist_ip = await get_whitelist_by_ip(db, ip_address)
        if whitelist_ip:
            results["blocked_by_whitelist"].append({
                "ip_address": ip_address,
                "event": event,
                "reason": "IP อยู่ใน Whitelist",
            })
            continue

        blacklist_ip = await get_blacklist_by_ip(db, ip_address)

        if blacklist_ip and blacklist_ip.is_active:
            # ยัง block อยู่ใน DB -> ส่งคำสั่ง block ซ้ำแทนการปฏิเสธ (เหตุผลเดียวกับ
            # api_add_blacklist: ให้แอดมินดึง agent ที่ rule หลุดไปกลับมาตรงกับ DB ได้)
            # ไม่นับเป็น added เพราะไม่ได้เพิ่มแถวใหม่ใน DB
            if is_longer_block(bulk_expires_at, blacklist_ip.expires_at):
                ip = await upgrade_blacklist_severity(
                    db, blacklist_ip, event=event, expires_at=bulk_expires_at,
                    actor=user["username"], actor_id=user["id"],
                )
                reason = "ถูกบล็อกอยู่แล้ว — ต่ออายุ + ส่งคำสั่งบล็อกซ้ำไปยัง Client Server แล้ว"
            else:
                ip = blacklist_ip
                reason = "ถูกบล็อกอยู่แล้ว — ส่งคำสั่งบล็อกซ้ำไปยัง Client Server แล้ว"

            command_result = publish_agent_command(
                command="block_ip",
                ip_address=ip.ip_address,
                event=ip.event,
                agent_id=payload.agent_id,
            )

            results["reblocked"].append({
                "id": ip.id,
                "ip_address": ip.ip_address,
                "event": ip.event,
                "reason": reason,
                "command": command_result,
            })
            continue

        if blacklist_ip:
            # เคยหมดอายุ/ถูกปลดบล็อก -> reactivate (กัน unique violation)
            #
            # ยกพื้น block_count เป็นอย่างน้อย 1 เหมือน api_add_blacklist — แถวที่กำลัง
            # block อยู่จริงต้องไม่ใช่ 0 (0 สงวนไว้ให้แถวที่แอดมินเพิ่งปลดบล็อกเอง)
            ip = await reactivate_blacklist(
                db,
                blacklist_ip,
                event=event,
                expires_at=bulk_expires_at,
                block_count=max(blacklist_ip.block_count, 1),
                actor=user["username"], actor_id=user["id"],
            )
        else:
            ip = await save_ip_blacklist(
                db,
                {
                    "source_ip": ip_address,
                    "attack_type": event,
                    "expires_at": bulk_expires_at,
                    "created_by": user["username"],
                "created_by_user_id": user["id"],
                },
            )

        command_result = publish_agent_command(
            command="block_ip",
            ip_address=ip.ip_address,
            event=ip.event,
            agent_id=payload.agent_id,
        )

        results["added"].append({
            "id": ip.id,
            "ip_address": ip.ip_address,
            "event": ip.event,
            "command": command_result,
        })

    return {
        "status": "ok",
        "message": "ประมวลผล Blacklist สำเร็จ",
        "summary": {
            "added": len(results["added"]),
            "reblocked": len(results["reblocked"]),
            "skipped": len(results["skipped"]),
            "invalid": len(results["invalid"]),
            "blocked_by_whitelist": len(results["blocked_by_whitelist"]),
        },
        "results": results,
    }
