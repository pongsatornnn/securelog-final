# เส้นทางจัดการ IP Whitelist

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_ip_whitelist,
    get_ip_whitelist_by_id,
    delete_ip_whitelist_by_id,
    save_ip_whitelist,
    find_whitelist_covering,
    get_active_blacklist_in_entry,
)
from ip_match import (
    normalize_entry,
    is_subnet,
    is_too_broad,
    entry_host_count,
    describe_entry,
    MIN_WHITELIST_PREFIXLEN,
)

from dependencies import require_login, require_admin
from shared import iso_utc
from process_log_detect.security_response import (
    broadcast_whitelist_from_db,
    is_non_blockable_ip,
    non_blockable_reason,
)

from schemas.whitelist_schema import (
    CreateWhitelistRequest,
    CreateWhitelistBulkRequest,
)


router = APIRouter()


# ข้อความเดียวกันทั้งตอนเพิ่มทีละรายการและเพิ่มทีละหลายรายการ
INVALID_FORMAT_DETAIL = (
    "รูปแบบไม่ถูกต้อง — กรอกได้ทั้ง IP เดี่ยว (192.168.1.10) "
    "และช่วง Subnet แบบ CIDR (192.168.1.0/24)"
)

# บอกชื่อ IP ที่ติดอยู่ไม่เกิน 10 ตัว — วง /8 ที่ชนเป็นร้อยตัวไม่ควรพ่นออกมาทั้งหมด
BLOCKED_PREVIEW_MAX = 10


def non_blockable_detail(entry: str) -> str:
    return f"{entry} {non_blockable_reason(entry)}"


def too_broad_detail(entry: str) -> str:
    return (
        f"{describe_entry(entry)} กว้างเกินกว่าจะใส่ Whitelist ได้ "
        f"— รับได้สูงสุดแค่ /{MIN_WHITELIST_PREFIXLEN}"
    )


def blocked_detail(entry: str, blocked_rows) -> str:
    names = [row.ip_address for row in blocked_rows]
    shown = ", ".join(names[:BLOCKED_PREVIEW_MAX])
    more = f" และอีก {len(names) - BLOCKED_PREVIEW_MAX} IP" if len(names) > BLOCKED_PREVIEW_MAX else ""

    return (
        f"{describe_entry(entry)} มี IP ที่กำลังถูกบล็อกอยู่ใน Blacklist: {shown}{more} "
        "— กรุณาปลดบล็อกที่หน้า Blacklist ก่อนจึงจะเพิ่มเข้า Whitelist ได้"
    )


@router.get("/api/get_whitelist")
async def api_get_whitelist(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    ips = await get_ip_whitelist(db)

    return [
        {
            "id": item.id,
            "ip_address": item.ip_address,
            # แถวที่เป็นช่วง subnet — หน้าเว็บเอาไปโชว์ว่ากินกี่เครื่อง
            "is_subnet": is_subnet(item.ip_address),
            "host_count": entry_host_count(item.ip_address),
            "description": item.description,
            "created_at": iso_utc(item.created_at),
            "created_by": item.created_by,
            "created_by_user_id": item.created_by_user_id,
        }
        for item in ips
    ]


@router.post("/api/add_whitelist")
async def api_add_whitelist(
    payload: CreateWhitelistRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    raw_value = payload.ip_address.strip()
    description = (payload.description or "manual_whitelist").strip()

    if not raw_value:
        raise HTTPException(
            status_code=400,
            detail="กรุณากรอก IP Address หรือ Subnet",
        )

    # รับได้ทั้ง IP เดี่ยวและช่วง subnet · normalize ให้วงเก็บเป็น network address เสมอ
    # (192.168.1.5/24 -> 192.168.1.0/24) กันเก็บวงเดียวกันซ้ำหลายหน้าตา
    ip_address = normalize_entry(raw_value)

    if ip_address is None:
        raise HTTPException(
            status_code=400,
            detail=INVALID_FORMAT_DETAIL,
        )

    if is_too_broad(ip_address):
        raise HTTPException(
            status_code=400,
            detail=too_broad_detail(ip_address),
        )

    if is_non_blockable_ip(ip_address):
        raise HTTPException(
            status_code=400,
            detail=non_blockable_detail(ip_address),
        )

    # เช็คเฉพาะแถวที่ยัง block อยู่จริง (is_active) — แถวที่ปลดบล็อก/หมดอายุไปแล้วเป็นแค่ประวัติ
    # วงเดียวอาจชนหลาย IP พร้อมกัน จึงบอกกลับไปว่าติดตัวไหนบ้าง
    blocked = await get_active_blacklist_in_entry(db, ip_address)
    if blocked:
        raise HTTPException(
            status_code=409,
            detail=blocked_detail(ip_address, blocked),
        )

    covering = await find_whitelist_covering(db, ip_address)
    if covering:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{ip_address} มีอยู่ใน Whitelist แล้ว"
                if covering.ip_address == ip_address
                else f"{ip_address} อยู่ในวง {covering.ip_address} ที่อยู่ใน Whitelist อยู่แล้ว"
            ),
        )

    ip = await save_ip_whitelist(
        db,
        {
            "source_ip": ip_address,
            "description": description,
            "created_by": user["username"],
                "created_by_user_id": user["id"],
        },
    )

    # อัปเดต never-block list ให้ทุก agent ที่ online แบบ real-time
    await broadcast_whitelist_from_db()

    return {
        "status": "ok",
        "message": "เพิ่ม IP Whitelist สำเร็จ",
        "whitelist": {
            "id": ip.id,
            "ip_address": ip.ip_address,
            "description": ip.description,
            "created_at": iso_utc(ip.created_at),
        },
    }


@router.post("/api/delete_whitelist/{whitelist_id}")
async def api_delete_whitelist(
    whitelist_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    ip = await get_ip_whitelist_by_id(db, whitelist_id)

    if not ip:
        raise HTTPException(
            status_code=404,
            detail="ไม่พบ IP ใน Whitelist",
        )

    ip_address = ip.ip_address
    deleted = await delete_ip_whitelist_by_id(db, whitelist_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="ไม่พบ IP ใน Whitelist",
        )

    # อัปเดต never-block list ให้ทุก agent ที่ online แบบ real-time
    await broadcast_whitelist_from_db()

    return {
        "status": "ok",
        "message": "ลบ IP Whitelist สำเร็จ",
        "ip_address": ip_address,
    }


@router.post("/api/add_whitelist_bulk")
async def api_add_whitelist_bulk(
    payload: CreateWhitelistBulkRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    items = payload.items

    results = {
        "added": [],
        "skipped": [],
        "invalid": [],
        "blocked_by_blacklist": [],
    }

    clean_items = []
    seen_ips = set()

    for item in items:
        ip_address = item.ip_address.strip()
        description = (item.description or "manual_whitelist").strip()

        if not ip_address:
            continue

        # เทียบซ้ำด้วยค่า normalize แล้ว — 192.168.1.0/24 กับ 192.168.1.5/24 คือวงเดียวกัน
        dedupe_key = normalize_entry(ip_address) or ip_address

        if dedupe_key in seen_ips:
            results["skipped"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": "ซ้ำในรายการที่ส่งมา",
            })
            continue

        seen_ips.add(dedupe_key)

        clean_items.append({
            "ip_address": ip_address,
            "description": description,
        })

    if not clean_items:
        raise HTTPException(
            status_code=400,
            detail="กรุณากรอก IP อย่างน้อย 1 รายการ",
        )

    for item in clean_items:
        ip_address = item["ip_address"]
        description = item["description"]

        normalized = normalize_entry(ip_address)

        if normalized is None:
            results["invalid"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": INVALID_FORMAT_DETAIL,
            })
            continue

        ip_address = normalized

        if is_too_broad(ip_address):
            results["invalid"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": too_broad_detail(ip_address),
            })
            continue

        if is_non_blockable_ip(ip_address):
            results["invalid"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": non_blockable_detail(ip_address),
            })
            continue

        # เช็ค is_active ด้วยเหตุผลเดียวกับ api_add_whitelist (แถวที่ปลดบล็อกแล้วเป็นแค่ประวัติ)
        blocked = await get_active_blacklist_in_entry(db, ip_address)
        if blocked:
            names = ", ".join(row.ip_address for row in blocked[:BLOCKED_PREVIEW_MAX])
            results["blocked_by_blacklist"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": f"มี IP ที่กำลังถูกบล็อกอยู่ ({names}) ต้องปลดบล็อกที่หน้า Blacklist ก่อน",
            })
            continue

        covering = await find_whitelist_covering(db, ip_address)
        if covering:
            results["skipped"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": (
                    "มีอยู่ใน Whitelist แล้ว"
                    if covering.ip_address == ip_address
                    else f"อยู่ในวง {covering.ip_address} ที่อยู่ใน Whitelist อยู่แล้ว"
                ),
            })
            continue

        ip = await save_ip_whitelist(
            db,
            {
                "source_ip": ip_address,
                "description": description,
                "created_by": user["username"],
                "created_by_user_id": user["id"],
            },
        )

        results["added"].append({
            "id": ip.id,
            "ip_address": ip.ip_address,
            "description": ip.description,
        })

    # ถ้ามีการเพิ่มจริงค่อย broadcast อัปเดต never-block list ให้ทุก agent
    if results["added"]:
        await broadcast_whitelist_from_db()

    return {
        "status": "ok",
        "message": "ประมวลผล Whitelist สำเร็จ",
        "summary": {
            "added": len(results["added"]),
            "skipped": len(results["skipped"]),
            "invalid": len(results["invalid"]),
            "blocked_by_blacklist": len(results["blocked_by_blacklist"]),
        },
        "results": results,
    }
