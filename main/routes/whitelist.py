"""
เส้นทางจัดการ IP Whitelist

add_whitelist / add_whitelist_bulk เคยรับ body เป็น raw JSON ผ่าน request.json() ตรง ๆ
ซึ่งทำให้ body ที่ parse ไม่ผ่านกลายเป็น 500 (JSONDecodeError หลุดขึ้นไปถึง handler กลาง)
และค่าที่ยาวเกินคอลัมน์ก็หลุดไปตายที่ PostgreSQL — ตอนนี้ใช้ Pydantic model เหมือน
routes/blacklist.py แล้ว ทั้งสองเคสจึงตอบ 422 พร้อมบอกฟิลด์ที่ผิด
"""

import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_ip_whitelist,
    get_ip_whitelist_by_id,
    delete_ip_whitelist_by_id,
    save_ip_whitelist,
    get_whitelist_by_ip,
    get_blacklist_by_ip,
)

from dependencies import require_login, require_admin
from shared import iso_utc
from process_log_detect.security_response import broadcast_whitelist_from_db

from schemas.whitelist_schema import (
    CreateWhitelistRequest,
    CreateWhitelistBulkRequest,
)


router = APIRouter()


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
            "description": item.description,
            "created_at": iso_utc(item.created_at),
            "created_by": item.created_by,   # None = แถวเก่าก่อนเก็บข้อมูลนี้
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
    ip_address = payload.ip_address.strip()
    description = (payload.description or "manual_whitelist").strip()

    if not ip_address:
        raise HTTPException(
            status_code=400,
            detail="กรุณากรอก IP Address",
        )

    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="รูปแบบ IP Address ไม่ถูกต้อง",
        )

    # เช็คเฉพาะแถวที่ยัง block อยู่จริง (is_active) — แถวที่ปลดบล็อก/หมดอายุไปแล้ว
    # ยังค้างอยู่ใน ip_black_list ในฐานะ "ประวัติ" เท่านั้น (ดู manual_unblock_blacklist)
    # ถ้าไม่กรอง is_active IP ที่แอดมินเพิ่งกดปลดบล็อกจะเพิ่มเข้า Whitelist ไม่ได้ตลอดไป
    blacklist_ip = await get_blacklist_by_ip(db, ip_address)
    if blacklist_ip and blacklist_ip.is_active:
        raise HTTPException(
            status_code=409,
            detail=(
                f"IP {ip_address} กำลังถูกบล็อกอยู่ใน Blacklist "
                "กรุณาปลดบล็อกที่หน้า Blacklist ก่อนจึงจะเพิ่มเข้า Whitelist ได้"
            ),
        )

    whitelist_ip = await get_whitelist_by_ip(db, ip_address)
    if whitelist_ip:
        raise HTTPException(
            status_code=409,
            detail=f"IP {ip_address} มีอยู่ใน Whitelist แล้ว",
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

        if ip_address in seen_ips:
            results["skipped"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": "IP ซ้ำในรายการที่ส่งมา",
            })
            continue

        seen_ips.add(ip_address)

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

        try:
            ipaddress.ip_address(ip_address)
        except ValueError:
            results["invalid"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": "รูปแบบ IP Address ไม่ถูกต้อง",
            })
            continue

        # เช็ค is_active ด้วยเหตุผลเดียวกับ api_add_whitelist (แถวที่ปลดบล็อกแล้วเป็นแค่ประวัติ)
        blacklist_ip = await get_blacklist_by_ip(db, ip_address)
        if blacklist_ip and blacklist_ip.is_active:
            results["blocked_by_blacklist"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": "IP กำลังถูกบล็อกอยู่ ต้องปลดบล็อกที่หน้า Blacklist ก่อน",
            })
            continue

        whitelist_ip = await get_whitelist_by_ip(db, ip_address)
        if whitelist_ip:
            results["skipped"].append({
                "ip_address": ip_address,
                "description": description,
                "reason": "IP มีอยู่ใน Whitelist แล้ว",
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
