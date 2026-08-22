"""
เส้นทางดู/แก้ detection rule (threshold, window) ของ detector ต่างๆ
แก้ผ่าน rule_cache.update_rule() ซึ่งเขียน DB แล้วเคลียร์ cache ให้อัตโนมัติ
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import get_all_detection_rules, get_detection_rule

from dependencies import require_admin
from rule_cache import update_rule, is_default_rule, restore_default_rule, restore_default_rules
from shared import iso_utc

from schemas.rule_schema import UpdateRuleRequest, RestoreDefaultRulesRequest


router = APIRouter()


@router.get("/api/rules")
async def api_get_rules(
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    rules = await get_all_detection_rules(db)

    return [
        {
            "rule_key": rule.rule_key,
            "category": rule.category,
            "description": rule.description,
            "window_seconds": rule.window_seconds,
            "threshold": rule.threshold,
            "is_active": rule.is_active,
            # rule ของระบบ (มีค่า default ให้คืนกลับ) — หน้าเว็บใช้ตัดสินว่าจะโชว์ปุ่มคืนค่าไหม
            "is_default": is_default_rule(rule.rule_key),
            "updated_at": iso_utc(rule.updated_at),
        }
        for rule in rules
    ]


@router.post("/api/rules/{rule_key}")
async def api_update_rule(
    rule_key: str,
    payload: UpdateRuleRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = await get_detection_rule(db, rule_key)

    if not existing:
        raise HTTPException(
            status_code=404,
            detail=f"ไม่พบ rule_key: {rule_key}",
        )

    if payload.window_seconds <= 0 or payload.threshold <= 0:
        raise HTTPException(
            status_code=400,
            detail="window_seconds และ threshold ต้องมากกว่า 0",
        )

    updated = await update_rule(
        rule_key,
        window_seconds=payload.window_seconds,
        threshold=payload.threshold,
        is_active=payload.is_active,
    )

    return {
        "status": "ok",
        "message": f"อัปเดต rule {rule_key} สำเร็จ",
        "rule": updated,
    }


# path แบนแบบเดียวกับ /api/alerts_unread_count — ถ้าตั้งเป็น /api/rules/restore-defaults
# จะถูก route /api/rules/{rule_key} ข้างบนดักไปก่อน แล้วกลายเป็นการแก้ rule ชื่อ
# "restore-defaults" (ตอบ 404 ไม่พบ rule_key) แทนที่จะเข้ามาที่นี่
@router.post("/api/rules_restore_defaults")
async def api_restore_default_rules(
    payload: RestoreDefaultRulesRequest | None = None,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    """
    คืนค่า default ของ detection rule — ไม่ส่ง body / ไม่ส่ง rule_key = คืนทั้งหมด

    ทุก rule ในระบบมาจาก DEFAULT_RULES (ไม่มี endpoint ให้สร้าง rule เอง) ปุ่มนี้จึงครอบ
    ได้ทุกตัว · rule ที่ถูกลบแถวทิ้งไปจะถูกสร้างกลับมาด้วย (update_rule ใช้ upsert)
    """
    rule_key = payload.rule_key if payload else None

    if rule_key:
        if not is_default_rule(rule_key):
            raise HTTPException(
                status_code=404,
                detail=f"ไม่มีค่า default ของ rule นี้ให้คืน: {rule_key}",
            )

        rule = await restore_default_rule(rule_key)
        return {
            "status": "ok",
            "message": f"คืนค่า default ของ {rule_key} แล้ว",
            "restored": 1,
            "rules": [rule],
        }

    result = await restore_default_rules()
    return {
        "status": "ok",
        "message": f"คืนค่า default ของ detection rule ทั้งหมด {result['restored']} ตัวแล้ว",
        **result,
    }
