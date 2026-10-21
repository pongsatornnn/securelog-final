

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_agent_by_agent_id,
    get_agents,
    get_all_agent_disabled_rules,
    get_all_detection_rules,
    get_detection_rule,
    set_agent_disabled_rules,
)

from dependencies import require_admin
from rule_cache import (
    clear_agent_rule_cache,
    update_rule,
    is_default_rule,
    restore_default_rule,
    restore_default_rules,
)
from shared import iso_utc

from schemas.rule_schema import UpdateRuleRequest, RestoreDefaultRulesRequest, UpdateAgentRulesRequest


router = APIRouter()


@router.get("/api/agent_rule_settings")
async def api_get_agent_rule_settings(
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agents = await get_agents(db)
    rules = [rule for rule in await get_all_detection_rules(db) if rule.category != "login"]
    disabled = await get_all_agent_disabled_rules(db)

    disabled_by_agent = {agent.agent_id: [] for agent in agents}
    for agent_id, rule_key in disabled:
        if agent_id in disabled_by_agent:
            disabled_by_agent[agent_id].append(rule_key)

    return {
        "agents": [
            {"agent_id": agent.agent_id, "hostname": agent.hostname or agent.agent_id}
            for agent in agents
        ],
        "rules": [
            {"rule_key": rule.rule_key, "category": rule.category, "is_active": bool(rule.is_active)}
            for rule in rules
        ],
        "disabled_by_agent": disabled_by_agent,
    }


@router.put("/api/agent_rule_settings/{agent_id}")
async def api_update_agent_rule_settings(
    agent_id: str,
    payload: UpdateAgentRulesRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agent = await get_agent_by_agent_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="ไม่พบ Client")

    allowed = {
        rule.rule_key for rule in await get_all_detection_rules(db)
        if rule.category != "login"
    }
    disabled = set(payload.disabled_rules)
    if not disabled <= allowed:
        raise HTTPException(status_code=400, detail="มี Rule ที่ใช้กับ Client ไม่ได้")

    await set_agent_disabled_rules(db, agent_id, disabled)
    clear_agent_rule_cache(agent_id)
    return {"status": "ok", "agent_id": agent_id, "disabled_rules": sorted(disabled)}


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


@router.post("/api/rules_restore_defaults")
async def api_restore_default_rules(
    payload: RestoreDefaultRulesRequest | None = None,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):

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
