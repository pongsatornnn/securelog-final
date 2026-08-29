"""เส้นทางจัดการ Agent: list/create/update/delete, regen download token,"""

import logging
import os
import time
import shutil
from pathlib import Path
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from starlette.background import BackgroundTask
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_agents,
    get_agent_by_agent_id,
    generate_next_agent_id,
    update_agent,
    count_alerts_by_agent,
    delete_agent_by_agent_id,
    invalidate_agent_downloads,
    get_agent_download_by_token_hash,
    mark_agent_downloaded,
)

from dependencies import require_login, require_admin
from redis_client import cache_get_json
from auth_cache import clear_agent_auth_cache
from shared import iso_utc

from schemas.agent_schema import CreateAgentRequest, UpdateAgentRequest

from manage_agent.create_agent_package import create_agent_package, regenerate_agent_package
from manage_agent.token_utils import hash_token


router = APIRouter()

logger = logging.getLogger("securelog.agents")

AGENT_PACKAGES_DIR = Path(__file__).resolve().parent.parent / "agent_packages"

AGENT_ONLINE_TIMEOUT_SECONDS = int(os.getenv("AGENT_ONLINE_TIMEOUT_SECONDS", "20"))


def agent_runtime_key(agent_id: str) -> str:
    return f"agent_runtime:{agent_id}"


def get_agent_runtime(agent_id: str) -> dict | None:
    return cache_get_json(agent_runtime_key(agent_id), log_prefix="AGENT_RUNTIME")


def resolve_agent_live_state(agent) -> dict:
    """ใช้ Redis runtime เป็นตัวตัดสิน online/offline แบบ real-time"""
    runtime = get_agent_runtime(agent.agent_id)
    now_ts = time.time()

    cpu = None
    ram = None
    runtime_last_seen = None
    runtime_last_seen_ts = None
    age_sec = None

    if runtime:
        cpu = runtime.get("cpu")
        ram = runtime.get("ram")
        runtime_last_seen = runtime.get("last_seen")
        runtime_last_seen_ts = runtime.get("last_seen_ts")

        try:
            runtime_last_seen_ts = float(runtime_last_seen_ts)
            age_sec = int(now_ts - runtime_last_seen_ts)
        except (TypeError, ValueError):
            age_sec = None

    if not agent.is_active:
        live_status = "offline"
    elif runtime and (age_sec is None or age_sec <= AGENT_ONLINE_TIMEOUT_SECONDS):
        live_status = "online"
    elif agent.status == "pending" and not agent.last_seen:
        live_status = "pending"
    else:
        live_status = "offline"

    return {
        "status": live_status,
        "cpu": cpu,
        "ram": ram,
        "runtime_last_seen": runtime_last_seen,
        "runtime_last_seen_ts": runtime_last_seen_ts,
        "last_seen_age_sec": age_sec,
    }


def agent_to_dict(agent):
    live = resolve_agent_live_state(agent)
    db_last_seen = iso_utc(agent.last_seen)

    return {
        "id": agent.id,
        "agent_id": agent.agent_id,
        "hostname": agent.hostname,
        "host_ip": agent.ip_address,
        # สถานะการผูก IP — host_ip ว่าง = ยังไม่เคยผูก (รอ agent รายงานมาครั้งแรก)
        "ip_interface": agent.ip_interface,
        "pending_ip": agent.pending_ip,
        "pending_ip_at": iso_utc(agent.pending_ip_at),
        "description": agent.description,
        "status": live["status"],
        "db_status": agent.status,
        "is_active": agent.is_active,
        "cpu": live["cpu"],
        "ram": live["ram"],
        "last_seen": live["runtime_last_seen"] or db_last_seen,
        "db_last_seen": db_last_seen,
        "last_seen_age_sec": live["last_seen_age_sec"],
        "created_at": iso_utc(agent.created_at),
        "updated_at": iso_utc(agent.updated_at),
    }


@router.get("/api/agents")
async def api_get_agents(
    user=Depends(require_login),
    db: AsyncSession = Depends(get_db),
):
    agents = await get_agents(db)
    # นับ alert ทีเดียวทุก agent (group by) — หน้าเว็บเอาไปบอกก่อนกดลบว่าจะลบ log ไปกี่รายการ
    alert_counts = await count_alerts_by_agent(db)
    return [
        {**agent_to_dict(agent), "alert_count": alert_counts.get(agent.agent_id, 0)}
        for agent in agents
    ]


@router.post("/api/agents")
async def api_create_agent(
    payload: CreateAgentRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agent_id = await generate_next_agent_id(db)

    exists = await get_agent_by_agent_id(db, agent_id)
    if exists:
        raise HTTPException(
            status_code=409,
            detail="Client Server ID ซ้ำ กรุณาลองใหม่อีกครั้ง",
        )

    try:
        result = await create_agent_package(
            agent_id=agent_id,
            hostname=payload.hostname,
            description=payload.description,
        )
    except Exception as exc:
        # ข้อความที่ส่งออกไปตั้งใจไม่บอกรายละเอียดภายใน แต่ถ้าไม่ log ไว้เลย ตอนเกิดปัญหาจริง
        logger.exception("สร้าง package ของ %s ไม่สำเร็จ", agent_id)
        raise HTTPException(
            status_code=500,
            detail="สร้าง Client Server package ไม่สำเร็จ",
        ) from exc

    return {
        "status": "ok",
        "agent_id": result["agent_id"],
        "download_url": result["download_url"],
    }


@router.put("/api/agents/{agent_id}")
async def api_update_agent(
    agent_id: str,
    payload: UpdateAgentRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agent = await get_agent_by_agent_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="ไม่พบ Client Server")

    old_is_active = agent.is_active

    # ไม่ส่ง ip_address ไปด้วย — IP ที่ผูกไว้แก้ผ่าน API นี้ไม่ได้โดยตั้งใจ
    agent = await update_agent(
        db=db,
        agent=agent,
        hostname=payload.hostname,
        description=payload.description,
        is_active=payload.is_active,
    )

    if old_is_active != agent.is_active:
        clear_agent_auth_cache(agent.agent_id)

    return {
        "status": "ok",
        "agent": agent_to_dict(agent),
    }


@router.delete("/api/agents/{agent_id}")
async def api_delete_agent(
    agent_id: str,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agent = await get_agent_by_agent_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="ไม่พบ Client Server")

    cert_dir = Path(agent.key_path).parent if agent.key_path else None

    deleted_agent, deleted_alerts = await delete_agent_by_agent_id(db, agent_id)
    if not deleted_agent:
        raise HTTPException(status_code=404, detail="ไม่พบ Client Server")

    # ลบไฟล์ cert/package ของ Agent ออกจากเครื่อง Central ด้วย
    package_path = AGENT_PACKAGES_DIR / f"{agent_id}.zip"
    if package_path.exists():
        package_path.unlink()

    if cert_dir and cert_dir.exists() and cert_dir.is_dir():
        shutil.rmtree(cert_dir)

    clear_agent_auth_cache(agent_id)

    # IP ที่เครื่องนี้เคยรายงานว่าโจมตี ยังอยู่ใน blacklist ตามเดิม — บอกให้ชัดในข้อความตอบกลับ
    return {
        "status": "ok",
        "deleted_alerts": deleted_alerts,
        "message": (
            f"ลบ {agent_id} สำเร็จ · ลบ log/alert ของเครื่องนี้ {deleted_alerts} รายการ "
            "· IP ที่บล็อกไว้ยังอยู่ตามกติกา blacklist เดิม"
        ),
    }


@router.post("/api/agents/{agent_id}/regen-download")
async def api_regen_agent_download(
    agent_id: str,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    agent = await get_agent_by_agent_id(db, agent_id)
    if not agent:
        raise HTTPException(status_code=404, detail="ไม่พบ Client Server")

    # ปิดลิงก์เก่าที่ยังไม่ได้ใช้ก่อนสร้างลิงก์ใหม่
    await invalidate_agent_downloads(db, agent_id)

    try:
        result = await regenerate_agent_package(agent)
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail=f"สร้าง download link ใหม่ไม่สำเร็จ: {exc}",
        )

    return {
        "status": "ok",
        "agent_id": result["agent_id"],
        "download_url": result["download_url"],
    }


@router.get("/download-agent/{download_token}")
async def download_agent_package(
    download_token: str,
    db: AsyncSession = Depends(get_db),
):
    token_hash = hash_token(download_token)
    download = await get_agent_download_by_token_hash(db, token_hash)

    if not download:
        raise HTTPException(
            status_code=404,
            detail="ไม่พบ download token",
        )

    if download.expires_at < datetime.now():
        raise HTTPException(
            status_code=410,
            detail="download token หมดอายุแล้ว",
        )

    if download.downloaded:
        raise HTTPException(
            status_code=410,
            detail="ไฟล์นี้ถูกดาวน์โหลดไปแล้ว",
        )

    zip_path = Path(download.zip_path)

    if not zip_path.exists():
        raise HTTPException(
            status_code=404,
            detail="ไม่พบไฟล์ package",
        )

    await mark_agent_downloaded(db, download)

    agent = await get_agent_by_agent_id(db, download.agent_id)
    cert_dir = Path(agent.key_path).parent if agent and agent.key_path else None

    # ลบไฟล์ zip + cert dir ของ agent ทิ้งหลังส่งให้ client จบแล้ว
    return FileResponse(
        path=str(zip_path),
        filename=zip_path.name,
        media_type="application/zip",
        background=BackgroundTask(_remove_package_files, zip_path, cert_dir),
    )


def _remove_package_files(zip_path: Path, cert_dir: Path | None):
    try:
        zip_path.unlink(missing_ok=True)
    except OSError:
        pass
    if cert_dir and cert_dir.is_dir():
        shutil.rmtree(cert_dir, ignore_errors=True)
