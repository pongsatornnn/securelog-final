# เส้นทางจัดการ user (หน้า Manage Users) — เฉพาะ role=admin เข้าได้ (require_admin)

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_all_users, get_user, get_user_by_id, create_user, set_user_password,
    get_first_user, delete_user, set_user_active, set_user_role,
)

from dependencies import require_admin
from auth import hash_password
import password_policy
from shared import iso_utc

from schemas.user_schema import (
    CreateUserRequest, ResetPasswordRequest, SetActiveRequest, SetRoleRequest,
)


router = APIRouter()


@router.get("/api/users")
async def api_get_users(
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    users = await get_all_users(db)
    # บัญชี id น้อยสุด = admin เริ่มต้น (seed ตอน DB ว่าง) — mark ไว้ให้หน้าเว็บซ่อนปุ่มลบ
    protected_id = min((u.id for u in users), default=None)
    return [
        {
            "id": u.id,
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "must_change_password": u.must_change_password,
            "is_protected": u.id == protected_id,
            "created_at": iso_utc(u.created_at),
            "updated_at": iso_utc(u.updated_at),
        }
        for u in users
    ]


@router.post("/api/users")
async def api_create_user(
    payload: CreateUserRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    exists = await get_user(db, payload.username)
    if exists:
        raise HTTPException(status_code=409, detail="มี username นี้อยู่แล้ว")

    # นโยบายรหัสผ่าน — กฎชุดเดียวกับ checklist ที่หน้าเว็บแสดงตอนพิมพ์
    failed = password_policy.failed_rules(payload.password)
    if failed:
        raise HTTPException(
            status_code=400,
            detail=password_policy.error_detail(failed),
            headers={"X-Password-Policy-Failed": ",".join(r["id"] for r in failed)},
        )

    # admin เป็นคนตั้งรหัสแรกให้ (ไม่ใช่รหัสที่เจ้าของบัญชีตั้งเอง) จึงบังคับเปลี่ยนตอน login
    created = await create_user(
        db, payload.username, hash_password(payload.password),
        role=payload.role, must_change_password=True,
    )

    return {
        "status": "ok",
        "message": f"สร้าง user {created.username} สำเร็จ",
        "user": {"id": created.id, "username": created.username, "role": created.role},
    }


@router.post("/api/users/{user_id}/reset-password")
async def api_reset_password(
    user_id: int,
    payload: ResetPasswordRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin ตั้งรหัสใหม่ให้ user คนไหนก็ได้ (รวมถึงตัวเอง) โดยไม่ต้องรู้รหัสเดิม
    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="ไม่พบ user นี้")

    failed = password_policy.failed_rules(payload.new_password)
    if failed:
        raise HTTPException(
            status_code=400,
            detail=password_policy.error_detail(failed),
            headers={"X-Password-Policy-Failed": ",".join(r["id"] for r in failed)},
        )

    await set_user_password(db, target, hash_password(payload.new_password), must_change_password=True)

    return {
        "status": "ok",
        "message": f"ตั้งรหัสผ่านใหม่ให้ {target.username} สำเร็จ (ต้องเปลี่ยนรหัสตอน login ครั้งถัดไป)",
    }


@router.delete("/api/users/{user_id}")
async def api_delete_user(
    user_id: int,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin ลบ user ออกจากระบบถาวร — กันสองเคสที่ห้ามลบ:
    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="ไม่พบ user นี้")

    first_user = await get_first_user(db)
    if first_user and target.id == first_user.id:
        raise HTTPException(status_code=403, detail="ลบบัญชี admin เริ่มต้นไม่ได้")

    if target.username == user["username"]:
        raise HTTPException(status_code=400, detail="ลบบัญชีที่กำลังใช้งานอยู่ไม่ได้")

    await delete_user(db, target)

    return {
        "status": "ok",
        "message": f"ลบ user {target.username} สำเร็จ",
    }


@router.post("/api/users/{user_id}/set-active")
async def api_set_user_active(
    user_id: int,
    payload: SetActiveRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin เปิด/ปิดใช้งาน user — บัญชีที่ถูกปิด (is_active=False) จะ login ไม่ได้ และ session ที่
    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="ไม่พบ user นี้")

    if not payload.is_active:
        first_user = await get_first_user(db)
        if first_user and target.id == first_user.id:
            raise HTTPException(status_code=403, detail="ปิดใช้งานบัญชี admin เริ่มต้นไม่ได้")
        if target.username == user["username"]:
            raise HTTPException(status_code=400, detail="ปิดใช้งานบัญชีที่กำลังใช้งานอยู่ไม่ได้")

    await set_user_active(db, target, payload.is_active)

    return {
        "status": "ok",
        "message": f"{'เปิด' if payload.is_active else 'ปิด'}ใช้งาน user {target.username} สำเร็จ",
    }


@router.post("/api/users/{user_id}/set-role")
async def api_set_user_role(
    user_id: int,
    payload: SetRoleRequest,
    user=Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin เปลี่ยน role ของ user (admin <-> user) — มีผลกับ session ที่ค้างอยู่ทันทีรอบ request ถัดไป
    target = await get_user_by_id(db, user_id)
    if not target:
        raise HTTPException(status_code=404, detail="ไม่พบ user นี้")

    first_user = await get_first_user(db)
    if first_user and target.id == first_user.id:
        raise HTTPException(status_code=403, detail="เปลี่ยน role ของ admin เริ่มต้นไม่ได้")

    if target.username == user["username"]:
        raise HTTPException(status_code=400, detail="เปลี่ยน role ของบัญชีตัวเองไม่ได้")

    await set_user_role(db, target, payload.role)

    return {
        "status": "ok",
        "message": f"เปลี่ยน role ของ {target.username} เป็น {payload.role} สำเร็จ",
    }
