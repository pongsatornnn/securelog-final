# เส้นทางจัดการ user (หน้า Manage Users) — เรียกได้เฉพาะบัญชี admin เริ่มต้น (id น้อยสุด) เท่านั้น

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from database.connection import get_db
from database.crud import (
    get_all_users, get_user, get_user_by_id, create_user, set_user_password,
    get_first_user, delete_user, set_user_active, get_view_user,
)
from view_account import is_view_role

from dependencies import require_primary_admin
from auth import hash_password
import password_policy
from shared import iso_utc

from schemas.user_schema import (
    CreateUserRequest, ResetPasswordRequest, SetActiveRequest,
)


async def get_managed_user(db: AsyncSession, user_id: int):
    # user ที่หน้า Manage Users แตะได้ — บัญชี View ไม่นับ (เปิด/ปิดผ่าน /api/users/view-account เท่านั้น)
    target = await get_user_by_id(db, user_id)
    if not target or is_view_role(target.role):
        raise HTTPException(status_code=404, detail="ไม่พบ user นี้")
    return target


router = APIRouter()


@router.get("/api/users")
async def api_get_users(
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    users = await get_all_users(db)
    # บัญชี id น้อยสุด = admin เริ่มต้น (seed ตอน DB ว่าง) — mark ไว้ให้หน้าเว็บซ่อนปุ่มลบ
    protected_id = min((u.id for u in users), default=None)
    return [
        {
            "id": u.id,
            "username": u.username,
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
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    exists = await get_user(db, payload.username)
    if exists and is_view_role(exists.role):
        raise HTTPException(status_code=409, detail="username นี้ระบบสงวนไว้ให้บัญชี View")
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
        must_change_password=True,
    )

    return {
        "status": "ok",
        "message": f"สร้าง user {created.username} สำเร็จ",
        "user": {"id": created.id, "username": created.username},
    }


@router.post("/api/users/{user_id}/reset-password")
async def api_reset_password(
    user_id: int,
    payload: ResetPasswordRequest,
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin ตั้งรหัสใหม่ให้ user คนไหนก็ได้ (รวมถึงตัวเอง) โดยไม่ต้องรู้รหัสเดิม
    target = await get_managed_user(db, user_id)

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
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin ลบ user ออกจากระบบถาวร — กันสองเคสที่ห้ามลบ:
    target = await get_managed_user(db, user_id)

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
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    # admin เปิด/ปิดใช้งาน user — บัญชีที่ถูกปิด (is_active=False) จะ login ไม่ได้ และ session ที่
    target = await get_managed_user(db, user_id)

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


# ── บัญชี View (ดูได้อย่างเดียว) — ไม่อยู่ในรายชื่อ user ข้างบน เปิด/ปิดได้ที่การ์ดของมันเองเท่านั้น ──

@router.get("/api/users/view-account")
async def api_get_view_account(
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    view_user = await get_view_user(db)
    return {
        # False = เครื่องนี้ไม่มีบัญชี View (เช่นมี user ชื่อ view ที่สร้างเองอยู่ก่อน) — หน้าเว็บซ่อนการ์ด
        "exists": view_user is not None,
        "enabled": bool(view_user and view_user.is_active),
        "username": view_user.username if view_user else None,
        "updated_at": iso_utc(view_user.updated_at) if view_user else None,
    }


@router.post("/api/users/view-account")
async def api_set_view_account(
    payload: SetActiveRequest,
    user=Depends(require_primary_admin),
    db: AsyncSession = Depends(get_db),
):
    # เปิด = หน้า login มีปุ่ม View ให้ใครก็ได้ที่เปิดหน้า login เข้ามาดู Dashboard / Alerts
    # ปิด = ปุ่มหาย และ session View ที่ค้างอยู่ตายทันที (require_login เช็ค is_active ทุก request)
    view_user = await get_view_user(db)
    if not view_user:
        raise HTTPException(status_code=404, detail="ไม่พบบัญชี View ในระบบ")

    await set_user_active(db, view_user, payload.is_active)

    return {
        "status": "ok",
        "enabled": payload.is_active,
        "message": "เปิดโหมด View แล้ว — หน้า login มีปุ่ม View" if payload.is_active
                   else "ปิดโหมด View แล้ว — ปุ่ม View หายจากหน้า login และ session ที่ค้างอยู่ถูกตัด",
    }

