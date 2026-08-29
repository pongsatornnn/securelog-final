# เส้นทางดู/เพิ่ม/ปิด/ลบ signature (regex) ของ Signature-based detector

from fastapi import APIRouter, Depends, HTTPException

from dependencies import require_admin
from signature_cache import (
    DEFAULT_SIGNATURES,
    is_valid_regex,
    list_signatures,
    add_signature,
    update_signature,
    set_signature_active,
    remove_signature,
    restore_default_signatures,
)

from schemas.signature_schema import (
    AddSignatureRequest,
    EditSignatureRequest,
    UpdateSignatureActiveRequest,
    RestoreDefaultSignaturesRequest,
)


router = APIRouter()

VALID_DETECTION_TYPES = set(DEFAULT_SIGNATURES.keys())


@router.get("/api/signatures")
async def api_get_signatures(user=Depends(require_admin)):
    return await list_signatures()


@router.post("/api/signatures")
async def api_add_signature(
    payload: AddSignatureRequest,
    user=Depends(require_admin),
):
    if payload.detection_type not in VALID_DETECTION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"detection_type ไม่ถูกต้อง (รองรับ: {sorted(VALID_DETECTION_TYPES)})",
        )

    pattern = (payload.pattern or "").strip()
    if not pattern:
        raise HTTPException(status_code=400, detail="pattern ห้ามว่าง")

    if not is_valid_regex(pattern):
        raise HTTPException(status_code=400, detail="regex ไม่ถูกต้อง compile ไม่ผ่าน")

    result = await add_signature(
        payload.detection_type,
        pattern,
        description=payload.description,
    )

    return {
        "status": "ok",
        "message": "มี pattern นี้อยู่แล้ว" if result.get("duplicated") else "เพิ่ม signature สำเร็จ",
        "signature": result,
    }


@router.post("/api/signatures/{signature_id}/edit")
async def api_edit_signature(
    signature_id: int,
    payload: EditSignatureRequest,
    user=Depends(require_admin),
):
    # แก้ pattern/คำอธิบายของ signature เดิม — detection_type เปลี่ยนไม่ได้
    pattern = (payload.pattern or "").strip()

    if not pattern:
        raise HTTPException(status_code=400, detail="pattern ห้ามว่าง")

    if not is_valid_regex(pattern):
        raise HTTPException(status_code=400, detail="regex ไม่ถูกต้อง compile ไม่ผ่าน")

    # ส่งเป็นสตริงเสมอ (ว่างได้) เพื่อให้ "ลบคำอธิบายทิ้ง" ทำได้จริง —
    description = (payload.description or "").strip()

    try:
        result = await update_signature(
            signature_id,
            pattern=pattern,
            description=description,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not result:
        raise HTTPException(status_code=404, detail=f"ไม่พบ signature id={signature_id}")

    return {
        "status": "ok",
        "message": f"แก้ไข signature id={signature_id} สำเร็จ",
        "signature": result,
    }


@router.post("/api/signatures/{signature_id}")
async def api_update_signature_active(
    signature_id: int,
    payload: UpdateSignatureActiveRequest,
    user=Depends(require_admin),
):
    result = await set_signature_active(signature_id, is_active=payload.is_active)

    if not result:
        raise HTTPException(status_code=404, detail=f"ไม่พบ signature id={signature_id}")

    return {
        "status": "ok",
        "message": f"อัปเดต signature id={signature_id} สำเร็จ",
        "signature": result,
    }


@router.delete("/api/signatures/{signature_id}")
async def api_delete_signature(
    signature_id: int,
    user=Depends(require_admin),
):
    result = await remove_signature(signature_id)

    if not result:
        raise HTTPException(status_code=404, detail=f"ไม่พบ signature id={signature_id}")

    return {
        "status": "ok",
        "message": f"ลบ signature id={signature_id} สำเร็จ",
        "signature": result,
    }


# path แบน (ไม่ใช่ /api/signatures/restore-defaults) ด้วยเหตุผลเดียวกับ routes/rules.py
@router.post("/api/signatures_restore_defaults")
async def api_restore_default_signatures(
    payload: RestoreDefaultSignaturesRequest | None = None,
    user=Depends(require_admin),
):
    # คืนค่า signature ของระบบกลับเป็นชุด default — ไม่ส่ง detection_type = ทำทุกชนิด
    detection_type = payload.detection_type if payload else None

    if detection_type and detection_type not in VALID_DETECTION_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"detection_type ไม่ถูกต้อง (รองรับ: {sorted(VALID_DETECTION_TYPES)})",
        )

    result = await restore_default_signatures(detection_type)

    scope = detection_type or "ทุกชนิด"
    return {
        "status": "ok",
        "message": (
            f"คืนค่า default ของ {scope} แล้ว {result['restored']} pattern "
            "(signature ที่เพิ่มเองไม่ถูกแตะ)"
        ),
        **result,
    }
