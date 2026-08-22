from pydantic import BaseModel, Field


# ต้องตรงกับความยาวคอลัมน์ detection_signatures.description
# (pattern เป็น TEXT ไม่มีเพดาน จึงไม่ต้องกำหนด — ดูเหตุผลเต็มใน schemas/agent_schema.py)
DESCRIPTION_MAX = 200


class AddSignatureRequest(BaseModel):
    detection_type: str
    pattern: str
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class UpdateSignatureActiveRequest(BaseModel):
    is_active: bool


class EditSignatureRequest(BaseModel):
    """แก้ pattern/คำอธิบายของ signature เดิม (detection_type เปลี่ยนไม่ได้)"""
    pattern: str
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class RestoreDefaultSignaturesRequest(BaseModel):
    """
    คืนค่า default ของ signature

    detection_type = None -> คืนทุกชนิด · ส่งมา -> คืนเฉพาะชนิดนั้น (ปุ่มบนแท็บที่เปิดอยู่)
    ทั้งสองแบบแตะเฉพาะแถวของระบบ (is_default) — แถวที่แอดมินเพิ่มเองไม่ถูกแตะ
    """
    detection_type: str | None = None
