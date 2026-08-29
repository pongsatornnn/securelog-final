from pydantic import BaseModel, Field


# ต้องตรงกับความยาวคอลัมน์ detection_signatures.description
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
    """คืนค่า default ของ signature"""
    detection_type: str | None = None
