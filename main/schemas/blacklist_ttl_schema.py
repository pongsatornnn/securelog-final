from pydantic import BaseModel


class UpdateBlacklistTtlRequest(BaseModel):
    ttl_seconds: int | None
    # True = block IP อัตโนมัติ · False = แจ้งเตือนอย่างเดียว
    # None = ไม่ได้สั่งเปลี่ยนโหมด (client เก่าที่ส่งมาแค่ ttl_seconds) — คงค่าเดิมใน DB
    auto_block: bool | None = None


class UpdateEscalationPolicyRequest(BaseModel):
    multiplier: int
    max_block_count: int
