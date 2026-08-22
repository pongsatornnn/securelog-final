from pydantic import BaseModel


class UpdateBlacklistTtlRequest(BaseModel):
    ttl_seconds: int | None   # None = ถาวร (ไม่หมดอายุ)


class UpdateEscalationPolicyRequest(BaseModel):
    multiplier: int          # โดนซ้ำครั้งถัดไป คูณเวลาด้วยเท่าไร (1 = ไม่ทวีคูณ)
    max_block_count: int     # block_count เกินค่านี้ -> ถาวร
