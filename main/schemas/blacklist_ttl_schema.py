from pydantic import BaseModel


class UpdateBlacklistTtlRequest(BaseModel):
    ttl_seconds: int | None


class UpdateEscalationPolicyRequest(BaseModel):
    multiplier: int
    max_block_count: int
