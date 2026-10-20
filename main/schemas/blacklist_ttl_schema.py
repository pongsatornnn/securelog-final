from pydantic import BaseModel


class UpdateBlacklistTtlRequest(BaseModel):
    ttl_seconds: int | None


    auto_block: bool | None = None

    notify_line: bool | None = None


class UpdateEscalationPolicyRequest(BaseModel):
    multiplier: int
    max_block_count: int
