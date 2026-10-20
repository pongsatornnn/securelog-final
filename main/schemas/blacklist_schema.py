from pydantic import BaseModel, Field


EVENT_MAX = 50


class CreateBlacklistRequest(BaseModel):
    ip_address: str
    event: str | None = Field(default="manual_blacklist", max_length=EVENT_MAX)
    agent_id: str | None = None

    duration_seconds: int | None = None


class BlacklistBulkItem(BaseModel):
    ip_address: str
    event: str | None = Field(default="manual_blacklist", max_length=EVENT_MAX)


class CreateBlacklistBulkRequest(BaseModel):
    items: list[BlacklistBulkItem]
    agent_id: str | None = None

    duration_seconds: int | None = None


class MoveToBlacklistRequest(BaseModel):

    duration_seconds: int | None = None
