from pydantic import BaseModel, Field


class UpdateAlertReadStateRequest(BaseModel):


    opened_ids: list[int] = Field(default_factory=list, max_length=500)
    last_seen_id: int | None = None
