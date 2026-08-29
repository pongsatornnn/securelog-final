from pydantic import BaseModel, Field


class UpdateAlertReadStateRequest(BaseModel):
    # body ของ POST /api/alerts_read_state — ส่งมาอย่างใดอย่างหนึ่งหรือทั้งคู่ก็ได้

    opened_ids: list[int] = Field(default_factory=list, max_length=500)
    last_seen_id: int | None = None
