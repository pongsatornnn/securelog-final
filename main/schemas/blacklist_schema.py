from pydantic import BaseModel, Field


# ต้องตรงกับความยาวคอลัมน์ ip_black_list.event — ไม่กำหนดไว้แล้วค่าที่ยาวเกินจะไปตายที่
EVENT_MAX = 50

# ip_address ไม่ใส่ max_length โดยตั้งใจ — ทุก route ที่รับค่านี้ผ่าน ipaddress.ip_address()


class CreateBlacklistRequest(BaseModel):
    ip_address: str
    event: str | None = Field(default="manual_blacklist", max_length=EVENT_MAX)
    agent_id: str | None = None
    # ระยะเวลา block (วินาที) สำหรับ manual block; None = ถาวร
    duration_seconds: int | None = None


class BlacklistBulkItem(BaseModel):
    ip_address: str
    event: str | None = Field(default="manual_blacklist", max_length=EVENT_MAX)


class CreateBlacklistBulkRequest(BaseModel):
    items: list[BlacklistBulkItem]
    agent_id: str | None = None
    # ระยะเวลา block (วินาที) ใช้กับทุก IP ในชุดนี้; None = ถาวร
    duration_seconds: int | None = None


class MoveToBlacklistRequest(BaseModel):
    # ปุ่ม "→ Blacklist" ในหน้า Whitelist — ระยะเวลา block (วินาที); None = ถาวร
    duration_seconds: int | None = None
