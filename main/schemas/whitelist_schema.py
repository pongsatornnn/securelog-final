"""Schema ของ Whitelist — เดิมสอง endpoint นี้อ่าน body ด้วย `await request.json()` ตรง ๆ"""

from pydantic import BaseModel, Field


# ต้องตรงกับความยาวคอลัมน์ ip_white_list.description
DESCRIPTION_MAX = 200


# ip_address มีค่าเริ่มต้นเป็นสตริงว่าง ไม่ใช่ฟิลด์บังคับ โดยตั้งใจ — body ที่ไม่มีฟิลด์นี้
class CreateWhitelistRequest(BaseModel):
    ip_address: str = ""
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class WhitelistBulkItem(BaseModel):
    ip_address: str = ""
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class CreateWhitelistBulkRequest(BaseModel):
    # ไม่ส่ง items มาเลย = ลิสต์ว่าง -> route ตอบ 400 "กรุณากรอก IP อย่างน้อย 1 รายการ"
    items: list[WhitelistBulkItem] = Field(default_factory=list)
