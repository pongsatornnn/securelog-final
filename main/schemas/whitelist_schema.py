"""
Schema ของ Whitelist — เดิมสอง endpoint นี้อ่าน body ด้วย `await request.json()` ตรง ๆ
โดยไม่มี try/except ครอบ body ที่ parse ไม่ผ่านจึงกลายเป็น JSONDecodeError หลุดขึ้นไป
เป็น 500 (endpoint อื่นที่ใช้ Pydantic ตอบ 422 ตามปกติ) — ย้ายมาใช้ model แล้ว FastAPI
จัดการให้เองทั้งการ parse และเพดานความยาว
"""

from pydantic import BaseModel, Field


# ต้องตรงกับความยาวคอลัมน์ ip_white_list.description
DESCRIPTION_MAX = 200


# ip_address มีค่าเริ่มต้นเป็นสตริงว่าง ไม่ใช่ฟิลด์บังคับ โดยตั้งใจ — body ที่ไม่มีฟิลด์นี้
# จะได้ตกไปเจอด่าน "กรุณากรอก IP Address" (400 ข้อความไทย) ในตัว route เหมือนเดิม
# ไม่ใช่ 422 ของ Pydantic ที่อธิบายให้ผู้ใช้หน้าเว็บไม่ได้
class CreateWhitelistRequest(BaseModel):
    ip_address: str = ""
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class WhitelistBulkItem(BaseModel):
    ip_address: str = ""
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class CreateWhitelistBulkRequest(BaseModel):
    # ไม่ส่ง items มาเลย = ลิสต์ว่าง -> route ตอบ 400 "กรุณากรอก IP อย่างน้อย 1 รายการ"
    items: list[WhitelistBulkItem] = Field(default_factory=list)
