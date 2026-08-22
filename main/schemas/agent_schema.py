from pydantic import BaseModel, Field


# ไม่มี host_ip ในทั้งสองคำขอโดยตั้งใจ — IP ของ agent ถูกผูกครั้งเดียวตอนที่ agent ติดต่อเข้ามา
# สำเร็จครั้งแรก จาก interface ที่เลือกตอนรัน setup.sh บนเครื่องจริง แล้วเปลี่ยนไม่ได้อีก
# (ต้องสร้าง package ใหม่) — ถ้ารับ field นี้ผ่าน API จะกลายเป็นช่องให้ย้าย binding ได้เฉย ๆ
#
# max_length ของทุกฟิลด์ต้องตรงกับความยาวคอลัมน์ใน database/models.py — ถ้าไม่กำหนดไว้
# ค่าที่ยาวเกินจะผ่าน validation ไปตายที่ PostgreSQL (StringDataRightTruncationError)
# แล้วกลายเป็น 500 แทนที่จะเป็น 422 ที่บอกผู้ใช้ได้ว่าช่องไหนยาวเกิน
HOSTNAME_MAX = 100      # agents.hostname
DESCRIPTION_MAX = 200   # agents.description


class CreateAgentRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=HOSTNAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class UpdateAgentRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=HOSTNAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    is_active: bool | None = None
