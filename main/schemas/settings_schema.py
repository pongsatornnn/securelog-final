from pydantic import BaseModel, Field


class UpdateSettingsRequest(BaseModel):
    """บันทึกค่าตั้งหลายรายการพร้อมกัน — ส่งมาเฉพาะคีย์ที่แก้จริง"""

    values: dict[str, str] = Field(default_factory=dict)

    # รหัสเดิมที่ผู้ใช้พิมพ์ยืนยัน สำหรับคีย์ที่ตั้ง confirm_current ไว้ (ตอนนี้มีตัวเดียวคือ
    current_values: dict[str, str] = Field(default_factory=dict)


class RotateRedisAdminPasswordRequest(BaseModel):
    """เปลี่ยนรหัส Redis ของ user ที่ central ใช้ (บัญชี admin) — ไม่ใช่การ "บันทึกค่า" """

    password: str = Field(default="", max_length=256)

    # รหัสเดิมที่ต้องพิมพ์ยืนยันก่อนเปลี่ยน — เทียบที่ redis_admin_password.verify_current_password
    current_password: str = Field(default="", max_length=256)
