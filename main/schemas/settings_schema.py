from pydantic import BaseModel, Field


class UpdateSettingsRequest(BaseModel):
    """
    บันทึกค่าตั้งหลายรายการพร้อมกัน — ส่งมาเฉพาะคีย์ที่แก้จริง

    ค่าที่เป็น secret หน้าเว็บจะไม่ส่งมาถ้าผู้ใช้ไม่ได้พิมพ์ค่าใหม่ ไม่งั้นค่าที่ mask ไว้
    ('••••••••abcd') จะถูกบันทึกทับของจริง · คีย์ที่ระบบไม่รู้จักถูกปฏิเสธที่ route (404)
    """

    values: dict[str, str] = Field(default_factory=dict)

    # รหัสเดิมที่ผู้ใช้พิมพ์ยืนยัน สำหรับคีย์ที่ตั้ง confirm_current ไว้ (ตอนนี้มีตัวเดียวคือ
    # agent_redis_password) — คีย์อื่นส่งมาก็ไม่ถูกใช้ ที่ route เทียบเฉพาะคีย์ที่ต้องยืนยัน
    current_values: dict[str, str] = Field(default_factory=dict)


class RotateRedisAdminPasswordRequest(BaseModel):
    """
    เปลี่ยนรหัส Redis ของ user ที่ central ใช้ (บัญชี admin) — ไม่ใช่การ "บันทึกค่า"
    แต่เป็นการสั่งให้ระบบไปแก้ users.acl + .env ของจริง จึงแยก endpoint ออกจาก /api/settings

    ตรวจความยาว/อักขระจริงที่ redis_password_rules.validate_password (ที่เดียว ไม่ตรวจสองที่
    ให้เงื่อนไขหลุดกัน) — ที่นี่กันแค่ payload ที่ใหญ่ผิดปกติก่อนถึง handler
    """

    password: str = Field(default="", max_length=256)

    # รหัสเดิมที่ต้องพิมพ์ยืนยันก่อนเปลี่ยน — เทียบที่ redis_admin_password.verify_current_password
    current_password: str = Field(default="", max_length=256)
