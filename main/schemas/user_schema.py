from pydantic import BaseModel, Field

# ระบบไม่มี role แล้ว — ทุกบัญชีที่สร้างได้สิทธิ์เท่ากันหมด (เท่ากับ admin เดิม)


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    # ความยาว/ความรัดกุมจริงตรวจด้วย password_policy (ตอบเป็นข้อความไทยบอกว่าตกข้อไหน)
    password: str = Field(min_length=1, max_length=128)


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):
    # optional: บัญชีที่ถูกบังคับเปลี่ยนรหัส (login ครั้งแรก / โดน admin reset) ไม่ต้องส่งรหัสเดิม
    current_password: str | None = None
    new_password: str = Field(min_length=1, max_length=128)


class UpdateProfileRequest(BaseModel):
    name: str = Field(max_length=100)


class SetActiveRequest(BaseModel):
    is_active: bool
