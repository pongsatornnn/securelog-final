from pydantic import BaseModel, Field, field_validator

VALID_ROLES = ("admin", "user")


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=8, max_length=100)
    role: str = "user"

    @field_validator("role")
    @classmethod
    def role_must_be_known(cls, value: str) -> str:
        lower = value.lower().strip()
        if lower not in VALID_ROLES:
            raise ValueError(f"role ต้องเป็นหนึ่งใน {', '.join(VALID_ROLES)}")
        return lower


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=8, max_length=100)


class ChangePasswordRequest(BaseModel):
    # optional: บัญชีที่ถูกบังคับเปลี่ยนรหัส (login ครั้งแรก / โดน admin reset) ไม่ต้องส่งรหัสเดิม
    # (การเปลี่ยนเองตามปกติผ่านหน้า Profile ยังต้องส่ง — บังคับเช็คในฝั่ง route)
    current_password: str | None = None
    new_password: str = Field(min_length=8, max_length=100)


class UpdateProfileRequest(BaseModel):
    name: str = Field(max_length=100)


class SetActiveRequest(BaseModel):
    is_active: bool


class SetRoleRequest(BaseModel):
    role: str

    @field_validator("role")
    @classmethod
    def role_must_be_known(cls, value: str) -> str:
        lower = value.lower().strip()
        if lower not in VALID_ROLES:
            raise ValueError(f"role ต้องเป็นหนึ่งใน {', '.join(VALID_ROLES)}")
        return lower
