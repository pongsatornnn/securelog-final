from pydantic import BaseModel, Field


class CreateUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=50)

    password: str = Field(min_length=1, max_length=128)


class ResetPasswordRequest(BaseModel):
    new_password: str = Field(min_length=1, max_length=128)


class ChangePasswordRequest(BaseModel):

    current_password: str | None = None
    new_password: str = Field(min_length=1, max_length=128)


class UpdateProfileRequest(BaseModel):
    name: str = Field(max_length=100)


class SetActiveRequest(BaseModel):
    is_active: bool
