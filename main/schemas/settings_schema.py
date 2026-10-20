from pydantic import BaseModel, Field


class UpdateSettingsRequest(BaseModel):


    values: dict[str, str] = Field(default_factory=dict)


    current_values: dict[str, str] = Field(default_factory=dict)


class RotateRedisAdminPasswordRequest(BaseModel):


    password: str = Field(default="", max_length=256)


    current_password: str = Field(default="", max_length=256)
