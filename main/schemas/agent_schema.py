from pydantic import BaseModel, Field


HOSTNAME_MAX = 100
DESCRIPTION_MAX = 200


class CreateAgentRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=HOSTNAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class UpdateAgentRequest(BaseModel):
    hostname: str | None = Field(default=None, max_length=HOSTNAME_MAX)
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)
    is_active: bool | None = None
