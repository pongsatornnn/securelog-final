

from pydantic import BaseModel, Field


DESCRIPTION_MAX = 200


class CreateWhitelistRequest(BaseModel):
    ip_address: str = ""
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class WhitelistBulkItem(BaseModel):
    ip_address: str = ""
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class CreateWhitelistBulkRequest(BaseModel):

    items: list[WhitelistBulkItem] = Field(default_factory=list)
