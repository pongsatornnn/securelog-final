from pydantic import BaseModel, Field


DESCRIPTION_MAX = 200


class AddSignatureRequest(BaseModel):
    detection_type: str
    pattern: str
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class UpdateSignatureActiveRequest(BaseModel):
    is_active: bool


class EditSignatureRequest(BaseModel):

    pattern: str
    description: str | None = Field(default=None, max_length=DESCRIPTION_MAX)


class RestoreDefaultSignaturesRequest(BaseModel):

    detection_type: str | None = None
