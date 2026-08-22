from pydantic import BaseModel, field_validator

from severity_cache import VALID_SEVERITIES


class UpdateAlertSeverityRequest(BaseModel):
    severity: str

    @field_validator("severity")
    @classmethod
    def severity_must_be_known(cls, value: str) -> str:
        upper = value.upper()
        if upper not in VALID_SEVERITIES:
            raise ValueError(f"severity ต้องเป็นหนึ่งใน {', '.join(VALID_SEVERITIES)}")
        return upper
