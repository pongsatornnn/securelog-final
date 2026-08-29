from pydantic import BaseModel


class UpdateRuleRequest(BaseModel):
    window_seconds: int
    threshold: int
    is_active: bool = True


class RestoreDefaultRulesRequest(BaseModel):
    # คืนค่า default ของ detection rule
    rule_key: str | None = None
