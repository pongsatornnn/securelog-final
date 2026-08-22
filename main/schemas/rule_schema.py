from pydantic import BaseModel


class UpdateRuleRequest(BaseModel):
    window_seconds: int
    threshold: int
    is_active: bool = True


class RestoreDefaultRulesRequest(BaseModel):
    """
    คืนค่า default ของ detection rule

    rule_key = None (ไม่ส่งมา / ส่ง body ว่าง) -> คืนทุก rule ที่เป็นของระบบ
    ส่ง rule_key มา -> คืนเฉพาะตัวนั้น (ปุ่มใน modal แก้ไข)
    """
    rule_key: str | None = None
