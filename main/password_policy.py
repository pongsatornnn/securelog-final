# นโยบายรหัสผ่าน — นิยามกฎไว้ที่เดียว ใช้ทั้งฝั่ง server (บังคับจริง) และฝั่งหน้าเว็บ (checklist สด)
# หน้าเว็บดึงกฎชุดนี้ผ่าน GET /api/password-policy แล้วประเมินด้วยตรรกะเดียวกัน
# (static/js/password_policy.js) จึงไม่มีทางที่ checklist บนจอกับที่ server บังคับจะไม่ตรงกัน

import re

MIN_LENGTH = 8
MAX_LENGTH = 128

# kind ที่รองรับ (ทั้ง python และ js ทำเหมือนกัน):
#   length  ยาวอยู่ในช่วง min..max
#   regex   ต้อง match
RULES = [
    {
        "id": "length",
        "label": f"ยาวอย่างน้อย {MIN_LENGTH} ตัวอักษร",
        "kind": "length",
        "min": MIN_LENGTH,
        "max": MAX_LENGTH,
    },
    {"id": "lower",  "label": "มีตัวพิมพ์เล็ก (a-z)",         "kind": "regex", "pattern": "[a-z]"},
    {"id": "upper",  "label": "มีตัวพิมพ์ใหญ่ (A-Z)",         "kind": "regex", "pattern": "[A-Z]"},
    {"id": "digit",  "label": "มีตัวเลข (0-9)",               "kind": "regex", "pattern": "[0-9]"},
    {"id": "symbol", "label": "มีอักขระพิเศษ (!@#$%^&* ฯลฯ)", "kind": "regex", "pattern": "[^A-Za-z0-9]"},
]


def _rule_passed(rule: dict, password: str) -> bool:
    kind = rule["kind"]
    if kind == "length":
        return rule["min"] <= len(password) <= rule["max"]
    if kind == "regex":
        return re.search(rule["pattern"], password) is not None
    raise ValueError(f"ไม่รู้จักกฎชนิด {kind}")


def evaluate(password: str) -> list[dict]:
    # คืนสถานะของทุกข้อ (ไว้ให้ฝั่งเรียกเอาไปแสดงหรือทำ log)
    return [
        {"id": r["id"], "label": r["label"], "passed": _rule_passed(r, password or "")}
        for r in RULES
    ]


def failed_rules(password: str) -> list[dict]:
    return [r for r in evaluate(password) if not r["passed"]]


def policy_for_client() -> dict:
    # ส่งให้หน้าเว็บไปประเมินเอง (label + วิธีตรวจ) — ไม่มีความลับอะไรในนี้
    return {"min_length": MIN_LENGTH, "max_length": MAX_LENGTH, "rules": RULES}


def error_detail(failed: list[dict]) -> str:
    return "รหัสผ่านไม่ผ่านนโยบาย: " + " · ".join(r["label"] for r in failed)
