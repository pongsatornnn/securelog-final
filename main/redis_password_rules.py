

import re
import secrets


PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128


PASSWORD_ALLOWED_RE = re.compile(r"[A-Za-z0-9_\-.~@%+=:,/]+")


MIN_DISTINCT_CHARS = 6


def generate_password(nbytes: int = 24) -> str:

    return secrets.token_urlsafe(nbytes)


def validate_password(new_password: str) -> None:

    if not new_password:
        raise ValueError("ยังไม่ได้กรอกรหัสใหม่")

    if len(new_password) < PASSWORD_MIN_LEN:
        raise ValueError(f"รหัสสั้นเกินไป ต้องยาวอย่างน้อย {PASSWORD_MIN_LEN} ตัวอักษร")

    if len(new_password) > PASSWORD_MAX_LEN:
        raise ValueError(f"รหัสยาวเกิน {PASSWORD_MAX_LEN} ตัวอักษร")

    if not PASSWORD_ALLOWED_RE.fullmatch(new_password):
        raise ValueError("รหัสมีอักขระที่ใช้ไม่ได้ — ห้ามเว้นวรรคและ # ' \" $ ` \\ !")

    if len(set(new_password)) < MIN_DISTINCT_CHARS:
        raise ValueError("รหัสซ้ำตัวอักษรเดิมมากเกินไป")
