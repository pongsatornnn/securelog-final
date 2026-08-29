# เงื่อนไขรหัสผ่าน Redis — **ที่เดียวของทั้งระบบ** ใช้ร่วมกันทั้งรหัสของ central (user admin)

import re
import secrets


PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128

# อักขระที่ยอมให้ใช้ — ตัดตัวที่ทำให้ไฟล์สองฝั่งเพี้ยนออกทั้งหมด:
PASSWORD_ALLOWED_RE = re.compile(r"^[A-Za-z0-9_\-.~@%+=:,/]+$")

# รหัสที่เจอบ่อยจริงในไฟล์ตัวอย่าง/เอกสาร — เดาง่ายจนไม่ต่างจากไม่ตั้ง
WEAK_PASSWORDS = frozenset({"123", "password", "redis", "admin", "changeme"})

MIN_DISTINCT_CHARS = 6


def generate_password(nbytes: int = 24) -> str:
    # สุ่มรหัสให้แอดมิน — token_urlsafe ได้ [A-Za-z0-9_-] ยาว ~32 ตัว ผ่านเงื่อนไขข้างล่างเสมอ
    return secrets.token_urlsafe(nbytes)


def validate_password(new_password: str) -> None:
    # ตรวจก่อนแตะไฟล์ใด ๆ — ผิดตรงไหนโยน ValueError พร้อมเหตุผลที่เอาไปโชว์ได้เลย
    if not new_password:
        raise ValueError("ยังไม่ได้กรอกรหัสใหม่")

    if len(new_password) < PASSWORD_MIN_LEN:
        raise ValueError(f"รหัสสั้นเกินไป ต้องยาวอย่างน้อย {PASSWORD_MIN_LEN} ตัวอักษร")

    if len(new_password) > PASSWORD_MAX_LEN:
        raise ValueError(f"รหัสยาวเกิน {PASSWORD_MAX_LEN} ตัวอักษร")

    if not PASSWORD_ALLOWED_RE.match(new_password):
        raise ValueError("รหัสมีอักขระที่ใช้ไม่ได้ — ห้ามเว้นวรรคและ # ' \" $ ` \\ !")

    if new_password.lower() in WEAK_PASSWORDS:
        raise ValueError("รหัสนี้เดาง่ายเกินไป")

    if len(set(new_password)) < MIN_DISTINCT_CHARS:
        raise ValueError("รหัสซ้ำตัวอักษรเดิมมากเกินไป")
