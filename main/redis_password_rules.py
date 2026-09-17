# เงื่อนไขรหัสผ่าน Redis — **ที่เดียวของทั้งระบบ** ใช้ร่วมกันทั้งรหัสของ central (user admin)

import re
import secrets


PASSWORD_MIN_LEN = 12
PASSWORD_MAX_LEN = 128

# อักขระที่ยอมให้ใช้ — ตัดตัวที่ทำให้ไฟล์สองฝั่งเพี้ยนออกทั้งหมด:
# ใช้คู่กับ fullmatch เท่านั้น: `match()` + `$` ของ re ยอมให้มี newline ปิดท้ายได้
# ("abc\n" ผ่าน) ซึ่งจะกลายเป็นบรรทัดเสียใน users.acl ตอนเขียนไฟล์ — ฝั่ง JS ไม่ยอมอยู่แล้ว
PASSWORD_ALLOWED_RE = re.compile(r"[A-Za-z0-9_\-.~@%+=:,/]+")

# เคยมีลิสต์ "รหัสเดาง่าย" (changeme/password/admin/…) อยู่ตรงนี้ — เอาออกแล้ว (2026-09-17)
# ตอนเทียบทั้งรหัสมันไม่เคยทำงานเลย (ทุกคำสั้นกว่า 12 ตัว ตกด่านความยาวไปก่อน) พอเปลี่ยนเป็น
# เช็คว่า "มีคำนี้อยู่ข้างใน" ก็เข้มเกินไป (รหัสอย่าง Prod-Admin-2026 โดนปฏิเสธ) —
# ผู้ใช้เลือกเอาแค่เงื่อนไขพื้นฐาน: ความยาว + อักขระที่ใช้ได้ + ตัวอักษรต้องไม่ซ้ำกันทั้งชุด
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

    if not PASSWORD_ALLOWED_RE.fullmatch(new_password):
        raise ValueError("รหัสมีอักขระที่ใช้ไม่ได้ — ห้ามเว้นวรรคและ # ' \" $ ` \\ !")

    if len(set(new_password)) < MIN_DISTINCT_CHARS:
        raise ValueError("รหัสซ้ำตัวอักษรเดิมมากเกินไป")
