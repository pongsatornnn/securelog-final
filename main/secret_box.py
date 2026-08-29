"""เข้ารหัสค่า secret ก่อนเก็บลงฐานข้อมูล (encryption at rest) — ใช้กับตาราง app_settings"""

import base64
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken


LOG_PREFIX = "SECRET-BOX"

# ค่าที่ผ่านการเข้ารหัสแล้วขึ้นต้นด้วยคำนำหน้านี้เสมอ — ใช้แยกจากค่า plaintext เดิม
ENC_PREFIX = "enc:v1:"

DEFAULT_KEY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    ".settings_key",
)

# อ่านไฟล์กุญแจครั้งเดียวแล้วถือไว้ใน process — get_setting() ถูกเรียกทุกครั้งที่ยิง LINE/Gemini
_fernet: Fernet | None = None


def key_file_path() -> str:
    return os.getenv("SETTINGS_KEY_FILE") or DEFAULT_KEY_FILE


def _load_or_create_key() -> bytes:
    """อ่านกุญแจจากไฟล์ ถ้ายังไม่มีก็สร้างให้ (สิทธิ์ 0600)"""
    path = key_file_path()

    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read().strip()
        if key:
            return key

    key = base64.urlsafe_b64encode(secrets.token_bytes(32))

    # เขียนแบบตั้งสิทธิ์ตั้งแต่ตอนสร้างไฟล์ ไม่ใช่เขียนก่อนแล้วค่อย chmod
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)

    print(f"[{LOG_PREFIX}] สร้างกุญแจใหม่ที่ {path} (สิทธิ์ 600) — สำรองไฟล์นี้ไว้คู่กับ .env")
    return key


def _box() -> Fernet:
    global _fernet
    if _fernet is None:
        _fernet = Fernet(_load_or_create_key())
    return _fernet


def is_encrypted(value: str | None) -> bool:
    return bool(value) and value.startswith(ENC_PREFIX)


def encrypt(value: str) -> str:
    """คืน ciphertext พร้อมคำนำหน้า · ค่าว่างไม่เข้ารหัส (ไม่มีอะไรให้ปิด และทำให้เช็ค 'ยังไม่ตั้ง' ง่าย)"""
    if not value:
        return ""
    return ENC_PREFIX + _box().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt(value: str | None) -> str:
    """ถอดค่าที่เข้ารหัสไว้ · ค่าที่ยังเป็น plaintext (ของเก่าก่อนอัปเกรด) คืนไปตามเดิม"""
    if not value:
        return ""

    if not is_encrypted(value):
        return value

    try:
        return _box().decrypt(value[len(ENC_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError) as e:
        print(
            f"[{LOG_PREFIX}] ถอดรหัสค่าไม่สำเร็จ ({type(e).__name__}) — "
            f"กุญแจ {key_file_path()} ไม่ตรงกับตอนที่เข้ารหัสไว้ "
            f"ให้ตั้งค่านั้นใหม่ที่หน้า System Settings"
        )
        return ""
