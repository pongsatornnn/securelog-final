"""
เข้ารหัสค่า secret ก่อนเก็บลงฐานข้อมูล (encryption at rest) — ใช้กับตาราง app_settings

**ปัญหาที่แก้:** คีย์ LINE/Gemini และรหัส Redis ของ agent ย้ายจาก .env มาอยู่ใน DB เพื่อให้
ตั้งผ่านหน้าเว็บได้ ผลข้างเคียงคือ **ใครได้ backup ของ DB ไปก็อ่านคีย์ได้ทันที** (เดิมอยู่ใน
.env สิทธิ์ 0600 ซึ่งไม่ติดไปกับ pg_dump) โมดูลนี้ทำให้ค่าที่เก็บใน DB เป็น ciphertext
กุญแจอยู่ **นอกฐานข้อมูล** (ไฟล์บนเครื่อง) — ได้ dump ไปอย่างเดียวจึงถอดไม่ได้

**กุญแจ:** ไฟล์ `.settings_key` ที่ repo root (สิทธิ์ 0600, อยู่ใน .gitignore)
สร้างให้อัตโนมัติครั้งแรกที่ใช้งาน ไม่ต้องตั้งเอง · ย้ายที่เก็บได้ด้วย env `SETTINGS_KEY_FILE`

⚠️ **กุญแจหาย = ค่าที่เข้ารหัสไว้กู้ไม่ได้** (ตั้งใจให้เป็นแบบนั้น) ระบบจะไม่พัง —
ค่าที่ถอดไม่ได้จะถูกมองว่า "ยังไม่ได้ตั้ง" แล้วแอดมินกรอกใหม่ในหน้า System Settings ได้
ถ้าย้ายเครื่อง/กู้ระบบ ให้ก๊อป `.settings_key` ไปด้วยคู่กับ `.env`

**เก็บเฉพาะค่าที่เป็น secret** — ค่าที่ไม่ลับ (เช่น ชื่อโมเดล, port, username) เก็บเป็น
plaintext เหมือนเดิม เพื่อให้ยังอ่าน/แก้จาก psql ตอน debug ได้ และไม่มีอะไรต้องปิดบัง
"""

import base64
import os
import secrets

from cryptography.fernet import Fernet, InvalidToken


LOG_PREFIX = "SECRET-BOX"

# ค่าที่ผ่านการเข้ารหัสแล้วขึ้นต้นด้วยคำนำหน้านี้เสมอ — ใช้แยกจากค่า plaintext เดิม
# ที่เก็บไว้ก่อนจะมีการเข้ารหัส (ทำให้อัปเกรดได้โดยไม่ต้องล้างค่าเก่าทิ้ง)
# มีเลขเวอร์ชันไว้เผื่อเปลี่ยนวิธีเข้ารหัสในอนาคตแล้วยังอ่านของเก่าออก
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
    """
    อ่านกุญแจจากไฟล์ ถ้ายังไม่มีก็สร้างให้ (สิทธิ์ 0600)

    สร้างเองอัตโนมัติโดยตั้งใจ: ถ้าบังคับให้แอดมินไปตั้ง env เองก่อน เครื่องที่อัปเกรดมา
    จะใช้หน้า Settings ไม่ได้จนกว่าจะไปแก้ไฟล์ — ซึ่งขัดกับเหตุผลที่ทำหน้านี้ตั้งแต่แรก
    """
    path = key_file_path()

    if os.path.exists(path):
        with open(path, "rb") as f:
            key = f.read().strip()
        if key:
            return key

    key = base64.urlsafe_b64encode(secrets.token_bytes(32))

    # เขียนแบบตั้งสิทธิ์ตั้งแต่ตอนสร้างไฟล์ ไม่ใช่เขียนก่อนแล้วค่อย chmod
    # (ช่วงระหว่างนั้นไฟล์กุญแจจะอ่านได้จาก user อื่นบนเครื่อง)
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
    """
    ถอดค่าที่เข้ารหัสไว้ · ค่าที่ยังเป็น plaintext (ของเก่าก่อนอัปเกรด) คืนไปตามเดิม

    ถอดไม่ได้ (กุญแจหาย/ถูกเปลี่ยน/ค่าเสียหาย) → คืนค่าว่าง + เตือนใน log
    **ไม่โยน exception ออกไป** เพราะตัวเรียกคือเส้นทางส่งแจ้งเตือนและหน้าเว็บ
    ถ้าพังทั้งเส้นเพราะคีย์เดียวถอดไม่ออก จะเสียมากกว่าได้ — ให้ระบบทำงานต่อแบบ
    "ยังไม่ได้ตั้งค่า" แล้วแอดมินกรอกใหม่ดีกว่า
    """
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
