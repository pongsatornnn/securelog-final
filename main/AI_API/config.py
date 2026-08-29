# ค่า config ของ Gemini (AI สรุป log ใน alert) — API key/model ตั้งได้จากหน้า System Settings (`/settings`)

import os

from dotenv import load_dotenv

from settings_cache import GEMINI_MODEL_CHOICES, get_setting

load_dotenv()

def api_key() -> str:
    return get_setting("gemini_api_key")


def model() -> str:
    # โมเดลที่ใช้สรุป log — เลือกจาก dropdown ในหน้า Settings (รายชื่อดึงจากคีย์ตัวที่ตั้งไว้)
    return get_setting("gemini_model")

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

# รายชื่อโมเดลที่คีย์นั้นเรียกได้ — ใช้ทำตัวเลือกใน dropdown ของหน้า Settings
LIST_MODELS_URL = f"{API_BASE}?pageSize=200"

# โมเดลที่ระบบยอมให้เลือก — เป็น **allowlist** ไม่ใช่การไล่กรองคำต้องห้าม เพราะรายชื่อฝั่ง
MODEL_ALLOWLIST = tuple(GEMINI_MODEL_CHOICES)

# แอดมินกดปุ่มแล้วต้องนั่งรอ -> ตั้ง timeout ไม่ให้ค้างนานเกินไป
FALLBACK_TIMEOUT_SEC = 120


def timeout_sec() -> int:
    # เวลารอ Google ตอบกลับ — **ตั้งจากหน้า System Settings ได้** เพราะโมเดลแต่ละตัวช้าไม่เท่ากันมาก
    try:
        value = int(get_setting("gemini_timeout_sec"))
    except (TypeError, ValueError):
        return FALLBACK_TIMEOUT_SEC

    return value if value > 0 else FALLBACK_TIMEOUT_SEC

# โมเดล Gemini "คิด" ก่อนตอบ และ token ที่ใช้คิด (thoughtsTokenCount) ถูกหักจาก
THINKING_BUDGET = int(os.getenv("GEMINI_THINKING_BUDGET", "0"))

# รุ่น 3 ขึ้นไปเลิกรับ thinkingBudget แล้ว (ส่งไปได้ 400 INVALID_ARGUMENT) เปลี่ยนมาคุมเป็น
THINKING_LEVEL = os.getenv("GEMINI_THINKING_LEVEL", "low")

# เพดานความยาวคำตอบ — เผื่อไว้มากกว่าที่ใช้จริง (สรุป 1 เหตุการณ์ ~500-700 token)
MAX_OUTPUT_TOKENS = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "4096"))

# จำนวน raw log สูงสุดที่ส่งเข้า prompt — เหตุการณ์ที่ merge กันเยอะ ๆ มี log ได้เป็นร้อยบรรทัด
MAX_LOGS_IN_PROMPT = int(os.getenv("GEMINI_MAX_LOGS", "40"))

# ตัดความยาวต่อบรรทัด กัน log ผิดปกติ (เช่น payload ยาว ๆ ของ SQLi) กิน token หมด
MAX_LOG_LINE_CHARS = 500


def is_configured() -> bool:
    return bool(api_key())


def generate_url() -> str:
    return f"{API_BASE}/{model()}:generateContent"
