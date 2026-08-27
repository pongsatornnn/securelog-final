"""
ค่า config ของ Gemini (AI สรุป log ใน alert) — API key/model ตั้งได้จากหน้า System Settings (`/settings`)

api_key()/model()/timeout_sec() เป็น **ฟังก์ชัน** เพราะอ่านค่าตอนเรียกใช้ (settings_cache)
แก้แล้วมีผลทันทีไม่ต้อง restart — timeout อยู่กลุ่มนี้เพราะต้องขยับตามโมเดลที่เลือก
ส่วนค่าจูนที่เหลือ (token/จำนวน log) ยังอยู่ที่ .env เพราะเป็นค่าที่ปรับครั้งเดียวตอนตั้งระบบ
ไม่ใช่ของที่แอดมินต้องมาแก้บ่อย ๆ จากหน้าเว็บ

ลำดับการหาค่า: Redis cache -> ตาราง app_settings -> .env
(GEMINI_API_KEY / GEMINI_MODEL / GEMINI_TIMEOUT_SEC)

ออกแบบเป็น "เรียกตอนกดปุ่ม" (on-demand) ไม่ใช่ worker แยกแบบ LINE_API:
detector ไม่ import โมดูลนี้เลย -> AI ล่ม/ไม่มี key/โควตาหมด ก็ไม่กระทบการตรวจจับ + block + LINE
"""

import os

from dotenv import load_dotenv

from settings_cache import GEMINI_MODEL_CHOICES, get_setting

load_dotenv()

def api_key() -> str:
    return get_setting("gemini_api_key")


def model() -> str:
    """โมเดลที่ใช้สรุป log — เลือกจาก dropdown ในหน้า Settings (รายชื่อดึงจากคีย์ตัวที่ตั้งไว้)"""
    return get_setting("gemini_model")

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

# รายชื่อโมเดลที่คีย์นั้นเรียกได้ — ใช้ทำตัวเลือกใน dropdown ของหน้า Settings
# pageSize สูงไว้ให้จบในหน้าเดียว (ปัจจุบัน Google ส่งมาราว 50 ตัว)
LIST_MODELS_URL = f"{API_BASE}?pageSize=200"

# โมเดลที่ระบบยอมให้เลือก — เป็น **allowlist** ไม่ใช่การไล่กรองคำต้องห้าม เพราะรายชื่อฝั่ง
# Google (50 ตัว) มีของใหม่โผล่มาเรื่อย ๆ ที่ประกาศว่ารองรับ generateContent แต่ไม่ใช่ของงานนี้
# (เจอมาแล้วทั้งรุ่นเสียง/ภาพ/หุ่นยนต์ และ `gemini-3.5-transcribe` ที่เพิ่งโผล่มา) —
# ไล่ตัดทีละคำต้องห้ามคือวิ่งตามหลัง Google ตลอด สู้ระบุตัวที่วัดมาแล้วว่าใช้ได้ไปเลยไม่ได้
#
# ใช้รายการเดียวกับตัวเลือกในหน้า Settings (`GEMINI_MODEL_CHOICES`) — เหตุผลที่เลือก
# แต่ละตัวและตัวเลขที่วัดได้อยู่ในคอมเมนต์ของรายการนั้น
MODEL_ALLOWLIST = tuple(GEMINI_MODEL_CHOICES)

# แอดมินกดปุ่มแล้วต้องนั่งรอ -> ตั้ง timeout ไม่ให้ค้างนานเกินไป
# ใช้เมื่ออ่านค่าจาก settings ไม่ได้/ไม่เป็นตัวเลข (ค่าเดียวกับ default ใน SETTING_DEFS)
FALLBACK_TIMEOUT_SEC = 120


def timeout_sec() -> int:
    """
    เวลารอ Google ตอบกลับ — **ตั้งจากหน้า System Settings ได้** เพราะโมเดลแต่ละตัวช้าไม่เท่ากันมาก
    และตัวเดียวกันยังแกว่งไปมา (วัดจริงกับ prompt สรุป alert: gemini-3.5-flash-lite 2.8-8.3 วินาที,
    gemini-3.6-flash 10.6-71.5 วินาที, gemini-3.7-flash ตอบ 503/ค้างยาวจนหมดเวลา)
    ค่าเดิมเป็นค่าคงที่จาก .env ซึ่งแก้ทีต้องรีสตาร์ต ทั้งที่เป็นค่าที่ต้องขยับตามโมเดลที่เลือก

    ค่าที่ไม่ใช่ตัวเลข/ไม่เป็นบวก -> ใช้ค่าตั้งต้น ไม่ปล่อยให้ ValueError หลุดไปตอนเรียกใช้
    """
    try:
        value = int(get_setting("gemini_timeout_sec"))
    except (TypeError, ValueError):
        return FALLBACK_TIMEOUT_SEC

    return value if value > 0 else FALLBACK_TIMEOUT_SEC

# โมเดล Gemini "คิด" ก่อนตอบ และ token ที่ใช้คิด (thoughtsTokenCount) ถูกหักจาก
# MAX_OUTPUT_TOKENS ก้อนเดียวกับคำตอบ -> ถ้าปล่อยให้คิดอิสระ prompt ที่มี log เยอะจะถูกคิด
# กินโควตาจนเหลือที่เขียนคำตอบนิดเดียว แล้วโดนตัดกลางประโยค (finishReason=MAX_TOKENS)
#
# รุ่น 2.5 คุมด้วยจำนวน token: 0 = ปิดการคิด — งานนี้เป็นการสรุป log ที่มีข้อมูลครบในมืออยู่แล้ว
# (วัดจริงกับ alert 25 log: ปิดคิดแล้ว "เร็วกว่า + ได้รายละเอียดครบกว่า" ตอนเปิดคิด)
THINKING_BUDGET = int(os.getenv("GEMINI_THINKING_BUDGET", "0"))

# รุ่น 3 ขึ้นไปเลิกรับ thinkingBudget แล้ว (ส่งไปได้ 400 INVALID_ARGUMENT) เปลี่ยนมาคุมเป็น
# ระดับแทน — low = คิดน้อยที่สุดเท่าที่โมเดลรุ่นใหม่ยอมให้ตั้ง ใกล้เคียงเจตนาเดียวกับ budget=0
THINKING_LEVEL = os.getenv("GEMINI_THINKING_LEVEL", "low")

# เพดานความยาวคำตอบ — เผื่อไว้มากกว่าที่ใช้จริง (สรุป 1 เหตุการณ์ ~500-700 token)
MAX_OUTPUT_TOKENS = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "4096"))

# จำนวน raw log สูงสุดที่ส่งเข้า prompt — เหตุการณ์ที่ merge กันเยอะ ๆ มี log ได้เป็นร้อยบรรทัด
# ส่งหมดเปลือง token เพราะบรรทัดท้าย ๆ ซ้ำรูปแบบเดิม (ยังบอก AI ว่ามีทั้งหมดกี่บรรทัด)
MAX_LOGS_IN_PROMPT = int(os.getenv("GEMINI_MAX_LOGS", "40"))

# ตัดความยาวต่อบรรทัด กัน log ผิดปกติ (เช่น payload ยาว ๆ ของ SQLi) กิน token หมด
MAX_LOG_LINE_CHARS = 500


def is_configured() -> bool:
    return bool(api_key())


def generate_url() -> str:
    return f"{API_BASE}/{model()}:generateContent"
