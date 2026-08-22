"""
ค่า config ของ Gemini (AI สรุป log ใน alert) — API key/model ตั้งได้จากหน้า System Settings (`/settings`)

api_key()/model() เป็น **ฟังก์ชัน** เพราะอ่านค่าตอนเรียกใช้ (settings_cache) แก้แล้วมีผลทันที
ไม่ต้อง restart — ส่วนค่าจูน (timeout/token/จำนวน log) ยังอยู่ที่ .env เพราะเป็นค่าที่ปรับครั้งเดียว
ตอนตั้งระบบ ไม่ใช่ของที่แอดมินต้องมาแก้บ่อย ๆ จากหน้าเว็บ

ลำดับการหาค่า: Redis cache -> ตาราง app_settings -> .env (GEMINI_API_KEY / GEMINI_MODEL)

ออกแบบเป็น "เรียกตอนกดปุ่ม" (on-demand) ไม่ใช่ worker แยกแบบ LINE_API:
detector ไม่ import โมดูลนี้เลย -> AI ล่ม/ไม่มี key/โควตาหมด ก็ไม่กระทบการตรวจจับ + block + LINE
"""

import os

from dotenv import load_dotenv

from settings_cache import get_setting

load_dotenv()

def api_key() -> str:
    return get_setting("gemini_api_key")


def model() -> str:
    """gemini-2.5-flash: เร็ว+ถูก เหมาะกับสรุป log ทีละเหตุการณ์ (เปลี่ยนได้จากหน้า Settings)"""
    return get_setting("gemini_model")

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"

# แอดมินกดปุ่มแล้วต้องนั่งรอ -> ตั้ง timeout ไม่ให้ค้างนานเกินไป
TIMEOUT_SEC = int(os.getenv("GEMINI_TIMEOUT_SEC", "60"))

# gemini-2.5-flash เป็นโมเดลที่ "คิด" ก่อนตอบ และ token ที่ใช้คิด (thoughtsTokenCount)
# ถูกหักจาก MAX_OUTPUT_TOKENS ก้อนเดียวกับคำตอบ -> ถ้าปล่อยให้คิดอิสระ prompt ที่มี log เยอะ
# จะถูกคิดกินโควตาจนเหลือที่เขียนคำตอบนิดเดียว แล้วโดนตัดกลางประโยค (finishReason=MAX_TOKENS)
# 0 = ปิดการคิด: งานนี้เป็นการสรุป log ที่มีข้อมูลครบในมืออยู่แล้ว ไม่ต้องคิดเยอะ
# (วัดจริงกับ alert 25 log: ปิดคิดแล้ว "เร็วกว่า + ได้รายละเอียดครบกว่า" ตอนเปิดคิด)
THINKING_BUDGET = int(os.getenv("GEMINI_THINKING_BUDGET", "0"))

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
