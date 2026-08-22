"""
ค่า config ของ LINE Messaging API — ตั้งได้จากหน้า System Settings (`/settings`)

**เป็นฟังก์ชัน ไม่ใช่ค่าคงที่โดยตั้งใจ:** ของเดิมอ่าน os.getenv ตอน import ทำให้แก้ค่าแล้ว
ต้อง restart ทุก service ถึงจะมีผล · ตอนนี้อ่านจาก settings_cache ทุกครั้งที่เรียก
แอดมินกดบันทึกในหน้าเว็บแล้วมีผลทันทีทั้ง app หลัก, webhook app และ worker แจ้งเตือน

ลำดับการหาค่า: Redis cache -> ตาราง app_settings -> .env (LINE_CHANNEL_ACCESS_TOKEN /
LINE_CHANNEL_SECRET) — เครื่องที่ตั้งค่าไว้ใน .env อยู่แล้วจึงทำงานต่อได้โดยไม่ต้องแก้อะไร
"""

import os

from dotenv import load_dotenv

from settings_cache import get_setting

load_dotenv()


def channel_access_token() -> str:
    return get_setting("line_channel_access_token")


def channel_secret() -> str:
    return get_setting("line_channel_secret")


def oa_id() -> str:
    """Basic ID ของ OA (เช่น @123abcd) — ใช้สร้างลิงก์แอดเพื่อน ไม่ได้ใช้เรียก API"""
    return get_setting("line_oa_id")


# LINE Messaging API endpoints
PUSH_URL = "https://api.line.me/v2/bot/message/push"
MULTICAST_URL = "https://api.line.me/v2/bot/message/multicast"
PROFILE_URL = "https://api.line.me/v2/bot/profile"  # /{userId}
# ข้อมูล OA ตัวเอง — ใช้ทดสอบว่า token ใช้ได้ในหน้า System Settings
BOT_INFO_URL = "https://api.line.me/v2/bot/info"

# multicast รับได้สูงสุด 500 userId ต่อครั้ง
MULTICAST_MAX = 500

# กันสแปม: ส่ง LINE ครั้งเดียวต่อ alert 1 แถว (1 id) — โจมตีซ้ำที่ merge เข้าแถวเดิม
# (id เดิม) จะไม่ส่งซ้ำ แต่คนละเครื่อง/ต้นทาง/ชนิด = คนละ id ส่งทันทีทุกอัน ไม่ throttle
# TTL แค่ไว้ล้าง key ที่ไม่ใช้แล้ว (ไม่ใช่ cooldown) — เผื่อเหตุการณ์เดิมยาวข้ามวันค่อยเตือนซ้ำ
NOTIFY_DEDUP_TTL_SEC = int(os.getenv("LINE_NOTIFY_DEDUP_TTL_SEC", "86400"))
NOTIFY_DEDUP_KEY_PREFIX = "line_notified:"


def is_configured() -> bool:
    """ครบทั้ง token (ไว้ push) และ secret (ไว้ตรวจลายเซ็น webhook) ถึงจะถือว่าตั้งค่าแล้ว"""
    return bool(channel_access_token() and channel_secret())
