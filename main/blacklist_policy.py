"""
นโยบายหมดอายุ (expiry) ของ blacklist — severity-based + escalation

หลักการ:
- เฉพาะ auto-block (จาก detector) เท่านั้นที่มี TTL — manual blacklist ถาวรเสมอ
- TTL ต่างกันตามความรุนแรง/ความมั่นใจของการตรวจจับ:
    * rate-based (scan/flood) มีโอกาส false-positive สูงกว่า -> ban สั้นกว่า
    * signature-based (xss/path) ยืนยันว่าเป็น payload โจมตีจริง -> ban นานกว่า
    * injection (sql/cmd) รุนแรงสุด -> ถาวร
- Escalation: IP ที่หลุด ban แล้วกลับมาโจมตีอีก โดน ban นานขึ้น (×2 ทุกครั้ง)
  เกิน MAX_BLOCK_COUNT_BEFORE_PERMANENT ครั้ง -> ถาวร (กันพวกดื้อ)

หมายเหตุ: ค่า TTL ฐานและค่า escalation ในไฟล์นี้เป็น **ค่าตั้งต้น** เท่านั้น —
ค่าที่ใช้จริงตอนรันดึงจาก DB ซึ่งแอดมินปรับได้จากหน้าเว็บ
  * TTL ต่อชนิด -> ตาราง `blacklist_ttl` (`blacklist_ttl_cache.get_ttl`)
  * ตัวคูณ/จำนวนครั้งก่อนถาวร -> `app_settings` (`blacklist_ttl_cache.get_escalation_policy`)
ฟังก์ชันในไฟล์นี้ยังเป็น pure function ที่ไม่แตะ DB/เวลา — ผู้เรียกเป็นคนส่งค่าเข้ามา
"""

HOUR = 3600

# TTL ฐาน (วินาที) ต่อ detection_type — None = ถาวร (ไม่หมดอายุ)
BASE_TTL_SECONDS: dict[str, int | None] = {
    # rate/behavior-based (false-positive risk สูงกว่า -> สั้น)
    "port_scan": 1 * HOUR,
    "http_flood": 6 * HOUR,
    "firewall_deny_rate": 6 * HOUR,
    # auth brute force (อาจเป็น user จริงลืมรหัส -> ไม่ถาวร)
    "ssh_brute_force": 6 * HOUR,
    "sudo_failed": 3 * HOUR,
    # signature-based (ยืนยัน payload โจมตี -> นานกว่า)
    "xss": 12 * HOUR,
    "path_traversal": 12 * HOUR,
    # injection รุนแรงสุด -> ถาวร
    "sql_injection": None,
    "command_injection": None,
}

# detection_type ที่ไม่รู้จัก ใช้ค่านี้ (กันลืมเพิ่ม type ใหม่แล้วกลายเป็นถาวรโดยไม่ตั้งใจ)
DEFAULT_TTL_SECONDS = 6 * HOUR

# event ของ manual blacklist (ต้องตรงกับ default ใน crud.save_ip_blacklist)
MANUAL_EVENT = "manual_blacklist"

# escalation: โดนซ้ำ ban นานขึ้นกี่เท่าต่อครั้ง (ค่าตั้งต้น — แอดมินปรับได้ที่หน้า Rules)
ESCALATION_MULTIPLIER = 2
# ถ้า block_count เกินค่านี้ -> ถาวร (ค่าตั้งต้น — แอดมินปรับได้ที่หน้า Rules)
MAX_BLOCK_COUNT_BEFORE_PERMANENT = 5

# เพดานของ TTL หลังคูณ escalation แล้ว — 10 ปี
#
# จำเป็นเพราะ multiplier ยกกำลังโตเร็วมาก: ตั้งตัวคูณ 100 แล้วโดนซ้ำ 10 ครั้ง
# จะได้ค่าระดับ 10^21 วินาที ซึ่ง `timedelta` รับไม่ไหว (เพดานราว 8.6×10^13 วินาที)
# แล้วจะโยน OverflowError ตอนคำนวณ expires_at = ตอบสนองล้มทั้งรอบ
#
# เกินเพดานให้ตัดลงเท่าเพดาน ไม่แปลงเป็น "ถาวร" เงียบ ๆ — บล็อก 10 ปีกับบล็อกถาวร
# ต่างกันตรงที่อันแรกยังมี expires_at ให้ตัวปลดบล็อกอัตโนมัติเห็นและแอดมินตรวจสอบได้
MAX_TTL_SECONDS = 10 * 365 * 24 * HOUR


def base_ttl_for(detection_type: str | None) -> int | None:
    """
    คืน TTL ฐาน default (วินาที) ของ detection_type; None = ถาวร
    ใช้ตอน seed ค่าเริ่มต้นลง DB — ค่าที่ใช้จริงตอน runtime ดึงจาก DB/cache
    (`blacklist_ttl_cache.get_ttl`) ซึ่ง admin ปรับได้
    """
    if not detection_type or detection_type == MANUAL_EVENT:
        return None
    # ใช้ `in` แยก sentinel เพราะค่าที่ตั้งใจให้เป็น None (ถาวร) ก็มี
    if detection_type in BASE_TTL_SECONDS:
        return BASE_TTL_SECONDS[detection_type]
    return DEFAULT_TTL_SECONDS


def escalated_ttl_seconds(
    base_ttl: int | None,
    block_count: int,
    multiplier: int = ESCALATION_MULTIPLIER,
    max_block_count: int = MAX_BLOCK_COUNT_BEFORE_PERMANENT,
) -> int | None:
    """
    คำนวณ TTL (วินาที) หลังคิด escalation จาก base_ttl + block_count
    คืน None = ถาวร (base เป็น None หรือ block_count เกิน max_block_count)
    ค่าที่คำนวณได้ถูกตัดไม่ให้เกิน MAX_TTL_SECONDS

    ตรรกะ escalation อยู่ที่นี่ที่เดียว (pure function, ไม่แตะ DB/เวลา)
    ไม่ส่ง multiplier/max_block_count มา = ใช้ค่าตั้งต้นในไฟล์นี้ — ตอนรันจริง
    `blacklist_ttl_cache.compute_expiry` จะดึงค่าที่แอดมินตั้งไว้ใน DB มาส่งให้
    """
    if base_ttl is None:
        return None
    if block_count > max_block_count:
        return None

    ttl = base_ttl * (multiplier ** (block_count - 1))
    return min(ttl, MAX_TTL_SECONDS)
