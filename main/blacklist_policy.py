# นโยบายหมดอายุ (expiry) ของ blacklist — severity-based + escalation

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
MAX_TTL_SECONDS = 10 * 365 * 24 * HOUR


def base_ttl_for(detection_type: str | None) -> int | None:
    # คืน TTL ฐาน default (วินาที) ของ detection_type; None = ถาวร
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
    # คำนวณ TTL (วินาที) หลังคิด escalation จาก base_ttl + block_count
    if base_ttl is None:
        return None
    if block_count > max_block_count:
        return None

    ttl = base_ttl * (multiplier ** (block_count - 1))
    return min(ttl, MAX_TTL_SECONDS)
