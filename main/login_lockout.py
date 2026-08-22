"""
Login lockout สำหรับหน้า login ของ dashboard เอง (ป้องกัน brute force เดารหัสผ่าน admin)
— คนละส่วนกับ auth_log_detect (ที่ตรวจ SSH brute force บนเครื่อง Agent)

ล็อกตาม **IP** (ไม่ใช่ username) โดยเจตนา: ถ้าล็อกตาม username คนไม่หวังดีจะจงใจใส่รหัส
ของ user จริงผิดรัวๆ เพื่อล็อกเจ้าตัวออกจากระบบได้ (DoS) — ล็อกตาม IP ตัดปัญหานี้
(IP ดึงด้วย get_remote_address ตัวเดียวกับที่ slowapi rate limit ใช้ เพื่อความสอดคล้อง)

ตามแพตเทิร์น rule_cache:
- config (threshold/window) ไม่ hardcode — เก็บใน detection_rules (rule_key=login_lockout)
  ดึงผ่าน get_rule() (cache-first + seed default) แก้ได้ผ่าน manage_rules.py / หน้า /rules
    threshold      = จำนวนครั้งที่ใส่รหัสผิดได้ก่อนถูกล็อก
    window_seconds = หน้าต่างนับ fail และเป็นระยะเวลาที่ถูกล็อกด้วย (ครบ threshold แล้ว
                     ล็อกจนกว่า key จะหมดอายุ — ใช้ TTL ของ Redis ปลดล็อกเอง ไม่ต้องมี cron)
    is_active      = ปิด lockout ชั่วคราวได้ (ยังคง login ได้ปกติ)

- state (ตัวนับ fail ต่อ IP) เก็บใน Redis key `login_fail:{ip}` TTL=window_seconds
  ตั้ง TTL ตอน fail ครั้งแรก (นับหน้าต่างจาก fail แรก) — login สำเร็จลบ key ทันที (reset)
"""

from rule_cache import get_rule
from redis_client import get_redis


LOCKOUT_RULE_KEY = "login_lockout"
FAIL_KEY_PREFIX = "login_fail:"


def fail_key(ip: str) -> str:
    return f"{FAIL_KEY_PREFIX}{(ip or 'unknown').strip()}"


async def _get_config() -> dict:
    """คืน config ปัจจุบันของ login_lockout (ผ่าน rule_cache: cache-first + seed default)"""
    return await get_rule(LOCKOUT_RULE_KEY)


async def check_locked(ip: str) -> tuple[bool, int]:
    """
    เช็คก่อน authenticate — คืน (locked, retry_after_seconds)
    ถ้า rule ถูกปิด (is_active=False) จะไม่ล็อกเลย
    """
    config = await _get_config()

    if not config.get("is_active", True):
        return False, 0

    threshold = config["threshold"]

    try:
        r = get_redis()
        raw = r.get(fail_key(ip))
        count = int(raw) if raw else 0

        if count >= threshold:
            ttl = r.ttl(fail_key(ip))
            return True, max(ttl, 0)

        return False, 0

    except Exception as e:
        # ถ้า Redis มีปัญหา ไม่ควรล็อกผู้ใช้ออกจากระบบทั้งหมด (fail-open)
        print(f"[LOGIN-LOCKOUT] check_locked error: {e}")
        return False, 0


async def record_failure(ip: str) -> dict:
    """
    บันทึกว่าใส่รหัสผิด 1 ครั้งจาก IP นี้ — เพิ่มตัวนับ + ตั้ง TTL ตอนครั้งแรก
    คืน dict {locked, count, threshold, retry_after} เพื่อให้ route ตัดสินใจตอบกลับ
    """
    config = await _get_config()
    threshold = config["threshold"]
    window = config["window_seconds"]

    if not config.get("is_active", True):
        return {"locked": False, "count": 0, "threshold": threshold, "retry_after": 0}

    try:
        r = get_redis()
        key = fail_key(ip)
        count = r.incr(key)

        # ตั้ง TTL ตอน fail ครั้งแรก และกันเคส key หลุด TTL (persist ค้าง) ด้วย
        if count == 1 or r.ttl(key) < 0:
            r.expire(key, window)

        ttl = r.ttl(key)

        return {
            "locked": count >= threshold,
            "count": count,
            "threshold": threshold,
            "retry_after": max(ttl, 0),
        }

    except Exception as e:
        print(f"[LOGIN-LOCKOUT] record_failure error: {e}")
        return {"locked": False, "count": 0, "threshold": threshold, "retry_after": 0}


async def reset_failures(ip: str) -> None:
    """login สำเร็จ / admin ปลดล็อกเอง — ลบตัวนับ fail ของ IP นั้น"""
    try:
        get_redis().delete(fail_key(ip))
    except Exception as e:
        print(f"[LOGIN-LOCKOUT] reset_failures error: {e}")
