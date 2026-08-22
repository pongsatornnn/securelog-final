"""
Cache + DB layer สำหรับ detection rules (window_seconds/threshold ต่อ rule_key)
cache-first (Redis TTL 300s เป็น fallback), miss แล้ว fallback DB (seed default
ครั้งแรกอัตโนมัติ), แก้ค่าผ่าน update_rule จะเคลียร์ cache ทันทีให้มีผลไม่ต้องรอ TTL
"""

from database.connection import AsyncSessionLocal
from database.crud import get_detection_rule, upsert_detection_rule
from database.defaults import snapshot_rule
from redis_client import cache_get_json, cache_set_json, cache_delete


RULE_CACHE_TTL_SECONDS = 300  # fallback เผื่อกรณีไม่ได้ผ่าน update_rule() โดยตรง

CACHE_KEY_PREFIX = "detection_rule:"

LOG_PREFIX = "RULE-CACHE"


# ค่า default ของแต่ละ rule (ใช้ตอน seed ครั้งแรกที่ยังไม่มีแถวใน DB)
DEFAULT_RULES = {
    # กฎเดียวครอบทั้งยิงถี่และยิงช้าสะสม (เดิมแยก fast 60s/5 กับ slow 900s/10)
    # window ยาวแบบ slow + threshold ต่ำแบบ fast: ยิงรัว 5 ครั้งใน 1 นาทีก็เข้าเงื่อนไข
    # เพราะยังอยู่ใน window 15 นาที ส่วนยิงช้าก็สะสมครบได้เหมือนเดิม (ตรงกับ default ของ fail2ban)
    "ssh_brute_force": {
        "category": "auth",
        "window_seconds": 15 * 60,
        "threshold": 5,
        "description": "SSH brute force: ล็อกอิน SSH ผิดซ้ำจาก IP เดียวกัน (ครอบทั้งยิงถี่และยิงช้าสะสม)",
    },
    "sudo_failed": {
        "category": "auth",
        "window_seconds": 5 * 60,
        "threshold": 3,
        "description": "Sudo authentication failure",
    },
    # Web signature-based detection
    #
    # window 300s / threshold 2-3 (เดิม 60s/1 = เจอ payload แรกยิงเลย):
    # - เครื่องมือจริง (sqlmap/commix/dotdotpwn/nikto) ยิงหลายสิบ payload ต่อวินาที จึงยัง
    #   เด้งแทบจะทันทีเหมือนเดิม แต่ request เดี่ยว ๆ ที่บังเอิญเข้า pattern (เช่นคำค้น
    #   "select ... from" หรือพารามิเตอร์ที่มี "alert(") ไม่ทำให้โดนบล็อกทันที
    # - window ยาวขึ้นเป็น 5 นาที เพื่อให้สะสมทันคนที่จงใจยิงช้า ๆ เลี่ยงการนับแบบ burst
    # - threshold ของ SQLi/XSS สูงกว่า (3) เพราะ pattern ไปพ้องคำอังกฤษ/สตริง JS ปกติได้ง่ายกว่า
    #   ส่วน traversal/command injection ตั้ง 2 เพราะ pattern เฉพาะเจาะจงกว่า พ้องของปกติยาก
    "web_sql_injection": {
        "category": "web",
        "window_seconds": 300,
        "threshold": 3,
        "description": "SQL Injection จาก Web Access Log (signature-based)",
    },
    "web_xss": {
        "category": "web",
        "window_seconds": 300,
        "threshold": 3,
        "description": "Cross-Site Scripting (XSS) จาก Web Access Log (signature-based)",
    },
    "web_path_traversal": {
        "category": "web",
        "window_seconds": 300,
        "threshold": 2,
        "description": "Path Traversal จาก Web Access Log (signature-based)",
    },
    "web_command_injection": {
        "category": "web",
        "window_seconds": 300,
        "threshold": 2,
        "description": "Command Injection จาก Web Access Log (signature-based)",
    },
    # App-level DoS (HTTP flood) — rate-based: นับ request ทั้งหมดต่อ IP
    # 300 req/60s = 5 req/วินาที ต่อ IP (เดิม 100 = 1.7 req/วิ ซึ่งต่ำกว่าการเปิดหน้าเว็บ
    # ที่มีรูป/CSS/JS ไม่กี่หน้า และคนหลังเราเตอร์ตัวเดียวกันก็ถูกนับรวมเป็น IP เดียว)
    "web_http_flood": {
        "category": "web",
        "window_seconds": 60,
        "threshold": 300,
        "description": "App-level DoS (HTTP flood): 1 IP ยิง request ถี่เกินปกติ (นับทุก request ต่อ IP)",
    },
    # Firewall behavior/rate-based detection (จาก UFW/iptables deny log)
    # threshold ตั้งต่ำ (=5) โดยตั้งใจ: UFW logging ระดับ low (default บน agent) rate-limit การ log
    # blocked packet เหลือ ~5 บรรทัด/flood — ตั้งสูงกว่านี้จะไม่มีวันถึงเพราะ log ไม่ออก ไม่ใช่เพราะไม่มีโจมตี
    # (แลกกับ: port scan ที่โดน block ≥5 distinct port อาจเข้าทั้ง port_scan และ deny_rate พร้อมกัน)
    "firewall_port_scan": {
        "category": "firewall",
        "window_seconds": 60,
        "threshold": 5,
        "description": "Port Scan: 1 IP ยิงหาหลาย port (นับจำนวน port ที่ไม่ซ้ำในหน้าต่างเวลา)",
    },
    "firewall_deny_rate": {
        "category": "firewall",
        "window_seconds": 60,
        "threshold": 5,
        "description": "Firewall Deny Flood: 1 IP โดน firewall ปฏิเสธถี่มาก (นับจำนวน event deny)",
    },
    # Login lockout — ป้องกัน brute force รหัสผ่านหน้า login ของ dashboard เอง (ล็อกตาม IP)
    # threshold = จำนวนครั้งที่ใส่รหัสผิดได้ก่อนถูกล็อก
    # window_seconds = หน้าต่างเวลานับ fail + ระยะเวลาที่ถูกล็อก (ครบ threshold แล้วล็อกจนกว่า window จะหมด)
    "login_lockout": {
        "category": "login",
        "window_seconds": 15 * 60,
        "threshold": 5,
        "description": "Login lockout: ล็อก IP ชั่วคราวเมื่อใส่รหัสผิดเกิน threshold ครั้งใน window",
    },
}


def rule_cache_key(rule_key: str) -> str:
    return f"{CACHE_KEY_PREFIX}{rule_key}"


def effective_default(rule_key: str) -> dict | None:
    """
    ค่า default ที่ใช้จริงของ rule นี้ = ค่าใน snapshot (database/seed_data.json) ทับค่าในโค้ด
    ปกติ startup seed ครบทุก rule อยู่แล้ว (database/seed.py) ทางนี้จึงเป็นแค่ตาข่ายรับ
    กรณีแถวหายไปหลัง start — ต้องได้ค่าเดียวกับตอน seed ไม่งั้นค่าที่ปรับไว้จะเด้งกลับเงียบๆ
    """
    code = DEFAULT_RULES.get(rule_key)
    snap = snapshot_rule(rule_key)

    if not code and not snap:
        return None

    return {**(code or {}), **(snap or {})}


async def load_rule_from_db(rule_key: str) -> dict:
    """
    อ่าน rule จาก DB ถ้ายังไม่เคยมีแถวนี้ (รันครั้งแรก) จะ seed ค่า default ลง DB ให้อัตโนมัติ
    """
    default = effective_default(rule_key)

    async with AsyncSessionLocal() as db:
        rule = await get_detection_rule(db, rule_key)

        if not rule:
            if not default:
                raise ValueError(f"ไม่รู้จัก rule_key: {rule_key}")

            rule = await upsert_detection_rule(
                db,
                rule_key,
                category=default.get("category", "auth"),
                window_seconds=default["window_seconds"],
                threshold=default["threshold"],
                description=default.get("description"),
            )
            print(f"[{LOG_PREFIX}] seed default rule ลง DB: {rule_key} = {default}")

        data = {
            "rule_key": rule.rule_key,
            "window_seconds": rule.window_seconds,
            "threshold": rule.threshold,
            "is_active": bool(rule.is_active),
        }

    cache_set_json(rule_cache_key(rule_key), data, RULE_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)
    return data


async def get_rule(rule_key: str) -> dict:
    """
    Entry point หลักที่ detector เรียกใช้ก่อนประเมิน threshold ทุกครั้ง
    เช็ค cache ก่อน ถ้าไม่มี (cache miss / เพิ่งถูกเคลียร์) ค่อย fallback ไปอ่าน DB แล้ว cache ใหม่
    """
    cached = cache_get_json(rule_cache_key(rule_key), log_prefix=LOG_PREFIX)

    if cached:
        return cached

    return await load_rule_from_db(rule_key)


async def update_rule(
    rule_key: str,
    *,
    window_seconds: int,
    threshold: int,
    is_active: bool = True,
) -> dict:
    """
    ใช้ตอนแก้ rule (จาก CLI/API) เขียนลง DB แล้วเคลียร์ cache ทันที
    เพื่อให้ detector อ่านค่าใหม่ในรอบถัดไปโดยไม่ต้องรอ TTL หมดอายุ

    ใช้ category/description ของแถวเดิมใน DB เป็นหลัก ถ้ายังไม่เคยมีแถวนี้เลย
    ค่อย fallback ไปที่ค่า default ที่ใช้จริง (snapshot ทับ DEFAULT_RULES — ดู effective_default)
    """
    default = effective_default(rule_key) or {}

    async with AsyncSessionLocal() as db:
        existing = await get_detection_rule(db, rule_key)

        category = existing.category if existing else default.get("category", "auth")
        description = existing.description if existing else default.get("description")

        rule = await upsert_detection_rule(
            db,
            rule_key,
            category=category,
            window_seconds=window_seconds,
            threshold=threshold,
            description=description,
            is_active=is_active,
        )

        result = {
            "rule_key": rule.rule_key,
            "category": rule.category,
            "description": rule.description,
            "window_seconds": rule.window_seconds,
            "threshold": rule.threshold,
            "is_active": bool(rule.is_active),
        }

    cache_delete(rule_cache_key(rule_key), log_prefix=LOG_PREFIX)

    print(
        f"[{LOG_PREFIX}] อัปเดต rule {rule_key}: "
        f"window={window_seconds}s threshold={threshold} is_active={is_active} (เคลียร์ cache แล้ว)"
    )

    return result


def is_default_rule(rule_key: str) -> bool:
    """rule นี้เป็นของระบบ (มีค่า default ให้คืนกลับ) หรือไม่ — ใช้ตัดสินว่าปุ่มคืนค่าแตะได้ไหม"""
    return effective_default(rule_key) is not None


async def restore_default_rule(rule_key: str) -> dict | None:
    """
    คืน rule ตัวเดียวกลับเป็นค่า default ของระบบ (window/threshold/is_active)

    คืน None ถ้า rule_key นี้ไม่มีค่า default ให้คืน — ปกติไม่เกิด เพราะทุก rule ในระบบ
    มาจาก DEFAULT_RULES ทั้งหมด (ไม่มี endpoint ให้สร้าง rule ใหม่) แต่กันไว้เผื่อมีแถว
    ที่ถูกใส่เข้ามาทางอื่น จะได้ไม่ไปเขียนทับด้วยค่าที่เดาเอาเอง
    """
    default = effective_default(rule_key)

    if not default:
        return None

    # is_active ไม่ได้อยู่ใน DEFAULT_RULES — ค่าตั้งต้นของทุก rule คือเปิดใช้งาน
    return await update_rule(
        rule_key,
        window_seconds=default["window_seconds"],
        threshold=default["threshold"],
        is_active=default.get("is_active", True),
    )


async def restore_default_rules() -> dict:
    """
    คืนทุก rule ที่เป็นของระบบกลับเป็นค่า default

    วนจาก DEFAULT_RULES ไม่ใช่จากแถวใน DB — rule ที่ถูกลบแถวทิ้งไปจึงถูกสร้างกลับมาด้วย
    (update_rule ใช้ upsert) ส่วนแถวใน DB ที่ไม่มีค่า default คู่กันจะไม่ถูกแตะเลย
    """
    restored = []

    for rule_key in DEFAULT_RULES:
        result = await restore_default_rule(rule_key)
        if result:
            restored.append(result)

    print(f"[{LOG_PREFIX}] คืนค่า default ของ rule ทั้งหมด {len(restored)} ตัว")
    return {"restored": len(restored), "rules": restored}
