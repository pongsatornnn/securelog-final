

from database.connection import AsyncSessionLocal
from database.crud import get_agent_disabled_rules, get_detection_rule, upsert_detection_rule
from database.defaults import snapshot_rule
from redis_client import cache_get_json, cache_set_json, cache_delete


RULE_CACHE_TTL_SECONDS = 300

CACHE_KEY_PREFIX = "detection_rule:"
AGENT_CACHE_KEY_PREFIX = "agent_disabled_rules:"

LOG_PREFIX = "RULE-CACHE"


DEFAULT_RULES = {

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

    "web_http_flood": {
        "category": "web",
        "window_seconds": 60,
        "threshold": 300,
        "description": "App-level DoS (HTTP flood): 1 IP ยิง request ถี่เกินปกติ (นับทุก request ต่อ IP)",
    },

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

    code = DEFAULT_RULES.get(rule_key)
    snap = snapshot_rule(rule_key)

    if not code and not snap:
        return None

    return {**(code or {}), **(snap or {})}


async def load_rule_from_db(rule_key: str) -> dict:

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


async def get_rule(rule_key: str, agent_id: str | None = None) -> dict:
    # Entry point หลักที่ detector เรียกใช้ก่อนประเมิน threshold ทุกครั้ง
    cached = cache_get_json(rule_cache_key(rule_key), log_prefix=LOG_PREFIX)

    rule = cached if cached else await load_rule_from_db(rule_key)
    if not agent_id or not rule["is_active"]:
        return rule

    cache_key = f"{AGENT_CACHE_KEY_PREFIX}{agent_id}"
    setting = cache_get_json(cache_key, log_prefix=LOG_PREFIX)
    if setting is None:
        async with AsyncSessionLocal() as db:
            disabled = await get_agent_disabled_rules(db, agent_id)
        setting = {"disabled": disabled}
        cache_set_json(cache_key, setting, RULE_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)

    if rule_key in setting["disabled"]:
        return {**rule, "is_active": False}
    return rule


def clear_agent_rule_cache(agent_id: str) -> None:
    cache_delete(f"{AGENT_CACHE_KEY_PREFIX}{agent_id}", log_prefix=LOG_PREFIX)


async def update_rule(
    rule_key: str,
    *,
    window_seconds: int,
    threshold: int,
    is_active: bool = True,
) -> dict:

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

    return effective_default(rule_key) is not None


async def restore_default_rule(rule_key: str) -> dict | None:

    default = effective_default(rule_key)

    if not default:
        return None


    return await update_rule(
        rule_key,
        window_seconds=default["window_seconds"],
        threshold=default["threshold"],
        is_active=default.get("is_active", True),
    )


async def restore_default_rules() -> dict:

    restored = []

    for rule_key in DEFAULT_RULES:
        result = await restore_default_rule(rule_key)
        if result:
            restored.append(result)

    print(f"[{LOG_PREFIX}] คืนค่า default ของ rule ทั้งหมด {len(restored)} ตัว")
    return {"restored": len(restored), "rules": restored}
