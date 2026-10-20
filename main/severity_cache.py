

from database.connection import AsyncSessionLocal
from database.crud import get_alert_severity, upsert_alert_severity
from database.defaults import snapshot_severity
from redis_client import cache_get_json, cache_set_json, cache_delete


SEVERITY_CACHE_TTL_SECONDS = 300
CACHE_KEY_PREFIX = "alert_severity:"

LOG_PREFIX = "SEVERITY-CACHE"

VALID_SEVERITIES = ("LOW", "MEDIUM", "HIGH", "CRITICAL")
DEFAULT_FALLBACK_SEVERITY = "LOW"


DEFAULT_SEVERITY = {
    "ssh_brute_force": {
        "severity": "CRITICAL",
        "description": "SSH Brute Force",
    },
    "sudo_failed": {
        "severity": "MEDIUM",
        "description": "Sudo Authentication Failure",
    },
    "sql_injection": {
        "severity": "CRITICAL",
        "description": "SQL Injection",
    },
    "command_injection": {
        "severity": "CRITICAL",
        "description": "Command Injection",
    },
    "xss": {
        "severity": "HIGH",
        "description": "Cross-Site Scripting (XSS)",
    },
    "path_traversal": {
        "severity": "HIGH",
        "description": "Path Traversal",
    },
    "http_flood": {
        "severity": "HIGH",
        "description": "HTTP Flood (App-level DoS)",
    },
    "firewall_deny_rate": {
        "severity": "HIGH",
        "description": "Firewall Deny Flood",
    },
    "port_scan": {
        "severity": "MEDIUM",
        "description": "Port Scan",
    },
}


def severity_key_for(detection_type: str, mode: str | None) -> str:
    return f"{detection_type}:{mode}" if mode else detection_type


def severity_cache_key(severity_key: str) -> str:
    return f"{CACHE_KEY_PREFIX}{severity_key}"


async def _load_one(severity_key: str) -> dict | None:

    cached = cache_get_json(severity_cache_key(severity_key), log_prefix=LOG_PREFIX)
    if cached is not None:
        return cached

    async with AsyncSessionLocal() as db:
        row = await get_alert_severity(db, severity_key)

        if not row:

            default = {
                **DEFAULT_SEVERITY.get(severity_key, {}),
                **(snapshot_severity(severity_key) or {}),
            }
            if not default.get("severity"):
                return None

            row = await upsert_alert_severity(
                db,
                severity_key,
                severity=default["severity"],
                description=default.get("description"),
            )
            print(f"[{LOG_PREFIX}] seed default severity ลง DB: {severity_key} = {default['severity']}")

        data = {"severity_key": row.severity_key, "severity": row.severity}

    cache_set_json(severity_cache_key(severity_key), data, SEVERITY_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)
    return data


async def get_severity(detection_type: str, mode: str | None = None) -> str:

    if mode:
        specific = await _load_one(severity_key_for(detection_type, mode))
        if specific:
            return specific["severity"]

    generic = await _load_one(detection_type)
    if generic:
        return generic["severity"]

    return DEFAULT_FALLBACK_SEVERITY


async def update_severity(severity_key: str, severity: str) -> dict:

    async with AsyncSessionLocal() as db:
        row = await upsert_alert_severity(db, severity_key, severity=severity)
        result = {"severity_key": row.severity_key, "severity": row.severity}

    cache_delete(severity_cache_key(severity_key), log_prefix=LOG_PREFIX)
    print(f"[{LOG_PREFIX}] อัปเดต severity {severity_key} = {severity} (เคลียร์ cache แล้ว)")
    return result
