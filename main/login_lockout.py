

from rule_cache import get_rule
from redis_client import get_redis


LOCKOUT_RULE_KEY = "login_lockout"
FAIL_KEY_PREFIX = "login_fail:"


def fail_key(ip: str) -> str:
    return f"{FAIL_KEY_PREFIX}{(ip or 'unknown').strip()}"


async def _get_config() -> dict:

    return await get_rule(LOCKOUT_RULE_KEY)


async def check_locked(ip: str) -> tuple[bool, int]:

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

        print(f"[LOGIN-LOCKOUT] check_locked error: {e}")
        return False, 0


async def record_failure(ip: str) -> dict:

    config = await _get_config()
    threshold = config["threshold"]
    window = config["window_seconds"]

    if not config.get("is_active", True):
        return {"locked": False, "count": 0, "threshold": threshold, "retry_after": 0}

    try:
        r = get_redis()
        key = fail_key(ip)
        count = r.incr(key)


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

    try:
        get_redis().delete(fail_key(ip))
    except Exception as e:
        print(f"[LOGIN-LOCKOUT] reset_failures error: {e}")
