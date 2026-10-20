

import json
import time

import redis

from redis_config import REDIS_CONFIG


try:
    from redis.retry import Retry
    from redis.backoff import NoBackoff

    _NO_RETRY = {"retry": Retry(NoBackoff(), 0), "retry_on_error": []}
except ImportError:
    _NO_RETRY = {}


REDIS_DOWN_BACKOFF_SECONDS = 10

_down_until = 0.0


class _Client(redis.Redis):

    def execute_command(self, *args, **kwargs):
        global _down_until

        now = time.monotonic()

        if now < _down_until:
            raise redis.exceptions.ConnectionError(
                "Redis ต่อไม่ได้เมื่อครู่นี้ - พักไว้ก่อน "
                f"{_down_until - now:.0f} วินาที (REDIS_HOST ชี้ที่อยู่ที่ยังใช้ไม่ได้หรือเปล่า)"
            )

        try:
            result = super().execute_command(*args, **kwargs)
        except (redis.exceptions.ConnectionError, redis.exceptions.TimeoutError):
            _down_until = time.monotonic() + REDIS_DOWN_BACKOFF_SECONDS
            raise

        _down_until = 0.0
        return result


_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:


        _client = _Client(
            **REDIS_CONFIG,
            health_check_interval=30,
            socket_connect_timeout=5,
            **_NO_RETRY,
        )
    return _client


def reset_client() -> None:

    global _client

    old, _client = _client, None

    if old is not None:
        try:
            old.close()
        except Exception as e:
            print(f"[REDIS] ปิด client เก่าไม่สำเร็จ (ข้ามไป): {e}")


def cache_get_json(key: str, *, log_prefix: str = "CACHE"):

    try:
        raw = get_redis().get(key)

        if raw is None:
            return None

        if isinstance(raw, bytes):
            raw = raw.decode()

        return json.loads(raw)

    except Exception as e:
        print(f"[{log_prefix}] อ่าน cache ไม่ได้: {key} | {e}")
        return None


def cache_set_json(key: str, data, ttl_seconds: int, *, log_prefix: str = "CACHE") -> None:
    try:
        get_redis().setex(key, ttl_seconds, json.dumps(data))
    except Exception as e:
        print(f"[{log_prefix}] บันทึก cache ไม่ได้: {key} | {e}")


def cache_delete(key: str, *, log_prefix: str = "CACHE") -> None:
    try:
        get_redis().delete(key)
        print(f"[{log_prefix}] cleared: {key}")
    except Exception as e:
        print(f"[{log_prefix}] ล้าง cache ไม่ได้: {key} | {e}")


def publish_json(channel: str, payload: dict, *, log_prefix: str = "PUBLISH") -> dict:

    try:
        receiver_count = get_redis().publish(
            channel,
            json.dumps(payload, ensure_ascii=False, default=str),
        )
        return {"ok": True, "channel": channel, "receiver_count": receiver_count}

    except Exception as e:
        print(f"[{log_prefix}] publish ไม่สำเร็จ: {channel} | {e}")
        return {"ok": False, "error": str(e)}
