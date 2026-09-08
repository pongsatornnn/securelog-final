# Redis client กลางของ process — แก้ปัญหาเดิมที่ทุก operation เปิด connection ใหม่

import json
import time

import redis

from redis_config import REDIS_CONFIG


# redis-py 6 ขึ้นไปตั้ง retry อัตโนมัติ 3 ครั้งพร้อม backoff — connect timeout 5 วิ จึงกลายเป็น
# เกือบนาทีกว่าจะรู้ว่าต่อไม่ได้ ที่นี่ไม่ต้องการ retry ชั้นนั้น (ทุก service มีลูปของตัวเองอยู่แล้ว)
try:
    from redis.retry import Retry
    from redis.backoff import NoBackoff

    _NO_RETRY = {"retry": Retry(NoBackoff(), 0), "retry_on_error": []}
except ImportError:
    _NO_RETRY = {}


# ต่อ Redis ไม่ได้แล้วพักไว้กี่วินาที ก่อนจะยอมลองใหม่
#
# ทำไมต้องมี: หน้าเว็บหนึ่งหน้าเรียก Redis หลายสิบครั้ง ถ้าปลายทางหายไป (ย้าย IP แล้วยังไม่ได้
# ตั้งค่าเครือข่าย) ทุกครั้งจะจ่ายค่า connect timeout เต็ม ๆ กลายเป็นค้างเป็นนาที ทั้งที่รู้ตั้งแต่
# ครั้งแรกแล้วว่าต่อไม่ได้ — วัดจริงบนเครื่องทดสอบ: /api/alerts ค้างเกิน 120 วินาที
# มีตัวนี้แล้ว ครั้งแรกจ่าย 5 วิ ที่เหลือเด้งทันที หน้าเว็บขึ้น error ให้เห็นแทนที่จะแขวน
REDIS_DOWN_BACKOFF_SECONDS = 10

_down_until = 0.0


class _Client(redis.Redis):
    # ครอบ execute_command เพื่อจำว่า "เพิ่งต่อไม่ได้" — ไม่ได้เปลี่ยนพฤติกรรมตอนใช้งานปกติ
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
        # health_check_interval: ping ก่อนใช้ connection ที่ idle นาน กัน error จาก
        #
        # socket_connect_timeout: ที่อยู่ใน REDIS_HOST หายไป (ย้าย IP แล้วยังไม่ได้ตั้งค่าเครือข่าย)
        # ต้องรู้เร็ว ไม่งั้นหน้าเว็บค้างเป็นนาทีโดยไม่มีข้อความบอกอะไรเลย
        #
        # ไม่ตั้ง socket_timeout เพราะ client ตัวเดียวกันนี้ถูกใช้ทำ pubsub แบบ blocking
        # (process_agent / LINE alert_subscriber วนอยู่ใน pubsub.listen()) — ตั้งแล้วจะเด้ง
        # TimeoutError ทุกครั้งที่ไม่มีข้อความเข้ามาในช่วงเวลานั้น
        _client = _Client(
            **REDIS_CONFIG,
            health_check_interval=30,
            socket_connect_timeout=5,
            **_NO_RETRY,
        )
    return _client


def reset_client() -> None:
    # ทิ้ง client กลางของ process นี้ ให้คำสั่งถัดไปสร้างใหม่จาก REDIS_CONFIG ตัวปัจจุบัน
    global _client

    old, _client = _client, None

    if old is not None:
        try:
            old.close()
        except Exception as e:
            print(f"[REDIS] ปิด client เก่าไม่สำเร็จ (ข้ามไป): {e}")


# ============================================================

def cache_get_json(key: str, *, log_prefix: str = "CACHE"):
    # คืนค่า JSON ที่ cache ไว้ หรือ None ถ้าไม่มี/อ่านไม่ได้ (ให้ caller fallback DB)
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


# ============================================================

def publish_json(channel: str, payload: dict, *, log_prefix: str = "PUBLISH") -> dict:
    # publish payload (JSON) ขึ้น channel — คืน {ok, channel, receiver_count}
    try:
        receiver_count = get_redis().publish(
            channel,
            json.dumps(payload, ensure_ascii=False, default=str),
        )
        return {"ok": True, "channel": channel, "receiver_count": receiver_count}

    except Exception as e:
        print(f"[{log_prefix}] publish ไม่สำเร็จ: {channel} | {e}")
        return {"ok": False, "error": str(e)}
