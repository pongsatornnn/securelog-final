# Redis client กลางของ process — แก้ปัญหาเดิมที่ทุก operation เปิด connection ใหม่

import json

import redis

from redis_config import REDIS_CONFIG


_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        # health_check_interval: ping ก่อนใช้ connection ที่ idle นาน กัน error จาก
        _client = redis.Redis(**REDIS_CONFIG, health_check_interval=30)
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
