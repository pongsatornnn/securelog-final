"""
Redis client กลางของ process — แก้ปัญหาเดิมที่ทุก operation เปิด connection ใหม่
(Redis เราเป็น mTLS: เปิดใหม่ = TLS handshake ทุกครั้ง ~38ms/operation วัดจริง
ใช้ client เดียวผ่าน ConnectionPool ในตัวของ redis-py เหลือ ~0.4ms)

ใช้ยังไง:
- get_redis() คืน client กลางของ process นี้ (สร้างครั้งแรกตอนเรียก) — ห้าม .close()
  ใช้ได้ทั้ง get/set/publish/blpop; pubsub ที่ฟังยาวๆ ให้เรียก get_redis().pubsub() ได้เลย
- cache_*_json / cache_delete* = helper สำหรับ cache layer (fail-open: Redis พังคืน None
  ให้ caller fallback ไป DB เอง เหมือน behavior เดิมทุกไฟล์)
- publish_json = helper สำหรับ pub/sub command bus (คืน {ok, receiver_count})

ถ้า Redis restart: connection เสียตัวแรกจะ error (caller เดิม catch อยู่แล้ว)
แล้ว pool จะสร้าง connection ใหม่ให้ในคำสั่งถัดไปเอง — พฤติกรรม reconnect เท่าเดิม
"""

import json

import redis

from redis_config import REDIS_CONFIG


_client: redis.Redis | None = None


def get_redis() -> redis.Redis:
    global _client
    if _client is None:
        # health_check_interval: ping ก่อนใช้ connection ที่ idle นาน กัน error จาก
        # connection ที่ server ปิดไปแล้วระหว่างช่วงเงียบ
        _client = redis.Redis(**REDIS_CONFIG, health_check_interval=30)
    return _client


def reset_client() -> None:
    """
    ทิ้ง client กลางของ process นี้ ให้คำสั่งถัดไปสร้างใหม่จาก REDIS_CONFIG ตัวปัจจุบัน

    ใช้ตอนเปลี่ยนรหัส Redis ระหว่างที่ระบบรันอยู่ (redis_admin_password.py) — พอ `ACL LOAD`
    ผ่าน Redis จะตัด connection ของ user นั้นทิ้งทันที และ pool เดิมยังถือรหัสเก่าไว้ในหน่วยความจำ
    ต่อใหม่เองก็ไม่ผ่าน · ไม่ได้ตั้งใจให้เรียกในเส้นทางปกติ
    """
    global _client

    old, _client = _client, None

    if old is not None:
        try:
            old.close()      # best-effort: connection ในนั้นถูก server ตัดไปแล้วเป็นส่วนใหญ่
        except Exception as e:
            print(f"[REDIS] ปิด client เก่าไม่สำเร็จ (ข้ามไป): {e}")


# ============================================================
# Cache helpers (JSON) — fail-open ทุกตัว
# ============================================================

def cache_get_json(key: str, *, log_prefix: str = "CACHE"):
    """คืนค่า JSON ที่ cache ไว้ หรือ None ถ้าไม่มี/อ่านไม่ได้ (ให้ caller fallback DB)"""
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
# Pub/Sub helper
# ============================================================

def publish_json(channel: str, payload: dict, *, log_prefix: str = "PUBLISH") -> dict:
    """
    publish payload (JSON) ขึ้น channel — คืน {ok, channel, receiver_count}
    หรือ {ok: False, error} ถ้าส่งไม่สำเร็จ (ไม่ throw ให้ caller ตัดสินใจเองจากผล)
    """
    try:
        receiver_count = get_redis().publish(
            channel,
            json.dumps(payload, ensure_ascii=False, default=str),
        )
        return {"ok": True, "channel": channel, "receiver_count": receiver_count}

    except Exception as e:
        print(f"[{log_prefix}] publish ไม่สำเร็จ: {channel} | {e}")
        return {"ok": False, "error": str(e)}
