# Worker: subscribe Redis channel `security_alerts_stream` (ตัวเดียวกับที่ detector

import asyncio
import json
import time

import redis

from alerts import SECURITY_ALERTS_STREAM_CHANNEL
from database.connection import AsyncSessionLocal, wait_for_table
from database.crud import get_approved_line_user_ids
from redis_client import get_redis

from settings_cache import ensure_loaded

from LINE_API import config, line_client
from LINE_API.alert_formatter import format_alert


# รอข้อความรอบละกี่วินาทีก่อนวนกลับมาเช็คใหม่ — ไม่ใช่ timeout ที่เป็น error
PUBSUB_POLL_SECONDS = 5

async def _approved_user_ids() -> list[str]:
    async with AsyncSessionLocal() as db:
        return await get_approved_line_user_ids(db)


def _is_new_alert(r: redis.Redis, alert_id) -> bool:
    # True = alert แถวนี้ (id นี้) ยังไม่เคยส่ง -> ส่งได้
    if alert_id is None:
        return True
    try:
        key = f"{config.NOTIFY_DEDUP_KEY_PREFIX}{alert_id}"
        # nx=True เซ็ตเฉพาะตอน key ยังไม่มี, ex=TTL ไว้ล้าง key อัตโนมัติ
        return bool(r.set(key, "1", nx=True, ex=config.NOTIFY_DEDUP_TTL_SEC))
    except Exception as e:
        # fail-open: ถ้า Redis error ให้ส่ง (ยอมส่งซ้ำ ดีกว่าพลาด alert)
        print(f"[LINE-NOTIFY] dedup check error (ส่งต่อ): {e}")
        return True


def handle_alert(alert: dict, loop: asyncio.AbstractEventLoop, r: redis.Redis) -> None:
    label = alert.get("attack_type", "-")

    # กันสแปม: alert แถวเดิมที่โจมตีซ้ำ (merge, id เดิม) ไม่ส่งซ้ำ
    if not _is_new_alert(r, alert.get("id")):
        print(f"[LINE-NOTIFY] ข้าม '{label}' (alert id={alert.get('id')} ส่งไปแล้ว)")
        return

    # อ่านค่า LINE ล่าสุดเข้า cache ก่อนใช้ — worker นี้เป็น process แยกและรันยาว
    loop.run_until_complete(ensure_loaded())

    if not config.is_configured():
        print("[LINE-NOTIFY] ยังไม่ได้ตั้งค่า LINE (หน้า System Settings) — ข้าม")
        return

    user_ids = loop.run_until_complete(_approved_user_ids())

    if not user_ids:
        print("[LINE-NOTIFY] ไม่มีผู้รับที่อนุมัติแล้ว — ข้าม")
        return

    text = format_alert(alert)
    ok = line_client.multicast_text(user_ids, text)
    print(f"[LINE-NOTIFY] ส่ง '{label}' ไป {len(user_ids)} คน: {'ok' if ok else 'FAIL'}")


async def _configured_now() -> bool:
    await ensure_loaded()
    return config.is_configured()


def start_line_notifier() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # ตารางถูกสร้างโดยเว็บตอน start — worker นี้ขึ้นพร้อมกันจึงอาจมาถึงก่อน (ดู wait_for_table)
    loop.run_until_complete(wait_for_table("app_settings", "LINE-NOTIFY"))

    # เตือนตอน start เฉย ๆ ไม่ต้อง exit — แอดมินตั้งค่าทีหลังจากหน้า System Settings ได้
    # อ่านไม่ได้จริง ๆ ก็ไปต่อ ไม่ตาย เดี๋ยวอ่านใหม่ตอนมี alert เข้ามา (ลูปนั้นกัน exception ไว้แล้ว)
    try:
        configured = loop.run_until_complete(_configured_now())
    except Exception as e:
        print(f"[LINE-NOTIFY] อ่านค่าจากฐานไม่ได้ ({e}) — เริ่มทำงานต่อ")
        configured = True

    if not configured:
        print("[LINE-NOTIFY] ยังไม่ได้ตั้งค่า LINE — ตั้งได้ที่หน้า System Settings แล้วมีผลทันที")

    print("[LINE-NOTIFY] started")
    print(f"[LINE-NOTIFY] subscribe channel: {SECURITY_ALERTS_STREAM_CHANNEL}")

    while True:
        pubsub = None
        try:
            r = get_redis()
            pubsub = r.pubsub(ignore_subscribe_messages=True)
            pubsub.subscribe(SECURITY_ALERTS_STREAM_CHANNEL)

            # อ่านด้วย get_message ไม่ใช่ listen(): redis-py 8 เอา socket_connect_timeout
            # มาเป็น socket_timeout ด้วย การ block รออ่านจึงเด้ง TimeoutError ทุก 5 วินาที
            # ทั้งที่ "ช่วงที่ไม่มีข้อความ" เป็นเรื่องปกติของ pubsub — เดิมต้องรื้อ subscription
            # ทิ้งแล้ว subscribe ใหม่ทุก 6 วินาที (มีช่วงสั้น ๆ ที่ไม่มีใคร subscribe = ข้อความหาย)
            while True:
                try:
                    message = pubsub.get_message(timeout=PUBSUB_POLL_SECONDS)
                except redis.exceptions.TimeoutError:
                    continue

                if message is None:
                    continue

                if message.get("type") != "message":
                    continue

                try:
                    alert = json.loads(message["data"])
                except (ValueError, TypeError) as e:
                    print(f"[LINE-NOTIFY] parse alert ไม่ได้: {e}")
                    continue

                try:
                    handle_alert(alert, loop, r)
                except Exception as e:
                    print(f"[LINE-NOTIFY] ส่งแจ้งเตือนล้มเหลว: {e}")

        except KeyboardInterrupt:
            print("\n[LINE-NOTIFY] stopped")
            break

        except redis.exceptions.ConnectionError as e:
            print(f"[LINE-NOTIFY] Redis connection error: {e}")
            time.sleep(3)

        except Exception as e:
            print(f"[LINE-NOTIFY] error: {e}")
            time.sleep(1)

        finally:
            # ปิดเฉพาะ pubsub (คืน connection เข้า pool) — client กลางห้ามปิด
            try:
                if pubsub:
                    pubsub.close()
            except Exception:
                pass

    try:
        loop.close()
    except Exception:
        pass


if __name__ == "__main__":
    start_line_notifier()
