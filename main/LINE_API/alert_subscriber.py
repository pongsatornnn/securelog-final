

import asyncio
import json
import time

import redis

from alerts import SECURITY_ALERTS_STREAM_CHANNEL
from blacklist_ttl_cache import should_notify_line
from database.connection import AsyncSessionLocal, wait_for_table
from database.crud import get_approved_line_user_ids
from redis_client import get_redis

from settings_cache import ensure_loaded

from LINE_API import config, line_client
from LINE_API.alert_formatter import format_alert


PUBSUB_POLL_SECONDS = 5

async def _approved_user_ids() -> list[str]:
    async with AsyncSessionLocal() as db:
        return await get_approved_line_user_ids(db)


def _is_new_alert(r: redis.Redis, alert_id) -> bool:

    if alert_id is None:
        return True
    try:
        key = f"{config.NOTIFY_DEDUP_KEY_PREFIX}{alert_id}"

        return bool(r.set(key, "1", nx=True, ex=config.NOTIFY_DEDUP_TTL_SEC))
    except Exception as e:

        print(f"[LINE-NOTIFY] dedup check error (ส่งต่อ): {e}")
        return True


async def _should_notify(alert: dict) -> bool:


    try:
        return await should_notify_line(alert.get("detection_type"))
    except Exception as e:

        print(f"[LINE-NOTIFY] อ่านค่าการแจ้ง LINE ไม่ได้ ({e}) — ส่งต่อ")
        return True


def handle_alert(alert: dict, loop: asyncio.AbstractEventLoop, r: redis.Redis) -> None:
    label = alert.get("attack_type", "-")


    if not loop.run_until_complete(_should_notify(alert)):
        print(f"[LINE-NOTIFY] ข้าม '{label}' (ตั้งไว้ว่าไม่ต้องแจ้ง LINE)")
        return


    if not _is_new_alert(r, alert.get("id")):
        print(f"[LINE-NOTIFY] ข้าม '{label}' (alert id={alert.get('id')} ส่งไปแล้ว)")
        return


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


    loop.run_until_complete(wait_for_table("app_settings", "LINE-NOTIFY"))


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
