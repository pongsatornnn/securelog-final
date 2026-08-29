import redis
import json
import time
import asyncio
from datetime import datetime
from zoneinfo import ZoneInfo

from auth_cache import verify_agent_token
from redis_client import get_redis

from database.connection import AsyncSessionLocal
from database.crud import get_active_blacklist, get_ip_whitelist


TZ = ZoneInfo("Asia/Bangkok")

AGENT_RUNTIME_TTL_SECONDS = 15
AGENT_COMMAND_CHANNEL_PREFIX = "agent_commands:"


def now_thai() -> str:
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")


def agent_runtime_key(agent_id: str) -> str:
    return f"agent_runtime:{agent_id}"


def agent_command_channel(agent_id: str) -> str:
    return f"{AGENT_COMMAND_CHANNEL_PREFIX}{agent_id}"


async def load_blacklist_ips() -> list[dict]:
    try:
        async with AsyncSessionLocal() as db:
            # เฉพาะ IP ที่ยัง block อยู่จริง (ไม่รวมที่หมดอายุแล้ว)
            rows = await get_active_blacklist(db)

            blacklist = []

            for row in rows:
                blacklist.append({
                    "ip_address": row.ip_address,
                    "event": row.event,
                })

            return blacklist

    except Exception as e:
        print(f"[BLACKLIST] ดึง blacklist จาก DB ไม่ได้: {e}")
        return []


async def load_whitelist_ips() -> list[str]:
    try:
        async with AsyncSessionLocal() as db:
            rows = await get_ip_whitelist(db)
            return [row.ip_address for row in rows]

    except Exception as e:
        print(f"[WHITELIST] ดึง whitelist จาก DB ไม่ได้: {e}")
        return []


def send_sync_whitelist_to_agent(
    r,
    agent_id: str,
    ip_whitelist: list[str] | None = None,
) -> None:

    if ip_whitelist is None:
        ip_whitelist = []

    payload = {
        "command": "sync_whitelist",
        "agent_id": agent_id,
        "ips": ip_whitelist,
        "timestamp": time.time(),
        "timestamp_text": now_thai(),
    }

    channel = agent_command_channel(agent_id)
    r.publish(channel, json.dumps(payload))

    print(
        f"[SYNC] ส่ง whitelist ปัจจุบันไปที่ {channel} | "
        f"Agent: {agent_id} | "
        f"จำนวน {len(ip_whitelist)} IP"
    )


def send_hello_to_agent(
    r,
    agent_id: str,
    ip_blacklist: list[dict] | None = None,
) -> None:

    if ip_blacklist is None:
        ip_blacklist = []

    payload = {
        "command": "hello",
        "agent_id": agent_id,
        "message": "hello",
        "timestamp": time.time(),
        "timestamp_text": now_thai(),
        "ip_blacklist": ip_blacklist,
    }

    channel = agent_command_channel(agent_id)
    r.publish(channel, json.dumps(payload))

    print(
        f"[HELLO] ส่ง hello ไปที่ {channel} | "
        f"Agent: {agent_id} | "
        f"Blacklist in hello: {len(ip_blacklist)} IP"
    )


def send_sync_blacklist_to_agent(
    r,
    agent_id: str,
    ip_blacklist: list[dict] | None = None,
) -> None:

    if ip_blacklist is None:
        ip_blacklist = []

    payload = {
        "command": "sync_blacklist",
        "agent_id": agent_id,
        "ips": ip_blacklist,
        "timestamp": time.time(),
        "timestamp_text": now_thai(),
    }

    channel = agent_command_channel(agent_id)
    r.publish(channel, json.dumps(payload))

    print(
        f"[SYNC] ส่ง blacklist ปัจจุบันไปที่ {channel} | "
        f"Agent: {agent_id} | "
        f"จำนวน {len(ip_blacklist)} IP"
    )


def save_agent_runtime(
    agent_id: str,
    cpu,
    ram,
    loop: asyncio.AbstractEventLoop,
) -> bool:
    try:
        now_ts = time.time()
        key = agent_runtime_key(agent_id)

        r = get_redis()

        was_offline = not bool(r.exists(key))

        payload = {
            "agent_id": agent_id,
            "status": "online",
            "cpu": cpu,
            "ram": ram,
            "last_seen": datetime.now(TZ).isoformat(),
            "last_seen_text": now_thai(),
            "last_seen_ts": now_ts,
        }

        r.set(
            key,
            json.dumps(payload),
            ex=AGENT_RUNTIME_TTL_SECONDS,
        )

        if was_offline:
            ip_blacklist = loop.run_until_complete(load_blacklist_ips())
            ip_whitelist = loop.run_until_complete(load_whitelist_ips())

            # ส่ง hello แบบไม่แนบ blacklist เพื่อไม่ให้กระทบ behavior เดิม
            send_hello_to_agent(
                r=r,
                agent_id=agent_id,
                ip_blacklist=[],
            )

            # ส่ง sync แยกอีก command
            send_sync_blacklist_to_agent(
                r=r,
                agent_id=agent_id,
                ip_blacklist=ip_blacklist,
            )

            # sync whitelist ให้ agent ใช้เป็น never-block list อัตโนมัติ
            send_sync_whitelist_to_agent(
                r=r,
                agent_id=agent_id,
                ip_whitelist=ip_whitelist,
            )

        return was_offline

    except Exception as e:
        print(f"[RUNTIME] บันทึก runtime cache ไม่ได้: {agent_id} | {e}")
        return False


def parse_redis_message(message) -> dict | None:
    try:
        raw_data = message.get("data")

        if isinstance(raw_data, bytes):
            raw_data = raw_data.decode()

        if isinstance(raw_data, str):
            return json.loads(raw_data)

        if isinstance(raw_data, dict):
            return raw_data

        print(f"[METRICS] message data type ไม่รองรับ: {type(raw_data)}")
        return None

    except json.JSONDecodeError as e:
        print(f"[METRICS] JSON ไม่ถูกต้อง: {e}")
        return None

    except Exception as e:
        print(f"[METRICS] อ่าน message ไม่ได้: {e}")
        return None


def listen_agent_metrics() -> None:
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    while True:
        pubsub = None

        try:
            r = get_redis()
            r.ping()

            pubsub = r.pubsub()
            pubsub.subscribe("agent_metrics")

            print("[CENTRAL] Redis connected")
            print("[CENTRAL] Listening agent_metrics...")

            for message in pubsub.listen():
                if message.get("type") != "message":
                    continue

                data = parse_redis_message(message)

                if not data:
                    continue

                agent_id = data.get("agent_id")
                secret_token = data.get("secret_token")
                cpu = data.get("cpu")
                ram = data.get("ram")

                # IP ที่ agent อ่านจาก interface ของตัวเอง ณ ตอนส่ง (ไม่ใช่ค่าที่ฝังในไฟล์)
                host_ip = data.get("host_ip")
                host_iface = data.get("host_iface")

                if not agent_id:
                    print("[METRICS] ไม่มี agent_id")
                    continue

                is_valid = loop.run_until_complete(
                    verify_agent_token(agent_id, secret_token, host_ip, host_iface)
                )

                if not is_valid:
                    print(f"[AUTH] ปฏิเสธ metrics จาก Agent: {agent_id}")
                    continue

                is_first_online = save_agent_runtime(
                    agent_id=agent_id,
                    cpu=cpu,
                    ram=ram,
                    loop=loop,
                )

                online_type = "first/reconnect" if is_first_online else "online"

                print(
                    f"[AGENT] {agent_id} | "
                    f"CPU: {cpu}% | "
                    f"RAM: {ram}% | "
                    f"STATUS: {online_type} | "
                    f"LAST_SEEN: {now_thai()}"
                )

        except KeyboardInterrupt:
            print("\n[CENTRAL] Stop process_agent")
            break

        except redis.exceptions.ConnectionError as e:
            print(f"[METRICS] Redis connection error: {e} รอ 5 วินาที...")
            time.sleep(5)

        except redis.exceptions.RedisError as e:
            print(f"[METRICS] Redis error: {e} รอ 5 วินาที...")
            time.sleep(5)

        except Exception as e:
            print(f"[METRICS] Error: {e} รอ 5 วินาที...")
            time.sleep(5)

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
    listen_agent_metrics()
