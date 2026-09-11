# โค้ดกลางที่ detector ทุกตัว (auth / web / firewall) ใช้ร่วมกัน

import json
import time
import asyncio
from collections import deque
from datetime import datetime, timedelta
from typing import Any, Callable

import redis

from database.connection import AsyncSessionLocal, wait_for_table
from database.crud import (
    create_security_alert,
    get_agent_by_agent_id,
    get_mergeable_security_alert,
    merge_security_alert,
)
from process_log_detect.security_response import handle_attack_ip, publish_alert_event
from alerts import build_alert_summary
from rule_cache import get_rule
from redis_client import get_redis


# ถ้า attacker ยิงต่อเนื่อง (ครบ threshold ซ้ำๆ ในเวลาไม่ห่างกันมาก) จะ merge
ALERT_MERGE_COOLDOWN_SECONDS = 60


# BLPOP รอของในคิวนานสุดกี่วินาทีก่อนวนรอบใหม่ — ต้อง **น้อยกว่า** socket timeout ของ redis-py
QUEUE_BLOCK_TIMEOUT_SECONDS = 3


# ============================================================

def safe_json_loads(raw: Any, log_prefix: str = "DETECT") -> dict | None:
    try:
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")

        if isinstance(raw, str):
            return json.loads(raw)

        if isinstance(raw, dict):
            return raw

        return None

    except Exception as e:
        print(f"[{log_prefix}] JSON decode error: {e}")
        print(f"[{log_prefix}] raw={raw!r}")
        return None


def parse_agent_time_to_epoch(log: dict) -> float:
    # ใช้เวลา log ฝั่ง Agent เป็นหลักในการนับ window
    value = log.get("agent_event_time_thai")

    if not value:
        return time.time()

    try:
        # format จาก normalize: 2026-06-26 14:30:05
        dt = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()
    except Exception:
        return time.time()


# ============================================================

def prune_old_events(
    events: deque,
    now_ts: float,
    window_seconds: int,
    max_events: int,
) -> None:
    # ตัด event ที่พ้น window + cap จำนวนสูงสุดกัน memory โตไม่จำกัด
    while events and now_ts - events[0]["ts"] > window_seconds:
        events.popleft()

    while len(events) > max_events:
        events.popleft()


def get_events_in_window(events: deque, now_ts: float, window_seconds: int) -> list[dict]:
    return [event for event in events if now_ts - event["ts"] <= window_seconds]


# ============================================================

async def save_alert_to_db(
    *,
    detection_type: str,
    category: str,
    log_prefix: str,
    event_count: int,
    window_seconds: int,
    threshold: int,
    related_logs: list[dict],
    mode: str | None = None,
    agent_id: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
) -> None:
    # เขียน alert ลง DB — merge เข้าแถวเดิมของเหตุการณ์เดียวกันที่ยัง active ใน cooldown
    try:
        first_event_at = None
        last_event_at = None

        if related_logs:
            first_event_at = datetime.fromtimestamp(related_logs[0]["ts"])
            last_event_at = datetime.fromtimestamp(related_logs[-1]["ts"])

        merge_since = datetime.now() - timedelta(seconds=ALERT_MERGE_COOLDOWN_SECONDS)

        async with AsyncSessionLocal() as db:
            existing = await get_mergeable_security_alert(
                db,
                detection_type=detection_type,
                since=merge_since,
                source_ip=source_ip,
                agent_id=agent_id,
                username=username if not source_ip else None,
            )

            response_action = await handle_attack_ip(source_ip, detection_type)

            if existing:
                alert = await merge_security_alert(
                    db,
                    existing,
                    add_event_count=event_count,
                    extra_related_logs=related_logs,
                    last_event_at=last_event_at,
                    response_action=response_action,
                )
                is_merge = True
            else:
                alert = await create_security_alert(
                    db,
                    detection_type=detection_type,
                    category=category,
                    mode=mode,
                    agent_id=agent_id,
                    source_ip=source_ip,
                    username=username,
                    response_action=response_action,
                    event_count=event_count,
                    window_seconds=window_seconds,
                    threshold=threshold,
                    first_event_at=first_event_at,
                    last_event_at=last_event_at,
                    related_logs=related_logs,
                )
                is_merge = False

            agent = await get_agent_by_agent_id(db, agent_id) if agent_id else None

        publish_alert_event(await build_alert_summary(alert, agent))

        action_word = "merge เข้า alert เดิม" if is_merge else "สร้าง alert ใหม่"
        user_part = f"user={username} | " if category == "auth" else ""
        print(
            f"[{log_prefix}] บันทึก alert ลง DB สำเร็จ ({action_word}): {detection_type} | "
            f"agent={agent_id} | ip={source_ip} | {user_part}"
            f"action={response_action} | total_event_count={alert.event_count}"
        )

    except Exception as e:
        print(f"[{log_prefix}] บันทึก alert ลง DB ไม่สำเร็จ: {detection_type} | {e}")


# ============================================================

def seed_rules(loop: asyncio.AbstractEventLoop, rule_keys, log_prefix: str) -> None:
    # เรียก get_rule ครั้งแรกของแต่ละ rule เพื่อ seed ค่า default ลง DB
    for rule_key in rule_keys:
        try:
            loop.run_until_complete(get_rule(rule_key))
        except Exception as e:
            print(f"[{log_prefix}] seed rule {rule_key} ไม่สำเร็จ: {e}")


# ตารางถูกสร้างโดยเว็บตอน start — detector อาจมาถึงก่อน (ดู wait_for_table ใน database/connection)
# ถ้าไม่รอ: seed rule/โหลด signature จะล้มเงียบ ๆ แล้ววิ่งต่อแบบ "ไม่มี signature เลย" จนครบรอบ refresh
DETECTOR_GATE_TABLE = "detection_rules"   # ตารางที่ detector ทุกตัวต้องใช้ (get_rule เรียกทุกครั้ง)


def run_detector_loop(
    queue_name: str,
    process_log: Callable[[dict, asyncio.AbstractEventLoop], None],
    log_prefix: str,
    startup_messages: tuple[str, ...] = (),
    on_start: Callable[[asyncio.AbstractEventLoop], None] | None = None,
) -> None:
    # โครง worker มาตรฐานของ detector: blpop จาก queue -> decode -> process_log(log, loop)
    r = get_redis()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print(f"[{log_prefix}] started")
    print(f"[{log_prefix}] input queue: {queue_name}")
    for message in startup_messages:
        print(f"[{log_prefix}] {message}")

    # รอให้ฐานพร้อมก่อนค่อย seed rule / โหลด signature (ไม่งั้นล้มเงียบแล้วได้ของว่างไปใช้)
    loop.run_until_complete(wait_for_table(DETECTOR_GATE_TABLE, log_prefix))

    if on_start:
        on_start(loop)

    while True:
        try:
            item = r.blpop(queue_name, timeout=QUEUE_BLOCK_TIMEOUT_SECONDS)

            if not item:
                continue

            _, raw = item
            log = safe_json_loads(raw, log_prefix)

            if not log:
                continue

            process_log(log, loop)

        except KeyboardInterrupt:
            print(f"\n[{log_prefix}] stopped")
            break

        except redis.exceptions.ConnectionError as e:
            print(f"[{log_prefix}] Redis connection error: {e}")
            time.sleep(3)

        except Exception as e:
            print(f"[{log_prefix}] error: {e}")
            time.sleep(1)

    try:
        loop.close()
    except Exception:
        pass
