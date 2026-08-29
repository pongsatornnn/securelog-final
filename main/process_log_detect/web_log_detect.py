# Detector: Web attack จาก normalized web access log — 2 แบบใน worker เดียว

import re
import time
import asyncio
from collections import defaultdict, deque
from urllib.parse import unquote_plus

from rule_cache import get_rule
from signature_cache import get_signatures
from process_log_detect.detector_common import (
    parse_agent_time_to_epoch,
    prune_old_events,
    get_events_in_window,
    save_alert_to_db,
    seed_rules,
    run_detector_loop,
)


NORMALIZED_WEB_QUEUE = "normalized_web_logs_queue"

LOG_PREFIX = "WEB-DETECT"

# detection_type -> rule_key ใน detection_rules
RULE_KEY_BY_TYPE = {
    "sql_injection": "web_sql_injection",
    "xss": "web_xss",
    "path_traversal": "web_path_traversal",
    "command_injection": "web_command_injection",
    "http_flood": "web_http_flood",
}

# เก็บ history สูงสุดต่อ key เพื่อไม่ให้ memory โตไม่จำกัด
MAX_EVENTS_PER_KEY = 1000

# detector เก็บ regex ที่ compile แล้วใน memory และ reload จาก DB/cache ตาม interval นี้
SIGNATURE_REFRESH_SECONDS = 30

# ลำดับ = ความสำคัญ (รุนแรงกว่าอยู่ก่อน) เวลา request เดียว match หลายชนิด
ATTACK_PRIORITY = [
    "sql_injection",
    "command_injection",
    "path_traversal",
    "xss",
]

ATTACK_LABEL = {
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal",
    "command_injection": "Command Injection",
    "http_flood": "HTTP Flood (App-level DoS)",
}


# ============================================================

# detection_type -> compiled regex (รวมทุก pattern ที่ active) หรือ None ถ้าไม่มี pattern
_compiled_signatures: dict[str, re.Pattern | None] = {}
_last_signature_reload: float = 0.0


def compile_patterns(patterns: list[str]) -> re.Pattern | None:
    # compile pattern ทั้งหมดของชนิดหนึ่งรวมเป็น regex เดียว (IGNORECASE)
    valid: list[str] = []

    for pattern in patterns:
        try:
            re.compile(pattern)
            valid.append(pattern)
        except re.error as e:
            print(f"[{LOG_PREFIX}] ข้าม pattern ที่ไม่ถูกต้อง: {pattern!r} | {e}")

    if not valid:
        return None

    return re.compile("|".join(f"(?:{p})" for p in valid), re.IGNORECASE)


def reload_signatures(loop: asyncio.AbstractEventLoop, force: bool = False) -> None:
    # โหลด pattern จาก DB/cache มา compile เก็บใน memory
    global _last_signature_reload

    now_ts = time.time()

    if not force and (now_ts - _last_signature_reload) < SIGNATURE_REFRESH_SECONDS:
        return

    for detection_type in ATTACK_PRIORITY:
        try:
            patterns = loop.run_until_complete(get_signatures(detection_type))
            _compiled_signatures[detection_type] = compile_patterns(patterns)
        except Exception as e:
            print(f"[{LOG_PREFIX}] โหลด signature ของ {detection_type} ไม่สำเร็จ: {e}")

    _last_signature_reload = now_ts


# ============================================================
events_by_key: dict[str, deque] = defaultdict(deque)


def clear_web_count(key: str) -> None:
    events_by_key[key].clear()
    print(f"[{LOG_PREFIX}] cleared web attack count for [{key}]")


# ============================================================

def decode_url(value: str) -> str:
    # decode URL-encoding สองชั้น เพื่อดัก payload ที่ encode มา (เช่น %2e%2e%2f, %253c)
    try:
        once = unquote_plus(value)
        twice = unquote_plus(once)
        return f"{once}\n{twice}"
    except Exception:
        return value


def build_haystack(log: dict) -> str:
    # รวมทุกจุดที่ payload อาจซ่อนอยู่ (path ดิบ + path decode + user_agent + raw)
    path = str(log.get("path") or "")
    user_agent = str(log.get("user_agent") or "")
    raw_message = str(log.get("raw_message") or "")

    return "\n".join([
        path,
        decode_url(path),
        user_agent,
        decode_url(user_agent),
        raw_message,
    ])


def detect_attack_types(haystack: str) -> list[tuple[str, str]]:
    # คืน list ของ (detection_type, signature ที่ match) เรียงตามความสำคัญ
    matches: list[tuple[str, str]] = []

    for detection_type in ATTACK_PRIORITY:
        pattern = _compiled_signatures.get(detection_type)
        if pattern is None:
            continue

        found = pattern.search(haystack)
        if found:
            matches.append((detection_type, found.group(0)))

    return matches


# ============================================================

def print_counted_web_log(
    detection_type: str,
    source_ip: str,
    count: int,
    signature: str,
    log: dict,
) -> None:
    print(
        f"WEB [{ATTACK_LABEL.get(detection_type, detection_type)}] "
        f"ip [{source_ip}] count {count} | "
        f"agent={log.get('agent_id')} | "
        f"time={log.get('agent_event_time_thai')} | "
        f"method={log.get('method')} | "
        f"status={log.get('status_code')} | "
        f"sig={signature!r} | "
        f"path={log.get('path')}"
    )


def print_web_alert(
    detection_type: str,
    source_ip: str,
    count: int,
    window_seconds: int,
    threshold: int,
    related_logs: list[dict],
) -> None:
    print("\n" + "=" * 90)
    print(f"[{LOG_PREFIX}] {ATTACK_LABEL.get(detection_type, detection_type).upper()} DETECTED")
    print("-" * 90)
    print(f"source_ip  : {source_ip}")
    print(f"count      : {count}")
    print(f"window     : {window_seconds} seconds")
    print(f"threshold  : {threshold}")
    print("-" * 90)
    print("related requests used for count:")

    for index, event in enumerate(related_logs, start=1):
        print(
            f"[{index}] time={event.get('agent_event_time_thai')} | "
            f"agent={event.get('agent_id')} | "
            f"method={event.get('method')} | "
            f"status={event.get('status_code')} | "
            f"sig={event.get('matched_signature')!r}"
        )
        print(f"    raw_message: {event.get('raw_message')}")

    print("=" * 90 + "\n")


# ============================================================

def process_http_flood(
    log: dict,
    source_ip: str | None,
    now_ts: float,
    loop: asyncio.AbstractEventLoop,
) -> None:
    # App-level DoS: นับจำนวน request "ทั้งหมด" ต่อ source_ip ใน sliding window
    if not source_ip:
        return

    rule = loop.run_until_complete(get_rule(RULE_KEY_BY_TYPE["http_flood"]))

    if not rule["is_active"]:
        return

    window_seconds = rule["window_seconds"]
    threshold = rule["threshold"]

    key = f"http_flood:{source_ip}"

    event = {
        "ts": now_ts,
        "agent_event_time_thai": log.get("agent_event_time_thai"),
        "agent_event_time_utc": log.get("agent_event_time_utc"),
        "central_normalized_at": log.get("central_normalized_at"),
        "agent_id": log.get("agent_id"),
        "source_ip": source_ip,
        "method": log.get("method"),
        "path": log.get("path"),
        "status_code": log.get("status_code"),
        "user_agent": log.get("user_agent"),
        "raw_message": log.get("raw_message"),
    }

    events_by_key[key].append(event)
    prune_old_events(events_by_key[key], now_ts, window_seconds, MAX_EVENTS_PER_KEY)

    window_events = get_events_in_window(events_by_key[key], now_ts, window_seconds)
    count = len(window_events)

    if count >= threshold:
        print_web_alert(
            detection_type="http_flood",
            source_ip=source_ip,
            count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        )
        loop.run_until_complete(save_alert_to_db(
            detection_type="http_flood",
            category="web",
            log_prefix=LOG_PREFIX,
            agent_id=log.get("agent_id"),
            source_ip=source_ip,
            event_count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        ))
        clear_web_count(key)


# ============================================================

def process_web_log(log: dict, loop: asyncio.AbstractEventLoop) -> None:
    if log.get("category") != "web":
        return

    # refresh pattern จาก DB เป็นระยะ (โหลดจริงเฉพาะเมื่อครบ interval)
    reload_signatures(loop)

    source_ip = log.get("source_ip")
    now_ts = parse_agent_time_to_epoch(log)

    # App-level DoS: นับทุก request ต่อ IP — ต้องรันก่อน signature return
    process_http_flood(log, source_ip, now_ts, loop)

    haystack = build_haystack(log)
    matches = detect_attack_types(haystack)

    if not matches:
        return

    # request เดียวอาจ match หลายชนิด เอาตัวแรก (สำคัญสุด) เป็น detection_type หลัก
    detection_type, signature = matches[0]
    all_types = [m[0] for m in matches]

    rule = loop.run_until_complete(get_rule(RULE_KEY_BY_TYPE[detection_type]))

    if not rule["is_active"]:
        return

    window_seconds = rule["window_seconds"]
    threshold = rule["threshold"]

    # web signature นับตาม IP เป็นหลัก
    key = f"{detection_type}:{source_ip or 'unknown'}"

    event = {
        "ts": now_ts,
        "agent_event_time_thai": log.get("agent_event_time_thai"),
        "agent_event_time_utc": log.get("agent_event_time_utc"),
        "central_normalized_at": log.get("central_normalized_at"),
        "agent_id": log.get("agent_id"),
        "source_ip": source_ip,
        "method": log.get("method"),
        "path": log.get("path"),
        "status_code": log.get("status_code"),
        "user_agent": log.get("user_agent"),
        "matched_signature": signature,
        "matched_types": all_types,
        "raw_message": log.get("raw_message"),
    }

    events_by_key[key].append(event)
    prune_old_events(events_by_key[key], now_ts, window_seconds, MAX_EVENTS_PER_KEY)

    window_events = get_events_in_window(events_by_key[key], now_ts, window_seconds)
    count = len(window_events)

    print_counted_web_log(detection_type, source_ip or "unknown", count, signature, log)

    if count >= threshold:
        print_web_alert(
            detection_type=detection_type,
            source_ip=source_ip or "unknown",
            count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        )
        loop.run_until_complete(save_alert_to_db(
            detection_type=detection_type,
            category="web",
            log_prefix=LOG_PREFIX,
            agent_id=log.get("agent_id"),
            source_ip=source_ip,
            event_count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        ))
        clear_web_count(key)


# ============================================================

def prepare_web_detector(loop: asyncio.AbstractEventLoop) -> None:
    # seed rule ลง DB + โหลด signature ครั้งแรกให้พร้อมก่อนรับ log
    seed_rules(loop, RULE_KEY_BY_TYPE.values(), LOG_PREFIX)
    reload_signatures(loop, force=True)
    total = sum(1 for p in _compiled_signatures.values() if p is not None)
    print(f"[{LOG_PREFIX}] โหลด signature พร้อมใช้งาน {total}/{len(ATTACK_PRIORITY)} ชนิด")


def start_web_detector() -> None:
    run_detector_loop(
        queue_name=NORMALIZED_WEB_QUEUE,
        process_log=process_web_log,
        log_prefix=LOG_PREFIX,
        startup_messages=(
            "mode: SIGNATURE + RATE DETECT + SAVE ALERT TO DB + AUTO BLOCK/BLACKLIST",
            "detects: SQL Injection / XSS / Path Traversal / Command Injection / HTTP Flood (App-DoS)",
        ),
        on_start=prepare_web_detector,
    )


if __name__ == "__main__":
    start_web_detector()
