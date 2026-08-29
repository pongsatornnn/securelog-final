# Detector: Firewall behavior/rate-based จาก normalized firewall log (UFW/iptables)

import asyncio
import ipaddress
from collections import defaultdict, deque

from rule_cache import get_rule
from process_log_detect.security_response import is_non_blockable_ip
from process_log_detect.detector_common import (
    parse_agent_time_to_epoch,
    prune_old_events,
    get_events_in_window,
    save_alert_to_db,
    seed_rules,
    run_detector_loop,
)


NORMALIZED_FIREWALL_QUEUE = "normalized_firewall_logs_queue"

LOG_PREFIX = "FW-DETECT"

# นับเฉพาะ log ที่ firewall ปฏิเสธจริง ๆ (allow/accept ไม่ใช่การโจมตี ข้ามไป)
DENY_ACTIONS = {"block", "reject"}

# detection_type -> rule_key ใน detection_rules
RULE_KEY_BY_TYPE = {
    "port_scan": "firewall_port_scan",
    "firewall_deny_rate": "firewall_deny_rate",
}

# ลำดับ = ความสำคัญ (รุนแรงกว่าอยู่ก่อน) — ใช้ตอน log เดียวเข้าเงื่อนไขทั้งสองชนิด
DETECTION_TYPES = [
    "firewall_deny_rate",
    "port_scan",
]

# เก็บ history สูงสุดต่อ key เพื่อไม่ให้ memory โตไม่จำกัด
MAX_EVENTS_PER_KEY = 500

ATTACK_LABEL = {
    "port_scan": "Port Scan",
    "firewall_deny_rate": "Firewall Deny Flood",
}


# ============================================================
events_by_key: dict[str, deque] = defaultdict(deque)


def clear_fw_count(key: str) -> None:
    events_by_key[key].clear()
    print(f"[{LOG_PREFIX}] cleared firewall count for [{key}]")


# ============================================================

def is_ipv4(ip: str | None) -> bool:
    # True เฉพาะเมื่อ ip เป็น IPv4 ที่ถูกต้อง — ใช้กรอง IPv6/SRC ผิดรูปตามนโยบาย IPv4-only
    if not ip:
        return False
    try:
        return isinstance(ipaddress.ip_address(str(ip).strip()), ipaddress.IPv4Address)
    except ValueError:
        return False


def count_for_type(detection_type: str, window_events: list[dict]) -> int:
    # แปลง event ในหน้าต่างเวลาเป็น "count" ตามความหมายของแต่ละ detection_type
    if detection_type == "port_scan":
        return len({
            e["destination_port"]
            for e in window_events
            if e.get("destination_port") is not None
        })
    return len(window_events)


def build_event(log: dict, now_ts: float) -> dict:
    return {
        "ts": now_ts,
        "agent_event_time_thai": log.get("agent_event_time_thai"),
        "agent_event_time_utc": log.get("agent_event_time_utc"),
        "central_normalized_at": log.get("central_normalized_at"),
        "agent_id": log.get("agent_id"),
        "source_ip": log.get("source_ip"),
        "destination_ip": log.get("destination_ip"),
        "protocol": log.get("protocol"),
        "source_port": log.get("source_port"),
        "destination_port": log.get("destination_port"),
        "firewall_source": log.get("firewall_source"),
        "firewall_action": log.get("firewall_action"),
        "raw_message": log.get("raw_message"),
    }


# ============================================================

def print_counted_fw_log(
    detection_type: str,
    source_ip: str,
    count: int,
    log: dict,
) -> None:
    print(
        f"FW [{ATTACK_LABEL.get(detection_type, detection_type)}] "
        f"ip [{source_ip}] count {count} | "
        f"agent={log.get('agent_id')} | "
        f"time={log.get('agent_event_time_thai')} | "
        f"src_fw={log.get('firewall_source')} | "
        f"action={log.get('firewall_action')} | "
        f"proto={log.get('protocol')} | "
        f"dpt={log.get('destination_port')}"
    )


def print_fw_alert(
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
    print("related firewall events used for count:")

    for index, event in enumerate(related_logs, start=1):
        print(
            f"[{index}] time={event.get('agent_event_time_thai')} | "
            f"agent={event.get('agent_id')} | "
            f"action={event.get('firewall_action')} | "
            f"proto={event.get('protocol')} | "
            f"dpt={event.get('destination_port')}"
        )
        print(f"    raw_message: {event.get('raw_message')}")

    print("=" * 90 + "\n")


# ============================================================

def process_firewall_log(log: dict, loop: asyncio.AbstractEventLoop) -> None:
    if log.get("category") != "firewall":
        return

    # นับเฉพาะ log ที่ firewall ปฏิเสธ (block/reject) — allow/accept ไม่ใช่การโจมตี
    if log.get("firewall_action") not in DENY_ACTIONS:
        return

    source_ip = log.get("source_ip")
    if not source_ip:
        # firewall deny ที่ parse SRC ไม่ได้ ก็ระบุตัวผู้โจมตีไม่ได้ ข้ามไป
        return

    if not is_ipv4(source_ip):
        # นโยบาย IPv4-only: ข้าม IPv6 (และ SRC ผิดรูป) ไม่ตรวจ/ไม่ alert/ไม่ block
        return

    if is_non_blockable_ip(source_ip):
        # ทราฟฟิก broadcast ปกติของวง (DHCP DISCOVER ออกจาก SRC=0.0.0.0 ฯลฯ) ที่ firewall
        return

    now_ts = parse_agent_time_to_epoch(log)
    event = build_event(log, now_ts)

    # log deny เดียวอาจเข้าเงื่อนไขได้ทั้ง 2 ชนิด (deny-rate + port-scan)
    for detection_type in DETECTION_TYPES:
        rule = loop.run_until_complete(get_rule(RULE_KEY_BY_TYPE[detection_type]))

        if not rule["is_active"]:
            continue

        window_seconds = rule["window_seconds"]
        threshold = rule["threshold"]

        key = f"{detection_type}:{source_ip}"

        events_by_key[key].append(event)
        prune_old_events(events_by_key[key], now_ts, window_seconds, MAX_EVENTS_PER_KEY)

        window_events = get_events_in_window(events_by_key[key], now_ts, window_seconds)
        count = count_for_type(detection_type, window_events)

        print_counted_fw_log(detection_type, source_ip, count, log)

        if count >= threshold:
            print_fw_alert(
                detection_type=detection_type,
                source_ip=source_ip,
                count=count,
                window_seconds=window_seconds,
                threshold=threshold,
                related_logs=window_events,
            )
            loop.run_until_complete(save_alert_to_db(
                detection_type=detection_type,
                category="firewall",
                log_prefix=LOG_PREFIX,
                agent_id=log.get("agent_id"),
                source_ip=source_ip,
                event_count=count,
                window_seconds=window_seconds,
                threshold=threshold,
                related_logs=window_events,
            ))
            clear_fw_count(key)


# ============================================================

def start_firewall_detector() -> None:
    run_detector_loop(
        queue_name=NORMALIZED_FIREWALL_QUEUE,
        process_log=process_firewall_log,
        log_prefix=LOG_PREFIX,
        startup_messages=(
            "mode: RATE/BEHAVIOR DETECT + SAVE ALERT TO DB + AUTO BLOCK/BLACKLIST",
            "detects: Port Scan / Firewall Deny Flood",
        ),
        on_start=lambda loop: seed_rules(loop, RULE_KEY_BY_TYPE.values(), LOG_PREFIX),
    )


if __name__ == "__main__":
    start_firewall_detector()
