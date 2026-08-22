"""
Detector: SSH brute force + Sudo failed จาก normalized auth log
- SSH Failed password -> นับ brute force ตาม source_ip
- Sudo failed         -> นับ failed sudo ตาม agent_id + username (sudo ไม่มี IP)

window/threshold ไม่ hardcode — ดึงจาก DB ผ่าน rule_cache (rule_key:
ssh_brute_force / sudo_failed) แก้ผ่าน manage_rules.py

รันด้วย: python -m process_log_detect.auth_log_detect
"""

import json
import asyncio
from collections import defaultdict, deque

from rule_cache import get_rule
from process_log_detect.detector_common import (
    parse_agent_time_to_epoch,
    prune_old_events,
    get_events_in_window,
    save_alert_to_db,
    run_detector_loop,
)


NORMALIZED_AUTH_QUEUE = "normalized_auth_logs_queue"

LOG_PREFIX = "AUTH-DETECT"

# เก็บ history สูงสุดต่อ key เพื่อไม่ให้ memory โตไม่จำกัด
MAX_EVENTS_PER_KEY = 200


# ============================================================
# Runtime memory
# ============================================================

# SSH failed by source IP
failed_attempts_by_ip: dict[str, deque] = defaultdict(deque)

# Sudo failed by agent_id + username
sudo_failed_by_user: dict[str, deque] = defaultdict(deque)


# ============================================================
# SSH failed password helper
# ============================================================

def is_failed_password_log(log: dict) -> bool:
    """
    นับเฉพาะ SSH Failed password เท่านั้น

    เหตุผล:
    - ไม่เอา Invalid user แยกมานับ เพราะ normalizer ควรตัดออกแล้ว
    - ไม่เอา sudo failed / auth failed แบบอื่นมานับรวมกับ SSH brute force
    - ใช้ field ที่ normalize แล้วเป็นหลัก และใช้ raw_message เป็นตัว confirm
    """
    raw_message = str(log.get("raw_message", ""))

    if log.get("category") != "auth":
        return False

    if log.get("auth_result") != "failed":
        return False

    # จาก normalizer: Failed password -> auth_method = password
    if log.get("auth_method") != "password":
        return False

    # confirm อีกชั้นจาก raw_message เพื่อกัน log failed แบบอื่นที่ field คล้ายกัน
    if "Failed password" not in raw_message:
        return False

    return True


def get_source_ip(log: dict) -> str | None:
    source_ip = log.get("source_ip")

    if source_ip:
        return str(source_ip)

    # ปกติ normalize ควรมี source_ip แล้ว
    # fallback นี้กันกรณี raw message มาแต่ field source_ip หาย
    raw_message = str(log.get("raw_message", ""))
    marker = " from "

    if marker not in raw_message:
        return None

    try:
        after_from = raw_message.split(marker, 1)[1]
        return after_from.split()[0]
    except Exception:
        return None


# ============================================================
# Sudo helper
# ============================================================

def is_sudo_failed_log(log: dict) -> bool:
    """
    ตรวจ sudo failed แยกจาก SSH brute force

    ตัวอย่างที่นับ:
    - sudo: pam_unix(sudo:auth): authentication failure ...
    - sudo: jj : 3 incorrect password attempts ...

    ตัวอย่างที่ไม่นับ:
    - sudo command สำเร็จ เช่น COMMAND=/bin/bash
    - SSH Failed password
    """
    if log.get("category") != "auth":
        return False

    if log.get("auth_method") != "sudo":
        return False

    if log.get("auth_result") != "failed":
        return False

    return True


def get_sudo_key(log: dict) -> str | None:
    agent_id = log.get("agent_id") or "unknown_agent"
    username = log.get("username")

    if not username:
        return None

    return f"{agent_id}:{username}"


def get_sudo_attempts(log: dict) -> int:
    """
    ถ้า normalizer เจอ "3 incorrect password attempts" จะมี attempts=3
    ถ้าไม่มี ให้ถือว่าเป็น 1 event
    """
    try:
        attempts = int(log.get("attempts") or 1)
    except Exception:
        attempts = 1

    if attempts < 1:
        attempts = 1

    return attempts


def clear_ssh_count(ip: str) -> None:
    failed_attempts_by_ip[ip].clear()
    print(f"[{LOG_PREFIX}] cleared SSH brute force count for IP [{ip}]")


def clear_sudo_count(key: str) -> None:
    sudo_failed_by_user[key].clear()
    print(f"[{LOG_PREFIX}] cleared sudo failed count for [{key}]")


# ============================================================
# Print helper
# ============================================================

def print_counted_ssh_log(ip: str, count: int, log: dict) -> None:
    """
    แสดงทุก SSH Failed password ที่เอามานับ
    format หลัก: IP [x.x.x.x] bruteforce count 1
    """
    print(
        f"IP [{ip}] bruteforce count {count} | "
        f"agent={log.get('agent_id')} | "
        f"time={log.get('agent_event_time_thai')} | "
        f"user={log.get('username')} | "
        f"invalid_user={log.get('is_invalid_user')} | "
        f"port={log.get('source_port')}"
    )


def print_counted_sudo_log(key: str, count: int, added: int, log: dict) -> None:
    print(
        f"SUDO [{key}] failed count {count} | "
        f"added={added} | "
        f"agent={log.get('agent_id')} | "
        f"time={log.get('agent_event_time_thai')} | "
        f"user={log.get('username')}"
    )


def print_ssh_bruteforce_alert(
    ip: str,
    count: int,
    window_seconds: int,
    threshold: int,
    related_logs: list[dict],
) -> None:
    print("\n" + "=" * 90)
    print(f"[{LOG_PREFIX}] SSH BRUTE FORCE DETECTED")
    print("-" * 90)
    print(f"IP [{ip}] bruteforce count {count}")
    print(f"window     : {window_seconds} seconds")
    print(f"threshold  : {threshold}")
    print("-" * 90)
    print("related logs used for count:")

    for index, event in enumerate(related_logs, start=1):
        print(
            f"[{index}] time={event.get('agent_event_time_thai')} | "
            f"agent={event.get('agent_id')} | "
            f"user={event.get('username')} | "
            f"invalid_user={event.get('is_invalid_user')} | "
            f"port={event.get('source_port')}"
        )
        print(f"    raw_message: {event.get('raw_message')}")

    print("=" * 90 + "\n")


def print_sudo_alert(
    key: str,
    count: int,
    window_seconds: int,
    threshold: int,
    related_logs: list[dict],
) -> None:
    print("\n" + "=" * 90)
    print(f"[{LOG_PREFIX}] SUDO FAILED ATTEMPTS DETECTED")
    print("-" * 90)
    print(f"target     : {key}")
    print(f"count      : {count}")
    print(f"window     : {window_seconds} seconds")
    print(f"threshold  : {threshold}")
    print("-" * 90)
    print("related sudo logs used for count:")

    for index, event in enumerate(related_logs, start=1):
        print(
            f"[{index}] time={event.get('agent_event_time_thai')} | "
            f"agent={event.get('agent_id')} | "
            f"user={event.get('username')} | "
            f"attempt_no={event.get('attempt_no')}"
        )
        print(f"    raw_message: {event.get('raw_message')}")

    print("=" * 90 + "\n")


# ============================================================
# Detection logic: SSH
# ============================================================

def process_ssh_failed_password(log: dict, loop: asyncio.AbstractEventLoop) -> None:
    # เอาเฉพาะ SSH Failed password เท่านั้น
    # sudo failed / invalid user เดี่ยว ๆ / session opened จะไม่ถูกนับ
    if not is_failed_password_log(log):
        return

    ip = get_source_ip(log)
    if not ip:
        print(f"[{LOG_PREFIX}] failed password log found but source_ip missing")
        print(json.dumps(log, ensure_ascii=False, indent=2))
        return

    now_ts = parse_agent_time_to_epoch(log)

    ssh_rule = loop.run_until_complete(get_rule("ssh_brute_force"))
    ssh_window = ssh_rule["window_seconds"]
    ssh_threshold = ssh_rule["threshold"]

    event = {
        "ts": now_ts,
        "agent_event_time_thai": log.get("agent_event_time_thai"),
        "agent_event_time_utc": log.get("agent_event_time_utc"),
        "central_normalized_at": log.get("central_normalized_at"),
        "agent_id": log.get("agent_id"),
        "username": log.get("username"),
        "is_invalid_user": log.get("is_invalid_user"),
        "source_port": log.get("source_port"),
        "raw_message": log.get("raw_message"),
    }

    failed_attempts_by_ip[ip].append(event)
    prune_old_events(failed_attempts_by_ip[ip], now_ts, ssh_window, MAX_EVENTS_PER_KEY)

    # แสดง log ที่นำมานับทุกครั้ง
    total_count = len(failed_attempts_by_ip[ip])
    print_counted_ssh_log(ip, total_count, log)

    ssh_events = get_events_in_window(failed_attempts_by_ip[ip], now_ts, ssh_window)
    ssh_count = len(ssh_events)

    # ครบ threshold แล้วยิง alert + clear count ทันที (กันยิงซ้ำทุก log ที่ตามมา)
    if ssh_rule["is_active"] and ssh_count >= ssh_threshold:
        print_ssh_bruteforce_alert(
            ip=ip,
            count=ssh_count,
            window_seconds=ssh_window,
            threshold=ssh_threshold,
            related_logs=ssh_events,
        )
        loop.run_until_complete(save_alert_to_db(
            detection_type="ssh_brute_force",
            category="auth",
            log_prefix=LOG_PREFIX,
            agent_id=log.get("agent_id"),
            source_ip=ip,
            username=log.get("username"),
            event_count=ssh_count,
            window_seconds=ssh_window,
            threshold=ssh_threshold,
            related_logs=ssh_events,
        ))
        clear_ssh_count(ip)


# ============================================================
# Detection logic: Sudo
# ============================================================

def process_sudo_failed(log: dict, loop: asyncio.AbstractEventLoop) -> None:
    if not is_sudo_failed_log(log):
        return

    key = get_sudo_key(log)
    if not key:
        print(f"[{LOG_PREFIX}] sudo failed log found but username missing")
        print(json.dumps(log, ensure_ascii=False, indent=2))
        return

    now_ts = parse_agent_time_to_epoch(log)
    attempts = get_sudo_attempts(log)

    sudo_rule = loop.run_until_complete(get_rule("sudo_failed"))
    sudo_window = sudo_rule["window_seconds"]
    sudo_threshold = sudo_rule["threshold"]

    # ถ้า log บอกว่า 3 incorrect password attempts
    # ให้แตกเป็น 3 event เพื่อให้ count ตรงกับจำนวน attempt จริง
    for attempt_no in range(1, attempts + 1):
        event = {
            "ts": now_ts,
            "agent_event_time_thai": log.get("agent_event_time_thai"),
            "agent_event_time_utc": log.get("agent_event_time_utc"),
            "central_normalized_at": log.get("central_normalized_at"),
            "agent_id": log.get("agent_id"),
            "username": log.get("username"),
            "attempt_no": attempt_no,
            "raw_message": log.get("raw_message"),
        }
        sudo_failed_by_user[key].append(event)

    prune_old_events(sudo_failed_by_user[key], now_ts, sudo_window, MAX_EVENTS_PER_KEY)

    total_count = len(sudo_failed_by_user[key])
    print_counted_sudo_log(key, total_count, attempts, log)

    sudo_events = get_events_in_window(sudo_failed_by_user[key], now_ts, sudo_window)
    sudo_count = len(sudo_events)

    if sudo_rule["is_active"] and sudo_count >= sudo_threshold:
        print_sudo_alert(
            key=key,
            count=sudo_count,
            window_seconds=sudo_window,
            threshold=sudo_threshold,
            related_logs=sudo_events,
        )
        loop.run_until_complete(save_alert_to_db(
            detection_type="sudo_failed",
            category="auth",
            log_prefix=LOG_PREFIX,
            agent_id=log.get("agent_id"),
            username=log.get("username"),
            event_count=sudo_count,
            window_seconds=sudo_window,
            threshold=sudo_threshold,
            related_logs=sudo_events,
        ))
        clear_sudo_count(key)


def process_auth_log(log: dict, loop: asyncio.AbstractEventLoop) -> None:
    """
    Main auth router

    แยก rule ชัดเจน:
    - SSH Failed password -> นับ brute force ตาม source_ip
    - Sudo failed         -> นับ failed sudo ตาม agent_id + username
    """
    process_ssh_failed_password(log, loop)
    process_sudo_failed(log, loop)


# ============================================================
# Main worker
# ============================================================

def start_auth_detector() -> None:
    run_detector_loop(
        queue_name=NORMALIZED_AUTH_QUEUE,
        process_log=process_auth_log,
        log_prefix=LOG_PREFIX,
        startup_messages=(
            "mode: PRINT + SAVE ALERT TO DB + AUTO BLOCK/BLACKLIST",
            "counted logs: SSH Failed password + Sudo failed",
        ),
    )


if __name__ == "__main__":
    start_auth_detector()
