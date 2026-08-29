import redis
import json
import re
import time
import asyncio
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from auth_cache import verify_agent_token
from redis_client import get_redis
from process_log_detect.detector_common import QUEUE_BLOCK_TIMEOUT_SECONDS, safe_json_loads


TZ = ZoneInfo("Asia/Bangkok")


# ============================================================

RAW_LOGS_QUEUE = "raw_logs_queue"

NORMALIZED_AUTH_QUEUE = "normalized_auth_logs_queue"
NORMALIZED_WEB_QUEUE = "normalized_web_logs_queue"
NORMALIZED_FIREWALL_QUEUE = "normalized_firewall_logs_queue"
NORMALIZED_SYSLOG_QUEUE = "normalized_syslog_logs_queue"
NORMALIZED_UNKNOWN_QUEUE = "normalized_unknown_logs_queue"

# คิวที่ไม่มี detector มาประมวลผลต่อ — ไม่ push ทิ้งไปเลย กัน Redis โตเปล่า ๆ
DROPPED_QUEUES = {NORMALIZED_SYSLOG_QUEUE, NORMALIZED_UNKNOWN_QUEUE}


# ============================================================

def now_thai() -> str:
    # เวลาที่ Central normalize log นี้
    return datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")


def parse_filebeat_timestamp(timestamp: str | None) -> tuple[str | None, str | None]:
    # @timestamp จาก Filebeat คือเวลาฝั่ง Agent / เวลาที่ Filebeat อ่าน log
    if not timestamp:
        return None, None

    try:
        dt_utc = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        if dt_utc.tzinfo is None:
            dt_utc = dt_utc.replace(tzinfo=timezone.utc)

        dt_utc = dt_utc.astimezone(timezone.utc)
        dt_thai = dt_utc.astimezone(TZ)

        agent_event_time_utc = dt_utc.strftime("%Y-%m-%d %H:%M:%S")
        agent_event_time_thai = dt_thai.strftime("%Y-%m-%d %H:%M:%S")

        return agent_event_time_utc, agent_event_time_thai

    except Exception:
        return timestamp, None


# ============================================================

def get_message(event: dict) -> str:
    return str(event.get("message", "")).strip()


def get_agent_id(event: dict) -> str | None:
    host = event.get("host", {})
    if not isinstance(host, dict):
        return None
    return host.get("id")


def get_secret_token(event: dict) -> str | None:
    host = event.get("host", {})
    if not isinstance(host, dict):
        return None
    return host.get("SECRET_TOKEN")


def get_host_ip(event: dict) -> str | None:
    # IP ของเครื่อง agent ที่ filebeat แนบมากับทุก event (processor add_fields target: host)
    host = event.get("host", {})
    if not isinstance(host, dict):
        return None

    ip = host.get("ip")
    return ip if isinstance(ip, str) else None


def base_normalized_event(event: dict) -> dict:
    # Field กลางที่ detector ต้องใช้จริง
    agent_event_time_utc, agent_event_time_thai = parse_filebeat_timestamp(
        event.get("@timestamp")
    )

    return {
        "agent_event_time_thai": agent_event_time_thai,
        "agent_event_time_utc": agent_event_time_utc,
        "central_normalized_at": now_thai(),

        "agent_id": get_agent_id(event),
        "log_type": event.get("log_type"),
        "service_name": event.get("service_name"),

        "raw_message": get_message(event),
    }


def clean_dash(value: str | None) -> str | None:
    if value is None:
        return None

    value = value.strip()
    if value == "-" or value == "":
        return None

    return value


def to_int(value: str | None) -> int | None:
    if value is None or value == "":
        return None

    try:
        return int(value)
    except Exception:
        return None


# ============================================================

SSH_FAILED_RE = re.compile(
    r"Failed password for (?:(?P<invalid_prefix>invalid user) )?"
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\d+\.\d+\.\d+\.\d+) port "
    r"(?P<source_port>\d+)"
)

SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<auth_method>\S+) for "
    r"(?P<username>\S+) from "
    r"(?P<source_ip>\d+\.\d+\.\d+\.\d+) port "
    r"(?P<source_port>\d+)"
)

INVALID_USER_RE = re.compile(
    r"Invalid user (?P<username>\S+) from "
    r"(?P<source_ip>\d+\.\d+\.\d+\.\d+)"
)

SUDO_AUTH_FAILURE_RE = re.compile(
    r"sudo:.*authentication failure.*(?:ruser=|user=)(?P<username>\S+)"
)

SUDO_INCORRECT_PASSWORD_RE = re.compile(
    r"sudo:\s+(?P<username>\S+)\s+:\s+"
    r"(?P<attempts>\d+) incorrect password attempts"
)


def normalize_auth(event: dict) -> dict | None:
    message = get_message(event)
    normalized = base_normalized_event(event)

    normalized.update({
        "category": "auth",

        "source_ip": None,
        "source_port": None,
        "username": None,
        "auth_method": None,
        "auth_result": None,
        "is_invalid_user": False,
        "attempts": None,
    })

    match = SSH_FAILED_RE.search(message)
    if match:
        normalized.update({
            "source_ip": match.group("source_ip"),
            "source_port": int(match.group("source_port")),
            "username": match.group("username"),
            "auth_method": "password",
            "auth_result": "failed",
            "is_invalid_user": bool(match.group("invalid_prefix")),
        })
        return normalized

    match = SSH_ACCEPTED_RE.search(message)
    if match:
        normalized.update({
            "source_ip": match.group("source_ip"),
            "source_port": int(match.group("source_port")),
            "username": match.group("username"),
            "auth_method": match.group("auth_method"),
            "auth_result": "success",
            "is_invalid_user": False,
        })
        return normalized

    match = INVALID_USER_RE.search(message)
    if match:
        # ไม่ส่ง Invalid user แยกเข้า Redis
        return None

    match = SUDO_AUTH_FAILURE_RE.search(message)
    if match:
        normalized.update({
            "username": match.group("username"),
            "auth_method": "sudo",
            "auth_result": "failed",
        })
        return normalized

    match = SUDO_INCORRECT_PASSWORD_RE.search(message)
    if match:
        normalized.update({
            "username": match.group("username"),
            "auth_method": "sudo",
            "auth_result": "failed",
            "attempts": int(match.group("attempts")),
        })
        return normalized

    # log auth ที่ไม่เกี่ยวกับ detect scope เช่น session opened/closed, cron, systemd
    return None


# ============================================================

WEB_ACCESS_RE = re.compile(
    r'(?P<source_ip>\d+\.\d+\.\d+\.\d+)\s+'
    r'(?P<remote_ident>\S+)\s+'
    r'(?P<remote_user>\S+)\s+'
    r'\[(?P<access_time>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+'
    r'(?P<path>\S+)'
    r'(?:\s+HTTP/(?P<http_version>[^"]+))?"\s+'
    r'(?P<status_code>\d{3})\s+'
    r'(?P<body_bytes>\S+)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
)


def status_group(status_code: int | None) -> str | None:
    if status_code is None:
        return None
    return f"{status_code // 100}xx"


def normalize_web(event: dict) -> dict:
    message = get_message(event)
    normalized = base_normalized_event(event)

    normalized.update({
        "category": "web",

        "source_ip": None,
        "method": None,
        "path": None,
        "status_code": None,
        "status_group": None,
        "body_bytes": None,
        "user_agent": None,
    })

    match = WEB_ACCESS_RE.search(message)
    if not match:
        return normalized

    code = int(match.group("status_code"))

    normalized.update({
        "source_ip": match.group("source_ip"),
        "method": match.group("method"),
        "path": match.group("path"),
        "status_code": code,
        "status_group": status_group(code),
        "body_bytes": to_int(match.group("body_bytes")),
        "user_agent": clean_dash(match.group("user_agent")),
    })

    return normalized


# ============================================================

UFW_ACTION_RE = re.compile(r"\[UFW (?P<action>\w+)\]")

IPTABLES_PREFIX_RE = re.compile(
    r"(?P<prefix>\b(?:IPTABLES|IP_TABLES|IPTABLE|SCAN|SSH|WEB|FIREWALL|FW|DROP|BLOCK|DENY|REJECT|ALLOW|ACCEPT)[A-Z0-9_-]*:)"
)

FIREWALL_KEY_VALUE_RE = re.compile(r"\b(?P<key>[A-Z0-9_]+)=(?P<value>\S*)")


def extract_firewall_fields(message: str) -> dict:
    fields: dict[str, str] = {}
    for match in FIREWALL_KEY_VALUE_RE.finditer(message):
        fields[match.group("key")] = match.group("value")
    return fields


def normalize_firewall_action(
    *,
    ufw_action: str | None = None,
    rule_prefix: str | None = None,
    raw_message: str = "",
) -> str | None:
    text = " ".join(x for x in [ufw_action, rule_prefix, raw_message] if x).upper()

    if "REJECT" in text:
        return "reject"
    if "BLOCK" in text or "DROP" in text or "DENY" in text:
        return "block"
    if "ALLOW" in text or "ACCEPT" in text:
        return "allow"

    return ufw_action.lower() if ufw_action else None


def normalize_firewall_common(
    event: dict,
    *,
    firewall_source: str,
    rule_prefix: str | None = None,
    ufw_action: str | None = None,
) -> dict:
    message = get_message(event)
    fields = extract_firewall_fields(message)
    action = normalize_firewall_action(
        ufw_action=ufw_action,
        rule_prefix=rule_prefix,
        raw_message=message,
    )

    normalized = base_normalized_event(event)

    normalized.update({
        "category": "firewall",

        "firewall_source": firewall_source,
        "firewall_action": action,

        "source_ip": fields.get("SRC") or None,
        "destination_ip": fields.get("DST") or None,
        "protocol": fields.get("PROTO") or None,
        "source_port": to_int(fields.get("SPT")),
        "destination_port": to_int(fields.get("DPT")),
    })

    return normalized


def normalize_ufw(event: dict) -> dict:
    message = get_message(event)
    action_match = UFW_ACTION_RE.search(message)
    ufw_action = action_match.group("action").lower() if action_match else None

    return normalize_firewall_common(
        event,
        firewall_source="ufw",
        rule_prefix=action_match.group(0) if action_match else None,
        ufw_action=ufw_action,
    )


def normalize_iptables(event: dict) -> dict:
    message = get_message(event)
    prefix_match = IPTABLES_PREFIX_RE.search(message)
    prefix = prefix_match.group("prefix") if prefix_match else None

    return normalize_firewall_common(
        event,
        firewall_source="iptables",
        rule_prefix=prefix,
    )


# ============================================================

SYSLOG_RE = re.compile(
    r"^(?P<syslog_time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<syslog_hostname>\S+)\s+"
    r"(?P<process>[A-Za-z0-9_\-\/\.]+)"
    r"(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<syslog_message>.*)$"
)


def normalize_syslog(event: dict) -> dict:
    message = get_message(event)
    normalized = base_normalized_event(event)

    normalized.update({
        "category": "system",

        "process": None,
        "pid": None,
        "syslog_message": message,
    })

    match = SYSLOG_RE.search(message)
    if match:
        normalized.update({
            "process": match.group("process"),
            "pid": to_int(match.group("pid")),
            "syslog_message": match.group("syslog_message"),
        })

    return normalized


# ============================================================

def normalize_unknown(event: dict) -> dict:
    normalized = base_normalized_event(event)
    normalized.update({
        "category": "unknown",
    })
    return normalized


# ============================================================

def is_ufw_log(log_type: str | None, message: str) -> bool:
    if log_type in ["ufw", "ufw_log", "ufwlog"]:
        return True
    if "[UFW " in message:
        return True
    return False


def is_iptables_log(log_type: str | None, message: str) -> bool:
    if log_type in [
        "iptables",
        "iptables_log",
        "iptableslog",
        "iptable",
        "iptable_log",
        "iptablelog",
    ]:
        return True

    if IPTABLES_PREFIX_RE.search(message):
        return True

    has_firewall_fields = (
        "SRC=" in message
        and "DST=" in message
        and "PROTO=" in message
        and ("DPT=" in message or "SPT=" in message)
    )

    if has_firewall_fields and "[UFW " not in message:
        return True

    return False


def is_syslog(log_type: str | None, message: str) -> bool:
    if log_type in ["syslog", "system", "system_log", "kern", "kernel"]:
        return True
    if SYSLOG_RE.search(message):
        return True
    return False


def is_auth_pattern(message: str) -> bool:
    # ใช้ดักกรณี auth failure / ssh brute force หลุดมาปนกับ syslog
    return bool(
        SSH_FAILED_RE.search(message)
        or SSH_ACCEPTED_RE.search(message)
        or SUDO_AUTH_FAILURE_RE.search(message)
        or SUDO_INCORRECT_PASSWORD_RE.search(message)
    )


# ============================================================

def normalize_event(event: dict) -> tuple[str | None, dict | None]:
    log_type = event.get("log_type")
    message = get_message(event)

    if log_type == "auth":
        normalized = normalize_auth(event)
        if normalized is None:
            return None, None
        return NORMALIZED_AUTH_QUEUE, normalized

    if log_type in [
        "nginx_access",
        "apache_access",
        "tomcat_access",
    ]:
        return NORMALIZED_WEB_QUEUE, normalize_web(event)

    if is_ufw_log(log_type, message):
        return NORMALIZED_FIREWALL_QUEUE, normalize_ufw(event)

    if is_iptables_log(log_type, message):
        return NORMALIZED_FIREWALL_QUEUE, normalize_iptables(event)

    if is_syslog(log_type, message):
        if is_auth_pattern(message):
            normalized = normalize_auth(event)
            if normalized is None:
                return None, None
            return NORMALIZED_AUTH_QUEUE, normalized
        return NORMALIZED_SYSLOG_QUEUE, normalize_syslog(event)

    return NORMALIZED_UNKNOWN_QUEUE, normalize_unknown(event)


# ============================================================

def push_normalized_log(
    r: redis.Redis,
    queue_name: str,
    normalized: dict,
) -> None:
    if queue_name in DROPPED_QUEUES:
        return

    r.rpush(
        queue_name,
        json.dumps(normalized, ensure_ascii=False)
    )


# ============================================================

def start_normalizer() -> None:
    r = get_redis()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    print("[NORMALIZE] started")
    print(f"[NORMALIZE] input queue: {RAW_LOGS_QUEUE}")

    while True:
        try:
            item = r.blpop(RAW_LOGS_QUEUE, timeout=QUEUE_BLOCK_TIMEOUT_SECONDS)

            if not item:
                continue

            _, raw = item
            event = safe_json_loads(raw, "NORMALIZE")

            if not event:
                continue

            agent_id = get_agent_id(event)
            secret_token = get_secret_token(event)
            host_ip = get_host_ip(event)

            is_valid = loop.run_until_complete(
                verify_agent_token(agent_id, secret_token, host_ip)
            )

            if not is_valid:
                print(f"[NORMALIZE] ปฏิเสธ raw log จาก Agent ที่ auth ไม่ผ่าน: {agent_id}")
                continue

            queue_name, normalized = normalize_event(event)

            if not queue_name or not normalized:
                continue

            push_normalized_log(r, queue_name, normalized)

            print(
                f"[NORMALIZE] "
                f"agent={normalized.get('agent_id')} | "
                f"agent_time={normalized.get('agent_event_time_thai')} | "
                f"log_type={normalized.get('log_type')} | "
                f"category={normalized.get('category')} | "
                f"queue={queue_name}"
            )

        except KeyboardInterrupt:
            print("\n[NORMALIZE] stopped")
            break

        except redis.exceptions.ConnectionError as e:
            print(f"[NORMALIZE] Redis connection error: {e}")
            time.sleep(3)

        except Exception as e:
            print(f"[NORMALIZE] error: {e}")
            time.sleep(1)

    try:
        loop.close()
    except Exception:
        pass


if __name__ == "__main__":
    start_normalizer()
