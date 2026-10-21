

from geoip import lookup_country
from geoip_holder import lookup_holder_country
from shared import iso_utc
from severity_cache import get_severity

SECURITY_ALERTS_STREAM_CHANNEL = "security_alerts_stream"


ATTACK_TYPE_LABELS = {

    ("ssh_brute_force", None): "SSH Brute Force",
    ("sudo_failed", None): "Sudo Authentication Failure",

    ("sql_injection", None): "SQL Injection",
    ("xss", None): "Cross-Site Scripting (XSS)",
    ("path_traversal", None): "Path Traversal",
    ("command_injection", None): "Command Injection",

    ("http_flood", None): "HTTP Flood (App-level DoS)",

    ("firewall_deny_rate", None): "Firewall Deny Flood",
    ("port_scan", None): "Port Scan",
}


def get_attack_type_label(detection_type: str, mode: str | None) -> str:
    return (
        ATTACK_TYPE_LABELS.get((detection_type, mode))
        or ATTACK_TYPE_LABELS.get((detection_type, None))
        or detection_type
    )


def attacker_country(ip: str | None) -> dict | None:


    country = lookup_country(ip)
    if country is not None:
        return country

    holder = lookup_holder_country(ip)
    if holder is None or holder["region"]:
        return None
    return {
        "code": holder["code"],
        "name": f"{holder['name']} (ประเทศผู้ถือ IP)",
        "private": False,
        "from_holder": True,
    }


async def build_alert_summary(alert, agent=None) -> dict:

    updated_at = alert.updated_at or alert.created_at

    return {
        "id": alert.id,
        "timestamp": iso_utc(updated_at),
        "first_seen": iso_utc(alert.created_at),
        "hostname": (agent.hostname if agent and agent.hostname else alert.agent_id) or "-",
        "host_ip": agent.ip_address if agent else None,

        "agent_id": alert.agent_id,
        "detection_type": alert.detection_type,
        "attack_type": get_attack_type_label(alert.detection_type, alert.mode),
        "source_ip": alert.source_ip,

        "source_country": attacker_country(alert.source_ip),
        "username": alert.username,
        "fail_count": alert.event_count,
        "severity": await get_severity(alert.detection_type, alert.mode),
    }


async def build_alert_detail(alert, agent=None) -> dict:

    detail = await build_alert_summary(alert, agent)

    related_logs = [
        (index, item) for index, item in enumerate(alert.related_logs or [])
        if isinstance(item, dict) and item.get("raw_message")
    ]
    # ts คือเวลาเหตุการณ์ที่ detector บันทึกไว้; ถ้าเวลาเท่ากันให้รายการที่มาทีหลังขึ้นก่อน
    # log เก่าที่ไม่มี ts อยู่ท้ายรายการ
    related_logs.sort(
        key=lambda pair: (
            pair[1]["ts"] if isinstance(pair[1].get("ts"), (int, float)) else float("-inf"),
            pair[0],
        ),
        reverse=True,
    )
    raw_logs = [item["raw_message"] for _, item in related_logs]

    detail.update({
        "window_sec": alert.window_seconds,
        "raw_logs": raw_logs,

        "ai_summary": alert.ai_summary,
        "ai_summary_at": iso_utc(alert.ai_summary_at),

        "source_holder_country": lookup_holder_country(alert.source_ip),
    })

    return detail
