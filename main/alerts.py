"""ตัวกลางแปลง SecurityAlert (DB model) ให้เป็น dict ที่ dashboard.html ใช้แสดงผล"""

from shared import iso_utc
from severity_cache import get_severity

SECURITY_ALERTS_STREAM_CHANNEL = "security_alerts_stream"


ATTACK_TYPE_LABELS = {
    # alert เก่าที่มี mode fast/slow ติดมาจากตอนแยก 2 rule จะ fallback มาที่ป้ายนี้เอง
    ("ssh_brute_force", None): "SSH Brute Force",
    ("sudo_failed", None): "Sudo Authentication Failure",
    # Web signature-based
    ("sql_injection", None): "SQL Injection",
    ("xss", None): "Cross-Site Scripting (XSS)",
    ("path_traversal", None): "Path Traversal",
    ("command_injection", None): "Command Injection",
    # App-level DoS
    ("http_flood", None): "HTTP Flood (App-level DoS)",
    # Firewall behavior/rate-based
    ("firewall_deny_rate", None): "Firewall Deny Flood",
    ("port_scan", None): "Port Scan",
}


def get_attack_type_label(detection_type: str, mode: str | None) -> str:
    return (
        ATTACK_TYPE_LABELS.get((detection_type, mode))
        or ATTACK_TYPE_LABELS.get((detection_type, None))
        or detection_type
    )


async def build_alert_summary(alert, agent=None) -> dict:
    """ใช้กับตารางหลัก (/api/alerts) และ SSE stream (/api/stream/alerts)"""
    updated_at = alert.updated_at or alert.created_at

    return {
        "id": alert.id,
        "timestamp": iso_utc(updated_at),
        "first_seen": iso_utc(alert.created_at),
        "hostname": (agent.hostname if agent and agent.hostname else alert.agent_id) or "-",
        "host_ip": agent.ip_address if agent else None,
        # ค่าดิบคู่กับป้ายที่อ่านออก — หน้า Alerts ใช้เทียบกับตัวกรองที่เลือกอยู่ ตอนที่ alert
        "agent_id": alert.agent_id,
        "detection_type": alert.detection_type,
        "attack_type": get_attack_type_label(alert.detection_type, alert.mode),
        "source_ip": alert.source_ip,
        "username": alert.username,
        "fail_count": alert.event_count,
        "severity": await get_severity(alert.detection_type, alert.mode),
    }


async def build_alert_detail(alert, agent=None) -> dict:
    """ใช้กับหน้ารายละเอียด (/api/alerts/{id}) เพิ่ม window_sec + raw_logs จาก related_logs"""
    detail = await build_alert_summary(alert, agent)

    raw_logs = [
        item.get("raw_message")
        for item in (alert.related_logs or [])
        if isinstance(item, dict) and item.get("raw_message")
    ]

    detail.update({
        "window_sec": alert.window_seconds,
        "raw_logs": raw_logs,
        # ผลสรุป AI ที่เคยกดวิเคราะห์ไว้ (None = ยังไม่เคยกด -> frontend โชว์ปุ่มให้กด)
        "ai_summary": alert.ai_summary,
        "ai_summary_at": iso_utc(alert.ai_summary_at),
    })

    return detail
