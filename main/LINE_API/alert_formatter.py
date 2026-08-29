"""แปลง alert_summary (dict ที่ build_alert_summary สร้าง แล้ว publish ขึ้น"""

from datetime import datetime, timedelta

# เซิร์ฟเวอร์เก็บเวลาเป็น UTC (build_alert_summary ต่อท้าย "Z") — ไทย = UTC+7
THAI_OFFSET = timedelta(hours=7)


def _to_thai_time(timestamp: str | None) -> str:
    """แปลง ISO timestamp (UTC, ลงท้าย Z) -> 'dd/mm/YYYY HH:MM:SS' เวลาไทย"""
    if not timestamp:
        return "-"
    try:
        raw = timestamp.rstrip("Z")
        dt_utc = datetime.fromisoformat(raw)
        dt_thai = dt_utc + THAI_OFFSET
        return dt_thai.strftime("%d/%m/%Y %H:%M:%S")
    except (ValueError, TypeError):
        return timestamp


def format_alert(alert: dict) -> str:
    attack_type = alert.get("attack_type") or "-"
    source_ip = alert.get("source_ip") or "-"

    hostname = alert.get("hostname") or "-"
    host_ip = alert.get("host_ip")
    if hostname != "-" and host_ip:
        hostname = f"{hostname} ({host_ip})"

    thai_time = _to_thai_time(alert.get("timestamp"))

    return "\n".join([
        "🚨 ตรวจพบการโจมตี",
        f"ชนิด: {attack_type}",
        f"เครื่อง: {hostname}",
        f"ต้นทาง: {source_ip}",
        f"เวลา: {thai_time} น.",
    ])
