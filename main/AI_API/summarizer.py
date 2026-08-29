"""สร้าง prompt จาก SecurityAlert (metadata + raw log ในแถวนั้น) แล้วให้ Gemini สรุปเป็นภาษาไทย"""

from AI_API import config, gemini_client
from alerts import get_attack_type_label


# response_action ที่เก็บใน DB -> คำอธิบายให้ AI รู้ว่าเกิดอะไรกับ IP นี้ไปแล้ว
RESPONSE_ACTION_TEXT = {
    "blocked": "ระบบบล็อก IP ต้นทางนี้อัตโนมัติแล้ว (เพิ่มเข้า blacklist + สั่ง Agent block)",
    "already_blacklisted": "IP ต้นทางนี้อยู่ใน blacklist อยู่ก่อนแล้ว (ถูกบล็อกอยู่)",
    "whitelisted": "IP ต้นทางนี้อยู่ใน whitelist ระบบจึงไม่บล็อก (เตือนอย่างเดียว)",
    "no_ip": "ไม่มี IP ต้นทางในเหตุการณ์นี้ ระบบจึงไม่ได้บล็อกอะไร",
    "not_blockable": (
        "IP ต้นทางเป็น address พิเศษของทราฟฟิก broadcast (เช่น 0.0.0.0) ไม่ใช่เครื่องจริง "
        "ระบบจึงไม่บล็อก (เตือนอย่างเดียว)"
    ),
}

PROMPT_TEMPLATE = """คุณเป็นนักวิเคราะห์ความมั่นคงปลอดภัยไซเบอร์ (SOC Analyst) ระดับสูง
วิเคราะห์เหตุการณ์ด้านล่างจาก "หลักฐานใน raw log จริง" เท่านั้น เขียนให้เจาะจงกับเหตุการณ์นี้
ห้ามตอบแบบสำเร็จรูป/กว้าง ๆ ที่ใช้ได้กับทุก alert

ข้อมูลเหตุการณ์ที่ระบบตรวจจับได้:
{metadata}

Raw log ที่เกี่ยวข้อง ({log_count} บรรทัด{log_note}):
{logs}

จงตอบเป็นภาษาไทย ความยาวรวมไม่เกิน 20 บรรทัด ใช้ 4 หัวข้อนี้เท่านั้น เรียงตามนี้ และขึ้นบรรทัดใหม่หลังหัวข้อ:

สรุปเหตุการณ์
(เกิดอะไรขึ้น 2-3 ประโยค อ้างอิงจากสิ่งที่เห็นใน log จริง)

รูปแบบการโจมตี
(ยกค่าที่เห็นจริงใน raw log มาอ้างให้เจาะจง เช่น username / path / method / HTTP status / port / payload / User-Agent / อัตราการยิง ถ้ามีหลายแบบให้ชี้ว่าเป็น pattern อะไร)

ผลกระทบ
(ประเมินตามหลักฐานว่า "สำเร็จ / ถูกปฏิเสธ / ยังสรุปไม่ได้" โดยดูสัญญาณจริงใน log เช่น
HTTP status 2xx = เซิร์ฟเวอร์ประมวลผล/อาจคืนข้อมูล ต่างจาก 4xx/5xx = ถูกปฏิเสธหรือ error,
"Accepted password" = ล็อกอินสำเร็จ ต่างจาก "Failed password", firewall deny = แพ็กเก็ตถูกบล็อกยังไม่เกิด connection
แล้วระบุความเสี่ยงที่ตามมาถ้าสำเร็จ ถ้า log ไม่พอสรุปให้บอกตรง ๆ ว่าสรุปไม่ได้ ห้ามเดา)

คำแนะนำ
(2-4 ข้อ ขึ้นต้นแต่ละข้อด้วย "- " เป็นวิธีแก้ที่ "ต้นเหตุจริง" และเจาะจงกับชนิดการโจมตี/บริการที่ถูกโจมตีนี้
เช่น แก้โค้ด/ตั้งค่า/แพตช์ช่องโหว่ ปิดช่องทางที่ถูกใช้ จำกัด rate ตรวจสอบบัญชีหรือ endpoint ที่กระทบ
หรือสืบว่ามี IP/เป้าหมายอื่นเกี่ยวข้องไหม)

ข้อกำหนดสำคัญ:
- ระบบ "จัดการ IP ต้นทางอัตโนมัติแล้ว" (ดูสถานะในข้อมูลด้านบน) ห้ามเอาการ block / unblock / whitelist / blacklist IP
  มาเป็นคำแนะนำ และห้ามพูดซ้ำว่าระบบบล็อก IP ไปแล้ว — ให้ใช้พื้นที่คำแนะนำกับการแก้ที่ต้นเหตุจริงแทน
- อ้างอิงเฉพาะค่าที่ปรากฏใน log/metadata ห้ามแต่งข้อมูลที่ไม่มี ถ้าข้อมูลไม่พอให้บอกตรง ๆ ว่าสรุปได้แค่ไหน
- ห้ามใช้เครื่องหมาย markdown (* # `) เขียนเป็นข้อความธรรมดา
- ห้ามใส่หัวข้ออื่นนอกจาก 4 หัวข้อข้างบน"""


def _build_metadata(alert, agent=None, severity: str = "LOW") -> str:
    hostname = (agent.hostname if agent and agent.hostname else alert.agent_id) or "-"
    host_ip = (agent.ip_address if agent else None) or "-"

    lines = [
        f"- ชนิดการโจมตีที่ตรวจจับได้: {get_attack_type_label(alert.detection_type, alert.mode)}",
        f"- ระดับความรุนแรงที่ระบบให้: {severity}",
        f"- เครื่องที่ถูกโจมตี: {hostname} (IP {host_ip})",
        f"- IP ต้นทางผู้โจมตี: {alert.source_ip or '-'}",
        f"- จำนวนครั้งที่ตรวจพบ: {alert.event_count} ครั้ง ภายใน {alert.window_seconds} วินาที "
        f"(เกณฑ์ที่ตั้งไว้คือ {alert.threshold} ครั้ง)",
        f"- ช่วงเวลาที่เกิด: {alert.first_event_at} ถึง {alert.last_event_at} (UTC)",
    ]

    if alert.username:
        lines.append(f"- username ที่เกี่ยวข้อง: {alert.username}")

    action = RESPONSE_ACTION_TEXT.get(alert.response_action)
    if action:
        lines.append(
            f"- การจัดการ IP ต้นทางโดยระบบ (อัตโนมัติแล้ว — เป็นบริบท ไม่ต้องแนะนำซ้ำ): {action}"
        )

    return "\n".join(lines)


def _build_logs(alert) -> tuple[str, int, str]:
    raw_logs = [
        item.get("raw_message")
        for item in (alert.related_logs or [])
        if isinstance(item, dict) and item.get("raw_message")
    ]

    total = len(raw_logs)
    note = ""

    if total > config.MAX_LOGS_IN_PROMPT:
        raw_logs = raw_logs[: config.MAX_LOGS_IN_PROMPT]
        note = f", ส่งให้ AI {config.MAX_LOGS_IN_PROMPT} บรรทัดแรก จากทั้งหมด {total}"

    if not raw_logs:
        return "(ไม่มี raw log)", total, note

    text = "\n".join(log[: config.MAX_LOG_LINE_CHARS] for log in raw_logs)
    return text, total, note


def build_prompt(alert, agent=None, severity: str = "LOW") -> str:
    logs, log_count, log_note = _build_logs(alert)

    return PROMPT_TEMPLATE.format(
        metadata=_build_metadata(alert, agent, severity),
        logs=logs,
        log_count=log_count,
        log_note=log_note,
    )


def summarize_alert(alert, agent=None, severity: str = "LOW") -> tuple[bool, str]:
    """blocking — route ต้องเรียกผ่าน asyncio.to_thread"""
    return gemini_client.generate(build_prompt(alert, agent, severity))
