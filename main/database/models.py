from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, DateTime, Text, Boolean, ForeignKey, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from database.connection import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False, index=True)
    # ชื่อที่แสดง (display name) — แก้เองได้ในหน้า Profile Setting, แยกจาก username ที่ใช้ login
    name = Column(String(100), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="admin")
    is_active = Column(Boolean, default=True)
    # True เฉพาะบัญชี admin/admin ที่ seed อัตโนมัติตอน DB ว่าง (main.py lifespan) หรือ
    must_change_password = Column(Boolean, nullable=False, default=False)

    # id ของ alert ล่าสุดที่ผู้ใช้คนนี้ "เห็นในรายการ" แล้ว — คุมเฉพาะตัวเลข badge ที่เมนู Alerts
    last_seen_alert_id = Column(Integer, nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class Agent(Base):
    __tablename__ = "agents"

    id = Column(Integer, primary_key=True, index=True)
    agent_id = Column(String(100), unique=True, nullable=False, index=True)
    secret_token_hash = Column(String(255), unique=True, nullable=False, index=True)
    hostname = Column(String(100), nullable=True)
    description = Column(String(200), nullable=True)

    # IP ที่ "ผูก" ไว้กับ agent_id นี้ — ข้อมูลที่ agent ส่งเข้ามา (ทั้ง metrics และ log)
    ip_address = Column(String(50), nullable=True)

    # ชื่อ interface ที่ agent ใช้เป็นแหล่งของ IP (เลือกตอนรัน setup.sh) — ไว้แสดงให้แอดมินรู้ว่า
    ip_interface = Column(String(50), nullable=True)

    # IP ล่าสุดที่ถูกปฏิเสธเพราะไม่ตรงกับ ip_address — เก็บไว้ให้หน้า Agents เตือนแอดมินได้ว่า
    pending_ip = Column(String(50), nullable=True)
    pending_ip_at = Column(DateTime, nullable=True)

    status = Column(String(20), default="offline")
    is_active = Column(Boolean, default=True)
    cert_path = Column(Text, nullable=True)
    key_path = Column(Text, nullable=True)
    last_seen = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class AgentDownload(Base):
    __tablename__ = "agent_downloads"

    id = Column(Integer, primary_key=True, index=True)

    # ผูกกับ agents.agent_id (unique) ระดับ DB — เดิมเป็น String ลอย ๆ ที่อาศัย
    agent_id = Column(
        String(100),
        ForeignKey(
            "agents.agent_id",
            ondelete="CASCADE",
            name="fk_agent_downloads_agent_id",
        ),
        nullable=False,
        index=True,
    )
    download_token_hash = Column(String(255), unique=True, nullable=False, index=True)
    zip_path = Column(Text, nullable=False)
    downloaded = Column(Boolean, default=False)
    downloaded_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=False)
    created_at = Column(DateTime, default=datetime.now)

class Ip_black_list(Base):
    __tablename__ = "ip_black_list"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), unique=True, nullable=False, index=True)
    event = Column(String(50), nullable=False)
    created_at = Column(DateTime, default=datetime.now)

    # Auto-expiry (blacklist expiry): NULL = ถาวร (manual/critical), มีค่า = หมดอายุเมื่อถึงเวลานี้
    expires_at = Column(DateTime, nullable=True)
    # is_active=False = หมดอายุแล้ว + สั่ง unblock agent แล้ว (เก็บแถวไว้เพื่อ escalation/history)
    is_active = Column(Boolean, nullable=False, default=True, index=True)
    # จำนวนครั้งที่ IP นี้เคยถูก block (ใช้คำนวณ escalation: โดนซ้ำ ban นานขึ้น)
    block_count = Column(Integer, nullable=False, default=1)

    # ใครทำให้ IP นี้ถูกบล็อก "รอบปัจจุบัน": ชื่อผู้ใช้ที่กดเอง หรือ `detector:<ชนิดการโจมตี>` เมื่อระบบบล็อกเอง
    created_by = Column(String(50), nullable=True)
    # id ของผู้ใช้ที่กดเพิ่ม (NULL เมื่อ detector เป็นคนเพิ่ม หรือผู้ใช้คนนั้นถูกลบไปแล้ว)
    created_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )


class Ip_white_list(Base):
    __tablename__ = "ip_white_list"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.now)

    # ชื่อผู้ใช้ที่กดเพิ่ม (whitelist ไม่มีทางเกิดเองจากระบบ) · NULL = แถวเก่าก่อนมีคอลัมน์นี้
    created_by = Column(String(50), nullable=True)
    created_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )


class SecurityAlert(Base):
    # เก็บเหตุการณ์ที่ detector (auth/web/firewall) ตรวจจับได้ว่าเข้าเงื่อนไข threshold

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    # ประเภทเหตุการณ์ เช่น ssh_brute_force, sudo_failed
    detection_type = Column(String(50), nullable=False, index=True)

    # กลุ่มของ log ต้นทาง: auth / web / firewall
    category = Column(String(20), nullable=False, index=True)

    # โหมดย่อยของ detection_type — ตอนนี้ยังไม่มี detector ตัวไหนใช้แล้ว
    mode = Column(String(20), nullable=True)

    agent_id = Column(String(100), nullable=True, index=True)
    source_ip = Column(String(50), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)

    # ผลของการตอบสนองต่อ source_ip นี้ ณ ตอนที่ alert เกิด
    response_action = Column(String(30), nullable=True, index=True)

    # จำนวน event ที่เข้าเงื่อนไข / window ที่ใช้นับ / threshold ที่ตั้งไว้
    event_count = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    threshold = Column(Integer, nullable=False)

    # เวลาของ log ตัวแรกและตัวสุดท้ายที่ถูกนำมานับใน window นี้ (จาก agent_event_time)
    first_event_at = Column(DateTime, nullable=True)
    last_event_at = Column(DateTime, nullable=True)

    # log ทุกบรรทัดที่เอามานับรวมเป็นเหตุการณ์นี้ เก็บเต็มไว้ trace ย้อนหลัง
    related_logs = Column(JSONB, nullable=False)

    # ผลสรุปจาก AI (Gemini) — สร้างตอนแอดมินกดปุ่มในหน้า alert เท่านั้น ไม่ทำอัตโนมัติ
    ai_summary = Column(Text, nullable=True)
    ai_summary_at = Column(DateTime, nullable=True)

    # created_at = เจอครั้งแรก, updated_at = กิจกรรมล่าสุดของ "เหตุการณ์เดียวกัน" นี้
    created_at = Column(DateTime, default=datetime.now, index=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, index=True)


class AlertRead(Base):
    # บันทึกว่า user คนไหนกด "ดูรายละเอียด" alert ตัวไหนไปแล้ว — หนึ่งแถว = หนึ่งคู่ (user, alert)

    __tablename__ = "alert_reads"

    id = Column(Integer, primary_key=True, index=True)

    # ลบ user หรือลบ alert ต้นทางแล้วแถวนี้หายตามไปเอง ไม่เหลือขยะค้างในตาราง
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    alert_id = Column(
        Integer, ForeignKey("security_alerts.id", ondelete="CASCADE"), nullable=False, index=True
    )

    read_at = Column(DateTime, default=datetime.now)

    __table_args__ = (
        UniqueConstraint("user_id", "alert_id", name="uq_alert_reads_user_alert"),
    )


class DetectionRule(Base):
    # ค่า threshold/window ของแต่ละ detector เก็บใน DB แทน hardcode

    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)

    # คีย์ระบุ rule เช่น ssh_brute_force, sudo_failed, firewall_port_scan
    rule_key = Column(String(50), unique=True, nullable=False, index=True)

    # กลุ่มของ detector: auth / web / firewall
    category = Column(String(20), nullable=False, index=True)

    window_seconds = Column(Integer, nullable=False)
    threshold = Column(Integer, nullable=False)

    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class AlertSeverity(Base):
    # ระดับความรุนแรง (LOW/MEDIUM/HIGH/CRITICAL) ของ alert ต่อ severity_key — เก็บใน DB แทน hardcode

    __tablename__ = "alert_severity"

    id = Column(Integer, primary_key=True, index=True)
    severity_key = Column(String(50), unique=True, nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    description = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class BlacklistTtl(Base):
    # ระยะเวลา (TTL) ที่ IP จะถูก block ก่อนหมดอายุ ต่อ detection_type — เก็บใน DB แทน hardcode

    __tablename__ = "blacklist_ttl"

    id = Column(Integer, primary_key=True, index=True)
    detection_type = Column(String(50), unique=True, nullable=False, index=True)
    ttl_seconds = Column(Integer, nullable=True)
    description = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class DetectionSignature(Base):
    # เก็บ signature (regex) ของ Signature-based detector แทน hardcode ในโค้ด

    __tablename__ = "detection_signatures"

    id = Column(Integer, primary_key=True, index=True)

    # ชนิดการโจมตี = detection_type ที่ detector ใช้ยิง alert
    detection_type = Column(String(50), nullable=False, index=True)

    # กลุ่ม detector: web / firewall (เผื่ออนาคต)
    category = Column(String(20), nullable=False, index=True, default="web")

    # regex pattern เก็บเป็น string ดิบ — detector เอาไป compile รวมแบบ IGNORECASE
    pattern = Column(Text, nullable=False)

    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)

    # True = แถวที่ระบบ seed มาจากค่า default (DEFAULT_SIGNATURES / seed_data.json)
    is_default = Column(Boolean, nullable=False, default=False, index=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class LineRecipient(Base):
    # ผู้รับแจ้งเตือนทาง LINE — คนที่แอด OA จะถูก webhook บันทึกเป็น status=pending

    __tablename__ = "line_recipients"

    id = Column(Integer, primary_key=True, index=True)

    # userId จาก LINE (source.userId ใน webhook event) — คีย์ปลายทางของ push
    line_user_id = Column(String(64), unique=True, nullable=False, index=True)

    # display name ตอน follow (ดึงจาก get profile) ไว้ให้แอดมินดูว่าใครขอ
    display_name = Column(String(255), nullable=True)

    # URL รูปโปรไฟล์จาก LINE (pictureUrl ของ get profile) — ไว้ให้แอดมินเห็นหน้าคนขอ
    picture_url = Column(String(512), nullable=True)

    # pending (เพิ่งแอด รออนุมัติ) / approved (รับแจ้งเตือน) / rejected (ปฏิเสธ/บล็อก)
    status = Column(String(20), nullable=False, default="pending", index=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    approved_at = Column(DateTime, nullable=True)

class AppSetting(Base):
    # ค่าตั้งของระบบที่แก้ได้ตอนรัน ผ่านหน้า System Settings (ไม่ต้องแก้ .env + restart)

    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)

    setting_key = Column(String(64), unique=True, nullable=False, index=True)

    # เก็บเป็น text ทุกชนิด (เลข/บูลีนแปลงเอาตอนอ่าน) — '' = ตั้งเป็นค่าว่างจริง ๆ ไม่ใช่ยังไม่ตั้ง
    value = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class AppSettingChange(Base):
    # ประวัติการแก้ค่าตั้ง — ตอบว่า "คีย์นี้ใครเป็นคนแก้ เมื่อไหร่ จากค่าอะไรเป็นอะไร"

    __tablename__ = "app_setting_changes"

    id = Column(Integer, primary_key=True, index=True)

    setting_key = Column(String(64), nullable=False, index=True)

    # set = ตั้งค่าทับ · reset = ลบค่าที่ตั้งทับ กลับไปใช้ .env · rotate = เปลี่ยนของจริงนอก DB
    action = Column(String(16), nullable=False)

    # ค่าก่อน/หลัง (mask แล้วถ้าเป็น secret) · None = ตอนนั้นยังไม่มีค่าตั้งทับ
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)

    # เก็บ "คู่กัน" ตั้งใจ: id ไว้ join กับตาราง users (เอาชื่อที่แสดง/role มาโชว์ได้)
    changed_by = Column(String(50), nullable=False, index=True)
    changed_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # มาจากหน้าไหน: settings / rules / startup / cli — คีย์เดียวกันแก้ได้จากหลายทาง
    source = Column(String(16), nullable=False, default="settings")

    changed_at = Column(DateTime, default=datetime.now, index=True)
