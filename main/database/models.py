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
    # บัญชีที่โดน admin กด reset password ให้ — บังคับเปลี่ยนรหัสก่อนใช้งานหน้าอื่นต่อ
    must_change_password = Column(Boolean, nullable=False, default=False)

    # id ของ alert ล่าสุดที่ผู้ใช้คนนี้ "เห็นในรายการ" แล้ว — คุมเฉพาะตัวเลข badge ที่เมนู Alerts
    # (คนละเรื่องกับตาราง alert_reads ที่เก็บว่าเปิดดู "รายละเอียด" ตัวไหนไปแล้วบ้าง)
    # NULL = บัญชีนี้ยังไม่เคยเปิดหน้าไหนเลย -> ครั้งแรกถือว่าของเก่าเห็นหมดแล้ว ไม่งั้น badge
    # จะเด้งเป็นจำนวน alert ทั้งตารางตั้งแต่วินาทีแรก ซึ่งไม่ได้บอกว่า "มีอะไรใหม่"
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
    # ต้องรายงาน IP ตรงกับค่านี้ ไม่งั้นถูกปฏิเสธ (auth_cache.verify_agent_token)
    #
    # NULL = ยังไม่เคยผูก -> ผูกให้อัตโนมัติจาก IP ที่ agent รายงานมาครั้งแรกที่ auth ผ่าน
    # (trust-on-first-use) แอดมินจะกรอกเองตั้งแต่ตอนสร้างก็ได้ ถ้าอยากล็อกไว้ตั้งแต่แรก
    ip_address = Column(String(50), nullable=True)

    # ชื่อ interface ที่ agent ใช้เป็นแหล่งของ IP (เลือกตอนรัน setup.sh) — ไว้แสดงให้แอดมินรู้ว่า
    # ค่าที่ผูกอยู่มาจากขาไหนของเครื่อง เวลาเครื่องมีหลายใบ ไม่ได้ใช้ตัดสินใจ auth
    ip_interface = Column(String(50), nullable=True)

    # IP ล่าสุดที่ถูกปฏิเสธเพราะไม่ตรงกับ ip_address — เก็บไว้ให้หน้า Agents เตือนแอดมินได้ว่า
    # "agent ตัวนี้กำลังพยายามส่งจาก IP อื่น" พร้อมปุ่มยืนยันผูก IP ใหม่
    #
    # จำเป็นมาก: ถ้าไม่มีช่องนี้ agent ที่ IP เปลี่ยนเพราะ DHCP จะเงียบหายไปเฉย ๆ
    # โดยไม่มีอะไรบอกว่าทำไม (ดูเหมือน agent ตาย ทั้งที่จริงคือถูกปฏิเสธ)
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
    # delete_agent_by_agent_id() ลบแถวลูกให้เอง ถ้ามี path ไหนลืมเรียก (หรือลบผ่าน psql)
    # จะเหลือ token กำพร้าที่ยังโหลด zip ได้ ทั้งที่ agent ถูกลบไปแล้ว — และ
    # /download-agent ไม่ได้เช็คว่า agent ยังอยู่ไหม (zip มี cert+key ของ mTLS อยู่ข้างใน)
    # CASCADE จึงบังคับให้ token ตายพร้อม agent เสมอ ไม่ต้องพึ่งโค้ดฝั่ง app จำ
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
    # เก็บ "ชื่อ ณ ตอนนั้น" คู่กับ FK ข้างล่าง — ลบผู้ใช้ทีหลัง id กลายเป็น NULL แต่ชื่อยังอยู่
    # NULL = แถวที่มีอยู่ก่อนจะเพิ่มคอลัมน์นี้ (ไม่มีข้อมูลย้อนหลัง หน้าเว็บแสดง "ไม่ทราบ")
    #
    # ⚠️ ต้องอัปเดตทุกครั้งที่แถวถูกใช้ซ้ำ (reactivate / upgrade / สั่งบล็อกซ้ำ) ไม่ใช่เขียนครั้งเดียว
    # ตอน insert — แถว blacklist ถูกใช้ซ้ำตลอด (IP เดิมโดนบล็อก-หมดอายุ-โดนอีก วนไปเรื่อย ๆ)
    # ถ้าเขียนแค่ตอน insert คนที่เพิ่งกดเพิ่ม IP ที่เคยมีแถวอยู่แล้วจะไม่ขึ้นชื่อเลย (เคยเป็นบั๊กจริง)
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
    """
    เก็บเหตุการณ์ที่ detector (auth/web/firewall) ตรวจจับได้ว่าเข้าเงื่อนไข threshold
    หนึ่งแถว = หนึ่งเหตุการณ์ที่ยิง alert พร้อม log ที่เกี่ยวข้องทั้งหมดที่เอามานับ (related_logs)
    """

    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)

    # ประเภทเหตุการณ์ เช่น ssh_brute_force, sudo_failed
    # (ไว้ต่อยอด web/firewall detector ในอนาคต เช่น sql_injection, port_scan)
    detection_type = Column(String(50), nullable=False, index=True)

    # กลุ่มของ log ต้นทาง: auth / web / firewall
    category = Column(String(20), nullable=False, index=True)

    # โหมดย่อยของ detection_type — ตอนนี้ยังไม่มี detector ตัวไหนใช้แล้ว
    # (ssh_brute_force เคยแยก fast/slow แล้วรวมเป็นกฎเดียว) เหลือไว้รองรับ alert เก่า
    mode = Column(String(20), nullable=True)

    agent_id = Column(String(100), nullable=True, index=True)
    source_ip = Column(String(50), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)

    # ผลของการตอบสนองต่อ source_ip นี้ ณ ตอนที่ alert เกิด
    # "no_ip" (ไม่มี IP ให้ตัดสินใจ) / "whitelisted" / "already_blacklisted" / "blocked"
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
    # เก็บไว้เพื่อไม่ต้องเรียก AI ซ้ำ (เสียเงิน) ทุกครั้งที่เปิดดู — กดวิเคราะห์ใหม่ได้ถ้า log เพิ่ม
    ai_summary = Column(Text, nullable=True)
    ai_summary_at = Column(DateTime, nullable=True)

    # created_at = เจอครั้งแรก, updated_at = กิจกรรมล่าสุดของ "เหตุการณ์เดียวกัน" นี้
    # (ถ้า attacker ยิงต่อเนื่องภายใน cooldown จะ merge เข้าแถวเดิม ไม่สร้างแถวใหม่)
    created_at = Column(DateTime, default=datetime.now, index=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, index=True)


class AlertRead(Base):
    """
    บันทึกว่า user คนไหนกด "ดูรายละเอียด" alert ตัวไหนไปแล้ว — หนึ่งแถว = หนึ่งคู่ (user, alert)
    ใช้คุมเครื่องหมาย "ยังไม่ได้อ่าน" หน้าแถวในหน้า Alerts/Dashboard

    เดิมสถานะนี้เก็บใน localStorage อย่างเดียว จึงผูกกับ "เครื่อง" ไม่ใช่ "บัญชี" — คนเดิม
    login จากอีกเครื่องเลยเห็นเป็นยังไม่ได้อ่านทั้งหมด ย้ายมาเก็บที่นี่เพื่อให้ซิงค์ตามบัญชี
    ทุกเครื่อง (localStorage เหลือหน้าที่แค่ cache ไว้วาดจุดทันทีโดยไม่ต้องรอ server)

    คู่ (user_id, alert_id) ห้ามซ้ำ — ฝั่ง crud ใช้ ON CONFLICT DO NOTHING กับ unique นี้
    เพื่อกันสองแท็บ/สองเครื่องยิงตัวเดียวกันเข้ามาพร้อมกันแล้วชนกัน
    """

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
    """
    ค่า threshold/window ของแต่ละ detector เก็บใน DB แทน hardcode
    ในโค้ดมีค่า default ไว้เผื่อแถวนี้ยังไม่เคยถูกสร้าง (seed อัตโนมัติตอนเรียกใช้ครั้งแรก)
    แก้ค่าที่นี่แล้วต้องเคลียร์ cache (`rule_cache.py`) เพื่อให้ detector อ่านค่าใหม่
    """

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
    """
    ระดับความรุนแรง (LOW/MEDIUM/HIGH/CRITICAL) ของ alert ต่อ severity_key — เก็บใน DB แทน hardcode
    severity_key คือ "{detection_type}" เฉยๆ หรือ "{detection_type}:{mode}" ถ้าแยกตาม mode
    (เช่น "sql_injection", "ssh_brute_force") ตรงกับที่ severity_cache.severity_key_for() สร้าง
    ในโค้ดมีค่า default (`severity_cache.DEFAULT_SEVERITY`) ไว้ seed ครั้งแรก
    แก้ที่นี่แล้วต้องเคลียร์ cache (`severity_cache.py`) เพื่อให้มีผลรอบถัดไป
    """

    __tablename__ = "alert_severity"

    id = Column(Integer, primary_key=True, index=True)
    severity_key = Column(String(50), unique=True, nullable=False, index=True)
    severity = Column(String(20), nullable=False)   # LOW / MEDIUM / HIGH / CRITICAL
    description = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class BlacklistTtl(Base):
    """
    ระยะเวลา (TTL) ที่ IP จะถูก block ก่อนหมดอายุ ต่อ detection_type — เก็บใน DB แทน hardcode
    ttl_seconds = NULL หมายถึง "ถาวร" (ไม่หมดอายุ เช่น sql/command injection)
    ในโค้ดมีค่า default (`blacklist_policy.BASE_TTL_SECONDS`) ไว้ seed ครั้งแรก
    แก้ที่นี่แล้วต้องเคลียร์ cache (`blacklist_ttl_cache.py`) เพื่อให้มีผลรอบถัดไป
    """

    __tablename__ = "blacklist_ttl"

    id = Column(Integer, primary_key=True, index=True)
    detection_type = Column(String(50), unique=True, nullable=False, index=True)
    ttl_seconds = Column(Integer, nullable=True)   # NULL = ถาวร
    description = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class DetectionSignature(Base):
    """
    เก็บ signature (regex) ของ Signature-based detector แทน hardcode ในโค้ด
    เพิ่ม/ปิด pattern ใหม่ได้เรื่อยๆ โดยไม่ต้องแก้โค้ด (โหลดผ่าน `signature_cache.py`)
    ในโค้ดมี DEFAULT_SIGNATURES ไว้ seed ครั้งแรกที่ยังไม่มีแถวของ detection_type นั้น
    แก้/เพิ่ม/ปิดที่นี่แล้วต้องเคลียร์ cache เพื่อให้ detector โหลด pattern ใหม่
    """

    __tablename__ = "detection_signatures"

    id = Column(Integer, primary_key=True, index=True)

    # ชนิดการโจมตี = detection_type ที่ detector ใช้ยิง alert
    # เช่น sql_injection / xss / path_traversal / command_injection
    detection_type = Column(String(50), nullable=False, index=True)

    # กลุ่ม detector: web / firewall (เผื่ออนาคต)
    category = Column(String(20), nullable=False, index=True, default="web")

    # regex pattern เก็บเป็น string ดิบ — detector เอาไป compile รวมแบบ IGNORECASE
    pattern = Column(Text, nullable=False)

    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)

    # True = แถวที่ระบบ seed มาจากค่า default (DEFAULT_SIGNATURES / seed_data.json)
    # False = แอดมินเพิ่มเองผ่านหน้า Signatures
    #
    # ใช้แยกว่าปุ่ม "คืนค่า default" แตะแถวไหนได้บ้าง — คืนค่าคือลบเฉพาะแถว is_default
    # ทิ้งแล้ว seed ชุด default ใหม่ทั้งชุด ส่วนแถวของแอดมินไม่ถูกแตะเลย
    # (ที่ต้องมีคอลัมน์นี้เพราะเทียบด้วยตัว pattern อย่างเดียวไม่พอ — แถว default ที่ถูก
    #  แก้ pattern ไปแล้วจะดูเหมือนแถวที่แอดมินเพิ่มเอง แล้วคืนค่าไม่กลับ)
    is_default = Column(Boolean, nullable=False, default=False, index=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class LineRecipient(Base):
    """
    ผู้รับแจ้งเตือนทาง LINE — คนที่แอด OA จะถูก webhook บันทึกเป็น status=pending
    แอดมินต้องกด "อนุมัติ" (status=approved) ถึงจะได้รับ push แจ้งเตือน alert
    (ไม่ใช่แค่แอด OA ก็ได้รับ) — alert_subscriber ส่งเฉพาะแถวที่ approved
    """

    __tablename__ = "line_recipients"

    id = Column(Integer, primary_key=True, index=True)

    # userId จาก LINE (source.userId ใน webhook event) — คีย์ปลายทางของ push
    line_user_id = Column(String(64), unique=True, nullable=False, index=True)

    # display name ตอน follow (ดึงจาก get profile) ไว้ให้แอดมินดูว่าใครขอ
    display_name = Column(String(255), nullable=True)

    # URL รูปโปรไฟล์จาก LINE (pictureUrl ของ get profile) — ไว้ให้แอดมินเห็นหน้าคนขอ
    # ไม่ใช่แค่ชื่อ เวลามีชื่อซ้ำหรือชื่อเล่นที่ดูไม่ออกว่าใคร
    #
    # 3 ค่าที่ต่างกัน (สำคัญ — ใช้คุมว่าจะยิง get profile ซ้ำเมื่อไร):
    #   NULL = ยังไม่เคยดึง profile ของคนนี้     -> webhook จะดึงให้ครั้งถัดไปที่มี event
    #   ''   = ดึงแล้ว แต่คนนี้ไม่ได้ตั้งรูปโปรไฟล์ -> ไม่ต้องดึงซ้ำทุกข้อความ
    #   URL  = มีรูป
    # URL ของ LINE เปลี่ยนเมื่อเจ้าตัวเปลี่ยนรูป ของเก่าจะโหลดไม่ขึ้น — หน้าเว็บ fallback
    # เป็นไอคอนให้เอง และจะได้ URL ใหม่ตอนคนนั้นมี event เข้ามาอีกครั้ง
    picture_url = Column(String(512), nullable=True)

    # pending (เพิ่งแอด รออนุมัติ) / approved (รับแจ้งเตือน) / rejected (ปฏิเสธ/บล็อก)
    status = Column(String(20), nullable=False, default="pending", index=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    approved_at = Column(DateTime, nullable=True)

class AppSetting(Base):
    """
    ค่าตั้งของระบบที่แก้ได้ตอนรัน ผ่านหน้า System Settings (ไม่ต้องแก้ .env + restart)

    เก็บเฉพาะ **runtime config** เท่านั้น — คีย์ LINE / Gemini / ค่าที่ฝังลงชุดติดตั้ง agent
    ส่วนค่า bootstrap (DB, Redis ของ central, cert, JWT/CSRF secret, IP/port ที่ bind)
    **ห้ามย้ายมาที่นี่** เพราะแอปต้องใช้ค่าพวกนั้นก่อนจะเปิดหน้าเว็บได้ (ไก่กับไข่ — ดู problem.md ข้อ 5)

    รายการคีย์ที่ระบบรู้จัก + ค่า default + ชื่อ env ที่ fallback ไป อยู่ใน settings_cache.SETTING_DEFS
    ตารางนี้เก็บแค่ค่าที่ "แอดมินตั้งทับ" — คีย์ที่ยังไม่เคยตั้งจะไม่มีแถวเลย แล้วไปใช้ค่าจาก .env แทน

    หมายเหตุความปลอดภัย: ค่าที่เป็น secret (token/api key/รหัสผ่าน) **เก็บเป็น ciphertext**
    ไม่ใช่ plaintext — เข้ารหัสด้วย main/secret_box.py (Fernet) กุญแจอยู่ในไฟล์ `.settings_key`
    ที่ repo root (สิทธิ์ 600, gitignore) คือ **อยู่นอกฐานข้อมูล** ใครได้ backup ของ DB ไป
    อย่างเดียวจึงถอดไม่ได้ · ค่าที่ไม่ลับ (ชื่อโมเดล/port/username) เก็บ plaintext ตามเดิม
    เพื่อให้ยังอ่านจาก psql ตอน debug ได้
    ป้องกันอีก 2 ชั้น: API ส่งกลับเป็นค่าที่ mask แล้วเสมอ และทุก endpoint เป็น admin-only
    """

    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)

    setting_key = Column(String(64), unique=True, nullable=False, index=True)

    # เก็บเป็น text ทุกชนิด (เลข/บูลีนแปลงเอาตอนอ่าน) — '' = ตั้งเป็นค่าว่างจริง ๆ ไม่ใช่ยังไม่ตั้ง
    value = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class AppSettingChange(Base):
    """
    ประวัติการแก้ค่าตั้ง — ตอบว่า "คีย์นี้ใครเป็นคนแก้ เมื่อไหร่ จากค่าอะไรเป็นอะไร"

    ทำไมเป็นตารางแยกแทนคอลัมน์ `updated_by` ใน app_settings: คอลัมน์เดียวเก็บได้แค่คนล่าสุด
    พอมีคนแก้ทับก็ไม่รู้แล้วว่าก่อนหน้านั้นใครตั้งไว้ · ตารางนี้ไม่มีการลบแถว (append-only)
    แถวของคีย์ที่ถูก reset/ลบไปแล้วก็ยังอยู่

    ⚠️ **ห้ามเก็บค่า secret แบบเปิด** — คีย์ที่ SETTING_DEFS บอกว่า secret จะเก็บเป็นค่า mask
    (`••••••••abcd`) เท่านั้น เพราะตาราง app_settings เองยังเก็บเป็น ciphertext อยู่
    ถ้าตารางนี้เก็บ plaintext เท่ากับเปิดรูใหม่ให้คนที่ได้ backup ของ DB ไป (ดู secret_box.py)

    `changed_by` เก็บเป็น "ชื่อผู้ใช้ ณ ตอนนั้น" ไม่ใช่ FK ไป users — ลบผู้ใช้ทีหลังประวัติต้องไม่หาย
    ค่าที่ไม่ได้มาจากคนกด (seed ตอน startup / สคริปต์) ใช้ `system`
    """

    __tablename__ = "app_setting_changes"

    id = Column(Integer, primary_key=True, index=True)

    setting_key = Column(String(64), nullable=False, index=True)

    # set = ตั้งค่าทับ · reset = ลบค่าที่ตั้งทับ กลับไปใช้ .env · rotate = เปลี่ยนของจริงนอก DB
    # (รหัส Redis ของ admin ที่ไม่ได้เก็บใน app_settings — บันทึกแค่ว่าใครสั่งเมื่อไหร่)
    action = Column(String(16), nullable=False)

    # ค่าก่อน/หลัง (mask แล้วถ้าเป็น secret) · None = ตอนนั้นยังไม่มีค่าตั้งทับ
    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)

    # เก็บ "คู่กัน" ตั้งใจ: id ไว้ join กับตาราง users (เอาชื่อที่แสดง/role มาโชว์ได้)
    # ส่วนชื่อเป็นค่าคงที่ของประวัติ — ลบผู้ใช้แล้ว id กลายเป็น NULL แต่ยังรู้ว่าตอนนั้นใครทำ
    changed_by = Column(String(50), nullable=False, index=True)
    changed_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )

    # มาจากหน้าไหน: settings / rules / startup / cli — คีย์เดียวกันแก้ได้จากหลายทาง
    source = Column(String(16), nullable=False, default="settings")

    changed_at = Column(DateTime, default=datetime.now, index=True)
