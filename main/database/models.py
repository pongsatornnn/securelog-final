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

    name = Column(String(100), nullable=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(30), nullable=False, default="admin")
    is_active = Column(Boolean, default=True)

    must_change_password = Column(Boolean, nullable=False, default=False)


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


    ip_address = Column(String(50), nullable=True)


    ip_interface = Column(String(50), nullable=True)


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


    expires_at = Column(DateTime, nullable=True)

    is_active = Column(Boolean, nullable=False, default=True, index=True)

    block_count = Column(Integer, nullable=False, default=1)


    created_by = Column(String(50), nullable=True)

    created_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )


class Ip_white_list(Base):
    __tablename__ = "ip_white_list"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(String(200), nullable=True)
    created_at = Column(DateTime, default=datetime.now)


    created_by = Column(String(50), nullable=True)
    created_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )


class SecurityAlert(Base):


    __tablename__ = "security_alerts"

    id = Column(Integer, primary_key=True, index=True)


    detection_type = Column(String(50), nullable=False, index=True)


    category = Column(String(20), nullable=False, index=True)


    mode = Column(String(20), nullable=True)

    agent_id = Column(String(100), nullable=True, index=True)
    source_ip = Column(String(50), nullable=True, index=True)
    username = Column(String(100), nullable=True, index=True)


    response_action = Column(String(30), nullable=True, index=True)


    event_count = Column(Integer, nullable=False)
    window_seconds = Column(Integer, nullable=False)
    threshold = Column(Integer, nullable=False)


    first_event_at = Column(DateTime, nullable=True)
    last_event_at = Column(DateTime, nullable=True)


    related_logs = Column(JSONB, nullable=False)


    ai_summary = Column(Text, nullable=True)
    ai_summary_at = Column(DateTime, nullable=True)


    created_at = Column(DateTime, default=datetime.now, index=True)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now, index=True)


class AlertRead(Base):


    __tablename__ = "alert_reads"

    id = Column(Integer, primary_key=True, index=True)


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


class AuthSession(Base):


    __tablename__ = "auth_sessions"

    jti = Column(String(64), primary_key=True)
    user_id = Column(
        Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime, nullable=False, index=True)

    revoked_at = Column(DateTime, nullable=True)


class DetectionRule(Base):


    __tablename__ = "detection_rules"

    id = Column(Integer, primary_key=True, index=True)


    rule_key = Column(String(50), unique=True, nullable=False, index=True)


    category = Column(String(20), nullable=False, index=True)

    window_seconds = Column(Integer, nullable=False)
    threshold = Column(Integer, nullable=False)

    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class AlertSeverity(Base):


    __tablename__ = "alert_severity"

    id = Column(Integer, primary_key=True, index=True)
    severity_key = Column(String(50), unique=True, nullable=False, index=True)
    severity = Column(String(20), nullable=False)
    description = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class BlacklistTtl(Base):


    __tablename__ = "blacklist_ttl"

    id = Column(Integer, primary_key=True, index=True)
    detection_type = Column(String(50), unique=True, nullable=False, index=True)
    ttl_seconds = Column(Integer, nullable=True)


    auto_block = Column(Boolean, nullable=False, default=True, server_default="true")


    notify_line = Column(Boolean, nullable=False, default=True, server_default="true")

    description = Column(String(200), nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class DetectionSignature(Base):


    __tablename__ = "detection_signatures"

    id = Column(Integer, primary_key=True, index=True)


    detection_type = Column(String(50), nullable=False, index=True)


    category = Column(String(20), nullable=False, index=True, default="web")


    pattern = Column(Text, nullable=False)

    description = Column(String(200), nullable=True)
    is_active = Column(Boolean, default=True)


    is_default = Column(Boolean, nullable=False, default=False, index=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class LineRecipient(Base):


    __tablename__ = "line_recipients"

    id = Column(Integer, primary_key=True, index=True)


    line_user_id = Column(String(64), unique=True, nullable=False, index=True)


    display_name = Column(String(255), nullable=True)


    picture_url = Column(String(512), nullable=True)


    status = Column(String(20), nullable=False, default="pending", index=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    approved_at = Column(DateTime, nullable=True)

class AppSetting(Base):


    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True, index=True)

    setting_key = Column(String(64), unique=True, nullable=False, index=True)


    value = Column(Text, nullable=True)

    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)


class AppSettingChange(Base):


    __tablename__ = "app_setting_changes"

    id = Column(Integer, primary_key=True, index=True)

    setting_key = Column(String(64), nullable=False, index=True)


    action = Column(String(16), nullable=False)


    old_value = Column(Text, nullable=True)
    new_value = Column(Text, nullable=True)


    changed_by = Column(String(50), nullable=False, index=True)
    changed_by_user_id = Column(
        Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )


    source = Column(String(16), nullable=False, default="settings")

    changed_at = Column(DateTime, default=datetime.now, index=True)
