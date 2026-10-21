from datetime import datetime, timedelta
from sqlalchemy import select, delete, func, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm.attributes import flag_modified

from database.models import *
from ip_match import entry_covers, entry_contains
from view_account import VIEW_ROLE, VIEW_USERNAME, VIEW_DISPLAY_NAME


async def get_user(db: AsyncSession, username: str):
    result = await db.execute(select(User).where(User.username == username))
    return result.scalar_one_or_none()


async def get_user_by_id(db: AsyncSession, user_id: int):
    result = await db.execute(select(User).where(User.id == user_id))
    return result.scalar_one_or_none()


async def get_all_users(db: AsyncSession):

    result = await db.execute(
        select(User).where(User.role.is_distinct_from(VIEW_ROLE)).order_by(User.username)
    )
    return result.scalars().all()


async def get_view_user(db: AsyncSession):
    result = await db.execute(select(User).where(User.role == VIEW_ROLE).limit(1))
    return result.scalar_one_or_none()


async def create_view_user(db: AsyncSession, hashed_password: str):

    user = User(
        username=VIEW_USERNAME,
        name=VIEW_DISPLAY_NAME,
        hashed_password=hashed_password,
        role=VIEW_ROLE,
        is_active=False,
        must_change_password=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def create_user(
    db: AsyncSession,
    username: str,
    hashed_password: str,
    must_change_password: bool = False,
):


    user = User(
        username=username,
        hashed_password=hashed_password,
        role="admin",
        must_change_password=must_change_password,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def set_user_password(
    db: AsyncSession,
    user: User,
    hashed_password: str,
    must_change_password: bool = False,
):
    user.hashed_password = hashed_password
    user.must_change_password = must_change_password
    user.updated_at = datetime.now()
    await db.commit()
    await db.refresh(user)
    return user


async def set_user_name(db: AsyncSession, user: User, name: str | None):
    user.name = name
    user.updated_at = datetime.now()
    await db.commit()
    await db.refresh(user)
    return user


async def set_user_active(db: AsyncSession, user: User, is_active: bool):
    user.is_active = is_active
    user.updated_at = datetime.now()
    await db.commit()
    await db.refresh(user)
    return user


async def get_first_user(db: AsyncSession):


    result = await db.execute(
        select(User).where(User.role.is_distinct_from(VIEW_ROLE)).order_by(User.id.asc()).limit(1)
    )
    return result.scalar_one_or_none()


async def delete_user(db: AsyncSession, user: User):
    await db.delete(user)
    await db.commit()
    return user


async def get_agents(db: AsyncSession):
    result = await db.execute(select(Agent).order_by(Agent.id.desc()))
    return result.scalars().all()


async def get_agent_by_id(db: AsyncSession, agent_db_id: int):
    result = await db.execute(select(Agent).where(Agent.id == agent_db_id))
    return result.scalar_one_or_none()


async def get_agent_by_agent_id(db: AsyncSession, agent_id: str):
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id))
    return result.scalar_one_or_none()


async def update_agent(
    db: AsyncSession,
    agent: Agent,
    hostname: str | None = None,
    description: str | None = None,
    is_active: bool | None = None,
):

    agent.hostname = hostname
    agent.description = description

    if is_active is not None:
        agent.is_active = is_active

        if not is_active:
            agent.status = "offline"

    agent.updated_at = datetime.now()
    await db.commit()
    await db.refresh(agent)
    return agent


async def bind_agent_ip(
    db: AsyncSession,
    agent_id: str,
    ip_address: str,
    ip_interface: str | None = None,
) -> bool:

    agent = await get_agent_by_agent_id(db, agent_id)

    if not agent or agent.ip_address:
        return False

    agent.ip_address = ip_address
    agent.pending_ip = None
    agent.pending_ip_at = None

    if ip_interface:
        agent.ip_interface = ip_interface

    agent.updated_at = datetime.now()
    await db.commit()
    return True


async def clear_agent_ip_binding(db: AsyncSession, agent: Agent) -> None:

    agent.ip_address = None
    agent.ip_interface = None
    agent.pending_ip = None
    agent.pending_ip_at = None


async def record_agent_ip_mismatch(
    db: AsyncSession,
    agent_id: str,
    reported_ip: str,
) -> bool:

    agent = await get_agent_by_agent_id(db, agent_id)

    if not agent:
        return False

    agent.pending_ip = reported_ip
    agent.pending_ip_at = datetime.now()
    await db.commit()
    return True


async def count_alerts_by_agent(db: AsyncSession) -> dict[str, int]:

    result = await db.execute(
        select(SecurityAlert.agent_id, func.count(SecurityAlert.id))
        .where(SecurityAlert.agent_id.isnot(None))
        .group_by(SecurityAlert.agent_id)
    )
    return {agent_id: count for agent_id, count in result.all()}


async def delete_agent_by_agent_id(db: AsyncSession, agent_id: str):

    agent = await get_agent_by_agent_id(db, agent_id)
    if not agent:
        return None, 0

    alerts = await db.execute(
        delete(SecurityAlert).where(SecurityAlert.agent_id == agent_id)
    )


    await db.execute(delete(AgentDownload).where(AgentDownload.agent_id == agent_id))
    await db.delete(agent)
    await db.commit()
    return agent, alerts.rowcount or 0


async def get_agent_download_by_token_hash(db: AsyncSession, token_hash: str):
    result = await db.execute(
        select(AgentDownload).where(
            AgentDownload.download_token_hash == token_hash
        )
    )
    return result.scalar_one_or_none()


async def get_latest_agent_download(db: AsyncSession, agent_id: str):
    result = await db.execute(
        select(AgentDownload)
        .where(AgentDownload.agent_id == agent_id)
        .order_by(AgentDownload.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def invalidate_agent_downloads(db: AsyncSession, agent_id: str):
    result = await db.execute(
        select(AgentDownload).where(
            AgentDownload.agent_id == agent_id,
            AgentDownload.downloaded == False,
        )
    )
    downloads = result.scalars().all()

    for download in downloads:
        download.downloaded = True
        download.downloaded_at = datetime.now()

    await db.commit()
    return downloads


async def mark_agent_downloaded(db: AsyncSession, download: AgentDownload):
    download.downloaded = True
    download.downloaded_at = datetime.now()
    await db.commit()
    await db.refresh(download)
    return download


async def generate_next_agent_id(db: AsyncSession) -> str:
    result = await db.execute(
        select(Agent).order_by(Agent.id.desc()).limit(1)
    )
    last_agent = result.scalar_one_or_none()

    if not last_agent:
        return "Agent_001"

    next_number = last_agent.id + 1
    return f"Agent_{next_number:03d}"

async def save_ip_blacklist(db: AsyncSession, ip_data: dict):
    ip = Ip_black_list(
        ip_address=ip_data.get("source_ip") or ip_data.get("ip_address"),
        event=ip_data.get("attack_type") or ip_data.get("event") or "manual_blacklist",
        expires_at=ip_data.get("expires_at"),
        block_count=ip_data.get("block_count", 1),
        is_active=True,

        created_by=ip_data.get("created_by"),
        created_by_user_id=ip_data.get("created_by_user_id"),
    )

    db.add(ip)


    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await get_blacklist_by_ip(db, ip.ip_address)
        if existing is None:
            raise
        return existing

    await db.refresh(ip)
    return ip

async def get_ip_blacklist(db: AsyncSession):
    ips = await db.execute(select(Ip_black_list).order_by(Ip_black_list.id.desc()))
    return ips.scalars().all()

async def get_active_blacklist(db: AsyncSession):

    ips = await db.execute(
        select(Ip_black_list)
        .where(Ip_black_list.is_active.is_(True))
        .order_by(Ip_black_list.id.desc())
    )
    return ips.scalars().all()

async def get_expired_active_blacklist(db: AsyncSession, now):

    ips = await db.execute(
        select(Ip_black_list).where(
            Ip_black_list.is_active.is_(True),
            Ip_black_list.expires_at.isnot(None),
            Ip_black_list.expires_at <= now,
        )
    )
    return ips.scalars().all()

async def deactivate_blacklist(db: AsyncSession, row):

    row.is_active = False
    await db.commit()
    return row


async def manual_unblock_blacklist(db: AsyncSession, row):

    row.is_active = False
    row.block_count = 0
    await db.commit()
    await db.refresh(row)
    return row

async def reactivate_blacklist(
    db: AsyncSession, row, *, event, expires_at, block_count, actor=None, actor_id=None
):

    row.is_active = True
    row.event = event
    row.expires_at = expires_at
    row.block_count = block_count

    if actor:
        row.created_by = actor
        row.created_by_user_id = actor_id

    await db.commit()
    await db.refresh(row)
    return row


async def upgrade_blacklist_severity(
    db: AsyncSession, row, *, event, expires_at, actor=None, actor_id=None
):

    row.event = event
    row.expires_at = expires_at


    if actor:
        row.created_by = actor
        row.created_by_user_id = actor_id

    await db.commit()
    await db.refresh(row)
    return row


async def set_blacklist_actor(db: AsyncSession, row, actor: str, actor_id=None):

    row.created_by = actor
    row.created_by_user_id = actor_id
    await db.commit()
    await db.refresh(row)
    return row


async def save_ip_whitelist(db: AsyncSession, ip_data: dict):
    ip = Ip_white_list(
        ip_address=ip_data.get("source_ip") or ip_data.get("ip_address"),
        description=ip_data.get("description"),
        created_by=ip_data.get("created_by"),
        created_by_user_id=ip_data.get("created_by_user_id"),
    )

    db.add(ip)


    try:
        await db.commit()
    except IntegrityError:
        await db.rollback()
        existing = await get_whitelist_by_ip(db, ip.ip_address)
        if existing is None:
            raise
        return existing

    await db.refresh(ip)
    return ip

async def get_ip_whitelist(db: AsyncSession):
    ips = await db.execute(select(Ip_white_list).order_by(Ip_white_list.id.desc()))
    return ips.scalars().all()

async def get_blacklist_by_ip(db: AsyncSession, ip_address: str):
    result = await db.execute(
        select(Ip_black_list).where(Ip_black_list.ip_address == ip_address)
    )
    return result.scalar_one_or_none()


async def get_whitelist_by_ip(db: AsyncSession, ip_address: str):

    result = await db.execute(
        select(Ip_white_list).where(Ip_white_list.ip_address == ip_address)
    )
    return result.scalar_one_or_none()


async def find_whitelist_covering(db: AsyncSession, value: str):


    if not value:
        return None

    rows = await get_ip_whitelist(db)

    for row in rows:
        if entry_covers(row.ip_address, value):
            return row

    return None


async def get_active_blacklist_in_entry(db: AsyncSession, entry: str):

    rows = await get_active_blacklist(db)
    return [row for row in rows if entry_contains(entry, row.ip_address)]


async def get_ip_blacklist_by_id(db: AsyncSession, blacklist_id: int):
    result = await db.execute(
        select(Ip_black_list).where(Ip_black_list.id == blacklist_id)
    )
    return result.scalar_one_or_none()


async def delete_ip_blacklist_by_id(db: AsyncSession, blacklist_id: int):

    ip = await get_ip_blacklist_by_id(db, blacklist_id)

    if not ip:
        return None

    await db.delete(ip)
    await db.commit()
    return ip


def alert_activity_at():
    return func.coalesce(SecurityAlert.updated_at, SecurityAlert.created_at)


def alert_filter_conditions(
    activity_at,
    start: datetime | None = None,
    end: datetime | None = None,
    agent_id: str | None = None,
    detection_types: list[str] | None = None,
) -> list:

    conditions = []

    if start is not None:
        conditions.append(activity_at >= start)

    if end is not None:
        conditions.append(activity_at <= end)

    if agent_id:
        conditions.append(SecurityAlert.agent_id == agent_id)


    if detection_types is not None:
        conditions.append(SecurityAlert.detection_type.in_(detection_types))

    return conditions


async def get_security_alerts(
    db: AsyncSession,
    limit: int = 200,
    offset: int = 0,
    start: datetime | None = None,
    end: datetime | None = None,
    agent_id: str | None = None,
    detection_types: list[str] | None = None,
):

    activity_at = alert_activity_at()

    stmt = (
        select(SecurityAlert)
        .where(*alert_filter_conditions(activity_at, start, end, agent_id, detection_types))

        .order_by(activity_at.desc(), SecurityAlert.id.desc())
        .limit(limit)
        .offset(offset)
    )

    result = await db.execute(stmt)
    return result.scalars().all()


async def count_security_alerts(
    db: AsyncSession,
    start: datetime | None = None,
    end: datetime | None = None,
    agent_id: str | None = None,
    detection_types: list[str] | None = None,
) -> int:

    total = await db.scalar(
        select(func.count())
        .select_from(SecurityAlert)
        .where(
            *alert_filter_conditions(
                alert_activity_at(), start, end, agent_id, detection_types
            )
        )
    )
    return int(total or 0)


async def get_alert_filter_facets(db: AsyncSession) -> dict:

    agent_rows = await db.execute(
        select(SecurityAlert.agent_id)
        .where(SecurityAlert.agent_id.isnot(None))
        .distinct()
    )
    type_rows = await db.execute(select(SecurityAlert.detection_type).distinct())

    return {
        "agent_ids": sorted(agent_rows.scalars().all()),
        "detection_types": sorted(type_rows.scalars().all()),
    }


async def count_alerts_by_type(db: AsyncSession) -> list[tuple[str, str | None, int]]:


    result = await db.execute(
        select(SecurityAlert.detection_type, SecurityAlert.mode, func.count())
        .group_by(SecurityAlert.detection_type, SecurityAlert.mode)
    )
    return [(row[0], row[1], int(row[2])) for row in result.all()]


async def count_alerts_per_local_day(
    db: AsyncSession, since: datetime, utc_offset_hours: int = 7
) -> dict:


    local_day = func.date(alert_activity_at() + timedelta(hours=utc_offset_hours))
    result = await db.execute(
        select(local_day, func.count())
        .where(alert_activity_at() >= since)
        .group_by(local_day)
    )
    return {row[0]: int(row[1]) for row in result.all()}


async def count_security_alerts_since(db: AsyncSession, since: int = 0) -> tuple[int, int]:

    unread = await db.scalar(
        select(func.count()).select_from(SecurityAlert).where(SecurityAlert.id > since)
    )
    latest_id = await db.scalar(select(func.max(SecurityAlert.id)))

    return int(unread or 0), int(latest_id or 0)


async def get_security_alert_by_id(db: AsyncSession, alert_id: int):
    result = await db.execute(
        select(SecurityAlert).where(SecurityAlert.id == alert_id)
    )
    return result.scalar_one_or_none()


async def set_security_alert_ai_summary(
    db: AsyncSession,
    alert: SecurityAlert,
    summary: str,
):

    keep_updated_at = alert.updated_at

    alert.ai_summary = summary
    alert.ai_summary_at = datetime.now()
    alert.updated_at = keep_updated_at
    flag_modified(alert, "updated_at")

    await db.commit()
    await db.refresh(alert)
    return alert


async def get_alert_read_ids(db: AsyncSession, user_id: int, limit: int = 500) -> list[int]:

    result = await db.execute(
        select(AlertRead.alert_id)
        .where(AlertRead.user_id == user_id)
        .order_by(AlertRead.alert_id.desc())
        .limit(limit)
    )
    return [int(alert_id) for alert_id in result.scalars().all()]


async def mark_alerts_read(db: AsyncSession, user_id: int, alert_ids: list[int]) -> list[int]:

    if not alert_ids:
        return []

    result = await db.execute(
        select(SecurityAlert.id).where(SecurityAlert.id.in_(alert_ids))
    )
    valid_ids = [int(alert_id) for alert_id in result.scalars().all()]

    if not valid_ids:
        return []

    await db.execute(
        pg_insert(AlertRead)
        .values([{"user_id": user_id, "alert_id": alert_id} for alert_id in valid_ids])
        .on_conflict_do_nothing(index_elements=["user_id", "alert_id"])
    )
    await db.commit()

    return valid_ids


async def get_user_last_seen_alert_id(db: AsyncSession, user_id: int) -> int | None:

    return await db.scalar(select(User.last_seen_alert_id).where(User.id == user_id))


async def set_user_last_seen_alert_id(db: AsyncSession, user_id: int, alert_id: int) -> None:

    await db.execute(
        update(User)
        .where(
            User.id == user_id,
            (User.last_seen_alert_id.is_(None)) | (User.last_seen_alert_id < alert_id),
        )
        .values(last_seen_alert_id=alert_id, updated_at=User.updated_at)
    )
    await db.commit()


async def get_agents_by_agent_ids(db: AsyncSession, agent_ids: list[str]):
    if not agent_ids:
        return []

    result = await db.execute(select(Agent).where(Agent.agent_id.in_(agent_ids)))
    return result.scalars().all()


async def get_detection_rule(db: AsyncSession, rule_key: str):
    result = await db.execute(
        select(DetectionRule).where(DetectionRule.rule_key == rule_key)
    )
    return result.scalar_one_or_none()


async def get_all_detection_rules(db: AsyncSession):
    result = await db.execute(select(DetectionRule).order_by(DetectionRule.rule_key))
    return result.scalars().all()


async def get_agent_disabled_rules(db: AsyncSession, agent_id: str) -> list[str]:
    result = await db.execute(
        select(AgentDisabledRule.rule_key).where(AgentDisabledRule.agent_id == agent_id)
    )
    return list(result.scalars().all())


async def get_all_agent_disabled_rules(db: AsyncSession):
    result = await db.execute(select(AgentDisabledRule.agent_id, AgentDisabledRule.rule_key))
    return result.all()


async def set_agent_disabled_rules(db: AsyncSession, agent_id: str, rule_keys: set[str]) -> None:
    await db.execute(delete(AgentDisabledRule).where(AgentDisabledRule.agent_id == agent_id))
    db.add_all(AgentDisabledRule(agent_id=agent_id, rule_key=key) for key in sorted(rule_keys))
    await db.commit()


async def upsert_detection_rule(
    db: AsyncSession,
    rule_key: str,
    *,
    category: str,
    window_seconds: int,
    threshold: int,
    description: str | None = None,
    is_active: bool = True,
):
    rule = await get_detection_rule(db, rule_key)

    if rule:
        rule.window_seconds = window_seconds
        rule.threshold = threshold
        rule.is_active = is_active

        if description is not None:
            rule.description = description

        rule.updated_at = datetime.now()
    else:
        rule = DetectionRule(
            rule_key=rule_key,
            category=category,
            window_seconds=window_seconds,
            threshold=threshold,
            description=description,
            is_active=is_active,
        )
        db.add(rule)

    await db.commit()
    await db.refresh(rule)
    return rule


async def get_blacklist_ttl(db: AsyncSession, detection_type: str):
    result = await db.execute(
        select(BlacklistTtl).where(BlacklistTtl.detection_type == detection_type)
    )
    return result.scalar_one_or_none()


async def get_all_blacklist_ttl(db: AsyncSession):
    result = await db.execute(
        select(BlacklistTtl).order_by(BlacklistTtl.detection_type)
    )
    return result.scalars().all()


async def upsert_blacklist_ttl(
    db: AsyncSession,
    detection_type: str,
    *,
    ttl_seconds: int | None,
    description: str | None = None,
    auto_block: bool | None = None,
    notify_line: bool | None = None,
):
    row = await get_blacklist_ttl(db, detection_type)

    if row:
        row.ttl_seconds = ttl_seconds
        if description is not None:
            row.description = description

        if auto_block is not None:
            row.auto_block = auto_block

        if notify_line is not None:
            row.notify_line = notify_line
        row.updated_at = datetime.now()
    else:
        row = BlacklistTtl(
            detection_type=detection_type,
            ttl_seconds=ttl_seconds,
            description=description,
            auto_block=True if auto_block is None else auto_block,
            notify_line=True if notify_line is None else notify_line,
        )
        db.add(row)

    await db.commit()
    await db.refresh(row)
    return row


async def get_alert_severity(db: AsyncSession, severity_key: str):
    result = await db.execute(
        select(AlertSeverity).where(AlertSeverity.severity_key == severity_key)
    )
    return result.scalar_one_or_none()


async def get_all_alert_severity(db: AsyncSession):
    result = await db.execute(
        select(AlertSeverity).order_by(AlertSeverity.severity_key)
    )
    return result.scalars().all()


async def upsert_alert_severity(
    db: AsyncSession,
    severity_key: str,
    *,
    severity: str,
    description: str | None = None,
):
    row = await get_alert_severity(db, severity_key)

    if row:
        row.severity = severity
        if description is not None:
            row.description = description
        row.updated_at = datetime.now()
    else:
        row = AlertSeverity(
            severity_key=severity_key,
            severity=severity,
            description=description,
        )
        db.add(row)

    await db.commit()
    await db.refresh(row)
    return row


async def get_detection_signatures(
    db: AsyncSession,
    *,
    detection_type: str | None = None,
    only_active: bool = False,
):
    stmt = select(DetectionSignature)

    if detection_type:
        stmt = stmt.where(DetectionSignature.detection_type == detection_type)

    if only_active:
        stmt = stmt.where(DetectionSignature.is_active.is_(True))

    stmt = stmt.order_by(DetectionSignature.detection_type, DetectionSignature.id)

    result = await db.execute(stmt)
    return result.scalars().all()


async def get_detection_signature_by_id(db: AsyncSession, signature_id: int):
    result = await db.execute(
        select(DetectionSignature).where(DetectionSignature.id == signature_id)
    )
    return result.scalar_one_or_none()


async def find_detection_signature(db: AsyncSession, detection_type: str, pattern: str):
    result = await db.execute(
        select(DetectionSignature).where(
            DetectionSignature.detection_type == detection_type,
            DetectionSignature.pattern == pattern,
        )
    )
    return result.scalar_one_or_none()


async def create_detection_signature(
    db: AsyncSession,
    *,
    detection_type: str,
    pattern: str,
    category: str = "web",
    description: str | None = None,
    is_active: bool = True,
    is_default: bool = False,
):

    signature = DetectionSignature(
        detection_type=detection_type,
        category=category,
        pattern=pattern,
        description=description,
        is_active=is_active,
        is_default=is_default,
    )
    db.add(signature)
    await db.commit()
    await db.refresh(signature)
    return signature


async def delete_default_signatures(db: AsyncSession, detection_type: str) -> int:

    result = await db.execute(
        delete(DetectionSignature)
        .where(
            DetectionSignature.detection_type == detection_type,
            DetectionSignature.is_default.is_(True),
        )
        .returning(DetectionSignature.id)
    )
    removed = len(result.fetchall())
    await db.commit()
    return removed


async def update_detection_signature(
    db: AsyncSession,
    signature_id: int,
    *,
    pattern: str | None = None,
    description: str | None = None,
    is_active: bool | None = None,
):
    signature = await get_detection_signature_by_id(db, signature_id)

    if not signature:
        return None

    if pattern is not None:
        signature.pattern = pattern

    if description is not None:
        signature.description = description

    if is_active is not None:
        signature.is_active = is_active

    signature.updated_at = datetime.now()

    await db.commit()
    await db.refresh(signature)
    return signature


async def delete_detection_signature(db: AsyncSession, signature_id: int):
    signature = await get_detection_signature_by_id(db, signature_id)

    if not signature:
        return None

    await db.delete(signature)
    await db.commit()
    return signature


async def get_line_recipient_by_user_id(db: AsyncSession, line_user_id: str):
    result = await db.execute(
        select(LineRecipient).where(LineRecipient.line_user_id == line_user_id)
    )
    return result.scalar_one_or_none()


async def get_line_recipient_by_id(db: AsyncSession, recipient_id: int):
    result = await db.execute(
        select(LineRecipient).where(LineRecipient.id == recipient_id)
    )
    return result.scalar_one_or_none()


async def get_all_line_recipients(db: AsyncSession):
    result = await db.execute(
        select(LineRecipient).order_by(LineRecipient.created_at.desc())
    )
    return result.scalars().all()


async def get_approved_line_user_ids(db: AsyncSession) -> list[str]:
    result = await db.execute(
        select(LineRecipient.line_user_id).where(LineRecipient.status == "approved")
    )
    return list(result.scalars().all())


async def upsert_pending_line_recipient(
    db: AsyncSession,
    line_user_id: str,
    display_name: str | None = None,
    picture_url: str | None = None,
):

    recipient = await get_line_recipient_by_user_id(db, line_user_id)

    if recipient:
        if display_name is not None:
            recipient.display_name = display_name
        if picture_url is not None:
            recipient.picture_url = picture_url
        if recipient.status == "rejected":
            recipient.status = "pending"
        recipient.updated_at = datetime.now()
    else:
        recipient = LineRecipient(
            line_user_id=line_user_id,
            display_name=display_name,
            picture_url=picture_url,
            status="pending",
        )
        db.add(recipient)

    await db.commit()
    await db.refresh(recipient)
    return recipient


async def set_line_recipient_status(db: AsyncSession, recipient_id: int, status: str):
    recipient = await get_line_recipient_by_id(db, recipient_id)

    if not recipient:
        return None

    recipient.status = status
    recipient.updated_at = datetime.now()
    recipient.approved_at = datetime.now() if status == "approved" else None

    await db.commit()
    await db.refresh(recipient)
    return recipient


async def delete_line_recipient(db: AsyncSession, recipient_id: int):
    recipient = await get_line_recipient_by_id(db, recipient_id)

    if not recipient:
        return None

    await db.delete(recipient)
    await db.commit()
    return recipient


async def create_security_alert(
    db: AsyncSession,
    *,
    detection_type: str,
    category: str,
    event_count: int,
    window_seconds: int,
    threshold: int,
    related_logs: list[dict],
    mode: str | None = None,
    agent_id: str | None = None,
    source_ip: str | None = None,
    username: str | None = None,
    response_action: str | None = None,
    first_event_at: datetime | None = None,
    last_event_at: datetime | None = None,
):
    alert = SecurityAlert(
        detection_type=detection_type,
        category=category,
        mode=mode,
        agent_id=agent_id,
        source_ip=source_ip,
        username=username,
        response_action=response_action,
        event_count=event_count,
        window_seconds=window_seconds,
        threshold=threshold,
        first_event_at=first_event_at,
        last_event_at=last_event_at,
        related_logs=related_logs,
    )

    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


async def get_mergeable_security_alert(
    db: AsyncSession,
    *,
    detection_type: str,
    since: datetime,
    source_ip: str | None = None,
    agent_id: str | None = None,
    username: str | None = None,
):

    conditions = [
        SecurityAlert.detection_type == detection_type,
        SecurityAlert.updated_at >= since,
    ]

    if source_ip:
        conditions.append(SecurityAlert.source_ip == source_ip)

    if agent_id:
        conditions.append(SecurityAlert.agent_id == agent_id)

    if username:
        conditions.append(SecurityAlert.username == username)

    result = await db.execute(
        select(SecurityAlert)
        .where(*conditions)
        .order_by(SecurityAlert.id.desc())
        .limit(1)
    )
    return result.scalar_one_or_none()


async def merge_security_alert(
    db: AsyncSession,
    alert: SecurityAlert,
    *,
    add_event_count: int,
    extra_related_logs: list[dict],
    last_event_at: datetime | None,
    response_action: str | None = None,
):
    alert.event_count += add_event_count
    alert.related_logs = (alert.related_logs or []) + extra_related_logs

    if last_event_at:
        alert.last_event_at = last_event_at


    if response_action is not None:
        alert.response_action = response_action

    alert.updated_at = datetime.now()

    await db.commit()
    await db.refresh(alert)
    return alert


async def get_ip_whitelist_by_id(db: AsyncSession, whitelist_id: int):
    result = await db.execute(
        select(Ip_white_list).where(Ip_white_list.id == whitelist_id)
    )
    return result.scalar_one_or_none()


async def delete_ip_whitelist_by_id(db: AsyncSession, whitelist_id: int):
    ip = await get_ip_whitelist_by_id(db, whitelist_id)

    if not ip:
        return None

    await db.delete(ip)
    await db.commit()
    return ip


async def get_app_setting(db: AsyncSession, setting_key: str):
    result = await db.execute(
        select(AppSetting).where(AppSetting.setting_key == setting_key)
    )
    return result.scalar_one_or_none()


async def get_all_app_settings(db: AsyncSession):
    result = await db.execute(select(AppSetting).order_by(AppSetting.setting_key))
    return result.scalars().all()


async def upsert_app_setting(db: AsyncSession, setting_key: str, value: str):
    row = await get_app_setting(db, setting_key)

    if row:
        row.value = value
        row.updated_at = datetime.now()
    else:
        row = AppSetting(setting_key=setting_key, value=value)
        db.add(row)

    await db.commit()
    await db.refresh(row)
    return row


async def delete_app_setting(db: AsyncSession, setting_key: str):

    row = await get_app_setting(db, setting_key)
    if not row:
        return None

    await db.delete(row)
    await db.commit()
    return row


async def log_app_setting_change(
    db: AsyncSession,
    setting_key: str,
    action: str,
    changed_by: str,
    old_value: str | None = None,
    new_value: str | None = None,
    source: str = "settings",
    changed_by_user_id: int | None = None,
):
    row = AppSettingChange(
        setting_key=setting_key,
        action=action,
        old_value=old_value,
        new_value=new_value,
        changed_by=changed_by or "system",
        changed_by_user_id=changed_by_user_id,
        source=source,
    )
    db.add(row)
    await db.commit()
    await db.refresh(row)
    return row


async def get_app_setting_changes(
    db: AsyncSession,
    setting_key: str | None = None,
    limit: int = 100,
):

    stmt = select(AppSettingChange)
    if setting_key:
        stmt = stmt.where(AppSettingChange.setting_key == setting_key)

    stmt = stmt.order_by(AppSettingChange.changed_at.desc(), AppSettingChange.id.desc()).limit(limit)
    result = await db.execute(stmt)
    return result.scalars().all()


async def get_latest_app_setting_changes(db: AsyncSession):

    result = await db.execute(
        select(AppSettingChange)
        .distinct(AppSettingChange.setting_key)
        .order_by(
            AppSettingChange.setting_key,
            AppSettingChange.changed_at.desc(),
            AppSettingChange.id.desc(),
        )
    )
    return result.scalars().all()
