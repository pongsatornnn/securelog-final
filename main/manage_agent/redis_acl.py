"""Provision one Redis ACL identity for each agent package.

The legacy users stay in the ACL file until every installed agent has migrated.
"""

import fcntl
import os
import re
import secrets
import shutil
import tempfile
from contextlib import contextmanager
from pathlib import Path

import redis

from redis_config import REDIS_CONFIG


def username_for(agent_id: str) -> str:
    match = re.fullmatch(r"Agent_([0-9]{3,})", agent_id)
    if not match:
        raise ValueError("Agent ID must have the form Agent_001")
    return f"agent_{match.group(1)}"


def _line(username: str, agent_id: str, password: str) -> str:
    # Filebeat needs INFO/SELECT/RPUSH; agent_core needs PING/SUBSCRIBE/PUBLISH.
    # Publishing is restricted to metrics, and subscriptions to this agent's channel.
    return (
        f"user {username} on >{password} -@all +ping +info +select +rpush +subscribe "
        f"~raw_logs_queue resetchannels &global_commands &agent_commands:{agent_id} "
        "(+publish &agent_metrics)"
    )


@contextmanager
def _locked_acl():
    client = redis.Redis(**REDIS_CONFIG, socket_connect_timeout=5, socket_timeout=5)
    path = Path(client.config_get("aclfile").get("aclfile", ""))
    if not path.is_absolute() or not path.is_file():
        raise RuntimeError("Redis has no readable aclfile")
    with open(f"{path}.lock", "a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        yield client, path


def _write_and_load(client, path: Path, content: str) -> None:
    mode = path.stat().st_mode & 0o777
    backup = path.with_name(f"{path.name}.bak.agent.{secrets.token_hex(6)}")
    shutil.copy2(path, backup)
    fd, temp = tempfile.mkstemp(prefix=".users.acl.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp, mode)
        os.replace(temp, path)
        try:
            client.execute_command("ACL", "LOAD")
        except Exception:
            os.replace(backup, path)
            client.execute_command("ACL", "LOAD")
            raise
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def ensure_agent_credentials(agent_id: str) -> tuple[str, str, bool]:
    """Return (username, password, created). Existing credentials never rotate here."""
    username = username_for(agent_id)
    with _locked_acl() as (client, path):
        lines = path.read_text(encoding="utf-8").splitlines()
        matching = [line for line in lines if line.split()[:2] == ["user", username]]
        if len(matching) > 1:
            raise RuntimeError(f"Duplicate Redis ACL user: {username}")
        if matching:
            password_tokens = [part[1:] for part in matching[0].split() if part.startswith(">")]
            if len(password_tokens) != 1:
                raise RuntimeError(f"Cannot recover password for {username}; keep the current package")
            password = password_tokens[0]
            # Refresh permissions when upgrading an existing account, preserving its password.
            replacement = _line(username, agent_id, password)
            if matching[0] != replacement:
                lines[lines.index(matching[0])] = replacement
                _write_and_load(client, path, "\n".join(lines) + "\n")
            created = False
        else:
            password = secrets.token_urlsafe(32)
            lines.append(_line(username, agent_id, password))
            _write_and_load(client, path, "\n".join(lines) + "\n")
            created = True
        try:
            redis.Redis(**{**REDIS_CONFIG, "username": username, "password": password},
                        socket_connect_timeout=5, socket_timeout=5).ping()
        except Exception:
            if created:
                _write_and_load(client, path, "\n".join(lines[:-1]) + "\n")
            raise
        return username, password, created


def remove_agent_credentials(agent_id: str) -> None:
    username = username_for(agent_id)
    with _locked_acl() as (client, path):
        lines = path.read_text(encoding="utf-8").splitlines()
        retained = [line for line in lines if line.split()[:2] != ["user", username]]
        if len(retained) != len(lines):
            _write_and_load(client, path, "\n".join(retained) + "\n")
