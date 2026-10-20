

import os
import re
import hmac
import shutil
import tempfile
import threading
from datetime import datetime

import redis

from redis_client import reset_client
from redis_config import REDIS_CONFIG

from redis_password_rules import generate_password, validate_password
from service_status import mark_env_applied


LOG_PREFIX = "REDIS-PASSWD"


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FALLBACK_ACL_PATH = os.path.join(REPO_ROOT, "redis", "users.acl")
ENV_PATH = os.path.join(REPO_ROOT, ".env")
ENV_KEY = "REDIS_PASS"

_LOCK = threading.Lock()


KEEP_BACKUPS = 5


class RotationError(RuntimeError):
    """เปลี่ยนรหัสไม่สำเร็จ — ข้อความในนี้ถูกส่งไปโชว์บนหน้าเว็บตรง ๆ"""


def verify_current_password(typed: str) -> None:

    current = REDIS_CONFIG.get("password") or ""

    if not hmac.compare_digest(typed.encode("utf-8"), current.encode("utf-8")):
        raise ValueError("รหัสเดิมไม่ถูกต้อง")


def _read_text(path: str, what: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        raise RotationError(f"อ่าน{what} ({path}) ไม่ได้: {e}") from e


def _require_writable(path: str, what: str) -> None:

    if not os.access(path, os.W_OK):
        raise RotationError(f"เขียน{what} ({path}) ไม่ได้ — process นี้ไม่มีสิทธิ์เขียนไฟล์")

    folder = os.path.dirname(path) or "."
    if not os.access(folder, os.W_OK):
        raise RotationError(f"เขียนในโฟลเดอร์ {folder} ไม่ได้ — ต้องสร้างไฟล์ชั่วคราวตอนบันทึก")


def _write_atomic(path: str, content: str) -> None:

    folder = os.path.dirname(path) or "."
    mode = os.stat(path).st_mode & 0o777

    fd, tmp = tempfile.mkstemp(dir=folder, prefix=".tmp-", suffix=".swap")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())

        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _prune_backups(path: str) -> None:

    folder = os.path.dirname(path) or "."
    prefix = os.path.basename(path) + ".bak."

    try:
        names = sorted(n for n in os.listdir(folder) if n.startswith(prefix))
    except OSError as e:
        print(f"[{LOG_PREFIX}] อ่านรายชื่อไฟล์สำรองใน {folder} ไม่ได้ (ข้ามการล้าง): {e}")
        return

    for name in names[:-KEEP_BACKUPS]:
        try:
            os.unlink(os.path.join(folder, name))
            print(f"[{LOG_PREFIX}] ลบไฟล์สำรองเก่าที่เกิน {KEEP_BACKUPS} ชุด: {name}")
        except OSError as e:
            print(f"[{LOG_PREFIX}] ลบไฟล์สำรองเก่า {name} ไม่สำเร็จ (ข้ามไป): {e}")


def _backup(path: str) -> str:

    dest = f"{path}.bak.{datetime.now():%Y%m%d%H%M%S}"
    shutil.copy2(path, dest)
    _prune_backups(path)
    return dest


def _restore(backup_path: str, path: str) -> None:
    shutil.copy2(backup_path, path)


def _find_user_line(lines: list[str], username: str) -> int:

    found = [i for i, raw in enumerate(lines)
             if (parts := raw.split()) and len(parts) >= 2 and parts[0] == "user" and parts[1] == username]

    if len(found) > 1:
        rows = ", ".join(str(i + 1) for i in found)
        raise RotationError(f"users.acl มีบรรทัดของ user {username} ซ้ำกัน (บรรทัด {rows}) — แก้ให้เหลือบรรทัดเดียวก่อน")

    return found[0] if found else -1


def _is_password_token(token: str, index: int) -> bool:

    if index < 2:
        return False
    return token.startswith((">", "<", "#")) or token == "nopass"


def _rewrite_acl_line(line: str, new_password: str) -> str:

    parts = line.split()
    out: list[str] = []
    replaced = False

    for i, token in enumerate(parts):
        if not _is_password_token(token, i):
            out.append(token)
            continue

        if not replaced:
            out.append(f">{new_password}")
            replaced = True

    if not replaced:

        out.insert(2, f">{new_password}")

    return " ".join(out)


def _env_key_pattern(key: str) -> re.Pattern:

    return re.compile(rf"^\s*(export\s+)?{re.escape(key)}\s*=")


def _replace_env_value(text: str, key: str, value: str) -> str:

    lines = text.splitlines(keepends=True)
    pattern = _env_key_pattern(key)

    for i, line in enumerate(lines):
        if pattern.match(line):
            newline = "\n" if line.endswith("\n") else ""
            lines[i] = f"{key}={value}{newline}"
            return "".join(lines)

    raise RotationError(f"ไม่พบบรรทัด {key} ใน .env")


def _has_env_key(text: str, key: str) -> bool:
    pattern = _env_key_pattern(key)
    return any(pattern.match(line) for line in text.splitlines())


def _connect(password: str, username: str | None = None) -> redis.Redis:

    config = {
        **REDIS_CONFIG,
        "password": password,
        "decode_responses": True,
        "socket_connect_timeout": 5,
        "socket_timeout": 5,
    }

    if username is not None:
        config["username"] = username

    return redis.Redis(**config)


def _acl_path(client: redis.Redis) -> str:

    try:
        value = (client.config_get("aclfile") or {}).get("aclfile", "")
    except redis.exceptions.RedisError:
        value = ""

    if not value:

        if not os.path.exists(FALLBACK_ACL_PATH):
            raise RotationError(
                "Redis ตัวนี้ไม่ได้ตั้งค่า aclfile — เปลี่ยนรหัสผ่านหน้านี้ไม่ได้ ต้องไปแก้ที่ redis.conf เอง"
            )
        return FALLBACK_ACL_PATH

    return value


def _reload_acl(password: str) -> bool:

    try:
        _connect(password).execute_command("ACL", "LOAD")
        return True
    except (redis.exceptions.RedisError, OSError) as e:
        print(f"[{LOG_PREFIX}] rollback: สั่ง ACL LOAD ไม่สำเร็จ — {e}")
        return False


def preflight() -> dict:

    username = REDIS_CONFIG.get("username") or "default"
    info = {"username": username, "acl_path": "", "env_path": ENV_PATH, "ok": False, "problem": ""}

    try:
        client = _connect(REDIS_CONFIG.get("password") or "")
        client.ping()

        acl_path = _acl_path(client)
        info["acl_path"] = acl_path

        lines = _read_text(acl_path, "ไฟล์ users.acl").splitlines()
        if _find_user_line(lines, username) == -1:
            raise RotationError(f"ไม่พบบรรทัดของ user {username} ใน {acl_path}")

        _require_writable(acl_path, "ไฟล์ users.acl")
        _require_writable(ENV_PATH, "ไฟล์ .env")

        if not _has_env_key(_read_text(ENV_PATH, "ไฟล์ .env"), ENV_KEY):
            raise RotationError(f"ไม่พบบรรทัด {ENV_KEY} ใน .env")

        info["ok"] = True

    except RotationError as e:
        info["problem"] = str(e)
    except redis.exceptions.AuthenticationError:
        info["problem"] = "รหัสใน .env ตอนนี้ใช้ล็อกอิน Redis ไม่ได้ — ต้องแก้ให้ต่อติดก่อน"
    except (redis.exceptions.RedisError, OSError) as e:
        info["problem"] = f"ต่อ Redis ไม่ได้: {e}"

    return info


def rotate_admin_password(new_password: str, typed_current: str) -> dict:

    username = REDIS_CONFIG.get("username") or "default"
    current_password = REDIS_CONFIG.get("password") or ""

    verify_current_password(typed_current)
    validate_password(new_password)

    if new_password == current_password:
        raise ValueError("รหัสใหม่ตรงกับรหัสเดิม")

    if not _LOCK.acquire(blocking=False):
        raise RotationError("มีการเปลี่ยนรหัสค้างอยู่ รอให้รอบก่อนหน้าทำงานจบก่อน")

    try:

        client = _connect(current_password)
        try:
            client.ping()
        except redis.exceptions.AuthenticationError as e:
            raise RotationError(
                f"รหัสปัจจุบันใน .env ใช้ล็อกอิน Redis ไม่ได้ ({ENV_KEY}) — แก้ให้ต่อติดก่อนถึงจะเปลี่ยนจากหน้านี้ได้"
            ) from e
        except (redis.exceptions.RedisError, OSError) as e:
            raise RotationError(f"ต่อ Redis ไม่ได้: {e}") from e

        acl_path = _acl_path(client)
        acl_text = _read_text(acl_path, "ไฟล์ users.acl")
        acl_lines = acl_text.splitlines()


        for line in acl_lines:
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "user" and re.fullmatch(r"agent_[0-9]+", parts[1]):
                if f">{new_password}" in parts[2:]:
                    raise ValueError("ห้ามใช้รหัสเดียวกับบัญชี Redis ของ Agent")

        line_index = _find_user_line(acl_lines, username)
        if line_index == -1:
            raise RotationError(f"ไม่พบบรรทัดของ user {username} ใน {acl_path}")

        _require_writable(acl_path, "ไฟล์ users.acl")
        _require_writable(ENV_PATH, "ไฟล์ .env")

        env_text = _read_text(ENV_PATH, "ไฟล์ .env")
        if not _has_env_key(env_text, ENV_KEY):
            raise RotationError(f"ไม่พบบรรทัด {ENV_KEY} ใน {ENV_PATH}")


        acl_backup = _backup(acl_path)
        acl_lines[line_index] = _rewrite_acl_line(acl_lines[line_index], new_password)
        _write_atomic(acl_path, "\n".join(acl_lines) + "\n")


        try:
            client.execute_command("ACL", "LOAD")
        except (redis.exceptions.RedisError, OSError) as e:

            _restore(acl_backup, acl_path)
            raise RotationError(
                f"Redis ไม่ยอมรับไฟล์ ACL ใหม่ ({e}) — คืนไฟล์เดิมให้แล้ว รหัสยังเป็นตัวเก่า ไม่มีอะไรเปลี่ยน"
            ) from e


        print(f"[{LOG_PREFIX}] ACL LOAD แล้ว — รหัสของ user {username} เปลี่ยนใน Redis เรียบร้อย")


        try:
            whoami = _connect(new_password).execute_command("ACL", "WHOAMI")
            if whoami != username:
                raise RotationError(f"ล็อกอินด้วยรหัสใหม่แล้วได้ user '{whoami}' ไม่ใช่ '{username}'")
        except RotationError:
            _restore(acl_backup, acl_path)
            _reload_acl(new_password)
            raise
        except (redis.exceptions.RedisError, OSError) as e:
            _restore(acl_backup, acl_path)
            rolled_back = _reload_acl(new_password)
            hint = (
                "คืนสถานะเดิมให้แล้ว รหัสยังเป็นตัวเก่า"
                if rolled_back else
                f"คืนไฟล์ {acl_path} เป็นของเดิมแล้ว แต่สั่ง ACL LOAD ซ้ำไม่ได้ — "
                "ต้อง sudo systemctl restart centralredis เพื่อให้ Redis อ่านไฟล์เดิมกลับเข้าไป"
            )
            raise RotationError(f"เปลี่ยนรหัสแล้วล็อกอินด้วยรหัสใหม่ไม่ได้ ({e}) — {hint}") from e


        try:
            env_backup = _backup(ENV_PATH)
            _write_atomic(ENV_PATH, _replace_env_value(env_text, ENV_KEY, new_password))
        except (OSError, RotationError) as e:

            _restore(acl_backup, acl_path)
            rolled_back = _reload_acl(new_password)
            hint = (
                "ถอยกลับเป็นรหัสเดิมให้แล้ว ไม่มีอะไรเปลี่ยน"
                if rolled_back else
                f"คืนไฟล์ {acl_path} แล้วแต่ ACL LOAD ไม่ผ่าน — ต้อง sudo systemctl restart centralredis"
            )
            raise RotationError(f"เขียน .env ไม่สำเร็จ ({e}) — {hint}") from e


        REDIS_CONFIG["password"] = new_password
        os.environ[ENV_KEY] = new_password
        reset_client()


        mark_env_applied()

        print(f"[{LOG_PREFIX}] เขียน .env และรีเซ็ต client ของ process นี้แล้ว")

        return {
            "username": username,
            "acl_path": acl_path,
            "acl_backup": os.path.basename(acl_backup),
            "env_backup": os.path.basename(env_backup),
        }

    finally:
        _LOCK.release()
