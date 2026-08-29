# เปลี่ยนรหัสผ่าน Redis ของจริงจากหน้า System Settings — ทั้งบัญชีของ central และของ agent

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
# เงื่อนไขรหัสอยู่ที่เดียว ใช้ร่วมกับช่องรหัสของ Client Server (ดู redis_password_rules.py)
from redis_password_rules import generate_password, validate_password
from service_status import mark_env_applied
from settings_cache import get_setting


LOG_PREFIX = "REDIS-PASSWD"

# รากของโปรเจกต์ = แม่ของ main/ (ไฟล์ทั้งสองที่ต้องแก้อยู่ที่ราก ไม่ใช่ใน main/)
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FALLBACK_ACL_PATH = os.path.join(REPO_ROOT, "redis", "users.acl")
ENV_PATH = os.path.join(REPO_ROOT, ".env")
ENV_KEY = "REDIS_PASS"

_LOCK = threading.Lock()


class RotationError(RuntimeError):
    """เปลี่ยนรหัสไม่สำเร็จ — ข้อความในนี้ถูกส่งไปโชว์บนหน้าเว็บตรง ๆ"""


# ── ยืนยันรหัสเดิม ────────────────────────────────────────────────────────

def verify_current_password(typed: str) -> None:
    # ให้แอดมินยืนยันรหัสที่ใช้อยู่ก่อนเปลี่ยน — กันการกดพลาดและกันคนที่ยืม session ที่เปิดค้างไว้
    current = REDIS_CONFIG.get("password") or ""

    if not hmac.compare_digest(typed.encode("utf-8"), current.encode("utf-8")):
        raise ValueError("รหัสเดิมไม่ถูกต้อง")


# ── อ่าน/เขียนไฟล์แบบกู้คืนได้ ────────────────────────────────────────────

def _read_text(path: str, what: str) -> str:
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        raise RotationError(f"อ่าน{what} ({path}) ไม่ได้: {e}") from e


def _require_writable(path: str, what: str) -> None:
    # เช็คสิทธิ์เขียนตั้งแต่ตอน pre-flight — ไม่งั้นจะไปพังตอนเขียน .env ซึ่งเป็นจังหวะที่
    if not os.access(path, os.W_OK):
        raise RotationError(f"เขียน{what} ({path}) ไม่ได้ — process นี้ไม่มีสิทธิ์เขียนไฟล์")

    folder = os.path.dirname(path) or "."
    if not os.access(folder, os.W_OK):
        raise RotationError(f"เขียนในโฟลเดอร์ {folder} ไม่ได้ — ต้องสร้างไฟล์ชั่วคราวตอนบันทึก")


def _write_atomic(path: str, content: str) -> None:
    # เขียนทับแบบ atomic (temp ในโฟลเดอร์เดียวกัน -> os.replace) — ไฟล์ปลายทางจะไม่มีสถานะ
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


def _backup(path: str) -> str:
    # สำเนาไฟล์เดิมไว้ข้าง ๆ ก่อนแก้ — ชื่อลงท้ายด้วยเวลา เหมือน users.acl.bak.* ที่เคยทำด้วยมือ
    dest = f"{path}.bak.{datetime.now():%Y%m%d%H%M%S}"
    shutil.copy2(path, dest)
    return dest


def _restore(backup_path: str, path: str) -> None:
    shutil.copy2(backup_path, path)


# ── จัดการบรรทัดใน users.acl ─────────────────────────────────────────────

def _find_user_line(lines: list[str], username: str) -> int:
    # หา index ของบรรทัด `user <username> ...` — คืน -1 ถ้าไม่เจอ
    found = [i for i, raw in enumerate(lines)
             if (parts := raw.split()) and len(parts) >= 2 and parts[0] == "user" and parts[1] == username]

    if len(found) > 1:
        rows = ", ".join(str(i + 1) for i in found)
        raise RotationError(f"users.acl มีบรรทัดของ user {username} ซ้ำกัน (บรรทัด {rows}) — แก้ให้เหลือบรรทัดเดียวก่อน")

    return found[0] if found else -1


def _is_password_token(token: str, index: int) -> bool:
    # token ที่เกี่ยวกับรหัสผ่านของ ACL: `>รหัส` (เพิ่ม) · `<รหัส` (ลบ) · `#hash` · `nopass`
    if index < 2:
        return False
    return token.startswith((">", "<", "#")) or token == "nopass"


def _rewrite_acl_line(line: str, new_password: str) -> str:
    # แทน token รหัสตัวแรกด้วย `>รหัสใหม่` แล้วทิ้ง token รหัสอื่นที่เหลือ (ถ้ามีหลายรหัส)
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
        # บรรทัดเดิมไม่มี token รหัสเลย (แปลก แต่เป็นไปได้) — เติมต่อท้ายชื่อ user
        out.insert(2, f">{new_password}")

    return " ".join(out)


# ── จัดการบรรทัดใน .env ──────────────────────────────────────────────────

def _env_key_pattern(key: str) -> re.Pattern:
    # รองรับทั้ง `KEY=`, `KEY =` และ `export KEY=` (ไฟล์นี้มีทั้งแบบเว้นวรรคและไม่เว้น)
    return re.compile(rf"^\s*(export\s+)?{re.escape(key)}\s*=")


def _replace_env_value(text: str, key: str, value: str) -> str:
    # แทนค่าในบรรทัดของ key นั้น โดยคงบรรทัดอื่นทั้งไฟล์ไว้เหมือนเดิมทุกตัวอักษร
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


# ── การเชื่อมต่อ ─────────────────────────────────────────────────────────

def _connect(password: str, username: str | None = None) -> redis.Redis:
    # client ชั่วคราวของงานนี้เท่านั้น — ไม่ใช้ตัวกลางจาก redis_client เพราะ
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
    # ถาม Redis เองว่า aclfile ชี้ไปไฟล์ไหน — ตรงกว่าเดาจาก path ในโปรเจกต์
    try:
        value = (client.config_get("aclfile") or {}).get("aclfile", "")
    except redis.exceptions.RedisError:
        value = ""

    if not value:
        # ไม่ได้ใช้ aclfile = แก้ไฟล์ไปก็ไม่มีผล (รหัสอยู่ใน redis.conf หรือตั้งผ่าน ACL SETUSER)
        if not os.path.exists(FALLBACK_ACL_PATH):
            raise RotationError(
                "Redis ตัวนี้ไม่ได้ตั้งค่า aclfile — เปลี่ยนรหัสผ่านหน้านี้ไม่ได้ ต้องไปแก้ที่ redis.conf เอง"
            )
        return FALLBACK_ACL_PATH

    return value


def _reload_acl(password: str) -> bool:
    # สั่ง ACL LOAD ด้วย connection ใหม่ — ใช้ตอน rollback (คืนไฟล์แล้วดันของในหน่วยความจำกลับ)
    try:
        _connect(password).execute_command("ACL", "LOAD")
        return True
    except (redis.exceptions.RedisError, OSError) as e:
        print(f"[{LOG_PREFIX}] rollback: สั่ง ACL LOAD ไม่สำเร็จ — {e}")
        return False


# ── ตรวจความพร้อมก่อนให้กดปุ่ม ───────────────────────────────────────────

def preflight() -> dict:
    # เช็คว่าเปลี่ยนรหัสผ่านหน้าเว็บได้ไหม โดย **ไม่แตะอะไรเลย** — หน้าเว็บเรียกตอนโหลด
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


# ── ตัวจริง ──────────────────────────────────────────────────────────────

def rotate_admin_password(new_password: str, typed_current: str) -> dict:
    # เปลี่ยนรหัสของ user admin ให้ครบวงจร — เป็นฟังก์ชัน sync (มี blocking IO) ให้ route
    username = REDIS_CONFIG.get("username") or "default"
    current_password = REDIS_CONFIG.get("password") or ""

    verify_current_password(typed_current)
    validate_password(new_password)

    if new_password == current_password:
        raise ValueError("รหัสใหม่ตรงกับรหัสเดิม")

    # บัญชี admin มีสิทธิ์ +@all ~* และไม่เคยออกไปกับ package ของ agent — ห้ามใช้รหัสร่วมกับ
    if new_password and new_password == get_setting("agent_redis_password"):
        raise ValueError(
            "ห้ามใช้รหัสเดียวกับ Redis Password ของ Client Server — บัญชี admin มีสิทธิ์เต็มเครื่อง "
            "ส่วนรหัสของ client ถูกแจกไปกับชุดติดตั้งทุกเครื่อง"
        )

    if not _LOCK.acquire(blocking=False):
        raise RotationError("มีการเปลี่ยนรหัสค้างอยู่ รอให้รอบก่อนหน้าทำงานจบก่อน")

    try:
        # ── 1) pre-flight: ต่อ Redis ได้จริง + ไฟล์ทั้งสองพร้อมให้แก้ ──────────
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

        line_index = _find_user_line(acl_lines, username)
        if line_index == -1:
            raise RotationError(f"ไม่พบบรรทัดของ user {username} ใน {acl_path}")

        _require_writable(acl_path, "ไฟล์ users.acl")
        _require_writable(ENV_PATH, "ไฟล์ .env")

        env_text = _read_text(ENV_PATH, "ไฟล์ .env")
        if not _has_env_key(env_text, ENV_KEY):
            raise RotationError(f"ไม่พบบรรทัด {ENV_KEY} ใน {ENV_PATH}")

        # ── 2) เขียน users.acl (สำรองก่อน) ───────────────────────────────────
        acl_backup = _backup(acl_path)
        acl_lines[line_index] = _rewrite_acl_line(acl_lines[line_index], new_password)
        _write_atomic(acl_path, "\n".join(acl_lines) + "\n")

        # ── 3) ACL LOAD — จุดที่ของจริงเปลี่ยน ───────────────────────────────
        try:
            client.execute_command("ACL", "LOAD")
        except (redis.exceptions.RedisError, OSError) as e:
            # LOAD ไม่ผ่าน = ของในหน่วยความจำไม่เปลี่ยนเลย คืนไฟล์อย่างเดียวก็กลับสู่สภาพเดิม
            _restore(acl_backup, acl_path)
            raise RotationError(
                f"Redis ไม่ยอมรับไฟล์ ACL ใหม่ ({e}) — คืนไฟล์เดิมให้แล้ว รหัสยังเป็นตัวเก่า ไม่มีอะไรเปลี่ยน"
            ) from e

        # ตั้งแต่บรรทัดนี้ไป: connection ของ admin ทั้งระบบถูกตัดแล้ว รวมถึง client ตัวข้างบน
        print(f"[{LOG_PREFIX}] ACL LOAD แล้ว — รหัสของ user {username} เปลี่ยนใน Redis เรียบร้อย")

        # ── 4) ตรวจว่ารหัสใหม่ล็อกอินได้จริง ก่อนไปแตะ .env ──────────────────
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

        # ── 5) เขียน .env ให้ service ที่เหลืออ่านตอน restart ────────────────
        try:
            env_backup = _backup(ENV_PATH)
            _write_atomic(ENV_PATH, _replace_env_value(env_text, ENV_KEY, new_password))
        except (OSError, RotationError) as e:
            # .env คือแหล่งความจริงของทั้ง 11 service — เขียนไม่ได้ก็ต้องถอย Redis กลับ
            _restore(acl_backup, acl_path)
            rolled_back = _reload_acl(new_password)
            hint = (
                "ถอยกลับเป็นรหัสเดิมให้แล้ว ไม่มีอะไรเปลี่ยน"
                if rolled_back else
                f"คืนไฟล์ {acl_path} แล้วแต่ ACL LOAD ไม่ผ่าน — ต้อง sudo systemctl restart centralredis"
            )
            raise RotationError(f"เขียน .env ไม่สำเร็จ ({e}) — {hint}") from e

        # ── 6) ให้ process นี้ (เว็บ) ใช้รหัสใหม่ต่อได้ทันที ─────────────────
        REDIS_CONFIG["password"] = new_password
        os.environ[ENV_KEY] = new_password
        reset_client()

        # บอก service_status ว่า process นี้รับค่าใหม่แล้ว ไม่งั้นแถบเตือน "ค้างรีสตาร์ต" จะนับ
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


# ── รหัสของฝั่ง agent (agent_node + default) ─────────────────────────────

# Filebeat ส่ง ACL username ไม่ได้ จึงเข้าเป็น user `default` เสมอ — รหัสของสองบัญชีนี้
FILEBEAT_USER = "default"


def agent_acl_users() -> list[str]:
    # ผู้ใช้ที่ต้องถูกเปลี่ยนรหัสพร้อมกัน — ชื่อของ agent_core ตั้งได้จากหน้า System Settings
    agent_user = get_setting("agent_redis_username") or "agent_node"
    return [agent_user] if agent_user == FILEBEAT_USER else [agent_user, FILEBEAT_USER]


def apply_agent_password(new_password: str) -> dict:
    # เขียนรหัสใหม่ลงบรรทัดของ agent ใน users.acl **ทั้งสองบัญชี** แล้วสั่ง ACL LOAD ให้เลย
    validate_password(new_password)

    admin_password = REDIS_CONFIG.get("password") or ""
    if new_password == admin_password:
        raise ValueError(
            "ห้ามใช้รหัสเดียวกับรหัส Redis ของ Central — บัญชี admin มีสิทธิ์เต็มเครื่อง "
            "ส่วนรหัสนี้ถูกแจกไปกับชุดติดตั้งทุกเครื่อง"
        )

    users = agent_acl_users()

    if not _LOCK.acquire(blocking=False):
        raise RotationError("มีการเปลี่ยนรหัสค้างอยู่ รอให้รอบก่อนหน้าทำงานจบก่อน")

    try:
        client = _connect(admin_password)
        try:
            client.ping()
        except (redis.exceptions.RedisError, OSError) as e:
            raise RotationError(f"ต่อ Redis ไม่ได้: {e}") from e

        acl_path = _acl_path(client)
        acl_lines = _read_text(acl_path, "ไฟล์ users.acl").splitlines()

        # หาบรรทัดให้ครบก่อนเขียนอะไรลงไฟล์ — ขาดบรรทัดไหนคือหยุดตั้งแต่ยังไม่แตะอะไร
        line_index = {}
        for user in users:
            index = _find_user_line(acl_lines, user)
            if index == -1:
                raise RotationError(f"ไม่พบบรรทัดของ user {user} ใน {acl_path}")
            line_index[user] = index

        _require_writable(acl_path, "ไฟล์ users.acl")

        acl_backup = _backup(acl_path)
        for user, index in line_index.items():
            acl_lines[index] = _rewrite_acl_line(acl_lines[index], new_password)
        _write_atomic(acl_path, "\n".join(acl_lines) + "\n")

        try:
            client.execute_command("ACL", "LOAD")
        except (redis.exceptions.RedisError, OSError) as e:
            # LOAD ไม่ผ่าน = ของในหน่วยความจำไม่เปลี่ยนเลย คืนไฟล์อย่างเดียวก็จบ
            _restore(acl_backup, acl_path)
            raise RotationError(
                f"Redis ไม่ยอมรับไฟล์ ACL ใหม่ ({e}) — คืนไฟล์เดิมให้แล้ว รหัสยังเป็นตัวเก่า"
            ) from e

        print(f"[{LOG_PREFIX}] ACL LOAD แล้ว — รหัสของ {', '.join(users)} เปลี่ยนใน Redis เรียบร้อย")

        # ตรวจว่าล็อกอินได้จริงทั้งสองบัญชี — ใช้ PING เพราะ ACL ของ agent ไม่มีสิทธิ์เรียก ACL WHOAMI
        for user in users:
            try:
                _connect(new_password, username=user).ping()
            except (redis.exceptions.RedisError, OSError) as e:
                _restore(acl_backup, acl_path)
                rolled_back = _reload_acl(admin_password)
                hint = (
                    "ถอยกลับเป็นรหัสเดิมให้แล้ว"
                    if rolled_back else
                    f"คืนไฟล์ {acl_path} แล้วแต่ ACL LOAD ไม่ผ่าน — ต้อง sudo systemctl restart centralredis"
                )
                raise RotationError(f"เปลี่ยนแล้วล็อกอินเป็น {user} ด้วยรหัสใหม่ไม่ได้ ({e}) — {hint}") from e

        return {
            "users": users,
            "acl_path": acl_path,
            "acl_backup": acl_backup,
        }

    finally:
        _LOCK.release()


def restore_agent_acl(acl_path: str, acl_backup: str) -> bool:
    # คืนไฟล์ ACL จากไฟล์สำรองแล้วสั่ง ACL LOAD — ใช้ตอนขั้นตอนหลัง apply_agent_password พัง
    try:
        _restore(acl_backup, acl_path)
    except OSError as e:
        print(f"[{LOG_PREFIX}] rollback: คืนไฟล์ {acl_path} ไม่สำเร็จ — {e}")
        return False

    return _reload_acl(REDIS_CONFIG.get("password") or "")
