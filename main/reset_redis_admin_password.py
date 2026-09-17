# กู้รหัส Redis ของ user admin ตอน "ลืมรหัสเดิม" — รันบนเครื่อง central ตรง ๆ ไม่ผ่านหน้าเว็บ
#
# ปุ่มเปลี่ยนรหัสในหน้า System Settings ใช้ได้ก็ต่อเมื่อ "พิมพ์รหัสเดิมถูก" และเว็บยังต่อ Redis ติด
# ไฟล์นี้คือทางออกตอนสองข้อนั้นไม่จริงแล้ว: เขียนรหัสใหม่ลง users.acl + .env ให้ แล้วดันเข้า Redis
# โดยใช้ **เงื่อนไขรหัสชุดเดียวกับหน้าเว็บ** (redis_password_rules) และวิธีเขียน/สำรองไฟล์ชุดเดียว
# กับปุ่มนั้น (redis_admin_password) — แก้เงื่อนไขที่เดียวแล้วทั้งสองทางเปลี่ยนตาม ไม่หลุดจากกัน
#
# วิธีใช้ (บนเครื่อง central ด้วย venv ของโปรเจกต์ และ **user เดียวกับที่รัน service**):
#   venv/bin/python main/reset_redis_admin_password.py --check          ดูสถานะอย่างเดียว ไม่แตะอะไร
#   venv/bin/python main/reset_redis_admin_password.py --generate       สุ่มรหัสใหม่ให้
#   venv/bin/python main/reset_redis_admin_password.py --password 'รหัสใหม่'
#   เติม --yes เพื่อข้ามคำถามยืนยัน · เติม --restart ให้สั่งรีสตาร์ต service ต่อให้เลย
#
# ทำอะไรบ้าง: สำรอง users.acl + .env -> เขียนรหัสใหม่ทั้งสองไฟล์ -> สั่ง ACL LOAD ด้วยรหัสเก่าที่
# ยังใช้ล็อกอินได้ (อ่านจาก .env เดิม/ไฟล์ acl เดิม) ถ้าไม่มีสักตัวก็ต้องรีสตาร์ต Redis แทน
# -> ตรวจว่ารหัสใหม่ล็อกอินได้จริง -> บอกให้รีสตาร์ต service ที่เหลือ

import argparse
import getpass
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import redis

from redis_config import REDIS_CONFIG
from redis_password_rules import generate_password, validate_password
# ใช้ตัวช่วยชุดเดียวกับปุ่มบนหน้าเว็บ (ขึ้นต้นด้วย _ เพราะเป็นของภายในโมดูลนั้น แต่จงใจใช้ซ้ำ
# ตรงนี้ — ถ้าลอกมาเขียนใหม่ วันหนึ่งสองทางนี้จะเขียนไฟล์คนละแบบแล้วหาสาเหตุกันไม่เจอ)
from redis_admin_password import (
    ENV_KEY,
    ENV_PATH,
    FALLBACK_ACL_PATH,
    RotationError,
    _backup,
    _connect,
    _find_user_line,
    _read_text,
    _replace_env_value,
    _restore,
    _rewrite_acl_line,
    _write_atomic,
    _has_env_key,
)


REDIS_UNIT = "centralredis"
SERVICES_UNIT = "securelog.target"


def say(message: str = "") -> None:
    print(message, flush=True)


def mask(password: str) -> str:
    # โชว์พอให้เทียบได้ว่าใช่ตัวเดียวกับที่จดไว้ไหม โดยไม่พ่นรหัสเต็มลง log ที่อาจถูกเก็บไว้
    if len(password) <= 8:
        return "*" * len(password)
    return f"{password[:4]}…{password[-2:]} ({len(password)} ตัว)"


# ── หาไฟล์และรหัสที่ยังใช้ได้ ────────────────────────────────────────────

def resolve_acl_path(given: str | None) -> str:
    # ปกติถาม Redis ว่า aclfile อยู่ไหนดีที่สุด แต่ตอนลืมรหัสก็ถามไม่ได้ — ไล่จากที่ผู้ใช้บอก
    # -> ที่เดียวกับที่ปุ่มบนหน้าเว็บใช้ -> ถามจาก Redis ถ้าบังเอิญรหัสใน .env ยังใช้ได้
    if given:
        if not os.path.exists(given):
            raise RotationError(f"ไม่พบไฟล์ ACL ตามที่ระบุ: {given}")
        return given

    env_password = REDIS_CONFIG.get("password") or ""
    if env_password:
        try:
            client = _connect(env_password)
            client.ping()
            value = (client.config_get("aclfile") or {}).get("aclfile", "")
            if value:
                return value
        except (redis.exceptions.RedisError, OSError):
            pass

    if os.path.exists(FALLBACK_ACL_PATH):
        return FALLBACK_ACL_PATH

    raise RotationError(
        f"หาไฟล์ users.acl ไม่เจอ (ดูที่ {FALLBACK_ACL_PATH} แล้ว) — ระบุเองด้วย --acl-file"
    )


def acl_passwords(line: str) -> list[str]:
    # รหัสแบบ plaintext ที่เขียนไว้ในบรรทัดนั้น (`>รหัส`) — ของที่ Redis ถืออยู่ตอนนี้ก็ตัวนี้
    # แปลว่า "ลืมรหัส" ส่วนใหญ่แก้ได้โดยไม่ต้องรีสตาร์ต Redis เลย เพราะรหัสเดิมอ่านได้จากไฟล์
    return [token[1:] for i, token in enumerate(line.split())
            if i >= 2 and token.startswith(">") and len(token) > 1]


def first_working_password(candidates: list[str], username: str) -> str | None:
    # ลองล็อกอินด้วยรหัสที่พอจะเป็นไปได้ — ตัวแรกที่ผ่านคือตัวที่สั่ง ACL LOAD ได้
    seen = set()
    for password in candidates:
        if not password or password in seen:
            continue
        seen.add(password)
        try:
            _connect(password, username=username).ping()
            return password
        except (redis.exceptions.RedisError, OSError):
            continue
    return None


# ── เขียนไฟล์โดยไม่ทำสิทธิ์เจ้าของเพี้ยน ─────────────────────────────────

def write_keeping_owner(path: str, content: str) -> None:
    # _write_atomic คงเฉพาะ "โหมด" ของไฟล์ ไม่ได้คงเจ้าของ — ถ้าเผลอรันด้วย sudo ไฟล์จะกลาย
    # เป็นของ root แล้ว service ที่รันด้วย user ธรรมดาอ่านไม่ได้ (ทั้งที่รหัสถูกทุกอย่าง)
    info = os.stat(path)
    _write_atomic(path, content)

    if os.geteuid() == 0 and (info.st_uid, info.st_gid) != (0, 0):
        os.chown(path, info.st_uid, info.st_gid)


def systemctl(*args: str) -> bool:
    command = list(args) if os.geteuid() == 0 else ["sudo", *args]
    say(f"  รัน: {' '.join(command)}")

    try:
        result = subprocess.run(command, timeout=120)
    except (OSError, subprocess.TimeoutExpired) as e:
        say(f"  สั่งไม่สำเร็จ: {e}")
        return False

    return result.returncode == 0


# ── รายงานสถานะ (--check) ────────────────────────────────────────────────

def check(acl_path: str, username: str) -> int:
    env_password = REDIS_CONFIG.get("password") or ""

    say(f"  user ของ central     : {username}")
    say(f"  ไฟล์ ACL             : {acl_path}")
    say(f"  ไฟล์ .env            : {ENV_PATH}")
    say(f"  เขียน ACL ได้ไหม      : {'ได้' if os.access(acl_path, os.W_OK) else 'ไม่ได้ (ต้องรันด้วย user เจ้าของไฟล์)'}")
    say(f"  เขียน .env ได้ไหม     : {'ได้' if os.access(ENV_PATH, os.W_OK) else 'ไม่ได้ (ต้องรันด้วย user เจ้าของไฟล์)'}")

    lines = _read_text(acl_path, "ไฟล์ users.acl").splitlines()
    index = _find_user_line(lines, username)
    say(f"  บรรทัด user {username} : {'บรรทัดที่ ' + str(index + 1) if index != -1 else 'ไม่พบ !!'}")

    if index == -1:
        return 1

    in_file = acl_passwords(lines[index])
    say(f"  รหัสในไฟล์ ACL        : {'อ่านได้ (plaintext) ' + mask(in_file[0]) if in_file else 'เป็น #hash หรือไม่มี — กู้แบบไม่รีสตาร์ต Redis ไม่ได้'}")
    say(f"  รหัสใน .env          : {mask(env_password) if env_password else 'ไม่มีค่า'}")

    working = first_working_password([env_password, *in_file], username)
    if working is None:
        say("  ล็อกอิน Redis ตอนนี้  : ไม่ได้เลยสักตัว — เปลี่ยนรหัสได้อยู่ แต่ต้องรีสตาร์ต Redis ให้โหลดไฟล์ใหม่")
    elif working == env_password:
        say("  ล็อกอิน Redis ตอนนี้  : ได้ด้วยรหัสใน .env (ระบบยังปกติดี — เปลี่ยนจากหน้าเว็บก็ได้)")
    else:
        say("  ล็อกอิน Redis ตอนนี้  : ได้ด้วยรหัสที่อ่านจากไฟล์ ACL (.env ไม่ตรงกับ Redis)")

    return 0


# ── ตัวจริง ──────────────────────────────────────────────────────────────

def reset(acl_path: str, username: str, new_password: str, assume_yes: bool, do_restart: bool) -> int:
    lines = _read_text(acl_path, "ไฟล์ users.acl").splitlines()

    index = _find_user_line(lines, username)
    if index == -1:
        raise RotationError(f"ไม่พบบรรทัดของ user {username} ใน {acl_path}")

    env_text = _read_text(ENV_PATH, "ไฟล์ .env")
    if not _has_env_key(env_text, ENV_KEY):
        raise RotationError(f"ไม่พบบรรทัด {ENV_KEY} ใน {ENV_PATH}")

    # รหัสของบัญชีอื่นในไฟล์เดียวกัน = รหัสฝั่ง agent ที่ถูกแจกไปกับชุดติดตั้งทุกเครื่อง
    # บัญชี admin มีสิทธิ์ +@all ~* ห้ามใช้รหัสร่วมกันเด็ดขาด (หน้าเว็บก็กันข้อนี้เหมือนกัน)
    others = [password
              for i, line in enumerate(lines) if i != index
              for password in acl_passwords(line)]
    if new_password in others:
        raise RotationError("รหัสนี้ถูกใช้เป็นรหัสของบัญชีอื่นใน users.acl อยู่แล้ว (รหัสฝั่ง agent) — ห้ามใช้ซ้ำ")

    env_password = REDIS_CONFIG.get("password") or ""
    old_passwords = acl_passwords(lines[index])

    say()
    say("จะทำสิ่งนี้:")
    say(f"  เปลี่ยนรหัสของ user {username} ใน {acl_path}")
    say(f"  เขียน {ENV_KEY} ใน {ENV_PATH}")
    say(f"  รหัสใหม่: {mask(new_password)}")
    say()

    if not assume_yes:
        answer = input("ยืนยันหรือไม่ (พิมพ์ yes): ").strip().lower()
        if answer != "yes":
            say("ยกเลิก — ยังไม่มีอะไรถูกแก้")
            return 1

    # ── เขียนไฟล์ (สำรองก่อนทั้งคู่) ─────────────────────────────────────
    acl_backup = _backup(acl_path)
    lines[index] = _rewrite_acl_line(lines[index], new_password)
    write_keeping_owner(acl_path, "\n".join(lines) + "\n")
    say(f"เขียน {os.path.basename(acl_path)} แล้ว (สำรองไว้ที่ {os.path.basename(acl_backup)})")

    try:
        env_backup = _backup(ENV_PATH)
        write_keeping_owner(ENV_PATH, _replace_env_value(env_text, ENV_KEY, new_password))
    except (OSError, RotationError) as e:
        _restore(acl_backup, acl_path)
        raise RotationError(f"เขียน .env ไม่สำเร็จ ({e}) — คืนไฟล์ ACL เป็นตัวเดิมแล้ว ไม่มีอะไรเปลี่ยน") from e

    say(f"เขียน .env แล้ว (สำรองไว้ที่ {os.path.basename(env_backup)})")

    # ── ดันเข้า Redis ────────────────────────────────────────────────────
    # ไฟล์ใหม่ยังไม่มีผลจนกว่า Redis จะอ่าน — ใช้รหัสเก่าที่ยังล็อกอินได้สั่ง ACL LOAD
    # (ตอนนี้ของในหน่วยความจำยังเป็นรหัสเก่าอยู่ จึงยังต่อได้) ไม่มีสักตัวค่อยรีสตาร์ต Redis
    say()
    say("ให้ Redis อ่านไฟล์ใหม่:")
    working = first_working_password([env_password, *old_passwords], username)

    if working:
        try:
            _connect(working, username=username).execute_command("ACL", "LOAD")
            say("  สั่ง ACL LOAD ด้วยรหัสเดิมสำเร็จ — ไม่ต้องรีสตาร์ต Redis")
        except (redis.exceptions.RedisError, OSError) as e:
            _restore(acl_backup, acl_path)
            _restore(env_backup, ENV_PATH)
            raise RotationError(f"Redis ไม่ยอมรับไฟล์ ACL ใหม่ ({e}) — คืนไฟล์เดิมทั้งสองให้แล้ว ไม่มีอะไรเปลี่ยน") from e
    else:
        say("  ล็อกอินด้วยรหัสเดิมไม่ได้เลย — ต้องให้ Redis อ่าน aclfile ใหม่ตอนเริ่มทำงาน")
        if not do_restart:
            say(f"  ยังไม่ได้รีสตาร์ตให้ (ไม่ได้ใส่ --restart) — สั่งเองด้วย: sudo systemctl restart {REDIS_UNIT}")
            say(f"  แล้วตามด้วย: sudo systemctl restart {SERVICES_UNIT}")
            say()
            say(f"รหัสใหม่: {new_password}")
            return 2

        if not systemctl("systemctl", "restart", REDIS_UNIT):
            raise RotationError(f"รีสตาร์ต {REDIS_UNIT} ไม่สำเร็จ — ไฟล์ถูกเขียนใหม่แล้ว สั่งรีสตาร์ตเองแล้วรหัสใหม่จะมีผล")

    # ── ตรวจว่ารหัสใหม่ใช้ได้จริง ────────────────────────────────────────
    try:
        whoami = _connect(new_password, username=username).execute_command("ACL", "WHOAMI")
    except (redis.exceptions.RedisError, OSError) as e:
        raise RotationError(
            f"เขียนไฟล์ครบแล้วแต่ล็อกอินด้วยรหัสใหม่ไม่ได้ ({e}) — ไฟล์สำรองอยู่ที่ "
            f"{os.path.basename(acl_backup)} / {os.path.basename(env_backup)}"
        ) from e

    if whoami != username:
        raise RotationError(f"ล็อกอินด้วยรหัสใหม่แล้วได้ user '{whoami}' ไม่ใช่ '{username}'")

    say(f"  ล็อกอินด้วยรหัสใหม่ผ่าน (ACL WHOAMI = {whoami})")

    # ── service ที่เหลือยังถือรหัสเก่าในหน่วยความจำ ──────────────────────
    say()
    if do_restart:
        say("รีสตาร์ต service ที่เหลือให้รับรหัสใหม่:")
        if systemctl("systemctl", "restart", SERVICES_UNIT):
            say("  เรียบร้อย")
        else:
            say(f"  ไม่สำเร็จ — สั่งเองด้วย: sudo systemctl restart {SERVICES_UNIT}")
    else:
        say(f"ขั้นต่อไป: sudo systemctl restart {SERVICES_UNIT}")
        say("  (service ทุกตัวอ่าน .env ตอนเริ่มทำงาน ยังถือรหัสเก่าอยู่จนกว่าจะรีสตาร์ต)")

    say()
    say(f"รหัสใหม่: {new_password}")
    say("เก็บไว้ให้ดี — ไฟล์นี้ไม่ได้จดไว้ที่ไหนนอกจาก .env กับ users.acl")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="กู้รหัส Redis ของ user admin เมื่อลืมรหัสเดิม (รันบนเครื่อง central)",
    )
    parser.add_argument("--password", help="รหัสใหม่ที่จะตั้ง (ไม่ใส่ทั้ง --password และ --generate จะถามให้พิมพ์)")
    parser.add_argument("--generate", action="store_true", help="สุ่มรหัสใหม่ให้")
    parser.add_argument("--acl-file", help="ระบุ path ของ users.acl เอง (ปกติหาเจอเอง)")
    parser.add_argument("--check", action="store_true", help="ดูสถานะอย่างเดียว ไม่แก้อะไร")
    parser.add_argument("--yes", action="store_true", help="ข้ามคำถามยืนยัน")
    parser.add_argument("--restart", action="store_true", help=f"สั่ง systemctl restart {SERVICES_UNIT} ต่อให้เลย")
    args = parser.parse_args()

    username = REDIS_CONFIG.get("username") or "default"

    try:
        acl_path = resolve_acl_path(args.acl_file)

        if args.check:
            return check(acl_path, username)

        if args.generate:
            new_password = generate_password()
        elif args.password:
            new_password = args.password
        else:
            new_password = getpass.getpass("รหัสใหม่: ")
            if new_password != getpass.getpass("พิมพ์อีกครั้ง: "):
                say("สองครั้งไม่ตรงกัน — ยกเลิก")
                return 1

        # เงื่อนไขเดียวกับหน้า System Settings เป๊ะ ๆ (ยาว 12-128 · อักขระที่ใช้ได้ · ไม่ซ้ำตัวเดิมเกินไป)
        validate_password(new_password)

        return reset(acl_path, username, new_password, args.yes, args.restart)

    except ValueError as e:
        say(f"รหัสใหม่ใช้ไม่ได้: {e}")
        return 1
    except RotationError as e:
        say(f"ไม่สำเร็จ: {e}")
        return 1
    except KeyboardInterrupt:
        say()
        say("ยกเลิก")
        return 1


if __name__ == "__main__":
    sys.exit(main())
