# ตั้งรหัสผ่าน "ผู้ใช้ของ dashboard" ใหม่ตอนลืมรหัส — รันบนเครื่อง central ตรง ๆ ไม่ผ่านหน้าเว็บ
#
# หน้า Manage Users รีเซ็ตรหัสให้คนอื่นได้ก็จริง แต่ต้องมี admin ที่ล็อกอินอยู่แล้วเป็นคนกด
# ถ้าลืมรหัสของ admin คนสุดท้ายก็เข้าไม่ได้เลยทั้งระบบ ไฟล์นี้เขียนลงตาราง users ให้ตรง ๆ
# โดยใช้ **นโยบายรหัสผ่านและวิธี hash ชุดเดียวกับหน้าเว็บ** (password_policy + auth.hash_password)
# แก้ที่เดียวแล้วทั้งสองทางเปลี่ยนตาม ไม่มีทางหลุดจากกัน
#
# วิธีใช้ (บนเครื่อง central ด้วย venv ของโปรเจกต์):
#   venv/bin/python main/reset_dashboard_password.py --list
#   venv/bin/python main/reset_dashboard_password.py --user admin --generate
#   venv/bin/python main/reset_dashboard_password.py --user admin --password 'Abcd1234!' --yes
#   เติม --activate ถ้าบัญชีถูกปิดใช้งานไว้ · --unlock ถ้าลองรหัสผิดจนหน้า login ล็อก IP
#   · --no-force-change ถ้าไม่อยากให้ระบบบังคับเปลี่ยนรหัสตอนล็อกอินครั้งแรก
#
# **ไม่ต้องรีสตาร์ต service** — ตอน login ระบบอ่านรหัสจากฐานข้อมูลสดทุกครั้ง ไม่มี cache คั่น
# (ต่างจาก reset_redis_admin_password.py ที่แก้รหัส Redis แล้วต้องรีสตาร์ตทุกตัว)

import argparse
import asyncio
import getpass
import os
import secrets
import string
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import password_policy
from auth import hash_password
from database.connection import AsyncSessionLocal
from database.crud import get_all_users, get_user, set_user_active, set_user_password
from login_lockout import FAIL_KEY_PREFIX
from redis_client import get_redis


# ชุดอักขระของรหัสที่สุ่มให้ — ต้องครบทุกข้อของ password_policy (เล็ก/ใหญ่/เลข/อักขระพิเศษ)
GENERATE_LENGTH = 16
SYMBOLS = "!@#$%^&*-_=+"


def say(message: str = "") -> None:
    print(message, flush=True)


def generate_password() -> str:
    # สุ่มให้ครบทุกกลุ่มก่อนแล้วค่อยเติมที่เหลือ — แล้วตรวจซ้ำด้วยนโยบายจริงกันพลาด
    while True:
        pool = string.ascii_lowercase + string.ascii_uppercase + string.digits + SYMBOLS
        chars = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
            secrets.choice(SYMBOLS),
            *(secrets.choice(pool) for _ in range(GENERATE_LENGTH - 4)),
        ]
        secrets.SystemRandom().shuffle(chars)
        password = "".join(chars)

        if not password_policy.failed_rules(password):
            return password


# ── IP ที่โดนล็อกหน้า login ────────────────────────────────────────────────

def locked_ips() -> list[tuple[str, int, int]]:
    # ตัวนับ login ผิดเก็บเป็นคีย์ `login_fail:<ip>` ใน Redis — คืน (ip, จำนวนครั้ง, ttl)
    # client กลางของโปรเจกต์ไม่ได้ตั้ง decode_responses ทั้งคีย์และค่าจึงเป็น bytes ต้องแปลงเอง
    try:
        client = get_redis()
        rows = []
        for key in client.scan_iter(f"{FAIL_KEY_PREFIX}*", count=100):
            name = key if isinstance(key, str) else key.decode()
            value = client.get(name)
            rows.append((name[len(FAIL_KEY_PREFIX):], int(value) if value else 0, client.ttl(name)))
        return sorted(rows)
    except Exception as e:
        say(f"  (อ่านตัวนับ login ผิดจาก Redis ไม่ได้: {e})")
        return []


def unlock_all() -> int:
    # ล้างตัวนับของทุก IP — คนที่ลืมรหัสมักลองผิดจนโดนล็อกไปแล้วก่อนจะมาหาไฟล์นี้
    try:
        client = get_redis()
        keys = [k if isinstance(k, str) else k.decode()
                for k in client.scan_iter(f"{FAIL_KEY_PREFIX}*", count=100)]
        for key in keys:
            client.delete(key)
        return len(keys)
    except Exception as e:
        say(f"  ปลดล็อกไม่สำเร็จ (Redis: {e}) — รหัสใหม่ยังใช้ได้ รอให้ตัวนับหมดอายุเองก็ได้")
        return 0


# ── รายชื่อผู้ใช้ ─────────────────────────────────────────────────────────

async def show_list() -> int:
    async with AsyncSessionLocal() as db:
        users = await get_all_users(db)

    if not users:
        say("ไม่มีผู้ใช้สักคนในตาราง users — ระบบจะสร้าง admin/admin ให้เองตอน start ครั้งถัดไป")
        return 1

    say(f"ผู้ใช้ทั้งหมด {len(users)} คน")
    say(f"  {'id':>3}  {'username':<20} {'role':<10} {'สถานะ':<12} บังคับเปลี่ยนรหัส")
    for user in users:
        status = "ใช้งานอยู่" if user.is_active else "ปิดใช้งาน"
        force = "ใช่" if user.must_change_password else "-"
        say(f"  {user.id:>3}  {user.username:<20} {user.role:<10} {status:<12} {force}")

    rows = locked_ips()
    if rows:
        say()
        say("IP ที่กำลังโดนนับ/ล็อกจากการใส่รหัสผิด (ใช้ --unlock เพื่อล้าง):")
        for ip, count, ttl in rows:
            say(f"  {ip:<18} ผิดไป {count} ครั้ง · หมดอายุใน {ttl} วินาที")

    return 0


# ── ตัวจริง ───────────────────────────────────────────────────────────────

async def reset(username: str, new_password: str, assume_yes: bool,
                force_change: bool, activate: bool, unlock: bool) -> int:
    failed = password_policy.failed_rules(new_password)
    if failed:
        say(password_policy.error_detail(failed))
        return 1

    async with AsyncSessionLocal() as db:
        user = await get_user(db, username)

        if not user:
            say(f"ไม่พบผู้ใช้ชื่อ {username} — ดูรายชื่อทั้งหมดด้วย --list")
            return 1

        say()
        say("จะทำสิ่งนี้:")
        say(f"  ตั้งรหัสผ่านใหม่ให้ {user.username} (id={user.id}, role={user.role})")
        if force_change:
            say("  และบังคับให้เปลี่ยนรหัสเองตอนล็อกอินครั้งแรก")
        if not user.is_active:
            say("  บัญชีนี้ถูกปิดใช้งานอยู่ — " +
                ("จะเปิดให้ด้วย (--activate)" if activate else "ล็อกอินยังไม่ได้จนกว่าจะเปิด (ใส่ --activate)"))
        if unlock:
            say("  และล้างตัวนับ login ผิดของทุก IP")
        say()

        if not assume_yes:
            answer = input("ยืนยันหรือไม่ (พิมพ์ yes): ").strip().lower()
            if answer != "yes":
                say("ยกเลิก — ยังไม่มีอะไรถูกแก้")
                return 1

        await set_user_password(db, user, hash_password(new_password), must_change_password=force_change)
        say(f"ตั้งรหัสใหม่ให้ {user.username} แล้ว")

        if activate and not user.is_active:
            await set_user_active(db, user, True)
            say("เปิดใช้งานบัญชีนี้แล้ว")

    if unlock:
        say(f"ล้างตัวนับ login ผิดแล้ว {unlock_all()} IP")

    say()
    say(f"รหัสใหม่ของ {username}: {new_password}")
    if force_change:
        say("ล็อกอินด้วยรหัสนี้แล้วระบบจะให้ตั้งรหัสใหม่ทันที (รหัสนี้ใช้ได้ครั้งเดียว)")
    say("ใช้ได้เลยไม่ต้องรีสตาร์ตอะไร — หน้า login อ่านรหัสจากฐานข้อมูลสดทุกครั้ง")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ตั้งรหัสผ่านผู้ใช้ของ dashboard ใหม่ตอนลืมรหัส (รันบนเครื่อง central)",
    )
    parser.add_argument("--list", action="store_true", help="ดูรายชื่อผู้ใช้ + IP ที่โดนล็อก แล้วจบ")
    parser.add_argument("--user", help="username ที่จะตั้งรหัสใหม่ให้")
    parser.add_argument("--password", help="รหัสใหม่ (ไม่ใส่ทั้ง --password และ --generate จะถามให้พิมพ์)")
    parser.add_argument("--generate", action="store_true", help="สุ่มรหัสชั่วคราวให้")
    parser.add_argument("--activate", action="store_true", help="เปิดใช้งานบัญชีที่ถูกปิดไว้ด้วย")
    parser.add_argument("--unlock", action="store_true", help="ล้างตัวนับ login ผิดของทุก IP")
    parser.add_argument("--no-force-change", action="store_true",
                        help="ไม่ต้องบังคับเปลี่ยนรหัสตอนล็อกอินครั้งแรก")
    parser.add_argument("--yes", action="store_true", help="ข้ามคำถามยืนยัน")
    args = parser.parse_args()

    try:
        if args.list:
            return asyncio.run(show_list())

        if not args.user:
            parser.error("ต้องระบุ --user (หรือใช้ --list ดูรายชื่อก่อน)")

        if args.generate:
            new_password = generate_password()
        elif args.password:
            new_password = args.password
        else:
            new_password = getpass.getpass("รหัสใหม่: ")
            if new_password != getpass.getpass("พิมพ์อีกครั้ง: "):
                say("สองครั้งไม่ตรงกัน — ยกเลิก")
                return 1

        return asyncio.run(reset(
            args.user, new_password, args.yes,
            not args.no_force_change, args.activate, args.unlock,
        ))

    except KeyboardInterrupt:
        say()
        say("ยกเลิก")
        return 1


if __name__ == "__main__":
    sys.exit(main())
