"""
บอกว่า service ตัวไหน "ยังรันด้วยค่าเก่า" หลัง `.env` ถูกแก้ — ใช้กับแถบเตือนในหน้า System Settings

**ทำไมไม่เก็บธง "ค้างรีสตาร์ต" ไว้ที่ไหนสักที่:**
ธงต้องมีคนมาล้าง ถ้าลืมล้าง (หรือ Redis ที่เก็บธงถูกล้างเอง) สถานะจะโกหกทันที — ที่นี่จึง
**คำนวณจากของจริงทุกครั้ง**: เทียบ "เวลาที่ unit เริ่มทำงาน" กับ "mtime ของ .env"
ตัวไหนเริ่ม *ก่อน* ไฟล์ถูกแก้ = process นั้นยังถือค่าเก่าที่อ่านไว้ตอน import อยู่แน่นอน

ผลพลอยได้: ใช้ได้กับการแก้ `.env` ทุกกรณี ไม่ใช่แค่ตอนเปลี่ยนรหัส Redis (แก้ DB_PASSWORD
หรือ JWT_SECRET ด้วยมือแล้วลืมรีสตาร์ต ก็ขึ้นเตือนเหมือนกัน)

`systemctl show` เป็นคำสั่งอ่านอย่างเดียว **ไม่ต้องใช้ root** (ต่างจาก restart) — จงใจไม่ให้
เว็บสั่งรีสตาร์ตเอง เพราะนั่นต้องเปิดสิทธิ์ sudo ถาวรให้ process ที่รับ request จากภายนอก
"""

import os
import subprocess
import time
from datetime import datetime, timezone

from shared import iso_utc


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(REPO_ROOT, ".env")

# ชื่อ unit ทั้งหมดมาจาก systemd/_gen.sh (ขึ้นต้น securelog- เสมอ) — ใช้ glob จะได้ไม่ต้องไล่แก้
# ที่นี่ทุกครั้งที่เพิ่ม service ใหม่ · centralredis ไม่รวมด้วยเพราะไม่ได้อ่าน .env
UNIT_GLOB = "securelog-*.service"
WEB_UNIT = "securelog-web.service"
TARGET_UNIT = "securelog.target"

SYSTEMCTL_TIMEOUT = 5

# process นี้อ่าน .env เข้าหน่วยความจำตอน import — ค่าที่ถืออยู่จึง "สดถึง" เวลานี้
_env_applied_at = time.time()


def mark_env_applied() -> None:
    """
    เรียกเมื่อ process นี้เขียน .env แล้ว **อัปเดตค่าในหน่วยความจำตามไปด้วยแล้ว**
    (ตอนนี้มีที่เดียวคือ redis_admin_password ซึ่งตั้ง REDIS_CONFIG/os.environ ใหม่ + reset client)
    ถ้าไม่บอก ตัวเว็บเองจะขึ้นเตือนว่าต้องรีสตาร์ตทั้งที่เพิ่งใช้ค่าใหม่ไปแล้ว
    """
    global _env_applied_at
    _env_applied_at = time.time()


def _iso(epoch: float) -> str:
    """epoch -> string เดียวกับที่ทั้งระบบส่งให้ frontend (UTC ลงท้าย Z ผ่าน shared.iso_utc)"""
    naive_utc = datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    return iso_utc(naive_utc) or ""


def _monotonic_to_epoch(usec: int) -> float:
    """
    systemd ให้เวลาเริ่ม unit เป็น monotonic (ไมโครวินาทีตั้งแต่ boot) — แปลงเป็น epoch
    ด้วยฐานเดียวกับ time.monotonic() ของ Python (CLOCK_MONOTONIC ทั้งคู่บน Linux)
    เลี่ยงการ parse ActiveEnterTimestamp ที่รูปแบบขึ้นกับ locale/timezone ของเครื่อง
    """
    return (time.time() - time.monotonic()) + usec / 1_000_000


def _query_units() -> list[dict]:
    """ถาม systemd ตรง ๆ — คืน list ว่างถ้าไม่มี unit ตรง glob (เช่นเครื่อง dev ที่ยังไม่ได้ติดตั้ง)"""
    result = subprocess.run(
        ["systemctl", "show", UNIT_GLOB, "--no-pager",
         "--property=Id", "--property=ActiveState", "--property=SubState",
         "--property=ActiveEnterTimestampMonotonic"],
        capture_output=True, text=True, timeout=SYSTEMCTL_TIMEOUT,
    )

    units = []
    for block in result.stdout.strip().split("\n\n"):
        fields = dict(
            line.split("=", 1) for line in block.splitlines() if "=" in line
        )
        if fields.get("Id"):
            units.append(fields)

    return units


def restart_status() -> dict:
    """
    สรุปว่าตอนนี้มี service ไหนต้องรีสตาร์ตบ้าง — ปลอดภัยที่จะเรียกบ่อย (อ่านอย่างเดียวทั้งหมด)

    คืน ok=False พร้อม problem เมื่อ "ตรวจไม่ได้" (ไม่มี systemctl / unit ยังไม่ติดตั้ง / อ่าน .env
    ไม่ได้) — ฝั่งหน้าเว็บถือว่าไม่มีข้อมูล ไม่ใช่ถือว่าทุกอย่างปกติ
    """
    info = {
        "ok": False,
        "problem": "",
        "env_changed_at": "",
        "checked_at": _iso(time.time()),
        "units": [],
        "pending_count": 0,
        "restart_command": "",
    }

    try:
        env_mtime = os.path.getmtime(ENV_PATH)
    except OSError as e:
        info["problem"] = f"อ่านเวลาแก้ไขล่าสุดของ .env ไม่ได้: {e}"
        return info

    info["env_changed_at"] = _iso(env_mtime)

    try:
        raw_units = _query_units()
    except FileNotFoundError:
        info["problem"] = "เครื่องนี้ไม่มีคำสั่ง systemctl — ตรวจสถานะ service ไม่ได้"
        return info
    except subprocess.TimeoutExpired:
        info["problem"] = f"systemctl ไม่ตอบกลับใน {SYSTEMCTL_TIMEOUT} วินาที"
        return info
    except OSError as e:
        info["problem"] = f"เรียก systemctl ไม่สำเร็จ: {e}"
        return info

    if not raw_units:
        info["problem"] = f"ไม่พบ unit ที่ตรงกับ {UNIT_GLOB} (ยังไม่ได้ติดตั้ง systemd unit?)"
        return info

    for fields in raw_units:
        unit = fields["Id"]
        active = fields.get("ActiveState") == "active" and fields.get("SubState") == "running"
        started_at = _monotonic_to_epoch(int(fields.get("ActiveEnterTimestampMonotonic") or 0))

        # ตัวเว็บ (process นี้) เทียบกับเวลาที่ "รับค่าใหม่เข้าหน่วยความจำ" ไม่ใช่เวลาที่ unit start
        # เพราะเปลี่ยนรหัส Redis จากหน้าเว็บแล้วมันอัปเดตตัวเองทันทีโดยไม่ต้องรีสตาร์ต
        fresh_since = max(started_at, _env_applied_at) if unit == WEB_UNIT else started_at
        stale = env_mtime > fresh_since

        if not active:
            reason = f"ไม่ได้ทำงาน ({fields.get('ActiveState', '?')}/{fields.get('SubState', '?')})"
        elif stale:
            reason = "เริ่มทำงานก่อน .env ถูกแก้ — ยังถือค่าเก่าอยู่"
        else:
            reason = ""

        info["units"].append({
            "unit": unit,
            "label": unit.removeprefix("securelog-").removesuffix(".service"),
            "active": active,
            "started_at": _iso(started_at) if started_at > 0 else "",
            "stale": stale,
            "needs_restart": bool(reason),
            "reason": reason,
        })

    info["units"].sort(key=lambda u: (not u["needs_restart"], u["unit"]))

    pending = [u["unit"] for u in info["units"] if u["needs_restart"]]
    info["pending_count"] = len(pending)
    info["ok"] = True

    if pending:
        # ค้างทั้งหมด = สั่งทีเดียวที่ target สั้นกว่า · ค้างบางตัว = ระบุชื่อ จะได้ไม่ไปแตะตัวที่ปกติ
        info["restart_command"] = (
            f"sudo systemctl restart {TARGET_UNIT}"
            if len(pending) == len(info["units"])
            else "sudo systemctl restart " + " ".join(pending)
        )

    return info
