

import os
import subprocess
import time
from datetime import datetime, timezone

from shared import iso_utc


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_PATH = os.path.join(REPO_ROOT, ".env")


UNIT_GLOB = "securelog-*.service"
WEB_UNIT = "securelog-web.service"
TARGET_UNIT = "securelog.target"

SYSTEMCTL_TIMEOUT = 5


_env_applied_at = time.time()


def mark_env_applied() -> None:

    global _env_applied_at
    _env_applied_at = time.time()


def _iso(epoch: float) -> str:

    naive_utc = datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None)
    return iso_utc(naive_utc) or ""


def _monotonic_to_epoch(usec: int) -> float:

    return (time.time() - time.monotonic()) + usec / 1_000_000


def _query_units() -> list[dict]:

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

        info["restart_command"] = (
            f"sudo systemctl restart {TARGET_UNIT}"
            if len(pending) == len(info["units"])
            else "sudo systemctl restart " + " ".join(pending)
        )

    return info
