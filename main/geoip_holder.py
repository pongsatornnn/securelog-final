


import gzip
import ipaddress
import json
import os
import sys
import time
from array import array
from bisect import bisect_right
from pathlib import Path

HOLDER_DB_PATH = Path(
    os.getenv("GEOIP_HOLDER_PATH")
    or Path(__file__).resolve().parent / "database" / "geoip" / "holder-country.txt.gz"
)
NAMES_PATH = Path(__file__).resolve().parent / "database" / "country_names.json"


STATUS_TEXT = {
    "s": "ได้รับ IP ตรงจากผู้ดูแล IP",   # assigned — ผู้ใช้ปลายทางได้ไปเอง
    "a": "ได้รับผ่านผู้ให้บริการ (ISP/hosting)",  # allocated — ISP ได้ไปแบ่งต่อ
}

CHECK_SECONDS = 60  # เช็คว่าไฟล์ถูกอัปเดตไหม ไม่ถี่กว่านี้


REGION_CODES = {"EU", "AP"}

_names: dict | None = None
_table = None          # (v4_start, v4_end, v4_meta, v6_start, v6_end, v6_meta, metas)
_table_mtime: float | None = None
_next_check = 0.0


def build(sources: list[str], dest: str) -> int:
    rows = []
    for src in sources:
        with open(src, encoding="utf-8", errors="replace") as f:
            for line in f:
                p = line.strip().split("|")

                if len(p) < 7 or line.startswith("#") or p[1] == "*" or p[3] == "*":
                    continue
                kind, cc, status = p[2], p[1].upper(), p[6]
                if kind not in ("ipv4", "ipv6") or status not in ("allocated", "assigned"):
                    continue  # available / reserved = ยังไม่มีผู้ถือ
                if len(cc) != 2 or not cc.isalpha():
                    continue
                try:
                    start = ipaddress.ip_address(p[3])
                    value = int(p[4])
                except ValueError:
                    continue
                st = "s" if status == "assigned" else "a"
                if kind == "ipv4":
                    s = int(start)
                    rows.append((4, s, s + value - 1, cc, st))
                else:

                    s = int(start) >> 64
                    rows.append((6, s, s + (1 << (64 - value)) - 1 if value <= 64 else s, cc, st))

    rows.sort()
    merged = []
    for r in rows:
        last = merged[-1] if merged else None

        if last and last[0] == r[0] and last[3] == r[3] and last[4] == r[4] and r[1] <= last[2] + 1:
            merged[-1] = (last[0], last[1], max(last[2], r[2]), last[3], last[4])
        else:
            merged.append(r)

    tmp = dest + ".tmp"
    with gzip.open(tmp, "wt", encoding="ascii") as out:
        for fam, s, e, cc, st in merged:
            out.write(f"{fam} {s:x} {e:x} {cc} {st}\n")
    os.replace(tmp, dest)
    return len(merged)


def _load():
    v4s, v4e, v4m = array("L"), array("L"), array("H")
    v6s, v6e, v6m = array("Q"), array("Q"), array("H")
    metas, meta_idx = [], {}
    with gzip.open(HOLDER_DB_PATH, "rt", encoding="ascii") as f:
        for line in f:
            fam, s, e, cc, st = line.split()
            key = (cc, st)
            if key not in meta_idx:
                meta_idx[key] = len(metas)
                metas.append(key)
            if fam == "4":
                v4s.append(int(s, 16)); v4e.append(int(e, 16)); v4m.append(meta_idx[key])
            else:
                v6s.append(int(s, 16)); v6e.append(int(e, 16)); v6m.append(meta_idx[key])
    return (v4s, v4e, v4m, v6s, v6e, v6m, metas)


def _get_table():

    global _table, _table_mtime, _next_check
    now = time.monotonic()
    if _table is not None and now < _next_check:
        return _table
    _next_check = now + CHECK_SECONDS
    try:
        mtime = HOLDER_DB_PATH.stat().st_mtime
    except OSError:
        return _table  # ไฟล์หายระหว่างทาง — ใช้ของที่โหลดไว้ต่อ (หรือ None ถ้าไม่เคยมี)
    if _table is None or mtime != _table_mtime:
        try:
            _table, _table_mtime = _load(), mtime
        except Exception as e:
            print(f"[GEOIP-HOLDER] เปิดไฟล์ {HOLDER_DB_PATH} ไม่ได้: {e}")
    return _table


def _country_name(code: str) -> str:
    global _names
    if _names is None:
        try:
            _names = json.loads(NAMES_PATH.read_text(encoding="utf-8"))
        except Exception:
            _names = {}
    return _names.get(code, code)


def lookup_holder_country(ip: str | None) -> dict | None:

    if not ip:
        return None
    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None
    if not addr.is_global:
        return None  # IP ภายใน — ไม่มีผู้ถือในทะเบียนสาธารณะ

    table = _get_table()
    if table is None:
        return None
    v4s, v4e, v4m, v6s, v6e, v6m, metas = table

    if addr.version == 4:
        key, starts, ends, meta = int(addr), v4s, v4e, v4m
    else:
        key, starts, ends, meta = int(addr) >> 64, v6s, v6e, v6m

    i = bisect_right(starts, key) - 1
    if i < 0 or key > ends[i]:
        return None

    code, st = metas[meta[i]]
    return {
        "code": code,
        "name": _country_name(code),
        "status": st,
        "status_text": STATUS_TEXT.get(st, ""),
        "region": code in REGION_CODES,
    }


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "build":
        n = build(sys.argv[2:-1], sys.argv[-1])
        print(f"สร้างตารางประเทศผู้ถือ IP แล้ว: {n} ช่วง -> {sys.argv[-1]}")
    else:
        print("ใช้: python3 geoip_holder.py build <delegated ...> <ปลายทาง.txt.gz>", file=sys.stderr)
        sys.exit(2)
