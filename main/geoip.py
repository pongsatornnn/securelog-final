# หาประเทศของ IP จากไฟล์ฐานข้อมูล GeoIP แบบ offline (DB-IP Lite Country, รูปแบบ .mmdb)
# ใช้เติมธงประเทศข้าง Attacker IP ในหน้า Alerts / Dashboard
#
# ไม่ส่ง IP ออกไปถาม service ภายนอก — อ่านจากไฟล์บนเครื่อง central ล้วน ๆ
# ไฟล์อยู่ที่ main/database/geoip/dbip-country-lite.mmdb (โหลด/อัปเดตด้วย update_geoip.sh เดือนละครั้ง)
# ไม่มีไฟล์ หรือยังไม่ได้ลง maxminddb -> คืน None เงียบ ๆ หน้าเว็บแค่ไม่โชว์ธง ระบบไม่ล้ม
#
# ข้อมูล IP โดย DB-IP (https://db-ip.com) — สัญญาอนุญาต CC BY 4.0

import ipaddress
import os
import time
from functools import lru_cache
from pathlib import Path

try:
    import maxminddb
except ImportError:  # ยังไม่ได้ pip install maxminddb — _get_reader ลอง import ใหม่เป็นระยะ
    maxminddb = None

# ลงไลบรารีทีหลังได้โดยไม่ต้อง restart (setup-server.sh ข้อ 3) — ลอง import ใหม่ไม่ถี่กว่านี้
IMPORT_RETRY_SECONDS = 60
_next_import_try = 0.0


GEOIP_DB_PATH = Path(
    os.getenv("GEOIP_DB_PATH")
    or Path(__file__).resolve().parent / "database" / "geoip" / "dbip-country-lite.mmdb"
)

# IP ภายในองค์กร/ทดสอบ — ไม่มีประเทศ แสดงเป็น "เครือข่ายภายใน" แทน
PRIVATE_COUNTRY = {"code": None, "name": "เครือข่ายภายใน", "private": True}

_reader = None
_reader_mtime: float | None = None


def _get_reader():
    # เปิดไฟล์ครั้งแรกที่ใช้ และเปิดใหม่เองเมื่อไฟล์ถูกอัปเดต (mtime เปลี่ยน) ไม่ต้อง restart service
    global _reader, _reader_mtime, maxminddb, _next_import_try

    if maxminddb is None:
        if time.monotonic() < _next_import_try:
            return None
        _next_import_try = time.monotonic() + IMPORT_RETRY_SECONDS
        try:
            import importlib
            importlib.invalidate_caches()  # ให้เห็น package ที่เพิ่งลงระหว่างที่ process รันอยู่
            maxminddb = importlib.import_module("maxminddb")
        except ImportError:
            return None

    try:
        mtime = GEOIP_DB_PATH.stat().st_mtime
    except OSError:
        return None

    if _reader is None or mtime != _reader_mtime:
        try:
            new_reader = maxminddb.open_database(str(GEOIP_DB_PATH))
        except Exception as e:
            print(f"[GEOIP] เปิดไฟล์ {GEOIP_DB_PATH} ไม่ได้: {e}")
            return None

        if _reader is not None:
            _reader.close()
        _reader, _reader_mtime = new_reader, mtime
        _lookup_cached.cache_clear()

    return _reader


@lru_cache(maxsize=4096)
def _lookup_cached(ip: str) -> dict | None:
    reader = _reader
    if reader is None:
        return None

    try:
        record = reader.get(ip)
    except (ValueError, maxminddb.InvalidDatabaseError):
        return None

    country = (record or {}).get("country") or {}
    code = country.get("iso_code")
    if not code:
        return None

    return {
        "code": code,
        "name": (country.get("names") or {}).get("en") or code,
        "private": False,
    }


def lookup_country(ip: str | None) -> dict | None:
    # คืน {"code": "TH", "name": "Thailand", "private": False}
    #   หรือ PRIVATE_COUNTRY ถ้าเป็น IP ภายใน · None ถ้าไม่รู้ (IP ผิดรูปแบบ / ไม่มีไฟล์ / ไม่อยู่ในฐานข้อมูล)
    if not ip:
        return None

    try:
        addr = ipaddress.ip_address(str(ip).strip())
    except ValueError:
        return None

    if not addr.is_global:
        return dict(PRIVATE_COUNTRY)

    if _get_reader() is None:
        return None

    found = _lookup_cached(str(addr))
    return dict(found) if found else None
