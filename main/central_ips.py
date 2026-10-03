# ที่อยู่ของเครื่อง Central Server เอง — ห้ามใส่ลง blacklist (ทั้งจากหน้าเว็บและที่ detector สั่ง block เอง)
#
# ไม่เขียน IP ตายตัว อ่านสดจาก 3 แหล่ง เพราะ central ย้าย IP ได้ (setup-server.sh):
#   1) IP ทุกตัวบนการ์ดเครือข่ายของเครื่องตอนนี้ (รวม IP สำรองที่แปะไว้ระหว่างย้ายเครื่อง)
#   2) REDIS_HOST / AGENT_CENTRAL_HOST ใน .env — ที่อยู่ที่ agent ใช้ต่อเข้ามา
#   3) AGENT_CENTRAL_CANDIDATES ใน .env — ที่อยู่สำรองที่ agent อาจถอยกลับไปใช้ (รวมที่อยู่เดิมก่อนย้าย)
# ฝั่ง agent ก็มีรายการ "ไม่มีวัน block central" แบบเดียวกันอยู่แล้ว (agent_core.rebuild_never_block_nets)
# ที่นี่กันตั้งแต่ต้นทาง ไม่ให้หน้าเว็บแสดงว่า block ทั้งที่จริง agent ไม่ทำ
#
# อ่านใหม่ทุก ๆ CACHE_SECONDS — ย้าย IP แล้วตามไปเองโดยไม่ต้อง restart

import ipaddress
import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from dotenv import dotenv_values

from ip_match import parse_entry

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
CACHE_SECONDS = 30
CENTRAL_IP_DETAIL = "IP นี้เป็นของ Central Server"

_cache: tuple[float, frozenset] = (0.0, frozenset())


def _host_of(entry: str) -> str:
    # "192.168.56.119:6381" -> "192.168.56.119" · ไม่มีพอร์ตก็คืนตามเดิม
    entry = entry.strip().strip('"')
    if entry.count(":") == 1:
        entry = entry.split(":", 1)[0]
    return entry.strip("[]")


def _interface_ips() -> set:
    ip_cmd = shutil.which("ip") or "/usr/sbin/ip"
    try:
        out = subprocess.run([ip_cmd, "-j", "addr"], capture_output=True, text=True, timeout=3).stdout
        ifaces = json.loads(out or "[]")
    except Exception as e:
        print(f"[CENTRAL-IP] อ่าน IP ของเครื่องไม่ได้: {e}")
        return set()
    return {a.get("local") for i in ifaces for a in i.get("addr_info", []) if a.get("local")}


def _env_ips() -> set:
    try:
        env = dotenv_values(ENV_PATH) if ENV_PATH.exists() else {}
    except Exception:
        env = {}
    get = lambda k: (env.get(k) or os.getenv(k) or "").strip()
    found = {_host_of(get("REDIS_HOST")), _host_of(get("AGENT_CENTRAL_HOST"))}
    found |= {_host_of(x) for x in get("AGENT_CENTRAL_CANDIDATES").replace(",", " ").split()}
    return found


def central_addresses() -> frozenset:
    global _cache
    now = time.monotonic()
    if now - _cache[0] < CACHE_SECONDS:
        return _cache[1]

    addrs = set()
    for raw in _interface_ips() | _env_ips():
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            continue  # ชื่อโดเมน/ค่าว่าง — เทียบกับ IP ที่ถูกสั่ง block ไม่ได้อยู่แล้ว
        if not ip.is_loopback and not ip.is_link_local:
            addrs.add(ip)

    _cache = (now, frozenset(addrs))
    return _cache[1]


def is_central_ip(value) -> bool:
    # True ถ้าค่านี้คือ/ครอบ IP ของ central (รับได้ทั้ง IP เดี่ยวและช่วง CIDR)
    net = parse_entry(value)
    if net is None:
        return False
    return any(ip.version == net.version and ip in net for ip in central_addresses())
