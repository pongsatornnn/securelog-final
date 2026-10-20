


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

    net = parse_entry(value)
    if net is None:
        return False
    return any(ip.version == net.version and ip in net for ip in central_addresses())
