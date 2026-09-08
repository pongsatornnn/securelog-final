import redis
import json
import psutil
import socket
import threading
import time
import subprocess
import os
import sys
import ipaddress
import hashlib
import hmac
import shutil
import tempfile
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------

# ค่า default เฉพาะ site — ปกติถูก override ด้วย agent_config.json (สร้างโดย setup.sh)
_DEFAULT_CONFIG = {
    "central_host": "192.168.56.110",
    "central_port": 6380,
    "redis_username": "agent_node",
    "redis_password": "123",
    # ที่อยู่สำรองของ central — agent ไล่ลองทีละอันเมื่อ central_host เดิมต่อไม่ได้
    "central_candidates": [],
}

CONFIG_FILE_NAME = "agent_config.json"


def _read_kv_file(path: Path) -> dict:
    # อ่านไฟล์ KEY=VALUE (agent_info.txt) — ไฟล์ไม่มี/บรรทัดเสีย ข้ามเงียบ ๆ
    info = {}
    try:
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if "=" in line and not line.startswith("#"):
                key, _, value = line.partition("=")
                info[key.strip()] = value.strip()
    except OSError:
        pass
    return info


def _load_config() -> dict:
    config = dict(_DEFAULT_CONFIG)
    try:
        with open(BASE_DIR / "agent_config.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            config.update(data)
    except (OSError, json.JSONDecodeError):
        pass
    return config


def _find_cert(filename: str) -> str:
    # หาไฟล์ cert: cert/ ก่อน (โครงหลัง setup.sh) แล้วค่อยข้างไฟล์นี้ (โครงจาก zip ดิบ)
    for candidate in (BASE_DIR / "cert" / filename, BASE_DIR / filename):
        if candidate.exists():
            return str(candidate)
    return str(BASE_DIR / "cert" / filename)


_INFO = _read_kv_file(BASE_DIR / "agent_info.txt")
_CONFIG = _load_config()

AGENT_ID = _INFO.get("AGENT_ID", "")
SECRET_TOKEN = _INFO.get("SECRET_TOKEN", "")

CENTRAL_HOST = str(_CONFIG["central_host"])
CENTRAL_PORT = int(_CONFIG["central_port"])
REDIS_USERNAME = str(_CONFIG["redis_username"])
REDIS_PASSWORD = str(_CONFIG["redis_password"])

AGENT_CERT_FILE = _find_cert(_INFO.get("CERT_FILE", f"{AGENT_ID}.crt"))
AGENT_KEY_FILE = _find_cert(_INFO.get("KEY_FILE", f"{AGENT_ID}.key"))
CA_CERT_FILE = _find_cert(_INFO.get("CA_FILE", "ca.crt"))

# interface ที่ใช้เป็นแหล่งของ IP เครื่องนี้ — เลือกตอนรัน setup.sh (setup.sh เขียนลง
HOST_IFACE = str(_CONFIG.get("host_iface") or "")

METRICS_INTERVAL_SECONDS = 1
RECONNECT_DELAY_SECONDS = 5

# ต่อ endpoint ปัจจุบันไม่ติดกี่ครั้งติดกันถึงจะเริ่มไล่ลองที่อยู่สำรอง (5 วิ/ครั้ง)
FAILOVER_AFTER_FAILURES = 2

# timeout ตอนทดสอบว่าที่อยู่ใหม่ของ central ใช้ได้จริงไหม (วินาที)
PROBE_TIMEOUT_SECONDS = 5

# ตัวเฝ้าสาย: ตรวจทุกกี่วินาที และเงียบจาก central นานแค่ไหนถึงถือว่าสายตาย
# (กรณี central หายไปเฉย ๆ TCP ฝั่งเราจะค้างอยู่แบบไม่มี error — ต้องมีคนคอยสะกิด)
LINK_CHECK_SECONDS = 10
LINK_SILENCE_SECONDS = 30

# เก็บที่อยู่ central ได้มากสุดกี่ที่ (รวมตัวที่ใช้อยู่) — ที่อยู่จากคำสั่ง central_move ที่เก่าที่สุด
# จะถูกทิ้งก่อนเมื่อเกิน เพื่อไม่ให้รายการยาวขึ้นเรื่อย ๆ ทุกครั้งที่ประกาศย้าย
MAX_ENDPOINTS = 5

# คำสั่ง central_move ที่ออกเกินเวลานี้ถือว่าหมดอายุ (กัน replay ข้อความเก่า)
MOVE_MAX_AGE_SECONDS = 900

# ไฟล์ config ของ Filebeat ที่ต้องแก้ปลายทางตามเมื่อ central ย้าย
FILEBEAT_CONFIG_FILE = "/etc/filebeat/filebeat.yml"

# อ่าน IP ใหม่ทุกกี่วินาที — ไม่อ่านทุกรอบ metrics (ทุก 1 วิ) เพราะ IP เครื่องแทบไม่เปลี่ยน
HOST_IP_REFRESH_SECONDS = 30

MANAGED_DIR = str(BASE_DIR / "state")
MANAGED_BLACKLIST_FILE = f"{MANAGED_DIR}/central_blacklist.json"
MANAGED_WHITELIST_FILE = f"{MANAGED_DIR}/central_whitelist.json"

# nonce ของคำสั่ง central_move ที่รับไปแล้ว — กันข้อความเดิมถูกส่งซ้ำ
SEEN_NONCE_FILE = f"{MANAGED_DIR}/seen_move_nonces.json"
SEEN_NONCE_LIMIT = 200
UFW_COMMENT = "central_blacklist"

# ---------------------------------------------------------------------------
# ที่อยู่ของ central: ตัวที่ใช้อยู่ + ตัวสำรอง
#
# central เปลี่ยน IP หรือย้ายเครื่องได้โดย agent ไม่ต้องลงใหม่ — ที่อยู่ใหม่เข้ามา 2 ทาง
#   1) คำสั่ง central_move ที่เซ็นด้วย secret token ของ agent ตัวนี้ (ส่งก่อนย้ายจริง)
#   2) ที่อยู่สำรองที่ใส่ไว้ตั้งแต่ตอนติดตั้ง (central_candidates ใน agent_config.json)
# ทุกที่อยู่ต้องผ่าน mTLS ด้วย CA เดิมก่อนถึงจะถูกใช้จริง (probe_endpoint)


def _norm_endpoint(host, port=None) -> tuple[str, int] | None:
    host = str(host or "").strip()

    if not host:
        return None

    try:
        port = int(port if port is not None else CENTRAL_PORT)
    except (TypeError, ValueError):
        return None

    if not 1 <= port <= 65535:
        return None

    return (host, port)


def _endpoints_from_config(config: dict) -> tuple[list[tuple[str, int]], dict]:
    # คืน (รายการที่อยู่, ที่มาของแต่ละที่อยู่) — ที่มา "setup" คือมาจากชุดติดตั้ง ไม่ทิ้งเวลารายการล้น
    result = []
    sources = {}

    def push(host, port, source="setup"):
        endpoint = _norm_endpoint(host, port)

        if endpoint and endpoint not in result:
            result.append(endpoint)
            sources[endpoint] = source

    push(config.get("central_host"), config.get("central_port"))

    for item in config.get("central_candidates") or []:
        if isinstance(item, dict):
            push(item.get("host"), item.get("port"), item.get("source") or "setup")
        elif isinstance(item, str):
            # รูปแบบสั้น "host" หรือ "host:port"
            host, _, port = item.rpartition(":")
            push(host or item, port if host else None)

    return result, sources


_ENDPOINTS, _ENDPOINT_SOURCES = _endpoints_from_config(_CONFIG)

_link_lock = threading.RLock()
_link = {
    "endpoints": _ENDPOINTS or [(CENTRAL_HOST, CENTRAL_PORT)],
    "sources": _ENDPOINT_SOURCES,
    # generation — ขยับทุกครั้งที่เปลี่ยนที่อยู่ ใช้บอก thread ที่ค้างอยู่ให้ต่อใหม่
    "gen": 0,
}


def active_endpoint() -> tuple[str, int]:
    with _link_lock:
        return _link["endpoints"][0]


def known_endpoints() -> list[tuple[str, int]]:
    with _link_lock:
        return list(_link["endpoints"])


def link_generation() -> int:
    with _link_lock:
        return _link["gen"]


def endpoint_text(endpoint: tuple[str, int]) -> str:
    return f"{endpoint[0]}:{endpoint[1]}"


# ---------------------------------------------------------------------------

def save_config_updates(updates: dict) -> bool:
    # เขียนทับเฉพาะคีย์ที่ส่งมา คีย์อื่นใน agent_config.json คงไว้ (เขียนแบบ atomic)
    path = BASE_DIR / CONFIG_FILE_NAME

    try:
        data = {}

        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                loaded = json.load(f)

            if isinstance(loaded, dict):
                data = loaded

        data.update(updates)

        fd, tmp_path = tempfile.mkstemp(dir=str(BASE_DIR), prefix=".agent_config.")

        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")

        os.chmod(tmp_path, 0o600)
        os.replace(tmp_path, path)
        return True

    except (OSError, json.JSONDecodeError) as e:
        print(f"[CONFIG] เขียน {CONFIG_FILE_NAME} ไม่ได้: {e}")
        return False


def persist_endpoints() -> None:
    with _link_lock:
        endpoints = list(_link["endpoints"])
        sources = dict(_link["sources"])

    save_config_updates({
        "central_host": endpoints[0][0],
        "central_port": endpoints[0][1],
        "central_candidates": [
            {"host": host, "port": port, "source": sources.get((host, port), "setup")}
            for host, port in endpoints[1:]
        ],
    })


def _prune_endpoints() -> None:
    # เรียกใต้ _link_lock เท่านั้น — ตัดที่อยู่ที่มาจากคำสั่งย้าย (เก่าสุดก่อน) จนเหลือไม่เกินที่กำหนด
    # ที่อยู่จากคำสั่งย้ายเรียงใหม่สุดไว้หน้า ตัวเก่าสุดจึงเป็นตัวท้ายสุดของกลุ่ม
    while len(_link["endpoints"]) > MAX_ENDPOINTS:
        victim = next(
            (e for e in reversed(_link["endpoints"][1:]) if _link["sources"].get(e) == "announce"),
            None,
        )

        if victim is None:
            return

        _link["endpoints"].remove(victim)
        _link["sources"].pop(victim, None)
        print(f"[LINK] รายการที่อยู่เต็ม ทิ้งที่อยู่เก่าจากคำสั่งย้าย: {endpoint_text(victim)}")


# รายการ IP/subnet ที่ agent จะ "ไม่มีวัน block" ไม่ว่า central จะสั่งมาหรือไม่
# (ที่อยู่ของ central ทุกตัวที่รู้จักถูกเติมให้อัตโนมัติใน rebuild_never_block_nets)
NEVER_BLOCK_CIDRS = [
    "127.0.0.0/8",
    # "192.168.56.1",  # <- ใส่ IP เครื่อง admin/gateway ที่ใช้ SSH เข้ามาที่นี่ด้วย
]

# address พิเศษของทราฟฟิก broadcast (0.0.0.0 = เครื่องที่ยังไม่ได้ IP เช่นตอนขอ DHCP,
ALWAYS_NEVER_BLOCK_CIDRS = [
    "0.0.0.0/32",
    "255.255.255.255/32",
]

_NEVER_BLOCK_NETS = []


def rebuild_never_block_nets() -> None:
    # เรียกใหม่ทุกครั้งที่รายการที่อยู่ central เปลี่ยน — กัน agent เผลอ block central ตัวเอง
    nets = []

    central_hosts = [host for host, _ in known_endpoints()]

    for entry in ALWAYS_NEVER_BLOCK_CIDRS + NEVER_BLOCK_CIDRS + central_hosts:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            # central_host ที่เป็นชื่อโดเมนตกมาทางนี้ — ไม่ใช่ IP ก็ข้ามไป ไม่ต้องเตือน
            if entry not in central_hosts:
                print(f"[CONFIG] NEVER_BLOCK_CIDRS entry ผิดรูป ข้าม: {entry}")

    global _NEVER_BLOCK_NETS
    _NEVER_BLOCK_NETS = nets


rebuild_never_block_nets()


# ---------------------------------------------------------------------------


def list_interface_ips() -> dict[str, str]:
    # {ชื่อ interface: IPv4} ของทุก interface ที่มี IPv4 (ข้าม loopback)
    result = {}

    for name, addrs in psutil.net_if_addrs().items():
        if name == "lo":
            continue

        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address:
                result[name] = addr.address
                break

    return result


def detect_outbound_ip() -> str | None:
    # IP ของ interface ที่ใช้ออกไปหา central จริง — ใช้เป็น fallback ตอนไม่ได้ระบุ interface ไว้
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(active_endpoint())
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def get_host_ip() -> str | None:
    # IP ปัจจุบันของเครื่องนี้ตาม interface ที่เลือกไว้ — None ถ้าหาไม่ได้
    if HOST_IFACE:
        # ระบุ interface ไว้แล้วต้องใช้ตัวนั้นเท่านั้น — สายหลุด/ยังไม่ได้ IP แล้วเงียบ ๆ ไป
        return list_interface_ips().get(HOST_IFACE)

    return detect_outbound_ip()


_host_ip_cache = {"ip": None, "at": 0.0}


def get_host_ip_cached() -> str | None:
    # เหมือน get_host_ip() แต่ไม่อ่านซ้ำถี่กว่า HOST_IP_REFRESH_SECONDS
    now = time.time()

    if now - _host_ip_cache["at"] >= HOST_IP_REFRESH_SECONDS:
        _host_ip_cache["ip"] = get_host_ip()
        _host_ip_cache["at"] = now

    return _host_ip_cache["ip"]


# redis-py 6 ขึ้นไปตั้ง retry อัตโนมัติ 3 ครั้งพร้อม backoff — connect timeout 5 วิกลายเป็นเกือบนาที
# กว่าจะรู้ว่าต่อไม่ได้ ที่นี่มีลูป reconnect ของตัวเองอยู่แล้ว จึงปิด retry ให้ล้มเร็วตามที่ตั้งไว้จริง
try:
    from redis.retry import Retry
    from redis.backoff import NoBackoff

    _NO_RETRY = {"retry": Retry(NoBackoff(), 0), "retry_on_error": []}
except ImportError:
    _NO_RETRY = {}


def create_redis(host: str | None = None, port: int | None = None, timeout: int | None = None):
    if host is None or port is None:
        host, port = active_endpoint()

    return redis.Redis(
        host=host,
        port=port,
        ssl=True,
        ssl_certfile=AGENT_CERT_FILE,
        ssl_keyfile=AGENT_KEY_FILE,
        ssl_ca_certs=CA_CERT_FILE,
        username=REDIS_USERNAME,
        password=REDIS_PASSWORD,
        ssl_check_hostname=True,
        socket_connect_timeout=timeout or 10,
        socket_timeout=timeout or 15,
        socket_keepalive=True,
        health_check_interval=15,
        **_NO_RETRY,
    )


def tcp_reachable(host: str, port: int) -> bool:
    # เคาะ TCP เปล่า ๆ ก่อนด้วย timeout ของเราเอง — ที่อยู่ที่ยังไม่มีเครื่องอยู่จริงจะได้รู้ผลใน
    # ไม่กี่วินาที ไม่ต้องรอ redis-py ลองใหม่หลายรอบ (ตอนนั้น thread คำสั่งจะค้างไปด้วย)
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT_SECONDS):
            return True
    except OSError as e:
        print(f"[LINK] เคาะ {host}:{port} ไม่ติด: {e}")
        return False


def probe_endpoint(host: str, port: int) -> bool:
    # ที่อยู่ใหม่ "ใช้ได้จริง" = ต่อ TLS ผ่าน (cert ต้องออกโดย CA ใบเดิมและครอบ IP นี้)
    # + ล็อกอินด้วยบัญชี ACL เดิมผ่าน + ping ตอบ — ปลอมไม่ได้ถ้าไม่มี key ของ CA
    if not tcp_reachable(host, port):
        return False

    r = None

    try:
        r = create_redis(host, port, timeout=PROBE_TIMEOUT_SECONDS)
        return bool(r.ping())

    except Exception as e:
        print(f"[LINK] ทดสอบ {host}:{port} ไม่ผ่าน: {e}")
        return False

    finally:
        try:
            if r:
                r.close()
        except Exception:
            pass


def allow_outbound_in_ufw(host: str, port: int) -> None:
    # เปิดขาออกไปหา central ตัวใหม่ใน ufw — ถ้าเครื่องนี้ไม่มี ufw ก็ข้ามไปเงียบ ๆ
    if not shutil.which("ufw"):
        return

    try:
        subprocess.run(
            [
                "ufw", "allow", "out", "to", host,
                "port", str(port), "proto", "tcp",
                "comment", "SecureLog agent -> central Redis",
            ],
            capture_output=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[LINK] เปิดขาออก ufw ไปหา {host}:{port} ไม่ได้: {e}")


def update_filebeat_endpoint(host: str, port: int) -> bool:
    # ชี้ output.redis ของ Filebeat ไปที่ central ตัวใหม่ แล้ว restart ให้ทันที
    path = FILEBEAT_CONFIG_FILE

    if not os.path.exists(path):
        print(f"[LINK] ไม่พบ {path} — ข้ามการแก้ Filebeat")
        return False

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as e:
        print(f"[LINK] อ่าน {path} ไม่ได้: {e}")
        return False

    in_output = False
    changed = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        if not stripped or stripped.startswith("#"):
            continue

        # ออกจากบล็อก output.redis เมื่อเจอคีย์ที่ระดับบนสุดอีกอัน
        if not line[:1].isspace():
            in_output = stripped.startswith("output.redis")
            continue

        if in_output and stripped.startswith("hosts:"):
            indent = line[: len(line) - len(line.lstrip())]
            new_line = f'{indent}hosts: ["{host}:{port}"]\n'

            if new_line != line:
                lines[i] = new_line
                changed = True

            break

    if not changed:
        return False

    try:
        shutil.copyfile(path, f"{path}.securelog.bak")

        with open(path, "w", encoding="utf-8") as f:
            f.writelines(lines)

    except OSError as e:
        print(f"[LINK] เขียน {path} ไม่ได้: {e}")
        return False

    print(f"[LINK] ชี้ Filebeat ไปที่ {host}:{port} แล้ว")

    try:
        subprocess.run(
            ["systemctl", "restart", "filebeat"],
            capture_output=True,
            timeout=60,
            check=False,
        )
        print("[LINK] restart filebeat แล้ว")
    except (OSError, subprocess.SubprocessError) as e:
        print(f"[LINK] restart filebeat ไม่ได้: {e}")

    return True


def add_endpoint(host: str, port: int, source: str = "announce") -> bool:
    # เพิ่ม/เลื่อนลำดับที่อยู่สำรอง (ยังไม่สลับไปใช้) — คืน True ถ้าเป็นที่อยู่ใหม่จริง ๆ
    endpoint = _norm_endpoint(host, port)

    if not endpoint:
        return False

    with _link_lock:
        known = endpoint in _link["endpoints"]

        # รู้จักอยู่แล้วและไม่ต้องเลื่อนลำดับอะไร
        if known and (source != "announce" or _link["endpoints"][0] == endpoint):
            return False

        if known:
            _link["endpoints"].remove(endpoint)

        # ที่อยู่ที่ central เพิ่งประกาศ = ที่ที่ central อยากให้ไปอยู่ ต่อไม่ติดเมื่อไหร่ให้ลองอันนี้ก่อน
        # (ไม่งั้น agent จะไปเกาะที่อยู่เก่าอันไหนก็ได้ที่บังเอิญยังตอบอยู่ แล้วคนสั่งย้ายจะงง)
        if source == "announce":
            _link["endpoints"].insert(1, endpoint)
        else:
            _link["endpoints"].append(endpoint)

        _link["sources"][endpoint] = source
        _prune_endpoints()

    rebuild_never_block_nets()
    persist_endpoints()
    allow_outbound_in_ufw(*endpoint)

    if known:
        print(f"[LINK] เลื่อน {endpoint_text(endpoint)} ขึ้นเป็นที่อยู่สำรองอันดับแรก")
        return False

    print(f"[LINK] เพิ่มที่อยู่สำรองของ central: {endpoint_text(endpoint)}")
    return True


def switch_endpoint(host: str, port: int) -> bool:
    # ย้ายไปใช้ที่อยู่นี้เป็นตัวหลัก — ที่อยู่เดิมยังถูกเก็บไว้เป็นตัวสำรอง (เผื่อย้ายกลับ)
    endpoint = _norm_endpoint(host, port)

    if not endpoint:
        return False

    with _link_lock:
        if _link["endpoints"][0] == endpoint:
            return False

        previous = _link["endpoints"][0]
        remaining = [e for e in _link["endpoints"] if e != endpoint]
        _link["endpoints"] = [endpoint] + remaining
        _link["gen"] += 1

    rebuild_never_block_nets()
    persist_endpoints()
    allow_outbound_in_ufw(*endpoint)
    update_filebeat_endpoint(*endpoint)

    print(
        f"[LINK] ย้าย central จาก {endpoint_text(previous)} "
        f"ไป {endpoint_text(endpoint)} เรียบร้อย"
    )
    return True


# connection ที่เปิดอยู่ตอนนี้ (thread ละอัน) — ตัวเฝ้าสายต้องปิดมันเพื่อปลุก thread ที่ค้างอยู่
_clients = {}
_clients_lock = threading.Lock()
_last_contact = {"at": time.time()}


def note_link_ok() -> None:
    _last_contact["at"] = time.time()


def register_client(label: str, client) -> None:
    with _clients_lock:
        _clients[label] = client


def unregister_client(label: str) -> None:
    with _clients_lock:
        _clients.pop(label, None)


def drop_all_connections() -> None:
    # ปิด socket ใต้ client ทุกตัว — thread ที่ค้างรออ่านอยู่จะเด้ง exception แล้ววนไปต่อใหม่เอง
    with _clients_lock:
        clients = list(_clients.values())

    for client in clients:
        try:
            client.connection_pool.disconnect()
        except Exception:
            pass


# ให้มีแค่ thread เดียวที่ไล่หาที่อยู่ใหม่ได้ในเวลาหนึ่ง — ทุก thread เจอสายตายพร้อมกัน
# ถ้าปล่อยให้ไล่หาพร้อมกันจะเสียเวลาซ้ำซ้อนและอาจย้ายทับกันเอง
_failover_lock = threading.Lock()


def failover_to_backup(from_generation: int | None = None) -> bool:
    # ไล่ลองที่อยู่สำรองทีละอัน อันไหน ping ผ่านก่อนก็ย้ายไปใช้อันนั้น
    with _failover_lock:
        # ระหว่างรอคิว อาจมี thread อื่นย้ายให้เรียบร้อยแล้ว — ไม่ต้องไล่ซ้ำ
        if from_generation is not None and link_generation() != from_generation:
            return True

        endpoints = known_endpoints()

        if len(endpoints) < 2:
            return False

        print(f"[LINK] ต่อ {endpoint_text(endpoints[0])} ไม่ได้ — ลองที่อยู่สำรอง {len(endpoints) - 1} ที่")

        for endpoint in endpoints[1:]:
            if probe_endpoint(*endpoint):
                return switch_endpoint(*endpoint)

        print("[LINK] ที่อยู่สำรองยังต่อไม่ได้สักที่ — รอแล้วลองใหม่")
        return False


def watch_link():
    # central ที่หายไปดื้อ ๆ (เครื่องดับ/ถูกไฟร์วอลล์กั้น) ไม่ทำให้ TCP ฝั่งเราพัง — thread จะค้าง
    # รออ่านไปเรื่อย ๆ ตัวนี้คอยดูว่าเงียบนานเกินไปไหม แล้วสะกิดให้ไปต่อ
    while True:
        time.sleep(LINK_CHECK_SECONDS)

        silence = time.time() - _last_contact["at"]

        if silence < LINK_SILENCE_SECONDS:
            continue

        generation = link_generation()
        host, port = active_endpoint()
        print(f"[LINK] ไม่ได้คุยกับ {host}:{port} มา {silence:.0f} วินาที — ตรวจสายใหม่")

        if not probe_endpoint(host, port):
            failover_to_backup(generation)

        # ต่อได้หรือย้ายแล้วก็ตาม ปิด connection เดิมทิ้งเสมอ ให้ทุก thread เริ่มสายใหม่
        drop_all_connections()
        note_link_ok()


# ---------------------------------------------------------------------------

def ensure_managed_dir():
    Path(MANAGED_DIR).mkdir(parents=True, exist_ok=True)


def _read_ip_file(path: str, label: str) -> set[str]:
    # อ่านไฟล์ JSON list ของ IP เป็น set — ไฟล์ไม่มี/เสีย คืน set ว่าง ไม่ crash
    try:
        ensure_managed_dir()

        if not os.path.exists(path):
            return set()

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            return set()

        return set(str(ip).strip() for ip in data if ip)

    except Exception as e:
        print(f"[{label}] อ่านไฟล์ {path} ไม่ได้: {e}")
        return set()


def _write_ip_file(path: str, ips: set[str], label: str):
    try:
        ensure_managed_dir()

        with open(path, "w", encoding="utf-8") as f:
            json.dump(sorted(ips), f, ensure_ascii=False, indent=2)

    except Exception as e:
        print(f"[{label}] บันทึกไฟล์ {path} ไม่ได้: {e}")


# whitelist ที่ sync มาถูกเช็คบ่อยมาก (ทุกครั้งที่จะ block) จึง cache ใน memory
_synced_whitelist_cache: set[str] | None = None


def load_synced_whitelist() -> set[str]:
    global _synced_whitelist_cache

    if _synced_whitelist_cache is None:
        _synced_whitelist_cache = _read_ip_file(MANAGED_WHITELIST_FILE, "WHITELIST")

    return _synced_whitelist_cache


def save_synced_whitelist(ips: set[str]):
    global _synced_whitelist_cache

    _synced_whitelist_cache = set(ips)
    _write_ip_file(MANAGED_WHITELIST_FILE, _synced_whitelist_cache, "WHITELIST")


def load_managed_ips() -> set[str]:
    # อ่าน IP ที่ระบบ sync ของ Central เคยจัดการไว้เท่านั้น
    return _read_ip_file(MANAGED_BLACKLIST_FILE, "SYNC STATE")


def save_managed_ips(ips: set[str]):
    _write_ip_file(MANAGED_BLACKLIST_FILE, ips, "SYNC STATE")


def add_managed_ip(ip: str):
    if not ip:
        return

    managed_ips = load_managed_ips()
    managed_ips.add(ip)
    save_managed_ips(managed_ips)


def remove_managed_ip(ip: str):
    if not ip:
        return

    managed_ips = load_managed_ips()
    managed_ips.discard(ip)
    save_managed_ips(managed_ips)


# ---------------------------------------------------------------------------

def is_never_block(ip: str) -> bool:
    # เช็คว่า ip ห้าม block ไหม จาก 3 แหล่ง:
    if not ip:
        return False

    ip = str(ip).strip()

    if ip in load_synced_whitelist():
        return True

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return any(addr in net for net in _NEVER_BLOCK_NETS)


def extract_ip(item) -> str | None:
    if isinstance(item, dict):
        ip = item.get("ip") or item.get("ip_address")
    else:
        ip = item

    if not ip:
        return None

    ip = str(ip).strip()
    return ip or None


def normalize_ip_list(items) -> set[str]:
    if not isinstance(items, list):
        return set()

    return {ip for ip in (extract_ip(item) for item in items) if ip}


# ---------------------------------------------------------------------------

def drop_conntrack(ip):
    # ล้าง connection ที่เปิดค้างอยู่ของ IP นี้ทิ้ง (ทั้งขาที่ IP เป็นต้นทางและปลายทาง)
    for direction in ("-s", "-d"):
        try:
            subprocess.run(
                ["sudo", "conntrack", "-D", direction, ip],
                check=False,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        except FileNotFoundError:
            print("[BLOCK] ไม่พบคำสั่ง conntrack (ข้ามการตัด session เดิม) — ติดตั้งด้วย: sudo apt install conntrack")
            return

    print(f"[BLOCK] ล้าง conntrack (ตัด session เดิม) ของ {ip} แล้ว")


def _ufw_block(ip, prefix: str, comment: str | None = None) -> bool:
    if not ip:
        print(f"[{prefix}] ไม่พบ IP")
        return False

    if is_never_block(ip):
        print(f"[{prefix}] {ip} อยู่ใน never-block list -> ข้าม ไม่ block (safety)")
        return False

    cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]

    if comment:
        cmd += ["comment", comment]

    try:
        subprocess.run(cmd, check=True)
        print(f"[{prefix}] {' '.join(cmd[1:])}")

        # ตัด connection เดิมที่ยัง established อยู่ทิ้งด้วย ไม่งั้น keep-alive ยังเข้าได้
        drop_conntrack(ip)
        return True

    except subprocess.CalledProcessError as e:
        print(f"[{prefix} ERROR] block IP {ip} ไม่สำเร็จ: {e}")
        return False


def _ufw_unblock(ip, prefix: str) -> bool:
    if not ip:
        print(f"[{prefix}] ไม่พบ IP")
        return False

    try:
        subprocess.run(
            ["sudo", "ufw", "delete", "deny", "from", ip, "to", "any"],
            check=True,
        )

        print(f"[{prefix}] ufw delete deny from {ip} to any")
        return True

    except subprocess.CalledProcessError as e:
        print(f"[{prefix} ERROR] unblock IP {ip} ไม่สำเร็จ: {e}")
        return False


def block_ip(ip) -> bool:
    return _ufw_block(ip, "BLOCK")


def unblock_ip(ip) -> bool:
    return _ufw_unblock(ip, "UNBLOCK")


def sync_block_ip(ip: str) -> bool:
    return _ufw_block(ip, "SYNC BLOCK", comment=UFW_COMMENT)


def sync_unblock_ip(ip: str) -> bool:
    return _ufw_unblock(ip, "SYNC UNBLOCK")


def sync_blacklist_desired_state(central_items):
    # sync แบบไม่กระทบของเดิม
    central_desired_ips = normalize_ip_list(central_items)
    managed_ips = load_managed_ips()

    to_block = central_desired_ips - managed_ips
    to_unblock = managed_ips - central_desired_ips

    print(
        f"[SYNC] Central desired: {len(central_desired_ips)} IP | "
        f"Managed local: {len(managed_ips)} IP | "
        f"Block เพิ่ม: {len(to_block)} | "
        f"Unblock: {len(to_unblock)}"
    )

    updated_managed_ips = set(managed_ips)

    for ip in sorted(to_block):
        if sync_block_ip(ip):
            updated_managed_ips.add(ip)

    for ip in sorted(to_unblock):
        if sync_unblock_ip(ip):
            updated_managed_ips.discard(ip)

    save_managed_ips(updated_managed_ips)

    print(f"[SYNC] เสร็จแล้ว Managed blacklist เหลือ {len(updated_managed_ips)} IP")


# ---------------------------------------------------------------------------

def parse_command_message(message) -> dict | None:
    try:
        raw_data = message.get("data")

        if isinstance(raw_data, bytes):
            raw_data = raw_data.decode()

        if isinstance(raw_data, str):
            return json.loads(raw_data)

        if isinstance(raw_data, dict):
            return raw_data

        print(f"[COMMAND] message data type ไม่รองรับ: {type(raw_data)}")
        return None

    except json.JSONDecodeError as e:
        print(f"[JSON ERROR] อ่านข้อความไม่ได้: {e}")
        return None

    except Exception as e:
        print(f"[COMMAND] อ่านข้อความไม่ได้: {e}")
        return None


def handle_hello_command(data: dict):
    # hello จาก Central ตอน agent กลับมา online
    text = data.get("message", "hello")
    ip_blacklist = data.get("ip_blacklist", [])

    print(f"[CENTRAL] {text}")

    if not ip_blacklist:
        print("[CENTRAL] ไม่มี Blacklist ใน hello")
        return

    print(f"[CENTRAL] ได้รับ Blacklist จาก hello {len(ip_blacklist)} IP: {ip_blacklist}")

    for item in ip_blacklist:
        ip = extract_ip(item)

        if ip:
            block_ip(ip)


def handle_block_ip_command(data: dict):
    # block ตามคำสั่งเดี่ยว + บันทึก managed state ให้รอบ sync ถัดไปรู้ว่ามาจาก Central
    ip = extract_ip(data.get("ip") or data.get("ip_address"))

    if not ip:
        print("[BLOCK] ไม่พบ IP จาก command")
        return

    if block_ip(ip):
        add_managed_ip(ip)


def handle_unblock_ip_command(data: dict):
    # unblock ตามคำสั่งเดี่ยว + ลบออกจาก managed state
    ip = extract_ip(data.get("ip") or data.get("ip_address"))

    if not ip:
        print("[UNBLOCK] ไม่พบ IP จาก command")
        return

    if unblock_ip(ip):
        remove_managed_ip(ip)


def handle_sync_blacklist_command(data: dict):
    ips = data.get("ips", [])
    print(f"[SYNC] ได้รับ blacklist ปัจจุบันจาก Central {len(ips)} รายการ")
    sync_blacklist_desired_state(ips)


def handle_sync_whitelist_command(data: dict):
    # รับ whitelist ปัจจุบันจาก Central มาเก็บไว้ (desired state)
    ips = normalize_ip_list(data.get("ips", []))
    save_synced_whitelist(ips)
    print(f"[WHITELIST] ได้รับ whitelist จาก Central {len(ips)} รายการ -> อัปเดต never-block แล้ว")


def move_signing_key() -> bytes:
    # กุญแจที่ใช้เซ็นคำสั่ง central_move = sha256 ของ secret token ของ agent ตัวนี้
    # ฝั่ง central มีค่านี้อยู่แล้วในคอลัมน์ secret_token_hash (ไม่ต้องเก็บ token ตัวจริง)
    return hashlib.sha256(SECRET_TOKEN.encode()).hexdigest().encode()


def move_signature(data: dict) -> str:
    payload = {k: v for k, v in data.items() if k != "sig"}
    message = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hmac.new(move_signing_key(), message.encode(), hashlib.sha256).hexdigest()


def load_seen_nonces() -> list[str]:
    try:
        with open(SEEN_NONCE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        return [str(x) for x in data] if isinstance(data, list) else []

    except (OSError, json.JSONDecodeError):
        return []


def remember_nonce(nonce: str) -> None:
    ensure_managed_dir()
    nonces = load_seen_nonces()
    nonces.append(nonce)

    try:
        with open(SEEN_NONCE_FILE, "w", encoding="utf-8") as f:
            json.dump(nonces[-SEEN_NONCE_LIMIT:], f)
    except OSError as e:
        print(f"[MOVE] เก็บ nonce ไม่ได้: {e}")


def verify_move_command(data: dict) -> bool:
    # คำสั่งย้าย central ต้องผ่านครบ 4 ด่านถึงจะเชื่อ:
    #   1) จ่าหน้าถึง agent ตัวนี้   2) ลายเซ็นตรง   3) ยังไม่หมดอายุ   4) ไม่ใช่ข้อความซ้ำ
    if not SECRET_TOKEN:
        print("[MOVE] ปฏิเสธ: agent ตัวนี้ไม่มี secret token")
        return False

    if data.get("agent_id") != AGENT_ID:
        print(f"[MOVE] ปฏิเสธ: คำสั่งจ่าหน้าถึง {data.get('agent_id')} ไม่ใช่ {AGENT_ID}")
        return False

    sig = str(data.get("sig") or "")

    if not sig or not hmac.compare_digest(sig, move_signature(data)):
        print("[MOVE] ปฏิเสธ: ลายเซ็นไม่ถูกต้อง")
        return False

    try:
        issued_at = float(data.get("issued_at") or 0)
    except (TypeError, ValueError):
        issued_at = 0

    age = time.time() - issued_at

    if issued_at <= 0 or age > MOVE_MAX_AGE_SECONDS or age < -MOVE_MAX_AGE_SECONDS:
        print(f"[MOVE] ปฏิเสธ: คำสั่งหมดอายุ (ออกเมื่อ {age:.0f} วินาทีก่อน)")
        return False

    nonce = str(data.get("nonce") or "")

    if not nonce:
        print("[MOVE] ปฏิเสธ: ไม่มี nonce")
        return False

    if nonce in load_seen_nonces():
        print("[MOVE] ปฏิเสธ: คำสั่งนี้เคยใช้ไปแล้ว (replay)")
        return False

    remember_nonce(nonce)
    return True


def handle_central_move_command(data: dict):
    # central แจ้งที่อยู่ใหม่ล่วงหน้าก่อนย้ายจริง — เก็บไว้เป็นตัวสำรองเสมอ
    # แล้วถ้าที่อยู่ใหม่ใช้ได้แล้วตอนนี้ ก็ย้ายไปเลยโดยไม่ต้องรอ central เดิมล่ม
    if not verify_move_command(data):
        return

    endpoint = _norm_endpoint(data.get("new_host"), data.get("new_port") or CENTRAL_PORT)

    if not endpoint:
        print(f"[MOVE] ปฏิเสธ: ที่อยู่ใหม่ผิดรูป ({data.get('new_host')}:{data.get('new_port')})")
        return

    host, port = endpoint
    print(f"[MOVE] central แจ้งย้ายไปที่ {host}:{port}")

    if endpoint == active_endpoint():
        print("[MOVE] เป็นที่อยู่เดิมที่ใช้อยู่แล้ว ไม่ต้องทำอะไร")
        return

    add_endpoint(host, port)

    if not data.get("switch_now", True):
        print("[MOVE] เก็บไว้เป็นตัวสำรองตามที่สั่ง ยังไม่ย้าย")
        return

    if probe_endpoint(host, port):
        switch_endpoint(host, port)
    else:
        print(
            f"[MOVE] {host}:{port} ยังต่อไม่ได้ — เก็บเป็นตัวสำรองไว้ก่อน "
            f"เดี๋ยวจะย้ายให้เองตอนที่อยู่เดิมล่ม"
        )


COMMAND_HANDLERS = {
    "hello": handle_hello_command,
    "central_move": handle_central_move_command,
    "block_ip": handle_block_ip_command,
    "unblock_ip": handle_unblock_ip_command,
    "sync_blacklist": handle_sync_blacklist_command,
    "sync_whitelist": handle_sync_whitelist_command,
}


def handle_command(data: dict):
    handler = COMMAND_HANDLERS.get(data.get("command"))

    if handler:
        handler(data)
    else:
        print(f"[UNKNOWN COMMAND] {data}")


# ---------------------------------------------------------------------------

def run_with_reconnect(label: str, worker):
    # เปิด Redis connection แล้วส่งให้ worker ทำงานยาว ๆ
    # worker คืนค่าเมื่อที่อยู่ central เปลี่ยน (generation ขยับ) รอบถัดไปจะต่อที่อยู่ใหม่ให้เอง
    failures = 0

    while True:
        r = None
        endpoint = active_endpoint()
        generation = link_generation()

        try:
            r = create_redis(*endpoint)
            r.ping()
            register_client(label, r)
            note_link_ok()

            if failures:
                print(f"[{label}] ต่อ {endpoint_text(endpoint)} ได้แล้ว")

            failures = 0
            worker(r, generation)

        except Exception as e:
            failures += 1
            print(f"[{label}] หลุด: {e} รอ {RECONNECT_DELAY_SECONDS} วินาที...")

            # ต่อที่อยู่เดิมไม่ติดหลายครั้งติดกัน = central อาจย้ายไปแล้ว ลองที่อยู่สำรอง
            if failures >= FAILOVER_AFTER_FAILURES and link_generation() == generation:
                if failover_to_backup(generation):
                    failures = 0
                    continue

            time.sleep(RECONNECT_DELAY_SECONDS)

        finally:
            unregister_client(label)

            try:
                if r:
                    r.close()
            except Exception:
                pass


def listen_commands():
    def worker(r, generation):
        pubsub = r.pubsub()
        private_channel = f"agent_commands:{AGENT_ID}"

        try:
            pubsub.subscribe("global_commands", private_channel)
            print(f"[LISTEN] subscribe global_commands และ {private_channel}")

            # ใช้ get_message แทน listen() เพื่อให้วนกลับมาเช็คได้ว่าที่อยู่ central เปลี่ยนหรือยัง
            while link_generation() == generation:
                message = pubsub.get_message(timeout=1.0)

                if not message:
                    continue

                note_link_ok()

                if message.get("type") != "message":
                    continue

                data = parse_command_message(message)

                if data:
                    handle_command(data)

        finally:
            try:
                pubsub.close()
            except Exception:
                pass

    run_with_reconnect("COMMAND", worker)


def send_metrics():
    print("[METRICS] เริ่มส่งค่า CPU/RAM")

    def worker(r, generation):
        while link_generation() == generation:
            host_ip = get_host_ip_cached()
            endpoint = active_endpoint()

            payload = {
                "agent_id": AGENT_ID,
                "secret_token": SECRET_TOKEN,
                # central เอาไปเทียบกับ IP ที่ผูกไว้กับ agent_id นี้ ไม่ตรง = ปฏิเสธทั้ง message
                "host_ip": host_ip,
                "host_iface": HOST_IFACE or None,
                # ที่อยู่ central ที่ agent ตัวนี้ใช้อยู่จริง — หน้า Agents เอาไว้ยืนยันว่าย้ายครบแล้ว
                "central_host": endpoint[0],
                "central_port": endpoint[1],
                "cpu": psutil.cpu_percent(interval=1),
                "ram": psutil.virtual_memory().percent,
                "timestamp": time.time(),
            }

            r.publish("agent_metrics", json.dumps(payload))
            note_link_ok()

            print(
                f"[METRICS] {AGENT_ID} | "
                f"IP: {host_ip or 'หา IP ไม่ได้'} | "
                f"CPU: {payload['cpu']}% | "
                f"RAM: {payload['ram']}%"
            )

            time.sleep(METRICS_INTERVAL_SECONDS)

    run_with_reconnect("METRICS", worker)


def _check_config_or_exit():
    problems = []

    if not AGENT_ID or not SECRET_TOKEN:
        problems.append(f"ไม่พบ AGENT_ID/SECRET_TOKEN — ต้องมี agent_info.txt (จาก zip) อยู่ที่ {BASE_DIR}")

    for name, path in (("cert", AGENT_CERT_FILE), ("key", AGENT_KEY_FILE), ("ca", CA_CERT_FILE)):
        if not os.path.exists(path):
            problems.append(f"ไม่พบไฟล์ {name}: {path}")

    endpoints = known_endpoints()
    print(f"[CONFIG] central ที่ใช้อยู่: {endpoint_text(endpoints[0])}")

    if len(endpoints) > 1:
        print(
            "[CONFIG] ที่อยู่สำรองของ central: "
            + ", ".join(endpoint_text(e) for e in endpoints[1:])
        )

    if HOST_IFACE and HOST_IFACE not in psutil.net_if_addrs():
        available = ", ".join(sorted(list_interface_ips())) or "ไม่มีเลย"
        problems.append(
            f"ไม่พบ interface '{HOST_IFACE}' ที่ตั้งไว้ใน agent_config.json "
            f"(ที่มีบนเครื่องนี้: {available}) — รัน setup.sh ใหม่เพื่อเลือก interface ใหม่"
        )

    if problems:
        for p in problems:
            print(f"[CONFIG ERROR] {p}")
        sys.exit(1)

    # หา IP ไม่ได้ = ยังรันต่อได้ (เดี๋ยว interface อาจได้ IP ทีหลัง) แต่ต้องบอกให้ชัดว่าทำไม
    host_ip = get_host_ip()

    if host_ip:
        print(f"[CONFIG] IP ที่จะรายงานให้ central: {host_ip} ({HOST_IFACE or 'ตาม route ที่ออกไปหา central'})")
    else:
        print(
            f"[CONFIG WARN] ยังหา IP ของเครื่องนี้ไม่ได้"
            f"{f' จาก interface {HOST_IFACE}' if HOST_IFACE else ''} — "
            f"central จะข้ามการตรวจ IP จนกว่าจะหาเจอ"
        )


if __name__ == "__main__":
    _check_config_or_exit()
    threading.Thread(target=listen_commands, daemon=True).start()
    threading.Thread(target=watch_link, daemon=True).start()
    send_metrics()
