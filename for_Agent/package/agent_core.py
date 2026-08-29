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
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent

# ---------------------------------------------------------------------------

# ค่า default เฉพาะ site — ปกติถูก override ด้วย agent_config.json (สร้างโดย setup.sh)
_DEFAULT_CONFIG = {
    "central_host": "192.168.56.110",
    "central_port": 6380,
    "redis_username": "agent_node",
    "redis_password": "123",
}


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

# อ่าน IP ใหม่ทุกกี่วินาที — ไม่อ่านทุกรอบ metrics (ทุก 1 วิ) เพราะ IP เครื่องแทบไม่เปลี่ยน
HOST_IP_REFRESH_SECONDS = 30

MANAGED_DIR = str(BASE_DIR / "state")
MANAGED_BLACKLIST_FILE = f"{MANAGED_DIR}/central_blacklist.json"
MANAGED_WHITELIST_FILE = f"{MANAGED_DIR}/central_whitelist.json"
UFW_COMMENT = "central_blacklist"

# รายการ IP/subnet ที่ agent จะ "ไม่มีวัน block" ไม่ว่า central จะสั่งมาหรือไม่
NEVER_BLOCK_CIDRS = [
    "127.0.0.0/8",
    CENTRAL_HOST,
    # "192.168.56.1",  # <- ใส่ IP เครื่อง admin/gateway ที่ใช้ SSH เข้ามาที่นี่ด้วย
]

# address พิเศษของทราฟฟิก broadcast (0.0.0.0 = เครื่องที่ยังไม่ได้ IP เช่นตอนขอ DHCP,
ALWAYS_NEVER_BLOCK_CIDRS = [
    "0.0.0.0/32",
    "255.255.255.255/32",
]

# แปลง never-block ทั้งสองลิสต์เป็น ip_network ครั้งเดียวตอน start
_NEVER_BLOCK_NETS = []
for _entry in ALWAYS_NEVER_BLOCK_CIDRS + NEVER_BLOCK_CIDRS:
    try:
        _NEVER_BLOCK_NETS.append(ipaddress.ip_network(_entry, strict=False))
    except ValueError:
        print(f"[CONFIG] NEVER_BLOCK_CIDRS entry ผิดรูป ข้าม: {_entry}")


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
        sock.connect((CENTRAL_HOST, CENTRAL_PORT))
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


def create_redis():
    return redis.Redis(
        host=CENTRAL_HOST,
        port=CENTRAL_PORT,
        ssl=True,
        ssl_certfile=AGENT_CERT_FILE,
        ssl_keyfile=AGENT_KEY_FILE,
        ssl_ca_certs=CA_CERT_FILE,
        username=REDIS_USERNAME,
        password=REDIS_PASSWORD,
        ssl_check_hostname=True,
    )


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


COMMAND_HANDLERS = {
    "hello": handle_hello_command,
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
    while True:
        r = None

        try:
            r = create_redis()
            r.ping()
            worker(r)

        except Exception as e:
            print(f"[{label}] หลุด: {e} รอ {RECONNECT_DELAY_SECONDS} วินาที...")
            time.sleep(RECONNECT_DELAY_SECONDS)

        finally:
            try:
                if r:
                    r.close()
            except Exception:
                pass


def listen_commands():
    def worker(r):
        pubsub = r.pubsub()
        private_channel = f"agent_commands:{AGENT_ID}"

        try:
            pubsub.subscribe("global_commands", private_channel)
            print(f"[LISTEN] subscribe global_commands และ {private_channel}")

            for message in pubsub.listen():
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

    def worker(r):
        while True:
            host_ip = get_host_ip_cached()

            payload = {
                "agent_id": AGENT_ID,
                "secret_token": SECRET_TOKEN,
                # central เอาไปเทียบกับ IP ที่ผูกไว้กับ agent_id นี้ ไม่ตรง = ปฏิเสธทั้ง message
                "host_ip": host_ip,
                "host_iface": HOST_IFACE or None,
                "cpu": psutil.cpu_percent(interval=1),
                "ram": psutil.virtual_memory().percent,
                "timestamp": time.time(),
            }

            r.publish("agent_metrics", json.dumps(payload))

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
    send_metrics()
