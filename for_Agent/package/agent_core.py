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


CONFIG_FILE_NAME = "agent_config.json"


def _read_kv_file(path: Path) -> dict:

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
    try:
        with open(BASE_DIR / "agent_config.json", "r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError("agent_config.json is required; run setup.sh") from exc
    required = ("central_host", "central_port", "redis_username", "redis_password")
    if not isinstance(data, dict) or any(not data.get(key) for key in required):
        raise RuntimeError("agent_config.json is incomplete; run setup.sh")
    return data


def _find_cert(filename: str) -> str:

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


HOST_IFACE = str(_CONFIG.get("host_iface") or "")

METRICS_INTERVAL_SECONDS = 4
RECONNECT_DELAY_SECONDS = 5


FAILOVER_AFTER_FAILURES = 2


PROBE_TIMEOUT_SECONDS = 5


LINK_CHECK_SECONDS = 10
LINK_SILENCE_SECONDS = 30


MAX_ENDPOINTS = 5


MOVE_MAX_AGE_SECONDS = 900


FILEBEAT_CONFIG_FILE = "/etc/filebeat/filebeat.yml"


HOST_IP_REFRESH_SECONDS = 30

MANAGED_DIR = str(BASE_DIR / "state")
MANAGED_BLACKLIST_FILE = f"{MANAGED_DIR}/central_blacklist.json"
MANAGED_WHITELIST_FILE = f"{MANAGED_DIR}/central_whitelist.json"


SEEN_NONCE_FILE = f"{MANAGED_DIR}/seen_move_nonces.json"
SEEN_NONCE_LIMIT = 200
UFW_COMMENT = "Securelog"
LEGACY_UFW_COMMENT = "central_blacklist"
ATTACK_COMMENT_LABELS = {
    "ssh_brute_force": "SSH Brute Force",
    "sudo_failed": "Sudo Authentication Failure",
    "sql_injection": "SQL Injection",
    "web_sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "web_xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal",
    "web_path_traversal": "Path Traversal",
    "command_injection": "Command Injection",
    "web_command_injection": "Command Injection",
    "http_flood": "HTTP Flood",
    "web_http_flood": "HTTP Flood",
    "firewall_deny_rate": "Firewall Deny Flood",
    "port_scan": "Port Scan",
    "firewall_port_scan": "Port Scan",
    "manual_blacklist": "Manual Blacklist",
}


def ufw_block_comment(event) -> str:
    reason = str(event or "").strip()
    if not reason or len(reason) > 64 or not all(c.isascii() and (c.isalnum() or c in "_-") for c in reason):
        reason = "unspecified"
    label = ATTACK_COMMENT_LABELS.get(reason, reason.replace("_", " ").replace("-", " ").title())
    return f"{UFW_COMMENT}:{label}"


def is_our_ufw_comment(comment: str) -> bool:
    # กฎที่ Agent รุ่นเก่าสร้างไว้ยังเป็นของระบบ และต้องปลดบล็อกได้ตามเดิม
    return (
        (comment.startswith(f"{UFW_COMMENT}:") and bool(comment[len(UFW_COMMENT) + 1:].strip()))
        or comment == LEGACY_UFW_COMMENT
        or comment.startswith(f"{LEGACY_UFW_COMMENT}: ")
    )


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

            host, _, port = item.rpartition(":")
            push(host or item, port if host else None)

    return result, sources


_ENDPOINTS, _ENDPOINT_SOURCES = _endpoints_from_config(_CONFIG)

_link_lock = threading.RLock()
_link = {
    "endpoints": _ENDPOINTS or [(CENTRAL_HOST, CENTRAL_PORT)],
    "sources": _ENDPOINT_SOURCES,

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


def save_config_updates(updates: dict) -> bool:

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


NEVER_BLOCK_CIDRS = [
    "127.0.0.0/8",

]


ALWAYS_NEVER_BLOCK_CIDRS = [
    "0.0.0.0/32",
    "255.255.255.255/32",
]

_NEVER_BLOCK_NETS = []


def rebuild_never_block_nets() -> None:

    nets = []

    central_hosts = [host for host, _ in known_endpoints()]

    for entry in ALWAYS_NEVER_BLOCK_CIDRS + NEVER_BLOCK_CIDRS + central_hosts:
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:

            if entry not in central_hosts:
                print(f"[CONFIG] NEVER_BLOCK_CIDRS entry ผิดรูป ข้าม: {entry}")

    global _NEVER_BLOCK_NETS
    _NEVER_BLOCK_NETS = nets


rebuild_never_block_nets()


def list_interface_ips() -> dict[str, str]:

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

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    try:
        sock.connect(active_endpoint())
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def get_host_ip() -> str | None:

    if HOST_IFACE:

        return list_interface_ips().get(HOST_IFACE)

    return detect_outbound_ip()


_host_ip_cache = {"ip": None, "at": 0.0}


def get_host_ip_cached() -> str | None:

    now = time.time()

    if now - _host_ip_cache["at"] >= HOST_IP_REFRESH_SECONDS:
        _host_ip_cache["ip"] = get_host_ip()
        _host_ip_cache["at"] = now

    return _host_ip_cache["ip"]


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


    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT_SECONDS):
            return True
    except OSError as e:
        print(f"[LINK] เคาะ {host}:{port} ไม่ติด: {e}")
        return False


AUTH_ERRORS = tuple(
    e for e in (
        getattr(redis.exceptions, "AuthenticationError", None),
        getattr(redis.exceptions, "AuthorizationError", None),
        getattr(redis.exceptions, "NoPermissionError", None),
    ) if e is not None
)


def endpoint_state(host: str, port: int) -> str:


    if not tcp_reachable(host, port):
        return "down"

    r = None

    try:
        r = create_redis(host, port, timeout=PROBE_TIMEOUT_SECONDS)
        return "ok" if r.ping() else "down"

    except AUTH_ERRORS as e:
        print(f"[LINK] {host}:{port} ต่อได้ แต่ล็อกอินไม่ผ่าน: {e}")
        return "auth"

    except Exception as e:
        print(f"[LINK] ทดสอบ {host}:{port} ไม่ผ่าน: {e}")
        return "down"

    finally:
        try:
            if r:
                r.close()
        except Exception:
            pass


def probe_endpoint(host: str, port: int) -> bool:
    return endpoint_state(host, port) == "ok"


def allow_outbound_in_ufw(host: str, port: int) -> None:

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

    endpoint = _norm_endpoint(host, port)

    if not endpoint:
        return False

    with _link_lock:
        known = endpoint in _link["endpoints"]


        if known and (source != "announce" or _link["endpoints"][0] == endpoint):
            return False

        if known:
            _link["endpoints"].remove(endpoint)


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

    with _clients_lock:
        clients = list(_clients.values())

    for client in clients:
        try:
            client.connection_pool.disconnect()
        except Exception:
            pass


_failover_lock = threading.Lock()


def failover_to_backup(from_generation: int | None = None) -> bool:

    with _failover_lock:

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


    while True:
        time.sleep(LINK_CHECK_SECONDS)

        silence = time.time() - _last_contact["at"]

        if silence < LINK_SILENCE_SECONDS:
            continue

        generation = link_generation()
        host, port = active_endpoint()
        print(f"[LINK] ไม่ได้คุยกับ {host}:{port} มา {silence:.0f} วินาที — ตรวจสายใหม่")

        state = endpoint_state(host, port)

        if state == "auth":

            print(
                f"[LINK] {host}:{port} ยังอยู่ที่เดิม แต่ล็อกอิน Redis ไม่ผ่าน — ไม่ใช่การย้ายที่อยู่ "
                "ต้องออกชุดติดตั้งใหม่จากหน้า Agents (Regenerate Download Link) มาลงที่เครื่องนี้"
            )
        elif state == "down":
            failover_to_backup(generation)


        drop_all_connections()
        note_link_ok()


def ensure_managed_dir():
    Path(MANAGED_DIR).mkdir(parents=True, exist_ok=True)


def _read_ip_file(path: str, label: str) -> set[str]:

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


_synced_whitelist_cache: set[str] | None = None


def load_synced_whitelist() -> set[str]:
    global _synced_whitelist_cache

    if _synced_whitelist_cache is None:
        _synced_whitelist_cache = _read_ip_file(MANAGED_WHITELIST_FILE, "WHITELIST")

    return _synced_whitelist_cache


def save_synced_whitelist(ips: set[str]):
    global _synced_whitelist_cache
    global _synced_whitelist_nets_cache

    _synced_whitelist_cache = set(ips)
    _synced_whitelist_nets_cache = None      # ให้สร้างใหม่รอบหน้าจากรายการชุดใหม่
    _write_ip_file(MANAGED_WHITELIST_FILE, _synced_whitelist_cache, "WHITELIST")


_synced_whitelist_nets_cache = None


def load_synced_whitelist_nets():
    global _synced_whitelist_nets_cache

    if _synced_whitelist_nets_cache is None:
        nets = []

        for entry in load_synced_whitelist():
            try:
                nets.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:

                print(f"[WHITELIST] รายการที่ central ส่งมาผิดรูป ข้าม: {entry}")

        _synced_whitelist_nets_cache = nets

    return _synced_whitelist_nets_cache


def load_managed_ips() -> set[str]:

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


def is_never_block(ip: str) -> bool:

    if not ip:
        return False

    ip = str(ip).strip()


    if ip in load_synced_whitelist():
        return True


    try:
        target = ipaddress.ip_network(ip, strict=False)
    except ValueError:
        return False


    for net in list(load_synced_whitelist_nets()) + list(_NEVER_BLOCK_NETS):
        if target.version == net.version and target.overlaps(net):
            return True

    return False


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


def drop_conntrack(ip):

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


def ufw_deny_rule_owner(ip: str) -> str:


    if not ip:
        return "none"

    try:
        result = subprocess.run(
            ["sudo", "ufw", "status"],
            check=False,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("[FIREWALL] ไม่พบคำสั่ง ufw — ตรวจกฎเดิมไม่ได้")
        return "unknown"

    if result.returncode != 0:
        print(f"[FIREWALL] อ่านสถานะ ufw ไม่ได้ (exit {result.returncode})")
        return "unknown"

    found_ours = False
    for line in result.stdout.splitlines():
        if not any(action in line for action in ("ALLOW", "DENY", "REJECT")):
            continue


        head, _, comment = line.partition("#")
        fields = head.split()

        source = fields[-2] if len(fields) >= 2 and fields[-1] == "(v6)" else fields[-1] if fields else None
        if source != ip:
            continue

        if not any(action in head for action in ("DENY", "REJECT")) or not is_our_ufw_comment(comment.strip()):
            return "foreign"
        found_ours = True

    return "ours" if found_ours else "none"


def _ufw_block(ip, prefix: str, comment: str | None = None) -> bool:
    if not ip:
        print(f"[{prefix}] ไม่พบ IP")
        return False

    if is_never_block(ip):
        print(f"[{prefix}] {ip} อยู่ใน never-block list -> ข้าม ไม่ block (safety)")
        return False


    owner = ufw_deny_rule_owner(ip)
    if owner == "unknown":
        print(f"[{prefix}] ตรวจเจ้าของกฎไม่ได้ -> ไม่เพิ่มกฎ")
        return False
    if owner == "foreign":
        print(
            f"[{prefix}] {ip} ถูกบล็อกด้วยกฎที่มีอยู่ก่อนแล้วบนเครื่องนี้ "
            f"-> ไม่แตะ และไม่รับมาเป็นของระบบ (กฎเดิมยังทำงานอยู่)"
        )
        return False

    if owner == "ours":
        print(f"[{prefix}] {ip} มีกฎของระบบอยู่แล้ว -> ไม่เพิ่มซ้ำ")
        return True

    cmd = ["sudo", "ufw", "insert", "1", "deny", "from", ip, "to", "any"]

    if comment:
        cmd += ["comment", comment]

    try:
        subprocess.run(cmd, check=True)
        print(f"[{prefix}] {' '.join(cmd[1:])}")


        drop_conntrack(ip)
        return True

    except subprocess.CalledProcessError as e:
        print(f"[{prefix} ERROR] block IP {ip} ไม่สำเร็จ: {e}")
        return False


def _ufw_unblock(ip, prefix: str) -> bool:
    if not ip:
        print(f"[{prefix}] ไม่พบ IP")
        return False


    owner = ufw_deny_rule_owner(ip)
    if owner == "unknown":
        print(f"[{prefix}] ตรวจเจ้าของกฎไม่ได้ -> ไม่ลบ")
        return False
    if owner == "foreign":
        print(f"[{prefix}] {ip} มีกฎของผู้ดูแลเครื่อง -> ไม่ลบ")
        return False
    if owner == "none":
        print(f"[{prefix}] {ip} ไม่มีกฎของระบบ -> ไม่ลบ")
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


def block_ip(ip, event=None) -> bool:

    return _ufw_block(ip, "BLOCK", comment=ufw_block_comment(event))


def unblock_ip(ip) -> bool:
    return _ufw_unblock(ip, "UNBLOCK")


def sync_block_ip(ip: str, event=None) -> bool:
    return _ufw_block(ip, "SYNC BLOCK", comment=ufw_block_comment(event))


def sync_unblock_ip(ip: str) -> bool:
    return _ufw_unblock(ip, "SYNC UNBLOCK")


def sync_blacklist_desired_state(central_items):

    central_desired_ips = normalize_ip_list(central_items)
    events_by_ip = {
        ip: item.get("event")
        for item in central_items if isinstance(item, dict)
        if (ip := extract_ip(item))
    } if isinstance(central_items, list) else {}
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
        if sync_block_ip(ip, events_by_ip.get(ip)):
            updated_managed_ips.add(ip)

    for ip in sorted(to_unblock):
        if sync_unblock_ip(ip):
            updated_managed_ips.discard(ip)

    save_managed_ips(updated_managed_ips)

    print(f"[SYNC] เสร็จแล้ว Managed blacklist เหลือ {len(updated_managed_ips)} IP")


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
            block_ip(ip, item.get("event") if isinstance(item, dict) else None)


def handle_block_ip_command(data: dict):

    ip = extract_ip(data.get("ip") or data.get("ip_address"))

    if not ip:
        print("[BLOCK] ไม่พบ IP จาก command")
        return

    if block_ip(ip, data.get("event")):
        add_managed_ip(ip)


def handle_unblock_ip_command(data: dict):

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

    ips = normalize_ip_list(data.get("ips", []))
    save_synced_whitelist(ips)
    print(f"[WHITELIST] ได้รับ whitelist จาก Central {len(ips)} รายการ -> อัปเดต never-block แล้ว")


def move_signing_key() -> bytes:


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


def run_with_reconnect(label: str, worker):


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
            auth_problem = isinstance(e, AUTH_ERRORS)

            if auth_problem:
                print(
                    f"[{label}] ล็อกอิน Redis ไม่ผ่าน: {e} — central อยู่ที่เดิม ไม่ใช่การย้ายที่อยู่ "
                    f"(ต้องลงชุดติดตั้งใหม่) รอ {RECONNECT_DELAY_SECONDS} วินาที..."
                )
            else:
                print(f"[{label}] หลุด: {e} รอ {RECONNECT_DELAY_SECONDS} วินาที...")


            if not auth_problem and failures >= FAILOVER_AFTER_FAILURES and link_generation() == generation:
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

                "host_ip": host_ip,
                "host_iface": HOST_IFACE or None,

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
