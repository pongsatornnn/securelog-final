import os
import asyncio
import shutil
import zipfile
import subprocess
import hashlib
import tempfile
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from sqlalchemy import update

from dotenv import load_dotenv

from database.connection import AsyncSessionLocal
from database.crud import clear_agent_ip_binding, get_agent_by_agent_id
from database.models import Agent, AgentDownload
from manage_agent.token_utils import generate_token, hash_token
from auth_cache import clear_agent_auth_cache
from base_path import with_base, RELATIVE_URLS
from manage_agent.redis_acl import ensure_agent_credentials, remove_agent_credentials


def _download_url(token: str) -> str:

    if RELATIVE_URLS:
        return f"download-agent/{token}"
    return with_base(f"/download-agent/{token}")


load_dotenv()

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

CA_CERT = os.path.join(PROJECT_ROOT, "cert/central/ca.crt")
CA_KEY = os.path.join(PROJECT_ROOT, "cert/central/ca.key")

AGENT_CERT_DIR = os.path.join(PROJECT_ROOT, "cert/agent")
PACKAGE_DIR = os.path.join(PROJECT_ROOT, "main/agent_packages")


AGENT_TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "for_Agent/package")
FILEBEAT_ACL_BINARY = os.getenv(
    "FILEBEAT_ACL_BINARY",
    os.path.join(PROJECT_ROOT, "for_Agent/build/filebeat-acl-8.19.23-amd64"),
)

DOWNLOAD_LINK_TTL = timedelta(minutes=5)

TZ = ZoneInfo("Asia/Bangkok")


def now_thai():
    return datetime.now(TZ).replace(tzinfo=None)


def central_address() -> tuple[str, str]:

    host = (os.getenv("AGENT_CENTRAL_HOST") or os.getenv("REDIS_HOST") or "").strip()
    port = (os.getenv("AGENT_CENTRAL_REDIS_PORT") or os.getenv("REDIS_PORT") or "").strip()

    return host, port or "6380"


def central_candidates() -> str:

    raw = (os.getenv("AGENT_CENTRAL_CANDIDATES") or "").replace(",", " ").split()
    return " ".join(dict.fromkeys(raw))


async def build_site_conf(agent_id: str, username: str, password: str) -> str:

    host, port = central_address()
    if not host:
        raise Exception(
            "ไม่รู้ที่อยู่ของ Central (ไม่มีทั้ง AGENT_CENTRAL_HOST และ REDIS_HOST ใน .env) — "
            "รัน setup-server.sh ให้จบก่อนสร้าง package"
        )

    if not username or not password:
        raise ValueError(f"Redis credentials missing for {agent_id}")

    return (
        "# ค่าต่อ site ของชุดติดตั้ง agent\n"
        "# บัญชี Redis เฉพาะ Agent นี้ ใช้ร่วมกันโดย Filebeat และ agent_core.py\n"
        "\n"
        f'CENTRAL_HOST="{host}"\n'
        f'CENTRAL_REDIS_PORT="{port}"\n'
        f'REDIS_USERNAME="{username}"\n'
        f'REDIS_PASSWORD="{password}"\n'
        f'CENTRAL_CANDIDATES="{central_candidates()}"\n'
    )


def run_cmd(cmd: list[str]):
    subprocess.run(cmd, check=True)


def agent_file_paths(agent_id: str) -> tuple[str, str]:

    return (
        os.path.join(AGENT_CERT_DIR, agent_id),
        os.path.join(PACKAGE_DIR, f"{agent_id}.zip"),
    )


def discard_agent_files(agent_id: str) -> None:

    agent_dir, zip_path = agent_file_paths(agent_id)

    if os.path.isdir(agent_dir):
        shutil.rmtree(agent_dir, ignore_errors=True)

    try:
        os.remove(zip_path)
    except FileNotFoundError:
        pass
    except OSError as e:
        print(f"[AGENT] ลบ {zip_path} ไม่สำเร็จ: {e}")


def create_agent_cert(agent_id: str):
    agent_dir = os.path.join(AGENT_CERT_DIR, agent_id)
    os.makedirs(agent_dir, exist_ok=True)

    key_path = os.path.join(agent_dir, f"{agent_id}.key")
    csr_path = os.path.join(agent_dir, f"{agent_id}.csr")
    crt_path = os.path.join(agent_dir, f"{agent_id}.crt")
    ca_copy_path = os.path.join(agent_dir, "ca.crt")

    if os.path.exists(key_path) or os.path.exists(crt_path):
        raise Exception(f"Cert for {agent_id} already exists")

    run_cmd(["openssl", "genrsa", "-out", key_path, "2048"])

    run_cmd([
        "openssl", "req",
        "-new",
        "-key", key_path,
        "-out", csr_path,
        "-subj", f"/CN={agent_id}",
    ])

    run_cmd([
        "openssl", "x509",
        "-req",
        "-in", csr_path,
        "-CA", CA_CERT,
        "-CAkey", CA_KEY,
        "-CAcreateserial",
        "-out", crt_path,
        "-days", "365",
        "-sha256",
    ])

    with open(CA_CERT, "rb") as src:
        with open(ca_copy_path, "wb") as dst:
            dst.write(src.read())

    os.chmod(key_path, 0o600)

    return {
        "agent_dir": agent_dir,
        "key_path": key_path,
        "crt_path": crt_path,
        "csr_path": csr_path,
        "ca_path": ca_copy_path,
    }


def get_existing_agent_cert(agent_id: str):
    agent_dir = os.path.join(AGENT_CERT_DIR, agent_id)
    key_path = os.path.join(agent_dir, f"{agent_id}.key")
    csr_path = os.path.join(agent_dir, f"{agent_id}.csr")
    crt_path = os.path.join(agent_dir, f"{agent_id}.crt")
    ca_copy_path = os.path.join(agent_dir, "ca.crt")

    if not os.path.exists(key_path) or not os.path.exists(crt_path):
        return create_agent_cert(agent_id)

    if not os.path.exists(ca_copy_path):
        shutil.copyfile(CA_CERT, ca_copy_path)

    os.chmod(key_path, 0o600)

    return {
        "agent_dir": agent_dir,
        "key_path": key_path,
        "crt_path": crt_path,
        "csr_path": csr_path,
        "ca_path": ca_copy_path,
    }


def create_agent_zip(agent_id: str, secret_token: str, cert_info: dict, site_conf: str):
    os.makedirs(PACKAGE_DIR, exist_ok=True)
    if not os.path.isfile(FILEBEAT_ACL_BINARY):
        raise FileNotFoundError(f"Redis ACL Filebeat binary missing: {FILEBEAT_ACL_BINARY}")
    version = subprocess.run([FILEBEAT_ACL_BINARY, "version"], capture_output=True,
                             text=True, check=True, timeout=10).stdout
    if "filebeat version 8.19.23 " not in version:
        raise RuntimeError("Redis ACL Filebeat binary must be version 8.19.23")

    agent_dir = cert_info["agent_dir"]
    zip_path = os.path.join(PACKAGE_DIR, f"{agent_id}.zip")
    info_path = os.path.join(agent_dir, "agent_info.txt")

    created_at = now_thai().strftime("%Y-%m-%d %H:%M:%S")

    # Keep the token private even when the process umask allows group/world reads.
    # fchmod also fixes an existing file when regenerating a package.
    info_fd = os.open(info_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(info_fd, "w", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        f.write(f"AGENT_ID={agent_id}\n")
        f.write(f"SECRET_TOKEN={secret_token}\n")
        f.write(f"CERT_FILE={agent_id}.crt\n")
        f.write(f"KEY_FILE={agent_id}.key\n")
        f.write("CA_FILE=ca.crt\n")

        f.write("HOST_IP=\n")
        f.write("TIMEZONE=Asia/Bangkok\n")
        f.write(f"PACKAGE_CREATED_AT={created_at}\n")

    if not os.path.isdir(AGENT_TEMPLATE_DIR):
        raise Exception(f"ไม่พบโฟลเดอร์ชุดติดตั้ง agent: {AGENT_TEMPLATE_DIR}")

    fd, temporary_zip = tempfile.mkstemp(prefix=f".{agent_id}.", suffix=".zip", dir=PACKAGE_DIR)
    os.close(fd)
    try:
        _write_agent_zip(temporary_zip, agent_id, cert_info, info_path, site_conf)
        os.chmod(temporary_zip, 0o600)
        os.replace(temporary_zip, zip_path)
    finally:
        if os.path.exists(temporary_zip):
            os.unlink(temporary_zip)
    return zip_path


def _write_agent_zip(zip_path: str, agent_id: str, cert_info: dict, info_path: str, site_conf: str):
    # Filebeat binary is ~178 MiB; the default compression level takes over a minute
    # for each client. Level 1 keeps the archive reasonably small and cuts that wait.
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=1) as zipf:
        if not os.path.isfile(FILEBEAT_ACL_BINARY):
            raise FileNotFoundError(f"Redis ACL Filebeat binary missing: {FILEBEAT_ACL_BINARY}")
        with open(FILEBEAT_ACL_BINARY, "rb") as binary:
            digest = hashlib.file_digest(binary, "sha256").hexdigest()
        zipf.write(FILEBEAT_ACL_BINARY, arcname="filebeat-acl")
        zipf.writestr("filebeat-acl.sha256", f"{digest}  filebeat-acl\n")
        zipf.write(cert_info["crt_path"], arcname=f"{agent_id}.crt")
        zipf.write(cert_info["key_path"], arcname=f"{agent_id}.key")
        zipf.write(cert_info["ca_path"], arcname="ca.crt")
        zipf.write(info_path, arcname="agent_info.txt")


        zipf.writestr("site.conf", site_conf)


        for name in sorted(os.listdir(AGENT_TEMPLATE_DIR)):
            path = os.path.join(AGENT_TEMPLATE_DIR, name)

            if name.startswith(".") or name.startswith("site.conf") or not os.path.isfile(path):
                continue

            zipf.write(path, arcname=name)

async def create_agent_package(
    agent_id: str,
    hostname: str | None = None,
    description: str | None = None,
):


    current_time = datetime.now()

    secret_token = generate_token()
    download_token = generate_token()

    secret_token_hash = hash_token(secret_token)
    download_token_hash = hash_token(download_token)


    async with AsyncSessionLocal() as db:
        if await get_agent_by_agent_id(db, agent_id):
            raise ValueError(f"มี {agent_id} อยู่ในระบบแล้ว")

    discard_agent_files(agent_id)

    if not central_address()[0]:
        raise RuntimeError("Central host is not configured")
    acl_created = False
    try:
        username, password, acl_created = await asyncio.to_thread(ensure_agent_credentials, agent_id)
        site_conf = await build_site_conf(agent_id, username, password)


        cert_info = create_agent_cert(agent_id)
        zip_path = create_agent_zip(agent_id, secret_token, cert_info, site_conf)

        async with AsyncSessionLocal() as db:
            agent = Agent(
                agent_id=agent_id,
                secret_token_hash=secret_token_hash,
                hostname=hostname,
                ip_address=None,
                description=description,
                status="pending",
                is_active=True,
                cert_path=cert_info["crt_path"],
                key_path=cert_info["key_path"],
                created_at=current_time,
                updated_at=current_time,
            )

            download = AgentDownload(
                agent_id=agent_id,
                download_token_hash=download_token_hash,
                zip_path=zip_path,
                downloaded=False,
                expires_at=current_time + DOWNLOAD_LINK_TTL,
                created_at=current_time,
            )

            db.add(agent)
            db.add(download)
            await db.commit()

    except Exception:
        discard_agent_files(agent_id)
        if acl_created:
            await asyncio.to_thread(remove_agent_credentials, agent_id)
        raise


    clear_agent_auth_cache(agent_id)

    return {
        "agent_id": agent_id,
        "zip_path": zip_path,
        "download_token": download_token,
        "download_url": _download_url(download_token),
    }


async def regenerate_agent_package(agent: Agent):

    current_time = datetime.now()

    secret_token = generate_token()
    download_token = generate_token()

    secret_token_hash = hash_token(secret_token)
    download_token_hash = hash_token(download_token)

    username, password, _ = await asyncio.to_thread(ensure_agent_credentials, agent.agent_id)
    site_conf = await build_site_conf(agent.agent_id, username, password)

    cert_info = get_existing_agent_cert(agent.agent_id)
    _, zip_path = agent_file_paths(agent.agent_id)
    info_path = os.path.join(cert_info["agent_dir"], "agent_info.txt")
    backup_suffix = f".regen.{generate_token()[:12]}"
    zip_backup = zip_path + backup_suffix
    info_backup = info_path + backup_suffix
    if os.path.isfile(zip_path):
        os.link(zip_path, zip_backup)
    if os.path.isfile(info_path):
        shutil.copy2(info_path, info_backup)

    try:
        zip_path = create_agent_zip(agent.agent_id, secret_token, cert_info, site_conf)
        async with AsyncSessionLocal() as db:
            db_agent = await db.get(Agent, agent.id)

            if not db_agent:
                raise Exception("ไม่พบ Client Server ในฐานข้อมูล")

            db_agent.secret_token_hash = secret_token_hash
            db_agent.cert_path = cert_info["crt_path"]
            db_agent.key_path = cert_info["key_path"]
            db_agent.status = "pending"
            db_agent.updated_at = current_time


            await db.execute(
                update(AgentDownload)
                .where(AgentDownload.agent_id == db_agent.agent_id,
                       AgentDownload.downloaded == False)
                .values(downloaded=True, downloaded_at=current_time)
            )
            await clear_agent_ip_binding(db, db_agent)

            download = AgentDownload(
                agent_id=db_agent.agent_id,
                download_token_hash=download_token_hash,
                zip_path=zip_path,
                downloaded=False,
                expires_at=current_time + DOWNLOAD_LINK_TTL,
                created_at=current_time,
            )

            db.add(download)
            await db.commit()
    except Exception:
        if os.path.isfile(zip_backup):
            os.replace(zip_backup, zip_path)
        if os.path.isfile(info_backup):
            os.replace(info_backup, info_path)
        raise
    finally:
        for path in (zip_backup, info_backup):
            if os.path.isfile(path):
                os.unlink(path)


    clear_agent_auth_cache(agent.agent_id)

    return {
        "agent_id": agent.agent_id,
        "zip_path": zip_path,
        "download_token": download_token,
        "download_url": _download_url(download_token),
    }
