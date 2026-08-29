import os
import shutil
import zipfile
import subprocess
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from dotenv import load_dotenv

from database.connection import AsyncSessionLocal
from database.crud import clear_agent_ip_binding, get_agent_by_agent_id
from database.models import Agent, AgentDownload
from manage_agent.token_utils import generate_token, hash_token
from auth_cache import clear_agent_auth_cache
from settings_cache import get_setting_async


load_dotenv()

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

CA_CERT = os.path.join(PROJECT_ROOT, "cert/central/ca.crt")
CA_KEY = os.path.join(PROJECT_ROOT, "cert/central/ca.key")

AGENT_CERT_DIR = os.path.join(PROJECT_ROOT, "cert/agent")
PACKAGE_DIR = os.path.join(PROJECT_ROOT, "main/agent_packages")

# ชุดไฟล์ติดตั้งฝั่ง agent (setup.sh, agent_core.py, filebeat template ฯลฯ)
AGENT_TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "for_Agent/package")

DOWNLOAD_LINK_TTL = timedelta(minutes=5)

# ไฟล์ในโฟลเดอร์ template ที่ **ไม่** เอาใส่ zip ตรง ๆ
SKIP_TEMPLATE_FILES = {"site.conf", "site.conf.example"}

TZ = ZoneInfo("Asia/Bangkok")


def now_thai():
    return datetime.now(TZ).replace(tzinfo=None)


def central_address() -> tuple[str, str]:
    """ที่อยู่ + พอร์ต Redis ของ central ที่ agent ต้องต่อกลับมา — มาจาก `.env` ไม่ใช่หน้าเว็บ"""
    host = (os.getenv("AGENT_CENTRAL_HOST") or os.getenv("REDIS_HOST") or "").strip()
    port = (os.getenv("AGENT_CENTRAL_REDIS_PORT") or os.getenv("REDIS_PORT") or "").strip()

    return host, port or "6380"


async def build_site_conf() -> str:
    """สร้างเนื้อไฟล์ site.conf ที่จะฝังไปกับ zip"""
    host, port = central_address()
    username = (await get_setting_async("agent_redis_username")).strip()
    password = await get_setting_async("agent_redis_password")

    if not host:
        raise Exception(
            "ไม่รู้ที่อยู่ของ Central (ไม่มีทั้ง AGENT_CENTRAL_HOST และ REDIS_HOST ใน .env) — "
            "รัน setup-server.sh ให้จบก่อนสร้าง package"
        )

    # สองค่านี้แก้ได้จากหน้าเว็บ จึงบอกทางไปแก้ได้ตรง ๆ (ต่างจาก host ที่ต้องไปทาง setup-server.sh)
    missing = [
        label
        for label, value in (
            ("Redis Username ของ Client Server", username),
            ("Redis Password ของ Client Server", password),
        )
        if not value
    ]

    if missing:
        raise Exception(
            "ยังตั้งค่าชุดติดตั้ง Client Server ไม่ครบ (" + ", ".join(missing) + ") — "
            "ตั้งได้ที่หน้า System Settings ก่อนสร้าง package"
        )

    return (
        "# ค่าต่อ site ของชุดติดตั้ง agent\n"
        "# ไฟล์นี้ถูกสร้างอัตโนมัติตอนออก package จากค่าในหน้า System Settings ของ Central\n"
        "# แก้ไฟล์นี้บนเครื่อง agent ได้ แต่ถ้าออก package ใหม่จะถูกเขียนทับด้วยค่าจากหน้าเว็บอีก\n"
        "\n"
        f'CENTRAL_HOST="{host}"\n'
        f'CENTRAL_REDIS_PORT="{port}"\n'
        f'REDIS_USERNAME="{username}"\n'
        f'REDIS_PASSWORD="{password}"\n'
    )


def run_cmd(cmd: list[str]):
    subprocess.run(cmd, check=True)


def agent_file_paths(agent_id: str) -> tuple[str, str]:
    """โฟลเดอร์ cert + ไฟล์ zip ของ agent ตัวนี้ — ที่เดียวที่ประกอบ path สองอันนี้"""
    return (
        os.path.join(AGENT_CERT_DIR, agent_id),
        os.path.join(PACKAGE_DIR, f"{agent_id}.zip"),
    )


def discard_agent_files(agent_id: str) -> None:
    """ลบ cert + zip ของ agent_id ทิ้ง"""
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

    agent_dir = cert_info["agent_dir"]
    zip_path = os.path.join(PACKAGE_DIR, f"{agent_id}.zip")
    info_path = os.path.join(agent_dir, "agent_info.txt")

    created_at = now_thai().strftime("%Y-%m-%d %H:%M:%S")

    with open(info_path, "w", encoding="utf-8") as f:
        f.write(f"AGENT_ID={agent_id}\n")
        f.write(f"SECRET_TOKEN={secret_token}\n")
        f.write(f"CERT_FILE={agent_id}.crt\n")
        f.write(f"KEY_FILE={agent_id}.key\n")
        f.write("CA_FILE=ca.crt\n")
        # เว้นว่างไว้เสมอ: IP ถูกผูกตอน agent ติดต่อเข้ามาครั้งแรก จาก interface ที่เลือกตอนรัน
        f.write("HOST_IP=\n")
        f.write("TIMEZONE=Asia/Bangkok\n")
        f.write(f"PACKAGE_CREATED_AT={created_at}\n")

    if not os.path.isdir(AGENT_TEMPLATE_DIR):
        raise Exception(f"ไม่พบโฟลเดอร์ชุดติดตั้ง agent: {AGENT_TEMPLATE_DIR}")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zipf:
        zipf.write(cert_info["crt_path"], arcname=f"{agent_id}.crt")
        zipf.write(cert_info["key_path"], arcname=f"{agent_id}.key")
        zipf.write(cert_info["ca_path"], arcname="ca.crt")
        zipf.write(info_path, arcname="agent_info.txt")

        # site.conf สร้างจากค่าในหน้า System Settings ทุกครั้ง ไม่ได้ก๊อปไฟล์ในเครื่อง —
        zipf.writestr("site.conf", site_conf)

        # zipf.write เก็บ file mode ไว้ด้วย — setup.sh ยังเป็น executable หลังแตก zip
        for name in sorted(os.listdir(AGENT_TEMPLATE_DIR)):
            if name.startswith(".") or name in SKIP_TEMPLATE_FILES:
                continue
            zipf.write(os.path.join(AGENT_TEMPLATE_DIR, name), arcname=name)

    os.chmod(zip_path, 0o600)
    return zip_path


async def create_agent_package(
    agent_id: str,
    hostname: str | None = None,
    description: str | None = None,
):
    """สร้าง agent ใหม่ + cert + zip"""
    current_time = now_thai()

    secret_token = generate_token()
    download_token = generate_token()

    secret_token_hash = hash_token(secret_token)
    download_token_hash = hash_token(download_token)

    # ── เก็บกวาดไฟล์กำพร้าจากรอบก่อนที่ล้มเหลว ก่อนเริ่มออกไฟล์ชุดใหม่ ────────────
    async with AsyncSessionLocal() as db:
        if await get_agent_by_agent_id(db, agent_id):
            raise ValueError(f"มี {agent_id} อยู่ในระบบแล้ว")

    discard_agent_files(agent_id)

    # สร้างเนื้อ site.conf ก่อนออก cert — ถ้าตั้งค่าไม่ครบจะได้ไม่ทิ้ง cert ค้างไว้
    site_conf = await build_site_conf()

    # ตั้งแต่จุดนี้มีการเขียนไฟล์ลงดิสก์ — พังตรงไหนก็ตามต้องเก็บกวาดให้หมดก่อนโยนต่อ
    try:
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
        raise

    # ล้าง cache เผื่อมี cache เก่าค้างจาก agent_id เดิม
    clear_agent_auth_cache(agent_id)

    return {
        "agent_id": agent_id,
        "zip_path": zip_path,
        "download_token": download_token,
        "download_url": f"/download-agent/{download_token}",
    }


async def regenerate_agent_package(agent: Agent):
    current_time = now_thai()

    secret_token = generate_token()
    download_token = generate_token()

    secret_token_hash = hash_token(secret_token)
    download_token_hash = hash_token(download_token)

    site_conf = await build_site_conf()

    cert_info = get_existing_agent_cert(agent.agent_id)
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

        # ทางเดียวที่ IP ที่ผูกไว้จะเปลี่ยนได้ — package ชุดใหม่ = ติดตั้งใหม่ = ผูกใหม่จาก
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

    # สำคัญมาก: regen token แล้วต้องล้าง cache ทันที
    clear_agent_auth_cache(agent.agent_id)

    return {
        "agent_id": agent.agent_id,
        "zip_path": zip_path,
        "download_token": download_token,
        "download_url": f"/download-agent/{download_token}",
    }