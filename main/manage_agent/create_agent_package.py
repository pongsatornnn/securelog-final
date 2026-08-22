import os
import shutil
import zipfile
import subprocess
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo

from database.connection import AsyncSessionLocal
from database.crud import clear_agent_ip_binding, get_agent_by_agent_id
from database.models import Agent, AgentDownload
from manage_agent.token_utils import generate_token, hash_token
from auth_cache import clear_agent_auth_cache
from settings_cache import get_setting_async


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))

CA_CERT = os.path.join(PROJECT_ROOT, "cert/central/ca.crt")
CA_KEY = os.path.join(PROJECT_ROOT, "cert/central/ca.key")

AGENT_CERT_DIR = os.path.join(PROJECT_ROOT, "cert/agent")
PACKAGE_DIR = os.path.join(PROJECT_ROOT, "main/agent_packages")

# ชุดไฟล์ติดตั้งฝั่ง agent (setup.sh, agent_core.py, filebeat template ฯลฯ)
# ถูกใส่เข้า zip ทุกไฟล์ — แตก zip แล้ว sudo ./setup.sh ได้เลย
AGENT_TEMPLATE_DIR = os.path.join(PROJECT_ROOT, "for_Agent/package")

DOWNLOAD_LINK_TTL = timedelta(minutes=2)

# ไฟล์ในโฟลเดอร์ template ที่ **ไม่** เอาใส่ zip ตรง ๆ
# site.conf: สร้างใหม่จากค่าในหน้า System Settings ทุกครั้ง (ดู build_site_conf)
# site.conf.example: เป็นตัวอย่างสำหรับคนอ่าน repo ไม่มีประโยชน์กับเครื่องที่เอาไปติดตั้ง
SKIP_TEMPLATE_FILES = {"site.conf", "site.conf.example"}

TZ = ZoneInfo("Asia/Bangkok")


def now_thai():
    return datetime.now(TZ).replace(tzinfo=None)


async def build_site_conf() -> str:
    """
    สร้างเนื้อไฟล์ site.conf ที่จะฝังไปกับ zip จากค่าในหน้า System Settings

    ค่าพวกนี้เป็นค่า **ร่วมของทุก agent** (เครื่องต่างกันแค่ agent_info.txt + cert)
    เดิมอ่านจาก for_Agent/package/site.conf บนเครื่อง central ซึ่งต้องไปแก้ไฟล์เอง —
    ตอนนี้แก้จากหน้าเว็บได้ แล้ว package ที่สร้างหลังจากนั้นได้ค่าใหม่ทันที

    ⚠️ ค่า redis username/password ต้องตรงกับ redis/users.acl บนเครื่อง central
    การแก้ที่นี่ **ไม่ได้** ไปแก้ users.acl ให้ — เปลี่ยนรหัสต้องแก้ทั้งสองที่แล้ว reload Redis
    และรหัสช่องเดียวนี้ถูกใช้กับ **2 บัญชี** ฝั่งเครื่อง agent: `agent_node` (agent_core ส่ง username ได้)
    กับ `default` (Filebeat ส่งได้แต่ password จึงถูกตีเป็น default เสมอ) ทั้งคู่ใน users.acl
    ต้องตั้งรหัสให้ตรงกัน ไม่งั้นจะได้อาการ "agent ต่อติดแต่ log ไม่เข้า" — ดู redis/README.md

    ใช้ get_setting_async (cache -> DB -> .env) ไม่ใช่ตัวอ่านแบบ sync ที่อ่านแต่ cache —
    ค่ากลุ่มนี้ไม่มีใน .env ถ้า cache หมดอายุพอดีตอนกดสร้าง package จะได้ค่าว่างทั้งชุด
    แล้ว zip ที่ออกไปจะต่อ Redis ไม่ได้ (หรือสร้างไม่สำเร็จ) ทั้งที่ตั้งค่าไว้ครบแล้ว
    """
    host = (await get_setting_async("agent_central_host")).strip()
    port = (await get_setting_async("agent_central_redis_port")).strip() or "6380"
    username = (await get_setting_async("agent_redis_username")).strip()
    password = await get_setting_async("agent_redis_password")

    missing = [
        label
        for label, value in (
            ("Central Host", host),
            ("Redis Username ของ Agent", username),
            ("Redis Password ของ Agent", password),
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
    """
    ลบ cert + zip ของ agent_id ทิ้ง

    ⚠️ เรียกได้เฉพาะตอนที่ยืนยันแล้วว่า **ไม่มีแถวใน DB** คู่กับ agent_id นี้ (ไฟล์กำพร้า)
    ถ้าเรียกกับ agent ที่ยังใช้งานอยู่ = ลบ cert ของเครื่องที่ทำงานปกติทิ้ง
    """
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
        # setup.sh บนเครื่องจริง — ตอนสร้าง package ยังไม่มีทางรู้ว่าจะไปติดตั้งที่ IP อะไร
        # (คงคีย์ไว้เพื่อให้ setup.sh เวอร์ชันเก่าที่ยัง get_info HOST_IP อยู่ไม่พัง)
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
        # แก้ค่าในหน้าเว็บแล้ว package ที่สร้างหลังจากนั้นได้ค่าใหม่ทันที ไม่ต้องแก้ไฟล์บนเครื่อง
        # (ไฟล์ site.conf ในโฟลเดอร์ template จึงถูกข้ามตอนใส่ zip — ดูลูปด้านล่าง)
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
    """
    สร้าง agent ใหม่ + cert + zip

    ไม่มี ip_address ให้ส่งเข้ามา — IP ถูกผูกตอนที่ agent ติดต่อเข้ามาสำเร็จครั้งแรก
    จาก interface ที่เลือกตอนรัน setup.sh บนเครื่องจริง (ตอนสร้าง package ยังไม่มีทางรู้ว่า
    จะไปติดตั้งที่เครื่อง IP อะไร และการให้กรอกเองเปิดช่องให้พิมพ์ผิดแล้วแก้ไม่ได้)
    """
    current_time = now_thai()

    secret_token = generate_token()
    download_token = generate_token()

    secret_token_hash = hash_token(secret_token)
    download_token_hash = hash_token(download_token)

    # ── เก็บกวาดไฟล์กำพร้าจากรอบก่อนที่ล้มเหลว ก่อนเริ่มออกไฟล์ชุดใหม่ ────────────
    #
    # create_agent_cert() ปฏิเสธ agent_id ที่มีโฟลเดอร์ cert อยู่แล้ว และ
    # generate_next_agent_id() คิดเลขจาก max(id) ใน DB — ถ้ารอบก่อนออก cert/zip ไปแล้ว
    # แต่เขียน DB ไม่สำเร็จ จะไม่มีแถวใหม่ให้เลขเดินหน้า ทุกครั้งต่อจากนั้นจึงได้ agent_id
    # ตัวเดิม แล้วชนโฟลเดอร์ที่ค้างอยู่ = สร้าง Client Server ไม่ได้อีกเลยจนกว่าจะลบด้วยมือ
    #
    # ไม่มีแถวใน DB = ไฟล์ชุดนั้นไม่มีเจ้าของ ลบได้ปลอดภัย · มีแถวอยู่ = ห้ามแตะ
    # (เช็คที่นี่ ไม่ใช่ที่ route เพราะ create_agent.py ก็เรียกเข้ามาตรง ๆ ด้วย agent_id ที่พิมพ์เอง)
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
                ip_address=None,      # ผูกทีหลังตอน agent ติดต่อเข้ามาครั้งแรก
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
        # interface ที่เลือกตอนนั้น (แก้ในหน้าเว็บเฉย ๆ ไม่ได้โดยตั้งใจ)
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