"""
Cache + DB layer สำหรับค่าตั้งของระบบที่แก้ได้ตอนรัน (หน้า System Settings)
โครงเดียวกับ rule_cache.py / severity_cache.py / blacklist_ttl_cache.py — cache-first แล้ว DB
แก้ค่าผ่าน update_setting() จะเคลียร์+เขียน cache ทันที ทุก process เห็นค่าใหม่โดยไม่ต้อง restart

ลำดับการหาค่า:  Redis cache  ->  ตาราง app_settings  ->  .env  ->  ค่า default ในโค้ด

**ทำไมต้องมีทั้งตัวอ่านแบบ sync และ async:**
ตัวใช้งานจริงของค่าพวกนี้ (LINE_API/line_client.py, AI_API/gemini_client.py) เป็นโค้ด sync
ที่เรียก urllib ตรง ๆ จะให้ไป await DB กลางทางไม่ได้ จึงแยกเป็น
  - `get_setting()`  (sync)  — อ่าน **จาก cache เท่านั้น** ถ้า miss ตกไป .env/default
  - `ensure_loaded()` (async) — เติม cache จาก DB ให้ครบทุกคีย์ เรียกที่ "ทางเข้า" ฝั่ง async
    (lifespan ตอน start, webhook, endpoint ที่เรียก AI, ตัว subscriber ก่อน push)
ทางเข้าทุกทางของโค้ด sync เหล่านั้นเป็น async ทั้งหมด -> เรียก ensure_loaded() ก่อนเสมอ
cache จึงอุ่นอยู่แล้วตอน sync อ่าน · ถ้า Redis ล่มพอดี ค่าจะตกไป .env (ค่าเดิมก่อนมีหน้านี้)
ซึ่งแย่กว่าค่าที่ตั้งไว้ แต่ไม่ทำให้ระบบพัง — เป็น trade-off ที่ยอมรับ ดู problem.md ข้อ 5

**ค่าที่เป็น secret ถูกเข้ารหัสก่อนเก็บลง DB** (ดู secret_box.py) — กุญแจอยู่ในไฟล์นอกฐานข้อมูล
ค่าที่วิ่งผ่าน cache จึงเป็น ciphertext ด้วย (ถอดตอนอ่านเท่านั้น) เพราะ Redis เขียน dump ลงดิสก์ได้
ทำให้ทั้ง backup ของ DB และไฟล์ dump ของ Redis ไม่มีคีย์จริงอยู่เลย

**ห้ามเอา config ชั้น bootstrap มาไว้ที่นี่** (DB, Redis ของ central, cert, JWT/CSRF, bind IP/port)
เพราะแอปต้องใช้ค่าพวกนั้นก่อนจะต่อ DB/Redis ได้ = ไก่กับไข่
"""

import os

from dotenv import load_dotenv

from database.connection import AsyncSessionLocal
from database.crud import (
    get_app_setting,
    get_all_app_settings,
    upsert_app_setting,
    delete_app_setting,
    log_app_setting_change,
    get_app_setting_changes,
    get_latest_app_setting_changes,
)
from redis_client import cache_get_json, cache_set_json, cache_delete
from secret_box import decrypt, encrypt, is_encrypted


load_dotenv()

SETTINGS_CACHE_TTL_SECONDS = 300
CACHE_KEY_PREFIX = "app_setting:"

# คีย์ยาม: มีอยู่ใน cache = เพิ่งเติม cache จาก DB มาแล้วในรอบ TTL นี้
# (ไม่งั้น ensure_loaded() จะยิง DB ทุก request)
LOADED_FLAG_KEY = f"{CACHE_KEY_PREFIX}_loaded"

LOG_PREFIX = "SETTINGS-CACHE"


# ── รายการคีย์ที่ระบบรู้จัก ────────────────────────────────────────────────
# secret=True  -> API ส่งกลับเป็นค่าที่ mask แล้วเท่านั้น ไม่เคยส่งค่าเต็มออกจากเซิร์ฟเวอร์
# env          -> ชื่อตัวแปรใน .env ที่ใช้เป็น fallback (ของเดิมก่อนมีหน้านี้ จึงไม่พังตอนอัปเกรด)
SETTING_DEFS: dict[str, dict] = {
    # ── LINE ──
    "line_channel_access_token": {
        "group": "line",
        "label": "Channel Access Token",
        "hint": "token ของ Messaging API — ใช้ส่งข้อความและดึงโปรไฟล์",
        "secret": True,
        "env": "LINE_CHANNEL_ACCESS_TOKEN",
        "default": "",
    },
    "line_channel_secret": {
        "group": "line",
        "label": "Channel Secret",
        "hint": "ใช้ตรวจลายเซ็น webhook — ไม่มีค่านี้ webhook ปฏิเสธทุก request",
        "secret": True,
        "env": "LINE_CHANNEL_SECRET",
        "default": "",
    },
    "line_oa_id": {
        "group": "line",
        "label": "LINE OA ID",
        "hint": "Basic ID ของ OA เช่น @123abcd — ใช้สร้างลิงก์แอดเพื่อน",
        "secret": False,
        "env": "LINE_OA_ID",
        "default": "",
    },
    # ── Gemini ──
    "gemini_api_key": {
        "group": "gemini",
        "label": "API Key",
        "hint": "API key จาก Google AI Studio — ไม่มีค่านี้ ปุ่มวิเคราะห์ AI ใช้ไม่ได้",
        "secret": True,
        "env": "GEMINI_API_KEY",
        "default": "",
    },
    "gemini_model": {
        "group": "gemini",
        "label": "Model",
        "hint": "โมเดลที่ใช้สรุป log เช่น gemini-2.5-flash",
        "secret": False,
        "env": "GEMINI_MODEL",
        "default": "gemini-2.5-flash",
    },
    # ── ค่าที่ฝังลงชุดติดตั้ง Agent (site.conf ใน zip) ──
    #
    # **รหัส Redis ตัวเดียวนี้ถูกใช้กับ 2 บัญชีใน users.acl** — เป็นข้อจำกัดของ Filebeat ไม่ใช่การมักง่าย:
    #   - agent_core.py (redis-py) ส่ง `AUTH agent_node <รหัส>`  -> เข้าเป็น `agent_node`
    #   - Filebeat (output.redis) ส่ง `AUTH <รหัส>` เฉย ๆ (ใส่ username ไม่ได้) -> Redis ตีเป็น `default` เสมอ
    # site.conf ที่ออกไปกับ zip มีช่องรหัสช่องเดียว ทั้งสองบัญชีจึง **ต้องตั้งรหัสให้ตรงกัน**
    # (Redis เก็บรหัสเป็น hash แยกต่อ user — ซ้ำกันได้ ไม่ชนกัน) และ `default` ต้องเปิดไว้แบบจำกัดสิทธิ์
    # ห้ามใช้รหัสนี้ซ้ำกับ user `admin` ที่ central ใช้ (`+@all ~*`) — อันนั้นต้องเป็นรหัสของตัวเอง
    "agent_central_host": {
        "group": "agent",
        "label": "Central Host",
        "hint": "IP/hostname ที่ Client Server ต่อเข้ามา — ต้องตรงกับ SAN ในใบรับรอง",
        "secret": False,
        "env": "AGENT_CENTRAL_HOST",
        "default": "",
    },
    "agent_central_redis_port": {
        "group": "agent",
        "label": "Central Redis Port",
        "hint": "พอร์ต Redis ฝั่ง Central (mTLS)",
        "secret": False,
        "env": "AGENT_CENTRAL_REDIS_PORT",
        "default": "6380",
    },
    "agent_redis_username": {
        "group": "agent",
        "label": "Redis Username ของ Client Server",
        "hint": "user ที่ agent_core ใช้ต่อ Redis · Filebeat ไม่ใช้ค่านี้ (เข้าเป็น default เสมอ)",
        "secret": False,
        "env": "AGENT_REDIS_USERNAME",
        "default": "agent_node",
    },
    "agent_redis_password": {
        "group": "agent",
        "label": "Redis Password ของ Client Server",
        "hint": "ใช้ร่วมกัน 2 บัญชี (agent_node + default) — ระบบแก้ redis/users.acl ให้เอง",
        "secret": True,
        "env": "AGENT_REDIS_PASSWORD",
        "default": "",
        # ต้องยืนยันรหัสเดิมก่อนเปลี่ยน (เฉพาะตอนที่มีค่าตั้งไว้แล้ว) — ค่านี้ถูกฝังลงชุดติดตั้ง
        # ของทุกเครื่อง เปลี่ยนพลาดทีเดียว agent ทุกตัวส่ง log เข้าไม่ได้จนกว่าจะออก package ใหม่
        "confirm_current": True,
        # ตรวจด้วยเงื่อนไขเดียวกับรหัสของ central (redis_password_rules) เพราะลงเอยที่
        # users.acl / site.conf เหมือนกัน — อักขระที่ทำให้ไฟล์เพี้ยนคือชุดเดียวกัน
        "password_rules": True,
        # แก้ผ่าน popup แยก ไม่ใช่ช่องกรอกในแถวเหมือนคีย์อื่น — ต้องกรอกรหัสเดิม/ใหม่/ยืนยัน
        # และต้องเห็นคำเตือนว่าเปลี่ยนแล้วต้องตามไปทำอะไรต่อ ก่อนกดยืนยัน
        "change_via_modal": True,
        # ระบบเขียน users.acl ทั้งสองบรรทัดแล้วสั่ง ACL LOAD ให้เอง (redis_admin_password.
        # apply_agent_password) — ที่เหลือเป็นงานที่ระบบทำแทนไม่ได้ เพราะรหัสอยู่ในไฟล์บนเครื่อง agent
        "apply_to_redis_acl": True,
        # คำเตือนบรรทัดเดียวใน popup — โชว์ **ก่อน** กรอก ไม่ใช่หลังกดสำเร็จ เพราะชุดติดตั้งใหม่
        # คือของที่ต้องเตรียมไว้ก่อน พอกดปุ๊บ agent เดิมส่ง log ไม่ได้ทันที
        "change_warning": (
            "กดแล้ว agent เดิมส่ง log ไม่เข้า จนกว่าจะเอาชุดติดตั้งใหม่ไปลงครบทุกเครื่อง "
            "· users.acl กับ ACL LOAD ระบบทำให้เอง"
        ),
    },
    # ── นโยบายยกระดับเมื่อ IP เดิมโดน block ซ้ำ (escalation) ──
    # อยู่หน้า Rules ไม่ใช่หน้า System Settings เพราะเป็นค่าตรรกะการตอบสนอง
    # ตระกูลเดียวกับ detection_rules / blacklist_ttl ไม่ใช่คีย์ของบริการภายนอก
    "escalation_multiplier": {
        "group": "escalation",
        "page": "rules",
        "label": "ตัวคูณเมื่อโดนซ้ำ",
        "hint": "โดนซ้ำครั้งถัดไป ระยะเวลาคูณด้วยค่านี้ (1 = ไม่ทวีคูณ)",
        "secret": False,
        "env": "ESCALATION_MULTIPLIER",
        "default": "2",
    },
    "escalation_max_block_count": {
        "group": "escalation",
        "page": "rules",
        "label": "โดนซ้ำกี่ครั้งจึงบล็อกถาวร",
        "hint": "โดนซ้ำเกินค่านี้ = บล็อกถาวร ไม่ปลดเอง",
        "secret": False,
        "env": "MAX_BLOCK_COUNT_BEFORE_PERMANENT",
        "default": "5",
    },
}

GROUP_LABELS = {
    "line": "LINE Messaging API",
    "gemini": "Google Gemini (AI สรุปเหตุการณ์)",
    "agent": "ชุดติดตั้ง Client Server (site.conf ใน zip)",
    "escalation": "การยกระดับเมื่อโดนบล็อกซ้ำ",
}

# หน้าไหนเป็นเจ้าของค่าตั้งคีย์นั้น — ค่าเริ่มต้นคือหน้า System Settings
# ใช้กันไม่ให้ค่าของหน้าหนึ่งไปโผล่/ถูกแก้จากอีกหน้าโดยไม่ผ่าน validation ของหน้านั้น
def setting_page(key: str) -> str:
    return SETTING_DEFS[key].get("page", "settings")


def keys_for_page(page: str) -> list[str]:
    return [k for k in SETTING_DEFS if setting_page(k) == page]


# ค่ากลุ่ม agent เดิมอยู่ในไฟล์นี้บนเครื่อง central (คนตั้งเองตอน setup) — ไม่ได้อยู่ใน .env
# จึงต้องยกมาเป็นค่าตั้งต้นให้ตอนอัปเกรด ไม่งั้นเครื่องที่ใช้งานอยู่จะสร้าง package ไม่ได้
# เพราะค่าว่างหมด (ดู seed_agent_settings_from_site_conf)
SITE_CONF_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "for_Agent", "package", "site.conf",
)

# ชื่อตัวแปรใน site.conf -> setting key ของเรา
SITE_CONF_KEY_MAP = {
    "CENTRAL_HOST": "agent_central_host",
    "CENTRAL_REDIS_PORT": "agent_central_redis_port",
    "REDIS_USERNAME": "agent_redis_username",
    "REDIS_PASSWORD": "agent_redis_password",
}


def setting_cache_key(key: str) -> str:
    return f"{CACHE_KEY_PREFIX}{key}"


def _parse_site_conf(path: str) -> dict[str, str]:
    """อ่าน site.conf (รูปแบบ KEY="value" แบบ shell) — คืน dict ว่างถ้าไม่มีไฟล์/อ่านไม่ได้"""
    values: dict[str, str] = {}

    try:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue

                name, _, raw = line.partition("=")
                key = SITE_CONF_KEY_MAP.get(name.strip())
                if key:
                    values[key] = raw.strip().strip('"').strip("'")
    except OSError:
        pass

    return values


async def seed_agent_settings_from_site_conf() -> int:
    """
    ยกค่าจาก for_Agent/package/site.conf มาเป็นค่าตั้งต้นของกลุ่ม agent — **เฉพาะคีย์ที่ยังไม่มีแถว**
    ไม่เขียนทับค่าที่แอดมินตั้งไว้เอง และรันซ้ำได้ (เรียกทุกครั้งที่ start)

    หลังจากนี้ไฟล์ site.conf บนเครื่อง central ไม่ถูกใช้แล้ว — ค่าจริงมาจาก DB
    (create_agent_package.build_site_conf สร้างไฟล์ใหม่ใส่ zip ทุกครั้ง)
    """
    from_file = _parse_site_conf(SITE_CONF_PATH)
    if not from_file:
        return 0

    seeded = 0
    async with AsyncSessionLocal() as db:
        existing = {r.setting_key for r in await get_all_app_settings(db)}

        for key, value in from_file.items():
            if key in existing or not value:
                continue
            # ผ่าน encrypt เหมือนทางปกติ — REDIS_PASSWORD เป็น secret ถ้าเขียนตรงจะได้ plaintext
            stored = encrypt(value) if SETTING_DEFS[key]["secret"] else value
            await upsert_app_setting(db, key, stored)
            # ลงประวัติเป็นของ "system" ด้วย ไม่งั้นค่าที่ระบบยกมาเองจะดูเหมือนไม่มีใครตั้ง
            await log_app_setting_change(
                db, key, "set", "system",
                old_value=None, new_value=_for_audit(key, stored), source="startup",
            )
            seeded += 1

    if seeded:
        print(f"[{LOG_PREFIX}] ยกค่าจาก site.conf มาเป็นค่าตั้งต้น {seeded} รายการ")

    return seeded


def env_default(key: str) -> str:
    """ค่าที่จะใช้เมื่อยังไม่เคยตั้งผ่านหน้าเว็บ — จาก .env ก่อน แล้วค่อยค่า default ในโค้ด"""
    spec = SETTING_DEFS[key]
    return os.getenv(spec["env"], "") or spec["default"]


def get_setting(key: str) -> str:
    """
    อ่านค่าแบบ sync — **cache เท่านั้น** miss แล้วตกไป .env/default (ดูหมายเหตุหัวไฟล์)
    ใช้ในโค้ด sync อย่าง line_client / gemini_client ที่ await ไม่ได้
    """
    if key not in SETTING_DEFS:
        raise KeyError(f"ไม่รู้จัก setting key: {key}")

    cached = cache_get_json(setting_cache_key(key), log_prefix=LOG_PREFIX)
    if cached is not None:
        # ค่าใน cache เก็บรูปเดียวกับใน DB (secret = ciphertext) ถอดตอนอ่านเท่านั้น
        return decrypt(cached.get("value", ""))

    return env_default(key)


def _cache_one(key: str, value: str) -> None:
    cache_set_json(
        setting_cache_key(key),
        {"value": value},
        SETTINGS_CACHE_TTL_SECONDS,
        log_prefix=LOG_PREFIX,
    )


async def encrypt_existing_secrets() -> int:
    """
    แปลงค่า secret ที่ยังเก็บเป็น plaintext ใน DB ให้เป็น ciphertext — เรียกตอน start ทุกครั้ง

    จำเป็นสำหรับเครื่องที่ตั้งค่าไว้ก่อนจะมีการเข้ารหัส (และแถวที่ seed มาจาก site.conf
    รุ่นก่อนหน้า) · รันซ้ำได้ ค่าที่เข้ารหัสแล้วจะถูกข้าม (เช็คด้วย is_encrypted)

    ไม่ยุ่งกับคีย์ที่ไม่ใช่ secret — พวกนั้นตั้งใจให้เป็น plaintext
    """
    converted = 0

    async with AsyncSessionLocal() as db:
        for row in await get_all_app_settings(db):
            spec = SETTING_DEFS.get(row.setting_key)

            if not spec or not spec["secret"] or not row.value:
                continue
            if is_encrypted(row.value):
                continue

            await upsert_app_setting(db, row.setting_key, encrypt(row.value))
            converted += 1

    if converted:
        print(f"[{LOG_PREFIX}] เข้ารหัสค่า secret ที่ยังเป็น plaintext ใน DB แล้ว {converted} รายการ")

    return converted


async def load_all_into_cache() -> dict[str, str]:
    """
    อ่าน app_settings ทั้งตารางแล้วเติม cache ให้ครบ **ทุกคีย์ที่ระบบรู้จัก**
    (คีย์ที่ยังไม่มีแถวก็ cache ค่าจาก .env ไว้ด้วย เพื่อให้ตัวอ่าน sync ได้ค่าเดียวกันเสมอ)
    """
    async with AsyncSessionLocal() as db:
        rows = {r.setting_key: r.value for r in await get_all_app_settings(db)}

    values = {}
    for key in SETTING_DEFS:
        # มีแถวใน DB = ใช้ค่านั้นเสมอ แม้เป็นค่าว่าง (แอดมินตั้งใจล้างค่า ไม่ใช่ "ยังไม่ตั้ง")
        if key in rows:
            stored = rows[key] or ""
        else:
            # ค่าจาก .env เป็น plaintext — เข้ารหัสก่อนลง cache ให้รูปตรงกับที่มาจาก DB
            fallback = env_default(key)
            stored = encrypt(fallback) if SETTING_DEFS[key]["secret"] else fallback

        _cache_one(key, stored)
        values[key] = decrypt(stored)

    cache_set_json(LOADED_FLAG_KEY, {"value": "1"}, SETTINGS_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)
    return values


async def ensure_loaded() -> None:
    """
    เรียกที่ทางเข้าฝั่ง async ก่อนที่โค้ด sync จะไปอ่านค่า — เติม cache จาก DB ถ้ายังไม่ได้เติม
    ราคาถูก: ถ้า cache อุ่นอยู่แล้วเสีย Redis GET แค่ครั้งเดียว
    """
    if cache_get_json(LOADED_FLAG_KEY, log_prefix=LOG_PREFIX) is not None:
        return
    await load_all_into_cache()


async def get_setting_async(key: str) -> str:
    """อ่านค่าแบบเต็มลำดับ cache -> DB -> .env (ใช้ในโค้ด async ที่อยากได้ค่าแม่นสุด)"""
    if key not in SETTING_DEFS:
        raise KeyError(f"ไม่รู้จัก setting key: {key}")

    cached = cache_get_json(setting_cache_key(key), log_prefix=LOG_PREFIX)
    if cached is not None:
        return decrypt(cached.get("value", ""))

    async with AsyncSessionLocal() as db:
        row = await get_app_setting(db, key)

    stored = row.value if row else env_default(key)
    _cache_one(key, stored or "")
    return decrypt(stored or "")


async def get_int_setting_async(key: str, minimum: int = 1) -> int:
    """
    อ่านค่าตั้งที่เป็นจำนวนเต็ม — ใช้กับค่าที่อยู่ในเส้นทางตัดสินใจ (เช่น escalation)
    ที่ห้ามพังเพราะค่าใน DB เสียหาย: แปลงไม่ได้ก็ตกกลับไปใช้ default ในโค้ด
    แล้วบังคับขั้นต่ำอีกชั้น ค่าที่คืนจึงใช้คำนวณต่อได้เสมอ
    """
    raw = await get_setting_async(key)

    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = int(SETTING_DEFS[key]["default"])

    return max(minimum, value)


def _for_audit(key: str, stored: str | None) -> str | None:
    """
    แปลงค่าที่เก็บใน DB ให้อยู่ในรูปที่ "บันทึกลงประวัติได้" —
    คีย์ที่เป็น secret ต้องออกมาเป็นค่า mask เท่านั้น (ตารางประวัติห้ามมีคีย์จริงเด็ดขาด)
    ถอดรหัสไม่ได้ (กุญแจเปลี่ยน/ค่าเพี้ยน) ก็คืนเป็น mask ล้วน ไม่ใช่ปล่อย ciphertext ออกไป
    """
    if stored is None:
        return None

    if not SETTING_DEFS[key]["secret"]:
        return stored

    try:
        return mask_secret(decrypt(stored))
    except Exception:
        return "••••••••"


async def update_setting(
    key: str, value: str, actor: str = "system", source: str = "settings",
    actor_id: int | None = None,
) -> str:
    """
    ตั้งค่าทับจากหน้าเว็บ — เขียน DB แล้วอัปเดต cache ทันที (ไม่ต้องรอ TTL)

    `actor` = ชื่อผู้ใช้ที่กด (route ส่ง user["username"] มา) · ไม่ได้ส่งมา = งานอัตโนมัติของระบบ
    บันทึกลงประวัติทุกครั้งแม้ค่าจะเท่าเดิม — "ใครกดบันทึกเมื่อไหร่" ก็เป็นข้อมูลที่ต้องตรวจย้อนได้
    """
    if key not in SETTING_DEFS:
        raise KeyError(f"ไม่รู้จัก setting key: {key}")

    value = (value or "").strip()

    # เก็บลง DB เป็น ciphertext ถ้าคีย์นี้เป็น secret — cache ก็เก็บรูปเดียวกัน
    stored = encrypt(value) if SETTING_DEFS[key]["secret"] else value

    async with AsyncSessionLocal() as db:
        before = await get_app_setting(db, key)
        old_stored = before.value if before else None

        await upsert_app_setting(db, key, stored)
        await log_app_setting_change(
            db, key, "set", actor,
            old_value=_for_audit(key, old_stored),
            new_value=_for_audit(key, stored),
            source=source,
            changed_by_user_id=actor_id,
        )

    _cache_one(key, stored)
    return value


async def reset_setting(
    key: str, actor: str = "system", source: str = "settings",
    actor_id: int | None = None,
) -> str:
    """
    ลบค่าที่ตั้งทับไว้ กลับไปใช้ค่าจาก .env — ต่างจากการตั้งเป็นค่าว่าง
    (ค่าว่าง = ตั้งใจปิดฟีเจอร์นั้น · reset = ยกเลิกการตั้งทับทั้งหมด)
    """
    if key not in SETTING_DEFS:
        raise KeyError(f"ไม่รู้จัก setting key: {key}")

    async with AsyncSessionLocal() as db:
        removed = await delete_app_setting(db, key)
        await log_app_setting_change(
            db, key, "reset", actor,
            old_value=_for_audit(key, removed.value if removed else None),
            new_value=None,          # กลับไปใช้ค่าจาก .env — ไม่มีค่าตั้งทับแล้ว
            source=source,
            changed_by_user_id=actor_id,
        )

    value = env_default(key)
    # cache ต้องเก็บรูปเดียวกับที่ตัวอ่านคาดไว้เสมอ (secret = ciphertext) ไม่งั้น decrypt()
    # จะเจอ plaintext จาก .env แล้วคืนไปตรง ๆ — ได้ค่าถูก แต่รูปไม่สม่ำเสมอ
    _cache_one(key, encrypt(value) if SETTING_DEFS[key]["secret"] else value)
    return value


def mask_secret(value: str) -> str:
    """
    ค่าที่เป็น secret ห้ามส่งกลับหน้าเว็บเต็ม ๆ — โชว์แค่ 4 ตัวท้ายพอให้แอดมินเทียบได้ว่าใช่ตัวที่ตั้งไว้
    ค่าสั้นกว่า 8 ตัวปิดทั้งหมด (โชว์ท้าย 4 ของค่า 6 ตัว = เดาง่ายเกินไป)
    """
    if not value:
        return ""
    if len(value) < 8:
        return "•" * len(value)
    return "•" * 8 + value[-4:]


async def all_settings_for_admin() -> list[dict]:
    """
    รายการค่าทั้งหมดสำหรับหน้า System Settings — ค่า secret ถูก mask แล้ว
    `is_overridden` บอกว่าค่านี้ตั้งทับจากหน้าเว็บ (มีแถวใน DB) หรือยังใช้ค่าจาก .env อยู่
    """
    async with AsyncSessionLocal() as db:
        rows = {r.setting_key: r for r in await get_all_app_settings(db)}

    items = []
    for key, spec in SETTING_DEFS.items():
        # ค่าของหน้าอื่น (เช่น escalation ที่อยู่หน้า Rules) ไม่ต้องโผล่ในหน้านี้
        if setting_page(key) != "settings":
            continue

        row = rows.get(key)
        # ค่าใน DB ของ secret เป็น ciphertext -> ถอดก่อนถึงจะ mask ให้เห็น 4 ตัวท้ายที่ถูกต้อง
        value = decrypt(row.value) if row else (env_default(key) or "")

        items.append({
            "key": key,
            "group": spec["group"],
            "group_label": GROUP_LABELS[spec["group"]],
            "label": spec["label"],
            "hint": spec["hint"],
            "is_secret": spec["secret"],
            "is_set": bool(value),
            "is_overridden": row is not None,
            "env_name": spec["env"],
            # ยังไม่เคยตั้งค่า = ไม่มีรหัสเดิมให้ยืนยัน (ตั้งครั้งแรกผ่านได้เลย)
            "confirm_current": bool(spec.get("confirm_current")) and bool(value),
            "password_rules": bool(spec.get("password_rules")),
            "modal_change": bool(spec.get("change_via_modal")),
            "change_warning": spec.get("change_warning") or "",
            # secret ส่งเฉพาะค่าที่ mask แล้ว · ค่าไม่ลับส่งเต็มเพื่อให้แก้ต่อจากของเดิมได้
            "value": mask_secret(value) if spec["secret"] else value,
            "updated_at": row.updated_at if row else None,
        })

    # ติด "ใครแก้ล่าสุด" ให้ทุกคีย์ในคำสั่งเดียว (แถวล่าสุดต่อคีย์จากตารางประวัติ)
    latest = await latest_setting_change_by_key()
    for item in items:
        last = latest.get(item["key"])
        item["last_changed_by"] = last["changed_by"] if last else None
        item["last_changed_at"] = last["changed_at"] if last else None
        item["last_action"] = last["action"] if last else None

    return items


# ============================================================
# ประวัติการแก้ค่าตั้ง — "คีย์นี้ใครเป็นคนแก้"
# ============================================================

def _change_to_dict(row) -> dict:
    return {
        "id": row.id,
        "setting_key": row.setting_key,
        "changed_by_user_id": row.changed_by_user_id,
        "label": SETTING_DEFS.get(row.setting_key, {}).get("label") or row.setting_key,
        "action": row.action,
        "old_value": row.old_value,
        "new_value": row.new_value,
        "changed_by": row.changed_by,
        "source": row.source,
        "changed_at": row.changed_at,
    }


async def setting_history(key: str | None = None, limit: int = 100) -> list[dict]:
    """ประวัติล่าสุดก่อน — ไม่ระบุคีย์ = รวมทุกคีย์ (ค่า secret ถูก mask ตั้งแต่ตอนบันทึกแล้ว)"""
    async with AsyncSessionLocal() as db:
        rows = await get_app_setting_changes(db, key, limit)

    return [_change_to_dict(r) for r in rows]


async def latest_setting_change_by_key() -> dict[str, dict]:
    async with AsyncSessionLocal() as db:
        rows = await get_latest_app_setting_changes(db)

    return {r.setting_key: _change_to_dict(r) for r in rows}


async def log_external_setting_change(
    setting_key: str,
    action: str,
    actor: str,
    source: str = "settings",
    old_value: str | None = None,
    new_value: str | None = None,
    actor_id: int | None = None,
) -> None:
    """
    บันทึกประวัติของสิ่งที่ "ไม่ได้เก็บใน app_settings" แต่เป็นการเปลี่ยนค่าตั้งของระบบจริง ๆ
    (ตอนนี้คือรหัส Redis ของ user admin ที่ไปแก้ users.acl + .env โดยตรง — ดู redis_admin_password.py)
    ห้ามส่งค่าจริงเข้ามา: เก็บแค่ว่าใครสั่งเมื่อไหร่ก็พอสำหรับการตรวจย้อน
    """
    async with AsyncSessionLocal() as db:
        await log_app_setting_change(
            db, setting_key, action, actor,
            old_value=old_value, new_value=new_value, source=source,
            changed_by_user_id=actor_id,
        )
