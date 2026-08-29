# Cache + DB layer สำหรับค่าตั้งของระบบที่แก้ได้ตอนรัน (หน้า System Settings)

import os

from dotenv import load_dotenv

from database.connection import AsyncSessionLocal
from database.crud import (
    get_app_setting,
    get_all_app_settings,
    upsert_app_setting,
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
LOADED_FLAG_KEY = f"{CACHE_KEY_PREFIX}_loaded"

LOG_PREFIX = "SETTINGS-CACHE"


# โมเดลที่ระบบรองรับ — รายการนี้ทำสองหน้าที่ (แหล่งเดียว ไม่ต้องไล่แก้สองที่):
GEMINI_MODEL_CHOICES = [
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash",
]

# คีย์ที่ออกใหม่ (ขึ้นต้น AQ.) ใช้ gemini-2.5-* ไม่ได้แล้ว — Google ตอบ 404 ว่า
DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"

# ── รายการคีย์ที่ระบบรู้จัก ────────────────────────────────────────────────
SETTING_DEFS: dict[str, dict] = {
    # ── LINE ──
    "line_channel_access_token": {
        "group": "line",
        "label": "Channel Access Token",
        "hint": "โทเคนของ Messaging API ที่ใช้ส่งข้อความ",
        "secret": True,
        "env": "LINE_CHANNEL_ACCESS_TOKEN",
        "default": "",
    },
    "line_channel_secret": {
        "group": "line",
        "label": "Channel Secret",
        "hint": "คีย์สำหรับตรวจลายเซ็น webhook ของ LINE",
        "secret": True,
        "env": "LINE_CHANNEL_SECRET",
        "default": "",
    },
    "line_oa_id": {
        "group": "line",
        "label": "LINE OA ID",
        "hint": "Basic ID ของ LINE OA เช่น @123abcd",
        "secret": False,
        "env": "LINE_OA_ID",
        "default": "",
    },
    # ── Gemini ──
    "gemini_api_key": {
        "group": "gemini",
        "label": "API Key",
        "hint": "API key จาก Google AI Studio",
        "secret": True,
        "env": "GEMINI_API_KEY",
        "default": "",
    },
    "gemini_model": {
        "group": "gemini",
        "label": "Model",
        "hint": "โมเดลที่ใช้สรุปเหตุการณ์",
        "secret": False,
        "env": "GEMINI_MODEL",
        "default": DEFAULT_GEMINI_MODEL,
        # เลือกจากรายชื่อแทนการพิมพ์เอง — ชื่อโมเดลของ Google เปลี่ยนบ่อยและพิมพ์ผิดนิดเดียว
        "choices": GEMINI_MODEL_CHOICES,
        # ค่านี้ถูกต่อท้าย URL ตรง ๆ (models/<ชื่อ>:generateContent) — จำกัดอักขระไว้
        "pattern": r"[A-Za-z0-9][A-Za-z0-9._-]*",
        "pattern_error": "ต้องเป็นชื่อโมเดล เช่น gemini-3.5-flash (ใช้ได้เฉพาะ A-Z a-z 0-9 . _ -)",
    },
    "gemini_timeout_sec": {
        "group": "gemini",
        "label": "Timeout (วินาที)",
        "hint": "รอ Gemini ตอบนานสุดกี่วินาทีก่อนยอมแพ้",
        "secret": False,
        "env": "GEMINI_TIMEOUT_SEC",
        # 120 ไม่ใช่ 60: วัดจริงด้วย prompt สรุป alert ของระบบ (40 บรรทัด log) รุ่น flash ตัวใหญ่
        "default": "120",
        # อยู่หน้านี้เพราะต้องขยับตามโมเดลที่เลือก — โมเดลแต่ละตัวช้าไม่เท่ากันเป็นสิบเท่า
        "pattern": r"[1-9][0-9]?|[1-5][0-9]{2}|600",
        "pattern_error": "ต้องเป็นตัวเลข 1-600 วินาที",
    },
    # ── ค่าที่ฝังลงชุดติดตั้ง Agent (site.conf ใน zip) ──
    "agent_redis_username": {
        "group": "agent",
        "label": "Redis Username ของ Client Server",
        "hint": "ชื่อผู้ใช้ Redis ที่ Client Server ใช้ต่อเข้ามา",
        "secret": False,
        "env": "AGENT_REDIS_USERNAME",
        "default": "agent_node",
        # ล็อกไม่ให้แก้จากหน้าเว็บ — ต่างจากรหัสผ่านที่ระบบเขียน users.acl + ACL LOAD ให้เอง
        "readonly": True,
    },
    "agent_redis_password": {
        "group": "agent",
        "label": "Redis Password ของ Client Server",
        "hint": "รหัสผ่าน Redis ของ Client Server",
        "secret": True,
        "env": "AGENT_REDIS_PASSWORD",
        "default": "",
        # ต้องยืนยันรหัสเดิมก่อนเปลี่ยน (เฉพาะตอนที่มีค่าตั้งไว้แล้ว) — ค่านี้ถูกฝังลงชุดติดตั้ง
        "confirm_current": True,
        # ตรวจด้วยเงื่อนไขเดียวกับรหัสของ central (redis_password_rules) เพราะลงเอยที่
        "password_rules": True,
        # แก้ผ่าน popup แยก ไม่ใช่ช่องกรอกในแถวเหมือนคีย์อื่น — ต้องกรอกรหัสเดิม/ใหม่/ยืนยัน
        "change_via_modal": True,
        # ระบบเขียน users.acl ทั้งสองบรรทัดแล้วสั่ง ACL LOAD ให้เอง (redis_admin_password.
        "apply_to_redis_acl": True,
        # คำเตือนบรรทัดเดียวใน popup — โชว์ **ก่อน** กรอก ไม่ใช่หลังกดสำเร็จ เพราะชุดติดตั้งใหม่
        "change_warning": (
            "กดแล้ว agent เดิมส่ง log ไม่เข้า จนกว่าจะเอาชุดติดตั้งใหม่ไปลงครบทุกเครื่อง "
            "· users.acl กับ ACL LOAD ระบบทำให้เอง"
        ),
    },
    # ── นโยบายยกระดับเมื่อ IP เดิมโดน block ซ้ำ (escalation) ──
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
def setting_page(key: str) -> str:
    return SETTING_DEFS[key].get("page", "settings")


def keys_for_page(page: str) -> list[str]:
    return [k for k in SETTING_DEFS if setting_page(k) == page]


# ค่ากลุ่ม agent เดิมอยู่ในไฟล์นี้บนเครื่อง central (คนตั้งเองตอน setup) — ไม่ได้อยู่ใน .env
SITE_CONF_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "for_Agent", "package", "site.conf",
)

# ชื่อตัวแปรใน site.conf -> setting key ของเรา
SITE_CONF_KEY_MAP = {
    "REDIS_USERNAME": "agent_redis_username",
    "REDIS_PASSWORD": "agent_redis_password",
}


def setting_cache_key(key: str) -> str:
    return f"{CACHE_KEY_PREFIX}{key}"


def _parse_site_conf(path: str) -> dict[str, str]:
    # อ่าน site.conf (รูปแบบ KEY="value" แบบ shell) — คืน dict ว่างถ้าไม่มีไฟล์/อ่านไม่ได้
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
    # ยกค่าจาก for_Agent/package/site.conf มาเป็นค่าตั้งต้นของกลุ่ม agent — **เฉพาะคีย์ที่ยังไม่มีแถว**
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
    # ค่าที่จะใช้เมื่อยังไม่เคยตั้งผ่านหน้าเว็บ — จาก .env ก่อน แล้วค่อยค่า default ในโค้ด
    spec = SETTING_DEFS[key]
    return os.getenv(spec["env"], "") or spec["default"]


def get_setting(key: str) -> str:
    # อ่านค่าแบบ sync — **cache เท่านั้น** miss แล้วตกไป .env/default (ดูหมายเหตุหัวไฟล์)
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
    # แปลงค่า secret ที่ยังเก็บเป็น plaintext ใน DB ให้เป็น ciphertext — เรียกตอน start ทุกครั้ง
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
    # อ่าน app_settings ทั้งตารางแล้วเติม cache ให้ครบ **ทุกคีย์ที่ระบบรู้จัก**
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
    # เรียกที่ทางเข้าฝั่ง async ก่อนที่โค้ด sync จะไปอ่านค่า — เติม cache จาก DB ถ้ายังไม่ได้เติม
    if cache_get_json(LOADED_FLAG_KEY, log_prefix=LOG_PREFIX) is not None:
        return
    await load_all_into_cache()


async def get_setting_async(key: str) -> str:
    # อ่านค่าแบบเต็มลำดับ cache -> DB -> .env (ใช้ในโค้ด async ที่อยากได้ค่าแม่นสุด)
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
    # อ่านค่าตั้งที่เป็นจำนวนเต็ม — ใช้กับค่าที่อยู่ในเส้นทางตัดสินใจ (เช่น escalation)
    raw = await get_setting_async(key)

    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = int(SETTING_DEFS[key]["default"])

    return max(minimum, value)


def _for_audit(key: str, stored: str | None) -> str | None:
    # แปลงค่าที่เก็บใน DB ให้อยู่ในรูปที่ "บันทึกลงประวัติได้" —
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
    # ตั้งค่าทับจากหน้าเว็บ — เขียน DB แล้วอัปเดต cache ทันที (ไม่ต้องรอ TTL)
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


def mask_secret(value: str) -> str:
    # ค่าที่เป็น secret ห้ามส่งกลับหน้าเว็บเต็ม ๆ — โชว์แค่ 4 ตัวท้ายพอให้แอดมินเทียบได้ว่าใช่ตัวที่ตั้งไว้
    if not value:
        return ""
    if len(value) < 8:
        return "•" * len(value)
    return "•" * 8 + value[-4:]


async def all_settings_for_admin() -> list[dict]:
    # รายการค่าทั้งหมดสำหรับหน้า System Settings — ค่า secret ถูก mask แล้ว
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
            # ค่าที่ยังไม่ได้ตั้งทับ มาจากได้ 2 ทาง: ตัวแปรใน .env จริง ๆ หรือค่าตั้งต้นในโค้ด
            "from_env": bool(os.getenv(spec["env"], "").strip()),
            # ยังไม่เคยตั้งค่า = ไม่มีรหัสเดิมให้ยืนยัน (ตั้งครั้งแรกผ่านได้เลย)
            "confirm_current": bool(spec.get("confirm_current")) and bool(value),
            "password_rules": bool(spec.get("password_rules")),
            # มีตัวเลือก = หน้าเว็บแสดงเป็น dropdown แทนช่องพิมพ์
            "choices": list(spec.get("choices") or []),
            "modal_change": bool(spec.get("change_via_modal")),
            "change_warning": spec.get("change_warning") or "",
            # แก้ไม่ได้จากหน้าเว็บ — หน้าเว็บแสดงเป็นค่าอ่านอย่างเดียว และ backend ปฏิเสธถ้าส่งมาแก้
            "readonly": bool(spec.get("readonly")),
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
    # ประวัติล่าสุดก่อน — ไม่ระบุคีย์ = รวมทุกคีย์ (ค่า secret ถูก mask ตั้งแต่ตอนบันทึกแล้ว)
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
    # บันทึกประวัติของสิ่งที่ "ไม่ได้เก็บใน app_settings" แต่เป็นการเปลี่ยนค่าตั้งของระบบจริง ๆ
    async with AsyncSessionLocal() as db:
        await log_app_setting_change(
            db, setting_key, action, actor,
            old_value=old_value, new_value=new_value, source=source,
            changed_by_user_id=actor_id,
        )
