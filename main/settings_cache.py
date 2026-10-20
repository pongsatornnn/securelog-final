

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


LOADED_FLAG_KEY = f"{CACHE_KEY_PREFIX}_loaded"

LOG_PREFIX = "SETTINGS-CACHE"


GEMINI_MODEL_CHOICES = [
    "gemini-3.5-flash-lite",
    "gemini-3.1-flash-lite",
    "gemini-2.5-flash",
]


DEFAULT_GEMINI_MODEL = "gemini-3.5-flash-lite"


SETTING_DEFS: dict[str, dict] = {

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

        "choices": GEMINI_MODEL_CHOICES,

        "pattern": r"[A-Za-z0-9][A-Za-z0-9._-]*",
        "pattern_error": "ต้องเป็นชื่อโมเดล เช่น gemini-3.5-flash (ใช้ได้เฉพาะ A-Z a-z 0-9 . _ -)",
    },
    "gemini_timeout_sec": {
        "group": "gemini",
        "label": "Timeout (วินาที)",
        "hint": "รอ Gemini ตอบนานสุดกี่วินาทีก่อนยอมแพ้",
        "secret": False,
        "env": "GEMINI_TIMEOUT_SEC",

        "default": "120",

        "pattern": r"[1-9][0-9]?|[1-5][0-9]{2}|600",
        "pattern_error": "ต้องเป็นตัวเลข 1-600 วินาที",
    },

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
    "escalation": "การยกระดับเมื่อโดนบล็อกซ้ำ",
}


def setting_page(key: str) -> str:
    return SETTING_DEFS[key].get("page", "settings")


def keys_for_page(page: str) -> list[str]:
    return [k for k in SETTING_DEFS if setting_page(k) == page]


def setting_cache_key(key: str) -> str:
    return f"{CACHE_KEY_PREFIX}{key}"


def env_default(key: str) -> str:

    spec = SETTING_DEFS[key]
    return os.getenv(spec["env"], "") or spec["default"]


def get_setting(key: str) -> str:

    if key not in SETTING_DEFS:
        raise KeyError(f"ไม่รู้จัก setting key: {key}")

    cached = cache_get_json(setting_cache_key(key), log_prefix=LOG_PREFIX)
    if cached is not None:

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

    async with AsyncSessionLocal() as db:
        rows = {r.setting_key: r.value for r in await get_all_app_settings(db)}

    values = {}
    for key in SETTING_DEFS:

        if key in rows:
            stored = rows[key] or ""
        else:

            fallback = env_default(key)
            stored = encrypt(fallback) if SETTING_DEFS[key]["secret"] else fallback

        _cache_one(key, stored)
        values[key] = decrypt(stored)

    cache_set_json(LOADED_FLAG_KEY, {"value": "1"}, SETTINGS_CACHE_TTL_SECONDS, log_prefix=LOG_PREFIX)
    return values


async def ensure_loaded() -> None:

    if cache_get_json(LOADED_FLAG_KEY, log_prefix=LOG_PREFIX) is not None:
        return
    await load_all_into_cache()


async def get_setting_async(key: str) -> str:

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

    raw = await get_setting_async(key)

    try:
        value = int(str(raw).strip())
    except (TypeError, ValueError):
        value = int(SETTING_DEFS[key]["default"])

    return max(minimum, value)


def _for_audit(key: str, stored: str | None) -> str | None:

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

    if key not in SETTING_DEFS:
        raise KeyError(f"ไม่รู้จัก setting key: {key}")

    value = (value or "").strip()


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

    if not value:
        return ""
    if len(value) < 8:
        return "•" * len(value)
    return "•" * 8 + value[-4:]


async def all_settings_for_admin() -> list[dict]:

    async with AsyncSessionLocal() as db:
        rows = {r.setting_key: r for r in await get_all_app_settings(db)}

    items = []
    for key, spec in SETTING_DEFS.items():

        if setting_page(key) != "settings":
            continue

        row = rows.get(key)

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

            "from_env": bool(os.getenv(spec["env"], "").strip()),

            "confirm_current": bool(spec.get("confirm_current")) and bool(value),
            "password_rules": bool(spec.get("password_rules")),

            "choices": list(spec.get("choices") or []),
            "modal_change": bool(spec.get("change_via_modal")),
            "change_warning": spec.get("change_warning") or "",

            "readonly": bool(spec.get("readonly")),

            "value": mask_secret(value) if spec["secret"] else value,
            "updated_at": row.updated_at if row else None,
        })


    latest = await latest_setting_change_by_key()
    for item in items:
        last = latest.get(item["key"])
        item["last_changed_by"] = last["changed_by"] if last else None
        item["last_changed_at"] = last["changed_at"] if last else None
        item["last_action"] = last["action"] if last else None

    return items


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

    async with AsyncSessionLocal() as db:
        await log_app_setting_change(
            db, setting_key, action, actor,
            old_value=old_value, new_value=new_value, source=source,
            changed_by_user_id=actor_id,
        )
