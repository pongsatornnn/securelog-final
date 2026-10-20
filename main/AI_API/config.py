

import os

from dotenv import load_dotenv

from settings_cache import GEMINI_MODEL_CHOICES, get_setting

load_dotenv()

def api_key() -> str:
    return get_setting("gemini_api_key")


def model() -> str:

    return get_setting("gemini_model")

API_BASE = "https://generativelanguage.googleapis.com/v1beta/models"


LIST_MODELS_URL = f"{API_BASE}?pageSize=200"


MODEL_ALLOWLIST = tuple(GEMINI_MODEL_CHOICES)


FALLBACK_TIMEOUT_SEC = 120


def timeout_sec() -> int:

    try:
        value = int(get_setting("gemini_timeout_sec"))
    except (TypeError, ValueError):
        return FALLBACK_TIMEOUT_SEC

    return value if value > 0 else FALLBACK_TIMEOUT_SEC


THINKING_BUDGET = int(os.getenv("GEMINI_THINKING_BUDGET", "0"))


THINKING_LEVEL = os.getenv("GEMINI_THINKING_LEVEL", "low")


MAX_OUTPUT_TOKENS = int(os.getenv("GEMINI_MAX_OUTPUT_TOKENS", "4096"))


MAX_LOGS_IN_PROMPT = int(os.getenv("GEMINI_MAX_LOGS", "40"))


MAX_LOG_LINE_CHARS = 500


def is_configured() -> bool:
    return bool(api_key())


def generate_url() -> str:
    return f"{API_BASE}/{model()}:generateContent"
