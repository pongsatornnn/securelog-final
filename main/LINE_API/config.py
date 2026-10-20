

import os

from dotenv import load_dotenv

from settings_cache import get_setting

load_dotenv()


def channel_access_token() -> str:
    return get_setting("line_channel_access_token")


def channel_secret() -> str:
    return get_setting("line_channel_secret")


def oa_id() -> str:

    return get_setting("line_oa_id")


PUSH_URL = "https://api.line.me/v2/bot/message/push"
MULTICAST_URL = "https://api.line.me/v2/bot/message/multicast"
PROFILE_URL = "https://api.line.me/v2/bot/profile"

BOT_INFO_URL = "https://api.line.me/v2/bot/info"


MULTICAST_MAX = 500


NOTIFY_DEDUP_TTL_SEC = int(os.getenv("LINE_NOTIFY_DEDUP_TTL_SEC", "86400"))
NOTIFY_DEDUP_KEY_PREFIX = "line_notified:"


def is_configured() -> bool:

    return bool(channel_access_token() and channel_secret())
