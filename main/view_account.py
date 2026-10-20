


import re
import secrets

VIEW_USERNAME = "view"
VIEW_ROLE = "viewer"
VIEW_DISPLAY_NAME = "View mode"


VIEW_ALLOWED = {
    ("GET", "/dashboard"),
    ("GET", "/alerts"),
    ("GET", "/api/alerts"),
    ("GET", "/api/alerts_filter_options"),
    ("GET", "/api/alerts_unread_count"),

    ("GET", "/api/alerts_stats"),


    ("GET", "/api/alerts_read_state"),
    ("GET", "/api/stream/alerts"),

    ("GET", "/api/agents"),
}


_ALERT_DETAIL_RE = re.compile(r"/api/alerts/\d+")


def is_view_role(role: str | None) -> bool:
    return role == VIEW_ROLE


def view_may(method: str, path: str) -> bool:
    method = method.upper()
    path = path.rstrip("/") or "/"

    if (method, path) in VIEW_ALLOWED:
        return True

    return method == "GET" and bool(_ALERT_DETAIL_RE.fullmatch(path))


def unusable_password() -> str:


    return secrets.token_urlsafe(48)
