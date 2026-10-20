

HOUR = 3600


BASE_TTL_SECONDS: dict[str, int | None] = {

    "port_scan": 1 * HOUR,
    "http_flood": 6 * HOUR,
    "firewall_deny_rate": 6 * HOUR,

    "ssh_brute_force": 6 * HOUR,
    "sudo_failed": 3 * HOUR,

    "xss": 12 * HOUR,
    "path_traversal": 12 * HOUR,

    "sql_injection": None,
    "command_injection": None,
}


DEFAULT_TTL_SECONDS = 6 * HOUR


MANUAL_EVENT = "manual_blacklist"


ESCALATION_MULTIPLIER = 2

MAX_BLOCK_COUNT_BEFORE_PERMANENT = 5


MAX_TTL_SECONDS = 10 * 365 * 24 * HOUR


def base_ttl_for(detection_type: str | None) -> int | None:

    if not detection_type or detection_type == MANUAL_EVENT:
        return None

    if detection_type in BASE_TTL_SECONDS:
        return BASE_TTL_SECONDS[detection_type]
    return DEFAULT_TTL_SECONDS


def escalated_ttl_seconds(
    base_ttl: int | None,
    block_count: int,
    multiplier: int = ESCALATION_MULTIPLIER,
    max_block_count: int = MAX_BLOCK_COUNT_BEFORE_PERMANENT,
) -> int | None:

    if base_ttl is None:
        return None
    if block_count > max_block_count:
        return None

    ttl = base_ttl * (multiplier ** (block_count - 1))
    return min(ttl, MAX_TTL_SECONDS)
