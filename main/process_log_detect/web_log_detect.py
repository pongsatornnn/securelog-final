# Detector: Web attack จาก normalized web access log — 2 แบบใน worker เดียว

import re
import time
import asyncio
from collections import defaultdict, deque
from urllib.parse import quote_plus, unquote_plus

from rule_cache import get_rule
from signature_cache import get_signatures
from process_log_detect.detector_common import (
    parse_agent_time_to_epoch,
    prune_old_events,
    get_events_in_window,
    save_alert_to_db,
    seed_rules,
    run_detector_loop,
)


NORMALIZED_WEB_QUEUE = "normalized_web_logs_queue"

LOG_PREFIX = "WEB-DETECT"

# detection_type -> rule_key ใน detection_rules
RULE_KEY_BY_TYPE = {
    "sql_injection": "web_sql_injection",
    "xss": "web_xss",
    "path_traversal": "web_path_traversal",
    "command_injection": "web_command_injection",
    "http_flood": "web_http_flood",
}

# เก็บ history สูงสุดต่อ key เพื่อไม่ให้ memory โตไม่จำกัด
MAX_EVENTS_PER_KEY = 1000

# detector เก็บ regex ที่ compile แล้วใน memory และ reload จาก DB/cache ตาม interval นี้
SIGNATURE_REFRESH_SECONDS = 30

# ลำดับ = ความสำคัญ (รุนแรงกว่าอยู่ก่อน) เวลา request เดียว match หลายชนิด
ATTACK_PRIORITY = [
    "sql_injection",
    "command_injection",
    "path_traversal",
    "xss",
]

ATTACK_LABEL = {
    "sql_injection": "SQL Injection",
    "xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal",
    "command_injection": "Command Injection",
    "http_flood": "HTTP Flood (App-level DoS)",
}


# ============================================================

# detection_type -> compiled regex (รวมทุก pattern ที่ active) หรือ None ถ้าไม่มี pattern
_compiled_signatures: dict[str, re.Pattern | None] = {}
_last_signature_reload: float = 0.0


def compile_patterns(patterns: list[str]) -> re.Pattern | None:
    # compile pattern ทั้งหมดของชนิดหนึ่งรวมเป็น regex เดียว (IGNORECASE)
    valid: list[str] = []

    for pattern in patterns:
        try:
            re.compile(pattern)
            valid.append(pattern)
        except re.error as e:
            print(f"[{LOG_PREFIX}] ข้าม pattern ที่ไม่ถูกต้อง: {pattern!r} | {e}")

    if not valid:
        return None

    return re.compile("|".join(f"(?:{p})" for p in valid), re.IGNORECASE)


def reload_signatures(loop: asyncio.AbstractEventLoop, force: bool = False) -> None:
    # โหลด pattern จาก DB/cache มา compile เก็บใน memory
    global _last_signature_reload

    now_ts = time.time()

    if not force and (now_ts - _last_signature_reload) < SIGNATURE_REFRESH_SECONDS:
        return

    for detection_type in ATTACK_PRIORITY:
        try:
            patterns = loop.run_until_complete(get_signatures(detection_type))
            _compiled_signatures[detection_type] = compile_patterns(patterns)
        except Exception as e:
            print(f"[{LOG_PREFIX}] โหลด signature ของ {detection_type} ไม่สำเร็จ: {e}")

    _last_signature_reload = now_ts


# ============================================================
events_by_key: dict[str, deque] = defaultdict(deque)


def clear_web_count(key: str) -> None:
    events_by_key[key].clear()
    print(f"[{LOG_PREFIX}] cleared web attack count for [{key}]")


# ============================================================

def decode_url(value: str) -> list[str]:
    # decode URL-encoding สองชั้น เพื่อดัก payload ที่ encode มา (เช่น %2e%2e%2f, %253c)
    try:
        once = unquote_plus(value)
        twice = unquote_plus(once)
        return [once, twice]
    except Exception:
        return []


# request line ใน raw log — ใช้แทน path เมื่อ normalize แยก path ไม่ได้ (เช่น payload มีช่องว่างดิบ)
RAW_REQUEST_RE = re.compile(r'"[A-Z]+ (.*?)(?: HTTP/[\d.]+)?"')
PHPMYADMIN_SQL_ROUTE_RE = re.compile(
    r"/(?:table|database|sql|server)(?:/[A-Za-z0-9_-]+)*", re.IGNORECASE,
)


def mask_phpmyadmin_parameters(path: str, *, for_command: bool = False) -> str:
    endpoint, separator, query = path.partition("?")
    if not separator or endpoint.lower() != "/phpmyadmin/index.php":
        return path

    fields = []
    for index, segment in enumerate(query.split("&")):
        key, equals, value = segment.partition("=")
        if equals:
            fields.append((unquote_plus(key), unquote_plus(value), index, key, value))

    def single_value(name: str) -> str | None:
        values = [value for key, value, *_ in fields if key == name]
        return values[0] if len(values) == 1 else None

    route = single_value("route")
    token = single_value("token")
    if not route or not PHPMYADMIN_SQL_ROUTE_RE.fullmatch(route):
        return path
    # Some phpMyAdmin links (notably column sorting) include a SQL signature but
    # omit the CSRF token from the URL. If a token is present, it must be valid.
    if token is not None and not re.fullmatch(r"[0-9a-f]{32,64}", token, re.IGNORECASE):
        return path

    segments = query.split("&")
    # phpMyAdmin's row Edit/Copy link has no SQL signature. Accept only its
    # narrow, generated primary-key lookup shape; arbitrary clauses still scan.
    table = single_value("table")
    where_clause = single_value("where_clause")
    row_link = (
        route == "/table/change"
        and table is not None
        and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", table) is not None
        and single_value("clause_is_unique") == "1"
        and single_value("default_action") in ("update", "insert")
        and where_clause is not None
        and re.fullmatch(
            rf"`{re.escape(table)}`\.`[A-Za-z_][A-Za-z0-9_$]*`\s*=\s*[0-9]+",
            where_clause,
        ) is not None
    )
    if row_link:
        for name in ("where_clause", "sql_query"):
            value = single_value(name)
            if value is None:
                continue
            if name == "sql_query":
                # Row links retain the current Browse sort, also without a
                # signature. Match only this generated SELECT for the table.
                simple_browse = rf"SELECT\s+\*\s+FROM\s+`{re.escape(table)}`"
                sorted_browse = (
                    rf"{simple_browse}\s+ORDER\s+BY\s+"
                    rf"`{re.escape(table)}`\.`[A-Za-z_][A-Za-z0-9_$]*`\s+(?:ASC|DESC)"
                )
                if not (
                    re.fullmatch(simple_browse, value, re.IGNORECASE)
                    or re.fullmatch(sorted_browse, value, re.IGNORECASE)
                ):
                    continue
            field = next(field for field in fields if field[0] == name)
            _, _, index, raw_key, _ = field
            segments[index] = f"{raw_key}="
    # Navigation identifiers are not SQL expressions. Keep unusual values
    # visible to the signatures.
    if not for_command:
        for name in ("db", "checkprivsdb"):
            value = single_value(name)
            if value and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_$]*", value):
                field = next(field for field in fields if field[0] == name)
                _, _, index, raw_key, _ = field
                segments[index] = f"{raw_key}="
        sort_by = single_value("sort_by")
        if route == "/server/databases" and sort_by and re.fullmatch(r"[A-Z][A-Z0-9_]*", sort_by):
            field = next(field for field in fields if field[0] == "sort_by")
            _, _, index, raw_key, _ = field
            segments[index] = f"{raw_key}="
    else:
        # phpMyAdmin's own navigation link contains "&goto", which overlaps
        # a generic shell signature. Only suppress a simple internal route.
        goto = single_value("goto")
        if goto and re.fullmatch(
            r"index\.php\?route=/(?:table|database|sql|server)(?:/[A-Za-z0-9_-]+)*"
            r"(?:&(?:db|table)=[A-Za-z_][A-Za-z0-9_$]*)*",
            goto, re.IGNORECASE,
        ):
            field = next(field for field in fields if field[0] == "goto")
            _, _, index, _, _ = field
            segments[index] = ""

    # SQL written by phpMyAdmin is expected input. Other parameters remain
    # searchable, and only fields with the matching signature shape are changed.
    for name, signature_name in (
        ("sql_query", "sql_signature"),
        ("where_clause", "where_clause_signature"),
    ):
        value = single_value(name)
        signature = single_value(signature_name)
        if not value or not signature or not re.fullmatch(r"[0-9a-f]{64}", signature, re.IGNORECASE):
            continue
        if name == "where_clause" and not single_value("table"):
            continue
        field = next(field for field in fields if field[0] == name)
        _, _, index, raw_key, _ = field
        if for_command:
            # SQL identifier quotes look like shell command substitution to the
            # generic backtick signature. Preserve the rest of the SQL value so
            # other command signatures still inspect it.
            decoded = unquote_plus(value)
            decoded = re.sub(r"`([A-Za-z_][A-Za-z0-9_$]*)`", r"\1", decoded)
            segments[index] = f"{raw_key}={quote_plus(decoded)}"
        else:
            segments[index] = f"{raw_key}="
    sanitized_query = "&".join(segment for segment in segments if segment)
    return f"{endpoint}?{sanitized_query}" if sanitized_query else endpoint


def build_haystack(
    log: dict, mask_phpmyadmin_sql: bool = False,
    mask_phpmyadmin_command: bool = False,
    split_query_parameters: bool = False,
) -> list[str]:
    # จุดที่ payload ซ่อนได้: path ดิบ + path decode + user_agent
    # ไม่ตรวจ raw log ทั้งบรรทัด — Referer คือ URL ของหน้าก่อนหน้า ทำให้ไฟล์ css/รูปที่โหลดตาม
    # หน้านั้นโดนนับซ้ำ และวันที่/ขนาด/สถานะในบรรทัดก็ไปชน signature ได้
    # คืนเป็นรายการแยกช่อง ตรวจทีละช่อง — ถ้าต่อกันเป็นสตริงเดียว regex ที่มี \s จะจับข้ามช่องได้
    path = str(log.get("path") or "")
    user_agent = str(log.get("user_agent") or "")

    if not path:
        found = RAW_REQUEST_RE.search(str(log.get("raw_message") or ""))
        path = found.group(1) if found else ""

    if mask_phpmyadmin_sql:
        path = mask_phpmyadmin_parameters(path)
    elif mask_phpmyadmin_command:
        path = mask_phpmyadmin_parameters(path, for_command=True)
    if split_query_parameters and "?" in path:
        # XSS signatures must not match across unrelated query parameters.
        # Split before decoding so an encoded '&' within one value stays visible.
        endpoint, query = path.split("?", 1)
        path_parts = [endpoint, *query.split("&")]
    else:
        path_parts = [path]
    parts = [
        *(part for value in path_parts for part in (value, *decode_url(value))),
        user_agent, *decode_url(user_agent),
    ]

    return list(dict.fromkeys(p for p in parts if p))


def detect_attack_types(
    haystack: list[str], sql_haystack: list[str] | None = None,
    command_haystack: list[str] | None = None,
    xss_haystack: list[str] | None = None,
) -> list[tuple[str, str]]:
    # คืน list ของ (detection_type, signature ที่ match) เรียงตามความสำคัญ
    matches: list[tuple[str, str]] = []

    for detection_type in ATTACK_PRIORITY:
        pattern = _compiled_signatures.get(detection_type)
        if pattern is None:
            continue

        parts = haystack
        if detection_type == "sql_injection" and sql_haystack is not None:
            parts = sql_haystack
        elif detection_type == "command_injection" and command_haystack is not None:
            parts = command_haystack
        elif detection_type == "xss" and xss_haystack is not None:
            parts = xss_haystack
        for part in parts:
            found = pattern.search(part)
            if found:
                matches.append((detection_type, found.group(0)))
                break

    return matches


# ============================================================

def print_counted_web_log(
    detection_type: str,
    source_ip: str,
    count: int,
    signature: str,
    log: dict,
) -> None:
    print(
        f"WEB [{ATTACK_LABEL.get(detection_type, detection_type)}] "
        f"ip [{source_ip}] count {count} | "
        f"agent={log.get('agent_id')} | "
        f"time={log.get('agent_event_time_thai')} | "
        f"method={log.get('method')} | "
        f"status={log.get('status_code')} | "
        f"sig={signature!r} | "
        f"path={log.get('path')}"
    )


def print_web_alert(
    detection_type: str,
    source_ip: str,
    count: int,
    window_seconds: int,
    threshold: int,
    related_logs: list[dict],
) -> None:
    print("\n" + "=" * 90)
    print(f"[{LOG_PREFIX}] {ATTACK_LABEL.get(detection_type, detection_type).upper()} DETECTED")
    print("-" * 90)
    print(f"source_ip  : {source_ip}")
    print(f"count      : {count}")
    print(f"window     : {window_seconds} seconds")
    print(f"threshold  : {threshold}")
    print("-" * 90)
    print("related requests used for count:")

    for index, event in enumerate(related_logs, start=1):
        print(
            f"[{index}] time={event.get('agent_event_time_thai')} | "
            f"agent={event.get('agent_id')} | "
            f"method={event.get('method')} | "
            f"status={event.get('status_code')} | "
            f"sig={event.get('matched_signature')!r}"
        )
        print(f"    raw_message: {event.get('raw_message')}")

    print("=" * 90 + "\n")


# ============================================================

def process_http_flood(
    log: dict,
    source_ip: str | None,
    now_ts: float,
    loop: asyncio.AbstractEventLoop,
) -> None:
    # App-level DoS: นับจำนวน request "ทั้งหมด" ต่อ source_ip ใน sliding window
    if not source_ip:
        return

    rule = loop.run_until_complete(get_rule(RULE_KEY_BY_TYPE["http_flood"], log.get("agent_id")))
    key = f"http_flood:{log.get('agent_id') or 'unknown_agent'}:{source_ip}"

    if not rule["is_active"]:
        clear_web_count(key)
        return

    window_seconds = rule["window_seconds"]
    threshold = rule["threshold"]

    event = {
        "ts": now_ts,
        "agent_event_time_thai": log.get("agent_event_time_thai"),
        "agent_event_time_utc": log.get("agent_event_time_utc"),
        "central_normalized_at": log.get("central_normalized_at"),
        "agent_id": log.get("agent_id"),
        "source_ip": source_ip,
        "method": log.get("method"),
        "path": log.get("path"),
        "status_code": log.get("status_code"),
        "user_agent": log.get("user_agent"),
        "raw_message": log.get("raw_message"),
    }

    events_by_key[key].append(event)
    prune_old_events(events_by_key[key], now_ts, window_seconds, MAX_EVENTS_PER_KEY)

    window_events = get_events_in_window(events_by_key[key], now_ts, window_seconds)
    count = len(window_events)

    if count >= threshold:
        print_web_alert(
            detection_type="http_flood",
            source_ip=source_ip,
            count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        )
        loop.run_until_complete(save_alert_to_db(
            detection_type="http_flood",
            category="web",
            log_prefix=LOG_PREFIX,
            agent_id=log.get("agent_id"),
            source_ip=source_ip,
            event_count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        ))
        clear_web_count(key)


# ============================================================

def process_web_log(log: dict, loop: asyncio.AbstractEventLoop) -> None:
    if log.get("category") != "web":
        return

    # refresh pattern จาก DB เป็นระยะ (โหลดจริงเฉพาะเมื่อครบ interval)
    reload_signatures(loop)

    source_ip = log.get("source_ip")
    now_ts = parse_agent_time_to_epoch(log)

    # App-level DoS: นับทุก request ต่อ IP — ต้องรันก่อน signature return
    process_http_flood(log, source_ip, now_ts, loop)

    haystack = build_haystack(log)
    matches = detect_attack_types(
        haystack,
        build_haystack(log, mask_phpmyadmin_sql=True),
        build_haystack(log, mask_phpmyadmin_command=True),
        build_haystack(log, split_query_parameters=True),
    )

    if not matches:
        return

    # ถ้า rule แรกถูกปิดเฉพาะ Agent นี้ ให้ตรวจชนิดถัดไปที่ match ด้วย
    selected = None
    active_types = []
    for matched_type, matched_signature in matches:
        matched_rule = loop.run_until_complete(
            get_rule(RULE_KEY_BY_TYPE[matched_type], log.get("agent_id"))
        )
        matched_key = f"{matched_type}:{log.get('agent_id') or 'unknown_agent'}:{source_ip or 'unknown'}"
        if not matched_rule["is_active"]:
            clear_web_count(matched_key)
            continue
        active_types.append(matched_type)
        if selected is None:
            selected = (matched_type, matched_signature, matched_rule)

    if selected is None:
        return

    detection_type, signature, rule = selected
    all_types = active_types

    window_seconds = rule["window_seconds"]
    threshold = rule["threshold"]

    # web signature นับตาม IP เป็นหลัก
    key = f"{detection_type}:{log.get('agent_id') or 'unknown_agent'}:{source_ip or 'unknown'}"

    event = {
        "ts": now_ts,
        "agent_event_time_thai": log.get("agent_event_time_thai"),
        "agent_event_time_utc": log.get("agent_event_time_utc"),
        "central_normalized_at": log.get("central_normalized_at"),
        "agent_id": log.get("agent_id"),
        "source_ip": source_ip,
        "method": log.get("method"),
        "path": log.get("path"),
        "status_code": log.get("status_code"),
        "user_agent": log.get("user_agent"),
        "matched_signature": signature,
        "matched_types": all_types,
        "raw_message": log.get("raw_message"),
    }

    events_by_key[key].append(event)
    prune_old_events(events_by_key[key], now_ts, window_seconds, MAX_EVENTS_PER_KEY)

    window_events = get_events_in_window(events_by_key[key], now_ts, window_seconds)
    count = len(window_events)

    print_counted_web_log(detection_type, source_ip or "unknown", count, signature, log)

    if count >= threshold:
        print_web_alert(
            detection_type=detection_type,
            source_ip=source_ip or "unknown",
            count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        )
        loop.run_until_complete(save_alert_to_db(
            detection_type=detection_type,
            category="web",
            log_prefix=LOG_PREFIX,
            agent_id=log.get("agent_id"),
            source_ip=source_ip,
            event_count=count,
            window_seconds=window_seconds,
            threshold=threshold,
            related_logs=window_events,
        ))
        clear_web_count(key)


# ============================================================

def prepare_web_detector(loop: asyncio.AbstractEventLoop) -> None:
    # seed rule ลง DB + โหลด signature ครั้งแรกให้พร้อมก่อนรับ log
    seed_rules(loop, RULE_KEY_BY_TYPE.values(), LOG_PREFIX)
    reload_signatures(loop, force=True)
    total = sum(1 for p in _compiled_signatures.values() if p is not None)
    print(f"[{LOG_PREFIX}] โหลด signature พร้อมใช้งาน {total}/{len(ATTACK_PRIORITY)} ชนิด")


def start_web_detector() -> None:
    run_detector_loop(
        queue_name=NORMALIZED_WEB_QUEUE,
        process_log=process_web_log,
        log_prefix=LOG_PREFIX,
        startup_messages=(
            "mode: SIGNATURE + RATE DETECT + SAVE ALERT TO DB + AUTO BLOCK/BLACKLIST",
            "detects: SQL Injection / XSS / Path Traversal / Command Injection / HTTP Flood (App-DoS)",
        ),
        on_start=prepare_web_detector,
    )


if __name__ == "__main__":
    start_web_detector()
