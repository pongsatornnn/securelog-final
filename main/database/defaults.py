

import json
from pathlib import Path


SEED_DATA_PATH = Path(__file__).resolve().parent / "seed_data.json"

LOG_PREFIX = "SEED-DATA"


def _load_snapshot() -> dict:

    if not SEED_DATA_PATH.exists():
        return {}

    try:
        with SEED_DATA_PATH.open(encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as exc:

        print(f"[{LOG_PREFIX}] อ่าน {SEED_DATA_PATH.name} ไม่ได้ ({exc}) — ใช้ค่า default ในโค้ดแทน")
        return {}

    if not isinstance(data, dict):
        print(f"[{LOG_PREFIX}] {SEED_DATA_PATH.name} ไม่ใช่ JSON object — ใช้ค่า default ในโค้ดแทน")
        return {}

    return data


SNAPSHOT = _load_snapshot()


def snapshot_section(section: str) -> dict:

    value = SNAPSHOT.get(section)
    return value if isinstance(value, dict) else {}


def snapshot_rule(rule_key: str) -> dict | None:
    return snapshot_section("detection_rules").get(rule_key)


def snapshot_severity(severity_key: str) -> dict | None:
    return snapshot_section("alert_severity").get(severity_key)


def snapshot_ttl(detection_type: str) -> dict | None:
    return snapshot_section("blacklist_ttl").get(detection_type)


def snapshot_signatures(detection_type: str) -> list[dict] | None:

    value = snapshot_section("detection_signatures").get(detection_type)
    return value if isinstance(value, list) else None


def snapshot_info() -> str:

    if not SNAPSHOT:
        return "ไม่มี snapshot (ใช้ค่า default ในโค้ด)"
    return f"snapshot จาก {SNAPSHOT.get('generated_at', 'ไม่ทราบเวลา')}"
