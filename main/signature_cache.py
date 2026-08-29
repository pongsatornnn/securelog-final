"""เก็บ signature (regex) ของ Signature-based detector ใน DB (ตาราง detection_signatures)"""

import re

from database.connection import AsyncSessionLocal
from database.defaults import snapshot_signatures
from database.crud import (
    get_detection_signatures,
    get_detection_signature_by_id,
    find_detection_signature,
    create_detection_signature,
    update_detection_signature,
    delete_detection_signature,
    delete_default_signatures,
)
from redis_client import cache_get_json, cache_set_json, cache_delete


SIGNATURE_CACHE_TTL_SECONDS = 300

CACHE_KEY_PREFIX = "detection_signatures:"

LOG_PREFIX = "SIG-CACHE"


# ค่า default ของแต่ละ detection_type (ใช้ seed ครั้งแรกที่ยังไม่มีแถวใน DB)
DEFAULT_SIGNATURES = {
    "sql_injection": [
        r"union\s+(all\s+)?select",
        r"select\s.{1,120}?\sfrom\s",
        r"insert\s+into\s",
        r"delete\s+from\s",
        r"update\s.{1,80}?\sset\s",
        r"drop\s+table",
        r"'\s*or\s*'?[^']{0,20}'?\s*=\s*'?[^']{0,20}",
        r"\bor\b\s+\d+\s*=\s*\d+",
        r"\band\b\s+\d+\s*=\s*\d+",
        r"'\s*;\s*--",
        r"'\s*--",
        r"sleep\s*\(\s*\d+",
        r"benchmark\s*\(",
        r"waitfor\s+delay",
        r"pg_sleep\s*\(",
        r"information_schema",
        r"group_concat\s*\(",
        r"load_file\s*\(",
        r"into\s+outfile",
        r"xp_cmdshell",
        r"@@version",
        # error-based ที่ sqlmap ใช้ดึงข้อมูลออกทางข้อความ error
        r"extractvalue\s*\(",
        r"updatexml\s*\(",
        r"floor\s*\(\s*rand\s*\(",
        r"exp\s*\(\s*~",
        # time-based เพิ่มเติม (Oracle / MySQL rlike)
        r"dbms_pipe\.receive_message",
        r"rlike\s+sleep\s*\(",
        # ขั้นสำรวจโครงสร้าง: หาจำนวนคอลัมน์ / เดา schema
        r"\border\s+by\s+\d+",
        r"\bhaving\s+\d+\s*=\s*\d+",
        r"\bnull\s*,\s*null\s*,\s*null",
        r"\bsys(objects|columns)\b",
        # แปลงชนิด/ต่อสตริง — ใช้ยัด payload ให้ผ่าน filter
        r"cast\s*\(.{0,40}?\s+as\s+(char|int|signed|nchar|varchar)\b",
        r"convert\s*\(\s*int\s*,",
        r"char\s*\(\s*\d{1,3}\s*,\s*\d{1,3}",
        r"concat(_ws)?\s*\(\s*(0x|')",
        r"'\s*\|\|\s*'",
        r"/\*!\d{5}",
        # stacked query: ต่อคำสั่งที่สองหลัง ;
        r";\s*(drop|truncate|alter|create)\s+(table|database|user)\b",
        r"sp_executesql",
    ],
    "xss": [
        r"<\s*script",
        r"<\s*/\s*script",
        r"javascript:",
        r"on(error|load|mouseover|click|focus|submit|toggle)\s*=",
        r"<\s*svg",
        r"<\s*iframe",
        r"<\s*img[^>]*\bon\w+\s*=",
        r"<\s*body[^>]*\bon\w+\s*=",
        r"alert\s*\(",
        r"prompt\s*\(",
        r"confirm\s*\(",
        r"document\.cookie",
        r"document\.location",
        r"String\.fromCharCode",
        r"eval\s*\(",
        r"expression\s*\(",
        # tag อื่นที่ยิง payload ได้ นอกจาก script/svg/iframe
        r"<\s*(object|embed|applet|frameset|frame)\b",
        r"<\s*(video|audio|source|details|marquee|template|math)\b",
        r"<\s*(meta|base|link)[^>]{0,80}\b(http-equiv|href)\s*=",
        # event handler + JS sink ใน request เดียว (แคบกว่า handler เดี่ยว ๆ ที่มีอยู่แล้ว)
        r"\bon[a-z]{3,15}\s*=\s*[\"']?\s*(alert|prompt|confirm|eval|fetch|atob|location|document|window|top|parent|this|String|setTimeout|setInterval|new\s+Function)",
        r"\bsrcdoc\s*=",
        r"\bformaction\s*=",
        r"\bxlink:href\s*=",
        # scheme / encoding ที่ใช้เลี่ยง filter
        r"java\s*script\s*:",
        r"vbscript\s*:",
        r"data:\s*text/html",
        r"(&#x?[0-9a-f]{2,6};){3,}",
        # JS sink ที่โผล่ใน payload บ่อย
        r"document\s*\.\s*(write|domain|referrer|createElement)",
        r"document\s*\[\s*[\"']cookie",
        r"window\s*\.\s*(location|open|name|top|parent)\b",
        r"location\s*\.\s*(href|hash|search|replace|assign)\b",
        r"\b(atob|btoa)\s*\(",
        r"\bnew\s+Function\s*\(",
        r"\bfetch\s*\(|XMLHttpRequest",
        r"\bset(Timeout|Interval)\s*\(",
    ],
    "path_traversal": [
        r"\.\./",
        r"\.\.\\",
        r"\.\.%2f",
        r"%2e%2e%2f",
        r"%2e%2e/",
        r"\.\.%5c",
        r"\.\.%c0%af",
        r"%252e%252e",
        r"\.\.\.\./+",
        r"/etc/passwd",
        r"/etc/shadow",
        r"/proc/self/environ",
        r"boot\.ini",
        r"win\.ini",
        # encoding bypass เพิ่มเติม
        r"\.\.%252f",
        r"%2e%2e%5c",
        r"\.%2e/",
        r"%c0%ae%c0%ae",
        r"\.\.%00",
        r"\.\.;/",
        # ไฟล์ระบบที่เป็นเป้าหมายประจำ
        r"/etc/(group|hosts|hostname|issue|motd|crontab|resolv\.conf)\b",
        r"/etc/ssh/ssh_host_\w+_key",
        r"/root/\.(ssh|bash_history)\b",
        r"\bid_rsa\b",
        r"/proc/self/(cmdline|fd|maps|status)\b",
        r"/var/log/(auth\.log|syslog|nginx|apache2)\b",
        r"\\windows\\system32",
        r"WEB-INF/(web\.xml|classes)",
        # ไฟล์ลับที่ scanner ชอบเดา (nikto/dirb ยิงชุดนี้ประจำ)
        r"/\.git/(config|HEAD|index)\b",
        r"/\.(env|htpasswd|htaccess)\b",
        # PHP stream wrapper — LFI/RFI ที่มาคู่กับ traversal
        r"php://(filter|input|memory)",
        r"\b(file|expect|zip|phar|data)://",
    ],
    "command_injection": [
        r";\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|rm|chmod|cp|mv|ping|kill|touch)\b",
        r"\|\s*(cat|ls|id|whoami|uname|nc|bash|sh|wget|curl|grep|awk)\b",
        r"&&\s*(cat|ls|id|whoami|wget|curl|bash|sh|nc|ping)\b",
        r"\|\|\s*(cat|ls|id|whoami|wget|curl)\b",
        r"`[^`]{1,80}`",
        r"\$\([^)]{1,80}\)",
        r"/bin/(ba)?sh\b",
        r"\bnc\s+-e\b",
        r"\b(wget|curl)\s+https?://",
        r"\bchmod\s+[0-7]{3,4}\b",
        r"\bbash\s+-i\b",
        r"%0a\s*(cat|ls|id|whoami|wget|curl)",
        # metachar + คำสั่งเพิ่มเติมที่ของเดิมไม่ครอบ
        r";\s*(ncat|socat|python3?|perl|ruby|php|busybox|env|export|crontab|useradd|passwd|systemctl|service)\b",
        r"\|\s*(ncat|socat|python3?|perl|ruby|php|xargs|tee|base64)\b",
        r"&&\s*(sleep|ping|python3?|perl|php|base64)\b",
        r"\|\|\s*(sleep|ping|nc|python3?|perl|bash|sh)\b",
        # ลายเซ็นของ commix / เครื่องมืออัตโนมัติ
        r"\$\{IFS\}",
        r"\bIFS\s*=",
        r"\bping\s+-[cn]\s+\d+",
        r"\bsleep\s+\d+\s*(;|\||&|$)",
        r">\s*/dev/null\s*2>&1",
        # reverse shell / โหลดมารัน
        r"/dev/tcp/\d{1,3}\.\d{1,3}",
        r"\bmkfifo\b",
        r"\b(wget|curl)\b[^|]{0,60}\|\s*(ba)?sh\b",
        r"\b(sh|bash|zsh)\s+-c\s",
        r"\b(python3?|perl|ruby)\s+-[ce]\s",
        r"\bphp\s+-r\s",
        r"\bbase64\s+-d\b",
        # ฟังก์ชันรันคำสั่งฝั่งแอป (RCE ผ่านพารามิเตอร์)
        r"\b(system|shell_exec|passthru|proc_open|popen)\s*\(",
        r"\b(cat|more|less|head|tail)\s+/etc/(passwd|shadow)\b",
    ],
}

# ชนิดการโจมตี -> กลุ่ม detector (สำหรับ seed แถวใหม่)
CATEGORY_BY_TYPE = {
    "sql_injection": "web",
    "xss": "web",
    "path_traversal": "web",
    "command_injection": "web",
}


def signature_cache_key(detection_type: str) -> str:
    return f"{CACHE_KEY_PREFIX}{detection_type}"


def is_valid_regex(pattern: str) -> bool:
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


# ============================================================

def effective_default_signatures(detection_type: str) -> list[dict]:
    """ชุด default ที่ "ใช้จริง" ของ detection_type นี้ — snapshot (database/seed_data.json)"""
    category = CATEGORY_BY_TYPE.get(detection_type, "web")
    snap = snapshot_signatures(detection_type)

    if snap is not None:
        return [
            {
                "pattern": row.get("pattern"),
                "category": row.get("category") or category,
                "description": row.get("description"),
                "is_active": row.get("is_active", True),
            }
            for row in snap if row.get("pattern")
        ]

    return [
        {"pattern": pattern, "category": category, "description": None, "is_active": True}
        for pattern in DEFAULT_SIGNATURES.get(detection_type, [])
    ]


def default_signature_patterns(detection_type: str) -> list[str]:
    """เฉพาะตัว pattern ของชุด default — ใช้ตอน backfill คอลัมน์ is_default"""
    return [row["pattern"] for row in effective_default_signatures(detection_type)]


async def _seed_defaults(db, detection_type: str) -> int:
    """เขียนชุด default ลง DB (mark is_default=True) — ผู้เรียกต้อง commit เอง"""
    existing = {
        row.pattern
        for row in await get_detection_signatures(db, detection_type=detection_type)
    }

    seeded = 0
    for row in effective_default_signatures(detection_type):
        if row["pattern"] in existing:
            continue

        await create_detection_signature(
            db,
            detection_type=detection_type,
            pattern=row["pattern"],
            category=row["category"],
            description=row["description"],
            is_active=row["is_active"],
            is_default=True,
        )
        seeded += 1

    return seeded


async def load_signatures_from_db(detection_type: str) -> list[str]:
    """อ่าน pattern ที่ active ของ detection_type จาก DB"""
    async with AsyncSessionLocal() as db:
        rows = await get_detection_signatures(db, detection_type=detection_type)

        if not rows:
            seeded = await _seed_defaults(db, detection_type)

            if seeded:
                print(f"[{LOG_PREFIX}] seed default signatures ลง DB: {detection_type} ({seeded} รายการ)")

            rows = await get_detection_signatures(db, detection_type=detection_type)

        patterns = [row.pattern for row in rows if row.is_active]

    cache_set_json(
        signature_cache_key(detection_type),
        patterns,
        SIGNATURE_CACHE_TTL_SECONDS,
        log_prefix=LOG_PREFIX,
    )
    return patterns


async def get_signatures(detection_type: str) -> list[str]:
    """Entry point หลักที่ detector เรียกเพื่อดึง pattern ที่ active ของ detection_type"""
    cached = cache_get_json(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)

    if cached is not None:
        return cached

    return await load_signatures_from_db(detection_type)


# ============================================================

async def add_signature(
    detection_type: str,
    pattern: str,
    *,
    description: str | None = None,
    category: str | None = None,
) -> dict:
    """เพิ่ม signature ใหม่ (validate ว่า regex compile ได้ก่อน)"""
    if not is_valid_regex(pattern):
        raise ValueError(f"regex ไม่ถูกต้อง: {pattern!r}")

    category = category or CATEGORY_BY_TYPE.get(detection_type, "web")

    async with AsyncSessionLocal() as db:
        existing = await find_detection_signature(db, detection_type, pattern)

        if existing:
            result = _to_dict(existing)
            result["duplicated"] = True
        else:
            signature = await create_detection_signature(
                db,
                detection_type=detection_type,
                pattern=pattern,
                category=category,
                description=description,
            )
            result = _to_dict(signature)
            result["duplicated"] = False

    cache_delete(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)
    return result


async def update_signature(
    signature_id: int,
    *,
    pattern: str | None = None,
    description: str | None = None,
) -> dict | None:
    """แก้ pattern / คำอธิบายของ signature ที่มีอยู่ (None = ไม่แตะฟิลด์นั้น, "" = ล้างค่า)"""
    if pattern is not None and not is_valid_regex(pattern):
        raise ValueError(f"regex ไม่ถูกต้อง: {pattern!r}")

    async with AsyncSessionLocal() as db:
        signature = await get_detection_signature_by_id(db, signature_id)

        if not signature:
            return None

        detection_type = signature.detection_type

        # กันแก้ pattern ไปชนของแถวอื่นในชนิดเดียวกัน — เท่ากับมี regex ซ้ำสองแถว
        if pattern is not None and pattern != signature.pattern:
            duplicated = await find_detection_signature(db, detection_type, pattern)

            if duplicated:
                raise ValueError(
                    f"มี pattern นี้อยู่แล้วใน {detection_type} (id={duplicated.id})"
                )

        updated = await update_detection_signature(
            db,
            signature_id,
            pattern=pattern,
            description=description,
        )
        result = _to_dict(updated)

    cache_delete(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)
    return result


async def set_signature_active(signature_id: int, is_active: bool) -> dict | None:
    async with AsyncSessionLocal() as db:
        signature = await update_detection_signature(db, signature_id, is_active=is_active)

        if not signature:
            return None

        result = _to_dict(signature)
        detection_type = signature.detection_type

    cache_delete(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)
    return result


async def remove_signature(signature_id: int) -> dict | None:
    async with AsyncSessionLocal() as db:
        signature = await get_detection_signature_by_id(db, signature_id)

        if not signature:
            return None

        result = _to_dict(signature)
        detection_type = signature.detection_type

        await delete_detection_signature(db, signature_id)

    cache_delete(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)
    return result


async def restore_default_signatures(detection_type: str | None = None) -> dict:
    """คืนค่า signature ของระบบกลับเป็นชุด default"""
    types = [detection_type] if detection_type else list(DEFAULT_SIGNATURES.keys())
    details = []

    for dt in types:
        async with AsyncSessionLocal() as db:
            removed = await delete_default_signatures(db, dt)
            seeded = await _seed_defaults(db, dt)

        cache_delete(signature_cache_key(dt), log_prefix=LOG_PREFIX)

        details.append({
            "detection_type": dt,
            "removed": removed,
            "restored": seeded,
        })
        print(f"[{LOG_PREFIX}] คืนค่า default: {dt} (ลบ {removed} · คืน {seeded})")

    return {
        "types": details,
        "removed": sum(d["removed"] for d in details),
        "restored": sum(d["restored"] for d in details),
    }


async def list_signatures(detection_type: str | None = None) -> list[dict]:
    async with AsyncSessionLocal() as db:
        rows = await get_detection_signatures(db, detection_type=detection_type)
        return [_to_dict(row) for row in rows]


def _to_dict(signature) -> dict:
    return {
        "id": signature.id,
        "detection_type": signature.detection_type,
        "category": signature.category,
        "pattern": signature.pattern,
        "description": signature.description,
        "is_active": bool(signature.is_active),
        # หน้าเว็บใช้ติดป้าย "ของระบบ" และบอกว่าปุ่มคืนค่า default จะแตะแถวไหนบ้าง
        "is_default": bool(signature.is_default),
    }
