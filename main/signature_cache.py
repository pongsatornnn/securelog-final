

import json
import re
from pathlib import Path

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

        r"'\s*--(\s|-|$)",
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

        r"extractvalue\s*\(",
        r"updatexml\s*\(",
        r"floor\s*\(\s*rand\s*\(",
        r"exp\s*\(\s*~",

        r"dbms_pipe\.receive_message",
        r"rlike\s+sleep\s*\(",

        r"\border\s+by\s+\d+",
        r"\bhaving\s+\d+\s*=\s*\d+",
        r"\bnull\s*,\s*null\s*,\s*null",
        r"\bsys(objects|columns)\b",

        r"cast\s*\(.{0,40}?\s+as\s+(char|int|signed|nchar|varchar)\b",
        r"convert\s*\(\s*int\s*,",
        r"char\s*\(\s*\d{1,3}\s*,\s*\d{1,3}",
        r"concat(_ws)?\s*\(\s*(0x|')",
        r"'\s*\|\|\s*'",
        r"/\*!\d{5}",

        r";\s*(drop|truncate|alter|create)\s+(table|database|user)\b",
        r"sp_executesql",

        r"\bunion\b(\s|/\*.{0,20}?\*/|\+|\(){1,10}(all|distinct)?(\s|/\*.{0,20}?\*/|\+|\()*select\b",
        r"/\*.{0,20}?\*/\s*(select|union|and|or|from|where|order)\b",

        r"\bcase\s+when\b.{1,80}?\bthen\b",
        r"'\s*(and|or|xor)\s+'[^']{0,20}'\s*(=|like\b)",
        r"'\s*(and|or)\s+(true|false|not)\b",
        r"\b(and|or)\s+\d+\s*(<>|!=|<|>)\s*\d+",
        r"\bwhere\s+\d+\s*=\s*\d+",

        r"\b(ascii|ord|hex|unhex|mid|substr(ing)?|length)\s*\(\s*\(?\s*select\b",
        r"\bselect\s+(\*|null\b|@@|\d+\s*,|count\s*\(|char\s*\()",
        r"\b(database|current_user|session_user|system_user|schema_name)\s*\(\s*\)",

        r"\bmysql\.(user|db)\b|\bpg_(catalog|shadow|user)\b|\bsqlite_master\b|\ball_tab(les|_columns)\b|\bsysibm\.\w+",

        r"\binto\s+dumpfile\b",
        r"\bpg_read_file\s*\(|\bcopy\s+\w+\s+(from|to)\s+program\b",
        r"\b(exec|execute)\s+(master\.|sp_|xp_)",
        r"\bopen(rowset|datasource|query)\s*\(",
        r"\butl_(http|inaddr|file)\.|\bdbms_(lock|xmlgen|java)\.",
        r"\bwaitfor\s+time\b",
        r"\bprocedure\s+analyse\s*\(",

        r"\[\s*\$(ne|eq|gt|gte|lt|lte|regex|where|in|nin|exists|or|and)\s*\]",
        r"\{\s*[\"']?\$(ne|gt|gte|lt|lte|regex|where|or|and)[\"']?\s*:",

        r"=\s*\\?'\s*(&|$)",

        r"'\s*/\*",
        r"\b(and|or)\s+[\w.]+\s+like\s+['\"][^'\"]{0,40}%",

        r"'[(),.]{0,8}\\?\"|\\?\"[(),.]{0,8}'",
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

        r"<\s*(object|embed|applet|frameset|frame)\b",
        r"<\s*(video|audio|source|details|marquee|template|math)\b",
        r"<\s*(meta|base|link)[^>]{0,80}\b(http-equiv|href)\s*=",

        r"\bon[a-z]{3,15}\s*=\s*[\"']?\s*(alert|prompt|confirm|eval|fetch|atob|location|document|window|top|parent|this|String|setTimeout|setInterval|new\s+Function)",
        r"\bsrcdoc\s*=",
        r"\bformaction\s*=",
        r"\bxlink:href\s*=",

        r"java\s*script\s*:",
        r"vbscript\s*:",
        r"data:\s*text/html",
        r"(&#x?[0-9a-f]{2,6};){3,}",

        r"document\s*\.\s*(write|domain|referrer|createElement)",
        r"document\s*\[\s*[\"']cookie",
        r"window\s*\.\s*(location|open|name|top|parent)\b",
        r"location\s*\.\s*(href|hash|search|replace|assign)\b",
        r"\b(atob|btoa)\s*\(",
        r"\bnew\s+Function\s*\(",
        r"\bfetch\s*\(|XMLHttpRequest",
        r"\bset(Timeout|Interval)\s*\(",

        r"<\s*[a-z][a-z0-9]{0,15}\b[^>]{0,160}?\bon[a-z]{3,25}\s*=",

        r"\bon(blur|change|dblclick|drag\w{0,5}|drop|input|invalid|key(down|up|press)|mouse(down|up|move|out|enter|leave)|pointer\w{2,8}|animation(start|end|iteration)|transition(end|start|run)|begin|unload|beforeunload|resize|scroll|wheel|copy|paste|cut|hashchange|pageshow|popstate|play|playing|canplay|message|search|select|auxclick|contextmenu)\s*=",
        r"<\s*style\b[^>]{0,80}>.{0,120}?(expression\s*\(|@import|behavior\s*:|-moz-binding)",
        r"<\s*(input|form|button|textarea|keygen|isindex)\b[^>]{0,120}\b(autofocus|formaction|action)\b",

        r"\{\{.{0,60}?(constructor|\$on|\$eval|_c\.|alert|prompt|confirm|\$emit)",

        r"\b(inner|outer)HTML\s*=",
        r"\binsertAdjacentHTML\s*\(",
        r"\b(window|self|top|parent|globalThis|frames)\s*\[\s*[\"'`]",
        r"\b(alert|prompt|confirm|eval)\s*`",
        r"\bimport\s*\(\s*[\"'`]",
        r"\bdocument\s*\.\s*(body|forms|getElementById|querySelector|head)\b",
        r"\blocalStorage\s*\.|\bsessionStorage\s*\.",
        r"\bnavigator\s*\.\s*sendBeacon\s*\(",

        r"&lt;\s*/?\s*(script|svg|img|iframe|body)\b",
        r"\\(u003c|x3c)\s*/?\s*(script|svg|img|iframe)",
        r"\+ADw-\s*script",

        r"[?&]([\w\[\].-]{1,40}=)?\s*<\s*/?\s*[a-z][a-z0-9]{0,10}(\s+[\w:-]+\s*=[^<>]{0,120})?\s*/?>",

        r"<[a-z][a-z0-9]{0,10}\s+[\w:-]+\s*=",
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

        r"\.\.%252f",
        r"%2e%2e%5c",
        r"\.%2e/",
        r"%c0%ae%c0%ae",
        r"\.\.%00",
        r"\.\.;/",

        r"/etc/(group|hosts|hostname|issue|motd|crontab|resolv\.conf)\b",
        r"/etc/ssh/ssh_host_\w+_key",
        r"/root/\.(ssh|bash_history)\b",
        r"\bid_rsa\b",
        r"/proc/self/(cmdline|fd|maps|status)\b",
        r"/var/log/(auth\.log|syslog|nginx|apache2)\b",
        r"\\windows\\system32",
        r"WEB-INF/(web\.xml|classes)",

        r"/\.git/(config|HEAD|index)\b",
        r"/\.(env|htpasswd|htaccess)\b",

        r"php://(filter|input|memory)",


        r"[?&](?![\w\[\]\\\"']*(return|redirect|callback|next|continue))[\w\[\]\\\"']*(path|dir|root|inc|include|lib|base|depth|racine|module|config|cfg|template|tpl|DDS)[\w\[\]\\\"']*=+\s*['\"]?(https?|ftps?)://[^&\s'\"]*\.(txt|php\d?|phtml|inc|sh|pl|py|cgi)(\?|&|%00|\s|['\"]|$)",
        r"\b(file|expect|zip|phar|data)://",

        r"%u002e%u002e|%u2215|%u2216",
        r"\.\.%255c|\.\.%c1%(1c|9c)|%c0%(2f|5c|9v)|%e0%80%af",
        r"\.\.(\\|/){1,3}\.\.(\\|/)|(\.\.\\){2}",
        r"\.{2,}\\{2,}|\.\.//+",

        r"=\s*(file:)?/+(etc|proc|root)/",
        r"\bfile:/+(etc|proc|c:|windows)",

        r"/etc/(nginx|apache2|httpd|mysql|php[\d.]*|ssl|sudoers|security)/",
        r"/etc/(sudoers|fstab|environment|profile|bashrc|my\.cnf|redis\.conf)\b",
        r"/proc/(version|cpuinfo|meminfo|mounts|net/(tcp|udp|arp|route)|\d+/(environ|cmdline|cwd|root))\b",
        r"/var/run/secrets/kubernetes|/\.kube/config\b|/\.aws/credentials\b|/\.docker/config\.json\b",
        r"/home/\w+/\.(ssh|bash_history|bashrc|profile)\b",
        r"/(root|home/\w+)/\.ssh/(authorized_keys|known_hosts|id_\w+)",

        r"/\.(svn|hg|bzr)/(entries|wc\.db|store|dirstate)\b|/\.svn/|/\.hg/",
        r"/\.git/(logs|refs|objects|packed-refs|description|COMMIT_EDITMSG)\b",
        r"/\.(DS_Store|npmrc|pgpass|my\.cnf|netrc|bash_history)\b",
        r"\bwp-config\.php(\.bak|\.old|\.save|\.swp|~|\.txt|\.orig)\b",
        r"\bweb\.config(?![\w.-])|\bconfig/database\.yml\b|/settings\.py(?![\w.-])|\blocalsettings\.php\b",
        r"WEB-INF/(lib|jboss-web\.xml|weblogic\.xml|spring)|META-INF/(MANIFEST\.MF|context\.xml)",

        r"\b[c-e]:(\\|/|%5c|%2f)+(windows|winnt|boot|inetpub|users|program\s?files)\b",
        r"\\(system32|syswow64)\\(drivers|config)\\",
        r"\b(system\.ini|repair\\sam|config\\sam|php\.ini|httpd\.conf|my\.ini)\b",


        r"/(WEB|META)\\{0,2}-INF(?:[\\/.;]|%2f|%5c)",

        r"%00|\x00",
    ],
    "command_injection": [
        r";\s*(cat|ls|id|whoami|uname|pwd|wget|curl|nc|bash|sh|rm|chmod|cp|mv|ping|kill|touch)\b",
        r"\|\s*(cat|ls|id|whoami|uname|nc|bash|sh|wget|curl|grep|awk)\b",
        r"&&\s*(cat|ls|id|whoami|wget|curl|bash|sh|nc|ping)\b",
        r"\|\|\s*(cat|ls|id|whoami|wget|curl)\b",

        r"`\s*(id|whoami|uname|cat|ls|pwd|wget|curl|nc|bash|sh|ping|sleep|echo|nslookup|hostname|ifconfig)(?![\w-])[^`]{0,80}`",
        r"\$\([^)]{1,80}\)",
        r"/bin/(ba)?sh\b",
        r"\bnc\s+-e\b",
        r"\b(wget|curl)\s+https?://",
        r"\bchmod\s+[0-7]{3,4}\b",
        r"\bbash\s+-i\b",
        r"%0a\s*(cat|ls|id|whoami|wget|curl)",

        r";\s*(ncat|socat|python3?|perl|ruby|php|busybox|env|export|crontab|useradd|passwd|systemctl|service)\b",
        r"\|\s*(ncat|socat|python3?|perl|ruby|php|xargs|tee|base64)\b",
        r"&&\s*(sleep|ping|python3?|perl|php|base64)\b",
        r"\|\|\s*(sleep|ping|nc|python3?|perl|bash|sh)\b",

        r"\$\{IFS\}",
        r"\bIFS\s*=",
        r"\bping\s+-[cn]\s+\d+",
        r"\bsleep\s+\d+\s*(;|\||&|$)",
        r">\s*/dev/null\s*2>&1",

        r"/dev/tcp/\d{1,3}\.\d{1,3}",
        r"\bmkfifo\b",
        r"\b(wget|curl)\b[^|]{0,60}\|\s*(ba)?sh\b",
        r"\b(sh|bash|zsh)\s+-c\s",
        r"\b(python3?|perl|ruby)\s+-[ce]\s",
        r"\bphp\s+-r\s",
        r"\bbase64\s+-d\b",


        r"\b(system|exec|eval|assert)\s*\\{0,2}\(\s*(\\{0,2}[\"'`$]|[a-z_]\w*\s*\\{0,2}\()|\b(shell_exec|passthru|proc_open|popen)\s*\(",

        r"\{\s*\$\{|\$\{\s*(system|exec|passthru|shell_exec|phpinfo|eval|assert|popen|proc_open)\s*\(",
        r"\bphpinfo\s*\(\s*\)",
        r"\b(cat|more|less|head|tail)\s+/etc/(passwd|shadow)\b",

        r";\s*(echo|printf|nslookup|dig|ifconfig|netstat|hostname|tftp|telnet|find|which|whoami|sleep)\b",
        r"\|\s*(echo|nslookup|dig|ifconfig|netstat|hostname|whoami|uname|id|sleep|tftp|telnet|sh)\b",
        r"&&\s*(echo|nslookup|dig|ifconfig|netstat|hostname|uname|id|tftp|telnet)\b",
        r"%0[ad]\s*(echo|nslookup|ping|sleep|bash|sh|nc|uname)\b",

        r"\b(burpcollaborator\.net|oastify\.com|interact\.sh|oast\.(pro|live|site|online|fun|me)|dnslog\.(cn|link)|ceye\.io|requestbin\.net|pipedream\.net|webhook\.site)\b",


        r"\b(wget|curl|fetch|tftp|lwp-download)[ \t]+(-\S+[ \t]+){0,4}(https?://)?\d{1,3}(\.\d{1,3}){3}",
        r"\b(nc|ncat|netcat)[ \t]+(-\w+[ \t]+){0,4}\d{1,3}(\.\d{1,3}){3}[ \t]+\d{2,5}\b",
        r"\bsocat\s+(tcp|exec|file|openssl)",
        r"\btelnet[ \t]+\d{1,3}(\.\d{1,3}){3}",
        r"\b(wget|curl)\b.{0,80}?(-O\s*/tmp|-o\s*/tmp|>\s*/tmp)",
        r"/tmp/[\w.-]{1,40}\s*;\s*(chmod|sh|bash|\./)",

        r"/\?{2,}/\?{2,}|/b\?n/|/\?in/",
        r"\b(cat|tac|nl|head|tail)\s*<\s*/",
        r"\becho\s+-[ne]\s",

        r"\(\s*\)\s*\{\s*:?\s*;?\s*\}\s*;",

        r"\$\{\s*(jndi|\$\{\s*(lower|upper|::-j|env:|sys:|date:)|ctx:|java:)",
        r"\bjndi\s*:\s*(ldaps?|rmi|dns|iiop|corba|nds|http)\s*:",

        r"\{\{.{0,60}?(__class__|__globals__|__builtins__|__import__|__subclasses__|os\.popen|subprocess|config\.items|self\._TemplateReference|request\.application)",
        r"\{\{\s*\d+\s*\*\s*['\"]?\d+['\"]?\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|<%=\s*\d+\s*\*\s*\d+\s*%>",
        r"\$\{.{0,30}?(Runtime|getRuntime|ProcessBuilder|T\(java\.lang)",
        r"#\{.{0,40}?(exec|system|popen|spawn)\b",

        r"java\.lang\.(Runtime|ProcessBuilder)|getRuntime\s*\(\s*\)\s*\.\s*exec",
        r"#_memberAccess|@ognl\.OgnlContext|%\{\s*\(?#",
        r"\bclass\.module\.classLoader",

        r"<\?php|<\?=",
        r"\b(eval|assert|create_function)\s*\(\s*(\$_|base64_decode|gzinflate|str_rot13)",
        r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\[",
        r"\bbase64_decode\s*\(|\bgzinflate\s*\(",
        r"allow_url_include|auto_prepend_file|-d\s*\+?\s*allow_url",

        r"\bcmd(\.exe)?\s*/[ck]\b",
        r"\bpowershell(\.exe)?\s+(-\w+\s+){0,4}-(e|enc|encodedcommand|nop|noprofile|w|windowstyle|c|command|ep|executionpolicy)\b",
        r"\b(certutil|bitsadmin|mshta|regsvr32|rundll32|wmic)(\.exe)?\s+[-/\w]",
        r"\bIEX\s*\(|Invoke-(Expression|WebRequest)|DownloadString\s*\(|Net\.WebClient",

        r"[|&;]\s*set\s+/a\s",
    ],
}


CRS_SIGNATURES_PATH = Path(__file__).resolve().parent / "database" / "crs_signatures.json"

DEFAULT_DESCRIPTIONS: dict[str, dict[str, str]] = {}


def _load_crs_signatures() -> None:
    try:
        with CRS_SIGNATURES_PATH.open(encoding="utf-8") as f:
            data = json.load(f).get("signatures") or {}
    except (OSError, ValueError) as exc:
        print(f"[{LOG_PREFIX}] อ่าน {CRS_SIGNATURES_PATH.name} ไม่ได้ ({exc}) — ข้ามชุด OWASP CRS")
        return

    for detection_type, rows in data.items():
        patterns = DEFAULT_SIGNATURES.setdefault(detection_type, [])
        for row in rows:
            if row.get("pattern") and row["pattern"] not in patterns:
                patterns.append(row["pattern"])
                DEFAULT_DESCRIPTIONS.setdefault(detection_type, {})[row["pattern"]] = row.get("description")


_load_crs_signatures()


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


def effective_default_signatures(detection_type: str) -> list[dict]:

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
        {
            "pattern": pattern,
            "category": category,
            "description": DEFAULT_DESCRIPTIONS.get(detection_type, {}).get(pattern),
            "is_active": True,
        }
        for pattern in DEFAULT_SIGNATURES.get(detection_type, [])
    ]


def default_signature_patterns(detection_type: str) -> list[str]:

    return [row["pattern"] for row in effective_default_signatures(detection_type)]


async def _seed_defaults(db, detection_type: str) -> int:

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

    cached = cache_get_json(signature_cache_key(detection_type), log_prefix=LOG_PREFIX)

    if cached is not None:
        return cached

    return await load_signatures_from_db(detection_type)


async def add_signature(
    detection_type: str,
    pattern: str,
    *,
    description: str | None = None,
    category: str | None = None,
) -> dict:

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
                is_default=pattern in set(default_signature_patterns(detection_type)),
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

    if pattern is not None and not is_valid_regex(pattern):
        raise ValueError(f"regex ไม่ถูกต้อง: {pattern!r}")

    async with AsyncSessionLocal() as db:
        signature = await get_detection_signature_by_id(db, signature_id)

        if not signature:
            return None

        detection_type = signature.detection_type


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

        "is_default": bool(signature.is_default),
    }
