#!/usr/bin/env bash
# generator: สร้างไฟล์ systemd unit ทั้งหมด (securelog-* 9 ตัว + centralredis) และ
# redis/redis-mtls.conf จาก "แม่แบบเดียว" — path/user/host ทั้งหมด derive จากค่า 4 ตัวข้างล่าง
#
# ★ ปกติ "ไม่ต้องตั้งอะไรเลย" — สคริปต์หาค่าเองจากที่ที่โปรเจกต์วางอยู่จริง:
#     PROJECT_DIR = โฟลเดอร์แม่ของ systemd/ (คือ repo ที่ไฟล์นี้อยู่ข้างใน)
#     APP_USER    = เจ้าของโฟลเดอร์นั้น
#   ย้ายโปรเจกต์ไปไหนก็แค่รัน `sudo ./install.sh` ที่เดิม unit จะชี้ path ใหม่ให้เอง
#
# ★ ส่วน "IP ที่จะ bind" ถามแยกทีละ service (dashboard :8000 / LINE webhook :8080) โดยโชว์
#   interface ที่มีจริงบนเครื่องให้เลือก หรือจะเอา 0.0.0.0 = ทุกเส้นก็ได้ — คำอธิบายอยู่ใน _hosts.sh
#   ตอบครั้งเดียวพอ ค่าถูกจำไว้ใน .env (WEB_BIND_HOST / WEBHOOK_BIND_HOST) รอบหน้าจึงไม่ถามซ้ำ
#     ถามใหม่:  ASK_HOSTS=1 sudo ./install.sh        (หรือแก้ค่าใน .env ตรง ๆ)
#
#   จะบังคับค่าเองก็ยังได้ (env ชนะค่าที่หาเอง/ค่าใน .env เสมอ และไม่ถาม):
#     APP_USER=deploy PROJECT_DIR=/srv/securelog WEB_BIND_HOST=10.0.0.5 WEBHOOK_BIND_HOST=127.0.0.1 bash _gen.sh
#
# ★ ค่าที่ขึ้นกับ "เครื่อง" ก็หาเองเช่นกัน (บังคับได้ด้วย env): ชื่อ unit ของ PostgreSQL (`PG_UNIT`)
#   และ path ของ redis-server (`REDIS_SERVER_BIN`) — distro/เวอร์ชันต่างกันคนละชื่อคนละที่
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_hosts.sh
source "$DIR/_hosts.sh"

# ---- ค่าที่ใช้สร้าง unit (env ที่ส่งเข้ามาชนะเสมอ ไม่งั้นหาเองจากของจริงบนเครื่อง) ----

# systemd/ อยู่ใต้ repo เสมอ -> โฟลเดอร์แม่คือที่ตั้งโปรเจกต์ ไม่ต้องเดา ไม่ต้องตั้งค่า
PROJECT_DIR="${PROJECT_DIR:-$(dirname "$DIR")}"

# กันสร้าง unit ที่ชี้ไปที่ที่ไม่ใช่โปรเจกต์ (เช่น copy แค่โฟลเดอร์ systemd/ ไปไว้ที่อื่น)
for need in main/main.py requirements.txt redis; do
    [ -e "$PROJECT_DIR/$need" ] || {
        echo "!! $PROJECT_DIR ไม่ใช่โฟลเดอร์โปรเจกต์ (ไม่พบ $need)" >&2
        echo "   ถ้าตั้งใจ ให้ระบุเอง: PROJECT_DIR=/path/to/securelog bash _gen.sh" >&2
        exit 1
    }
done

# user ที่รัน service = เจ้าของโฟลเดอร์โปรเจกต์ (คนที่ไฟล์เป็นของเขาอยู่แล้ว = อ่านได้แน่)
APP_USER="${APP_USER:-$(stat -c %U "$PROJECT_DIR")}"
APP_GROUP="${APP_GROUP:-$APP_USER}"

# ---- IP ที่แต่ละ service จะ bind (dashboard กับ webhook แยกกันคนละค่า) ----
ENV_FILE="$PROJECT_DIR/.env"

# ค่าที่เคยเลือกไว้ใน .env = ค่าที่ระบบใช้อยู่จริง จึงไม่ต้องถามซ้ำทุกครั้งที่ติดตั้ง
# (ASK_HOSTS=1 = ข้ามค่าที่จำไว้ แล้วถามใหม่)
if [ "${ASK_HOSTS:-0}" != "1" ]; then
    WEB_BIND_HOST="${WEB_BIND_HOST:-$(env_get WEB_BIND_HOST "$ENV_FILE")}"
    WEBHOOK_BIND_HOST="${WEBHOOK_BIND_HOST:-$(env_get WEBHOOK_BIND_HOST "$ENV_FILE")}"
fi

# ค่าตั้งต้นของ dashboard ไล่จาก "ของจริงที่สุด" ลงไป:
#   BIND_HOST ที่ส่งมาเอง -> ค่าที่ unit ตัวที่ติดตั้งอยู่ bind อยู่ตอนนี้ -> REDIS_HOST ใน .env
#   (IP ที่อยู่ใน SAN ของ cert แน่ ๆ) -> IP หลักของเครื่อง
WEB_DEFAULT="${BIND_HOST:-}"
[ -n "$WEB_DEFAULT" ] || WEB_DEFAULT="$(installed_bind_host securelog-web.service)"
[ -n "$WEB_DEFAULT" ] || WEB_DEFAULT="$(env_get REDIS_HOST "$ENV_FILE")"
[ -n "$WEB_DEFAULT" ] || WEB_DEFAULT="$(detect_primary_ip)"

pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) — ให้เปิดรับทาง IP ไหน" "$WEB_DEFAULT" 1 \
    "เลือก IP เดียว = เครือข่ายอื่นของเครื่องเข้าไม่ถึงเลย · ต้องเป็น IP ที่มีใน SAN ของ cert ด้วย"

# ไม่เคยติดตั้งมาก่อนจึงจะใช้ 0.0.0.0 = พฤติกรรมเดิมก่อนแยกค่านี้ออกมา (เดิมฮาร์ดโค้ดไว้ในบรรทัด gen)
HOOK_DEFAULT="$(installed_bind_host securelog-line-webhook.service)"
[ -n "$HOOK_DEFAULT" ] || HOOK_DEFAULT="0.0.0.0"

pick_bind_host WEBHOOK_BIND_HOST \
    "LINE webhook (HTTP :8080) — ให้เปิดรับทาง IP ไหน" "$HOOK_DEFAULT" 1 \
    "LINE ยิงเข้ามาผ่าน tunnel · tunnel อยู่เครื่องเดียวกันเลือก 127.0.0.1 ได้ (ไม่โผล่ออกเครือข่าย)"

for _v in WEB_BIND_HOST WEBHOOK_BIND_HOST; do
    [ -n "${!_v}" ] || {
        echo "!! หา IP ของเครื่องไม่ได้ — ระบุเอง: $_v=10.0.0.5 bash _gen.sh" >&2
        exit 1
    }
    valid_host "${!_v}" || { echo "!! $_v='${!_v}' ไม่ใช่ IP/ชื่อโฮสต์ที่ถูกต้อง" >&2; exit 1; }
done

# จำค่าที่ได้ลง .env เพื่อให้รอบถัดไปไม่ถามอีก และให้เห็นได้จากที่เดียวว่าตอนนี้ bind อะไรอยู่
if [ -f "$ENV_FILE" ]; then
    [ "$(env_get WEB_BIND_HOST "$ENV_FILE")" = "$WEB_BIND_HOST" ] \
        || env_set WEB_BIND_HOST "$WEB_BIND_HOST" "$ENV_FILE"
    [ "$(env_get WEBHOOK_BIND_HOST "$ENV_FILE")" = "$WEBHOOK_BIND_HOST" ] \
        || env_set WEBHOOK_BIND_HOST "$WEBHOOK_BIND_HOST" "$ENV_FILE"
fi
# ------------------------------------------------

REDIS_DIR="$PROJECT_DIR/redis"

# ---- ค่าที่ขึ้นกับเครื่อง ไม่ใช่กับโปรเจกต์ (distro/เวอร์ชันต่างกันคนละชื่อ/คนละ path) ----

# ชื่อ unit ของ PostgreSQL: Debian/Ubuntu เป็น postgresql@<major>-<cluster> (ตัวที่ถือ process จริง)
# distro อื่นเป็น postgresql.service เฉย ๆ — เดิมฮาร์ดโค้ด @16-main ไว้ เครื่องที่เป็นเวอร์ชันอื่น
# systemd จะข้าม After= นั้นเงียบ ๆ แล้ว service ได้ start ก่อน DB พร้อมตอน boot
detect_pg_unit() {
    local u
    u="$(systemctl list-units --all --plain --no-legend 'postgresql@*.service' 2>/dev/null | awk 'NR==1{print $1}')" || true
    [ -n "${u:-}" ] && { printf '%s' "$u"; return; }
    u="$(systemctl list-unit-files --plain --no-legend 'postgresql.service' 2>/dev/null | awk 'NR==1{print $1}')" || true
    printf '%s' "${u:-}"
}
PG_UNIT="${PG_UNIT:-$(detect_pg_unit)}"
# ไม่เจอเลย = ไม่ต้องใส่ After= ของ postgres (ใส่ชื่อมั่วไปก็ได้แค่บรรทัดที่ systemd ไม่สนใจ)
AFTER_LINE="After=network-online.target centralredis.service${PG_UNIT:+ $PG_UNIT}"

# path ของ redis-server: apt ลงที่ /usr/bin แต่ distro อื่น/ติดตั้งเองอยู่คนละที่ = 203/EXEC
REDIS_SERVER_BIN="${REDIS_SERVER_BIN:-$(command -v redis-server || true)}"
REDIS_SERVER_BIN="${REDIS_SERVER_BIN:-/usr/bin/redis-server}"

# โฟลเดอร์เก็บ dump.rdb ต้องมีอยู่ก่อน redis จะ start (redis ตอบ "dir ... No such file or directory"
# แล้วตายทันที) — fresh clone ไม่มีโฟลเดอร์นี้เพราะ .gitignore กันข้อมูลไว้
mkdir -p "$REDIS_DIR/data-redis"

VENV="$PROJECT_DIR/venv"
PY="$VENV/bin/python"
UVICORN="$VENV/bin/uvicorn"
DASH_CERT="$PROJECT_DIR/cert/central/dashboard.crt"
DASH_KEY="$PROJECT_DIR/cert/central/dashboard.key"

# ---- securelog-* : app process (โครงเดียวกันหมด ต่างแค่ desc/exec + บล็อกเสริมของบางตัว) ----
#
# ⚠️ แก้ค่าใน unit ต้องแก้ "ที่นี่" เท่านั้น — ไฟล์ .service ถูกสร้างใหม่ทับทุกครั้งที่ติดตั้ง
#    (เคยมีคนไปแก้ TimeoutStopSec ในไฟล์ .service ตรง ๆ แล้วรอบถัดไปหายไปเงียบ ๆ)
gen() {
    local name="$1" desc="$2" exec="$3" extra="${4:-}"
    cat > "$DIR/$name.service" <<EOF
[Unit]
Description=SecureLog - $desc
# start หลัง network + redis + postgres พร้อม (โค้ดมี reconnect loop เอง ใช้ After พอ ไม่ต้อง Requires)
$AFTER_LINE
Wants=network-online.target
# stop/restart ที่ securelog.target ให้ลามมาถึงตัวนี้ด้วย
PartOf=securelog.target

[Service]
Type=simple
User=$APP_USER
Group=$APP_GROUP
# สำคัญ: ทุก process ต้องรันจาก main/ (import แบบ package + อ่าน .env จาก cwd)
WorkingDirectory=$PROJECT_DIR/main
ExecStart=$exec
Restart=always
RestartSec=5
Environment=PYTHONUNBUFFERED=1
$extra
[Install]
WantedBy=securelog.target
EOF
}

# ตัวเว็บมีบล็อกเสริมเรื่องเวลาปิด — ดูคำอธิบายในบล็อกนั้น
gen securelog-web "Web Dashboard (HTTPS)" \
    "$UVICORN main:app --host $WEB_BIND_HOST --port 8000 --ssl-certfile $DASH_CERT --ssl-keyfile $DASH_KEY --timeout-graceful-shutdown 5" \
'
# ⚠️ ค่านี้กับ --timeout-graceful-shutdown ใน ExecStart คือตัวที่ทำให้ `systemctl restart` ไม่ค้าง — ห้ามลบ
#
# `/api/stream/alerts` เป็น SSE ที่วนส่ง event ไปเรื่อย ๆ จบเองไม่ได้ ถ้ามีใครเปิดหน้า
# dashboard ค้างไว้ ตอน stop uvicorn จะขึ้น "Waiting for connections to close." แล้วรอ
# ตลอดไป จน systemd หมด TimeoutStopSec (default 90 วิ) ค่อย SIGKILL
# → เคยวัดได้จริง: restart ครั้งนึงค้าง 90 วินาที
#
# แก้ที่โค้ดไม่ได้ เพราะ uvicorn ปิด connection ให้หมด "ก่อน" จะรัน lifespan shutdown
# (ธงบอกสถานะที่ตั้งใน lifespan จึงตั้งช้าไปเสมอ) — ต้องใช้ตัวจับเวลาของ uvicorn เอง
# ตอนนี้: มี SSE ค้าง = ปิดใน ~5 วิ / ไม่มีใครเปิดหน้าค้าง = ปิดใน ~1 วิ
TimeoutStopSec=20
'
gen securelog-normalizer         "Log Normalizer"        "$PY -m process_log_detect.normalize_log"
gen securelog-auth-detector      "Auth Detector (SSH brute force / sudo)"  "$PY -m process_log_detect.auth_log_detect"
gen securelog-web-detector       "Web Detector (SQLi/XSS/Path/CMDi/Flood)" "$PY -m process_log_detect.web_log_detect"
gen securelog-firewall-detector  "Firewall Detector (Port scan / deny rate)" "$PY -m process_log_detect.firewall_log_detect"
gen securelog-agent-monitor      "Agent Monitor (metrics + state sync)"    "$PY -m process_agent.process_agent"
gen securelog-blacklist-sweeper  "Blacklist Expiry Sweeper"                "$PY blacklist_expiry.py"
gen securelog-line-notifier      "LINE Alert Notifier"                     "$PY -m LINE_API.alert_subscriber"
gen securelog-line-webhook       "LINE Webhook Receiver"                   "$UVICORN LINE_API.webhook_app:app --host $WEBHOOK_BIND_HOST --port 8080"

# ---- centralredis : infrastructure (โครงต่างจาก securelog-* — ไม่มี PartOf securelog.target
#      เพราะ restart กลุ่ม app ต้องไม่ลาก Redis/คิว log/connection agent ไป restart ด้วย) ----
cat > "$DIR/centralredis.service" <<EOF
[Unit]
Description=Custom Redis Server (SecureLog mTLS)
After=network.target

[Service]
Type=simple
WorkingDirectory=$REDIS_DIR
ExecStart=$REDIS_SERVER_BIN $REDIS_DIR/redis-mtls.conf
# ⚠️ ห้ามใส่ ExecStop=redis-cli shutdown กลับมา — redis-cli ที่ไม่ระบุ port จะต่อ 127.0.0.1:6379
#    ซึ่ง "ไม่ใช่ instance ของเรา" (ของเราคือ tls-port 6380 และตั้ง port 0 ปิด plaintext ไว้)
#    เครื่องที่มี redis ของ distro รันอยู่ด้วย = stop centralredis แล้วไปปิด redis ตัวนั้นแทน
#    ปล่อยให้ systemd ส่ง SIGTERM พอ — redis จัดการ save + ปิดให้เองอยู่แล้ว
Restart=always
User=$APP_USER
Group=$APP_GROUP

[Install]
WantedBy=multi-user.target
EOF

# ---- redis-mtls.conf : path ทั้งหมด derive จาก PROJECT_DIR (ต้องตรงกับ centralredis.service) ----
cat > "$REDIS_DIR/redis-mtls.conf" <<EOF
port 0
tls-port 6380
tls-cert-file $PROJECT_DIR/cert/central/central.crt
tls-key-file $PROJECT_DIR/cert/central/central.key
tls-ca-cert-file $PROJECT_DIR/cert/central/ca.crt
tls-auth-clients yes
aclfile $REDIS_DIR/users.acl
dir $REDIS_DIR/data-redis
dbfilename dump.rdb
EOF

# รันด้วย sudo แล้วไฟล์ที่เพิ่งเขียนจะเป็นของ root — คืนเจ้าของให้ตรงกับโปรเจกต์
# ไม่งั้นเจ้าของเดิมแก้/ลบไฟล์พวกนี้ไม่ได้ (และ git status จะขึ้นสิทธิ์เปลี่ยนทุกครั้ง)
if [ "$(id -u)" -eq 0 ]; then
    # data-redis ต้องเป็นของ APP_USER ด้วย — redis รันด้วย user นั้นและต้องเขียน dump.rdb ลงไปได้
    chown "$(stat -c %U:%G "$PROJECT_DIR")" "$DIR"/securelog-*.service "$DIR/centralredis.service" \
        "$REDIS_DIR/redis-mtls.conf" "$REDIS_DIR/data-redis" 2>/dev/null || true
fi

echo "generated: $(ls "$DIR"/securelog-*.service | wc -l) securelog units + centralredis.service + redis-mtls.conf"
echo "  APP_USER=$APP_USER  PROJECT_DIR=$PROJECT_DIR"
echo "  dashboard :8000 -> $WEB_BIND_HOST   ·   LINE webhook :8080 -> $WEBHOOK_BIND_HOST"
echo "  redis-server=$REDIS_SERVER_BIN  ·  After= postgres: ${PG_UNIT:-(ไม่พบ — ข้ามไป)}"

# เตือนกรณีที่ unit จะ start ไม่ขึ้นแน่ ๆ — บอกตอนนี้ดีกว่าไปงงตอน systemd ตอบ 203/EXEC
if [ ! -x "$REDIS_SERVER_BIN" ]; then
    echo "  [!] ไม่พบ $REDIS_SERVER_BIN — ติดตั้ง redis ก่อน (apt install redis-server) ไม่งั้น centralredis start ไม่ขึ้น"
fi

if [ -z "$PG_UNIT" ]; then
    echo "  [!] หา unit ของ PostgreSQL ไม่เจอ — unit จะไม่มี After= ของ DB (ตอน boot อาจ start ก่อน DB พร้อม"
    echo "      แล้ว restart เองจนต่อได้) · ระบุเองได้: PG_UNIT=postgresql@17-main.service"
fi

if [ ! -x "$PY" ]; then
    echo "  [!] ยังไม่มี $PY — สร้าง venv ก่อน ไม่งั้น service จะ start ไม่ขึ้น"
fi

# เบราว์เซอร์จะขึ้น cert error ถ้าเข้าเว็บด้วย IP ที่ไม่มีใน SAN — เตือนตอนนี้ดีกว่าไปเจอตอนเปิดหน้า
# (0.0.0.0 บอกอะไรไม่ได้ เพราะขึ้นกับว่าคนใช้พิมพ์ IP ไหนบนเบราว์เซอร์)
if [ "$WEB_BIND_HOST" != "0.0.0.0" ] && [ -f "$DASH_CERT" ] && command -v openssl >/dev/null 2>&1; then
    if ! openssl x509 -in "$DASH_CERT" -noout -ext subjectAltName 2>/dev/null \
        | grep -qE "(IP Address|DNS):${WEB_BIND_HOST}([,[:space:]]|\$)"; then
        echo "  [!] SAN ใน dashboard.crt ไม่มี $WEB_BIND_HOST — เบราว์เซอร์จะเตือน cert ไม่ตรง"
        echo "      ออก cert ใหม่: sudo BIND_HOST=$WEB_BIND_HOST FORCE_CERT=1 $PROJECT_DIR/setup-server.sh"
    fi
fi

if [ "$APP_USER" = "root" ]; then
    echo "  [!] โปรเจกต์เป็นของ root — service จะรันด้วยสิทธิ์ root (ตั้ง APP_USER=... ถ้าไม่ต้องการ)"
fi
