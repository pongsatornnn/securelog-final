#!/usr/bin/env bash
# generator: สร้างไฟล์ systemd unit ทั้งหมด (securelog-* 9 ตัว + centralredis) และ
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
        echo "!! $PROJECT_DIR is not the project directory ($need not found)" >&2
        echo "   If this is intentional, set it explicitly: PROJECT_DIR=/path/to/securelog bash _gen.sh" >&2
        exit 1
    }
done

# user ที่รัน service = เจ้าของโฟลเดอร์โปรเจกต์ (คนที่ไฟล์เป็นของเขาอยู่แล้ว = อ่านได้แน่)
APP_USER="${APP_USER:-$(stat -c %U "$PROJECT_DIR")}"
APP_GROUP="${APP_GROUP:-$APP_USER}"

# ---- IP ที่แต่ละ service จะ bind (dashboard กับ webhook แยกกันคนละค่า) ----
ENV_FILE="$PROJECT_DIR/.env"

# ค่าที่เคยเลือกไว้ใน .env = ค่าที่ระบบใช้อยู่จริง จึงไม่ต้องถามซ้ำทุกครั้งที่ติดตั้ง
if [ "${ASK_HOSTS:-0}" != "1" ]; then
    WEB_BIND_HOST="${WEB_BIND_HOST:-$(env_get WEB_BIND_HOST "$ENV_FILE")}"
    WEBHOOK_BIND_HOST="${WEBHOOK_BIND_HOST:-$(env_get WEBHOOK_BIND_HOST "$ENV_FILE")}"
fi

# ---- reverse proxy หน้า dashboard (nginx ฯลฯ) ----
# มี proxy คั่น = socket ที่ uvicorn เห็นเป็นของ proxy ไม่ใช่ของ client -> login lockout กับ rate limit
# ที่นับตาม IP จะรวมทุกคนเป็นก้อนเดียว (คนเดียวใส่รหัสผิดจนล็อก = ล็อกทุกคน)
# ใส่ IP ของ proxy ที่เชื่อได้ (คั่นด้วย ,) แล้ว uvicorn จะอ่าน IP จริงจาก X-Forwarded-For ให้
# ว่าง = ไม่มี proxy ไม่ต้องใส่ flag (ค่าเดิมของระบบ)
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-$(env_get FORWARDED_ALLOW_IPS "$ENV_FILE")}"
PROXY_FLAGS=""
if [ -n "$FORWARDED_ALLOW_IPS" ]; then
    PROXY_FLAGS=" --proxy-headers --forwarded-allow-ips $FORWARDED_ALLOW_IPS"
fi

# ค่าตั้งต้นของ dashboard ไล่จาก "ของจริงที่สุด" ลงไป:
WEB_DEFAULT="${BIND_HOST:-}"
[ -n "$WEB_DEFAULT" ] || WEB_DEFAULT="$(installed_bind_host securelog-web.service)"
[ -n "$WEB_DEFAULT" ] || WEB_DEFAULT="$(env_get REDIS_HOST "$ENV_FILE")"
[ -n "$WEB_DEFAULT" ] || WEB_DEFAULT="$(detect_primary_ip)"

pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) - which IP to listen on" "$WEB_DEFAULT" 1 \
    "One IP = other networks on this host cannot reach it; it must also be in the cert SAN"

# ไม่เคยติดตั้งมาก่อนจึงจะใช้ 0.0.0.0 = พฤติกรรมเดิมก่อนแยกค่านี้ออกมา (เดิมฮาร์ดโค้ดไว้ในบรรทัด gen)
HOOK_DEFAULT="$(installed_bind_host securelog-line-webhook.service)"
[ -n "$HOOK_DEFAULT" ] || HOOK_DEFAULT="0.0.0.0"

pick_bind_host WEBHOOK_BIND_HOST \
    "LINE webhook (HTTP :8080) - which IP to listen on" "$HOOK_DEFAULT" 1 \
    "LINE calls in through a tunnel; if the tunnel runs here, 127.0.0.1 keeps it off the network"

for _v in WEB_BIND_HOST WEBHOOK_BIND_HOST; do
    [ -n "${!_v}" ] || {
        echo "!! Could not detect this machine's IP - set it explicitly: $_v=10.0.0.5 bash _gen.sh" >&2
        exit 1
    }
    valid_host "${!_v}" || { echo "!! $_v='${!_v}' is not a valid IP or hostname" >&2; exit 1; }
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

# ---- พอร์ตที่ Redis (mTLS) ฟัง — setup-server.sh ถามตอนติดตั้งแล้วเขียนลง .env ----
REDIS_PORT="${REDIS_PORT:-$(env_get REDIS_PORT "$ENV_FILE")}"
REDIS_PORT="${REDIS_PORT:-6380}"

# ค่าเพี้ยน (แก้ .env ด้วยมือแล้วพิมพ์ผิด) = **หยุด** ไม่ใช่ตกไปใช้ 6380 เงียบ ๆ — ถ้าตกกลับไป
valid_port "$REDIS_PORT" || {
    echo "!! REDIS_PORT='$REDIS_PORT' in $ENV_FILE is not a usable port (must be 1024-65535)" >&2
    echo "   centralredis runs as a normal user, so ports below 1024 cannot be bound either." >&2
    echo "   Fix the value in .env, or re-run: sudo $PROJECT_DIR/setup-server.sh" >&2
    exit 1
}

# ---- ค่าที่ขึ้นกับเครื่อง ไม่ใช่กับโปรเจกต์ (distro/เวอร์ชันต่างกันคนละชื่อ/คนละ path) ----

# ชื่อ unit ของ PostgreSQL: Debian/Ubuntu เป็น postgresql@<major>-<cluster> (ตัวที่ถือ process จริง)
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
mkdir -p "$REDIS_DIR/data-redis"

VENV="$PROJECT_DIR/venv"
PY="$VENV/bin/python"
UVICORN="$VENV/bin/uvicorn"
DASH_CERT="$PROJECT_DIR/cert/central/dashboard.crt"
DASH_KEY="$PROJECT_DIR/cert/central/dashboard.key"

# ---- securelog-* : app process (โครงเดียวกันหมด ต่างแค่ desc/exec + บล็อกเสริมของบางตัว) ----
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
    "$UVICORN main:app --host $WEB_BIND_HOST --port 8000 --ssl-certfile $DASH_CERT --ssl-keyfile $DASH_KEY --timeout-graceful-shutdown 5$PROXY_FLAGS" \
'
# ⚠️ ค่านี้กับ --timeout-graceful-shutdown ใน ExecStart คือตัวที่ทำให้ `systemctl restart` ไม่ค้าง — ห้ามลบ
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
REDIS_CONF="$REDIS_DIR/redis-mtls.conf"
NEW_REDIS_CONF="$(cat <<EOF
port 0
tls-port $REDIS_PORT
tls-cert-file $PROJECT_DIR/cert/central/central.crt
tls-key-file $PROJECT_DIR/cert/central/central.key
tls-ca-cert-file $PROJECT_DIR/cert/central/ca.crt
tls-auth-clients yes
aclfile $REDIS_DIR/users.acl
dir $REDIS_DIR/data-redis
dbfilename dump.rdb
EOF
)"

# สำรองของเดิมไว้ก่อนเขียนทับ — **เฉพาะตอนเนื้อหาต่างจริง** ไม่งั้นติดตั้งซ้ำทุกครั้งจะได้ไฟล์
REDIS_CONF_BACKUP=""
if [ -f "$REDIS_CONF" ] && [ "$(cat "$REDIS_CONF")" != "$NEW_REDIS_CONF" ]; then
    REDIS_CONF_BACKUP="$REDIS_CONF.bak.$(date +%Y%m%d%H%M%S)"
    cp -p "$REDIS_CONF" "$REDIS_CONF_BACKUP"
fi

printf '%s\n' "$NEW_REDIS_CONF" > "$REDIS_CONF"

# รันด้วย sudo แล้วไฟล์ที่เพิ่งเขียนจะเป็นของ root — คืนเจ้าของให้ตรงกับโปรเจกต์
if [ "$(id -u)" -eq 0 ]; then
    # data-redis ต้องเป็นของ APP_USER ด้วย — redis รันด้วย user นั้นและต้องเขียน dump.rdb ลงไปได้
    chown "$(stat -c %U:%G "$PROJECT_DIR")" "$DIR"/securelog-*.service "$DIR/centralredis.service" \
        "$REDIS_CONF" ${REDIS_CONF_BACKUP:+"$REDIS_CONF_BACKUP"} "$REDIS_DIR/data-redis" 2>/dev/null || true
fi

echo "generated: $(ls "$DIR"/securelog-*.service | wc -l) securelog units + centralredis.service + redis-mtls.conf"
echo "  APP_USER=$APP_USER  PROJECT_DIR=$PROJECT_DIR"
echo "  dashboard :8000 -> $WEB_BIND_HOST   ·   LINE webhook :8080 -> $WEBHOOK_BIND_HOST"
echo "  redis mTLS tls-port $REDIS_PORT"
if [ -n "$REDIS_CONF_BACKUP" ]; then
    echo "  previous redis-mtls.conf kept at $REDIS_CONF_BACKUP"
fi
echo "  redis-server=$REDIS_SERVER_BIN  |  After= postgres: ${PG_UNIT:-(not found - skipped)}"

# เตือนกรณีที่ unit จะ start ไม่ขึ้นแน่ ๆ — บอกตอนนี้ดีกว่าไปงงตอน systemd ตอบ 203/EXEC
if [ ! -x "$REDIS_SERVER_BIN" ]; then
    echo "  [!] $REDIS_SERVER_BIN not found - install redis first (apt install redis-server) or centralredis will not start"
fi

if [ -z "$PG_UNIT" ]; then
    echo "  [!] PostgreSQL unit not found - the units will have no After= for the DB (on boot they may start before the DB is ready"
    echo "      and restart themselves until it connects) - set it explicitly: PG_UNIT=postgresql@17-main.service"
fi

if [ ! -x "$PY" ]; then
    echo "  [!] $PY does not exist yet - create the venv first or the services will not start"
fi

# เบราว์เซอร์จะขึ้น cert error ถ้าเข้าเว็บด้วย IP ที่ไม่มีใน SAN — เตือนตอนนี้ดีกว่าไปเจอตอนเปิดหน้า
if [ "$WEB_BIND_HOST" != "0.0.0.0" ] && [ -f "$DASH_CERT" ] && command -v openssl >/dev/null 2>&1; then
    if ! openssl x509 -in "$DASH_CERT" -noout -ext subjectAltName 2>/dev/null \
        | grep -qE "(IP Address|DNS):${WEB_BIND_HOST}([,[:space:]]|\$)"; then
        echo "  [!] dashboard.crt SAN does not include $WEB_BIND_HOST - browsers will warn about a cert mismatch"
        echo "      Reissue the cert: sudo BIND_HOST=$WEB_BIND_HOST FORCE_CERT=1 $PROJECT_DIR/setup-server.sh"
    fi
fi

if [ "$APP_USER" = "root" ]; then
    echo "  [!] The project is owned by root - services will run as root (set APP_USER=... if you do not want that)"
fi
