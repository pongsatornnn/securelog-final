#!/usr/bin/env bash
#
# setup-server.sh — ติดตั้ง SecureLog "ฝั่ง Central" บนเครื่องใหม่ (แบบ interactive)
#
#   sudo ./setup-server.sh
#
# - ติดตั้ง "ตรงที่วางโปรเจกต์ไว้" — วางไว้ที่ไหนก็รันจากที่นั่นได้เลย ไม่ผูกกับ /opt
#   อยากให้ไปอยู่ที่อื่น:  sudo INSTALL_DIR=/srv/securelog ./setup-server.sh  (ย้ายให้แล้วรันต่อ)
#   หมายเหตุ: ถ้าวางไว้ใน /home/<คนอื่น>/ ให้ใช้ APP_USER=<เจ้าของ home นั้น> ไม่งั้น service
#   เข้าไปอ่านไฟล์ไม่ได้ (home ปกติเป็น 750) — หรือวางนอก home ไปเลยเช่น /srv, /usr/local
# - ถาม user / IP / รหัสผ่าน เอง (ไม่รู้ก็กรอกตอนรัน) — หรือ preset ผ่าน env เพื่อรันแบบไม่ถาม:
#     sudo APP_USER=deploy BIND_HOST=10.0.0.5 DB_PASSWORD=xxx REDIS_PASS=yyy ./setup-server.sh
#   IP ถามแยก 3 ช่อง (โชว์ interface ที่มีจริงให้เลือก): BIND_HOST = ที่อยู่ของ central ที่เครื่องอื่น
#   เรียกเข้ามา (ลง SAN/agent · ห้าม 0.0.0.0) · WEB_BIND_HOST = --host ของ dashboard :8000 ·
#   WEBHOOK_BIND_HOST = --host ของ LINE webhook :8080  (สองตัวหลังใส่ 0.0.0.0 = ทุก interface ได้)
#   (ถ้า PostgreSQL superuser ต้องใช้รหัส — peer auth ต่อไม่ได้ — สคริปต์จะถามรหัสตอนรัน หรือ preset
#    PG_SUPERUSER_PASSWORD=xxx ; ตั้ง PG_SUPERUSER/PG_HOST ได้ถ้าไม่ใช่ postgres@localhost)
# - รันซ้ำได้ (idempotent): apt/venv/DB/systemd ข้ามของที่มีอยู่แล้ว, ไม่ทับ .env เดิม
#
# ทำให้ครบตั้งแต่ต้นจนพร้อมใช้ รวมถึงส่วนที่เคยต้องทำเอง:
#   * ออก cert ใน cert/central/ ให้ SAN ตรง BIND_HOST (Root CA -> central mTLS -> dashboard HTTPS)
#   * เขียน redis/users.acl ทั้ง 3 บัญชีด้วยรหัสจริงที่กรอก/สุ่มให้ (ไม่เหลือค่า default)
#   * เขียน for_Agent/package/site.conf ให้ zip ของ agent ฝังค่าถูกต้องตั้งแต่ครั้งแรก
#
# ตัวแปรบังคับเขียนทับของเดิม (ปกติไม่ต้องใช้ — ของที่ตั้งไว้แล้วสคริปต์จะไม่แตะ):
#   FORCE_CERT=1  ออก cert ใหม่ · FORCE_ACL=1 เขียน users.acl ใหม่ · FORCE_SITE_CONF=1 เขียน site.conf ใหม่
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '  \033[1;31m[ERR]\033[0m %s\n' "$*" >&2; }

[ "$(id -u)" -eq 0 ] || { err "ต้องรันเป็น root: sudo ./setup-server.sh"; exit 1; }

# ---------------------------------------------------------------------------
# 0) ที่ตั้งของระบบ = ที่ที่วางโปรเจกต์ไว้ตอนรัน (วางไว้ตรงไหนก็ติดตั้งตรงนั้น)
#    อยากให้ไปอยู่ที่อื่น สั่ง INSTALL_DIR=/path/ที่ต้องการ แล้วสคริปต์จะย้ายให้เอง
# ---------------------------------------------------------------------------
SELF="$(readlink -f "$0")"
SRC_DIR="$(cd "$(dirname "$SELF")" && pwd)"

INSTALL_DIR="$(readlink -f "${INSTALL_DIR:-$SRC_DIR}")"

if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
    log "ย้ายโปรเจกต์ไป $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    # copy ทุกอย่างยกเว้น venv (สร้างใหม่ให้ตรงเครื่อง) และ .git (ไม่จำเป็นบน production)
    tar -C "$SRC_DIR" --exclude=venv --exclude=.git -cf - . | tar -C "$INSTALL_DIR" -xf -
    ok "คัดลอกไปที่ $INSTALL_DIR แล้ว — รันต่อจากที่นั่น"
    exec bash "$INSTALL_DIR/setup-server.sh" "$@"
fi

log "ติดตั้งที่ $INSTALL_DIR"

PROJECT_DIR="$INSTALL_DIR"
cd "$PROJECT_DIR"

# ตรวจว่าเป็น repo จริง (กันรันผิดที่)
for need in main/main.py systemd/_gen.sh systemd/_hosts.sh requirements.txt .env.example; do
    [ -e "$PROJECT_DIR/$need" ] || { err "ไม่พบ $need ใน $PROJECT_DIR — วางโปรเจกต์ไม่ครบ"; exit 1; }
done

# ตัวช่วยเลือก IP ที่จะ bind (ใช้ชุดเดียวกับ systemd/_gen.sh จะได้ถามเหมือนกันทั้งสองทาง)
# shellcheck source=systemd/_hosts.sh
source "$PROJECT_DIR/systemd/_hosts.sh"

# ---------------------------------------------------------------------------
# 1) เก็บค่า config (ถามถ้ายังไม่ได้ preset ผ่าน env)
# ---------------------------------------------------------------------------
ask() {  # ask VAR "คำถาม" "ค่า default"
    local var="$1" prompt="$2" def="${3:-}" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"      # ถ้า preset มาทาง env แล้วใช้เลย
    if [ -n "$cur" ]; then ok "$var = $cur (จาก env)"; return; fi
    if [ ! -t 0 ]; then err "ไม่มี tty และไม่ได้ set $var มา"; exit 1; fi
    read -rp "  $prompt${def:+ [$def]}: " ans
    ans="${ans:-$def}"
    [ -n "$ans" ] || { err "$var ห้ามว่าง"; exit 1; }
    eval "$var=\$ans"
}
ask_secret() {  # ask_secret VAR "คำถาม"
    local var="$1" prompt="$2" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then ok "$var = ****** (จาก env)"; return; fi
    if [ ! -t 0 ]; then err "ไม่มี tty และไม่ได้ set $var มา"; exit 1; fi
    read -rsp "  $prompt: " ans; echo
    [ -n "$ans" ] || { err "$var ห้ามว่าง"; exit 1; }
    eval "$var=\$ans"
}

# เงื่อนไขเดียวกับ main/redis_password_rules.py — รหัสที่หลุดเงื่อนไขจะทำให้ users.acl/.env เพี้ยน
# (ไฟล์ ACL แยก token ด้วยช่องว่าง · .env ตีความ # ' " $ ` \ ! เป็นอย่างอื่น)
valid_redis_pass() {
    local p="$1"
    [ "${#p}" -ge 12 ] || return 1
    printf '%s' "$p" | grep -qE '^[A-Za-z0-9_.~@%+=:,/-]+$' || return 1
    return 0
}

# ถามรหัส Redis — กด Enter เฉย ๆ = สุ่มให้ (จดชื่อตัวแปรไว้ไปโชว์ตอนจบ)
GENERATED_PASSWORDS=""
ask_redis_secret() {  # ask_redis_secret VAR "คำอธิบายบัญชี"
    local var="$1" what="$2" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then
        valid_redis_pass "$cur" || { err "$var ไม่ผ่านเงื่อนไข (ยาว >=12 และใช้ได้เฉพาะ A-Z a-z 0-9 _-.~@%+=:,/)"; exit 1; }
        ok "$var = ****** (จาก env)"
        return
    fi
    if [ ! -t 0 ]; then err "ไม่มี tty และไม่ได้ set $var มา"; exit 1; fi

    while :; do
        read -rsp "  รหัส Redis ของ$what (Enter = สุ่มให้): " ans; echo
        if [ -z "$ans" ]; then
            ans="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
            GENERATED_PASSWORDS="$GENERATED_PASSWORDS$var=$ans"$'\n'
            ok "สุ่มรหัสให้แล้ว (จะแสดงตอนจบ ให้เก็บไว้)"
            break
        fi
        valid_redis_pass "$ans" && break
        err "ต้องยาวอย่างน้อย 12 ตัว และใช้ได้เฉพาะ A-Z a-z 0-9 _-.~@%+=:,/ — ลองใหม่"
    done
    eval "$var=\$ans"
}

log "ตั้งค่า (Enter เพื่อใช้ค่า default)"
DETECTED_IP="$(detect_primary_ip)"
DEFAULT_USER="${SUDO_USER:-$(stat -c '%U' "$PROJECT_DIR")}"

ask        APP_USER   "ผู้ใช้ที่จะรัน service (User=)" "$DEFAULT_USER"

# ---- IP 3 ช่อง ถามแยกกัน (ความหมายต่างกัน — อ่านหัวไฟล์ systemd/_hosts.sh) ----
# BIND_HOST เดาแทนไม่ได้: เครื่องหลาย interface มักมีเส้น NAT ที่ agent เรียกกลับมาไม่ได้ปนอยู่
# ถ้าเดาผิดจะได้ cert ที่ SAN ผิดและชุดติดตั้ง agent ที่ต่อไม่ติด — โหมดไม่ถามจึงต้องส่งมาเอง
if [ ! -t 0 ] && [ -z "${BIND_HOST:-}" ]; then
    err "ไม่มี tty และไม่ได้ set BIND_HOST มา"; exit 1
fi
pick_bind_host BIND_HOST \
    "ที่อยู่ของ central ที่ 'เครื่องอื่น' ใช้เรียกเข้ามา" "${DETECTED_IP:-}" 0 \
    "ค่านี้ลง SAN ของ cert · REDIS_HOST · และฝังไปกับชุดติดตั้ง agent — ต้องเป็น IP จริง"
pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) — ให้เปิดรับทาง IP ไหน" "$BIND_HOST" 1 \
    "เลือก IP เดียว = เครือข่ายอื่นของเครื่องเข้าไม่ถึงเลย · 0.0.0.0 = ทุกเส้น"
pick_bind_host WEBHOOK_BIND_HOST \
    "LINE webhook (HTTP :8080) — ให้เปิดรับทาง IP ไหน" "0.0.0.0" 1 \
    "LINE ยิงเข้ามาผ่าน tunnel · tunnel อยู่เครื่องเดียวกันเลือก 127.0.0.1 ได้"

ask        DB_NAME    "ชื่อ PostgreSQL database"        "security_central"
ask        DB_USER    "PostgreSQL user"                 "$APP_USER"
ask_secret DB_PASSWORD "รหัส PostgreSQL ของ $DB_USER"
ask        REDIS_USER "Redis user ของ central"          "admin"
ask_redis_secret REDIS_PASS       "บัญชี $REDIS_USER (central ใช้ต่อ Redis)"
ask_redis_secret AGENT_REDIS_PASS "บัญชีของ agent (agent_node + default)"

APP_GROUP="${APP_GROUP:-$APP_USER}"

# ---------------------------------------------------------------------------
# 2) OS packages
# ---------------------------------------------------------------------------
log "ติดตั้ง OS packages (apt)"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq python3-venv python3-pip postgresql redis-server tar >/dev/null
ok "python3-venv / postgresql / redis-server พร้อม"

# ปิด default redis (:6379) — เรารัน instance ของเราเองผ่าน centralredis (:6380 mTLS)
systemctl disable --now redis-server >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 3) ผู้ใช้ระบบ
# ---------------------------------------------------------------------------
if id "$APP_USER" >/dev/null 2>&1; then
    ok "มี user '$APP_USER' อยู่แล้ว"
else
    warn "ยังไม่มี user '$APP_USER' — สร้างเป็น system account ให้"
    useradd --system --shell /usr/sbin/nologin --home-dir "$PROJECT_DIR" "$APP_USER"
    ok "สร้าง user '$APP_USER' แล้ว"
fi

# ---------------------------------------------------------------------------
# 4) venv + Python deps
# ---------------------------------------------------------------------------
log "สร้าง venv + ติดตั้ง requirements.txt"
[ -x "$PROJECT_DIR/venv/bin/python" ] || python3 -m venv "$PROJECT_DIR/venv"
"$PROJECT_DIR/venv/bin/pip" install -q --upgrade pip
"$PROJECT_DIR/venv/bin/pip" install -q -r "$PROJECT_DIR/requirements.txt"
ok "Python dependencies พร้อม"

# ---------------------------------------------------------------------------
# 5) .env (สร้างใหม่ถ้ายังไม่มี — ไม่ทับของเดิม)
# ---------------------------------------------------------------------------
log "ไฟล์ .env"
if [ -f "$PROJECT_DIR/.env" ]; then
    warn ".env มีอยู่แล้ว — ไม่แตะ (ถ้าต้องการสร้างใหม่ ลบทิ้งก่อนแล้วรันซ้ำ)"

    # .env เดิมคือแหล่งความจริงของรหัสที่ service ใช้อยู่ — ต้องยึดค่าจากไฟล์นี้ ไม่ใช่ค่าที่เพิ่งกรอก
    # ไม่งั้น users.acl ที่เขียนในขั้นถัดไปจะไม่ตรงกับ .env แล้ว central ต่อ Redis ไม่ได้ทันที
    ENV_REDIS_PASS="$(grep -E '^REDIS_PASS=' "$PROJECT_DIR/.env" | head -1 | cut -d= -f2- || true)"
    if [ -n "$ENV_REDIS_PASS" ] && [ "$ENV_REDIS_PASS" != "$REDIS_PASS" ]; then
        REDIS_PASS="$ENV_REDIS_PASS"
        warn "ยึดรหัสของ $REDIS_USER จาก .env เดิม (ไม่ใช่ที่เพิ่งกรอก) — จะตั้ง users.acl ให้ตรงกับ .env"
    fi

    ENV_AGENT_PASS="$(grep -E '^AGENT_REDIS_PASSWORD=' "$PROJECT_DIR/.env" | head -1 | cut -d= -f2- || true)"
    if [ -n "$ENV_AGENT_PASS" ]; then
        if [ "$ENV_AGENT_PASS" != "$AGENT_REDIS_PASS" ]; then
            AGENT_REDIS_PASS="$ENV_AGENT_PASS"
            warn "ยึดรหัสของ agent จาก .env เดิมเช่นกัน"
        fi
    else
        # .env เก่าที่ยังไม่มีคีย์กลุ่ม agent — เติมให้ ไม่งั้นชุดติดตั้งกับ users.acl จะคนละรหัสกัน
        {
            echo ""
            echo "# ค่าที่ถูกฝังลงชุดติดตั้ง agent (เติมโดย setup-server.sh)"
            echo "AGENT_CENTRAL_HOST=$BIND_HOST"
            echo "AGENT_CENTRAL_REDIS_PORT=6380"
            echo "AGENT_REDIS_USERNAME=agent_node"
            echo "AGENT_REDIS_PASSWORD=$AGENT_REDIS_PASS"
        } >> "$PROJECT_DIR/.env"
        ok "เติมค่ากลุ่ม agent ลง .env เดิม"
    fi

    # ค่า bind ยึดตามที่เพิ่งตอบ (ต่างจากรหัสผ่านที่ต้องยึด .env เดิม) — ถ้าปล่อยให้ต่างกัน
    # unit จะ bind อย่างหนึ่งแต่ .env บอกอีกอย่าง ไล่ปัญหาทีหลังไม่รู้ว่าอันไหนจริง
    env_set WEB_BIND_HOST     "$WEB_BIND_HOST"     "$PROJECT_DIR/.env"
    env_set WEBHOOK_BIND_HOST "$WEBHOOK_BIND_HOST" "$PROJECT_DIR/.env"
    ok "ตั้ง WEB_BIND_HOST=$WEB_BIND_HOST · WEBHOOK_BIND_HOST=$WEBHOOK_BIND_HOST ใน .env เดิม"
else
    JWT_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    CSRF_SECRET_VAL="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    cat > "$PROJECT_DIR/.env" <<EOF
# สร้างโดย setup-server.sh — แก้ค่า LINE/GEMINI เพิ่มเองได้ภายหลัง
DB_HOST=localhost
DB_PORT=5432
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD

REDIS_HOST=$BIND_HOST
REDIS_PORT=6380
REDIS_SSL=True
REDIS_CERT=$PROJECT_DIR/cert/central/central.crt
REDIS_KEY=$PROJECT_DIR/cert/central/central.key
REDIS_CA=$PROJECT_DIR/cert/central/ca.crt
REDIS_USER=$REDIS_USER
REDIS_PASS=$REDIS_PASS

JWT_SECRET_KEY=$JWT_SECRET
JWT_EXPIRE_MIN=500
CSRF_SECRET=$CSRF_SECRET_VAL
COOKIE_SECURE=true
ALGORITHM=HS256

# IP ที่แต่ละ service เปิดรับ (systemd/_gen.sh อ่านค่านี้ไปใส่ --host ของ unit)
# แก้แล้วต้องรัน sudo systemd/install.sh ใหม่ ค่าถึงจะมีผล
WEB_BIND_HOST=$WEB_BIND_HOST
WEBHOOK_BIND_HOST=$WEBHOOK_BIND_HOST

LINE_CHANNEL_ACCESS_TOKEN=
LINE_CHANNEL_SECRET=
GEMINI_API_KEY=

# ค่าที่ถูกฝังลงชุดติดตั้ง agent (แก้ทีหลังได้จากหน้า System Settings)
AGENT_CENTRAL_HOST=$BIND_HOST
AGENT_CENTRAL_REDIS_PORT=6380
AGENT_REDIS_USERNAME=agent_node
AGENT_REDIS_PASSWORD=$AGENT_REDIS_PASS
EOF
    chmod 600 "$PROJECT_DIR/.env"
    ok "สร้าง .env (JWT/CSRF secret สุ่มให้อัตโนมัติ, สิทธิ์ 600)"
fi

# ---------------------------------------------------------------------------
# 6) PostgreSQL: role + database (idempotent)
#    ต่อในฐานะ superuser ได้ 2 แบบ:
#      - peer auth (default Ubuntu/Debian): sudo -u postgres  (ไม่ต้องรหัส)
#      - password auth: ตั้ง PG_SUPERUSER_PASSWORD (หรือปล่อยให้ถามเมื่อ peer ต่อไม่ได้)
#    override ได้: PG_SUPERUSER (default postgres), PG_HOST (default localhost)
# ---------------------------------------------------------------------------
log "PostgreSQL: role + database"
systemctl enable --now postgresql >/dev/null 2>&1 || true

PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
PG_SUPERUSER_PASSWORD="${PG_SUPERUSER_PASSWORD:-}"
PG_HOST="${PG_HOST:-localhost}"

# ไม่ได้ preset รหัส superuser -> ลอง peer auth ก่อน; ต่อไม่ได้ค่อยถามรหัส (รองรับ Postgres ที่บังคับ password)
if [ -z "$PG_SUPERUSER_PASSWORD" ] && ! sudo -u "$PG_SUPERUSER" psql -tAc "SELECT 1" >/dev/null 2>&1; then
    warn "ต่อ PostgreSQL แบบ peer (sudo -u $PG_SUPERUSER) ไม่ได้ — superuser น่าจะต้องใช้รหัส"
    ask_secret PG_SUPERUSER_PASSWORD "รหัสของ PostgreSQL superuser '$PG_SUPERUSER'"
fi

# helper: รัน psql/createdb ในฐานะ superuser — เลือก peer หรือ password อัตโนมัติ
pg_su_psql() {
    if [ -n "$PG_SUPERUSER_PASSWORD" ]; then
        PGPASSWORD="$PG_SUPERUSER_PASSWORD" psql -h "$PG_HOST" -U "$PG_SUPERUSER" -d postgres "$@"
    else
        sudo -u "$PG_SUPERUSER" psql "$@"
    fi
}
pg_su_createdb() {
    if [ -n "$PG_SUPERUSER_PASSWORD" ]; then
        PGPASSWORD="$PG_SUPERUSER_PASSWORD" createdb -h "$PG_HOST" -U "$PG_SUPERUSER" "$@"
    else
        sudo -u "$PG_SUPERUSER" createdb "$@"
    fi
}

if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'")" = "1" ]; then
    pg_su_psql -qc "ALTER ROLE \"$DB_USER\" WITH LOGIN PASSWORD '$DB_PASSWORD'" >/dev/null
    ok "role '$DB_USER' มีอยู่แล้ว (อัปเดตรหัสให้ตรง .env)"
else
    pg_su_psql -qc "CREATE ROLE \"$DB_USER\" WITH LOGIN PASSWORD '$DB_PASSWORD'" >/dev/null
    ok "สร้าง role '$DB_USER'"
fi
if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" = "1" ]; then
    ok "database '$DB_NAME' มีอยู่แล้ว"
else
    pg_su_createdb -O "$DB_USER" "$DB_NAME"
    ok "สร้าง database '$DB_NAME' (owner=$DB_USER) — ตาราง+admin ระบบสร้างเองตอน start แรก"
fi

# ---------------------------------------------------------------------------
# 7) cert — ออกให้เอง (Root CA -> central สำหรับ Redis mTLS -> dashboard สำหรับ HTTPS)
#    SAN ต้องมี BIND_HOST ไม่งั้น service ไม่ start และ agent ต่อ Redis ไม่ได้
#    ของเดิมที่มีอยู่ไม่ทับ ยกเว้น SAN ไม่ครอบ BIND_HOST (ย้ายไปเก็บแล้วออกใหม่) หรือสั่ง FORCE_CERT=1
# ---------------------------------------------------------------------------
log "cert (mTLS ของ Redis + HTTPS ของ dashboard)"
CERT_DIR="$PROJECT_DIR/cert/central"
mkdir -p "$CERT_DIR"

if printf '%s' "$BIND_HOST" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
    SAN_LINE="IP:$BIND_HOST,IP:127.0.0.1"
    ALT_NAMES="IP.1 = 127.0.0.1
IP.2 = $BIND_HOST"
else
    SAN_LINE="DNS:$BIND_HOST,IP:127.0.0.1"
    ALT_NAMES="IP.1 = 127.0.0.1
DNS.1 = $BIND_HOST"
fi

# cert เดิมที่ SAN ไม่มี BIND_HOST ใช้ไม่ได้เลย — เก็บเข้ากรุแล้วออกใหม่ (CA เดิมเก็บไว้เสมอ
# เพราะ cert ของ agent ที่ออกไปแล้วเซ็นด้วย CA ตัวนี้ ถ้าเปลี่ยน CA ต้องออก package ใหม่ทุกเครื่อง)
if [ -f "$CERT_DIR/central.crt" ]; then
    if [ "${FORCE_CERT:-0}" = "1" ] || ! openssl x509 -in "$CERT_DIR/central.crt" -noout -text 2>/dev/null | grep -q "$BIND_HOST"; then
        BK="$CERT_DIR/old-$(date +%Y%m%d%H%M%S)"
        mkdir -p "$BK"
        mv "$CERT_DIR"/central.crt "$CERT_DIR"/central.key "$BK/" 2>/dev/null || true
        mv "$CERT_DIR"/dashboard.crt "$CERT_DIR"/dashboard.key "$BK/" 2>/dev/null || true
        warn "cert เดิมไม่ตรงกับ $BIND_HOST — ย้ายไป $(basename "$BK") แล้วออกใหม่"
    fi
fi

if [ ! -f "$CERT_DIR/ca.crt" ] || [ ! -f "$CERT_DIR/ca.key" ]; then
    openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
        -out "$CERT_DIR/ca.crt" -subj "/CN=Security-Root-CA" 2>/dev/null
    ok "สร้าง Root CA"
else
    ok "ใช้ Root CA เดิม (cert ของ agent ที่ออกไปแล้วยังใช้ได้)"
fi

cat > "$CERT_DIR/central_openssl.cnf" <<EOF
[ req ]
default_bits = 2048
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[ dn ]
CN = Central_Server

[ req_ext ]
subjectAltName = @alt_names
extendedKeyUsage = serverAuth, clientAuth
keyUsage = digitalSignature, keyEncipherment

[ alt_names ]
$ALT_NAMES
EOF

if [ ! -f "$CERT_DIR/central.crt" ]; then
    openssl genrsa -out "$CERT_DIR/central.key" 2048 2>/dev/null
    openssl req -new -key "$CERT_DIR/central.key" -out "$CERT_DIR/central.csr" \
        -config "$CERT_DIR/central_openssl.cnf" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/central.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/central.crt" -days 3650 -sha256 \
        -extensions req_ext -extfile "$CERT_DIR/central_openssl.cnf" 2>/dev/null
    rm -f "$CERT_DIR/central.csr"
    ok "ออก central.crt (SAN $SAN_LINE)"
fi

printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\n' "$SAN_LINE" > "$CERT_DIR/dashboard_ext.cnf"

if [ ! -f "$CERT_DIR/dashboard.crt" ]; then
    openssl genrsa -out "$CERT_DIR/dashboard.key" 2048 2>/dev/null
    openssl req -new -key "$CERT_DIR/dashboard.key" -out "$CERT_DIR/dashboard.csr" \
        -subj "/CN=$BIND_HOST" 2>/dev/null
    openssl x509 -req -in "$CERT_DIR/dashboard.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
        -CAcreateserial -out "$CERT_DIR/dashboard.crt" -days 3650 -sha256 \
        -extfile "$CERT_DIR/dashboard_ext.cnf" 2>/dev/null
    rm -f "$CERT_DIR/dashboard.csr"
    ok "ออก dashboard.crt (SAN $SAN_LINE)"
fi

chmod 600 "$CERT_DIR"/*.key
CERT_OK=1
for f in ca.crt central.crt central.key dashboard.crt dashboard.key; do
    [ -f "$CERT_DIR/$f" ] || { err "ออก cert/central/$f ไม่สำเร็จ"; CERT_OK=0; }
done

# ---------------------------------------------------------------------------
# 7.1) redis/users.acl — เขียนรหัสจริงให้ตรงกับ .env และชุดติดตั้ง agent
#      ห้ามมีคอมเมนต์ในไฟล์นี้ (Redis 7 ไม่ start ถ้าบรรทัดไม่ขึ้นต้นด้วย user) — ดู redis/README.md
# ---------------------------------------------------------------------------
log "redis/users.acl"
ACL_FILE="$PROJECT_DIR/redis/users.acl"
mkdir -p "$PROJECT_DIR/redis"

# เขียนใหม่เมื่อ: ยังไม่มีไฟล์ / ยังเป็นรหัส placeholder / สั่ง FORCE_ACL=1
# ไฟล์ที่ตั้งรหัสจริงไว้แล้วไม่แตะ — กันรันซ้ำแล้วทับรหัสที่เปลี่ยนไปจากหน้าเว็บ
if [ ! -f "$ACL_FILE" ] || grep -q '>123 ' "$ACL_FILE" || [ "${FORCE_ACL:-0}" = "1" ]; then
    [ -f "$ACL_FILE" ] && cp -p "$ACL_FILE" "$ACL_FILE.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$ACL_FILE" <<EOF
user $REDIS_USER on >$REDIS_PASS +@all ~* &*
user agent_node on >$AGENT_REDIS_PASS -@all +ping +lpush +publish +subscribe ~raw_logs_queue resetchannels &global_commands &agent_commands:* &agent_status &agent_metrics
user default on >$AGENT_REDIS_PASS -@all +ping +info +select +rpush +lpush ~raw_logs_queue resetchannels
EOF
    chmod 600 "$ACL_FILE"
    ok "เขียน users.acl (3 บัญชี: $REDIS_USER / agent_node / default)"
else
    warn "users.acl ตั้งรหัสจริงไว้แล้ว — ไม่แตะ (บังคับเขียนใหม่ด้วย FORCE_ACL=1)"
fi

# ---------------------------------------------------------------------------
# 7.2) for_Agent/package/site.conf — ค่าที่ถูกฝังลง zip ของ agent ทุกครั้งที่สร้าง
# ---------------------------------------------------------------------------
log "ค่าชุดติดตั้ง agent (site.conf)"
SITE_CONF="$PROJECT_DIR/for_Agent/package/site.conf"
if [ ! -f "$SITE_CONF" ] || [ "${FORCE_SITE_CONF:-0}" = "1" ]; then
    cat > "$SITE_CONF" <<EOF
CENTRAL_HOST="$BIND_HOST"
CENTRAL_REDIS_PORT="6380"
REDIS_USERNAME="agent_node"
REDIS_PASSWORD="$AGENT_REDIS_PASS"
EOF
    chmod 600 "$SITE_CONF"
    ok "เขียน site.conf — zip ของ agent จะฝังค่านี้ให้อัตโนมัติ"
else
    warn "site.conf มีอยู่แล้ว — ไม่แตะ (บังคับเขียนใหม่ด้วย FORCE_SITE_CONF=1)"
fi

# ---------------------------------------------------------------------------
# 8) สิทธิ์ไฟล์ + data dir ของ Redis
# ---------------------------------------------------------------------------
log "ตั้งเจ้าของไฟล์เป็น $APP_USER:$APP_GROUP"
mkdir -p "$PROJECT_DIR/redis/data-redis"
chown -R "$APP_USER":"$APP_GROUP" "$PROJECT_DIR"
ok "chown เสร็จ"

# ---------------------------------------------------------------------------
# 9) systemd: generate units (ตาม user/path/host) แล้วติดตั้ง
# ---------------------------------------------------------------------------
log "สร้าง systemd units + redis-mtls.conf (parametric) แล้วติดตั้ง"
APP_USER="$APP_USER" APP_GROUP="$APP_GROUP" PROJECT_DIR="$PROJECT_DIR" BIND_HOST="$BIND_HOST" \
    WEB_BIND_HOST="$WEB_BIND_HOST" WEBHOOK_BIND_HOST="$WEBHOOK_BIND_HOST" \
    bash "$PROJECT_DIR/systemd/_gen.sh"

if [ "$CERT_OK" -eq 1 ]; then
    bash "$PROJECT_DIR/systemd/install.sh"
    STARTED=1
else
    warn "ยังไม่ start service เพราะ cert ไม่ครบ — copy unit เข้าที่แต่ไม่รัน"
    cp "$PROJECT_DIR"/systemd/securelog-*.service "$PROJECT_DIR"/systemd/securelog.target \
       "$PROJECT_DIR"/systemd/centralredis.service /etc/systemd/system/
    systemctl daemon-reload
    STARTED=0
fi

# ---------------------------------------------------------------------------
# สรุป
# ---------------------------------------------------------------------------
log "เสร็จแล้ว — สรุป"
echo "  ที่ตั้ง       : $PROJECT_DIR"
echo "  รันด้วย user  : $APP_USER"
echo "  ที่อยู่ central : $BIND_HOST  (agent ต่อ Redis ทาง $BIND_HOST:6380)"
echo "  dashboard     : bind $WEB_BIND_HOST:8000  ->  https://$BIND_HOST:8000"
echo "  LINE webhook  : bind $WEBHOOK_BIND_HOST:8080"
echo "  database      : $DB_NAME (owner $DB_USER)"
echo ""
if [ "$STARTED" -eq 1 ]; then
    ok "service ทำงานแล้ว — login ครั้งแรก admin/admin (ระบบบังคับเปลี่ยนรหัสทันที)"
    echo "  ดูสถานะ: systemctl --plain list-units 'securelog-*'"
else
    warn "ยังไม่รัน service เพราะ cert ไม่ครบ — ตรวจ $CERT_DIR แล้วสั่ง: sudo $PROJECT_DIR/systemd/install.sh"
fi

# รหัสที่สุ่มให้ไม่เคยถูกแสดงที่อื่นอีก — ต้องโชว์ตรงนี้ครั้งเดียวให้เก็บไว้
if [ -n "$GENERATED_PASSWORDS" ]; then
    echo ""
    warn "รหัสที่สุ่มให้ (เก็บไว้ให้ดี — ไม่แสดงอีก · อยู่ในไฟล์ .env และ redis/users.acl ด้วย):"
    printf '%s' "$GENERATED_PASSWORDS" | while IFS='=' read -r k v; do
        [ -n "$k" ] && echo "     $k = $v"
    done
fi

echo ""
echo "  ทำให้แล้วในรอบนี้: cert (SAN $BIND_HOST) · redis/users.acl 3 บัญชี · site.conf ของชุดติดตั้ง agent"
echo "  ที่เหลือทำในหน้าเว็บ: คีย์ LINE / Gemini และค่าอื่นของชุดติดตั้ง (System Settings)"
warn "ห้ามตั้ง 'user default off' ใน redis/users.acl — log จากทุก agent จะหยุดไหล (อ่าน redis/README.md)"
