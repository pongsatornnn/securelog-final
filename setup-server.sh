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
#   * เปิด port ที่ระบบใช้บน firewall (ufw/firewalld): 6380 Redis mTLS, 8000 dashboard, 8080 LINE webhook
#
# ตัวแปรบังคับเขียนทับของเดิม (ปกติไม่ต้องใช้ — ของที่ตั้งไว้แล้วสคริปต์จะไม่แตะ):
#   FORCE_CERT=1  ออก cert ใหม่ · FORCE_ACL=1 เขียน users.acl ใหม่ · FORCE_SITE_CONF=1 เขียน site.conf ใหม่
#   SKIP_FIREWALL=1 ไม่ต้องแตะ firewall เลย (ปกติสคริปต์เปิด port ให้ผ่าน ufw/firewalld)
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '  \033[1;31m[ERR]\033[0m %s\n' "$*" >&2; }

# ---------------------------------------------------------------------------
# run_step — รันขั้นที่กินเวลานาน (apt/venv/pip) พร้อมตัวหมุน + เวลาที่ใช้ไป
#
# ของเดิมสั่ง apt/pip แบบ -q แล้วเงียบไปเป็นนาที แยกไม่ออกว่ากำลังโหลดอยู่หรือค้างไปแล้ว
# ที่นี่จึงเก็บเอาต์พุตจริงลงไฟล์ log แล้วโชว์ตัวหมุนแทน — คำสั่งพังเมื่อไหร่ค่อยพ่น 20 บรรทัด
# ท้าย log ออกมาให้เห็นสาเหตุ แล้ว return code เดิมกลับไป (set -e หยุดสคริปต์ให้เหมือนเดิม)
#
# stdin ต่อ /dev/null: ถ้ามีอะไรแอบถามขึ้นมา จะได้ตายไปเลยพร้อมข้อความ ไม่ใช่ค้างหมุนไม่รู้จบ
# หลังตัวหมุนที่คนมองไม่เห็นว่ามันรอ input อยู่
# ไม่มี tty (รันผ่าน pipe/cron/CI) ก็ปล่อยเอาต์พุตไหลตามปกติ ไม่ต้องหมุนให้ log รก
# ---------------------------------------------------------------------------
STEP_LOG=""
run_step() {  # run_step "คำอธิบาย" cmd [args...]
    local desc="$1"; shift
    local rc=0 start="$SECONDS"

    if [ ! -t 1 ]; then
        printf '  ... %s\n' "$desc"
        "$@" </dev/null || rc=$?
        if [ "$rc" -ne 0 ]; then err "$desc failed (exit $rc)"; return "$rc"; fi
        ok "$desc ($((SECONDS - start))s)"
        return 0
    fi

    # สร้าง log ตอนใช้จริงครั้งแรก — ขั้นย้ายโปรเจกต์ด้านล่าง exec ทับตัวเอง ถ้าสร้างไว้ก่อนจะค้างทิ้ง
    if [ -z "$STEP_LOG" ]; then
        STEP_LOG="$(mktemp)"
        trap 'rm -f "$STEP_LOG"' EXIT
    fi

    local pid i=0 frames='|/-\'
    "$@" </dev/null >"$STEP_LOG" 2>&1 &
    pid=$!

    printf '\033[?25l'                 # ซ่อน cursor ไม่ให้กระพริบวิ่งตามตัวหมุน
    while kill -0 "$pid" 2>/dev/null; do
        printf '\r  \033[1;36m%s\033[0m %s \033[2m(%ds)\033[0m' \
            "${frames:i++%4:1}" "$desc" "$((SECONDS - start))"
        sleep 0.2
    done
    printf '\r\033[K\033[?25h'       # ล้างบรรทัดตัวหมุนแล้วคืน cursor

    wait "$pid" || rc=$?
    if [ "$rc" -ne 0 ]; then
        err "$desc failed (exit $rc) - last lines of the output:"
        tail -20 "$STEP_LOG" >&2
        return "$rc"
    fi
    ok "$desc ($((SECONDS - start))s)"
}

[ "$(id -u)" -eq 0 ] || { err "Must be run as root: sudo ./setup-server.sh"; exit 1; }

# ---------------------------------------------------------------------------
# 0) ที่ตั้งของระบบ = ที่ที่วางโปรเจกต์ไว้ตอนรัน (วางไว้ตรงไหนก็ติดตั้งตรงนั้น)
#    อยากให้ไปอยู่ที่อื่น สั่ง INSTALL_DIR=/path/ที่ต้องการ แล้วสคริปต์จะย้ายให้เอง
# ---------------------------------------------------------------------------
SELF="$(readlink -f "$0")"
SRC_DIR="$(cd "$(dirname "$SELF")" && pwd)"

INSTALL_DIR="$(readlink -f "${INSTALL_DIR:-$SRC_DIR}")"

if [ "$SRC_DIR" != "$INSTALL_DIR" ]; then
    log "Moving project to $INSTALL_DIR"
    mkdir -p "$INSTALL_DIR"
    # copy ทุกอย่างยกเว้น venv (สร้างใหม่ให้ตรงเครื่อง) และ .git (ไม่จำเป็นบน production)
    tar -C "$SRC_DIR" --exclude=venv --exclude=.git -cf - . | tar -C "$INSTALL_DIR" -xf -
    ok "Copied to $INSTALL_DIR - continuing from there"
    exec bash "$INSTALL_DIR/setup-server.sh" "$@"
fi

log "Installing at $INSTALL_DIR"

PROJECT_DIR="$INSTALL_DIR"
cd "$PROJECT_DIR"

# ตรวจว่าเป็น repo จริง (กันรันผิดที่)
for need in main/main.py systemd/_gen.sh systemd/_hosts.sh requirements.txt .env.example; do
    [ -e "$PROJECT_DIR/$need" ] || { err "$need not found in $PROJECT_DIR - project files are incomplete"; exit 1; }
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
    if [ -n "$cur" ]; then ok "$var = $cur (from env)"; return; fi
    if [ ! -t 0 ]; then err "No tty and $var was not preset"; exit 1; fi
    read -rp "  $prompt${def:+ [$def]}: " ans
    ans="${ans:-$def}"
    [ -n "$ans" ] || { err "$var must not be empty"; exit 1; }
    eval "$var=\$ans"
}
ask_secret() {  # ask_secret VAR "คำถาม"
    local var="$1" prompt="$2" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then ok "$var = ****** (from env)"; return; fi
    if [ ! -t 0 ]; then err "No tty and $var was not preset"; exit 1; fi
    read -rsp "  $prompt: " ans; echo
    [ -n "$ans" ] || { err "$var must not be empty"; exit 1; }
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
        valid_redis_pass "$cur" || { err "$var fails the rules (min 12 chars; allowed: A-Z a-z 0-9 _-.~@%+=:,/)"; exit 1; }
        ok "$var = ****** (from env)"
        return
    fi
    if [ ! -t 0 ]; then err "No tty and $var was not preset"; exit 1; fi

    while :; do
        read -rsp "  Redis password for $what (Enter = generate): " ans; echo
        if [ -z "$ans" ]; then
            ans="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
            GENERATED_PASSWORDS="$GENERATED_PASSWORDS$var=$ans"$'\n'
            ok "Password generated (shown at the end - save it)"
            break
        fi
        valid_redis_pass "$ans" && break
        err "Must be at least 12 chars; allowed: A-Z a-z 0-9 _-.~@%+=:,/ - try again"
    done
    eval "$var=\$ans"
}

log "Configuration (press Enter to accept the default)"
DETECTED_IP="$(detect_primary_ip)"
DEFAULT_USER="${SUDO_USER:-$(stat -c '%U' "$PROJECT_DIR")}"

ask        APP_USER   "User the services will run as (User=)" "$DEFAULT_USER"

# ---- IP 3 ช่อง ถามแยกกัน (ความหมายต่างกัน — อ่านหัวไฟล์ systemd/_hosts.sh) ----
# BIND_HOST เดาแทนไม่ได้: เครื่องหลาย interface มักมีเส้น NAT ที่ agent เรียกกลับมาไม่ได้ปนอยู่
# ถ้าเดาผิดจะได้ cert ที่ SAN ผิดและชุดติดตั้ง agent ที่ต่อไม่ติด — โหมดไม่ถามจึงต้องส่งมาเอง
if [ ! -t 0 ] && [ -z "${BIND_HOST:-}" ]; then
    err "No tty and BIND_HOST was not preset"; exit 1
fi
pick_bind_host BIND_HOST \
    "Address other machines use to reach this central server" "${DETECTED_IP:-}" 0 \
    "Goes into the cert SAN, REDIS_HOST and the agent installer - must be a real IP"
pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) - which IP to listen on" "$BIND_HOST" 1 \
    "One IP = other networks on this host cannot reach it; 0.0.0.0 = all interfaces"
pick_bind_host WEBHOOK_BIND_HOST \
    "LINE webhook (HTTP :8080) - which IP to listen on" "0.0.0.0" 1 \
    "LINE calls in through a tunnel; if the tunnel runs here, 127.0.0.1 is fine"

ask        DB_NAME    "PostgreSQL database name"        "security_central"
ask        DB_USER    "PostgreSQL user"                 "$APP_USER"
ask_secret DB_PASSWORD "PostgreSQL password for $DB_USER"
ask        REDIS_USER "Redis user for central"          "admin"
ask_redis_secret REDIS_PASS       "account $REDIS_USER (central uses it for Redis)"
ask_redis_secret AGENT_REDIS_PASS "agent accounts (agent_node + default)"

APP_GROUP="${APP_GROUP:-$APP_USER}"

# ---------------------------------------------------------------------------
# 2) OS packages
# ---------------------------------------------------------------------------
log "Installing OS packages (apt)"
export DEBIAN_FRONTEND=noninteractive
run_step "apt-get update" apt-get update -qq
run_step "Installing python3-venv / python3-pip / postgresql / redis-server / tar" \
    apt-get install -y -qq python3-venv python3-pip postgresql redis-server tar

# ปิด default redis (:6379) — เรารัน instance ของเราเองผ่าน centralredis (:6380 mTLS)
systemctl disable --now redis-server >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# 3) ผู้ใช้ระบบ
# ---------------------------------------------------------------------------
if id "$APP_USER" >/dev/null 2>&1; then
    ok "User '$APP_USER' already exists"
else
    warn "User '$APP_USER' does not exist - creating it as a system account"
    useradd --system --shell /usr/sbin/nologin --home-dir "$PROJECT_DIR" "$APP_USER"
    ok "Created user '$APP_USER'"
fi

# ---------------------------------------------------------------------------
# 4) venv + Python deps
# ---------------------------------------------------------------------------
log "Creating venv + installing requirements.txt"
if [ -x "$PROJECT_DIR/venv/bin/python" ]; then
    ok "venv already exists"
else
    run_step "Creating venv" python3 -m venv "$PROJECT_DIR/venv"
fi
run_step "Upgrading pip" "$PROJECT_DIR/venv/bin/pip" install -q --upgrade pip
run_step "Installing requirements.txt (this is the slow one)" \
    "$PROJECT_DIR/venv/bin/pip" install -q -r "$PROJECT_DIR/requirements.txt"

# ---------------------------------------------------------------------------
# 5) .env (สร้างใหม่ถ้ายังไม่มี — ไม่ทับของเดิม)
# ---------------------------------------------------------------------------
log ".env file"
if [ -f "$PROJECT_DIR/.env" ]; then
    warn ".env already exists - left untouched (delete it and re-run to recreate)"

    # .env เดิมคือแหล่งความจริงของรหัสที่ service ใช้อยู่ — ต้องยึดค่าจากไฟล์นี้ ไม่ใช่ค่าที่เพิ่งกรอก
    # ไม่งั้น users.acl ที่เขียนในขั้นถัดไปจะไม่ตรงกับ .env แล้ว central ต่อ Redis ไม่ได้ทันที
    ENV_REDIS_PASS="$(grep -E '^REDIS_PASS=' "$PROJECT_DIR/.env" | head -1 | cut -d= -f2- || true)"
    if [ -n "$ENV_REDIS_PASS" ] && [ "$ENV_REDIS_PASS" != "$REDIS_PASS" ]; then
        REDIS_PASS="$ENV_REDIS_PASS"
        warn "Keeping the $REDIS_USER password from the existing .env (not the one just entered) - users.acl will match .env"
    fi

    ENV_AGENT_PASS="$(grep -E '^AGENT_REDIS_PASSWORD=' "$PROJECT_DIR/.env" | head -1 | cut -d= -f2- || true)"
    if [ -n "$ENV_AGENT_PASS" ]; then
        if [ "$ENV_AGENT_PASS" != "$AGENT_REDIS_PASS" ]; then
            AGENT_REDIS_PASS="$ENV_AGENT_PASS"
            warn "Keeping the agent password from the existing .env as well"
        fi
    else
        # .env เก่าที่ยังไม่มีคีย์กลุ่ม agent — เติมให้ ไม่งั้นชุดติดตั้งกับ users.acl จะคนละรหัสกัน
        {
            echo ""
            echo "# Values embedded into the agent installer (added by setup-server.sh)"
            echo "AGENT_CENTRAL_HOST=$BIND_HOST"
            echo "AGENT_CENTRAL_REDIS_PORT=6380"
            echo "AGENT_REDIS_USERNAME=agent_node"
            echo "AGENT_REDIS_PASSWORD=$AGENT_REDIS_PASS"
        } >> "$PROJECT_DIR/.env"
        ok "Added the agent settings to the existing .env"
    fi

    # ค่า bind ยึดตามที่เพิ่งตอบ (ต่างจากรหัสผ่านที่ต้องยึด .env เดิม) — ถ้าปล่อยให้ต่างกัน
    # unit จะ bind อย่างหนึ่งแต่ .env บอกอีกอย่าง ไล่ปัญหาทีหลังไม่รู้ว่าอันไหนจริง
    env_set WEB_BIND_HOST     "$WEB_BIND_HOST"     "$PROJECT_DIR/.env"
    env_set WEBHOOK_BIND_HOST "$WEBHOOK_BIND_HOST" "$PROJECT_DIR/.env"
    ok "Set WEB_BIND_HOST=$WEB_BIND_HOST and WEBHOOK_BIND_HOST=$WEBHOOK_BIND_HOST in the existing .env"
else
    JWT_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    CSRF_SECRET_VAL="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    cat > "$PROJECT_DIR/.env" <<EOF
# Generated by setup-server.sh - fill in the LINE/GEMINI values later if needed
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

# IP each service listens on (systemd/_gen.sh reads these into the unit --host)
# After editing, re-run sudo systemd/install.sh for the change to take effect
WEB_BIND_HOST=$WEB_BIND_HOST
WEBHOOK_BIND_HOST=$WEBHOOK_BIND_HOST

LINE_CHANNEL_ACCESS_TOKEN=
LINE_CHANNEL_SECRET=
GEMINI_API_KEY=

# Values embedded into the agent installer (editable later on the System Settings page)
AGENT_CENTRAL_HOST=$BIND_HOST
AGENT_CENTRAL_REDIS_PORT=6380
AGENT_REDIS_USERNAME=agent_node
AGENT_REDIS_PASSWORD=$AGENT_REDIS_PASS
EOF
    chmod 600 "$PROJECT_DIR/.env"
    ok "Created .env (JWT/CSRF secrets generated automatically, mode 600)"
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
    warn "Peer auth to PostgreSQL (sudo -u $PG_SUPERUSER) failed - the superuser probably needs a password"
    ask_secret PG_SUPERUSER_PASSWORD "Password for PostgreSQL superuser '$PG_SUPERUSER'"
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
    ok "Role '$DB_USER' already exists (password updated to match .env)"
else
    pg_su_psql -qc "CREATE ROLE \"$DB_USER\" WITH LOGIN PASSWORD '$DB_PASSWORD'" >/dev/null
    ok "Created role '$DB_USER'"
fi
if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" = "1" ]; then
    ok "Database '$DB_NAME' already exists"
else
    pg_su_createdb -O "$DB_USER" "$DB_NAME"
    ok "Created database '$DB_NAME' (owner=$DB_USER) - tables and the admin account are created on first start"
fi

# ---------------------------------------------------------------------------
# 7) cert — ออกให้เอง (Root CA -> central สำหรับ Redis mTLS -> dashboard สำหรับ HTTPS)
#    SAN ต้องมี BIND_HOST ไม่งั้น service ไม่ start และ agent ต่อ Redis ไม่ได้
#    ของเดิมที่มีอยู่ไม่ทับ ยกเว้น SAN ไม่ครอบ BIND_HOST (ย้ายไปเก็บแล้วออกใหม่) หรือสั่ง FORCE_CERT=1
# ---------------------------------------------------------------------------
log "Certificates (Redis mTLS + dashboard HTTPS)"
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
        warn "Existing cert does not match $BIND_HOST - moved to $(basename "$BK") and reissuing"
    fi
fi

if [ ! -f "$CERT_DIR/ca.crt" ] || [ ! -f "$CERT_DIR/ca.key" ]; then
    openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
    openssl req -x509 -new -nodes -key "$CERT_DIR/ca.key" -sha256 -days 3650 \
        -out "$CERT_DIR/ca.crt" -subj "/CN=Security-Root-CA" 2>/dev/null
    ok "Created Root CA"
else
    ok "Reusing the existing Root CA (certs already issued to agents stay valid)"
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
    ok "Issued central.crt (SAN $SAN_LINE)"
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
    ok "Issued dashboard.crt (SAN $SAN_LINE)"
fi

chmod 600 "$CERT_DIR"/*.key
CERT_OK=1
for f in ca.crt central.crt central.key dashboard.crt dashboard.key; do
    [ -f "$CERT_DIR/$f" ] || { err "Failed to issue cert/central/$f"; CERT_OK=0; }
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
    ok "Wrote users.acl (3 accounts: $REDIS_USER / agent_node / default)"
else
    warn "users.acl already holds real passwords - left untouched (force a rewrite with FORCE_ACL=1)"
fi

# ---------------------------------------------------------------------------
# 7.2) for_Agent/package/site.conf — ค่าที่ถูกฝังลง zip ของ agent ทุกครั้งที่สร้าง
# ---------------------------------------------------------------------------
log "Agent installer settings (site.conf)"
SITE_CONF="$PROJECT_DIR/for_Agent/package/site.conf"
if [ ! -f "$SITE_CONF" ] || [ "${FORCE_SITE_CONF:-0}" = "1" ]; then
    cat > "$SITE_CONF" <<EOF
CENTRAL_HOST="$BIND_HOST"
CENTRAL_REDIS_PORT="6380"
REDIS_USERNAME="agent_node"
REDIS_PASSWORD="$AGENT_REDIS_PASS"
EOF
    chmod 600 "$SITE_CONF"
    ok "Wrote site.conf - agent zips embed these values automatically"
else
    warn "site.conf already exists - left untouched (force a rewrite with FORCE_SITE_CONF=1)"
fi

# ---------------------------------------------------------------------------
# 8) สิทธิ์ไฟล์ + data dir ของ Redis
# ---------------------------------------------------------------------------
log "Setting file ownership to $APP_USER:$APP_GROUP"
mkdir -p "$PROJECT_DIR/redis/data-redis"
chown -R "$APP_USER":"$APP_GROUP" "$PROJECT_DIR"
ok "chown done"

# ---------------------------------------------------------------------------
# 9) systemd: generate units (ตาม user/path/host) แล้วติดตั้ง
# ---------------------------------------------------------------------------
log "Generating systemd units + redis-mtls.conf, then installing them"
APP_USER="$APP_USER" APP_GROUP="$APP_GROUP" PROJECT_DIR="$PROJECT_DIR" BIND_HOST="$BIND_HOST" \
    WEB_BIND_HOST="$WEB_BIND_HOST" WEBHOOK_BIND_HOST="$WEBHOOK_BIND_HOST" \
    bash "$PROJECT_DIR/systemd/_gen.sh"

if [ "$CERT_OK" -eq 1 ]; then
    bash "$PROJECT_DIR/systemd/install.sh"
    STARTED=1
else
    warn "Not starting services because certs are incomplete - units copied but not started"
    cp "$PROJECT_DIR"/systemd/securelog-*.service "$PROJECT_DIR"/systemd/securelog.target \
       "$PROJECT_DIR"/systemd/centralredis.service /etc/systemd/system/
    systemctl daemon-reload
    STARTED=0
fi

# ---------------------------------------------------------------------------
# 10) Firewall — เปิดเฉพาะ port ที่ระบบนี้ใช้จริง
#       6380/tcp  Redis mTLS   เปิดเสมอ — ไม่เปิด agent ส่ง log เข้ามาไม่ได้เลย
#       8000/tcp  dashboard    เปิดเมื่อ WEB_BIND_HOST ไม่ใช่ 127.0.0.1
#       8080/tcp  LINE webhook เปิดเมื่อ WEBHOOK_BIND_HOST ไม่ใช่ 127.0.0.1
#     PostgreSQL 5432 ไม่เปิด — ต่อผ่าน localhost อย่างเดียว
#
#     ไม่สั่ง `ufw enable` ให้เอง: คนติดตั้งส่วนใหญ่ ssh เข้ามาทำ พอ ufw ขึ้นมาพร้อม
#     default deny incoming มันจะตัด ssh ของตัวเองทิ้งกลางคัน เข้าเครื่องไม่ได้อีก
#     rule ที่เพิ่มไว้ตอน ufw ยัง inactive ไม่หายไปไหน enable ทีหลังมีผลทันที
#     ข้ามทั้งขั้น: SKIP_FIREWALL=1
# ---------------------------------------------------------------------------
log "Firewall (opening the ports this system serves)"

FW_KIND="none"
if [ "${SKIP_FIREWALL:-0}" = "1" ]; then
    FW_KIND="skip"
elif command -v ufw >/dev/null 2>&1; then
    FW_KIND="ufw"
elif command -v firewall-cmd >/dev/null 2>&1; then
    FW_KIND="firewalld"
fi

FW_OPENED=""
# เปิดไม่สำเร็จแค่เตือน ไม่ล้มสคริปต์ — ของอื่นติดตั้งครบแล้ว และ firewall เครื่องนั้น
# อาจเปิดทางไว้อยู่แล้วด้วยวิธีอื่น เอาไปเช็คเองได้จากบรรทัดที่เตือน
fw_allow() {  # fw_allow PORT "คำอธิบาย"
    local port="$1" what="$2"
    case "$FW_KIND" in
        ufw)
            # ufw ก่อน 0.35 ไม่รู้จัก comment — ตกลงมาสั่งแบบไม่มี comment ให้
            ufw allow "$port"/tcp comment "SecureLog $what" >/dev/null 2>&1 \
                || ufw allow "$port"/tcp >/dev/null 2>&1 \
                || { warn "ufw could not open $port/tcp ($what) - open it yourself"; return 0; }
            ;;
        firewalld)
            firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1 \
                || { warn "firewalld could not open $port/tcp ($what) - open it yourself"; return 0; }
            ;;
        *) return 0 ;;
    esac
    ok "$port/tcp open - $what"
    FW_OPENED="$FW_OPENED $port"
}

case "$FW_KIND" in
    skip)
        warn "SKIP_FIREWALL=1 - firewall left alone (open tcp 6380/8000/8080 yourself if one sits in front)"
        FW_SUMMARY="skipped (SKIP_FIREWALL=1)"
        ;;
    none)
        warn "Neither ufw nor firewalld found on this machine - nothing to open"
        warn "If something else filters traffic, open tcp 6380 (agents), 8000 (dashboard), 8080 (LINE webhook)"
        FW_SUMMARY="no ufw/firewalld - nothing opened"
        ;;
    *)
        fw_allow 6380 "Redis mTLS (agents send logs in)"

        if [ "$WEB_BIND_HOST" = "127.0.0.1" ]; then
            warn "dashboard binds 127.0.0.1 - 8000/tcp left closed (local access only)"
        else
            fw_allow 8000 "dashboard HTTPS"
        fi

        if [ "$WEBHOOK_BIND_HOST" = "127.0.0.1" ]; then
            warn "LINE webhook binds 127.0.0.1 - 8080/tcp left closed (the tunnel runs on this host)"
        else
            fw_allow 8080 "LINE webhook"
        fi

        FW_SUMMARY="$FW_KIND: opened${FW_OPENED:- (nothing)}"

        if [ "$FW_KIND" = "firewalld" ]; then
            firewall-cmd --reload >/dev/null 2>&1 \
                || warn "firewall-cmd --reload failed - run it yourself for the rules to take effect"
            if ! systemctl is-active --quiet firewalld; then
                warn "firewalld is installed but not running - the rules are saved and apply once it starts"
                FW_SUMMARY="$FW_SUMMARY (firewalld not running)"
            fi
        elif ! ufw status 2>/dev/null | grep -q "Status: active"; then
            warn "ufw is installed but inactive - the rules are saved, they apply once you run:"
            warn "  sudo ufw allow OpenSSH   <- do this FIRST or you lock yourself out"
            warn "  sudo ufw enable"
            FW_SUMMARY="$FW_SUMMARY (ufw still inactive)"
        fi
        ;;
esac

# ---------------------------------------------------------------------------
# สรุป
# ---------------------------------------------------------------------------
log "Done - summary"
echo "  Location      : $PROJECT_DIR"
echo "  Runs as user  : $APP_USER"
echo "  Central addr  : $BIND_HOST  (agents reach Redis at $BIND_HOST:6380)"
echo "  dashboard     : bind $WEB_BIND_HOST:8000  ->  https://$BIND_HOST:8000"
echo "  LINE webhook  : bind $WEBHOOK_BIND_HOST:8080"
echo "  database      : $DB_NAME (owner $DB_USER)"
echo "  firewall      : $FW_SUMMARY"
echo ""
if [ "$STARTED" -eq 1 ]; then
    ok "Services are running - first login is admin/admin (you must change it immediately)"
    echo "  Check status: systemctl --plain list-units 'securelog-*'"
else
    warn "Services not started because certs are incomplete - check $CERT_DIR then run: sudo $PROJECT_DIR/systemd/install.sh"
fi

# รหัสที่สุ่มให้ไม่เคยถูกแสดงที่อื่นอีก — ต้องโชว์ตรงนี้ครั้งเดียวให้เก็บไว้
if [ -n "$GENERATED_PASSWORDS" ]; then
    echo ""
    warn "Generated passwords (save them - not shown again; also stored in .env and redis/users.acl):"
    printf '%s' "$GENERATED_PASSWORDS" | while IFS='=' read -r k v; do
        [ -n "$k" ] && echo "     $k = $v"
    done
fi

echo ""
echo "  Done this run: certs (SAN $BIND_HOST), redis/users.acl 3 accounts, site.conf for the agent installer"
echo "  Remaining, in the web UI: LINE / Gemini keys and the other agent installer values (System Settings)"
warn "Never set 'user default off' in redis/users.acl - logs from every agent stop flowing"
