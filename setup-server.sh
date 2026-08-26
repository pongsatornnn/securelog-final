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
# - รันซ้ำได้ (idempotent): apt/venv/DB/systemd ข้ามของที่มีอยู่แล้ว · ค่าที่เคยตั้งไว้ถูกอ่านกลับมา
#   จาก .env เป็นค่าตั้งต้น กด Enter รัว ๆ = ไม่มีอะไรเปลี่ยน (คีย์ LINE/Gemini/JWT/CSRF ไม่ถูกแตะ)
# - ★ ย้าย IP ด้วยการรันซ้ำได้เลย: ตอบ IP ใหม่ในช่อง "Address other machines use to reach this
#   central server" แล้วสคริปต์ไล่แก้ให้ครบทุกที่ที่ IP เดิมฝังอยู่ — SAN ในใบรับรอง (ออกใหม่ด้วย
#   CA เดิม agent ที่ลงไปแล้วจึงยังเชื่อถือใบใหม่), REDIS_HOST/AGENT_CENTRAL_HOST ใน .env,
#   site.conf, แถว agent_central_host ในตาราง app_settings และ unit ของ systemd + restart ให้
#   ⚠️ agent ที่ติดตั้งไปแล้วยังชี้ IP เดิม ต้องออก package ใหม่ไปลงทับ (หรือแก้ site.conf บนเครื่องนั้น)
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
#   SKIP_DB_CHECK=1 ข้ามการทดสอบล็อกอิน PostgreSQL ด้วยรหัสที่กรอก (ปกติทดสอบให้ก่อนไปต่อ)
#   ALLOW_FOREIGN_DB=1 ยอมใช้ฐานข้อมูลเดิมที่ไม่มีตารางของระบบนี้ (ปกติหยุด กันไปสร้างตารางทับฐานของแอปอื่น)
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

# ตัวช่วยเลือก IP ที่จะ bind + env_get/env_set (ใช้ชุดเดียวกับ systemd/_gen.sh จะได้ตรงกันทั้งสองทาง)
# shellcheck source=systemd/_hosts.sh
source "$PROJECT_DIR/systemd/_hosts.sh"

# ---------------------------------------------------------------------------
# 0.1) ของที่ "ติดตั้งไว้แล้ว" บนเครื่องนี้ = ความจริงของระบบที่รันอยู่
#
# รันซ้ำต้องต่อจากของเดิม ไม่ใช่เริ่มใหม่ — ค่าที่เคยตั้งจึงถูกอ่านกลับมาจาก .env ตั้งแต่ก่อนถาม
# คนติดตั้งไม่ต้องจำรหัสเดิมมากรอกซ้ำ และไม่มีทางที่ postgres/redis/cert จะไปคนละทางกับ .env
# (ของเดิมถามใหม่หมดทุกรอบแล้วค่อยทิ้งคำตอบทีหลัง — รหัส DB ที่กรอกใหม่จึงไป ALTER ROLE จริง
#  แต่ .env ยังเป็นรหัสเก่า service ตายยกแผงด้วย password authentication failed)
#
# ใครชนะเมื่อค่าไม่ตรงกัน:
#   DB_*                 ค่าที่ preset มาทาง env ชนะ -> เปลี่ยนรหัส DB ด้วย
#                        `sudo DB_PASSWORD=ใหม่ ./setup-server.sh` (ALTER ROLE + เขียน .env ให้ตรงกัน)
#   REDIS_PASS /         ค่าใน .env ชนะเสมอ — รหัสจริงอยู่ใน users.acl ที่ผูกกับ .env อยู่แล้ว และ
#   AGENT_REDIS_PASS     เปลี่ยนจากหน้าเว็บได้ (System Settings) สคริปต์จึงห้ามไปทับ
#   IP ทั้ง 3 ช่อง       ถามใหม่ทุกครั้งโดยใช้ค่าปัจจุบันเป็น default -> ตอบค่าใหม่ = ย้าย IP ทั้งระบบ
# ---------------------------------------------------------------------------
ENV_FILE="$PROJECT_DIR/.env"
ENV_EXISTED=0
[ -f "$ENV_FILE" ] && ENV_EXISTED=1

FROM_ENV_FILE=" "   # รายชื่อตัวแปรที่ค่ามาจาก .env เดิม (ไว้บอกให้ถูกว่าค่ามาจากไหน)

preload_env() {  # preload_env VAR KEY [file_wins]
    local var="$1" key="$2" file_wins="${3:-0}" cur val
    [ "$ENV_EXISTED" = "1" ] || return 0
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    val="$(env_get "$key" "$ENV_FILE")"
    [ -n "$val" ] || return 0

    if [ -n "$cur" ]; then
        [ "$file_wins" = "1" ] || return 0            # preset ทาง env ชนะ
        [ "$cur" = "$val" ] && return 0
        warn "$var from the command line differs from the existing .env - keeping the .env value"
        warn "  (change it from the web UI instead: System Settings - it rewrites users.acl and .env together)"
    fi
    eval "$var=\$val"
    FROM_ENV_FILE="$FROM_ENV_FILE$var "
}

value_source() { case "$FROM_ENV_FILE" in *" $1 "*) printf '.env' ;; *) printf 'env' ;; esac; }

preload_env DB_NAME          DB_NAME
preload_env DB_USER          DB_USER
preload_env DB_PASSWORD      DB_PASSWORD
preload_env DB_HOST          DB_HOST
preload_env DB_PORT          DB_PORT
preload_env REDIS_USER       REDIS_USER
preload_env REDIS_PASS       REDIS_PASS           1
preload_env AGENT_REDIS_PASS AGENT_REDIS_PASSWORD 1

# ที่อยู่ของ central ที่ระบบใช้อยู่ "ตอนนี้" — ไว้เทียบว่ารอบนี้ IP เปลี่ยนไหม
CURRENT_BIND_HOST="$(env_get REDIS_HOST "$ENV_FILE")"

# postgres อยู่ไหน: DB_HOST คือค่าที่แอปใช้ต่อ (ลง .env) · PG_HOST คือที่ที่สคริปต์ต่อไปสร้าง role/db
# แยกกันได้ แต่ค่าตั้งต้นอิงกัน — เครื่องที่ DB อยู่ host อื่น ตั้ง PG_HOST มาแล้ว .env จะตามให้เอง
PG_HOST="${PG_HOST:-${DB_HOST:-localhost}}"
DB_HOST="${DB_HOST:-$PG_HOST}"
DB_PORT="${DB_PORT:-5432}"

# ---------------------------------------------------------------------------
# 1) เก็บค่า config (ถามถ้ายังไม่ได้ preset ผ่าน env)
# ---------------------------------------------------------------------------
ask() {  # ask VAR "คำถาม" "ค่า default"
    local var="$1" prompt="$2" def="${3:-}" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"      # ถ้า preset มาทาง env แล้วใช้เลย
    if [ -n "$cur" ]; then ok "$var = $cur (from $(value_source "$var"))"; return; fi
    # ไม่มี tty (รันจากสคริปต์/cron) แต่มีค่าตั้งต้นที่เชื่อได้ = ใช้ค่านั้นเงียบ ๆ เหมือน pick_bind_host
    # ไม่มีให้ใช้เลยค่อยตาย — รันซ้ำแบบไม่ถามจะได้ไม่ติดตรงคำถามที่ตอบแทนได้อยู่แล้ว
    if [ ! -t 0 ]; then
        [ -n "$def" ] || { err "No tty and $var was not preset"; exit 1; }
        eval "$var=\$def"
        ok "$var = $def (default, no tty)"
        return
    fi
    read -rp "  $prompt${def:+ [$def]}: " ans
    ans="${ans:-$def}"
    [ -n "$ans" ] || { err "$var must not be empty"; exit 1; }
    eval "$var=\$ans"
}
ask_secret() {  # ask_secret VAR "คำถาม"
    local var="$1" prompt="$2" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then ok "$var = ****** (from $(value_source "$var"))"; return; fi
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
        ok "$var = ****** (from $(value_source "$var"))"
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

# user ที่ unit ซึ่งติดตั้งอยู่ตอนนี้รันด้วย — เป็นค่าตั้งต้นที่ "จริง" กว่า SUDO_USER
# (รันซ้ำด้วยบัญชี sudo คนละคนแล้วเผลอเปลี่ยน User= ของทุก service + chown โปรเจกต์ทั้งก้อน)
installed_app_user() {
    local unit="/etc/systemd/system/securelog-web.service"
    [ -f "$unit" ] || return 0
    sed -nE 's/^User=([^[:space:]]+).*/\1/p' "$unit" 2>/dev/null | head -1 || true
}

log "Configuration (press Enter to accept the default)"
DETECTED_IP="$(detect_primary_ip)"
DEFAULT_USER="$(installed_app_user)"
[ -n "$DEFAULT_USER" ] || DEFAULT_USER="${SUDO_USER:-$(stat -c '%U' "$PROJECT_DIR")}"

ask        APP_USER   "User the services will run as (User=)" "$DEFAULT_USER"

# ---- IP 3 ช่อง ถามแยกกัน (ความหมายต่างกัน — อ่านหัวไฟล์ systemd/_hosts.sh) ----
# BIND_HOST เดาแทนไม่ได้: เครื่องหลาย interface มักมีเส้น NAT ที่ agent เรียกกลับมาไม่ได้ปนอยู่
# ถ้าเดาผิดจะได้ cert ที่ SAN ผิดและชุดติดตั้ง agent ที่ต่อไม่ติด — โหมดไม่ถามจึงต้องส่งมาเอง
# ค่าตั้งต้นของทั้ง 3 ช่อง = ค่าที่ระบบ "ใช้อยู่ตอนนี้" (เพิ่งติดตั้งใหม่ค่อยใช้ IP ที่ตรวจเจอ)
# กด Enter ผ่านทุกช่อง = ไม่มีอะไรเปลี่ยน · ตอบค่าใหม่ = ย้ายทั้งระบบไป IP นั้นให้ครบทุกไฟล์
if [ ! -t 0 ] && [ -z "${BIND_HOST:-}" ] && [ -z "$CURRENT_BIND_HOST" ]; then
    err "No tty and BIND_HOST was not preset"; exit 1
fi
WEB_DEFAULT="$(env_get WEB_BIND_HOST "$ENV_FILE")"
HOOK_DEFAULT="$(env_get WEBHOOK_BIND_HOST "$ENV_FILE")"

pick_bind_host BIND_HOST \
    "Address other machines use to reach this central server" \
    "${CURRENT_BIND_HOST:-${DETECTED_IP:-}}" 0 \
    "Goes into the cert SAN, REDIS_HOST and the agent installer - must be a real IP"
pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) - which IP to listen on" "${WEB_DEFAULT:-$BIND_HOST}" 1 \
    "One IP = other networks on this host cannot reach it; 0.0.0.0 = all interfaces"
pick_bind_host WEBHOOK_BIND_HOST \
    "LINE webhook (HTTP :8080) - which IP to listen on" "${HOOK_DEFAULT:-0.0.0.0}" 1 \
    "LINE calls in through a tunnel; if the tunnel runs here, 127.0.0.1 is fine"

# ★ IP ของ central เปลี่ยนจากรอบก่อน = ต้องไล่แก้ให้ครบทุกที่ที่ IP เดิมฝังอยู่ ไม่งั้นระบบจะ
#   ครึ่ง ๆ กลาง ๆ แบบไล่ยาก (เว็บเปิดได้ แต่ agent ต่อ Redis ไม่ติด / package ที่ออกใหม่ยังชี้ IP เก่า)
IP_CHANGED=0
if [ -n "$CURRENT_BIND_HOST" ] && [ "$CURRENT_BIND_HOST" != "$BIND_HOST" ]; then
    IP_CHANGED=1
    warn "Central address changed: $CURRENT_BIND_HOST -> $BIND_HOST"
    warn "  cert SAN, .env, site.conf, the agent_central_host row in the DB and the units will all follow"
fi

ask        DB_NAME    "PostgreSQL database name"        "security_central"
ask        DB_USER    "PostgreSQL user"                 "$APP_USER"
ask_secret DB_PASSWORD "PostgreSQL password for $DB_USER"

# ชื่อ role/database ถูกเอาไปต่อเป็นคำสั่ง SQL ตรง ๆ — จำกัดให้เป็น identifier ปกติของ postgres
# (กันทั้งพิมพ์อักขระที่ psql ตีความเป็นอย่างอื่น และกันค่าที่แทรกคำสั่ง SQL เข้ามาได้)
valid_pg_ident() { printf '%s' "$1" | grep -qE '^[A-Za-z_][A-Za-z0-9_]{0,62}$'; }
for _v in DB_NAME DB_USER; do
    valid_pg_ident "${!_v}" || {
        err "$_v='${!_v}' is not a valid PostgreSQL name (a-z A-Z 0-9 _ only, must not start with a digit)"
        exit 1
    }
done

# .env เป็นไฟล์ KEY=VALUE ที่ python-dotenv อ่าน — อักขระพวกนี้ทำให้ค่าที่อ่านได้ไม่ตรงกับที่กรอก
case "$DB_PASSWORD" in
    *[\'\"\#\$\`\\]*|*" "*)
        warn "DB_PASSWORD contains one of  ' \" # \$ \` \\  or a space - .env may read it back differently"
        warn "  If the services cannot log in to PostgreSQL, use a password without those characters"
        ;;
esac

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
# 5) PostgreSQL: role + database (idempotent)
#    ต่อในฐานะ superuser ได้ 2 แบบ:
#      - peer auth (default Ubuntu/Debian): sudo -u postgres  (ไม่ต้องรหัส)
#      - password auth: ตั้ง PG_SUPERUSER_PASSWORD (หรือปล่อยให้ถามเมื่อ peer ต่อไม่ได้)
#    override ได้: PG_SUPERUSER (default postgres), PG_HOST (default localhost)
#
#    เครื่องที่ "มี PostgreSQL + ฐานข้อมูลอยู่ก่อนแล้ว" คือเคสที่พลาดง่ายที่สุด ขั้นนี้จึงตรวจให้ครบ:
#      - ฐานที่มีอยู่เป็นของระบบนี้จริงไหม (ไม่ใช่ก็หยุด ไม่ไปสร้างตารางทับฐานของแอปอื่น)
#      - เจ้าของฐาน/ตาราง ตรงกับ role ที่กรอกไหม (ไม่ตรง = ตอน start ตาย permission denied)
#      - ท้ายสุดลองล็อกอินด้วยรหัสที่กรอกจริง ๆ ทาง TCP แบบเดียวกับที่แอปต่อ
#
#    ทำก่อนเขียน .env (ขั้น 6) โดยตั้งใจ — DB ล้มกลางทางแล้ว .env ต้องยังเป็นของเดิมทุกตัวอักษร
#    ไม่ใช่ถูกแก้ไปแล้วครึ่งทางจนไม่รู้ว่าเครื่องอยู่สถานะไหน
# ---------------------------------------------------------------------------
log "PostgreSQL: role + database"
systemctl enable --now postgresql >/dev/null 2>&1 || true

PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
PG_SUPERUSER_PASSWORD="${PG_SUPERUSER_PASSWORD:-}"

# peer auth (sudo -u postgres) ใช้ได้เฉพาะกับ postgres ที่อยู่บนเครื่องนี้เท่านั้น
# ตั้ง PG_HOST เป็นเครื่องอื่นแล้วยังใช้ peer = ไปสร้าง role/db ลง postgres ของ "เครื่องนี้"
# ทั้งที่ .env ชี้ไปอีกเครื่อง — เงียบสนิทจนกว่า service จะ start ไม่ขึ้น
PG_LOCAL=0
case "$PG_HOST" in localhost|127.0.0.1|::1|"") PG_LOCAL=1 ;; esac

# helper: รัน psql/createdb ในฐานะ superuser — เลือก peer (local + ไม่มีรหัส) หรือ TCP+password
pg_su_psql() {
    if [ "$PG_LOCAL" = "1" ] && [ -z "$PG_SUPERUSER_PASSWORD" ]; then
        sudo -u "$PG_SUPERUSER" psql -p "$DB_PORT" "$@"
    else
        PGPASSWORD="$PG_SUPERUSER_PASSWORD" psql -h "$PG_HOST" -p "$DB_PORT" -U "$PG_SUPERUSER" -d postgres "$@"
    fi
}
# ตัวเดียวกันแต่ต่อเข้า "ฐานของระบบ" — ใช้ตรวจตาราง/ให้สิทธิ์ข้างในฐานนั้น (ต่อ postgres ทำไม่ได้)
pg_su_psql_db() {
    if [ "$PG_LOCAL" = "1" ] && [ -z "$PG_SUPERUSER_PASSWORD" ]; then
        sudo -u "$PG_SUPERUSER" psql -p "$DB_PORT" -d "$DB_NAME" "$@"
    else
        PGPASSWORD="$PG_SUPERUSER_PASSWORD" psql -h "$PG_HOST" -p "$DB_PORT" -U "$PG_SUPERUSER" -d "$DB_NAME" "$@"
    fi
}
pg_su_createdb() {
    if [ "$PG_LOCAL" = "1" ] && [ -z "$PG_SUPERUSER_PASSWORD" ]; then
        sudo -u "$PG_SUPERUSER" createdb -p "$DB_PORT" "$@"
    else
        PGPASSWORD="$PG_SUPERUSER_PASSWORD" createdb -h "$PG_HOST" -p "$DB_PORT" -U "$PG_SUPERUSER" "$@"
    fi
}

# ไม่ได้ preset รหัส superuser -> ลองต่อด้วยวิธีข้างบนก่อน ต่อไม่ได้ค่อยถามรหัส
# (รองรับทั้ง Postgres ที่บังคับ password และ DB ที่อยู่คนละเครื่อง)
if [ -z "$PG_SUPERUSER_PASSWORD" ] && ! pg_su_psql -tAc "SELECT 1" >/dev/null 2>&1; then
    if [ "$PG_LOCAL" = "1" ]; then
        warn "Peer auth to PostgreSQL (sudo -u $PG_SUPERUSER) failed - the superuser probably needs a password"
    else
        warn "Connecting to PostgreSQL at $PG_HOST:$DB_PORT as '$PG_SUPERUSER' needs a password"
    fi
    ask_secret PG_SUPERUSER_PASSWORD "Password for PostgreSQL superuser '$PG_SUPERUSER'"
fi
# ค่าที่เอาไปต่อเป็น string literal ใน SQL (รหัสผ่าน) — ' ในค่าต้องกลายเป็น '' ไม่งั้นคำสั่งเพี้ยน
pg_quote_lit() { printf "'%s'" "${1//\'/\'\'}"; }

# ต่อไม่ได้ตั้งแต่ต้นให้ตายตรงนี้พร้อมเหตุผล — ปล่อยไปให้พังที่ CREATE ROLE จะได้ error ที่อ่านไม่รู้เรื่อง
if ! pg_su_psql -tAc "SELECT 1" >/dev/null 2>&1; then
    err "Cannot connect to PostgreSQL as superuser '$PG_SUPERUSER' at $PG_HOST:$DB_PORT"
    err "  Wrong password, or pg_hba.conf does not allow this connection - nothing has been changed in the DB"
    err "  Retry with:  sudo PG_SUPERUSER_PASSWORD='...' PG_HOST=$PG_HOST $PROJECT_DIR/setup-server.sh"
    exit 1
fi

if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'")" = "1" ]; then
    pg_su_psql -qc "ALTER ROLE \"$DB_USER\" WITH LOGIN PASSWORD $(pg_quote_lit "$DB_PASSWORD")" >/dev/null
    ok "Role '$DB_USER' already exists (password set to the one used by this run)"
else
    pg_su_psql -qc "CREATE ROLE \"$DB_USER\" WITH LOGIN PASSWORD $(pg_quote_lit "$DB_PASSWORD")" >/dev/null
    ok "Created role '$DB_USER'"
fi

if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" = "1" ]; then
    # ---- ฐานข้อมูลมีอยู่ก่อนแล้ว: เป็นของระบบนี้จริงหรือของแอปอื่นที่ชื่อบังเอิญตรงกัน? ----
    #
    # ปล่อยผ่านโดยไม่ตรวจ = ตอน service start ครั้งแรก create_all() จะสร้างตารางของเราลงไปในฐาน
    # ของคนอื่น และ migration ใน main.py จะ ALTER TABLE users เติมคอลัมน์ใส่ตาราง users ของเขา
    # (แก้ข้อมูลของระบบอื่นโดยที่คนติดตั้งไม่รู้ตัว) — ต้องหยุดตรงนี้เท่านั้น
    #
    # "ของเรา" ดูจากชื่อตารางเฉพาะของระบบนี้ ไม่นับ users ที่ชื่อโหลเกินกว่าจะใช้ชี้ขาด
    PUBLIC_TABLES="$(pg_su_psql_db -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='public'")"
    OUR_TABLES="$(pg_su_psql_db -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ('agents','security_alerts','ip_black_list','ip_white_list','detection_rules','detection_signatures','alert_severity','alert_reads','blacklist_ttl','line_recipients','agent_downloads','app_settings')")"

    if [ "${PUBLIC_TABLES:-0}" -eq 0 ]; then
        ok "Database '$DB_NAME' already exists and is empty - tables are created on first start"
    elif [ "${OUR_TABLES:-0}" -gt 0 ]; then
        ok "Database '$DB_NAME' already exists with this system's tables ($OUR_TABLES of them) - data is kept as is"
    elif [ "${ALLOW_FOREIGN_DB:-0}" = "1" ]; then
        warn "Database '$DB_NAME' holds $PUBLIC_TABLES tables that are not this system's - continuing (ALLOW_FOREIGN_DB=1)"
    else
        err "Database '$DB_NAME' already exists and holds $PUBLIC_TABLES tables that do not belong to this system"
        err "  Starting on top of it would create this system's tables inside someone else's database"
        err "  Use another name:  sudo DB_NAME=securelog_central $PROJECT_DIR/setup-server.sh"
        err "  Or, if that database really is ours:  sudo ALLOW_FOREIGN_DB=1 $PROJECT_DIR/setup-server.sh"
        exit 1
    fi

    # ---- เจ้าของฐาน/ตาราง ต้องเป็น role ที่แอปใช้ ----
    # กรอกชื่อ user คนละตัวกับเจ้าของเดิม = ต่อฐานได้ (PUBLIC มีสิทธิ์ CONNECT) แต่ทำอะไรไม่ได้เลย
    # และ GRANT อย่างเดียวไม่พอ เพราะ ALTER TABLE ตอน migration ต้องเป็น "เจ้าของตาราง" เท่านั้น
    DB_OWNER="$(pg_su_psql -tAc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DB_NAME'")"
    if [ "$DB_OWNER" != "$DB_USER" ]; then
        warn "Database '$DB_NAME' is owned by '$DB_OWNER', not '$DB_USER' - handing it over"
        pg_su_psql  -qc "ALTER DATABASE \"$DB_NAME\" OWNER TO \"$DB_USER\"" >/dev/null
        pg_su_psql_db -qc "GRANT ALL ON SCHEMA public TO \"$DB_USER\"" >/dev/null
        # โอนทีละ object แทน REASSIGN OWNED เพราะ REASSIGN ลามไปทุก object ของ role เดิมในฐานนี้
        # (รวมของที่ไม่เกี่ยวกับระบบเรา) และล้มทันทีถ้าเจ้าของเดิมคือ postgres ซึ่งถือ object ของระบบไว้
        pg_su_psql_db -tAc "
            SELECT format('ALTER TABLE public.%I OWNER TO %I;', tablename, '$DB_USER')
              FROM pg_tables WHERE schemaname='public'
            UNION ALL
            SELECT format('ALTER SEQUENCE public.%I OWNER TO %I;', sequencename, '$DB_USER')
              FROM pg_sequences WHERE schemaname='public'
        " | pg_su_psql_db -q -v ON_ERROR_STOP=1 >/dev/null
        ok "Database, tables and sequences in '$DB_NAME' now belong to '$DB_USER'"
    fi
else
    pg_su_createdb -O "$DB_USER" "$DB_NAME"
    ok "Created database '$DB_NAME' (owner=$DB_USER) - tables and the admin account are created on first start"
fi

# ---- ลองล็อกอินด้วยรหัสที่จะเขียนลง .env จริง ๆ ทางเดียวกับที่แอปต่อ (TCP + password) ----
# ของเดิมไม่เคยทดสอบส่วนนี้: สคริปต์จบสวยแล้วไปตายตอน service start ด้วย password authentication
# failed / no pg_hba.conf entry ซึ่งคนติดตั้งต้องไปงมใน journalctl เอง
if [ "${SKIP_DB_CHECK:-0}" = "1" ]; then
    warn "SKIP_DB_CHECK=1 - not verifying that '$DB_USER' can actually log in"
elif ! command -v psql >/dev/null 2>&1; then
    warn "psql not found - cannot verify that '$DB_USER' can log in (the services will find out at start)"
else
    PG_TEST_ERR="$(mktemp)"
    if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
            -tAc "SELECT 1" >/dev/null 2>"$PG_TEST_ERR"; then
        ok "Logged in as '$DB_USER' to $DB_HOST:$DB_PORT/$DB_NAME - the services will connect the same way"
        rm -f "$PG_TEST_ERR"
    else
        err "Role '$DB_USER' cannot log in to $DB_HOST:$DB_PORT/$DB_NAME with the password given:"
        sed 's/^/      /' "$PG_TEST_ERR" >&2
        rm -f "$PG_TEST_ERR"
        err "  Fix pg_hba.conf (a 'host $DB_NAME $DB_USER 127.0.0.1/32 scram-sha-256' line) or the password,"
        err "  then run this script again - or skip this check with SKIP_DB_CHECK=1"
        exit 1
    fi
fi

# ---- IP ของ central เปลี่ยน: แถวใน app_settings ต้องตามด้วย ----
# ค่าที่ชุดติดตั้ง agent ใช้จริง มาจากตาราง app_settings (หน้า System Settings) ไม่ใช่ .env —
# .env เป็นแค่ค่าตั้งต้นตอนยังไม่มีแถว เครื่องที่เคย start แล้วจะมีแถวนี้เสมอ ถ้าไม่แก้ด้วย
# package ที่ออกใหม่หลังย้าย IP จะยังฝัง IP เก่าไปให้ agent ทุกเครื่อง
if [ "$IP_CHANGED" = "1" ] \
   && [ "$(pg_su_psql_db -tAc "SELECT to_regclass('public.app_settings') IS NOT NULL")" = "t" ]; then
    OLD_SETTING="$(pg_su_psql_db -tAc "SELECT value FROM app_settings WHERE setting_key='agent_central_host'")"
    if [ -n "$OLD_SETTING" ] && [ "$OLD_SETTING" != "$BIND_HOST" ]; then
        pg_su_psql_db -q -v ON_ERROR_STOP=1 -c "
            UPDATE app_settings SET value=$(pg_quote_lit "$BIND_HOST"), updated_at=now()
             WHERE setting_key='agent_central_host'" >/dev/null
        # ลงประวัติให้ตรงกับที่หน้า System Settings ทำ ไม่งั้นค่าจะเปลี่ยนเองโดยไม่มีร่องรอย
        if [ "$(pg_su_psql_db -tAc "SELECT to_regclass('public.app_setting_changes') IS NOT NULL")" = "t" ]; then
            pg_su_psql_db -q -v ON_ERROR_STOP=1 -c "
                INSERT INTO app_setting_changes
                    (setting_key, action, old_value, new_value, changed_by, source, changed_at)
                VALUES ('agent_central_host', 'set', $(pg_quote_lit "$OLD_SETTING"),
                        $(pg_quote_lit "$BIND_HOST"), 'system', 'cli', now())" >/dev/null
        fi
        ok "app_settings.agent_central_host: $OLD_SETTING -> $BIND_HOST (new agent packages get the new address)"
    fi
fi

# ---------------------------------------------------------------------------
# 6) .env — สร้างใหม่ถ้ายังไม่มี · มีแล้วก็ "ซิงค์เฉพาะคีย์ที่ระบบเป็นคนดูแล" ให้ตรงกับรอบนี้
#
#    ที่ต้องเขียนกลับ ไม่ใช่ปล่อยไว้เฉย ๆ: ค่าพวกนี้คือค่าที่สคริปต์เพิ่งลงมือทำของจริงไปแล้ว
#    (ALTER ROLE ด้วยรหัสไหน · cert ออก SAN เป็น IP ไหน · unit bind อะไร) ถ้า .env ไม่ตรง
#    = service อ่านค่าคนละชุดกับที่เครื่องเป็นอยู่จริง แล้วตายตอน start โดยไม่มีใครรู้ว่าเพราะอะไร
#    คีย์ที่ระบบไม่ได้ดูแล (LINE_*, GEMINI_*, JWT_*, CSRF_*, COOKIE_SECURE, ALGORITHM) ไม่ถูกแตะ
#    รวมถึงคอมเมนต์และลำดับบรรทัดเดิมด้วย — env_set แทนที่เฉพาะบรรทัดของคีย์นั้น
# ---------------------------------------------------------------------------
log ".env file"
if [ "$ENV_EXISTED" = "1" ]; then
    ok ".env already exists - syncing the keys this script owns (everything else is left as is)"

    ENV_CHANGED=""
    env_sync() {  # env_sync KEY VALUE
        local key="$1" val="$2"
        [ "$(env_get "$key" "$ENV_FILE")" = "$val" ] && return 0
        env_set "$key" "$val" "$ENV_FILE"
        ENV_CHANGED="$ENV_CHANGED $key"
    }

    env_sync DB_HOST     "$DB_HOST"
    env_sync DB_PORT     "$DB_PORT"
    env_sync DB_NAME     "$DB_NAME"
    env_sync DB_USER     "$DB_USER"
    env_sync DB_PASSWORD "$DB_PASSWORD"

    # REDIS_HOST คือที่อยู่ของ central ที่ตัวมันเองใช้ต่อ Redis (ผ่าน mTLS ที่ตรวจชื่อใน SAN ด้วย)
    # ย้าย IP แล้วไม่ตามมาแก้ที่นี่ = ทุก service ต่อ Redis ไม่ติดทั้งเครื่อง
    env_sync REDIS_HOST "$BIND_HOST"
    env_sync REDIS_USER "$REDIS_USER"
    env_sync REDIS_PASS "$REDIS_PASS"

    # path ของ cert ผูกกับที่ตั้งโปรเจกต์ — ย้ายโฟลเดอร์ (INSTALL_DIR) แล้วต้องตามไปด้วย
    env_sync REDIS_CERT "$PROJECT_DIR/cert/central/central.crt"
    env_sync REDIS_KEY  "$PROJECT_DIR/cert/central/central.key"
    env_sync REDIS_CA   "$PROJECT_DIR/cert/central/ca.crt"

    env_sync WEB_BIND_HOST     "$WEB_BIND_HOST"
    env_sync WEBHOOK_BIND_HOST "$WEBHOOK_BIND_HOST"

    # กลุ่ม agent: .env เป็นค่าตั้งต้นสำหรับตอนที่ตาราง app_settings ยังไม่มีแถวของคีย์นั้น
    # (ของจริงหลังเครื่องเคย start แล้วอยู่ใน DB — ขั้น 5 ตามไปแก้แถวนั้นให้ด้วยเมื่อ IP เปลี่ยน)
    env_sync AGENT_CENTRAL_HOST       "$BIND_HOST"
    env_sync AGENT_CENTRAL_REDIS_PORT "6380"
    env_sync AGENT_REDIS_USERNAME     "agent_node"
    env_sync AGENT_REDIS_PASSWORD     "$AGENT_REDIS_PASS"

    if [ -n "$ENV_CHANGED" ]; then
        ok "Updated in .env:$ENV_CHANGED"
    else
        ok "Everything in .env already matches - nothing to change"
    fi
else
    JWT_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    CSRF_SECRET_VAL="$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')"
    cat > "$PROJECT_DIR/.env" <<EOF
# Generated by setup-server.sh - fill in the LINE/GEMINI values later if needed
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT
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
# 7) cert — ออกให้เอง (Root CA -> central สำหรับ Redis mTLS -> dashboard สำหรับ HTTPS)
#    SAN ต้องมีทุก IP ที่ระบบถูกเรียกด้วย ไม่งั้น service ไม่ start / agent ต่อ Redis ไม่ได้ /
#    เบราว์เซอร์ฟ้อง cert ไม่ตรง — ที่นี่จึงใส่ให้ทั้ง BIND_HOST และ WEB_BIND_HOST (ถ้าเป็นคนละ IP)
#    ของเดิมที่ SAN ครอบครบอยู่แล้วไม่ทับ · ไม่ครบ (เช่นเพิ่งย้าย IP) = เก็บเข้ากรุแล้วออกใหม่ · FORCE_CERT=1 บังคับได้
# ---------------------------------------------------------------------------
log "Certificates (Redis mTLS + dashboard HTTPS)"
CERT_DIR="$PROJECT_DIR/cert/central"
mkdir -p "$CERT_DIR"

# ---- host ที่ต้องอยู่ใน SAN ----
SAN_HOSTS=("$BIND_HOST")
# dashboard bind อีก IP หนึ่ง = คนเปิดเว็บด้วย IP นั้น ต้องมีใน SAN ด้วย ไม่งั้นเบราว์เซอร์ฟ้องทุกครั้ง
# (0.0.0.0 บอกอะไรไม่ได้ว่าจะถูกเรียกด้วย IP ไหน จึงข้าม)
if [ "$WEB_BIND_HOST" != "0.0.0.0" ] && [ "$WEB_BIND_HOST" != "$BIND_HOST" ]; then
    SAN_HOSTS+=("$WEB_BIND_HOST")
fi

SAN_LINE=""
ALT_NAMES=""
SAN_SEEN=" "
san_ip_n=0
san_dns_n=0
add_san() {  # add_san HOST — ต่อเข้า SAN_LINE (ให้ openssl) + ALT_NAMES (ไฟล์ cnf) แบบไม่ซ้ำ
    local h="$1"
    case "$SAN_SEEN" in *" $h "*) return 0 ;; esac
    SAN_SEEN="$SAN_SEEN$h "
    if printf '%s' "$h" | grep -qE '^[0-9]+(\.[0-9]+){3}$'; then
        san_ip_n=$((san_ip_n + 1))
        ALT_NAMES="${ALT_NAMES}IP.$san_ip_n = $h"$'\n'
        SAN_LINE="${SAN_LINE:+$SAN_LINE,}IP:$h"
    else
        san_dns_n=$((san_dns_n + 1))
        ALT_NAMES="${ALT_NAMES}DNS.$san_dns_n = $h"$'\n'
        SAN_LINE="${SAN_LINE:+$SAN_LINE,}DNS:$h"
    fi
}
add_san 127.0.0.1
for _h in "${SAN_HOSTS[@]}"; do add_san "$_h"; done
ALT_NAMES="${ALT_NAMES%$'\n'}"

# ---- cert เดิมครอบ host พวกนั้นครบไหม ----
# ⚠️ ต้องเทียบ "ทั้งรายการ SAN แบบเป๊ะ ๆ" ไม่ใช่ grep หา IP ในเนื้อ cert แบบเดิม:
#    grep -q "192.168.56.11" เจอใน cert ที่ SAN เป็น 192.168.56.110 ด้วย (เป็น substring กัน)
#    ย้าย IP จาก .110 ไป .11 แล้วสคริปต์จะนึกว่า cert ยังใช้ได้ ปล่อย SAN เดิมไว้ทั้งที่ผิด
cert_san() {  # cert_san FILE — openssl เก่าที่ยังไม่มี -ext ตกไปอ่านจาก -text
    openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null \
        || openssl x509 -in "$1" -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name'
}
cert_has_host() {  # cert_has_host FILE HOST
    local esc
    esc="$(printf '%s' "$2" | sed 's/\./\\./g')"
    cert_san "$1" | grep -qE "(IP Address|DNS):$esc([,[:space:]]|\$)"
}
cert_covers_all() {  # cert_covers_all FILE
    local h
    for h in "${SAN_HOSTS[@]}"; do
        cert_has_host "$1" "$h" || return 1
    done
    return 0
}

# CA เดิมเก็บไว้เสมอ — cert ของ agent ที่ออกไปแล้วเซ็นด้วย CA ตัวนี้ ถ้าเปลี่ยน CA ต้องไล่ลง
# package ใหม่ทุกเครื่อง · ออก central/dashboard ใหม่ด้วย CA เดิม agent เก่าจึงยังเชื่อถือใบใหม่ได้
CERT_ISSUED=0
if [ -f "$CERT_DIR/central.crt" ] || [ -f "$CERT_DIR/dashboard.crt" ]; then
    CERT_REASON=""
    [ "${FORCE_CERT:-0}" = "1" ] && CERT_REASON="FORCE_CERT=1"
    for _f in central dashboard; do
        [ -f "$CERT_DIR/$_f.crt" ] || continue
        cert_covers_all "$CERT_DIR/$_f.crt" || CERT_REASON="${CERT_REASON:-$_f.crt does not cover SAN $SAN_LINE}"
    done

    if [ -n "$CERT_REASON" ]; then
        BK="$CERT_DIR/old-$(date +%Y%m%d%H%M%S)"
        mkdir -p "$BK"
        mv "$CERT_DIR"/central.crt "$CERT_DIR"/central.key "$BK/" 2>/dev/null || true
        mv "$CERT_DIR"/dashboard.crt "$CERT_DIR"/dashboard.key "$BK/" 2>/dev/null || true
        warn "Reissuing certs ($CERT_REASON) - the old ones are in $(basename "$BK")"
    else
        ok "Existing certs already cover $SAN_LINE - left untouched"
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
    CERT_ISSUED=1
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
    CERT_ISSUED=1
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

    # ไฟล์นี้ไม่ถูกเขียนทับโดยตั้งใจ (หน้าเว็บเปลี่ยนรหัส agent ได้ และเขียนลงไฟล์นี้อย่างเดียว
    # ไม่แตะ .env) แต่ถ้าบรรทัดของ $REDIS_USER ไม่มีรหัสตรงกับ .env = central ล็อกอิน Redis
    # ไม่ได้ทั้งเครื่อง ต้องรู้ตั้งแต่ตอนนี้ ไม่ใช่ไปงมใน journalctl ทีหลัง
    if ! awk -v u="$REDIS_USER" -v p=">$REDIS_PASS" '
            $1 == "user" && $2 == u { for (i = 3; i <= NF; i++) if ($i == p) { found = 1 } }
            END { exit !found }
        ' "$ACL_FILE"; then
        warn "users.acl has no matching password for user '$REDIS_USER' - central will not be able to log in to Redis"
        warn "  Change it from the web UI (System Settings), or rewrite the file: sudo FORCE_ACL=1 $PROJECT_DIR/setup-server.sh"
    fi
fi

# ---------------------------------------------------------------------------
# 7.2) for_Agent/package/site.conf — ค่าที่ถูกฝังลง zip ของ agent ทุกครั้งที่สร้าง
# ---------------------------------------------------------------------------
log "Agent installer settings (site.conf)"
SITE_CONF="$PROJECT_DIR/for_Agent/package/site.conf"

# ของเดิมเขียนแค่ตอนยังไม่มีไฟล์ — ย้าย IP แล้วไฟล์นี้จึงค้าง IP เก่าไว้เงียบ ๆ
# เทียบค่าในไฟล์กับค่ารอบนี้ ต่างเมื่อไหร่เขียนใหม่ (ไฟล์นี้เป็นค่าตั้งต้นของ System Settings
# ตอนที่ตาราง app_settings ยังไม่มีแถวของคีย์นั้น — ดู settings_cache.seed_agent_settings_from_site_conf)
SITE_HOST="$(env_get CENTRAL_HOST "$SITE_CONF")"
SITE_PASS="$(env_get REDIS_PASSWORD "$SITE_CONF")"

if [ ! -f "$SITE_CONF" ] || [ "${FORCE_SITE_CONF:-0}" = "1" ] \
   || [ "$SITE_HOST" != "$BIND_HOST" ] || [ "$SITE_PASS" != "$AGENT_REDIS_PASS" ]; then
    [ -f "$SITE_CONF" ] && cp -p "$SITE_CONF" "$SITE_CONF.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$SITE_CONF" <<EOF
CENTRAL_HOST="$BIND_HOST"
CENTRAL_REDIS_PORT="6380"
REDIS_USERNAME="agent_node"
REDIS_PASSWORD="$AGENT_REDIS_PASS"
EOF
    chmod 600 "$SITE_CONF"
    if [ -n "$SITE_HOST" ] && [ "$SITE_HOST" != "$BIND_HOST" ]; then
        ok "Rewrote site.conf (CENTRAL_HOST $SITE_HOST -> $BIND_HOST)"
    else
        ok "Wrote site.conf - agent zips embed these values automatically"
    fi
else
    ok "site.conf already matches this run - left untouched"
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

# ★ ออก cert ใหม่แล้ว Redis ต้อง restart — ปกติ install.sh ตั้งใจไม่แตะ centralredis (restart =
#   ตัดคิว log + connection ของ agent ทุกตัว) แต่ Redis อ่านไฟล์ cert ตอน start ครั้งเดียว
#   ใบเก่ายังถูกยื่นให้ client อยู่ในหน่วยความจำ และ redis_config.py ต่อแบบ ssl_check_hostname=True
#   -> ย้าย IP แล้วไม่ restart = ทุก service ต่อ Redis ไม่ผ่านการตรวจชื่อ ทั้งที่ไฟล์บนดิสก์ถูกแล้ว
if [ "$CERT_ISSUED" = "1" ] && systemctl is-active --quiet centralredis.service; then
    log "Restarting centralredis (it is still serving the old certificate)"
    systemctl restart centralredis.service || warn "Could not restart centralredis - do it yourself: systemctl restart centralredis.service"
fi

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
# เว็บ bind IP เดียว = ต้องเข้าด้วย IP นั้นเท่านั้น (0.0.0.0 ค่อยใช้ที่อยู่ของ central เป็นตัวแทน)
if [ "$WEB_BIND_HOST" = "0.0.0.0" ]; then WEB_URL_HOST="$BIND_HOST"; else WEB_URL_HOST="$WEB_BIND_HOST"; fi
echo "  dashboard     : bind $WEB_BIND_HOST:8000  ->  https://$WEB_URL_HOST:8000"
echo "  LINE webhook  : bind $WEBHOOK_BIND_HOST:8080"
echo "  database      : $DB_NAME (owner $DB_USER) at $DB_HOST:$DB_PORT"
echo "  firewall      : $FW_SUMMARY"
echo ""
if [ "$STARTED" -eq 1 ]; then
    ok "First login is admin/admin"
else
    warn "Services not started because certs are incomplete - check $CERT_DIR then run: sudo $PROJECT_DIR/systemd/install.sh"
fi

# ย้าย IP: ของบนเครื่อง central ถูกแก้ให้ครบแล้ว แต่ agent ที่ลงไปแล้วยังชี้ที่เก่า
# เขาจะ retry ต่อ IP เดิมไปเรื่อย ๆ เงียบ ๆ ไม่มีอะไรฟ้องที่ central ว่าหายไปกี่เครื่อง
if [ "$IP_CHANGED" = "1" ]; then
    echo ""
    warn "Central address moved: $CURRENT_BIND_HOST -> $BIND_HOST"
    echo "     Updated here: the cert SAN, REDIS_HOST/AGENT_CENTRAL_HOST in .env, site.conf,"
    echo "     the agent_central_host row in the database, and the regenerated systemd units"
    warn "     Agents already installed still point at $CURRENT_BIND_HOST - they will keep retrying the old address."
    echo "     Fix each agent machine by re-running its installer with the new address - the address sits in"
    echo "     BOTH agent_config.json and /etc/filebeat/filebeat.yml, so editing one file is not enough:"
    echo "       - download a fresh package for that agent from the dashboard and run setup.sh again, or"
    echo "       - edit CENTRAL_HOST in the agent folder's site.conf, then re-run its setup.sh"
fi

# รหัสที่สุ่มให้ไม่เคยถูกแสดงที่อื่นอีก — ต้องโชว์ตรงนี้ครั้งเดียวให้เก็บไว้
if [ -n "$GENERATED_PASSWORDS" ]; then
    echo ""
    warn "Generated passwords (save them - not shown again; also stored in .env and redis/users.acl):"
    printf '%s' "$GENERATED_PASSWORDS" | while IFS='=' read -r k v; do
        [ -n "$k" ] && echo "     $k = $v"
    done
fi

# ปิดท้ายด้วยรายชื่อ service ที่รันจริง — เป็นสิ่งสุดท้ายที่ค้างอยู่บนจอหลังสคริปต์จบ
echo ""
if [ "$STARTED" -eq 1 ]; then
    ok "Setup complete - services running:"
    systemctl --no-pager --plain --no-legend list-units 'centralredis.service' 'securelog-*' 2>/dev/null \
        | awk '{printf "     %-36s %s %s\n", $1, $3, $4}'
else
    warn "Setup finished - services are not running yet"
fi
