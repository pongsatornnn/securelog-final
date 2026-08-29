#!/usr/bin/env bash
#
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m %s\n' "$*"; }
err()  { printf '  \033[1;31m[ERR]\033[0m %s\n' "$*" >&2; }

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

    local pid i=0 frames='|/-\' spent=0 tail_line hint=''
    "$@" </dev/null >"$STEP_LOG" 2>&1 &
    pid=$!

    printf '\033[?25l'                 # ซ่อน cursor ไม่ให้กระพริบวิ่งตามตัวหมุน
    while kill -0 "$pid" 2>/dev/null; do
        spent=$((SECONDS - start))
        # เกิน 15 วิ = ไม่ใช่ขั้นที่ผ่านไวแล้ว เอาบรรทัดล่าสุดใน log มาแปะข้างตัวหมุนให้เห็นว่า
        if [ "$spent" -ge 15 ]; then
            tail_line="$(tail -n 1 "$STEP_LOG" 2>/dev/null | tr -d '\r' | cut -c1-58)"
            if [ -n "$tail_line" ]; then hint="  "$'\033[2m'"| $tail_line"$'\033[0m'; fi
        fi
        printf '\r\033[K  \033[1;36m%s\033[0m %s \033[2m(%ds)\033[0m%s' \
            "${frames:i++%4:1}" "$desc" "$spent" "$hint"
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
source "$PROJECT_DIR/systemd/_hosts.sh"

# ---------------------------------------------------------------------------
ENV_FILE="$PROJECT_DIR/.env"
ENV_EXISTED=0
[ -f "$ENV_FILE" ] && ENV_EXISTED=1

FROM_ENV_FILE=" "   # รายชื่อตัวแปรที่ค่ามาจาก .env เดิม (ไว้บอกให้ถูกว่าค่ามาจากไหน)
declare -A ENV_DEFAULT=()   # ค่าเดิมที่ถูกย้ายไปเป็น "ค่าตั้งต้นของคำถาม" ในโหมดตั้งค่าใหม่ (ขั้น 0.2)

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

# พอร์ต Redis ที่ระบบใช้อยู่ "ตอนนี้" — ต้องอ่านเก็บไว้ก่อนขั้น 6 เขียนทับ .env เพราะเป็นพอร์ต
OLD_REDIS_PORT="$(env_get REDIS_PORT "$ENV_FILE")"
if [ -z "$OLD_REDIS_PORT" ] && [ "$ENV_EXISTED" = "1" ]; then
    OLD_REDIS_PORT=6380
fi

# ค่าที่ระบบ "ใช้อยู่ตอนนี้" ตัวอื่น ๆ อ่านเก็บไว้ตั้งแต่ก่อนถาม — ขั้น 6 เขียนทับ .env ไปแล้ว
OLD_DB_NAME="$(env_get DB_NAME "$ENV_FILE")"
OLD_DB_USER="$(env_get DB_USER "$ENV_FILE")"
OLD_DB_HOST="$(env_get DB_HOST "$ENV_FILE")"
OLD_DB_PORT="$(env_get DB_PORT "$ENV_FILE")"
OLD_DB_PASSWORD="$(env_get DB_PASSWORD "$ENV_FILE")"
OLD_REDIS_USER="$(env_get REDIS_USER "$ENV_FILE")"
OLD_REDIS_PASS="$(env_get REDIS_PASS "$ENV_FILE")"
OLD_AGENT_PASS="$(env_get AGENT_REDIS_PASSWORD "$ENV_FILE")"
INSTALLED_APP_USER=""   # เติมตอนขั้น 1 (ฟังก์ชัน installed_app_user ประกาศทีหลัง)

# postgres อยู่ไหน: DB_HOST คือค่าที่แอปใช้ต่อ (ลง .env) · PG_HOST คือที่ที่สคริปต์ต่อไปสร้าง role/db
PG_HOST_PRESET="${PG_HOST:-}"   # ตั้ง PG_HOST มาเองทาง env ไหม — ถ้าใช่ ตอบ DB_HOST ใหม่ก็ไม่ไปแตะ
PG_HOST="${PG_HOST:-${DB_HOST:-localhost}}"
DB_HOST="${DB_HOST:-$PG_HOST}"
DB_PORT="${DB_PORT:-5432}"

# ---------------------------------------------------------------------------
RECONFIGURE="${RECONFIGURE:-}"
if [ "$ENV_EXISTED" = "1" ] && [ -z "$RECONFIGURE" ]; then
    if [ -t 0 ]; then
        log "This machine has been set up before (.env found)"
        echo "  What it runs on right now:"
        echo "    central address : ${CURRENT_BIND_HOST:-?}"
        echo "    database        : ${OLD_DB_NAME:-?} as ${OLD_DB_USER:-?} at ${OLD_DB_HOST:-?}:${OLD_DB_PORT:-?}"
        echo "    Redis user      : ${OLD_REDIS_USER:-?}"
        echo ""
        echo "    1) Keep these settings      - reuse what is in .env, only repair what is missing  <- default"
        echo "    2) Set everything up again  - ask every question again: another database, another"
        echo "                                  postgres user, new Redis passwords, another IP"
        echo "                                  (Enter on a question = keep what it is now)"
        echo ""
        while :; do
            read -rp "  Pick a number [1]: " _rc_ans
            case "${_rc_ans:-1}" in
                1) RECONFIGURE=0; break ;;
                2) RECONFIGURE=1; break ;;
                *) echo "    !! No option '$_rc_ans' in the list (1-2) - try again" ;;
            esac
        done
    else
        RECONFIGURE=0      # ไม่มี tty ถามไม่ได้ = ทำตัวเหมือนเดิมทุกอย่าง (สคริปต์อื่นเรียกอยู่)
    fi
fi
RECONFIGURE="${RECONFIGURE:-0}"

# ย้ายค่าที่โหลดมาจาก .env ไปเป็น "ค่าตั้งต้นของคำถาม" แทนการเอาไปใช้เงียบ ๆ
reask() {  # reask VAR
    local var="$1" cur
    case "$FROM_ENV_FILE" in *" $var "*) ;; *) return 0 ;; esac
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    [ -n "$cur" ] || return 0
    ENV_DEFAULT["$var"]="$cur"
    unset "$var"
}
if [ "$RECONFIGURE" = "1" ]; then
    for _v in DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD REDIS_USER REDIS_PASS AGENT_REDIS_PASS; do
        reask "$_v"
    done
    warn "Setting everything up again - pressing Enter on a question keeps the value it has now"
fi

# ---------------------------------------------------------------------------
ask() {  # ask VAR "คำถาม" "ค่า default"
    local var="$1" prompt="$2" def="${3:-}" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"      # ถ้า preset มาทาง env แล้วใช้เลย
    if [ -n "$cur" ]; then ok "$var = $cur (from $(value_source "$var"))"; return; fi
    # ไม่มี tty (รันจากสคริปต์/cron) แต่มีค่าตั้งต้นที่เชื่อได้ = ใช้ค่านั้นเงียบ ๆ เหมือน pick_bind_host
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
# ask_secret VAR "คำถาม" ["ค่าเดิม"] — มีค่าเดิม (โหมดตั้งค่าใหม่) กด Enter = ใช้ค่าเดิมต่อ
ask_secret() {  # ask_secret VAR "คำถาม" ["ค่าเดิม"]
    local var="$1" prompt="$2" def="${3:-}" cur ans
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then ok "$var = ****** (from $(value_source "$var"))"; return; fi
    if [ ! -t 0 ]; then
        [ -n "$def" ] || { err "No tty and $var was not preset"; exit 1; }
        eval "$var=\$def"; ok "$var = ****** (unchanged, no tty)"; return
    fi
    read -rsp "  $prompt${def:+ (Enter = keep the current one)}: " ans; echo
    ans="${ans:-$def}"
    [ -n "$ans" ] || { err "$var must not be empty"; exit 1; }
    eval "$var=\$ans"
}

# เงื่อนไขเดียวกับ main/redis_password_rules.py — รหัสที่หลุดเงื่อนไขจะทำให้ users.acl/.env เพี้ยน
valid_redis_pass() {
    local p="$1"
    [ "${#p}" -ge 12 ] || return 1
    printf '%s' "$p" | grep -qE '^[A-Za-z0-9_.~@%+=:,/-]+$' || return 1
    return 0
}

# ถามรหัส Redis — ยังไม่มีรหัสเดิม: Enter = สุ่มให้ · มีรหัสเดิมอยู่ (โหมดตั้งค่าใหม่): Enter = ใช้ของเดิม
GENERATED_PASSWORDS=""
ask_redis_secret() {  # ask_redis_secret VAR "คำอธิบายบัญชี" ["รหัสเดิม"]
    local var="$1" what="$2" def="${3:-}" cur ans hint
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then
        valid_redis_pass "$cur" || { err "$var fails the rules (min 12 chars; allowed: A-Z a-z 0-9 _-.~@%+=:,/)"; exit 1; }
        ok "$var = ****** (from $(value_source "$var"))"
        return
    fi
    if [ ! -t 0 ]; then
        [ -n "$def" ] || { err "No tty and $var was not preset"; exit 1; }
        eval "$var=\$def"; ok "$var = ****** (unchanged, no tty)"; return
    fi

    if [ -n "$def" ]; then hint="Enter = keep the current one, type 'new' = generate a new one"
    else                   hint="Enter = generate"; fi

    while :; do
        read -rsp "  Redis password for $what ($hint): " ans; echo
        if [ -z "$ans" ] && [ -n "$def" ]; then
            ans="$def"
            ok "Kept the password this account already uses"
            break
        fi
        if [ -z "$ans" ] || [ "$ans" = "new" ]; then
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

# ---- พอร์ตที่ service ของเราจะ bind ----

# port_reject PORT — พิมพ์เหตุผลออกมาถ้ารับพอร์ตนี้ไม่ได้ · ไม่พิมพ์อะไร = ผ่าน
port_reject() {
    local p="$1"
    if ! valid_port "$p"; then
        printf '%s' "not a port number in 1024-65535 (centralredis runs as '$APP_USER', not root, so anything below 1024 cannot be bound)"
        return 0
    fi
    case "$p" in
        8000) printf '%s' "8000 is the dashboard on this machine" ;;
        8080) printf '%s' "8080 is the LINE webhook on this machine" ;;
    esac
}

# มีอย่างอื่นฟังพอร์ตนี้อยู่ไหม — **เตือนอย่างเดียว ไม่บล็อก**: ตัวที่ฟังอยู่อาจเป็นของที่กำลังจะถูก
port_warn_in_use() {  # port_warn_in_use PORT
    local p="$1"
    [ "$p" = "${OLD_REDIS_PORT:-}" ] && return 0
    if command -v ss >/dev/null 2>&1 && ss -ltnH "sport = :$p" 2>/dev/null | grep -q .; then
        warn "Something is already listening on $p/tcp - centralredis cannot start until it stops"
        warn "  See what it is:  sudo ss -ltnp \"sport = :$p\""
    fi
    if [ "$p" = "6379" ]; then
        warn "6379 is the default port of the distro's own redis-server (this script disables that service,"
        warn "  but anything else pointed at 127.0.0.1:6379 would then reach our instance instead)"
    fi
}

# ask_port VAR "คำถาม" "ค่าเดิม" — โครงเดียวกับ ask(): preset ทาง env ชนะ · ไม่มี tty ใช้ค่าเดิม
ask_port() {
    local var="$1" prompt="$2" def="${3:-}" cur ans why

    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then
        why="$(port_reject "$cur")"
        [ -z "$why" ] && { ok "$var = $cur (from env)"; port_warn_in_use "$cur"; return 0; }
        err "$var=$cur: $why"; exit 1
    fi

    if [ ! -t 0 ]; then
        [ -n "$def" ] || { err "No tty and $var was not preset"; exit 1; }
        why="$(port_reject "$def")"
        [ -n "$why" ] && { err "$var=$def: $why"; exit 1; }
        eval "$var=\$def"
        ok "$var = $def (default, no tty)"
        return 0
    fi

    while :; do
        read -rp "  $prompt${def:+ [$def]}: " ans
        ans="${ans:-$def}"
        why="$(port_reject "$ans")"
        [ -z "$why" ] && break
        echo "    !! '$ans' - $why"
    done
    eval "$var=\$ans"
    port_warn_in_use "$ans"
}

# user ที่ unit ซึ่งติดตั้งอยู่ตอนนี้รันด้วย — เป็นค่าตั้งต้นที่ "จริง" กว่า SUDO_USER
installed_app_user() {
    local unit="/etc/systemd/system/securelog-web.service"
    [ -f "$unit" ] || return 0
    sed -nE 's/^User=([^[:space:]]+).*/\1/p' "$unit" 2>/dev/null | head -1 || true
}

log "Configuration (press Enter to accept the default)"
DETECTED_IP="$(detect_primary_ip)"
INSTALLED_APP_USER="$(installed_app_user)"
DEFAULT_USER="$INSTALLED_APP_USER"
[ -n "$DEFAULT_USER" ] || DEFAULT_USER="${SUDO_USER:-$(stat -c '%U' "$PROJECT_DIR")}"

ask        APP_USER   "User the services will run as (User=)" "$DEFAULT_USER"

# ---- IP 3 ช่อง ถามแยกกัน (ความหมายต่างกัน — อ่านหัวไฟล์ systemd/_hosts.sh) ----
if [ ! -t 0 ] && [ -z "${BIND_HOST:-}" ] && [ -z "$CURRENT_BIND_HOST" ]; then
    err "No tty and BIND_HOST was not preset"; exit 1
fi
WEB_DEFAULT="$(env_get WEB_BIND_HOST "$ENV_FILE")"
HOOK_DEFAULT="$(env_get WEBHOOK_BIND_HOST "$ENV_FILE")"

pick_bind_host BIND_HOST \
    "Address other machines use to reach this central server" \
    "${CURRENT_BIND_HOST:-${DETECTED_IP:-}}" 0 \
    "Goes into the cert SAN, REDIS_HOST and the agent installer - must be a real IP"
# พอร์ต Redis ถามต่อจากที่อยู่ทันที เพราะเป็นคู่กัน — "agent ต่อกลับมาที่ไหน" คือ IP + พอร์ตนี้
ask_port REDIS_PORT \
    "Port the Redis of this central listens on (mTLS - agents connect to it)" \
    "${OLD_REDIS_PORT:-6380}"

pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) - which IP to listen on" "${WEB_DEFAULT:-$BIND_HOST}" 1 \
    "One IP = other networks on this host cannot reach it; 0.0.0.0 = all interfaces"
pick_bind_host WEBHOOK_BIND_HOST \
    "LINE webhook (HTTP :8080) - which IP to listen on" "${HOOK_DEFAULT:-0.0.0.0}" 1 \
    "LINE calls in through a tunnel; if the tunnel runs here, 127.0.0.1 is fine"

# ★ IP ของ central เปลี่ยนจากรอบก่อน = ต้องไล่แก้ให้ครบทุกที่ที่ IP เดิมฝังอยู่ ไม่งั้นระบบจะ
IP_CHANGED=0
if [ -n "$CURRENT_BIND_HOST" ] && [ "$CURRENT_BIND_HOST" != "$BIND_HOST" ]; then
    IP_CHANGED=1
    warn "Central address changed: $CURRENT_BIND_HOST -> $BIND_HOST"
    warn "  cert SAN, .env, site.conf and the units will all follow"
fi

# ★ พอร์ต Redis เปลี่ยน = เรื่องเดียวกับย้าย IP ในแง่ของ agent (ที่อยู่ที่ฝังไว้ในเครื่องเขาผิดไปแล้ว)
PORT_CHANGED=0
if [ -n "$OLD_REDIS_PORT" ] && [ "$OLD_REDIS_PORT" != "$REDIS_PORT" ]; then
    PORT_CHANGED=1
    warn "Redis port changed: $OLD_REDIS_PORT -> $REDIS_PORT"
    warn "  redis-mtls.conf (the old file is kept as .bak), .env, site.conf, firewall and a restart of centralredis"
fi

# DB_HOST/DB_PORT ปกติไม่ใช่คำถาม (ตั้งผ่าน env เอาเมื่อ postgres อยู่คนละเครื่อง) — โหมดตั้งค่าใหม่
if [ "$RECONFIGURE" = "1" ]; then
    ask DB_HOST "PostgreSQL host the services connect to" "${ENV_DEFAULT[DB_HOST]:-$DB_HOST}"
    ask DB_PORT "PostgreSQL port"                         "${ENV_DEFAULT[DB_PORT]:-$DB_PORT}"
    # ที่ที่สคริปต์ต่อไปสร้าง role/db ตามค่าที่เพิ่งตอบ เว้นแต่ตั้ง PG_HOST มาเองทาง env
    [ -n "$PG_HOST_PRESET" ] || PG_HOST="$DB_HOST"
fi

ask        DB_NAME    "PostgreSQL database name"        "${ENV_DEFAULT[DB_NAME]:-security_central}"
ask        DB_USER    "PostgreSQL user"                 "${ENV_DEFAULT[DB_USER]:-$APP_USER}"
ask_secret DB_PASSWORD "PostgreSQL password for $DB_USER" "${ENV_DEFAULT[DB_PASSWORD]:-}"

# ตอบ DB_PORT ใหม่ได้แล้ว = ต้องกันค่าที่ไม่ใช่พอร์ต ไม่งั้นไปตายที่ psql ด้วย error ที่อ่านไม่รู้เรื่อง
printf '%s' "$DB_PORT" | grep -qE '^[0-9]{1,5}$' \
    || { err "DB_PORT='$DB_PORT' is not a port number"; exit 1; }

# ชื่อ role/database ถูกเอาไปต่อเป็นคำสั่ง SQL ตรง ๆ — จำกัดให้เป็น identifier ปกติของ postgres
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

ask        REDIS_USER "Redis user for central"          "${ENV_DEFAULT[REDIS_USER]:-admin}"

# ชื่อ user ถูกเขียนลง users.acl แบบ token คั่นด้วยช่องว่าง — มีช่องว่าง/อักขระแปลกปนคือไฟล์เสีย
printf '%s' "$REDIS_USER" | grep -qE '^[A-Za-z0-9_.-]{1,64}$' \
    || { err "REDIS_USER='$REDIS_USER' is not valid (A-Z a-z 0-9 _ - . only)"; exit 1; }

ask_redis_secret REDIS_PASS       "account $REDIS_USER (central uses it for Redis)" "${ENV_DEFAULT[REDIS_PASS]:-}"
ask_redis_secret AGENT_REDIS_PASS "agent accounts (agent_node + default)"           "${ENV_DEFAULT[AGENT_REDIS_PASS]:-}"

APP_GROUP="${APP_GROUP:-$APP_USER}"

# ---------------------------------------------------------------------------
CHANGES=()
DB_TARGET_CHANGED=0
REDIS_ACL_CHANGED=0
AGENT_PASS_CHANGED=0

if [ "$ENV_EXISTED" = "1" ]; then
    # IP ถูกเตือนไปแล้วตอนตอบคำถาม แต่ต้องอยู่ในสรุปก่อนยืนยันด้วย — มันคือข้อที่กระทบหนักที่สุด
    if [ "$IP_CHANGED" = "1" ]; then
        CHANGES+=("central address $CURRENT_BIND_HOST -> $BIND_HOST (cert SAN, .env, site.conf and units all follow)")
    fi
    if [ "$PORT_CHANGED" = "1" ]; then
        CHANGES+=("Redis port $OLD_REDIS_PORT -> $REDIS_PORT (redis-mtls.conf, .env, site.conf, firewall - EVERY agent already installed stops reporting)")
    fi
    if [ -n "$INSTALLED_APP_USER" ] && [ "$INSTALLED_APP_USER" != "$APP_USER" ]; then
        CHANGES+=("services run as '$APP_USER' instead of '$INSTALLED_APP_USER' (the whole project is chown'd)")
    fi
    if [ -n "$OLD_DB_NAME" ] && [ "$OLD_DB_NAME" != "$DB_NAME" ]; then
        DB_TARGET_CHANGED=1
        CHANGES+=("database '$OLD_DB_NAME' -> '$DB_NAME'")
    fi
    if [ -n "$OLD_DB_USER" ] && [ "$OLD_DB_USER" != "$DB_USER" ]; then
        DB_TARGET_CHANGED=1
        CHANGES+=("postgres user '$OLD_DB_USER' -> '$DB_USER'")
    fi
    if [ -n "$OLD_DB_HOST" ] && [ "$OLD_DB_HOST:$OLD_DB_PORT" != "$DB_HOST:$DB_PORT" ]; then
        DB_TARGET_CHANGED=1
        CHANGES+=("postgres moves to $DB_HOST:$DB_PORT (was $OLD_DB_HOST:$OLD_DB_PORT)")
    fi
    if [ -n "$OLD_DB_PASSWORD" ] && [ "$OLD_DB_PASSWORD" != "$DB_PASSWORD" ]; then
        CHANGES+=("password of postgres role '$DB_USER' is reset to the one typed now (ALTER ROLE)")
    fi
    if [ -n "$OLD_REDIS_USER" ] && [ "$OLD_REDIS_USER" != "$REDIS_USER" ]; then
        REDIS_ACL_CHANGED=1
        CHANGES+=("Redis user for central '$OLD_REDIS_USER' -> '$REDIS_USER'")
    fi
    if [ -n "$OLD_REDIS_PASS" ] && [ "$OLD_REDIS_PASS" != "$REDIS_PASS" ]; then
        REDIS_ACL_CHANGED=1
        CHANGES+=("Redis password of '$REDIS_USER' changes - users.acl is rewritten and centralredis restarted")
    fi
    if [ -n "$OLD_AGENT_PASS" ] && [ "$OLD_AGENT_PASS" != "$AGENT_REDIS_PASS" ]; then
        REDIS_ACL_CHANGED=1
        AGENT_PASS_CHANGED=1
        CHANGES+=("Redis password of the agent accounts changes - EVERY agent already installed stops reporting")
    fi
fi

# ---------------------------------------------------------------------------
log "Database check (read-only - nothing has been installed or changed yet)"

PG_SUPERUSER="${PG_SUPERUSER:-postgres}"
# peer auth (sudo -u postgres) ใช้ได้เฉพาะ postgres ที่อยู่บนเครื่องนี้เท่านั้น (ขั้น 5 ใช้ค่านี้ต่อ)
PG_LOCAL=0
case "$PG_HOST" in localhost|127.0.0.1|::1|"") PG_LOCAL=1 ;; esac

# ตารางที่ชี้ขาดว่า "ฐานนี้เป็นของระบบนี้" — ไม่นับ users ที่ชื่อโหลเกินกว่าจะใช้ตัดสิน (ขั้น 5 ใช้ชุดเดียวกัน)
OUR_TABLES_SQL="'agents','security_alerts','ip_black_list','ip_white_list','detection_rules','detection_signatures','alert_severity','alert_reads','blacklist_ttl','line_recipients','agent_downloads','app_settings'"

DB_STATE=""      # ไปโผล่ในบรรทัดสรุปท้ายสคริปต์ด้วย
DB_ROWS=""
# จำนวน agent ที่ "ลงทะเบียนไว้ในฐาน" — สัญญาณที่เชื่อได้ว่ามีเครื่อง agent อยู่ข้างนอกจริง
EXISTING_AGENTS=""

# ต่อด้วย role ของแอปเองทาง TCP = เส้นทางเดียวกับที่ service ต่อจริง (ล้มเหลวคืนค่าว่าง ไม่ทำสคริปต์ตาย)
app_psql() {  # app_psql SQL [DATABASE]
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
        -d "${2:-$DB_NAME}" -tAc "$1" 2>/dev/null || true
}
# สำรองสำหรับตอน role ของแอปยังล็อกอินไม่ได้ — peer auth ไม่ต้องรหัส จึงไม่ต้องไปถามอะไรเพิ่มตอนนี้
peer_psql() {  # peer_psql SQL [DATABASE]
    [ "$PG_LOCAL" = "1" ] || return 0
    sudo -n -u "$PG_SUPERUSER" psql -p "$DB_PORT" -d "${2:-$DB_NAME}" -tAc "$1" 2>/dev/null || true
}
db_rows() {  # db_rows TABLE VIA(app|peer) — จำนวนแถว (ว่าง = ยังไม่มีตารางนั้น/อ่านไม่ได้)
    [ "$("${2}_psql" "SELECT to_regclass('public.$1') IS NOT NULL")" = "t" ] || return 0
    "${2}_psql" "SELECT count(*) FROM public.$1"
}

# ★ ใจความของขั้นนี้: ฐานนี้ "มีข้อมูลอยู่เท่าไร" — ตอบเป็นจำนวนแถวจริง ไม่ใช่แค่ว่ามีตารางกี่ตัว
report_db_contents() {  # report_db_contents VIA(app|peer)
    local via="$1" pub our ag al us
    pub="$("${via}_psql" "SELECT count(*) FROM pg_tables WHERE schemaname='public'")"
    if [ -z "$pub" ]; then
        warn "Cannot read what is inside '$DB_NAME' from here - step 5 reports it once it can connect"
        DB_STATE="exists, contents unknown"
        return 0
    fi
    our="$("${via}_psql" "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ($OUR_TABLES_SQL)")"
    if [ "${pub:-0}" -eq 0 ]; then
        ok "Database '$DB_NAME' is empty - tables are created on first start, the system begins from scratch (admin/admin)"
        DB_STATE="exists but empty"
    elif [ "${our:-0}" -gt 0 ]; then
        ag="$(db_rows agents "$via")"; al="$(db_rows security_alerts "$via")"; us="$(db_rows users "$via")"
        EXISTING_AGENTS="$ag"
        DB_ROWS="agents ${ag:-?} · alerts ${al:-?} · users ${us:-?}"
        ok "Database '$DB_NAME' already belongs to this system ($our tables) - the data in it is kept and used as is"
        echo "       rows right now: $DB_ROWS"
        DB_STATE="existing data ($DB_ROWS)"
    else
        warn "Database '$DB_NAME' holds $pub tables that are NOT this system's"
        warn "  Step 5 stops there rather than creating our tables inside someone else's database"
        warn "  Answer with another database name, or confirm it really is ours with ALLOW_FOREIGN_DB=1"
        DB_STATE="someone else's database ($pub tables)"
    fi
}

if [ "${SKIP_DB_CHECK:-0}" = "1" ]; then
    warn "SKIP_DB_CHECK=1 - the database is not checked at all"
    DB_STATE="not checked (SKIP_DB_CHECK=1)"

elif ! command -v psql >/dev/null 2>&1; then
    ok "PostgreSQL is not on this machine yet - it gets installed in step 2, the database created in step 5"
    DB_STATE="to be created"

elif command -v pg_isready >/dev/null 2>&1 && ! pg_isready -h "$DB_HOST" -p "$DB_PORT" >/dev/null 2>&1; then
    if [ "$PG_LOCAL" = "1" ]; then
        warn "Nothing is answering on $DB_HOST:$DB_PORT yet - PostgreSQL is enabled and started for you in step 5"
        DB_STATE="not running yet"
    else
        err "Cannot reach PostgreSQL at $DB_HOST:$DB_PORT"
        err "  It is on another machine, so this script cannot start it - and every later step needs it."
        err "  ** Nothing has been installed or changed on this machine yet. **"
        err "  Check the host/port/firewall and that postgres listens on that address, or point elsewhere:"
        err "    sudo DB_HOST=... DB_PORT=... $PROJECT_DIR/setup-server.sh"
        err "  To carry on regardless: SKIP_DB_CHECK=1"
        exit 1
    fi

else
    ok "PostgreSQL answers on $DB_HOST:$DB_PORT"

    # ⚠️ ต้องรู้ก่อนว่า "ล็อกอินได้ทางไหนบ้าง" ไม่งั้นแยก 2 อย่างนี้ไม่ออก แล้วรายงานผิด:
    CAN_APP=0
    if [ "$(app_psql "SELECT 1" postgres)" = "1" ]; then CAN_APP=1; fi
    CAN_PEER=0
    if [ "$(peer_psql "SELECT 1" postgres)" = "1" ]; then CAN_PEER=1; fi

    # รอบนี้ตั้งใจเปลี่ยนรหัสอยู่แล้ว = ล็อกอินไม่ผ่านตอนนี้เป็นเรื่องปกติ ขั้น 5 ALTER ROLE ให้
    PW_CHANGING=0
    if [ "$ENV_EXISTED" = "1" ] && [ -n "$OLD_DB_PASSWORD" ] && [ "$OLD_DB_PASSWORD" != "$DB_PASSWORD" ]; then
        PW_CHANGING=1
    fi

    if [ "$CAN_APP" = "0" ] && [ "$CAN_PEER" = "0" ]; then
        DB_STATE="could not be checked (no login yet)"
        if [ "$PW_CHANGING" = "1" ]; then
            ok "'$DB_USER' cannot log in with the new password yet - expected, step 5 runs ALTER ROLE to set it"
        else
            warn "PostgreSQL answers, but nothing can log in yet - '$DB_USER' is rejected and peer auth is not available here"
        fi
        warn "  So it cannot be said from here whether '$DB_NAME' exists or how much data it holds"
        warn "  Step 5 connects as superuser '$PG_SUPERUSER' (asking for its password if peer auth is off) and reports it there"

    else
        if [ "$CAN_APP" = "1" ]; then
            DB_EXISTS="$(app_psql "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" postgres)"
        else
            DB_EXISTS="$(peer_psql "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'" postgres)"
        fi

        if [ "$DB_EXISTS" != "1" ]; then
            ok "Database '$DB_NAME' does not exist yet - it is created in step 5, the system starts empty (first login admin/admin)"
            DB_STATE="new, empty"

        elif [ "$(app_psql "SELECT 1")" = "1" ]; then
            ok "Logged in as '$DB_USER' to '$DB_NAME' - the services will connect exactly this way"
            report_db_contents app

        else
            # ฐานมีอยู่ แต่ role ของแอปยังเข้าไม่ได้ — บอกสาเหตุที่ตรงเคส แล้วอ่านสภาพฐานผ่าน peer แทน
            if [ "$PW_CHANGING" = "1" ]; then
                ok "'$DB_USER' cannot log in with the new password yet - expected, step 5 runs ALTER ROLE to set it"
            elif [ "$CAN_PEER" = "1" ] \
                 && [ "$(peer_psql "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'" postgres)" != "1" ]; then
                ok "Role '$DB_USER' does not exist yet - it is created in step 5"
            else
                warn "Cannot log in as '$DB_USER' to '$DB_NAME' with the password given"
                warn "  Step 5 sets the role password to the one typed now and verifies it before going on"
                warn "  If it still fails there, the cause is pg_hba.conf (needs a 'host $DB_NAME $DB_USER ... scram-sha-256' line)"
            fi
            if [ "$CAN_PEER" = "1" ]; then
                report_db_contents peer
            else
                warn "  Cannot read what is inside '$DB_NAME' from here either - step 5 reports it"
                DB_STATE="exists, contents unknown"
            fi
        fi
    fi
fi

# ---------------------------------------------------------------------------
case "${EXISTING_AGENTS:-}" in
    ''|*[!0-9]*) ;;                       # อ่านจำนวน agent ไม่ได้ = ไม่เดา ไม่เตือนมั่ว
    *)
        if [ "$EXISTING_AGENTS" -gt 0 ] && [ ! -f "$PROJECT_DIR/cert/central/ca.crt" ]; then
            echo ""
            warn "The database has $EXISTING_AGENTS agent(s) registered, but there is no Root CA in cert/central/"
            warn "  This run would issue a BRAND NEW Root CA - and every agent already installed trusts the old one."
            warn "  They would all fail with CERTIFICATE_VERIFY_FAILED and keep retrying in silence."
            echo "     If you still have the old cert/central/ca.crt and ca.key from before, put them back"
            echo "     into $PROJECT_DIR/cert/central/ and run this again - the agents then keep working."
            echo "     Otherwise every agent machine has to be installed again from a fresh package."
            if [ "${ALLOW_NEW_CA:-0}" != "1" ] && [ -t 0 ]; then
                read -rp "  Issue a new Root CA anyway? [y/N] " _ca
                case "${_ca:-n}" in
                    [Yy]*) ;;
                    *) err "Stopped - nothing has been installed or changed"; exit 1 ;;
                esac
            fi
        fi
        ;;
esac

# ก่อนลงมือ: บอกให้เห็นเป็นข้อ ๆ ว่ารอบนี้จะไปแตะอะไรของจริงบ้าง แล้วให้ยืนยันครั้งเดียว
if [ "$RECONFIGURE" = "1" ] && [ "${#CHANGES[@]}" -gt 0 ]; then
    echo ""
    warn "This run changes things that are already live on this machine:"
    for _c in "${CHANGES[@]}"; do echo "       - $_c"; done
    if [ "$DB_TARGET_CHANGED" = "1" ]; then
        echo "     The old database is left exactly as it is - nothing is copied across."
        # สถานะฐานปลายทางมาจากขั้น 1.2 ที่เพิ่งตรวจไปจริง ๆ ไม่ใช่คำเตือนลอย ๆ
        [ -n "$DB_STATE" ] && echo "     '$DB_NAME' right now: $DB_STATE"
        case "$DB_STATE" in
            *empty*|"to be created") echo "     -> the system starts from scratch there (first login admin/admin again)." ;;
            *"existing data"*)       echo "     -> that existing data is what the system will show after the switch." ;;
        esac
    fi
    echo "     Nothing has been touched yet."
    if [ -t 0 ]; then
        read -rp "  Go ahead? [Y/n] " _go
        case "${_go:-y}" in
            [Yy]*) ;;
            *) err "Stopped - nothing was changed"; exit 1 ;;
        esac
    fi
fi

# ---------------------------------------------------------------------------
log "Installing OS packages (apt)"
export DEBIAN_FRONTEND=noninteractive
run_step "apt-get update" apt-get update -qq
run_step "Installing python3-venv / python3-pip / postgresql / redis-server / tar" \
    apt-get install -y -qq python3-venv python3-pip postgresql redis-server tar

# ปิด default redis (:6379) — เรารัน instance ของเราเองผ่าน centralredis (mTLS พอร์ตที่เลือกไว้ ตั้งต้น 6380)
systemctl disable --now redis-server >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
if id "$APP_USER" >/dev/null 2>&1; then
    ok "User '$APP_USER' already exists"
else
    warn "User '$APP_USER' does not exist - creating it as a system account"
    useradd --system --shell /usr/sbin/nologin --home-dir "$PROJECT_DIR" "$APP_USER"
    ok "Created user '$APP_USER'"
fi

# ---------------------------------------------------------------------------
log "Creating venv + installing requirements.txt"
VENV_CREATED=0
if [ -x "$PROJECT_DIR/venv/bin/python" ]; then
    ok "venv already exists"
else
    run_step "Creating venv" python3 -m venv "$PROJECT_DIR/venv"
    VENV_CREATED=1
fi

PIP="$PROJECT_DIR/venv/bin/pip"
# --disable-pip-version-check: ไม่ต้องแอบถาม PyPI ว่ามี pip รุ่นใหม่ไหมตอนท้ายทุกคำสั่ง
PIP_OPTS=(--disable-pip-version-check --no-input
          --timeout "${PIP_TIMEOUT:-15}" --retries "${PIP_RETRIES:-2}")

# เกณฑ์: pip 23 ขึ้นไปลง wheel ทุกตัวใน requirements.txt ได้หมดแล้ว (manylinux ต้องการแค่ >= 20.3)
MIN_PIP_MAJOR=23
PIP_VER="$("$PIP" --version 2>/dev/null | awk '{print $2}')" || true
PIP_MAJOR="${PIP_VER%%.*}"
case "$PIP_MAJOR" in ''|*[!0-9]*) PIP_MAJOR=0 ;; esac

if [ "$VENV_CREATED" = "1" ] || [ "$PIP_MAJOR" -lt "$MIN_PIP_MAJOR" ] || [ "${FORCE_PIP_UPGRADE:-0}" = "1" ]; then
    # ล้มเหลว = เตือนแล้วไปต่อ ไม่ล้มทั้งสคริปต์ — pip ตัวเดิมลง requirements.txt ได้อยู่แล้ว
    run_step "Upgrading pip (this one always goes out to PyPI)" \
        "$PIP" install -q "${PIP_OPTS[@]}" --upgrade pip \
        || warn "Could not upgrade pip - carrying on with pip ${PIP_VER:-unknown}, it installs requirements.txt fine"
else
    ok "pip $PIP_VER is new enough - upgrade skipped (it is the only step that needs PyPI on a re-run; force it with FORCE_PIP_UPGRADE=1)"
fi

run_step "Installing requirements.txt (this is the slow one)" \
    "$PIP" install -q "${PIP_OPTS[@]}" -r "$PROJECT_DIR/requirements.txt"

# ---------------------------------------------------------------------------
log "PostgreSQL: role + database"
systemctl enable --now postgresql >/dev/null 2>&1 || true

PG_SUPERUSER_PASSWORD="${PG_SUPERUSER_PASSWORD:-}"
# PG_SUPERUSER / PG_LOCAL ตั้งไว้แล้วที่ขั้น 1.2 (ตอนเช็กฐานก่อนลงมือ) — ใช้ค่าเดียวกันทั้งสองที่

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

# ---- role: ยังไม่มี = สร้างพร้อมรหัสที่กรอก · มีอยู่แล้ว = "ตรวจ" ว่ารหัสถูกไหม ไม่ใช่ทับ ----
if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_roles WHERE rolname='$DB_USER'")" = "1" ]; then
    PG_ROLE_ERR="$(mktemp)"
    if [ "${SKIP_DB_CHECK:-0}" = "1" ]; then
        rm -f "$PG_ROLE_ERR"
        warn "SKIP_DB_CHECK=1 - role '$DB_USER' left untouched without checking its password"
    elif PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d postgres \
            -tAc "SELECT 1" >/dev/null 2>"$PG_ROLE_ERR"; then
        ok "Role '$DB_USER' already exists and the password given is correct - left untouched"
        rm -f "$PG_ROLE_ERR"
    elif [ "${FORCE_DB_PASSWORD:-0}" = "1" ]; then
        rm -f "$PG_ROLE_ERR"
        pg_su_psql -qc "ALTER ROLE \"$DB_USER\" WITH LOGIN PASSWORD $(pg_quote_lit "$DB_PASSWORD")" >/dev/null
        warn "FORCE_DB_PASSWORD=1 - the password of role '$DB_USER' has been reset to the one typed now"
        warn "  Anything else that logs in as '$DB_USER' with the old password stops working from here on"
    elif grep -qi "password authentication failed" "$PG_ROLE_ERR"; then
        rm -f "$PG_ROLE_ERR"
        err "Wrong database password: role '$DB_USER' exists, but the password given is not its password"
        err "  Nothing has been changed - the role still has the password it had before."
        err "  Either run again and type the right one, or overwrite it on purpose:"
        err "    sudo FORCE_DB_PASSWORD=1 $PROJECT_DIR/setup-server.sh"
        err "  (the old password is in the .env of the previous installation, key DB_PASSWORD)"
        exit 1
    else
        err "Role '$DB_USER' exists but cannot be logged into at $DB_HOST:$DB_PORT - this is not a wrong password:"
        sed 's/^/      /' "$PG_ROLE_ERR" >&2
        rm -f "$PG_ROLE_ERR"
        err "  Usually pg_hba.conf: it needs a line like"
        err "    host $DB_NAME $DB_USER 127.0.0.1/32 scram-sha-256"
        err "  Nothing has been changed. Fix that and run again, or skip the check with SKIP_DB_CHECK=1"
        exit 1
    fi
else
    pg_su_psql -qc "CREATE ROLE \"$DB_USER\" WITH LOGIN PASSWORD $(pg_quote_lit "$DB_PASSWORD")" >/dev/null
    ok "Created role '$DB_USER' with the password given"
fi

if [ "$(pg_su_psql -tAc "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" = "1" ]; then
    # ---- ฐานข้อมูลมีอยู่ก่อนแล้ว: เป็นของระบบนี้จริงหรือของแอปอื่นที่ชื่อบังเอิญตรงกัน? ----
    PUBLIC_TABLES="$(pg_su_psql_db -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='public'")"
    OUR_TABLES="$(pg_su_psql_db -tAc "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND tablename IN ($OUR_TABLES_SQL)")"

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
    DB_OWNER="$(pg_su_psql -tAc "SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='$DB_NAME'")"
    if [ "$DB_OWNER" != "$DB_USER" ]; then
        warn "Database '$DB_NAME' is owned by '$DB_OWNER', not '$DB_USER' - handing it over"
        pg_su_psql  -qc "ALTER DATABASE \"$DB_NAME\" OWNER TO \"$DB_USER\"" >/dev/null
        pg_su_psql_db -qc "GRANT ALL ON SCHEMA public TO \"$DB_USER\"" >/dev/null
        # โอนทีละ object แทน REASSIGN OWNED เพราะ REASSIGN ลามไปทุก object ของ role เดิมในฐานนี้
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

# ---- ที่อยู่ของ central ที่ชุดติดตั้ง agent ใช้ ไม่มีแถวใน DB แล้ว ----

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
    env_sync REDIS_HOST "$BIND_HOST"
    env_sync REDIS_PORT "$REDIS_PORT"
    env_sync REDIS_USER "$REDIS_USER"
    env_sync REDIS_PASS "$REDIS_PASS"

    # path ของ cert ผูกกับที่ตั้งโปรเจกต์ — ย้ายโฟลเดอร์ (INSTALL_DIR) แล้วต้องตามไปด้วย
    env_sync REDIS_CERT "$PROJECT_DIR/cert/central/central.crt"
    env_sync REDIS_KEY  "$PROJECT_DIR/cert/central/central.key"
    env_sync REDIS_CA   "$PROJECT_DIR/cert/central/ca.crt"

    env_sync WEB_BIND_HOST     "$WEB_BIND_HOST"
    env_sync WEBHOOK_BIND_HOST "$WEBHOOK_BIND_HOST"

    # กลุ่ม agent: AGENT_CENTRAL_* คือค่าที่ชุดติดตั้ง agent ใช้จริง (build_site_conf อ่านจากที่นี่)
    env_sync AGENT_CENTRAL_HOST       "$BIND_HOST"
    env_sync AGENT_CENTRAL_REDIS_PORT "$REDIS_PORT"
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
REDIS_PORT=$REDIS_PORT
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

# Values embedded into the agent installer
# AGENT_CENTRAL_* are read straight from here (re-run this script to change them);
# AGENT_REDIS_* are only the fallback - the System Settings page stores those in the database
AGENT_CENTRAL_HOST=$BIND_HOST
AGENT_CENTRAL_REDIS_PORT=$REDIS_PORT
AGENT_REDIS_USERNAME=agent_node
AGENT_REDIS_PASSWORD=$AGENT_REDIS_PASS
EOF
    chmod 600 "$PROJECT_DIR/.env"
    ok "Created .env (JWT/CSRF secrets generated automatically, mode 600)"
fi

# ---------------------------------------------------------------------------
log "Certificates (Redis mTLS + dashboard HTTPS)"
CERT_DIR="$PROJECT_DIR/cert/central"
mkdir -p "$CERT_DIR"

# ---- host ที่ต้องอยู่ใน SAN ----
SAN_HOSTS=("$BIND_HOST")
# dashboard bind อีก IP หนึ่ง = คนเปิดเว็บด้วย IP นั้น ต้องมีใน SAN ด้วย ไม่งั้นเบราว์เซอร์ฟ้องทุกครั้ง
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
CERT_ISSUED=0
CA_CREATED=0
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
    CA_CREATED=1
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
log "redis/users.acl"
ACL_FILE="$PROJECT_DIR/redis/users.acl"
mkdir -p "$PROJECT_DIR/redis"

# รหัสของ "บัญชี agent" ที่จะเขียนลงไฟล์ — ไม่ใช่ค่าจาก .env เสมอไป
acl_pass_of() {  # acl_pass_of USER FILE — รหัส (token ที่ขึ้นต้นด้วย >) ของ user นั้นในไฟล์ ACL
    [ -f "$2" ] || return 0
    awk -v u="$1" '
        $1 == "user" && $2 == u {
            for (i = 3; i <= NF; i++) if (substr($i, 1, 1) == ">") { print substr($i, 2); exit }
        }' "$2" 2>/dev/null || true
}

# หาให้ได้ก่อนว่า "รหัส agent ตัวจริง" รอบนี้คือตัวไหน — ทั้ง users.acl (ขั้นนี้) และ site.conf
ACL_AGENT_PASS="$AGENT_REDIS_PASS"
if [ "$AGENT_PASS_CHANGED" != "1" ] && [ "${FORCE_ACL:-0}" != "1" ]; then
    LIVE_AGENT_PASS="$(acl_pass_of agent_node "$ACL_FILE")"
    # valid_redis_pass กัน placeholder `>123` ที่ยังไม่เคยตั้งจริงไม่ให้ถูกยึดว่าเป็นของจริง
    if [ -n "$LIVE_AGENT_PASS" ] && [ "$LIVE_AGENT_PASS" != "$AGENT_REDIS_PASS" ] \
       && valid_redis_pass "$LIVE_AGENT_PASS"; then
        ACL_AGENT_PASS="$LIVE_AGENT_PASS"
        warn "users.acl holds a different agent password than .env - keeping the one in users.acl"
        warn "  (that is the one the agents actually use; it was most likely changed from the web UI)"
        warn "  To push .env's value in instead: sudo FORCE_ACL=1 $PROJECT_DIR/setup-server.sh"
    fi
fi

# เขียนใหม่เมื่อ: ยังไม่มีไฟล์ / ยังเป็นรหัส placeholder / สั่ง FORCE_ACL=1 /
ACL_WRITTEN=0
if [ ! -f "$ACL_FILE" ] || grep -q '>123 ' "$ACL_FILE" || [ "${FORCE_ACL:-0}" = "1" ] \
   || [ "$REDIS_ACL_CHANGED" = "1" ]; then
    # รหัสที่ไฟล์เดิมถืออยู่ = รหัสที่ agent ข้างนอกใช้จริง ณ ตอนนี้ — ต่างจากที่กำลังจะเขียนเมื่อไหร่
    PREV_ACL_AGENT_PASS="$(acl_pass_of agent_node "$ACL_FILE")"
    if [ -n "$PREV_ACL_AGENT_PASS" ] && [ "$PREV_ACL_AGENT_PASS" != "$ACL_AGENT_PASS" ]; then
        AGENT_PASS_CHANGED=1
    fi

    [ -f "$ACL_FILE" ] && cp -p "$ACL_FILE" "$ACL_FILE.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$ACL_FILE" <<EOF
user $REDIS_USER on >$REDIS_PASS +@all ~* &*
user agent_node on >$ACL_AGENT_PASS -@all +ping +lpush +publish +subscribe ~raw_logs_queue resetchannels &global_commands &agent_commands:* &agent_status &agent_metrics
user default on >$ACL_AGENT_PASS -@all +ping +info +select +rpush +lpush ~raw_logs_queue resetchannels
EOF
    chmod 600 "$ACL_FILE"
    ACL_WRITTEN=1
    ok "Wrote users.acl (3 accounts: $REDIS_USER / agent_node / default)"
else
    warn "users.acl already holds real passwords - left untouched (force a rewrite with FORCE_ACL=1)"

    # ไฟล์นี้ไม่ถูกเขียนทับโดยตั้งใจ (หน้าเว็บเปลี่ยนรหัส agent ได้ และเขียนลงไฟล์นี้อย่างเดียว
    if ! awk -v u="$REDIS_USER" -v p=">$REDIS_PASS" '
            $1 == "user" && $2 == u { for (i = 3; i <= NF; i++) if ($i == p) { found = 1 } }
            END { exit !found }
        ' "$ACL_FILE"; then
        warn "users.acl has no matching password for user '$REDIS_USER' - central will not be able to log in to Redis"
        warn "  Change it from the web UI (System Settings), or rewrite the file: sudo FORCE_ACL=1 $PROJECT_DIR/setup-server.sh"
    fi
fi

# ---------------------------------------------------------------------------
log "Agent installer settings (site.conf)"
SITE_CONF="$PROJECT_DIR/for_Agent/package/site.conf"

# ของเดิมเขียนแค่ตอนยังไม่มีไฟล์ — ย้าย IP แล้วไฟล์นี้จึงค้าง IP เก่าไว้เงียบ ๆ
SITE_HOST="$(env_get CENTRAL_HOST "$SITE_CONF")"
SITE_PORT="$(env_get CENTRAL_REDIS_PORT "$SITE_CONF")"
SITE_PASS="$(env_get REDIS_PASSWORD "$SITE_CONF")"

# เทียบกับ ACL_AGENT_PASS (รหัสตัวจริงที่ users.acl ถืออยู่) ไม่ใช่ค่าจาก .env ที่อาจค้างของเก่า
if [ ! -f "$SITE_CONF" ] || [ "${FORCE_SITE_CONF:-0}" = "1" ] \
   || [ "$SITE_HOST" != "$BIND_HOST" ] || [ "$SITE_PORT" != "$REDIS_PORT" ] \
   || [ "$SITE_PASS" != "$ACL_AGENT_PASS" ]; then
    [ -f "$SITE_CONF" ] && cp -p "$SITE_CONF" "$SITE_CONF.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$SITE_CONF" <<EOF
CENTRAL_HOST="$BIND_HOST"
CENTRAL_REDIS_PORT="$REDIS_PORT"
REDIS_USERNAME="agent_node"
REDIS_PASSWORD="$ACL_AGENT_PASS"
EOF
    chmod 600 "$SITE_CONF"
    if [ -n "$SITE_HOST" ] && [ "$SITE_HOST:$SITE_PORT" != "$BIND_HOST:$REDIS_PORT" ]; then
        ok "Rewrote site.conf (agents now dial $BIND_HOST:$REDIS_PORT, was $SITE_HOST:$SITE_PORT)"
    else
        ok "Wrote site.conf - agent zips embed these values automatically"
    fi
else
    ok "site.conf already matches this run - left untouched"
fi

# ---------------------------------------------------------------------------
log "Setting file ownership to $APP_USER:$APP_GROUP"
mkdir -p "$PROJECT_DIR/redis/data-redis"
chown -R "$APP_USER":"$APP_GROUP" "$PROJECT_DIR"
ok "chown done"

# ---------------------------------------------------------------------------
log "Generating systemd units + redis-mtls.conf, then installing them"
APP_USER="$APP_USER" APP_GROUP="$APP_GROUP" PROJECT_DIR="$PROJECT_DIR" BIND_HOST="$BIND_HOST" \
    WEB_BIND_HOST="$WEB_BIND_HOST" WEBHOOK_BIND_HOST="$WEBHOOK_BIND_HOST" \
    REDIS_PORT="$REDIS_PORT" \
    bash "$PROJECT_DIR/systemd/_gen.sh"

# ★ Redis อ่านทั้ง cert และ aclfile ตอน start ครั้งเดียว แก้ไฟล์เฉย ๆ จึงไม่มีผลกับตัวที่รันอยู่
redis_serving_stale_cert() {
    local served ondisk
    [ -f "$CERT_DIR/central.crt" ] || return 1
    served="$(echo | timeout 5 openssl s_client -connect "$BIND_HOST:${OLD_REDIS_PORT:-$REDIS_PORT}" 2>/dev/null \
        | openssl x509 -noout -fingerprint -sha256 2>/dev/null)" || true
    [ -n "$served" ] || return 1          # ต่อไม่ได้/ยังไม่ start = ไม่มีอะไรให้สรุป
    ondisk="$(openssl x509 -in "$CERT_DIR/central.crt" -noout -fingerprint -sha256 2>/dev/null)" || true
    [ -n "$ondisk" ] || return 1
    [ "$served" != "$ondisk" ]
}

REDIS_RESTART_REASON=""
if [ "$CERT_ISSUED" = "1" ]; then
    REDIS_RESTART_REASON="it is still serving the old certificate"
elif redis_serving_stale_cert; then
    REDIS_RESTART_REASON="the certificate it is serving is not the one in $CERT_DIR (left over from an earlier run)"
fi
if [ "$ACL_WRITTEN" = "1" ]; then
    REDIS_RESTART_REASON="${REDIS_RESTART_REASON:+$REDIS_RESTART_REASON, and }users.acl was rewritten"
fi
# พอร์ตอยู่ใน redis-mtls.conf ซึ่ง Redis อ่านตอน start ครั้งเดียว — ไม่ restart = ยังฟังพอร์ตเก่า
if [ "$PORT_CHANGED" = "1" ]; then
    REDIS_RESTART_REASON="${REDIS_RESTART_REASON:+$REDIS_RESTART_REASON, and }the port moved $OLD_REDIS_PORT -> $REDIS_PORT"
fi
if [ -n "$REDIS_RESTART_REASON" ] && systemctl is-active --quiet centralredis.service; then
    log "Restarting centralredis ($REDIS_RESTART_REASON)"
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

# ป้ายที่ใช้บอกว่า "rule นี้สคริปต์นี้เป็นคนเปิด" — เก็บไว้ใน comment ของ ufw เอง ไม่ใช่ไฟล์ข้างนอก
FW_TAG="SecureLog"

# ไฟล์จำพอร์ตที่เปิดเอง — **เฉพาะ firewalld** ซึ่งไม่มี comment ให้ติดป้าย (ufw ไม่ใช้ไฟล์นี้)
FW_OWNED_FILE="$PROJECT_DIR/.fw-owned-ports"

# ---- ufw: อ่าน rule ที่ ufw จำไว้ ----
fw_rules_for() {  # fw_rules_for PORT — บรรทัด rule ทั้งหมดที่เกี่ยวกับพอร์ตนี้
    local port="$1"
    ufw show added 2>/dev/null | sed -n 's/^ufw //p' | awk -v p="$port" '
        {
            bare = $0
            sub(/ comment .*$/, "", bare)     # ตัด comment ก่อนค้นเลข ไม่งั้นเลขในข้อความก็นับด้วย
            if (bare ~ "(^|[[:space:]])" p "(/tcp|/udp)?([[:space:]]|$)") print
        }'
}

# มี rule ของพอร์ตนี้อยู่แล้วไหม (ของใครก็ตาม)
fw_port_covered() { [ -n "$(fw_rules_for "$1")" ]; }

# rule ของพอร์ตนี้เป็นของสคริปต์ไหม — ดูจากป้ายใน comment
fw_port_is_ours() { fw_rules_for "$1" | grep -q "comment '$FW_TAG"; }

# ---- เปิดพอร์ต ----
fw_allow() {  # fw_allow PORT "คำอธิบาย"
    local port="$1" what="$2"

    case "$FW_KIND" in
        ufw)
            if fw_port_covered "$port"; then
                if fw_port_is_ours "$port"; then
                    ok "$port/tcp already open - rule added by this script earlier, left as is"
                else
                    ok "$port/tcp already allowed by a rule that was here before this script - left as is"
                fi
                FW_OPENED="$FW_OPENED $port"
                return 0
            fi

            if ! ufw allow "$port"/tcp comment "$FW_TAG $what" >/dev/null 2>&1; then
                # ufw ก่อน 0.35 ไม่รู้จัก comment — เปิดพอร์ตให้ได้ แต่ไม่มีป้ายบอกว่าเป็นของเรา
                ufw allow "$port"/tcp >/dev/null 2>&1 \
                    || { warn "ufw could not open $port/tcp ($what) - open it yourself"; return 0; }
                warn "$port/tcp opened, but this ufw cannot store comments - the rule carries no owner tag,"
                warn "  so it will NOT be removed automatically if the port changes later"
            fi
            ;;
        firewalld)
            if firewall-cmd --permanent --query-port="$port"/tcp >/dev/null 2>&1; then
                ok "$port/tcp already allowed by firewalld - left as is"
                FW_OPENED="$FW_OPENED $port"
                return 0
            fi
            firewall-cmd --permanent --add-port="$port"/tcp >/dev/null 2>&1 \
                || { warn "firewalld could not open $port/tcp ($what) - open it yourself"; return 0; }
            # firewalld ไม่มี comment ให้ติดป้าย -> จดไว้ในไฟล์แทน (รูปแบบ: หนึ่งพอร์ตต่อบรรทัด)
            if ! grep -qx "$port" "$FW_OWNED_FILE" 2>/dev/null; then
                echo "$port" >> "$FW_OWNED_FILE"
            fi
            ;;
        *) return 0 ;;
    esac

    ok "$port/tcp open - $what"
    FW_OPENED="$FW_OPENED $port"
}

# ---- ปิดพอร์ตเก่าหลังย้ายพอร์ต Redis ----
fw_close_old_port() {  # fw_close_old_port PORT
    local port="$1"

    case "$FW_KIND" in
        ufw)
            if ! fw_port_covered "$port"; then
                ok "Nothing allows the old port $port any more - nothing to close"
                return 0
            fi

            if ! fw_port_is_ours "$port"; then
                warn "Port $port is still allowed, but by a rule this script did not create:"
                fw_rules_for "$port" | sed 's/^/       ufw /'
                warn "  Left untouched. Close it yourself if you want it closed:"
                warn "    sudo ufw status numbered   then   sudo ufw delete <number>"
                return 0
            fi

            ufw --force delete allow "$port"/tcp >/dev/null 2>&1 || true

            if fw_port_is_ours "$port"; then
                warn "Could not remove the $port/tcp rule this script had added - remove it yourself:"
                warn "    sudo ufw delete allow $port/tcp"
                return 0
            fi

            ok "Closed $port/tcp - the rule this script had added is gone"
            if fw_port_covered "$port"; then
                warn "  Port $port is still allowed by a rule that was here before - left as is:"
                fw_rules_for "$port" | sed 's/^/       ufw /'
            fi
            ;;

        firewalld)
            if ! firewall-cmd --permanent --query-port="$port"/tcp >/dev/null 2>&1; then
                ok "Nothing allows the old port $port any more - nothing to close"
                return 0
            fi
            if ! grep -qx "$port" "$FW_OWNED_FILE" 2>/dev/null; then
                warn "Port $port/tcp is still allowed by firewalld, but this script did not open it - left as is"
                warn "  Close it yourself: sudo firewall-cmd --permanent --remove-port=$port/tcp && sudo firewall-cmd --reload"
                return 0
            fi
            if firewall-cmd --permanent --remove-port="$port"/tcp >/dev/null 2>&1; then
                sed -i "/^$port\$/d" "$FW_OWNED_FILE" 2>/dev/null || true
                ok "Closed $port/tcp - the rule this script had added is gone (a --reload runs below)"
            else
                warn "Could not remove $port/tcp from firewalld - do it yourself"
            fi
            ;;
    esac
}

case "$FW_KIND" in
    skip)
        warn "SKIP_FIREWALL=1 - firewall left alone (open tcp $REDIS_PORT/8000/8080 yourself if one sits in front)"
        FW_SUMMARY="skipped (SKIP_FIREWALL=1)"
        ;;
    none)
        warn "Neither ufw nor firewalld found on this machine - nothing to open"
        warn "If something else filters traffic, open tcp $REDIS_PORT (agents), 8000 (dashboard), 8080 (LINE webhook)"
        FW_SUMMARY="no ufw/firewalld - nothing opened"
        ;;
    *)
        fw_allow "$REDIS_PORT" "Redis mTLS (agents send logs in)"

        # ย้ายพอร์ตแล้วพอร์ตเก่าไม่มีอะไรฟังอีก — ปิดให้ **เฉพาะ rule ที่สคริปต์นี้เปิดไว้เอง**
        if [ "$PORT_CHANGED" = "1" ]; then
            fw_close_old_port "$OLD_REDIS_PORT"
        fi

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
REDIS_CHECK="skipped"
if [ "$STARTED" -eq 1 ] && [ -x "$PROJECT_DIR/venv/bin/python" ] && [ "$CERT_OK" -eq 1 ]; then
    log "Checking that this machine can actually use its own Redis (mTLS + ACL)"
    sleep 2      # เผื่อ centralredis ที่เพิ่ง start/restart ไปเมื่อครู่ยังรับ connection ไม่ทัน
    REDIS_CHECK="$("$PROJECT_DIR/venv/bin/python" - <<PYCHK 2>&1 || true
import sys
try:
    import redis
except Exception:
    print("skipped (the redis library is not in the venv)"); sys.exit(0)
try:
    c = redis.Redis(
        host="$BIND_HOST", port=$REDIS_PORT, ssl=True,
        ssl_certfile="$CERT_DIR/central.crt", ssl_keyfile="$CERT_DIR/central.key",
        ssl_ca_certs="$CERT_DIR/ca.crt", ssl_cert_reqs="required", ssl_check_hostname=True,
        username="$REDIS_USER", password="$REDIS_PASS",
        socket_connect_timeout=5, socket_timeout=5,
    )
    c.ping()
    print("ok")
except Exception as e:
    print("FAILED: %s" % e)
PYCHK
)"
    case "$REDIS_CHECK" in
        ok)
            ok "Logged in to Redis at $BIND_HOST:$REDIS_PORT over mTLS as '$REDIS_USER' - the services connect the same way"
            ;;
        skipped*)
            warn "Redis check $REDIS_CHECK"
            ;;
        *)
            err "This machine CANNOT use its own Redis - every service will sit in a retry loop:"
            printf '      %s\n' "$REDIS_CHECK" >&2
            err "  The services are running but nothing works until this is fixed. Usually one of:"
            err "    - centralredis still serving an older certificate:  sudo systemctl restart centralredis.service"
            err "    - users.acl and .env holding different passwords:   sudo FORCE_ACL=1 $PROJECT_DIR/setup-server.sh"
            err "  Then check again with:  journalctl -u securelog-agent-monitor -n 20"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
log "Done - summary"
echo "  Location      : $PROJECT_DIR"
echo "  Runs as user  : $APP_USER"
echo "  Central addr  : $BIND_HOST  (agents reach Redis at $BIND_HOST:$REDIS_PORT)"
# เว็บ bind IP เดียว = ต้องเข้าด้วย IP นั้นเท่านั้น (0.0.0.0 ค่อยใช้ที่อยู่ของ central เป็นตัวแทน)
if [ "$WEB_BIND_HOST" = "0.0.0.0" ]; then WEB_URL_HOST="$BIND_HOST"; else WEB_URL_HOST="$WEB_BIND_HOST"; fi
echo "  dashboard     : bind $WEB_BIND_HOST:8000  ->  https://$WEB_URL_HOST:8000"
echo "  LINE webhook  : bind $WEBHOOK_BIND_HOST:8080"
echo "  database      : $DB_NAME (owner $DB_USER) at $DB_HOST:$DB_PORT${DB_STATE:+  [$DB_STATE]}"
echo "  firewall      : $FW_SUMMARY"
case "$REDIS_CHECK" in
    ok)       echo "  Redis (mTLS)  : reachable and logged in" ;;
    skipped*) echo "  Redis (mTLS)  : $REDIS_CHECK" ;;
    *)        echo "  Redis (mTLS)  : ** NOT USABLE - see the error above **" ;;
esac
echo ""
if [ "$STARTED" -eq 1 ]; then
    ok "First login is admin/admin"
else
    warn "Services not started because certs are incomplete - check $CERT_DIR then run: sudo $PROJECT_DIR/systemd/install.sh"
fi

# ---------------------------------------------------------------------------
AGENT_COUNT_KNOWN=0
case "${EXISTING_AGENTS:-}" in ''|*[!0-9]*) ;; *) AGENT_COUNT_KNOWN=1 ;; esac
if [ "$ENV_EXISTED" = "1" ] || { [ "$AGENT_COUNT_KNOWN" = "1" ] && [ "$EXISTING_AGENTS" -gt 0 ]; }; then
    AGENT_REASONS=()
    if [ "$IP_CHANGED" = "1" ]; then
        AGENT_REASONS+=("the central address moved $CURRENT_BIND_HOST -> $BIND_HOST (they still dial $CURRENT_BIND_HOST)")
    fi
    if [ "$PORT_CHANGED" = "1" ]; then
        AGENT_REASONS+=("the Redis port moved $OLD_REDIS_PORT -> $REDIS_PORT (they still dial ${CURRENT_BIND_HOST:-the central}:$OLD_REDIS_PORT)")
    fi
    if [ "$AGENT_PASS_CHANGED" = "1" ]; then
        AGENT_REASONS+=("the Redis password of the agent accounts changed (they authenticate with the old one)")
    fi
    if [ "$CA_CREATED" = "1" ]; then
        AGENT_REASONS+=("a new Root CA was issued - the certificates in their packages are signed by the old CA,"$'\n'"         so they fail with CERTIFICATE_VERIFY_FAILED and retry forever without saying anything")
    fi

    echo ""
    if [ "${#AGENT_REASONS[@]}" -gt 0 ]; then
        if [ "$AGENT_COUNT_KNOWN" = "1" ] && [ "$EXISTING_AGENTS" -gt 0 ]; then
            warn "The $EXISTING_AGENTS agent machine(s) registered in the database have to be installed again:"
        else
            warn "Agent machines (client side) have to be installed again - this run changed what they rely on:"
        fi
        for _r in "${AGENT_REASONS[@]}"; do echo "       - $_r"; done
        echo ""
        echo "     Until that is done they keep retrying quietly and their logs never arrive here."
        echo "     On EVERY agent machine, one of these:"
        echo "       - open the dashboard -> download a fresh package for that agent -> unzip it there"
        echo "         and run:  sudo ./setup.sh      (it rewrites everything, this is the safe one)"
        echo "       - or, in the agent folder, edit site.conf (CENTRAL_HOST / CENTRAL_REDIS_PORT / REDIS_PASSWORD) and"
        echo "         re-run:   sudo ./setup.sh"
        echo "     Editing one file by hand is not enough - those values sit in BOTH"
        echo "     <agent dir>/agent_config.json and /etc/filebeat/filebeat.yml; setup.sh writes both."
        if [ "$IP_CHANGED" = "1" ]; then
            echo "     Updated on this machine already: cert SAN, REDIS_HOST/AGENT_CENTRAL_HOST in .env,"
            echo "     site.conf and the systemd units."
        fi
    else
        ok "Agent machines: nothing they depend on changed - the agents already installed keep working as is"
    fi
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
