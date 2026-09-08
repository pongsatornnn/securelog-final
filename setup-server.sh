#!/usr/bin/env bash
#
set -euo pipefail

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '  \033[1;32m[OK]\033[0m %s\n' "$*"; }
warn() { printf '  \033[1;33m[!]\033[0m %s\n' "$*"; }
SETUP_ERRORS=0
ENV_WRITTEN=0
SITE_CONF_WRITTEN=0
err()  { SETUP_ERRORS=$((SETUP_ERRORS + 1)); printf '  \033[1;31m[ERR]\033[0m %s\n' "$*" >&2; }
# ข้อความแดงที่ "ไม่ใช่ error" (เป็นสิ่งที่ต้องไปทำต่อ) — ไม่ให้ไปนับรวมกับความล้มเหลวของสคริปต์
red()  { printf '  \033[1;31m%s\033[0m\n' "$*"; }

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
preload_env ROOT_PATH            ROOT_PATH
AGENT_CENTRAL_CANDIDATES="${AGENT_CENTRAL_CANDIDATES:-}"
preload_env AGENT_CENTRAL_CANDIDATES AGENT_CENTRAL_CANDIDATES
preload_env FORWARDED_ALLOW_IPS  FORWARDED_ALLOW_IPS

# ---- ทางเข้าเว็บ: ค่าที่ระบบใช้อยู่ตอนนี้ (ไว้เป็นค่าตั้งต้นของคำถาม/ของการรันซ้ำ) ----
OLD_ROOT_PATH="$(env_get ROOT_PATH "$ENV_FILE")"
OLD_FORWARDED_ALLOW="$(env_get FORWARDED_ALLOW_IPS "$ENV_FILE")"

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
    for _v in DB_HOST DB_PORT DB_NAME DB_USER DB_PASSWORD REDIS_USER REDIS_PASS AGENT_REDIS_PASS ROOT_PATH; do
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
    # ตอบว่างแล้วไม่มีค่าตั้งต้น = ถามใหม่ ไม่ใช่จบสคริปต์ (ตอนติดตั้งใหม่ คำถามรหัสฐานข้อมูล
    # ไม่มีค่าตั้งต้นให้ เผลอกด Enter ทีเดียวเคยต้องเริ่มตอบใหม่ทั้งชุด)
    # read คืนค่าไม่ใช่ 0 เมื่อเจอ EOF (สคริปต์อื่นป้อนคำตอบมาแล้วหมด) — ตรงนั้นต้องออก ไม่ใช่วนไม่รู้จบ
    while :; do
        read -rp "  $prompt${def:+ [$def]}: " ans \
            || { err "$var must not be empty (no answer left to read)"; exit 1; }
        ans="${ans:-$def}"
        [ -n "$ans" ] && break
        echo "    !! $var must not be empty - type a value"
    done
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
    # เหตุผลเดียวกับ ask() — ตอบว่างแล้วไม่มีค่าเดิมให้ใช้ ก็ถามใหม่
    while :; do
        read -rsp "  $prompt${def:+ (Enter = keep the current one)}: " ans \
            || { echo; err "$var must not be empty (no answer left to read)"; exit 1; }
        echo
        ans="${ans:-$def}"
        [ -n "$ans" ] && break
        echo "    !! $var must not be empty - type a value"
    done
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
WEAK_SECRETS=""   # รหัสที่อยู่ใน .env อยู่แล้วแต่ไม่ผ่านกติกา (เตือนซ้ำตอนจบ ไม่ขวางการทำงาน)
ask_redis_secret() {  # ask_redis_secret VAR "คำอธิบายบัญชี" ["รหัสเดิม"]
    local var="$1" what="$2" def="${3:-}" cur ans ans2 choice mode
    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    if [ -n "$cur" ]; then
        if ! valid_redis_pass "$cur"; then
            # ค่ามาจาก .env = รหัสที่ระบบ "ใช้อยู่จริง" ตอนนี้ (เครื่องที่ลงไว้ก่อนกติกานี้จะมี)
            # ถ้าตายตรงนี้ = รันสคริปต์ไม่ได้อีกเลยทั้งที่มาทำเรื่องอื่น เช่นแก้ root path -> เตือนแล้วไปต่อ
            if [ "$(value_source "$var")" = ".env" ]; then
                warn "$var in .env does not meet the rules (min 12 chars; allowed: A-Z a-z 0-9 _-.~@%+=:,/)"
                warn "  keeping it - it is the password the running system uses right now"
                warn "  rotate it when you can - on the dashboard: System Settings"
                WEAK_SECRETS="$WEAK_SECRETS $var"
            else
                # ค่าที่เพิ่งส่งเข้ามาทาง env = ตั้งใจจะเปลี่ยนรหัส -> ไม่ยอมให้ตั้งรหัสอ่อน
                err "$var fails the rules (min 12 chars; allowed: A-Z a-z 0-9 _-.~@%+=:,/)"
                exit 1
            fi
        fi
        ok "$var = ****** (from $(value_source "$var"))"
        return
    fi
    if [ ! -t 0 ]; then
        [ -n "$def" ] || { err "No tty and $var was not preset"; exit 1; }
        eval "$var=\$def"; ok "$var = ****** (unchanged, no tty)"; return
    fi

    # ให้เลือกเป็นข้อ ๆ ว่าจะเอารหัสแบบไหน (ของเดิมต้องรู้เองว่า Enter = ใช้ค่าเดิม, พิมพ์ new = สุ่ม)
    echo ""
    echo "  Redis password for $what"
    if [ -n "$def" ]; then
        echo "    1) Keep the one it uses now   <- default"
        echo "    2) Generate a strong one for me"
        echo "    3) Type it myself"
    else
        echo "    1) Generate a strong one for me   <- default"
        echo "    2) Type it myself"
    fi

    while :; do
        read -rp "  Pick a number [1]: " choice
        choice="${choice:-1}"
        if [ -n "$def" ]; then
            case "$choice" in
                1)  # ใช้ของเดิม — ถ้าของเดิมอ่อนก็เตือนไว้ (แต่ไม่ขวาง คนเลือกเองว่าจะเก็บไว้)
                    if ! valid_redis_pass "$def"; then
                        warn "The current $var does not meet the rules (min 12 chars) - keeping it as you asked"
                        WEAK_SECRETS="$WEAK_SECRETS $var"
                    fi
                    eval "$var=\$def"
                    ok "Kept the password this account already uses"
                    return ;;
                2) mode=generate; break ;;
                3) mode=type; break ;;
                *) echo "    !! No option '$choice' in the list (1-3) - try again" ;;
            esac
        else
            case "$choice" in
                1) mode=generate; break ;;
                2) mode=type; break ;;
                *) echo "    !! No option '$choice' in the list (1-2) - try again" ;;
            esac
        fi
    done

    if [ "$mode" = "generate" ]; then
        ans="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"
        GENERATED_PASSWORDS="$GENERATED_PASSWORDS$var=$ans"$'\n'
        ok "Password generated (shown at the end - save it)"
    else
        while :; do
            read -rsp "  Type the password (12+ chars; A-Z a-z 0-9 _-.~@%+=:,/): " ans; echo
            if ! valid_redis_pass "$ans"; then
                err "Must be at least 12 chars; allowed: A-Z a-z 0-9 _-.~@%+=:,/ - try again"
                continue
            fi
            read -rsp "  Type it again: " ans2; echo
            [ "$ans" = "$ans2" ] && break
            err "The two do not match - try again"
        done
    fi
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

# ตอบเป็นตัวเลข = systemd กับ chown ตีเป็น uid เงียบ ๆ (พิมพ์ 3 = บริการไปรันเป็น 'sys' ทั้งชุด
# และโปรเจกต์ทั้งโฟลเดอร์ถูก chown ตามไปด้วย) — เจอมาแล้วตอนทดสอบ จึงกันไว้ตรงนี้
case "$APP_USER" in
    *[!0-9]*) ;;
    *) err "APP_USER='$APP_USER' is a number - systemd would read it as a uid; type the user NAME"; exit 1 ;;
esac
getent passwd "$APP_USER" >/dev/null 2>&1 \
    || { err "There is no user '$APP_USER' on this machine - create it first, or answer with an existing one"; exit 1; }

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

# ---- root path ของเว็บ + ความพร้อมสำหรับ reverse proxy ----
# ฝั่งนี้ทำแค่ "ระบบ" ให้พร้อม — ใครจะเอา nginx/HAProxy/Apache มาครอบทีหลังก็ทำได้เลย
norm_root_path() {  # "xxx" / "/xxx/" / "//a//b//" -> "/xxx", "/a/b" · "/" หรือว่าง = อยู่ที่ราก
    local v="$1"
    v="${v//\"/}"; v="${v//\'/}"
    v="$(printf '%s' "$v" | tr -s '/' | sed 's#^[[:space:]]*##; s#[[:space:]]*$##; s#^/*##; s#/*$##')"
    [ -n "$v" ] && printf '/%s' "$v" || printf ''
}

# ค่าตั้งต้นของคำถาม: ค่าที่ส่งมาทาง env > ค่าที่อยู่ใน .env ตอนนี้ > "/" (อยู่ที่ราก)
# ใช้ OLD_ROOT_PATH เป็นหลักเพราะอ่านจาก .env ตั้งแต่ก่อนโหมด "ตั้งค่าใหม่ทั้งหมด" จะ unset ตัวแปรทิ้ง
ROOT_PATH_DEFAULT="${ROOT_PATH:-${OLD_ROOT_PATH:-/}}"
[ -n "$ROOT_PATH_DEFAULT" ] || ROOT_PATH_DEFAULT="/"

# มีคนนั่งตอบอยู่ = ถามทุกครั้ง โดยเอาค่าที่ใช้อยู่เป็นค่าตั้งต้น (ไม่งั้นแก้ root path ไม่ได้เลย)
if [ -t 0 ]; then
    case "$FROM_ENV_FILE" in
        *" ROOT_PATH "*) unset ROOT_PATH ;;
    esac
fi

# รันซ้ำแบบไม่มี tty และไม่ได้สั่งอะไรมา = คงค่าเดิมไว้ (ไม่ต้องเดา)
if [ -z "${ROOT_PATH:-}" ] && [ ! -t 0 ] && [ "$ENV_EXISTED" = "1" ]; then
    ROOT_PATH="$OLD_ROOT_PATH"
    ok "ROOT_PATH = ${ROOT_PATH:-/} (from .env)"
else
    ask ROOT_PATH "Root path of the dashboard - / for the whole site, or a sub-path like /securelog" \
        "$ROOT_PATH_DEFAULT"
fi
ROOT_PATH="$(norm_root_path "$ROOT_PATH")"
if [ -n "$ROOT_PATH" ]; then
    printf '%s' "$ROOT_PATH" | grep -qE '^(/[A-Za-z0-9._~-]+)+$' \
        || { err "Root path '$ROOT_PATH' has characters that do not belong in a URL path"; exit 1; }
    ok "The dashboard will live under $ROOT_PATH/ (cookies get tied to that path too)"
else
    ok "The dashboard will live at / (the way it has always been)"
fi

# ---- เตรียมพร้อมสำหรับ reverse proxy เสมอ (ไม่ต้องถาม) ----
# ตั้ง FORWARDED_ALLOW_IPS ไว้ตั้งแต่แรก = วันไหนเอา nginx/HAProxy มาครอบก็ใช้ได้ทันที ไม่ต้องรื้อ
# ไม่มี proxy ก็ไม่เสียอะไร: uvicorn เชื่อ X-Forwarded-For เฉพาะที่มาจาก IP ในรายการนี้เท่านั้น
# request ที่วิ่งตรงมาจากเครือข่ายยังถูกอ่าน IP จาก TCP ตามปกติ
FORWARDED_ALLOW_IPS="${FORWARDED_ALLOW_IPS:-${OLD_FORWARDED_ALLOW:-127.0.0.1}}"
printf '%s' "$FORWARDED_ALLOW_IPS" | grep -qE '^[0-9A-Fa-f.:*,[:space:]-]+$' \
    || { err "FORWARDED_ALLOW_IPS='$FORWARDED_ALLOW_IPS' should be IP addresses separated by commas"; exit 1; }

PROXY_IS_LOCAL=1
case "$FORWARDED_ALLOW_IPS" in
    127.0.0.1|localhost|::1) ;;
    *) PROXY_IS_LOCAL=0 ;;
esac
if [ "$PROXY_IS_LOCAL" = "1" ]; then
    ok "Ready for a reverse proxy on this host (trusts X-Forwarded-For from $FORWARDED_ALLOW_IPS)"
else
    ok "Ready for a reverse proxy at $FORWARDED_ALLOW_IPS (trusts X-Forwarded-For from there)"
fi

# ---- IP ที่ dashboard ฟัง (คำถามเดิม) ----
_web_default="${WEB_DEFAULT:-$BIND_HOST}"
pick_bind_host WEB_BIND_HOST \
    "dashboard (HTTPS :8000) - which IP to listen on" "$_web_default" 1 \
    "127.0.0.1 = only a proxy running on this host can reach it; 0.0.0.0 = all interfaces"

# proxy อยู่คนละเครื่องแต่ฟังแค่ loopback = proxy ต่อไม่ถึงตลอดกาล
if [ "$PROXY_IS_LOCAL" = "0" ] && [ "$WEB_BIND_HOST" = "127.0.0.1" ]; then
    err "The proxy at $FORWARDED_ALLOW_IPS is not on this host, but the dashboard would listen on 127.0.0.1 only"
    err "  it could never reach it - bind the dashboard to an IP that $FORWARDED_ALLOW_IPS can dial"
    exit 1
fi

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
# ย้ายที่อยู่ของ central: agent ตามมาเองยังไง
#
# agent คุยกับ central ได้ทางเดียวคือผ่าน Redis ของ central เอง — พอที่อยู่เดิมตาย ช่องทางนั้น
# ตายไปด้วย สั่งอะไรทีหลังไม่มีใครได้ยิน จึงต้องฝากที่อยู่ใหม่ไว้ "ตอนที่ยังคุยกันได้" เท่านั้น
#
# สคริปต์นี้ไม่ยุ่งกับการตั้งค่าเครือข่ายของเครื่อง — หน้าที่นั้นเป็นของแอดมิน (netplan)
# ที่นี่ทำแค่บอก agent ว่าที่อยู่ใหม่คืออะไร แล้วบอกแอดมินว่าต้องไปทำอะไรต่อ
#
#   live   = ที่อยู่ใหม่อยู่บนเครื่องนี้แล้ว -> ประกาศเฉย ๆ ใช้งานต่อได้ทันที
#   notify = ที่อยู่ใหม่ยังไม่มีบนเครื่อง   -> ประกาศไว้ก่อน แล้วเตือนให้ไปตั้ง IP เอง
#   skip   = ยังไม่มี agent ในระบบ         -> ไม่ต้องทำอะไร
MIGRATE_MODE="skip"

host_has_ip() {  # host_has_ip IP — เครื่องนี้ถือ IP นี้อยู่แล้วไหม
    # ไม่จำกัด scope global เพราะ 127.0.0.1 อยู่ scope host — ไม่นับจะกลายเป็น "เครื่องไม่มีที่อยู่นี้"
    ip -4 -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 \
        | grep -qx "$1"
}

looks_like_ipv4() {  # looks_like_ipv4 VALUE — ใช่ IPv4 ไหม (ชื่อโฮสต์ตัดสินจาก ip addr ไม่ได้)
    case "$1" in
        ''|*[!0-9.]*|.*|*.|*..*) return 1 ;;
    esac
    [ "$(printf '%s' "$1" | tr -cd . | wc -c)" = "3" ]
}

iface_of_ip() {  # iface_of_ip IP — ชื่อ interface ที่ถือ IP นี้ (ไม่เจอ = คืนค่าว่าง ไม่ใช่ error)
    ip -4 -o addr show scope global 2>/dev/null \
        | awk -v want="$1" '{split($4, a, "/"); if (a[1] == want) {print $2; exit}}' \
        || true
}

iface_toward() {  # iface_toward IP — ขาที่เคอร์เนลจะใช้วิ่งไปหา IP นี้ (ใช้ตอน IP ยังไม่มีบนเครื่อง)
    ip -4 route get "$1" 2>/dev/null \
        | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}' \
        || true
}

prefix_of_iface() {  # prefix_of_iface IFACE — /prefix ของ IPv4 ใบแรก (ไม่มี interface นั้น = ค่าว่าง)
    ip -4 -o addr show dev "$1" scope global 2>/dev/null \
        | awk '{split($4, a, "/"); print a[2]; exit}' \
        || true
}

ip_is_permanent() {  # ip_is_permanent IP — IP นี้จะยังอยู่หลัง reboot ไหม
    # มาจาก DHCP (dynamic) = อยู่ · เขียนไว้ใน netplan = อยู่ · นอกนั้นคือแปะไว้ชั่วคราว หายแน่
    case "$1" in 127.*) return 0 ;; esac      # loopback มากับเคอร์เนล ไม่ต้องเขียนใน netplan
    ip -4 -o addr show scope global 2>/dev/null | grep -q "inet $1/.* dynamic " && return 0
    grep -rqs -- "$1" /etc/netplan/ 2>/dev/null && return 0
    return 1
}

AGENTS_PRESENT=0
case "${EXISTING_AGENTS:-}" in
    ''|*[!0-9]*) ;;
    *) [ "$EXISTING_AGENTS" -gt 0 ] && AGENTS_PRESENT=1 ;;
esac

if [ "$IP_CHANGED" = "1" ] || [ "$PORT_CHANGED" = "1" ]; then
    if [ "$AGENTS_PRESENT" != "1" ]; then
        MIGRATE_MODE="skip"
    elif [ "$IP_CHANGED" != "1" ] || host_has_ip "$BIND_HOST"; then
        MIGRATE_MODE="live"
        [ "$IP_CHANGED" = "1" ] \
            && ok "$BIND_HOST is already on this machine ($(iface_of_ip "$BIND_HOST")) - the agents can move over straight away"
    else
        MIGRATE_MODE="notify"
        warn "This machine does not hold $BIND_HOST yet"
        echo "       The $EXISTING_AGENTS agent(s) will be told the new address while $CURRENT_BIND_HOST still"
        echo "       answers, then move across by themselves once you give this machine $BIND_HOST."
        echo "       How to do that comes at the end of this run."
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

    # ทางเข้าเว็บ: prefix ของ URL + proxy ที่เชื่อได้ (systemd/_gen.sh อ่าน FORWARDED_ALLOW_IPS ไปใส่ unit)
    env_sync ROOT_PATH           "$ROOT_PATH"
    env_sync FORWARDED_ALLOW_IPS "$FORWARDED_ALLOW_IPS"

    # กลุ่ม agent: AGENT_CENTRAL_* คือค่าที่ชุดติดตั้ง agent ใช้จริง (build_site_conf อ่านจากที่นี่)
    env_sync AGENT_CENTRAL_HOST       "$BIND_HOST"
    # คีย์นี้ปกติปล่อยว่าง แต่ต้องโผล่ใน .env ให้เห็น ไม่งั้นไม่มีใครรู้ว่าตั้งได้ (env_sync ข้ามค่าว่าง)
    if grep -qE "^[[:space:]]*AGENT_CENTRAL_CANDIDATES[[:space:]]*=" "$ENV_FILE" 2>/dev/null; then
        env_sync AGENT_CENTRAL_CANDIDATES "$AGENT_CENTRAL_CANDIDATES"
    else
        {
            echo ""
            echo "# Backup addresses of this central, e.g. \"192.168.56.120 central.local\" (space or comma separated)."
            echo "# They go into the cert SAN and into every agent package, so the agents can follow this server"
            echo "# to another IP on their own - see CENTRAL_MOVE.md"
            echo "AGENT_CENTRAL_CANDIDATES=$AGENT_CENTRAL_CANDIDATES"
        } >> "$ENV_FILE"
        ENV_CHANGED="$ENV_CHANGED AGENT_CENTRAL_CANDIDATES"
    fi
    env_sync AGENT_CENTRAL_REDIS_PORT "$REDIS_PORT"
    env_sync AGENT_REDIS_USERNAME     "agent_node"
    env_sync AGENT_REDIS_PASSWORD     "$AGENT_REDIS_PASS"

    if [ -n "$ENV_CHANGED" ]; then
        ENV_WRITTEN=1
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

# URL prefix of the whole dashboard - empty = served at /
# (change it by re-running this script; cookie names follow it automatically)
ROOT_PATH=$ROOT_PATH
# Trust X-Forwarded-For only from these IPs - the installer sets 127.0.0.1 so a local proxy works.
# Empty with a proxy in front = login lockout and rate limit count every user as one.
FORWARDED_ALLOW_IPS=$FORWARDED_ALLOW_IPS

LINE_CHANNEL_ACCESS_TOKEN=
LINE_CHANNEL_SECRET=
GEMINI_API_KEY=

# Values embedded into the agent installer
# AGENT_CENTRAL_* are read straight from here (re-run this script to change them);
# AGENT_REDIS_* are only the fallback - the System Settings page stores those in the database
AGENT_CENTRAL_HOST=$BIND_HOST
# Backup addresses of this central, e.g. "192.168.56.120 central.local" (space or comma separated).
# They go into the cert SAN and into every agent package, so the agents can follow this server
# to another IP on their own - see CENTRAL_MOVE.md
AGENT_CENTRAL_CANDIDATES=$AGENT_CENTRAL_CANDIDATES
AGENT_CENTRAL_REDIS_PORT=$REDIS_PORT
AGENT_REDIS_USERNAME=agent_node
AGENT_REDIS_PASSWORD=$AGENT_REDIS_PASS
EOF
    chmod 600 "$PROJECT_DIR/.env"
    ENV_WRITTEN=2
    ok "Created .env (JWT/CSRF secrets generated automatically, mode 600)"
fi

# ---------------------------------------------------------------------------
log "Certificates (Redis mTLS + dashboard HTTPS)"
CERT_DIR="$PROJECT_DIR/cert/central"
mkdir -p "$CERT_DIR"

# ---- host ที่ต้องอยู่ใน SAN ----
SAN_HOSTS=("$BIND_HOST")
# รอบที่ย้าย IP: เก็บที่อยู่เดิมไว้ใน SAN ด้วย — agent ที่ยังเกาะที่อยู่เดิมอยู่จะได้ไม่ถูกตัดทันที
# ที่ Redis restart ด้วย cert ใบใหม่ (มันมีเวลาให้ย้ายตามอย่างเป็นระเบียบ)
if [ "$IP_CHANGED" = "1" ] && [ -n "$CURRENT_BIND_HOST" ]; then
    SAN_HOSTS+=("$CURRENT_BIND_HOST")
fi
# ที่อยู่สำรองของ central (ไว้ย้าย IP ทีหลังโดย agent ตามเองได้) ต้องอยู่ใน SAN ตั้งแต่ตอนนี้
# ไม่งั้นวันย้ายจริง agent จะเจอ cert ที่ไม่ครอบ IP ใหม่แล้วปฏิเสธการเชื่อมต่อ
for _c in $(printf '%s' "${AGENT_CENTRAL_CANDIDATES:-}" | tr ',' ' '); do
    SAN_HOSTS+=("${_c%%:*}")
done
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

# สิทธิ์ของบัญชี agent — เก็บไว้ที่เดียว ใช้ทั้งตอนเขียนไฟล์และตอนตรวจว่าไฟล์เดิมล้าสมัย
#   ราก: ส่ง log (+lpush ~raw_logs_queue) · ฟังคำสั่ง (+subscribe ช่องคำสั่ง) · ping — ไม่มี +publish
#   selector: เปิด +publish เฉพาะช่อง agent_metrics ที่ agent ต้องรายงานสถานะจริง ๆ
# เหตุผล: ช่อง global_commands / agent_commands:* คือช่องที่ central ใช้สั่งงาน agent ทุกตัว
# ถ้า agent publish ลงช่องนั้นได้ ใครยึดเครื่อง agent ได้เครื่องเดียว (รหัสเป็นรหัสร่วมทุกเครื่อง)
# ก็สั่ง block_ip / unblock_ip / sync_blacklist ทั้งฟลีตได้เหมือน central
ACL_AGENT_PERMS="-@all +ping +lpush +subscribe ~raw_logs_queue resetchannels &global_commands &agent_commands:* (+publish &agent_metrics)"

acl_perms_of() {  # acl_perms_of USER FILE — เอาเฉพาะส่วนสิทธิ์ (ตัด user/ชื่อ/on/รหัส ทิ้ง)
    [ -f "$2" ] || return 0
    awk -v u="$1" '
        $1 == "user" && $2 == u {
            out = ""
            for (i = 5; i <= NF; i++) out = out (out == "" ? "" : " ") $i
            print out; exit
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

# ไฟล์เดิมถือสิทธิ์รุ่นเก่าอยู่ (เช่น agent ยัง publish ลงช่องคำสั่งได้) = ต้องเขียนใหม่ให้ตรงนโยบาย
if [ -f "$ACL_FILE" ] && [ "$(acl_perms_of agent_node "$ACL_FILE")" != "$ACL_AGENT_PERMS" ]; then
    REDIS_ACL_CHANGED=1
    warn "users.acl: agent_node carries an older permission set - rewriting it (the passwords are kept)"
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
user agent_node on >$ACL_AGENT_PASS $ACL_AGENT_PERMS
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
        SITE_CONF_WRITTEN=1
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
# สองโฟลเดอร์นี้ถูกสร้างตอน "ออก agent package ครั้งแรก" — ถ้าครั้งแรกนั้นถูกสั่งด้วย sudo
# (เช่นรัน main/create_agent.py ผ่าน root) โฟลเดอร์จะเป็นของ root แล้วหน้าเว็บที่รันเป็น $APP_USER
# จะสร้าง agent ไม่ได้อีกเลย ตอบ 500 PermissionError — สร้างไว้ก่อนตรงนี้ให้ chown ข้างล่างจัดการ
mkdir -p "$PROJECT_DIR/cert/agent" "$PROJECT_DIR/main/agent_packages"
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

# ---- บอก agent ว่า central ย้ายที่อยู่/พอร์ต ----
# agent เก็บ "รายการที่อยู่ของ central" ไว้ได้หลายที่ (agent_config.json) พอที่อยู่ที่ใช้อยู่ล่ม
# มันจะไล่ลองที่อยู่สำรองเอง — ที่นี่จึงแค่ฝากที่อยู่ใหม่ไว้ตอนที่ยังคุยกันได้ แล้วมันตามมาเอง
#
# ยิง 2 จังหวะ:
#   รอบ 1 ก่อน restart Redis — ผ่านที่อยู่+พอร์ต "เดิม" ตอน agent ยังเกาะอยู่ (ได้ยินแน่)
#          จำเป็นมากตอนเปลี่ยนพอร์ต เพราะพอ Redis ย้ายพอร์ตแล้ว agent จะไม่ได้ยินอะไรอีกเลย
#   รอบ 2 หลัง service ขึ้นครบ — ที่อยู่ใหม่ใช้ได้จริงแล้ว ตัวที่ต่อกลับมาทันจะย้ายทันที
#
# คำสั่งถูกเซ็นด้วย HMAC โดยใช้ secret_token_hash ของ agent ตัวนั้นเป็นกุญแจ (ค่าที่ central
# มีอยู่แล้วใน DB และ agent คำนวณเองได้จาก token ของตัวเอง) และ agent จะยอมย้ายก็ต่อเมื่อ
# ต่อ mTLS ที่อยู่ใหม่ได้จริงเท่านั้น — สั่งลอย ๆ ให้ไปเกาะเครื่องอื่นไม่ได้
AGENTS_ANNOUNCED=0

# รอ agent ต่อกลับมาและย้ายตามได้นานสุดเท่านี้ (รวมทั้งรอบประกาศที่สองและตอนทำตารางสถานะ)
# หมดเวลาแล้วจบเลย ไม่ต้องรอต่อ — ตัวที่ยังไม่กลับมามีที่อยู่ใหม่อยู่ในรายการสำรองแล้ว
# เดี๋ยวมันย้ายเองตอนที่อยู่เดิมเงียบ ไม่ต้องให้คนนั่งเฝ้าหน้าจอ
AGENT_WAIT_SECONDS=60
AGENT_WAIT_UNTIL=0

agent_wait_left() {  # เหลือกี่วินาทีในโควตารอ agent (0 = หมดเวลาแล้ว)
    local left
    [ "$AGENT_WAIT_UNTIL" -gt 0 ] || { printf '0'; return 0; }
    left=$(( AGENT_WAIT_UNTIL - $(date +%s) ))
    [ "$left" -gt 0 ] && printf '%s' "$left" || printf '0'
}

agent_key_file() {  # เขียน "agent_id<TAB>secret_token_hash" ของ agent ที่ยัง active ลงไฟล์ 600
    local f
    f="$(mktemp)"
    chmod 600 "$f"
    app_psql "select agent_id || E'\t' || secret_token_hash from agents where is_active" > "$f" 2>/dev/null
    sed -i '/^[[:space:]]*$/d' "$f"
    printf '%s' "$f"
}

announce_central_move() {  # announce_central_move WAIT [ที่อยู่ที่ใช้ส่ง] [พอร์ตที่ใช้ส่ง]
    local waited="${1:-0}" via="${2:-$BIND_HOST}" via_port="${3:-$REDIS_PORT}"
    local keys out rc=0

    [ "$IP_CHANGED" = "1" ] || [ "$PORT_CHANGED" = "1" ] || return 0
    [ "$MIGRATE_MODE" != "skip" ] || return 0
    [ -x "$PROJECT_DIR/venv/bin/python" ] || return 0
    [ -n "$via" ] || return 0
    case "${EXISTING_AGENTS:-}" in ''|*[!0-9]*) return 0 ;; esac
    [ "$EXISTING_AGENTS" -gt 0 ] || return 0
    systemctl is-active --quiet centralredis.service || return 0

    # ประกาศได้ก็ต่อเมื่อต่อ Redis ผ่านที่อยู่ "$via" ได้ — ถ้าเครื่องยังไม่มีที่อยู่นั้น (ย้าย IP แล้วยัง
    # ไม่ได้ตั้งค่าเครือข่าย) ก็ไม่ต้องเสียเวลาลอง รอบแรกที่ยิงผ่านที่อยู่เดิมทำหน้าที่ครบแล้ว
    case "$via" in
        *[0-9].[0-9]*)
            if ! host_has_ip "$via"; then
                [ "$waited" = "0" ] \
                    || log "Not announcing again over $via - this machine does not hold that address yet"
                return 0
            fi ;;
    esac

    keys="$(agent_key_file)"
    if [ ! -s "$keys" ]; then rm -f "$keys"; return 0; fi

    log "Telling the agents that central is now $BIND_HOST:$REDIS_PORT"

    out="$("$PROJECT_DIR/venv/bin/python" - <<PYMOVE 2>&1 || rc=$?
import hashlib, hmac, json, os, secrets, sys, time

try:
    import redis
except Exception:
    print("skipped (the redis library is not in the venv)"); sys.exit(2)

AGENTS = []
for line in open("$keys", encoding="utf-8"):
    parts = line.rstrip("\n").split("\t")
    if len(parts) == 2 and parts[0] and parts[1]:
        AGENTS.append((parts[0].strip(), parts[1].strip()))

if not AGENTS:
    print("no active agent in the database"); sys.exit(2)

try:
    r = redis.Redis(
        host="$via", port=$via_port, ssl=True,
        ssl_certfile="$CERT_DIR/central.crt", ssl_keyfile="$CERT_DIR/central.key",
        ssl_ca_certs="$CERT_DIR/ca.crt", ssl_cert_reqs="required", ssl_check_hostname=True,
        username="$REDIS_USER", password="$REDIS_PASS",
        socket_connect_timeout=5, socket_timeout=10,
    )
    r.ping()
except Exception as e:
    print("cannot reach Redis at $via:$via_port - %s" % str(e)[:120]); sys.exit(2)

channels = ["agent_commands:%s" % a for a, _ in AGENTS]
deadline = time.time() + $waited

# เพิ่ง restart Redis ไป agent ยังต่อกลับมาไม่ครบ ประกาศตอนนี้จะไม่มีใครได้ยิน
while time.time() < deadline:
    try:
        if any(n for _, n in r.pubsub_numsub(*channels)):
            break
    except Exception:
        pass
    time.sleep(1)

for agent_id, token_hash in AGENTS:
    now = int(time.time())
    payload = {
        "command": "central_move",
        "agent_id": agent_id,
        "new_host": "$BIND_HOST",
        "new_port": $REDIS_PORT,
        "switch_now": True,
        "issued_at": now,
        "expires_at": now + 900,
        "nonce": secrets.token_hex(16),
    }
    # ต้องเรียงคีย์ + ไม่มีช่องว่าง ให้ตรงกับที่ agent คำนวณ ไม่งั้นลายเซ็นไม่ตรง
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    payload["sig"] = hmac.new(token_hash.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    heard = r.publish("agent_commands:%s" % agent_id, json.dumps(payload))
    print("%-20s %s" % (agent_id, "got it" if heard else "offline (it will follow once the old address stops answering)"))
PYMOVE
)"

    printf '%s\n' "$out" | sed 's/^/       /'
    rm -f "$keys"

    case "$rc" in
        0) AGENTS_ANNOUNCED=1 ;;
        *) [ "$waited" = "0" ] || warn "Could not announce the move - the agents have to be reinstalled by hand" ;;
    esac
    return 0
}

# รอบแรก: ยิงผ่านที่อยู่+พอร์ตเดิมตอน agent ยังเกาะอยู่ ก่อน Redis จะ restart ด้วย cert/พอร์ตใหม่
announce_central_move 0 "${CURRENT_BIND_HOST:-$BIND_HOST}" "${OLD_REDIS_PORT:-$REDIS_PORT}"

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
    QUIET_STATUS=1 bash "$PROJECT_DIR/systemd/install.sh"
    STARTED=1

    # รอบสอง: ตอนนี้ที่อยู่ใหม่พร้อมใช้จริงแล้ว (cert ใบใหม่ + service ขึ้นครบ) agent ที่ต่อกลับมา
    # จะย้ายตามได้ทันทีโดยไม่ต้องรอที่อยู่เดิมล่ม — เริ่มจับเวลาโควตารอ agent ตรงนี้
    AGENT_WAIT_UNTIL=$(( $(date +%s) + AGENT_WAIT_SECONDS ))
    announce_central_move "$(agent_wait_left)"
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
            # ฟังแค่ loopback = rule ของ 8000 ไม่มีความหมายแล้ว ถอนเฉพาะที่สคริปต์นี้เปิดไว้เอง
            fw_close_old_port 8000
            ok "dashboard binds 127.0.0.1 - reachable only from this host (a local proxy, for example)"
        else
            fw_allow 8000 "dashboard HTTPS"
            if [ "$PROXY_IS_LOCAL" = "0" ]; then
                warn "The dashboard is open at :8000 to the whole network while it trusts X-Forwarded-For"
                warn "  from $FORWARDED_ALLOW_IPS - anyone able to reach :8000 directly can fake a client IP. Lock it down:"
                warn "    sudo ufw delete allow 8000/tcp"
                warn "    sudo ufw allow from $FORWARDED_ALLOW_IPS to any port 8000 proto tcp"
            fi
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
CAN_CHECK_REDIS=0
if [ "$STARTED" -eq 1 ] && [ -x "$PROJECT_DIR/venv/bin/python" ] && [ "$CERT_OK" -eq 1 ]; then
    CAN_CHECK_REDIS=1
fi

if [ "$CAN_CHECK_REDIS" = "1" ] && looks_like_ipv4 "$BIND_HOST" && ! host_has_ip "$BIND_HOST"; then
    # เครื่องยังไม่ถือที่อยู่นี้ (ย้าย IP แล้วรอ netplan) — ต่อยังไงก็ไม่ติด ไม่ต้องเสียเวลาลอง
    # แล้วพ่นสีแดงให้ตกใจเปล่า ๆ ของจริงจะได้เช็คตอนที่อยู่มาอยู่บนเครื่องแล้ว
    REDIS_CHECK="not checked yet - waiting for you to apply netplan"
    log "Skipping the Redis self-check - this machine does not hold $BIND_HOST yet"
    echo "       it will work once you apply netplan (see the end of this run)"
elif [ "$CAN_CHECK_REDIS" = "1" ]; then
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
            echo "      The services are running but nothing works until this is fixed. Usually one of:"
            echo "        - centralredis still serving an older certificate:"
            echo "            sudo systemctl restart centralredis.service"
            echo "        - users.acl and .env holding different passwords:"
            echo "            sudo FORCE_ACL=1 $PROJECT_DIR/setup-server.sh"
            echo "      Then check again with:  journalctl -u securelog-agent-monitor -n 20"
            ;;
    esac
fi

# ---------------------------------------------------------------------------
# agent แต่ละตัวกำลังเกาะ central ที่ไหนอยู่ — ค่านี้ agent รายงานมาเองทุกวินาที (agent_runtime)
# จึงใช้ยืนยันได้จริงว่าย้ายตามครบหรือยัง ไม่ใช่เดาจากไฟล์ config
agent_status_table() {  # agent_status_table [ที่อยู่ที่คาดว่า agent ต้องย้ายไป] [วินาทีที่ยอมรอ]
    local keys want="${1:-}" wait_left="${2:-0}"
    [ "$AGENTS_PRESENT" = "1" ] || return 0
    [ -x "$PROJECT_DIR/venv/bin/python" ] || return 0
    [ "$REDIS_CHECK" = "ok" ] || return 0

    keys="$(agent_key_file)"
    if [ ! -s "$keys" ]; then rm -f "$keys"; return 0; fi

    "$PROJECT_DIR/venv/bin/python" - <<PYSTAT 2>/dev/null || true
import json, sys, time

try:
    import redis
except Exception:
    sys.exit(0)

agents = [l.split("\t")[0].strip() for l in open("$keys", encoding="utf-8") if l.strip()]

try:
    r = redis.Redis(
        host="$BIND_HOST", port=$REDIS_PORT, ssl=True,
        ssl_certfile="$CERT_DIR/central.crt", ssl_keyfile="$CERT_DIR/central.key",
        ssl_ca_certs="$CERT_DIR/ca.crt", ssl_cert_reqs="required", ssl_check_hostname=True,
        username="$REDIS_USER", password="$REDIS_PASS",
        socket_connect_timeout=5, socket_timeout=5,
    )
    r.ping()
except Exception:
    sys.exit(0)

def snapshot():
    rows = []
    for agent_id in agents:
        raw = r.get("agent_runtime:%s" % agent_id)
        if not raw:
            rows.append((agent_id, "offline", "-"))
            continue
        try:
            data = json.loads(raw)
        except Exception:
            data = {}
        host = data.get("central_host")
        port = data.get("central_port")
        where = "%s:%s" % (host, port) if host and port else (host or "(older agent - does not report it)")
        rows.append((agent_id, "online", where))
    return rows

# เพิ่งประกาศย้ายไป agent ใช้เวลาสักครู่กว่าจะสลับสายและรายงานที่อยู่ใหม่ — รอให้มันเสร็จก่อน
# ไม่งั้นตารางจะโชว์ที่อยู่เก่าทั้งที่อีกวินาทีเดียวมันก็ย้ายแล้ว
want = "$want"
deadline = time.time() + $wait_left

while want and time.time() < deadline:
    rows = snapshot()
    live = [r_ for r_ in rows if r_[1] == "online"]
    if live and all(r_[2] == want for r_ in live):
        break
    time.sleep(2)

online = 0
print("  %-20s %-9s %s" % ("AGENT", "STATUS", "CENTRAL IT IS ATTACHED TO"))

for agent_id, status, where in snapshot():
    if status == "online":
        online += 1
    print("  %-20s %-9s %s" % (agent_id, status, where))

print("  %d of %d online" % (online, len(agents)))

# หมดโควตารอแล้วแต่ยังไม่ครบ = เรื่องปกติ ไม่ใช่ความผิดพลาด บอกให้ชัดจะได้ไม่ต้องนั่งลุ้น
if want:
    late = [a for a, s, w in snapshot() if s == "online" and w != want]
    if late:
        print("  Not all of them are on %s yet - no need to wait here, they switch by" % want)
        print("  themselves once the old address goes quiet (CENTRAL_MOVE.md)")
PYSTAT

    rm -f "$keys"
}

# ---------------------------------------------------------------------------
# สรุปทีเดียวตอนจบ — ระหว่างทางพิมพ์แค่ว่ากำลังทำอะไร ผลรวมมาอยู่ตรงนี้ที่เดียว
DID=()          # รอบนี้ทำอะไรไปบ้าง
NOTES=()        # เรื่องที่ควรรู้ แต่ไม่ต้องทำอะไร
ACTIONS=()      # เรื่องที่ต้องไปทำต่อ (พิมพ์ตัวแดงท้ายสุด)

if [ "$WEB_BIND_HOST" = "0.0.0.0" ]; then WEB_URL_HOST="$BIND_HOST"; else WEB_URL_HOST="$WEB_BIND_HOST"; fi
DASH_URL="https://$WEB_URL_HOST:8000$ROOT_PATH/"

# ---- รอบนี้ทำอะไรไปบ้าง ----
[ "$IP_CHANGED" = "1" ]   && DID+=("moved the central address $CURRENT_BIND_HOST -> $BIND_HOST")
[ "$PORT_CHANGED" = "1" ] && DID+=("moved the Redis port $OLD_REDIS_PORT -> $REDIS_PORT")
[ "$CA_CREATED" = "1" ]   && DID+=("created a new Root CA")
[ "$CERT_ISSUED" = "1" ]  && DID+=("issued new certificates (SAN $SAN_LINE)")
[ "$ACL_WRITTEN" = "1" ]  && DID+=("wrote redis/users.acl")
[ "$ENV_WRITTEN" = "2" ]  && DID+=("created .env")
[ "$ENV_WRITTEN" = "1" ]  && DID+=("updated .env:$ENV_CHANGED")
[ "$SITE_CONF_WRITTEN" = "1" ] && DID+=("rewrote the agent installer's site.conf")
[ -n "$REDIS_RESTART_REASON" ] && DID+=("restarted centralredis")
[ "$AGENTS_ANNOUNCED" = "1" ]  && DID+=("told the agents where to find central")
[ "$STARTED" -eq 1 ]      && DID+=("installed the systemd units and (re)started the stack")
[ "${#DID[@]}" -gt 0 ]    || DID+=("nothing - everything was already in the state you asked for")

# ---- เรื่องที่ควรรู้ ----
NOTES+=("proxy ready - trusts X-Forwarded-For from $FORWARDED_ALLOW_IPS · sample nginx: REVERSE_PROXY.md")
[ "$PROXY_IS_LOCAL" = "1" ] && NOTES+=("proxy on another host? re-run with FORWARDED_ALLOW_IPS=<its ip>")
[ "$STARTED" -eq 1 ] && [ "$ENV_WRITTEN" = "2" ] && NOTES+=("first login is admin/admin")

if [ -n "$GENERATED_PASSWORDS" ]; then
    NOTES+=("passwords generated this run (not shown again - they are in .env and redis/users.acl):")
    while IFS='=' read -r _k _v; do
        [ -n "$_k" ] && NOTES+=("    $_k = $_v")
    done <<< "$GENERATED_PASSWORDS"
fi

# ---- เรื่องที่ต้องไปทำต่อ ----
if [ -n "$WEAK_SECRETS" ]; then
    ACTIONS+=("Rotate the weak Redis password(s):$WEAK_SECRETS")
    ACTIONS+=("    do it on the dashboard: System Settings - it rewrites redis/users.acl and .env together")
    ACTIONS+=("    (running this script with REDIS_PASS=... does NOT change it: a value already in .env wins)")
    ACTIONS+=("    changing the agent account's password means every agent machine has to be installed again")
fi

# ที่อยู่ที่ระบบชี้ไปต้องเป็นของเครื่องนี้จริง ๆ ไม่งั้น service ตัวเองก็ต่อ Redis ไม่ได้
# สคริปต์ไม่ตั้งค่าเครือข่ายให้ (พลาดแล้วเครื่องหลุดจากเน็ตถาวร กู้ยากกว่าเดิม) — สั่งให้แอดมินไปทำ
if ! host_has_ip "$BIND_HOST" || ! ip_is_permanent "$BIND_HOST"; then
    _iface="$(iface_of_ip "$BIND_HOST")"
    [ -n "$_iface" ] || _iface="$(iface_toward "$BIND_HOST")"
    [ -n "$_iface" ] || _iface="$(iface_of_ip "$CURRENT_BIND_HOST")"
    [ -n "$_iface" ] || _iface="<interface>"
    _prefix="$(prefix_of_iface "$_iface")"

    if host_has_ip "$BIND_HOST"; then
        ACTIONS+=("Make $BIND_HOST permanent on $_iface with netplan, then: sudo netplan try")
        ACTIONS+=("    right now it only lives in memory - the next reboot takes it away and the whole")
        ACTIONS+=("    system stops working, with nothing to point at why")
    else
        ACTIONS+=("Give this machine the address $BIND_HOST/${_prefix:-24} on $_iface with netplan,")
        ACTIONS+=("    then: sudo netplan try")
        ACTIONS+=("    until you do, the services here cannot reach their own Redis")
        [ "$AGENTS_PRESENT" = "1" ] && \
            ACTIONS+=("    (the agents are fine - they were told the new address and follow by themselves)")
    fi
    case "${SSH_CONNECTION:-}" in
        *" $CURRENT_BIND_HOST "*)
            ACTIONS+=("    your ssh session comes in on $CURRENT_BIND_HOST - applying that cuts you off,")
            ACTIONS+=("    so keep this window open or reconnect via $BIND_HOST first") ;;
    esac
fi

# ---- agent: ต้องลงใหม่ไหม ----
AGENT_COUNT_KNOWN=0
case "${EXISTING_AGENTS:-}" in ''|*[!0-9]*) ;; *) AGENT_COUNT_KNOWN=1 ;; esac
AGENT_LINE=""
if [ "$ENV_EXISTED" = "1" ] || { [ "$AGENT_COUNT_KNOWN" = "1" ] && [ "$EXISTING_AGENTS" -gt 0 ]; }; then
    AGENT_REASONS=()
    [ "$IP_CHANGED" = "1" ]   && [ "$AGENTS_ANNOUNCED" != "1" ] && AGENT_REASONS+=("the central address moved (they still dial $CURRENT_BIND_HOST)")
    [ "$PORT_CHANGED" = "1" ] && [ "$AGENTS_ANNOUNCED" != "1" ] && AGENT_REASONS+=("the Redis port moved (they still dial port $OLD_REDIS_PORT)")
    [ "$AGENT_PASS_CHANGED" = "1" ] && AGENT_REASONS+=("the Redis password of the agent accounts changed")
    [ "$CA_CREATED" = "1" ] && AGENT_REASONS+=("a new Root CA was issued - their certificates are signed by the old one")

    if [ "$AGENT_COUNT_KNOWN" = "1" ] && [ "$EXISTING_AGENTS" -eq 0 ]; then
        AGENT_LINE="none registered yet - nothing to do on that side"
    elif [ "${#AGENT_REASONS[@]}" -gt 0 ]; then
        AGENT_LINE="they cannot reach central any more and have to be installed again"
        ACTIONS+=("Install the agent again on every agent machine - this run changed what they rely on:")
        for _r in "${AGENT_REASONS[@]}"; do ACTIONS+=("    - $_r"); done
        ACTIONS+=("    dashboard -> download a fresh package for that agent -> unzip there -> sudo ./setup.sh")
        ACTIONS+=("    (editing one file by hand is not enough: the address sits in agent_config.json AND filebeat.yml)")
        [ "$IP_CHANGED" = "1" ] && \
            ACTIONS+=("    next time run this script BEFORE the old address goes away - then they follow on their own")
    elif [ "$AGENTS_ANNOUNCED" = "1" ]; then
        AGENT_LINE="told the new address - they move over on their own (CENTRAL_MOVE.md)"
    else
        AGENT_LINE="nothing they depend on changed - the ones already installed keep working"
    fi
fi

# ---------------------------------------------------------------------------
LINE_="============================================================"
echo ""
echo "$LINE_"
if [ "$SETUP_ERRORS" -gt 0 ]; then
    printf '  \033[1;31mSETUP FINISHED WITH %d ERROR(S) - scroll up for the [ERR] lines\033[0m\n' "$SETUP_ERRORS"
elif [ "$STARTED" -ne 1 ]; then
    printf '  \033[1;31mSETUP FINISHED - the services are not running\033[0m\n'
elif [ "${#ACTIONS[@]}" -gt 0 ]; then
    printf '  \033[1;32mSETUP COMPLETE\033[0m - but there is something left for you to do (bottom of this page)\n'
else
    printf '  \033[1;32mSETUP COMPLETE\033[0m\n'
fi
echo "$LINE_"

echo ""
echo "  What this run did"
for _d in "${DID[@]}"; do echo "     - $_d"; done

echo ""
echo "  Where things are"
printf '     %-13s %s\n' "dashboard" "$DASH_URL   (bind $WEB_BIND_HOST:8000)"
printf '     %-13s %s\n' "Redis mTLS" "$BIND_HOST:$REDIS_PORT   ($([ "$REDIS_CHECK" = "ok" ] && echo "reachable and logged in" || echo "$REDIS_CHECK"))"
printf '     %-13s %s\n' "database" "$DB_NAME (owner $DB_USER) at $DB_HOST:$DB_PORT${DB_STATE:+  [$DB_STATE]}"
printf '     %-13s %s\n' "LINE webhook" "$WEBHOOK_BIND_HOST:8080"
printf '     %-13s %s\n' "project" "$PROJECT_DIR   (runs as $APP_USER)"
printf '     %-13s %s\n' "root path" "${ROOT_PATH:-/}"
[ -n "$FW_SUMMARY" ] && printf '     %-13s %s\n' "firewall" "$FW_SUMMARY"

echo ""
UNITS_ALL="$(systemctl --no-pager --plain --no-legend list-units --all 'centralredis.service' 'securelog-*.service' 2>/dev/null || true)"
UNITS_N="$(printf '%s\n' "$UNITS_ALL" | grep -c . || true)"
UNITS_BAD="$(printf '%s\n' "$UNITS_ALL" | awk '$3 != "active" || $4 != "running"' || true)"
if [ -z "$UNITS_BAD" ] && [ "${UNITS_N:-0}" -gt 0 ]; then
    printf '  Services       \033[1;32m%s/%s running\033[0m\n' "$UNITS_N" "$UNITS_N"
else
    printf '  Services       %s of %s running - these are not:\n' \
        "$(( ${UNITS_N:-0} - $(printf '%s\n' "$UNITS_BAD" | grep -c . || true) ))" "${UNITS_N:-0}"
    printf '%s\n' "$UNITS_BAD" | awk 'NF {printf "     %-36s %s %s\n", $1, $3, $4}'
    echo "     journalctl -u <name> -n 30      to see why"
fi

if [ -n "$AGENT_LINE" ]; then
    echo ""
    echo "  Agents         $AGENT_LINE"
    if [ "$AGENTS_ANNOUNCED" = "1" ]; then
        agent_status_table "$BIND_HOST:$REDIS_PORT" "$(agent_wait_left)"
    else
        agent_status_table
    fi
fi

if [ "${#NOTES[@]}" -gt 0 ]; then
    echo ""
    echo "  Good to know"
    for _n in "${NOTES[@]}"; do echo "     $_n"; done
fi

if [ "${#ACTIONS[@]}" -gt 0 ]; then
    echo ""
    red "  >>> YOU STILL HAVE TO DO THIS <<<"
    for _a in "${ACTIONS[@]}"; do red "  $_a"; done
fi
echo ""
