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
# - ★ รันซ้ำบนเครื่องที่ติดตั้งไปแล้ว จะถามก่อนว่าจะเอาแบบไหน:
#     1) ใช้ค่าเดิมจาก .env (ค่าตั้งต้น — รันซ้ำเพื่อซ่อม/อัปเดตโค้ด เหมือนพฤติกรรมเดิมทุกอย่าง)
#     2) ตั้งค่าใหม่ทั้งชุด — ถามใหม่ทุกช่องโดยเอาค่าที่ใช้อยู่ตอนนี้เป็น default (Enter = ของเดิม)
#        ไว้เปลี่ยนฐานข้อมูล/ผู้ใช้ postgres/รหัส Redis/IP โดยไม่ต้องไปแก้ .env เอง — และผลของค่าที่
#        เปลี่ยนถูกไล่ทำให้ครบ (users.acl เขียนใหม่ + restart centralredis, ALTER ROLE, cert, unit)
#        preset ได้: RECONFIGURE=1 (ตั้งใหม่) / RECONFIGURE=0 (ใช้ของเดิม)
#     จบแล้วสรุปให้ด้วยว่า agent (client) ที่ลงไปแล้วต้องไปลงใหม่ไหม เพราะอะไร
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
#   FORCE_DB_PASSWORD=1 ยอมทับรหัสของ PostgreSQL role ที่มีอยู่แล้วด้วยรหัสที่กรอกรอบนี้ (ALTER ROLE)
#     ปกติสคริปต์แค่ "ตรวจ" ว่ารหัสถูกไหม กรอกผิดจะหยุด ไม่ไปเปลี่ยนรหัสของ role ทิ้งเงียบ ๆ
#   ALLOW_NEW_CA=1 ยอมออก Root CA ใบใหม่ทั้งที่ฐานยังมี agent ลงทะเบียนอยู่ (ปกติเตือนแล้วถามก่อน —
#     CA ใหม่ = agent ที่ลงไปแล้วต่อไม่ได้ทุกเครื่องด้วย CERTIFICATE_VERIFY_FAILED)
#   FORCE_PIP_UPGRADE=1 บังคับ upgrade pip (ปกติทำเฉพาะตอน venv เพิ่งสร้าง/pip เก่ากว่า 23 — ขั้นนี้
#     ต้องออกไปถาม PyPI ทุกครั้งเสมอ เน็ตช้าเมื่อไหร่คือขั้นที่ดูเหมือนค้าง อ่านคำอธิบายที่ขั้น 4)
#   PIP_TIMEOUT=15 / PIP_RETRIES=2 เวลารอต่อ PyPI ของทุกคำสั่ง pip (default ของ pip เองคือ 15 x 5 + backoff)
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

    local pid i=0 frames='|/-\' spent=0 tail_line hint=''
    "$@" </dev/null >"$STEP_LOG" 2>&1 &
    pid=$!

    printf '\033[?25l'                 # ซ่อน cursor ไม่ให้กระพริบวิ่งตามตัวหมุน
    while kill -0 "$pid" 2>/dev/null; do
        spent=$((SECONDS - start))
        # เกิน 15 วิ = ไม่ใช่ขั้นที่ผ่านไวแล้ว เอาบรรทัดล่าสุดใน log มาแปะข้างตัวหมุนให้เห็นว่า
        # ตอนนี้มันติดอยู่กับอะไร — ของเดิมซ่อนเอาต์พุตไว้หมด ขั้นที่ค้างจึงหน้าตาเหมือนขั้นที่
        # กำลังทำงานปกติเป๊ะ ๆ (เช่น pip ที่นั่ง retry ต่อ PyPI ไม่ติดเงียบ ๆ อยู่เป็นนาที)
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
#   DB_*                 ค่าที่ preset มาทาง env ชนะ · **รหัสของ role ที่มีอยู่แล้วจะไม่ถูกทับ** —
#                        สคริปต์ลองล็อกอินด้วยรหัสที่กรอก ไม่ผ่าน = หยุดพร้อมบอกว่ารหัสผิด
#                        ตั้งใจเปลี่ยนรหัสจริง ๆ: `sudo FORCE_DB_PASSWORD=1 DB_PASSWORD=ใหม่ ./setup-server.sh`
#   REDIS_PASS /         ค่าใน .env ชนะเสมอ — รหัสจริงอยู่ใน users.acl ที่ผูกกับ .env อยู่แล้ว และ
#   AGENT_REDIS_PASS     เปลี่ยนจากหน้าเว็บได้ (System Settings) สคริปต์จึงห้ามไปทับ
#   IP ทั้ง 3 ช่อง       ถามใหม่ทุกครั้งโดยใช้ค่าปัจจุบันเป็น default -> ตอบค่าใหม่ = ย้าย IP ทั้งระบบ
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

# ค่าที่ระบบ "ใช้อยู่ตอนนี้" ตัวอื่น ๆ อ่านเก็บไว้ตั้งแต่ก่อนถาม — ขั้น 6 เขียนทับ .env ไปแล้ว
# ตอนที่เราต้องรู้ว่ารอบนี้เปลี่ยนอะไรไปบ้าง (ต้องเขียน users.acl ใหม่ไหม · agent ต้องลงใหม่ไหม)
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
# แยกกันได้ แต่ค่าตั้งต้นอิงกัน — เครื่องที่ DB อยู่ host อื่น ตั้ง PG_HOST มาแล้ว .env จะตามให้เอง
PG_HOST_PRESET="${PG_HOST:-}"   # ตั้ง PG_HOST มาเองทาง env ไหม — ถ้าใช่ ตอบ DB_HOST ใหม่ก็ไม่ไปแตะ
PG_HOST="${PG_HOST:-${DB_HOST:-localhost}}"
DB_HOST="${DB_HOST:-$PG_HOST}"
DB_PORT="${DB_PORT:-5432}"

# ---------------------------------------------------------------------------
# 0.2) รันซ้ำบนเครื่องที่ติดตั้งไปแล้ว: "ใช้ของเดิม" หรือ "ตั้งค่าใหม่ทั้งชุด"
#
# ของเดิมพอมี .env อยู่แล้ว ค่าที่สคริปต์ดูแล (DB/Redis) ถูกอ่านกลับมาใช้เงียบ ๆ ไม่ถามอีกเลย —
# ดีตอน "รันซ้ำเพื่อซ่อม/อัปเดตโค้ด" แต่ทำอะไรไม่ได้เลยตอนอยากเปลี่ยนของจริง เช่นย้ายไปฐานข้อมูล
# ใหม่ เปลี่ยน user ของ postgres หรือหมุนรหัส Redis — ต้องไปแก้ .env ด้วยมือก่อนแล้วค่อยรัน
#
# ตรงนี้จึงถามก่อนว่าจะเอาแบบไหน แล้วโหมด "ตั้งค่าใหม่" ถามใหม่ทุกช่องโดยเอา **ค่าที่ใช้อยู่จริง
# ตอนนี้เป็น default** — กด Enter ผ่าน = ได้ค่าเดิม เปลี่ยนเฉพาะช่องที่ตั้งใจพิมพ์ทับเท่านั้น
# ผลของค่าที่เปลี่ยนถูกไล่ทำให้ครบจริง ๆ ไม่ใช่แค่เขียนลง .env: รหัส Redis ใหม่ -> users.acl ถูก
# เขียนใหม่ + restart centralredis ให้ · ฐานใหม่ -> สร้าง role/db + ตรวจล็อกอินให้เหมือนติดตั้งใหม่
# preset ผ่าน env: RECONFIGURE=1 (ตั้งใหม่) / RECONFIGURE=0 (ใช้ของเดิม — ค่าตั้งต้น และโหมดไม่มี tty)
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
# ค่าที่ preset มาทาง env ยังชนะเหมือนเดิม ไม่ถูกถามซ้ำ — `sudo DB_PASSWORD=x RECONFIGURE=1 ...`
# จึงยังรันแบบไม่ต้องนั่งตอบได้
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
# ask_secret VAR "คำถาม" ["ค่าเดิม"] — มีค่าเดิม (โหมดตั้งค่าใหม่) กด Enter = ใช้ค่าเดิมต่อ
# ไม่โชว์ค่าเดิมบนจอ (มันคือรหัสผ่าน) จึงบอกแค่ว่า Enter แล้วได้ของเดิม
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
# (ไฟล์ ACL แยก token ด้วยช่องว่าง · .env ตีความ # ' " $ ` \ ! เป็นอย่างอื่น)
valid_redis_pass() {
    local p="$1"
    [ "${#p}" -ge 12 ] || return 1
    printf '%s' "$p" | grep -qE '^[A-Za-z0-9_.~@%+=:,/-]+$' || return 1
    return 0
}

# ถามรหัส Redis — ยังไม่มีรหัสเดิม: Enter = สุ่มให้ · มีรหัสเดิมอยู่ (โหมดตั้งค่าใหม่): Enter = ใช้ของเดิม
# อยากได้ของใหม่ทั้งที่มีของเดิมอยู่ ให้พิมพ์ `new` (สั้นกว่า 12 ตัว จึงไม่มีทางไปชนกับรหัสจริง)
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

# user ที่ unit ซึ่งติดตั้งอยู่ตอนนี้รันด้วย — เป็นค่าตั้งต้นที่ "จริง" กว่า SUDO_USER
# (รันซ้ำด้วยบัญชี sudo คนละคนแล้วเผลอเปลี่ยน User= ของทุก service + chown โปรเจกต์ทั้งก้อน)
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

# DB_HOST/DB_PORT ปกติไม่ใช่คำถาม (ตั้งผ่าน env เอาเมื่อ postgres อยู่คนละเครื่อง) — โหมดตั้งค่าใหม่
# ค่อยถาม เพราะ "ย้ายไปฐานข้อมูลอื่น" บางทีก็คือย้ายไปอีกเครื่องด้วย
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

ask        REDIS_USER "Redis user for central"          "${ENV_DEFAULT[REDIS_USER]:-admin}"

# ชื่อ user ถูกเขียนลง users.acl แบบ token คั่นด้วยช่องว่าง — มีช่องว่าง/อักขระแปลกปนคือไฟล์เสีย
# แล้ว Redis ไม่ start ทั้งตัว (เงื่อนไขเดียวกับรหัสผ่าน ดู main/redis_password_rules.py)
printf '%s' "$REDIS_USER" | grep -qE '^[A-Za-z0-9_.-]{1,64}$' \
    || { err "REDIS_USER='$REDIS_USER' is not valid (A-Z a-z 0-9 _ - . only)"; exit 1; }

ask_redis_secret REDIS_PASS       "account $REDIS_USER (central uses it for Redis)" "${ENV_DEFAULT[REDIS_PASS]:-}"
ask_redis_secret AGENT_REDIS_PASS "agent accounts (agent_node + default)"           "${ENV_DEFAULT[AGENT_REDIS_PASS]:-}"

APP_GROUP="${APP_GROUP:-$APP_USER}"

# ---------------------------------------------------------------------------
# 1.1) รอบนี้เปลี่ยนอะไรไปจากของที่ติดตั้งอยู่บ้าง
#
# ใช้ตัดสินอีก 3 อย่างที่ของเดิมทำไม่ได้เลย เพราะไม่เคยรู้ว่า "เปลี่ยน" กับ "เหมือนเดิม" ต่างกันตรงไหน:
#   1. users.acl ต้องเขียนใหม่ไหม — เปลี่ยนรหัส Redis แล้วไม่เขียน = .env กับ Redis คนละรหัส ตายยกเครื่อง
#   2. centralredis ต้อง restart ไหม — Redis อ่าน aclfile ตอน start ครั้งเดียว แก้ไฟล์เฉย ๆ ไม่มีผล
#   3. ท้ายสคริปต์ต้องบอกไหมว่า agent ที่ลงไปแล้วใช้ต่อไม่ได้ ต้องไปลงใหม่ทุกเครื่อง
# ---------------------------------------------------------------------------
CHANGES=()
DB_TARGET_CHANGED=0
REDIS_ACL_CHANGED=0
AGENT_PASS_CHANGED=0

if [ "$ENV_EXISTED" = "1" ]; then
    # IP ถูกเตือนไปแล้วตอนตอบคำถาม แต่ต้องอยู่ในสรุปก่อนยืนยันด้วย — มันคือข้อที่กระทบหนักที่สุด
    if [ "$IP_CHANGED" = "1" ]; then
        CHANGES+=("central address $CURRENT_BIND_HOST -> $BIND_HOST (cert SAN, .env, site.conf, DB row and units all follow)")
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
# 1.2) เช็กฐานข้อมูล "ก่อนจะไปแตะอะไรทั้งนั้น"
#
# ของเดิมกว่าจะรู้ว่าต่อฐานไม่ได้ ต้องผ่าน apt + สร้าง venv + ลง requirements.txt ไปก่อน
# (หลายนาที) แล้วค่อยไปตายที่ขั้น 5 · และ "ฐานนี้มีข้อมูลอยู่แล้วหรือเปล่า" ก็เป็นแค่บรรทัดเดียว
# แทรกกลางขั้น 5 ซึ่งอ่านผ่านตาไปง่ายมาก
#
# ขั้นนี้จึงถามฐานตั้งแต่ยังไม่ลงมือ **ทุกคำสั่งเป็น SELECT ล้วน ไม่สร้าง ไม่แก้อะไรสักอย่าง**:
#   - server ตอบที่ $DB_HOST:$DB_PORT ไหม
#   - role ที่กรอกล็อกอินได้ไหม ด้วยเส้นทางเดียวกับที่ service จะต่อจริง (TCP + password)
#   - ฐาน $DB_NAME มีอยู่ไหม · เป็นของระบบนี้ไหม · **มีข้อมูลอยู่เท่าไร**
#     (เครื่องที่ลงซ้ำ บางเครื่องมีข้อมูลเดิมอยู่ บางเครื่องเป็นฐานเปล่า — ต้องรู้ตั้งแต่ตอนนี้ว่า
#      กำลังจะใช้ของเดิมต่อหรือเริ่มจากศูนย์ ไม่ใช่ไปเซอร์ไพรส์ตอนเปิดเว็บแล้วเจอ admin/admin
#      กับหน้าว่าง ๆ)
#
# ต่อไม่ได้แล้วสคริปต์ช่วยอะไรไม่ได้จริง ๆ (postgres อยู่อีกเครื่อง) = หยุดตรงนี้เลย ยังไม่มีอะไรถูกแตะ
# ส่วนเคสที่ขั้นถัดไปแก้ให้ได้อยู่แล้ว (ยังไม่ได้ลง postgres / ยังไม่ start / role ยังไม่มี /
# รหัสยังไม่ตรงเพราะรอบนี้ตั้งใจเปลี่ยน) = แค่บอกให้รู้แล้วไปต่อ ไม่ต้องหยุด
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
# เชื่อถือได้กว่าการดูว่ามี .env เดิมไหม (ล้างโฟลเดอร์ทิ้งแต่ฐานยังอยู่ = .env หาย แต่ agent ยังอยู่ครบ)
EXISTING_AGENTS=""

# ต่อด้วย role ของแอปเองทาง TCP = เส้นทางเดียวกับที่ service ต่อจริง (ล้มเหลวคืนค่าว่าง ไม่ทำสคริปต์ตาย)
app_psql() {  # app_psql SQL [DATABASE]
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
        -d "${2:-$DB_NAME}" -tAc "$1" 2>/dev/null || true
}
# สำรองสำหรับตอน role ของแอปยังล็อกอินไม่ได้ — peer auth ไม่ต้องรหัส จึงไม่ต้องไปถามอะไรเพิ่มตอนนี้
# `sudo -n` (ไม่ถามรหัส): สคริปต์นี้รันเป็น root อยู่แล้ว -n จึงไม่เปลี่ยนอะไร แต่กันไม่ให้ขั้น
# "ตรวจเฉย ๆ" กลายเป็นขั้นที่ค้างรอรหัส sudo อยู่บนจอถ้าถูกเรียกในบริบทที่ไม่ใช่ root
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
    #      ฐานไม่มีอยู่จริง   vs.   ฐานมีอยู่แต่เรายังเข้าไปถามไม่ได้
    #    (เจอตอนทดสอบ: กรอกรหัสผิด แล้วรายงานว่า "ฐานยังไม่มี" ทั้งที่ฐานมีข้อมูลเต็มอยู่)
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
# 1.3) ฐานมี agent ลงทะเบียนไว้ แต่ Root CA หายไป = กำลังจะตัด agent ทิ้งทั้งหมดโดยไม่รู้ตัว
#
# เคสนี้เกิดจาก "ลบ/ย้ายโฟลเดอร์โปรเจกต์ทิ้งแล้วลงใหม่ แต่ฐานข้อมูลยังอยู่" ซึ่งหน้าตาเหมือนติดตั้ง
# ใหม่สะอาด ๆ ทุกอย่าง แต่จริง ๆ คือ: ออก Root CA ใบใหม่ -> cert ในชุดติดตั้งของ agent ทุกเครื่อง
# เซ็นด้วย CA เก่า -> ต่อ Redis ไม่ได้ทันทีด้วย CERTIFICATE_VERIFY_FAILED และ retry เงียบ ๆ ตลอดไป
# โดยที่ฝั่ง central ไม่มีอะไรฟ้องเลยว่าหายไปกี่เครื่อง
#
# ถ้ายังเก็บ ca.crt/ca.key ใบเก่าไว้ที่ไหนสักแห่ง เอากลับมาวางแล้วรันใหม่ = agent เดิมใช้ต่อได้เลย
# ไม่ต้องไล่ลงใหม่ทุกเครื่อง จึงต้องถามตรงนี้ ก่อนที่ขั้น 7 จะออก CA ใหม่ทับ
# ข้ามได้ด้วย ALLOW_NEW_CA=1 (หรือรันแบบไม่มี tty ซึ่งถามไม่ได้อยู่แล้ว)
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
# (ทำเฉพาะโหมดตั้งค่าใหม่ + มีของเปลี่ยนจริง — รันซ้ำเพื่อซ่อมแบบเดิมจะไม่มีจอนี้มากวน)
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
#
# ★ ทำไมรันรอบสองแล้วเหมือนค้างตรง "Upgrading pip":
#   `pip install --upgrade pip` ไม่มีเวอร์ชันกำกับ -> pip **ต้องยิงถาม PyPI ทุกครั้ง** ว่ารุ่นล่าสุด
#   คืออะไร ตอบจากของที่ลงไว้ในเครื่องไม่ได้ ต่างจาก `-r requirements.txt` ที่ pin `==` ไว้ทุกตัว
#   (ครบแล้ว pip ตอบจาก metadata ในเครื่อง ไม่แตะเน็ตเลย ~1 วินาที)
#   รันรอบสองขั้นอื่นเป็น no-op ในเครื่องทั้งหมด (venv มีแล้ว/DB มีแล้ว/cert ครบ) เหลือขั้นนี้
#   ขั้นเดียวที่ออกเน็ต พอเน็ตช้าหรือตัน pip จะ retry ตามค่า default (`--timeout 15 --retries 5`
#   + backoff) = นั่งดูตัวหมุนเงียบ ๆ ได้ 1.5-5 นาที **แล้ว exit 0 เหมือนไม่มีอะไรเกิดขึ้น**
#   (วัดจริง: index ที่ต่อไม่ติด -> 1 นาที 38 วินาที, rc=0, ไม่มี error โผล่มาสักตัว)
#
#   แก้: upgrade เฉพาะตอนที่จำเป็นจริง — venv เพิ่งสร้าง หรือ pip เก่ากว่าเกณฑ์เท่านั้น
#   venv เดิมที่ pip ใหม่พออยู่แล้วให้ข้ามไปเลย ไม่ต้องออกเน็ต · บังคับ upgrade: FORCE_PIP_UPGRADE=1
#   และทุกคำสั่ง pip ใส่ timeout/retries สั้นลง + --no-input ไว้ เน็ตพังจะได้ตายพร้อมเหตุผลใน 45
#   วินาที ไม่ใช่ค้างยาว · ปรับได้ด้วย PIP_TIMEOUT / PIP_RETRIES
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
# --no-input: มีอะไรจะถามให้ตายไปเลย ไม่ใช่ค้างรอ input อยู่หลังตัวหมุนที่คนดูไม่เห็น
PIP_OPTS=(--disable-pip-version-check --no-input
          --timeout "${PIP_TIMEOUT:-15}" --retries "${PIP_RETRIES:-2}")

# เกณฑ์: pip 23 ขึ้นไปลง wheel ทุกตัวใน requirements.txt ได้หมดแล้ว (manylinux ต้องการแค่ >= 20.3)
# ต่ำกว่านั้นค่อยไปเอาของใหม่มา — ของ Ubuntu 24.04 ที่ ensurepip ให้มาคือ 24.0 ผ่านเกณฑ์อยู่แล้ว
MIN_PIP_MAJOR=23
PIP_VER="$("$PIP" --version 2>/dev/null | awk '{print $2}')" || true
PIP_MAJOR="${PIP_VER%%.*}"
case "$PIP_MAJOR" in ''|*[!0-9]*) PIP_MAJOR=0 ;; esac

if [ "$VENV_CREATED" = "1" ] || [ "$PIP_MAJOR" -lt "$MIN_PIP_MAJOR" ] || [ "${FORCE_PIP_UPGRADE:-0}" = "1" ]; then
    # ล้มเหลว = เตือนแล้วไปต่อ ไม่ล้มทั้งสคริปต์ — pip ตัวเดิมลง requirements.txt ได้อยู่แล้ว
    # ไม่มีเหตุผลให้การติดตั้งทั้งเครื่องพังเพราะแค่ upgrade ตัวติดตั้งเองไม่ผ่าน
    run_step "Upgrading pip (this one always goes out to PyPI)" \
        "$PIP" install -q "${PIP_OPTS[@]}" --upgrade pip \
        || warn "Could not upgrade pip - carrying on with pip ${PIP_VER:-unknown}, it installs requirements.txt fine"
else
    ok "pip $PIP_VER is new enough - upgrade skipped (it is the only step that needs PyPI on a re-run; force it with FORCE_PIP_UPGRADE=1)"
fi

run_step "Installing requirements.txt (this is the slow one)" \
    "$PIP" install -q "${PIP_OPTS[@]}" -r "$PROJECT_DIR/requirements.txt"

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

PG_SUPERUSER_PASSWORD="${PG_SUPERUSER_PASSWORD:-}"
# PG_SUPERUSER / PG_LOCAL ตั้งไว้แล้วที่ขั้น 1.2 (ตอนเช็กฐานก่อนลงมือ) — ใช้ค่าเดียวกันทั้งสองที่
# เพื่อไม่ให้ "ที่ที่ไปตรวจ" กับ "ที่ที่ไปสร้าง role/db" หลุดไปคนละที่กันได้

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

# ---- role: ยังไม่มี = สร้างพร้อมรหัสที่กรอก · มีอยู่แล้ว = "ตรวจ" ว่ารหัสถูกไหม ไม่ใช่ทับ ----
#
# ⚠️ ของเดิม `ALTER ROLE ... PASSWORD` ทับทุกรอบโดยไม่ถาม = กรอกรหัสผิด/พิมพ์ตกก็ไม่มีอะไรฟ้อง
#    รหัสของ role ถูกเปลี่ยนเป็นค่าที่พิมพ์ผิดนั้นเงียบ ๆ แล้วอะไรก็ตามที่ใช้ role นี้อยู่ก็ล็อกอิน
#    ไม่ได้ทันทีโดยไม่มีใครรู้ว่าเพราะอะไร
#    ตอนนี้จึงลองล็อกอินจริงด้วยรหัสที่กรอก (TCP + password เส้นเดียวกับที่ service ใช้) ไม่ผ่าน =
#    หยุดพร้อมบอกว่า "รหัสผิด" ไม่ไปแตะ role · ตั้งใจเปลี่ยนรหัสจริง ๆ ค่อยสั่ง FORCE_DB_PASSWORD=1
#    ต่อฐาน postgres ไม่ใช่ $DB_NAME ในการทดสอบ — จะได้แยก "รหัสผิด" ออกจาก "ฐานยังไม่ถูกสร้าง"
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
    #
    # ปล่อยผ่านโดยไม่ตรวจ = ตอน service start ครั้งแรก create_all() จะสร้างตารางของเราลงไปในฐาน
    # ของคนอื่น และ migration ใน main.py จะ ALTER TABLE users เติมคอลัมน์ใส่ตาราง users ของเขา
    # (แก้ข้อมูลของระบบอื่นโดยที่คนติดตั้งไม่รู้ตัว) — ต้องหยุดตรงนี้เท่านั้น
    #
    # "ของเรา" ดูจากชื่อตารางเฉพาะของระบบนี้ ไม่นับ users ที่ชื่อโหลเกินกว่าจะใช้ชี้ขาด
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
# 7.1) redis/users.acl — เขียนรหัสจริงให้ตรงกับ .env และชุดติดตั้ง agent
#      ห้ามมีคอมเมนต์ในไฟล์นี้ (Redis 7 ไม่ start ถ้าบรรทัดไม่ขึ้นต้นด้วย user) — ดู redis/README.md
# ---------------------------------------------------------------------------
log "redis/users.acl"
ACL_FILE="$PROJECT_DIR/redis/users.acl"
mkdir -p "$PROJECT_DIR/redis"

# รหัสของ "บัญชี agent" ที่จะเขียนลงไฟล์ — ไม่ใช่ค่าจาก .env เสมอไป
#
# ⚠️ หน้าเว็บเปลี่ยนรหัส agent ได้ (System Settings) และ apply_agent_password() เขียนแค่
#    users.acl + ACL LOAD + แถวใน DB — **ไม่แตะ .env** เพราะฝั่ง central ไม่ได้ใช้รหัสนี้ล็อกอิน
#    .env จึงอาจค้างค่าเก่าไว้ ถ้าเอาค่านั้นมาเขียนทับตอนที่เรามาแก้บรรทัดอื่น (เช่นเปลี่ยนรหัส
#    admin อย่างเดียว) = agent ทุกเครื่องหลุดทันทีโดยไม่มีใครสั่งให้เปลี่ยน
#    -> รอบไหน "ไม่ได้ตอบรหัส agent มาใหม่" ให้ยึดรหัสที่อยู่ในไฟล์จริงเป็นหลัก
#    (ยกเว้น FORCE_ACL=1 ซึ่งคือการสั่งตรง ๆ ว่าให้เขียนใหม่จากค่าของสคริปต์)
acl_pass_of() {  # acl_pass_of USER FILE — รหัส (token ที่ขึ้นต้นด้วย >) ของ user นั้นในไฟล์ ACL
    [ -f "$2" ] || return 0
    awk -v u="$1" '
        $1 == "user" && $2 == u {
            for (i = 3; i <= NF; i++) if (substr($i, 1, 1) == ">") { print substr($i, 2); exit }
        }' "$2" 2>/dev/null || true
}

# หาให้ได้ก่อนว่า "รหัส agent ตัวจริง" รอบนี้คือตัวไหน — ทั้ง users.acl (ขั้นนี้) และ site.conf
# (ขั้น 7.2) ต้องใช้ค่าเดียวกัน ไม่งั้นไฟล์สองตัวบนเครื่องเดียวกันบอกคนละรหัส
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
#   **รอบนี้ตอบรหัส Redis หรือชื่อ user มาใหม่** (ขั้น 1.1 เป็นคนตัดสิน)
# นอกจากนั้นไม่แตะ — กันรันซ้ำแล้วทับรหัสที่เปลี่ยนไปจากหน้าเว็บ
# ⚠️ ข้อสุดท้ายขาดไม่ได้: ไม่มีมันแล้วโหมดตั้งค่าใหม่จะเขียนรหัสใหม่ลง .env อย่างเดียว ส่วน Redis
#    ยังใช้รหัสเก่าในไฟล์เดิม -> central ล็อกอิน Redis ไม่ได้ ตายทั้งเครื่องแบบไล่หาสาเหตุยาก
ACL_WRITTEN=0
if [ ! -f "$ACL_FILE" ] || grep -q '>123 ' "$ACL_FILE" || [ "${FORCE_ACL:-0}" = "1" ] \
   || [ "$REDIS_ACL_CHANGED" = "1" ]; then
    # รหัสที่ไฟล์เดิมถืออยู่ = รหัสที่ agent ข้างนอกใช้จริง ณ ตอนนี้ — ต่างจากที่กำลังจะเขียนเมื่อไหร่
    # แปลว่า agent ทุกเครื่องจะล็อกอินไม่ได้ ต้องไปโผล่ในสรุปท้ายสคริปต์ด้วย
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

# เทียบกับ ACL_AGENT_PASS (รหัสตัวจริงที่ users.acl ถืออยู่) ไม่ใช่ค่าจาก .env ที่อาจค้างของเก่า
if [ ! -f "$SITE_CONF" ] || [ "${FORCE_SITE_CONF:-0}" = "1" ] \
   || [ "$SITE_HOST" != "$BIND_HOST" ] || [ "$SITE_PASS" != "$ACL_AGENT_PASS" ]; then
    [ -f "$SITE_CONF" ] && cp -p "$SITE_CONF" "$SITE_CONF.bak.$(date +%Y%m%d%H%M%S)"
    cat > "$SITE_CONF" <<EOF
CENTRAL_HOST="$BIND_HOST"
CENTRAL_REDIS_PORT="6380"
REDIS_USERNAME="agent_node"
REDIS_PASSWORD="$ACL_AGENT_PASS"
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

# ★ Redis อ่านทั้ง cert และ aclfile ตอน start ครั้งเดียว แก้ไฟล์เฉย ๆ จึงไม่มีผลกับตัวที่รันอยู่
#   ปกติ install.sh ตั้งใจไม่แตะ centralredis (restart = ตัดคิว log + connection ของ agent ทุกตัว)
#   แต่ 2 เคสนี้ไม่ restart ไม่ได้:
#     - cert ใหม่: ใบเก่ายังถูกยื่นให้ client อยู่ในหน่วยความจำ และ redis_config.py ต่อแบบ
#       ssl_check_hostname=True -> ย้าย IP แล้วไม่ restart = ทุก service ต่อ Redis ไม่ผ่านการตรวจชื่อ
#     - users.acl ใหม่: .env ถือรหัสใหม่แต่ Redis ยังบังคับรหัสเก่า -> ล็อกอินไม่ผ่านทั้งเครื่อง
# ★ ตัวชี้ขาดที่เชื่อได้คือ "ใบที่ Redis ยื่นออกมาตอนนี้" ไม่ใช่ CERT_ISSUED ของรอบนี้
#
# ⚠️ เจอจริงบนเครื่องทดสอบ: รอบก่อนออก cert ใหม่แล้วจบกลางคันก่อนถึงขั้นนี้ -> Redis ยังถือใบเก่าไว้
#    รอบถัดมาเห็นว่า cert บนดิสก์ครบและ SAN ถูกแล้ว CERT_ISSUED จึงเป็น 0 -> ไม่ restart · แล้ว
#    install.sh ก็ข้ามให้อีกเพราะ "centralredis รันอยู่แล้ว" -> Redis ค้างใบเก่าถาวร ทุก service
#    ต่อไม่ติดด้วย CERTIFICATE_VERIFY_FAILED วนไปเรื่อย ๆ ทั้งที่สคริปต์จบด้วยข้อความว่าสำเร็จ
#    ถาม Redis เองว่าตอนนี้ยื่นใบไหน แล้วเทียบกับไฟล์บนดิสก์ = จับได้ทุกกรณีที่มันหลุดจากกัน
redis_serving_stale_cert() {
    local served ondisk
    [ -f "$CERT_DIR/central.crt" ] || return 1
    served="$(echo | timeout 5 openssl s_client -connect "$BIND_HOST:6380" 2>/dev/null \
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
# 11) ตรวจว่า "ใช้งานได้จริง" ไม่ใช่แค่ service ขึ้น
#
# ⚠️ ของเดิมจบด้วย "Setup complete - services running" โดยดูแค่ว่า systemd ยังไม่ตาย — แต่ service
#    ของระบบนี้ออกแบบให้ retry ต่อ Redis ไปเรื่อย ๆ ไม่ยอมตาย เครื่องที่ Redis ยื่น cert คนละใบกับ
#    ที่ .env ชี้ จึงขึ้นเขียวครบทุกตัวทั้งที่ต่อไม่ติดสักตัว และไม่มีใครรู้จนกว่าจะไปเปิด journalctl เอง
#    (เกิดขึ้นจริงบนเครื่องทดสอบ: ทุก service วน CERTIFICATE_VERIFY_FAILED อยู่เป็นชั่วโมง)
#    ตรงนี้จึงต่อ Redis ด้วยค่าใน .env จริง ๆ ทางเดียวกับที่ service ต่อ แล้วบอกผลตรง ๆ
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
        host="$BIND_HOST", port=6380, ssl=True,
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
            ok "Logged in to Redis at $BIND_HOST:6380 over mTLS as '$REDIS_USER' - the services connect the same way"
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
# ฝั่ง agent (client) — สิ่งที่สคริปต์นี้ตามไปแก้ให้ไม่ได้
#
# ค่าที่ agent ใช้ต่อกลับมา (CENTRAL_HOST + รหัส Redis ของ agent + CA) ถูก **ฝังลงเครื่อง agent
# ตั้งแต่ตอนติดตั้ง** ไม่ได้ถามจาก central ตอนรัน เปลี่ยนที่นี่จึงไม่มีทางถึงเขาเอง และ agent จะ
# retry เงียบ ๆ ไปเรื่อย ๆ — ที่ central ไม่มีอะไรฟ้องเลยว่าหายไปกี่เครื่อง จึงต้องบอกตรงนี้ให้ชัด
# ว่าต้องไปไล่ลงใหม่ ไม่ใช่ปล่อยให้ไปเจอเองตอนสงสัยว่าทำไม log หาย
#
# cert ของ central/dashboard ที่ออกใหม่ "ไม่" อยู่ในรายการนี้ — เซ็นด้วย CA เดิม agent เก่าจึงยัง
# เชื่อถือใบใหม่ได้ตามปกติ (เหตุผลเดียวกับที่ขั้น 7 หวง CA เดิมไว้)
# ---------------------------------------------------------------------------
# เงื่อนไขคือ "มี agent อยู่ข้างนอกไหม" ไม่ใช่ "เคยมี .env ไหม" — ล้างโฟลเดอร์ทิ้งแล้วลงใหม่โดยที่
# ฐานข้อมูลยังอยู่ คือเคสที่ .env หายไปแต่ agent ยังอยู่ครบ และเป็นเคสที่ต้องเตือนที่สุด
AGENT_COUNT_KNOWN=0
case "${EXISTING_AGENTS:-}" in ''|*[!0-9]*) ;; *) AGENT_COUNT_KNOWN=1 ;; esac
if [ "$ENV_EXISTED" = "1" ] || { [ "$AGENT_COUNT_KNOWN" = "1" ] && [ "$EXISTING_AGENTS" -gt 0 ]; }; then
    AGENT_REASONS=()
    if [ "$IP_CHANGED" = "1" ]; then
        AGENT_REASONS+=("the central address moved $CURRENT_BIND_HOST -> $BIND_HOST (they still dial $CURRENT_BIND_HOST)")
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
        echo "       - or, in the agent folder, edit site.conf (CENTRAL_HOST / REDIS_PASSWORD) and"
        echo "         re-run:   sudo ./setup.sh"
        echo "     Editing one file by hand is not enough - those values sit in BOTH"
        echo "     <agent dir>/agent_config.json and /etc/filebeat/filebeat.yml; setup.sh writes both."
        if [ "$IP_CHANGED" = "1" ]; then
            echo "     Updated on this machine already: cert SAN, REDIS_HOST/AGENT_CENTRAL_HOST in .env,"
            echo "     site.conf, the agent_central_host row in the database and the systemd units."
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
