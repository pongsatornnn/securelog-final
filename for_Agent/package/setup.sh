#!/usr/bin/env bash
#
# SecureLog Agent — สคริปต์ติดตั้ง/อัปเดตบนเครื่อง agent (Debian/Ubuntu)
#
# ครั้งแรกที่ตั้ง repo นี้ (ทำที่เครื่อง central ครั้งเดียว ก่อนสร้าง agent package แรก):
#   cp site.conf.example site.conf   แล้วใส่ค่าจริง (site.conf ถูก .gitignore ไว้ ไม่ขึ้น git)
#   จากนั้น zip ที่โหลดจากหน้า Agents บน dashboard จะมี site.conf ติดไปด้วยอัตโนมัติทุกครั้ง
#
# วิธีใช้ (ฝั่งเครื่อง agent):
#   1. วางโฟลเดอร์นี้ไว้ที่ /opt/securelog-agent (แนะนำ)
#   2. แตกไฟล์ zip ของ agent (โหลดจากหน้า Agents บน dashboard) ลงโฟลเดอร์เดียวกัน
#      ให้มี agent_info.txt + <Agent_ID>.crt + <Agent_ID>.key + ca.crt + site.conf อยู่ข้างสคริปต์นี้
#   3. (ถ้าเครื่องไม่มีเน็ต/ยังไม่มี filebeat) วางไฟล์ filebeat-<version>-amd64.deb ไว้ข้างสคริปต์ด้วย
#   4. sudo ./setup.sh
#
# รันซ้ำได้ (idempotent) — ใช้ตอนอัปเดตโค้ด/config ก็รันตัวเดิมซ้ำ
#
# firewall: เปิดทางออกไปหา central Redis ให้ผ่าน ufw + เปิด ufw logging ที่ตัวตรวจจับต้องใช้
#           (ไม่ enable ufw ให้เอง — จะตัด ssh ตัวเองขาด) · ข้ามทั้งขั้น: SKIP_FIREWALL=1 sudo ./setup.sh
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="securelog-agent"
MARKER="$INSTALL_DIR/.setup_done"

log()  { echo -e "\e[32m[SETUP]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m  $*"; }
die()  { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# run_step — รันขั้นที่กินเวลานาน (apt/dpkg/venv/pip) พร้อมตัวหมุน + เวลาที่ใช้ไป
#
# ของเดิมสั่ง apt/pip แบบ -q แล้วจอเงียบไปเป็นนาที คนติดตั้งแยกไม่ออกว่ากำลังโหลดอยู่หรือค้าง
# ที่นี่เก็บเอาต์พุตจริงลง log แล้วโชว์ตัวหมุนแทน — พังเมื่อไหร่ค่อยพ่น 20 บรรทัดท้ายให้เห็นสาเหตุ
# แล้วคืน exit code เดิม (set -e หยุดสคริปต์ให้เหมือนเดิม ไม่มีอะไรถูกกลืนหาย)
#
# stdin ต่อ /dev/null: มีอะไรแอบถามขึ้นมาจะได้ตายพร้อมข้อความ ไม่ใช่หมุนค้างโดยไม่มีใครรู้ว่ามันรอ input
# ไม่มี tty (รันผ่าน pipe/cron) ก็ปล่อยเอาต์พุตไหลตามปกติ ไม่ต้องหมุน
# ---------------------------------------------------------------------------
STEP_LOG=""
run_step() {  # run_step "คำอธิบาย" cmd [args...]
    local desc="$1"; shift
    local rc=0 start="$SECONDS"

    if [ ! -t 1 ]; then
        log "$desc ..."
        "$@" </dev/null || rc=$?
        if [ "$rc" -ne 0 ]; then
            echo -e "\e[31m[ERROR]\e[0m $desc failed (exit $rc)" >&2
            return "$rc"
        fi
        log "$desc - done ($((SECONDS - start))s)"
        return 0
    fi

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
        # ตอนนี้มันติดอยู่กับอะไร — ของเดิมซ่อนเอาต์พุตไว้หมด ขั้นที่ค้าง (เช่น apt/pip ที่ต่อเน็ต
        # ไม่ติดแล้ว retry เงียบ ๆ) จึงหน้าตาเหมือนขั้นที่กำลังทำงานปกติเป๊ะ ๆ
        if [ "$spent" -ge 15 ]; then
            tail_line="$(tail -n 1 "$STEP_LOG" 2>/dev/null | tr -d '\r' | cut -c1-52)"
            if [ -n "$tail_line" ]; then hint="  "$'\033[2m'"| $tail_line"$'\033[0m'; fi
        fi
        printf '\r\033[K\033[32m[SETUP]\033[0m %s \033[2m(%ds)\033[0m %s%s' \
            "$desc" "$spent" "${frames:i++%4:1}" "$hint"
        sleep 0.2
    done
    printf '\r\033[K\033[?25h'       # ล้างบรรทัดตัวหมุนแล้วคืน cursor

    wait "$pid" || rc=$?
    if [ "$rc" -ne 0 ]; then
        echo -e "\e[31m[ERROR]\e[0m $desc failed (exit $rc) - last lines of the output:" >&2
        tail -20 "$STEP_LOG" >&2
        return "$rc"
    fi
    log "$desc - done ($((SECONDS - start))s)"
}

[ "$(id -u)" -eq 0 ] || die "Must be run as root: sudo ./setup.sh"
command -v python3 >/dev/null || die "python3 not found on this machine"

# ---------- 0) ค่าต่อ site (จาก site.conf ข้างสคริปต์ — ไม่ commit ขึ้น git) ----------
SITE_CONF="$INSTALL_DIR/site.conf"
[ -f "$SITE_CONF" ] || die "$SITE_CONF not found - copy it from site.conf.example and fill in the real values: cp site.conf.example site.conf"
# shellcheck source=/dev/null
source "$SITE_CONF"

: "${CENTRAL_HOST:?CENTRAL_HOST is missing from site.conf}"
: "${CENTRAL_REDIS_PORT:?CENTRAL_REDIS_PORT is missing from site.conf}"
: "${REDIS_USERNAME:?REDIS_USERNAME is missing from site.conf}"
: "${REDIS_PASSWORD:?REDIS_PASSWORD is missing from site.conf}"

# ---------- 1) อ่านค่าเฉพาะ agent จาก agent_info.txt (มากับ zip) ----------
INFO_FILE="$INSTALL_DIR/agent_info.txt"
[ -f "$INFO_FILE" ] || die "$INFO_FILE not found - extract the agent zip into this folder first"

# key ที่ไม่มีในไฟล์ (เช่น zip เก่าก่อนมี HOST_IP) ต้องคืนค่าว่างเฉย ๆ ไม่ใช่ทำให้สคริปต์ตายเงียบ —
# grep ไม่เจอ match คืน exit 1, pipefail ลากค่านั้นทะลุมาถึง set -e ตาย ก่อนแม้แต่จะได้ die() message
get_info() { grep -E "^$1=" "$INFO_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true; }
AGENT_ID="$(get_info AGENT_ID)"
SECRET_TOKEN="$(get_info SECRET_TOKEN)"
CERT_FILE="$(get_info CERT_FILE)"; CERT_FILE="${CERT_FILE:-$AGENT_ID.crt}"
KEY_FILE="$(get_info KEY_FILE)";   KEY_FILE="${KEY_FILE:-$AGENT_ID.key}"
CA_FILE="$(get_info CA_FILE)";     CA_FILE="${CA_FILE:-ca.crt}"
HOST_IP="$(get_info HOST_IP)"

[ -n "$AGENT_ID" ] && [ -n "$SECRET_TOKEN" ] || die "agent_info.txt has no AGENT_ID/SECRET_TOKEN"
log "Installing agent: $AGENT_ID into $INSTALL_DIR"

# ---------- 1.5) เลือก interface ที่จะใช้เป็น IP ของเครื่องนี้ ----------
#
# IP นี้ถูกผูกกับ Agent ID ที่ฝั่ง central — ข้อมูลที่ส่งไปต้องมาจาก IP นี้เท่านั้น ไม่งั้นถูกปฏิเสธ
# จึงต้องให้เลือกเองว่าจะเอาจาก interface ไหน (เครื่องที่มีหลายใบ เช่น NAT + host-only
# การเดาให้เองมีโอกาสได้ขาที่คุยกับ central ไม่ได้ แล้วไปตายตอน central ปฏิเสธทีหลัง)
#
# เก็บ "ชื่อ interface" ไม่ใช่ตัวเลข IP — agent_core.py อ่าน IP จาก interface นี้ใหม่ทุกครั้ง
# ตอนรัน ค่าจึงตามทันเองเมื่อ DHCP เปลี่ยน IP และการยกไฟล์ไปรันเครื่องอื่นจะได้ IP ของเครื่อง
# นั้นออกมาเอง (ถ้าเก็บเป็นตัวเลข ค่าจะถูกยกตามไปด้วย = ตรวจไม่เจอ)

# ชื่อ interface + IPv4 ของแต่ละใบ (ข้าม loopback) — ip -o เอาต์พุตบรรทัดละใบ ตัดคำที่ 2 กับ 4
mapfile -t IFACE_LINES < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2" "$4}' | cut -d/ -f1 | sort -u)

[ "${#IFACE_LINES[@]}" -gt 0 ] || die "No interface with an IPv4 address on this machine - configure networking, then run again"

echo ""
log "Interfaces with an IPv4 address on this machine:"
for i in "${!IFACE_LINES[@]}"; do
    printf "    %d) %-12s %s\n" "$((i + 1))" "$(echo "${IFACE_LINES[$i]}" | awk '{print $1}')" "$(echo "${IFACE_LINES[$i]}" | awk '{print $2}')"
done
echo ""

# ค่าที่แนะนำ = ขาที่ route ออกไปหา central จริง (ใบที่คุยกับ central ได้แน่ ๆ)
DEFAULT_IFACE="$(ip -o route get "$CENTRAL_HOST" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | head -1)"
DEFAULT_INDEX=1
for i in "${!IFACE_LINES[@]}"; do
    [ "$(echo "${IFACE_LINES[$i]}" | awk '{print $1}')" = "$DEFAULT_IFACE" ] && DEFAULT_INDEX=$((i + 1))
done

if [ "${#IFACE_LINES[@]}" -eq 1 ]; then
    CHOICE=1
    log "Only one interface - using it automatically"
else
    read -rp "Pick the interface to use as this agent's IP [1-${#IFACE_LINES[@]}] (Enter = $DEFAULT_INDEX, the one that routes to central): " CHOICE
    CHOICE="${CHOICE:-$DEFAULT_INDEX}"
fi

case "$CHOICE" in
    ''|*[!0-9]*) die "Must be a number between 1 and ${#IFACE_LINES[@]}" ;;
esac
[ "$CHOICE" -ge 1 ] && [ "$CHOICE" -le "${#IFACE_LINES[@]}" ] || die "Choice must be between 1 and ${#IFACE_LINES[@]}"

HOST_IFACE="$(echo "${IFACE_LINES[$((CHOICE - 1))]}" | awk '{print $1}')"
DETECTED_IP="$(echo "${IFACE_LINES[$((CHOICE - 1))]}" | awk '{print $2}')"

log "Using interface: $HOST_IFACE (IP $DETECTED_IP)"
warn "IP $DETECTED_IP is bound to $AGENT_ID permanently on the first successful connection to central"
warn "It cannot be changed later - if this machine moves network or changes IP, use 'Regenerate Download Link'"
warn "on the Agents page and reinstall with the new package"

HOST_IP="$DETECTED_IP"

# ---------- 2) จัดโครงโฟลเดอร์ (cert/ + state/) ----------
mkdir -p "$INSTALL_DIR/cert" "$INSTALL_DIR/state"

for f in "$CERT_FILE" "$KEY_FILE" "$CA_FILE"; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        mv -f "$INSTALL_DIR/$f" "$INSTALL_DIR/cert/$f"
    fi
    [ -f "$INSTALL_DIR/cert/$f" ] || die "Missing cert file: $f (it must come from the agent zip)"
done
log "All cert files present: $CERT_FILE / $KEY_FILE / $CA_FILE"

# ---------- 3) เขียน agent_config.json ให้ agent_core.py ----------
# host_iface เก็บ "ชื่อ" ไม่ใช่ IP — agent_core.py อ่าน IP จาก interface นี้ใหม่ทุกครั้งตอนรัน
cat > "$INSTALL_DIR/agent_config.json" <<EOF
{
  "central_host": "$CENTRAL_HOST",
  "central_port": $CENTRAL_REDIS_PORT,
  "redis_username": "$REDIS_USERNAME",
  "redis_password": "$REDIS_PASSWORD",
  "host_iface": "$HOST_IFACE"
}
EOF
log "Wrote agent_config.json (host_iface=$HOST_IFACE)"

# ---------- 4) ลง system packages ----------
export DEBIAN_FRONTEND=noninteractive
NEED_PKGS=()
dpkg -s python3-venv >/dev/null 2>&1 || NEED_PKGS+=(python3-venv)
dpkg -s conntrack    >/dev/null 2>&1 || NEED_PKGS+=(conntrack)
dpkg -s curl         >/dev/null 2>&1 || NEED_PKGS+=(curl)
dpkg -s gnupg        >/dev/null 2>&1 || NEED_PKGS+=(gnupg)

if [ "${#NEED_PKGS[@]}" -gt 0 ]; then
    run_step "apt-get update" apt-get update -qq
    run_step "Installing packages: ${NEED_PKGS[*]}" apt-get install -y -qq "${NEED_PKGS[@]}"
else
    log "python3-venv + conntrack + curl + gnupg already present"
fi

# ---------- 5) ลง Filebeat ----------
# ลำดับ: มีอยู่แล้ว > ไฟล์ .deb ข้างสคริปต์ (ไม่พึ่งเน็ต) > Elastic APT repo (ต้องมีเน็ตออก)
ELASTIC_LIST="/etc/apt/sources.list.d/elastic-8.x.list"
ELASTIC_KEYRING="/usr/share/keyrings/elastic.gpg"

if command -v filebeat >/dev/null 2>&1; then
    log "filebeat already installed: $(filebeat version 2>/dev/null | head -1)"
else
    DEB="$(ls "$INSTALL_DIR"/filebeat-*.deb 2>/dev/null | head -1 || true)"
    if [ -n "$DEB" ]; then
        log "Found $DEB locally - installing filebeat from it (used first, no internet needed)"
        run_step "dpkg -i $(basename "$DEB")" dpkg -i "$DEB"
    elif curl -fsS --max-time 5 -o /dev/null https://artifacts.elastic.co 2>/dev/null; then
        log "No local .deb - installing filebeat from the Elastic APT repository instead"

        if [ ! -f "$ELASTIC_KEYRING" ]; then
            curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
                | gpg --dearmor -o "$ELASTIC_KEYRING"
        fi

        if [ ! -f "$ELASTIC_LIST" ]; then
            echo "deb [signed-by=$ELASTIC_KEYRING] https://artifacts.elastic.co/packages/8.x/apt stable main" \
                > "$ELASTIC_LIST"
        fi

        run_step "apt-get update (Elastic repo)" apt-get update -qq
        run_step "Installing filebeat" apt-get install -y -qq filebeat
        log "Installed filebeat from the Elastic APT repo (on a later re-run apt will upgrade it if a newer version exists)"
    else
        die "filebeat not found and no internet access - put filebeat-<version>-amd64.deb next to this script (download it from elastic.co) or connect to the internet and run again"
    fi
fi

# ---------- 6) สร้าง venv + ลง dependency ----------
if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    run_step "Creating venv (separate from system python - does not affect other processes)" \
        python3 -m venv "$INSTALL_DIR/venv"
else
    log "venv already exists"
fi
# --no-input: มีอะไรจะถามให้ตายไปเลย ไม่ใช่ค้างรอ input อยู่หลังตัวหมุนที่คนดูไม่เห็น
# --timeout/--retries: default ของ pip คือ 15 วิ x 5 รอบ + backoff = เน็ตตันแล้วค้างเงียบได้หลายนาที
# (requirements.txt ที่นี่ pin `==` ไว้ทุกตัว ลงครบแล้ว pip ตอบจากในเครื่อง ไม่ออกเน็ตอยู่แล้ว)
run_step "Installing python dependencies (redis, psutil) into the venv" \
    "$INSTALL_DIR/venv/bin/pip" install -q --disable-pip-version-check --no-input \
    --timeout "${PIP_TIMEOUT:-15}" --retries "${PIP_RETRIES:-2}" \
    -r "$INSTALL_DIR/requirements.txt"

# ---------- 7) generate /etc/filebeat/filebeat.yml จาก template ----------
#
# ไม่มีการแทน __REDIS_USERNAME__ ที่นี่แล้ว — output.redis ของ Beats ไม่รองรับ ACL username
# (ส่ง AUTH ได้แต่ password → Redis ตีเป็นบัญชี `default` เสมอ) ดูคำอธิบายเต็มใน template
# ค่า REDIS_USERNAME ยังต้องมีใน site.conf อยู่ เพราะ agent_core ใช้ต่อเป็นบัญชี agent_node
TEMPLATE="$INSTALL_DIR/filebeat.yml.template"
[ -f "$TEMPLATE" ] || die "$TEMPLATE not found"

TMP_YML="$(mktemp)"
sed -e "s|__CENTRAL_HOST__|$CENTRAL_HOST|g" \
    -e "s|__CENTRAL_REDIS_PORT__|$CENTRAL_REDIS_PORT|g" \
    -e "s|__REDIS_PASSWORD__|$REDIS_PASSWORD|g" \
    -e "s|__INSTALL_DIR__|$INSTALL_DIR|g" \
    -e "s|__CERT_FILE__|$CERT_FILE|g" \
    -e "s|__KEY_FILE__|$KEY_FILE|g" \
    -e "s|__CA_FILE__|$CA_FILE|g" \
    -e "s|__AGENT_ID__|$AGENT_ID|g" \
    -e "s|__HOST_IP__|$HOST_IP|g" \
    -e "s|__SECRET_TOKEN__|$SECRET_TOKEN|g" \
    "$TEMPLATE" > "$TMP_YML"

grep -q "__" "$TMP_YML" && die "Generated filebeat.yml still contains placeholders - check the template"

if [ -f /etc/filebeat/filebeat.yml ] && ! cmp -s "$TMP_YML" /etc/filebeat/filebeat.yml; then
    cp /etc/filebeat/filebeat.yml "/etc/filebeat/filebeat.yml.bak.$(date +%Y%m%d%H%M%S)"
    log "Backed up the previous filebeat.yml"
fi
install -m 600 -o root -g root "$TMP_YML" /etc/filebeat/filebeat.yml
rm -f "$TMP_YML"
log "Installed /etc/filebeat/filebeat.yml"

filebeat test config -c /etc/filebeat/filebeat.yml >/dev/null || die "filebeat config failed validation (filebeat test config)"
log "filebeat config passed validation"

# ครั้งแรกเท่านั้น: ลบ registry ให้ tail_files เริ่มอ่านจากท้ายไฟล์ (ไม่ลาก log เก่าทั้งไฟล์)
# รอบถัดไปห้ามลบ — registry คือตัวจำตำแหน่งที่อ่านถึง ทำให้ agent หลุดแล้วกลับมาอ่านต่อได้ไม่ขาด
if [ ! -f "$MARKER" ]; then
    systemctl stop filebeat 2>/dev/null || true
    rm -rf /var/lib/filebeat/registry
    log "Clearing the filebeat registry (first install only)"
fi

# ---------- 8) สิทธิ์ไฟล์ ----------
chown -R root:root "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/cert/$KEY_FILE" "$INFO_FILE" "$INSTALL_DIR/agent_config.json"
log "Setting file permissions (key/token = 600, owned by root)"

# ---------- 9) UFW: log ที่ตัวตรวจจับต้องใช้ + ทางออกไปหา central ----------
#
# เครื่อง agent ไม่ได้เปิด port รับเข้าเลย (agent_core ต่อออกไปหา central อย่างเดียว รวมทั้ง
# ช่อง pubsub ที่รับคำสั่งบล็อก IP ก็วิ่งบน connection ขาออกเส้นเดิม) — ที่ต้องเปิดจึงมีแต่ขาออก
# ไปหา central Redis  เครื่องที่ตั้ง `ufw default deny outgoing` ไว้ถ้าไม่เปิดให้ agent จะต่อไม่ติด
# แบบไม่มีอะไรฟ้องชัด ๆ (เห็นแค่ timeout) เลยเปิดให้ตั้งแต่ตอนติดตั้ง
#
# ไม่สั่ง `ufw enable` ให้เอง — คนติดตั้งมัก ssh เข้ามาทำ พอ ufw ขึ้นพร้อม default deny incoming
# มันจะตัด ssh ของตัวเองทิ้งกลางคัน  rule ที่เพิ่มไว้ตอน ufw ยัง inactive ไม่หาย enable ทีหลังมีผลเลย
if [ "${SKIP_FIREWALL:-0}" = "1" ]; then
    warn "SKIP_FIREWALL=1 - not touching ufw (the firewall detector needs 'ufw logging low' to be on)"
elif ! command -v ufw >/dev/null 2>&1; then
    warn "ufw is not installed - block IP commands have no effect on this machine"
    warn "Install it and turn it on: sudo apt-get install ufw && sudo ufw allow OpenSSH && sudo ufw enable"
else
    # ขาออกไปหา central — สั่งได้แม้ ufw ยัง inactive (rule ถูกเก็บไว้รอ) และสั่งซ้ำได้ ufw ข้ามให้เอง
    if ufw allow out to "$CENTRAL_HOST" port "$CENTRAL_REDIS_PORT" proto tcp \
            comment "SecureLog agent -> central Redis" >/dev/null 2>&1 \
       || ufw allow out to "$CENTRAL_HOST" port "$CENTRAL_REDIS_PORT" proto tcp >/dev/null 2>&1; then
        log "Allowed outbound $CENTRAL_HOST:$CENTRAL_REDIS_PORT/tcp in ufw (agent + filebeat -> central)"
    else
        warn "Could not add the ufw outbound rule for $CENTRAL_HOST:$CENTRAL_REDIS_PORT/tcp"
        warn "If outgoing traffic is denied by default here, add it yourself or the agent cannot report in"
    fi

    if ufw status | grep -q "Status: active"; then
        if ufw status verbose | grep -qi "Logging: off"; then
            ufw logging low
            log "Enabling ufw logging low (required by the firewall detector)"
        else
            log "ufw logging already enabled"
        fi
    else
        warn "ufw is installed but inactive - block IP commands have no effect and no firewall logs are"
        warn "produced until you run:  sudo ufw allow OpenSSH  (FIRST, or you lock yourself out)"
        warn "                          sudo ufw enable"
    fi
fi

# ---------- 10) systemd ----------
sed "s|__INSTALL_DIR__|$INSTALL_DIR|g" "$INSTALL_DIR/$SERVICE_NAME.service" \
    > "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1
systemctl restart "$SERVICE_NAME"      # รันซ้ำ = โหลดโค้ด/config ใหม่
systemctl enable --now filebeat >/dev/null 2>&1
systemctl restart filebeat
log "Enabled services: $SERVICE_NAME + filebeat (they also start on boot)"

touch "$MARKER"

# ---------- 11) ตรวจปลายทาง ----------
echo ""
log "Testing the mTLS connection to central Redis..."
if "$INSTALL_DIR/venv/bin/python" - <<PYEOF
import sys, redis
try:
    r = redis.Redis(
        host="$CENTRAL_HOST", port=$CENTRAL_REDIS_PORT, ssl=True,
        ssl_certfile="$INSTALL_DIR/cert/$CERT_FILE",
        ssl_keyfile="$INSTALL_DIR/cert/$KEY_FILE",
        ssl_ca_certs="$INSTALL_DIR/cert/$CA_FILE",
        username="$REDIS_USERNAME", password="$REDIS_PASSWORD",
        ssl_check_hostname=True, socket_timeout=5, socket_connect_timeout=5,
    )
    r.ping()
except Exception as e:
    print(f"   connection failed: {e}")
    sys.exit(1)
PYEOF
then
    log "Connected to central Redis ($CENTRAL_HOST:$CENTRAL_REDIS_PORT)"
else
    warn "Could not connect to central Redis - check network/cert/password, then the logs: journalctl -u $SERVICE_NAME -f"
fi

# log file ที่มีจริงบนเครื่องนี้ อ่านได้ไหม (filebeat รันเป็น root ปกติไม่ติด แต่บาง distro ตั้ง ACL แปลก)
for f in /var/log/auth.log /var/log/apache2/access.log /var/log/nginx/access.log /var/log/ufw.log /var/log/iptables.log; do
    if [ -e "$f" ] && [ ! -r "$f" ]; then
        warn "$f exists but is not readable - filebeat cannot collect this log"
    fi
done

echo ""
log "Installation complete - check the status:"
echo "    systemctl status $SERVICE_NAME filebeat"
echo "    journalctl -u $SERVICE_NAME -f"
echo "  Then check the Agents page on the dashboard to see $AGENT_ID come online"
