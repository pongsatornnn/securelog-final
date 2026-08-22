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
set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="securelog-agent"
MARKER="$INSTALL_DIR/.setup_done"

log()  { echo -e "\e[32m[SETUP]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m  $*"; }
die()  { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "ต้องรันเป็น root: sudo ./setup.sh"
command -v python3 >/dev/null || die "ไม่พบ python3 บนเครื่องนี้"

# ---------- 0) ค่าต่อ site (จาก site.conf ข้างสคริปต์ — ไม่ commit ขึ้น git) ----------
SITE_CONF="$INSTALL_DIR/site.conf"
[ -f "$SITE_CONF" ] || die "ไม่พบ $SITE_CONF — คัดลอกจาก site.conf.example แล้วใส่ค่าจริงก่อน: cp site.conf.example site.conf"
# shellcheck source=/dev/null
source "$SITE_CONF"

: "${CENTRAL_HOST:?ไม่มี CENTRAL_HOST ใน site.conf}"
: "${CENTRAL_REDIS_PORT:?ไม่มี CENTRAL_REDIS_PORT ใน site.conf}"
: "${REDIS_USERNAME:?ไม่มี REDIS_USERNAME ใน site.conf}"
: "${REDIS_PASSWORD:?ไม่มี REDIS_PASSWORD ใน site.conf}"

# ---------- 1) อ่านค่าเฉพาะ agent จาก agent_info.txt (มากับ zip) ----------
INFO_FILE="$INSTALL_DIR/agent_info.txt"
[ -f "$INFO_FILE" ] || die "ไม่พบ $INFO_FILE — ต้องแตก zip ของ agent ลงโฟลเดอร์นี้ก่อน"

# key ที่ไม่มีในไฟล์ (เช่น zip เก่าก่อนมี HOST_IP) ต้องคืนค่าว่างเฉย ๆ ไม่ใช่ทำให้สคริปต์ตายเงียบ —
# grep ไม่เจอ match คืน exit 1, pipefail ลากค่านั้นทะลุมาถึง set -e ตาย ก่อนแม้แต่จะได้ die() message
get_info() { grep -E "^$1=" "$INFO_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true; }
AGENT_ID="$(get_info AGENT_ID)"
SECRET_TOKEN="$(get_info SECRET_TOKEN)"
CERT_FILE="$(get_info CERT_FILE)"; CERT_FILE="${CERT_FILE:-$AGENT_ID.crt}"
KEY_FILE="$(get_info KEY_FILE)";   KEY_FILE="${KEY_FILE:-$AGENT_ID.key}"
CA_FILE="$(get_info CA_FILE)";     CA_FILE="${CA_FILE:-ca.crt}"
HOST_IP="$(get_info HOST_IP)"

[ -n "$AGENT_ID" ] && [ -n "$SECRET_TOKEN" ] || die "agent_info.txt ไม่มี AGENT_ID/SECRET_TOKEN"
log "ติดตั้ง agent: $AGENT_ID ที่ $INSTALL_DIR"

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

[ "${#IFACE_LINES[@]}" -gt 0 ] || die "ไม่พบ interface ที่มี IPv4 บนเครื่องนี้ — ตั้งค่า network ก่อนแล้วรันใหม่"

echo ""
log "interface ที่มี IPv4 บนเครื่องนี้:"
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
    log "มี interface เดียว — ใช้ตัวนี้อัตโนมัติ"
else
    read -rp "เลือก interface ที่จะใช้เป็น IP ของ agent นี้ [1-${#IFACE_LINES[@]}] (Enter = $DEFAULT_INDEX ซึ่งเป็นขาที่ออกไปหา central): " CHOICE
    CHOICE="${CHOICE:-$DEFAULT_INDEX}"
fi

case "$CHOICE" in
    ''|*[!0-9]*) die "ต้องเลือกเป็นตัวเลข 1-${#IFACE_LINES[@]}" ;;
esac
[ "$CHOICE" -ge 1 ] && [ "$CHOICE" -le "${#IFACE_LINES[@]}" ] || die "เลือกได้แค่ 1-${#IFACE_LINES[@]}"

HOST_IFACE="$(echo "${IFACE_LINES[$((CHOICE - 1))]}" | awk '{print $1}')"
DETECTED_IP="$(echo "${IFACE_LINES[$((CHOICE - 1))]}" | awk '{print $2}')"

log "ใช้ interface: $HOST_IFACE (IP $DETECTED_IP)"
warn "IP $DETECTED_IP จะถูกผูกกับ $AGENT_ID ถาวรตอนเชื่อมต่อ central สำเร็จครั้งแรก"
warn "เปลี่ยนทีหลังไม่ได้ — ถ้าเครื่องนี้ย้าย network/เปลี่ยน IP ต้องกด \"สร้าง Download Link ใหม่\""
warn "ในหน้า Agents แล้วติดตั้งด้วย package ชุดใหม่เท่านั้น"

HOST_IP="$DETECTED_IP"

# ---------- 2) จัดโครงโฟลเดอร์ (cert/ + state/) ----------
mkdir -p "$INSTALL_DIR/cert" "$INSTALL_DIR/state"

for f in "$CERT_FILE" "$KEY_FILE" "$CA_FILE"; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        mv -f "$INSTALL_DIR/$f" "$INSTALL_DIR/cert/$f"
    fi
    [ -f "$INSTALL_DIR/cert/$f" ] || die "ไม่พบไฟล์ cert: $f (ต้องมาจาก zip ของ agent)"
done
log "ไฟล์ cert ครบ: $CERT_FILE / $KEY_FILE / $CA_FILE"

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
log "เขียน agent_config.json แล้ว (host_iface=$HOST_IFACE)"

# ---------- 4) ลง system packages ----------
export DEBIAN_FRONTEND=noninteractive
NEED_PKGS=()
dpkg -s python3-venv >/dev/null 2>&1 || NEED_PKGS+=(python3-venv)
dpkg -s conntrack    >/dev/null 2>&1 || NEED_PKGS+=(conntrack)
dpkg -s curl         >/dev/null 2>&1 || NEED_PKGS+=(curl)
dpkg -s gnupg        >/dev/null 2>&1 || NEED_PKGS+=(gnupg)

if [ "${#NEED_PKGS[@]}" -gt 0 ]; then
    log "ติดตั้ง packages: ${NEED_PKGS[*]}"
    apt-get update -qq
    apt-get install -y -qq "${NEED_PKGS[@]}"
else
    log "python3-venv + conntrack + curl + gnupg มีแล้ว"
fi

# ---------- 5) ลง Filebeat ----------
# ลำดับ: มีอยู่แล้ว > ไฟล์ .deb ข้างสคริปต์ (ไม่พึ่งเน็ต) > Elastic APT repo (ต้องมีเน็ตออก)
ELASTIC_LIST="/etc/apt/sources.list.d/elastic-8.x.list"
ELASTIC_KEYRING="/usr/share/keyrings/elastic.gpg"

if command -v filebeat >/dev/null 2>&1; then
    log "filebeat มีแล้ว: $(filebeat version 2>/dev/null | head -1)"
else
    DEB="$(ls "$INSTALL_DIR"/filebeat-*.deb 2>/dev/null | head -1 || true)"
    if [ -n "$DEB" ]; then
        log "ติดตั้ง filebeat จาก $DEB (พบไฟล์ในเครื่อง — ใช้ก่อน ไม่ต้องพึ่งเน็ต)"
        dpkg -i "$DEB"
    elif curl -fsS --max-time 5 -o /dev/null https://artifacts.elastic.co 2>/dev/null; then
        log "ไม่พบ .deb ในเครื่อง — ติดตั้ง filebeat ผ่าน Elastic APT repository แทน"

        if [ ! -f "$ELASTIC_KEYRING" ]; then
            curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
                | gpg --dearmor -o "$ELASTIC_KEYRING"
        fi

        if [ ! -f "$ELASTIC_LIST" ]; then
            echo "deb [signed-by=$ELASTIC_KEYRING] https://artifacts.elastic.co/packages/8.x/apt stable main" \
                > "$ELASTIC_LIST"
        fi

        apt-get update -qq
        apt-get install -y -qq filebeat
        log "ติดตั้ง filebeat จาก Elastic APT repo แล้ว (รันซ้ำครั้งหน้า apt จะอัปเดตเวอร์ชันให้เองถ้ามีใหม่)"
    else
        die "ไม่พบ filebeat และต่อเน็ตออกไม่ได้ — วางไฟล์ filebeat-<version>-amd64.deb ไว้ข้างสคริปต์นี้ (โหลดจาก elastic.co) หรือต่อเน็ตแล้วรันใหม่"
    fi
fi

# ---------- 6) สร้าง venv + ลง dependency ----------
if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    log "สร้าง venv (แยกจาก system python — ไม่กระทบ process อื่น)"
    python3 -m venv "$INSTALL_DIR/venv"
else
    log "venv มีแล้ว"
fi
"$INSTALL_DIR/venv/bin/pip" install -q -r "$INSTALL_DIR/requirements.txt"
log "ลง python dependency (redis, psutil) ใน venv แล้ว"

# ---------- 7) generate /etc/filebeat/filebeat.yml จาก template ----------
#
# ไม่มีการแทน __REDIS_USERNAME__ ที่นี่แล้ว — output.redis ของ Beats ไม่รองรับ ACL username
# (ส่ง AUTH ได้แต่ password → Redis ตีเป็นบัญชี `default` เสมอ) ดูคำอธิบายเต็มใน template
# ค่า REDIS_USERNAME ยังต้องมีใน site.conf อยู่ เพราะ agent_core ใช้ต่อเป็นบัญชี agent_node
TEMPLATE="$INSTALL_DIR/filebeat.yml.template"
[ -f "$TEMPLATE" ] || die "ไม่พบ $TEMPLATE"

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

grep -q "__" "$TMP_YML" && die "ยังมี placeholder ค้างใน filebeat.yml ที่ generate — เช็ค template"

if [ -f /etc/filebeat/filebeat.yml ] && ! cmp -s "$TMP_YML" /etc/filebeat/filebeat.yml; then
    cp /etc/filebeat/filebeat.yml "/etc/filebeat/filebeat.yml.bak.$(date +%Y%m%d%H%M%S)"
    log "backup filebeat.yml เดิมไว้แล้ว"
fi
install -m 600 -o root -g root "$TMP_YML" /etc/filebeat/filebeat.yml
rm -f "$TMP_YML"
log "ติดตั้ง /etc/filebeat/filebeat.yml แล้ว"

filebeat test config -c /etc/filebeat/filebeat.yml >/dev/null || die "filebeat config ไม่ผ่านการตรวจ (filebeat test config)"
log "filebeat config ผ่านการตรวจ"

# ครั้งแรกเท่านั้น: ลบ registry ให้ tail_files เริ่มอ่านจากท้ายไฟล์ (ไม่ลาก log เก่าทั้งไฟล์)
# รอบถัดไปห้ามลบ — registry คือตัวจำตำแหน่งที่อ่านถึง ทำให้ agent หลุดแล้วกลับมาอ่านต่อได้ไม่ขาด
if [ ! -f "$MARKER" ]; then
    systemctl stop filebeat 2>/dev/null || true
    rm -rf /var/lib/filebeat/registry
    log "ลบ filebeat registry (เฉพาะติดตั้งครั้งแรก)"
fi

# ---------- 8) สิทธิ์ไฟล์ ----------
chown -R root:root "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/cert/$KEY_FILE" "$INFO_FILE" "$INSTALL_DIR/agent_config.json"
log "ตั้งสิทธิ์ไฟล์ (key/token = 600, เจ้าของ root)"

# ---------- 9) UFW ----------
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
    if ufw status verbose | grep -qi "Logging: off"; then
        ufw logging low
        log "เปิด ufw logging low (จำเป็นสำหรับ firewall detector)"
    else
        log "ufw logging เปิดอยู่แล้ว"
    fi
else
    warn "ufw ยังไม่ active — คำสั่ง block IP จะไม่มีผลจนกว่าจะ: sudo ufw enable"
fi

# ---------- 10) systemd ----------
sed "s|__INSTALL_DIR__|$INSTALL_DIR|g" "$INSTALL_DIR/$SERVICE_NAME.service" \
    > "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1
systemctl restart "$SERVICE_NAME"      # รันซ้ำ = โหลดโค้ด/config ใหม่
systemctl enable --now filebeat >/dev/null 2>&1
systemctl restart filebeat
log "เปิด service: $SERVICE_NAME + filebeat (start เองตอน boot ด้วย)"

touch "$MARKER"

# ---------- 11) ตรวจปลายทาง ----------
echo ""
log "ทดสอบต่อ Redis central แบบ mTLS..."
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
    print(f"   ต่อไม่ได้: {e}")
    sys.exit(1)
PYEOF
then
    log "ต่อ Redis central ($CENTRAL_HOST:$CENTRAL_REDIS_PORT) สำเร็จ"
else
    warn "ต่อ Redis central ไม่ได้ — เช็ค network/cert/รหัส แล้วดู log: journalctl -u $SERVICE_NAME -f"
fi

# log file ที่มีจริงบนเครื่องนี้ อ่านได้ไหม (filebeat รันเป็น root ปกติไม่ติด แต่บาง distro ตั้ง ACL แปลก)
for f in /var/log/auth.log /var/log/apache2/access.log /var/log/nginx/access.log /var/log/ufw.log /var/log/iptables.log; do
    if [ -e "$f" ] && [ ! -r "$f" ]; then
        warn "$f มีอยู่แต่อ่านไม่ได้ — filebeat จะเก็บ log นี้ไม่ได้"
    fi
done

echo ""
log "ติดตั้งเสร็จ — เช็คสถานะ:"
echo "    systemctl status $SERVICE_NAME filebeat"
echo "    journalctl -u $SERVICE_NAME -f"
echo "  แล้วดูหน้า Agents บน dashboard ว่า $AGENT_ID ขึ้น online"
