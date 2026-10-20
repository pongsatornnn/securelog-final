#!/usr/bin/env bash

set -euo pipefail

INSTALL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="securelog-agent"
MARKER="$INSTALL_DIR/.setup_done"

log()  { echo -e "\e[32m[SETUP]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m  $*"; }
die()  { echo -e "\e[31m[ERROR]\e[0m $*" >&2; exit 1; }


term_cols() {  # ความกว้างจอตอนนี้ — tput ถาม terminal ตรง ๆ ใช้ได้แม้ stdout ถูกจับไว้ใน $( )
    local c=""
    c="$(tput cols 2>/dev/null)" || c=""
    case "$c" in ''|*[!0-9]*) c="$(stty size </dev/tty 2>/dev/null | awk '{print $2}')" ;; esac
    case "$c" in ''|*[!0-9]*) c=80 ;; esac
    [ "$c" -ge 30 ] || c=80
    printf '%s' "$c"
}

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

    local pid i=0 frames='|/-\' spent=0 tail_line hint='' room dsp cut_to
    SPIN_COLS="$(term_cols)"
    trap 'SPIN_COLS="$(term_cols)"' WINCH   # ย่อ/ขยายหน้าต่างระหว่างรออยู่ก็ยังพอดีจอ
    "$@" </dev/null >"$STEP_LOG" 2>&1 &
    pid=$!

    printf '\033[?25l'                 # ซ่อน cursor ไม่ให้กระพริบวิ่งตามตัวหมุน
    while kill -0 "$pid" 2>/dev/null; do
        spent=$((SECONDS - start))


        dsp="$desc"
        room=$(( SPIN_COLS - 1 - ${#dsp} - ${#spent} - 14 ))  # "[SETUP] desc (Ns) X" กินไป 14 ตัว
        if [ "$room" -lt 0 ]; then                            # จอแคบจนชื่อขั้นเองยังไม่พอ
            cut_to=$(( ${#dsp} + room ))
            [ "$cut_to" -lt 4 ] && cut_to=4
            dsp="${dsp:0:cut_to}"
            room=0
        fi
        hint=''


        if [ "$spent" -ge 15 ] && [ "$room" -ge 16 ]; then
            tail_line="$(tail -n 1 "$STEP_LOG" 2>/dev/null | tr -d '\r' | cut -c1-"$(( room - 4 ))")"
            [ -n "$tail_line" ] && hint="  "$'\033[2m'"| $tail_line"$'\033[0m'
        fi
        printf '\r\033[K\033[32m[SETUP]\033[0m %s \033[2m(%ds)\033[0m %s%s' \
            "$dsp" "$spent" "${frames:i++%4:1}" "$hint"
        sleep 0.2
    done
    printf '\r\033[K\033[?25h'       # ล้างบรรทัดตัวหมุนแล้วคืน cursor
    trap - WINCH

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


SITE_CONF="$INSTALL_DIR/site.conf"
[ -f "$SITE_CONF" ] || die "$SITE_CONF not found - copy it from site.conf.example and fill in the real values: cp site.conf.example site.conf"

source "$SITE_CONF"

: "${CENTRAL_HOST:?CENTRAL_HOST is missing from site.conf}"
: "${CENTRAL_REDIS_PORT:?CENTRAL_REDIS_PORT is missing from site.conf}"
: "${REDIS_USERNAME:?REDIS_USERNAME is missing from site.conf}"
: "${REDIS_PASSWORD:?REDIS_PASSWORD is missing from site.conf}"


INFO_FILE="$INSTALL_DIR/agent_info.txt"
[ -f "$INFO_FILE" ] || die "$INFO_FILE not found - extract the agent zip into this folder first"


get_info() { grep -E "^$1=" "$INFO_FILE" | head -1 | cut -d= -f2- | tr -d '\r' || true; }
AGENT_ID="$(get_info AGENT_ID)"
SECRET_TOKEN="$(get_info SECRET_TOKEN)"
CERT_FILE="$(get_info CERT_FILE)"; CERT_FILE="${CERT_FILE:-$AGENT_ID.crt}"
KEY_FILE="$(get_info KEY_FILE)";   KEY_FILE="${KEY_FILE:-$AGENT_ID.key}"
CA_FILE="$(get_info CA_FILE)";     CA_FILE="${CA_FILE:-ca.crt}"
HOST_IP="$(get_info HOST_IP)"

[ -n "$AGENT_ID" ] && [ -n "$SECRET_TOKEN" ] || die "agent_info.txt has no AGENT_ID/SECRET_TOKEN"
log "Installing agent: $AGENT_ID into $INSTALL_DIR"


ACL_BEAT="$INSTALL_DIR/filebeat-acl"
[ -f "$ACL_BEAT" ] && [ -f "$INSTALL_DIR/filebeat-acl.sha256" ] || die "patched Filebeat missing from agent package"
(cd "$INSTALL_DIR" && sha256sum -c filebeat-acl.sha256) || die "patched Filebeat checksum mismatch"


mapfile -t IFACE_LINES < <(ip -o -4 addr show scope global 2>/dev/null | awk '{print $2" "$4}' | cut -d/ -f1 | sort -u)

[ "${#IFACE_LINES[@]}" -gt 0 ] || die "No interface with an IPv4 address on this machine - configure networking, then run again"

echo ""
log "Interfaces with an IPv4 address on this machine:"
for i in "${!IFACE_LINES[@]}"; do
    printf "    %d) %-12s %s\n" "$((i + 1))" "$(echo "${IFACE_LINES[$i]}" | awk '{print $1}')" "$(echo "${IFACE_LINES[$i]}" | awk '{print $2}')"
done
echo ""


DEFAULT_IFACE="$(ip -o route get "$CENTRAL_HOST" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | head -1)"
DEFAULT_INDEX=1
for i in "${!IFACE_LINES[@]}"; do
    [ "$(echo "${IFACE_LINES[$i]}" | awk '{print $1}')" = "$DEFAULT_IFACE" ] && DEFAULT_INDEX=$((i + 1))
done

if [ "${#IFACE_LINES[@]}" -eq 1 ]; then
    CHOICE=1
    log "Only one interface - using it automatically"
else


    if ! read -rp "Pick the interface to use as this agent's IP [1-${#IFACE_LINES[@]}] (Enter = $DEFAULT_INDEX, the one that routes to central): " CHOICE; then
        CHOICE=""
        echo ""
        log "No answer on stdin - using the default: $DEFAULT_INDEX"
    fi

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


mkdir -p "$INSTALL_DIR/cert" "$INSTALL_DIR/state"

for f in "$CERT_FILE" "$KEY_FILE" "$CA_FILE"; do
    if [ -f "$INSTALL_DIR/$f" ]; then
        mv -f "$INSTALL_DIR/$f" "$INSTALL_DIR/cert/$f"
    fi
    [ -f "$INSTALL_DIR/cert/$f" ] || die "Missing cert file: $f (it must come from the agent zip)"
done
log "All cert files present: $CERT_FILE / $KEY_FILE / $CA_FILE"


CONFIG_BACKUPS="$(python3 - "$INSTALL_DIR/agent_config.json" "$CENTRAL_HOST" "$CENTRAL_REDIS_PORT" \
        "$REDIS_USERNAME" "$REDIS_PASSWORD" "$HOST_IFACE" "${CENTRAL_CANDIDATES:-}" <<'PY'
import json, os, sys, tempfile

path, host, port, user, password, iface, candidates_raw = sys.argv[1:8]
port = int(port)

old = {}
if os.path.exists(path):
    try:
        with open(path, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, dict):
            old = loaded
    except (OSError, ValueError):
        pass

seen = [(host, port)]

def push(h, p=None):
    h = str(h or "").strip()
    if not h:
        return
    try:
        p = int(p) if p else port
    except ValueError:
        return
    if (h, p) not in seen:
        seen.append((h, p))

for item in candidates_raw.replace(",", " ").split():
    h, _, p = item.rpartition(":")
    push(h or item, p if h else None)

push(old.get("central_host"), old.get("central_port"))

for item in old.get("central_candidates") or []:
    if isinstance(item, dict):
        push(item.get("host"), item.get("port"))
    elif isinstance(item, str):
        h, _, p = item.rpartition(":")
        push(h or item, p if h else None)

config = dict(old)
config.update({
    "central_host": host,
    "central_port": port,
    "central_candidates": [{"host": h, "port": p} for h, p in seen[1:]],
    "redis_username": user,
    "redis_password": password,
    "host_iface": iface,
})

fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".agent_config.")
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
    f.write("\n")
os.chmod(tmp, 0o600)
os.replace(tmp, path)

print(" ".join(f"{h}:{p}" for h, p in seen[1:]) or "-")
PY
)"
log "Wrote agent_config.json (host_iface=$HOST_IFACE, central=$CENTRAL_HOST:$CENTRAL_REDIS_PORT, backups=$CONFIG_BACKUPS)"


export DEBIAN_FRONTEND=noninteractive
NEED_PKGS=()
dpkg -s python3-venv >/dev/null 2>&1 || NEED_PKGS+=(python3-venv)
dpkg -s conntrack    >/dev/null 2>&1 || NEED_PKGS+=(conntrack)
dpkg -s curl         >/dev/null 2>&1 || NEED_PKGS+=(curl)
dpkg -s gnupg        >/dev/null 2>&1 || NEED_PKGS+=(gnupg)


APT_STAMP="/var/lib/apt/lists/.securelog-apt-update-stamp"
apt_lists_fresh() {  # apt_lists_fresh MINUTES — เพิ่ง update สำเร็จไปไม่เกินกี่นาที (update-success-stamp

    local f
    for f in "$APT_STAMP" /var/lib/apt/periodic/update-success-stamp; do
        [ -f "$f" ] && [ -n "$(find "$f" -mmin -"$1" -print -quit 2>/dev/null)" ] && return 0
    done
    return 1
}

if [ "${#NEED_PKGS[@]}" -gt 0 ]; then


    APT_LISTS_MAX_AGE_MIN="${APT_LISTS_MAX_AGE_MIN:-60}"
    if apt_lists_fresh "$APT_LISTS_MAX_AGE_MIN"; then
        log "apt package lists were refreshed less than $APT_LISTS_MAX_AGE_MIN minutes ago - apt-get update skipped"


    elif run_step "apt-get update" apt-get update -q \
            -o Acquire::Retries=1 -o Acquire::http::Timeout=15 -o Acquire::Languages=none; then
        : > "$APT_STAMP" 2>/dev/null || true
    else
        warn "apt-get update failed - trying the install with the lists already on disk"
    fi
    run_step "Installing packages: ${NEED_PKGS[*]}" apt-get install -y -qq "${NEED_PKGS[@]}"
else
    log "python3-venv + conntrack + curl + gnupg already present"
fi


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


        run_step "apt-get update (Elastic repo only)" apt-get update -q \
            -o Dir::Etc::sourcelist="$ELASTIC_LIST" -o Dir::Etc::sourceparts="-" \
            -o APT::Get::List-Cleanup="0" -o Acquire::Retries=1 -o Acquire::http::Timeout=15
        run_step "Installing filebeat 8.19.23" apt-get install -y -qq filebeat=8.19.23
        log "Installed filebeat from the Elastic APT repo (on a later re-run apt will upgrade it if a newer version exists)"
    else
        die "filebeat not found and no internet access - put filebeat-<version>-amd64.deb next to this script (download it from elastic.co) or connect to the internet and run again"
    fi
fi

filebeat version 2>/dev/null | grep -q 'filebeat version 8.19.23 ' \
    || die "This package requires the Filebeat 8.19.23 layout; install that version first"


if [ ! -x "$INSTALL_DIR/venv/bin/python" ]; then
    run_step "Creating venv (separate from system python - does not affect other processes)" \
        python3 -m venv "$INSTALL_DIR/venv"
else
    log "venv already exists"
fi

run_step "Installing python dependencies (redis, psutil) into the venv" \
    "$INSTALL_DIR/venv/bin/pip" install -q --disable-pip-version-check --no-input \
    --timeout "${PIP_TIMEOUT:-15}" --retries "${PIP_RETRIES:-2}" \
    -r "$INSTALL_DIR/requirements.txt"


TEMPLATE="$INSTALL_DIR/filebeat.yml.template"
[ -f "$TEMPLATE" ] || die "$TEMPLATE not found"

TMP_YML="$(mktemp)"
sed -e "s|__CENTRAL_HOST__|$CENTRAL_HOST|g" \
    -e "s|__CENTRAL_REDIS_PORT__|$CENTRAL_REDIS_PORT|g" \
    -e "s|__REDIS_USERNAME__|$REDIS_USERNAME|g" \
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
install -m 755 -o root -g root "$ACL_BEAT" /usr/local/bin/securelog-filebeat
"/usr/local/bin/securelog-filebeat" test config -c "$TMP_YML" >/dev/null || die "patched Filebeat config failed validation"
install -m 600 -o root -g root "$TMP_YML" /etc/filebeat/filebeat.yml
rm -f "$TMP_YML"
log "Installed /etc/filebeat/filebeat.yml"

mkdir -p /etc/systemd/system/filebeat.service.d
cat > /etc/systemd/system/filebeat.service.d/securelog-acl.conf <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/local/bin/securelog-filebeat --environment systemd $BEAT_LOG_OPTS $BEAT_CONFIG_OPTS $BEAT_PATH_OPTS
EOF
systemctl daemon-reload
log "filebeat config passed validation"


if [ ! -f "$MARKER" ]; then
    systemctl stop filebeat 2>/dev/null || true
    rm -rf /var/lib/filebeat/registry
    log "Clearing the filebeat registry (first install only)"
fi


chown -R root:root "$INSTALL_DIR"
chmod 600 "$INSTALL_DIR/cert/$KEY_FILE" "$INFO_FILE" "$INSTALL_DIR/agent_config.json"
log "Setting file permissions (key/token = 600, owned by root)"


if [ "${SKIP_FIREWALL:-0}" = "1" ]; then
    warn "SKIP_FIREWALL=1 - not touching ufw (the firewall detector needs 'ufw logging low' to be on)"
elif ! command -v ufw >/dev/null 2>&1; then
    warn "ufw is not installed - block IP commands have no effect on this machine"
    warn "Install it and turn it on: sudo apt-get install ufw && sudo ufw allow OpenSSH && sudo ufw enable"
else

    if ufw allow out to "$CENTRAL_HOST" port "$CENTRAL_REDIS_PORT" proto tcp \
            comment "SecureLog agent -> central Redis" >/dev/null 2>&1 \
       || ufw allow out to "$CENTRAL_HOST" port "$CENTRAL_REDIS_PORT" proto tcp >/dev/null 2>&1; then
        log "Allowed outbound $CENTRAL_HOST:$CENTRAL_REDIS_PORT/tcp in ufw (agent + filebeat -> central)"
    else
        warn "Could not add the ufw outbound rule for $CENTRAL_HOST:$CENTRAL_REDIS_PORT/tcp"
        warn "If outgoing traffic is denied by default here, add it yourself or the agent cannot report in"
    fi


    if [ "$CONFIG_BACKUPS" != "-" ]; then
        for _backup in $CONFIG_BACKUPS; do
            _bhost="${_backup%:*}"; _bport="${_backup##*:}"
            if ufw allow out to "$_bhost" port "$_bport" proto tcp \
                    comment "SecureLog agent -> central Redis" >/dev/null 2>&1 \
               || ufw allow out to "$_bhost" port "$_bport" proto tcp >/dev/null 2>&1; then
                log "Allowed outbound $_bhost:$_bport/tcp in ufw (central backup address)"
            fi
        done
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


sed "s|__INSTALL_DIR__|$INSTALL_DIR|g" "$INSTALL_DIR/$SERVICE_NAME.service" \
    > "/etc/systemd/system/$SERVICE_NAME.service"
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME" >/dev/null 2>&1
systemctl restart "$SERVICE_NAME"      # รันซ้ำ = โหลดโค้ด/config ใหม่
systemctl enable --now filebeat >/dev/null 2>&1
systemctl restart filebeat
log "Enabled services: $SERVICE_NAME + filebeat (they also start on boot)"

touch "$MARKER"


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


for f in /var/log/auth.log /var/log/apache2/*access.log /var/log/nginx/*access.log /var/log/tomcat*/*access_log*.txt /var/log/ufw.log /var/log/iptables.log; do
    if [ -e "$f" ] && [ ! -r "$f" ]; then
        warn "$f exists but is not readable - filebeat cannot collect this log"
    fi
done

echo ""
log "Installation complete - check the status:"
echo "    systemctl status $SERVICE_NAME filebeat"
echo "    journalctl -u $SERVICE_NAME -f"
echo "  Then check the Agents page on the dashboard to see $AGENT_ID come online"
