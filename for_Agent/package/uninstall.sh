#!/usr/bin/env bash
#
# SecureLog Agent — ถอนการติดตั้ง agent ออกจากเครื่อง (ลบ service + filebeat + ufw rule + โฟลเดอร์ agent)
#
# วิธีใช้:
#   sudo ./uninstall.sh                 # ถามยืนยันก่อน
#   sudo ./uninstall.sh --yes           # ไม่ถาม
#   sudo KEEP_FILEBEAT=1 ./uninstall.sh # เก็บ filebeat ไว้
#
# ทำงานเฉพาะฝั่ง agent ไม่ยุ่งกับ central
set -euo pipefail

SERVICE_NAME="securelog-agent"          # ชื่อเป๊ะ ห้าม glob (central มี securelog-agent-monitor)
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME.service"
FW_TAG="SecureLog agent"                # ป้ายใน comment ของ ufw ที่บอกว่า rule นี้ของ agent

# re-exec จาก /tmp ก่อน เพราะสคริปต์อยู่ในโฟลเดอร์ที่ตัวเองจะลบ
if [ "${_SL_RELOCATED:-0}" != "1" ]; then
    _here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    _tmp="$(mktemp /tmp/securelog-uninstall.XXXXXX.sh)"
    cp "$_here/$(basename "${BASH_SOURCE[0]}")" "$_tmp"
    chmod +x "$_tmp"
    exec env _SL_RELOCATED=1 _SL_TMP="$_tmp" SL_AGENT_DIR="$_here" bash "$_tmp" "$@"
fi
trap 'rm -f "$_SL_TMP"' EXIT
AGENT_DIR="$SL_AGENT_DIR"

log()  { echo -e "\e[32m[UNINSTALL]\e[0m $*"; }
warn() { echo -e "\e[33m[WARN]\e[0m      $*"; }
die()  { echo -e "\e[31m[ERROR]\e[0m     $*" >&2; exit 1; }

# ---------- อ่าน flag ----------
ASSUME_YES="${FORCE:-0}"
KEEP_FILEBEAT="${KEEP_FILEBEAT:-0}"
for arg in "$@"; do
    case "$arg" in
        -y|--yes)        ASSUME_YES=1 ;;
        --keep-filebeat) KEEP_FILEBEAT=1 ;;
        -h|--help)
            sed -n '3,9p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown option: $arg (use --yes / --keep-filebeat)" ;;
    esac
done

[ "$(id -u)" -eq 0 ] || die "Must be run as root: sudo ./uninstall.sh"

# ---------- ด่านกันลบผิดโฟลเดอร์ ----------
case "$AGENT_DIR" in
    ""|/|/opt|/home|/root|/etc|/usr|/var|/srv|/tmp)
        die "refusing to operate on '$AGENT_DIR' - this does not look like an agent folder" ;;
esac
IS_AGENT_DIR=0
if [ -f "$AGENT_DIR/agent_core.py" ] \
   && { [ -f "$AGENT_DIR/agent_config.json" ] || [ -f "$AGENT_DIR/securelog-agent.service" ]; }; then
    IS_AGENT_DIR=1
fi

# ---------- สรุปสิ่งที่จะทำ + ขอยืนยัน ----------
echo ""
warn "This will REMOVE the SecureLog agent from this machine:"
echo "     - stop + disable + delete the '$SERVICE_NAME' service"
if [ "$KEEP_FILEBEAT" = "1" ]; then
    echo "     - stop filebeat and remove ONLY the config this system wrote (the filebeat package is kept)"
else
    echo "     - stop + remove filebeat entirely (package, /etc/filebeat, registry, the Elastic apt repo this system added)"
fi
echo "     - remove the ufw outbound rule this system added (rules you made yourself are left alone)"
if [ "$IS_AGENT_DIR" = "1" ]; then
    echo "     - delete the agent folder and everything in it:  $AGENT_DIR"
else
    warn "     - '$AGENT_DIR' does not look like an agent folder - it will NOT be deleted (only services/filebeat/ufw are cleaned)"
fi
echo ""
warn "central is NOT touched. The agent's IP binding still lives on central - remove the agent on the Agents page too."
echo ""

if [ "$ASSUME_YES" != "1" ]; then
    if [ ! -t 0 ]; then
        die "no tty - refusing to remove anything without confirmation. Re-run with: sudo ./uninstall.sh --yes"
    fi
    read -rp "  Remove all of the above? [y/N] " ans
    case "${ans:-n}" in
        [Yy]*) ;;
        *) die "aborted - nothing was removed" ;;
    esac
fi

echo ""

# ---------- 1) securelog-agent service ----------
if systemctl list-unit-files --plain --no-legend "$SERVICE_NAME.service" 2>/dev/null | grep -q .; then
    systemctl stop    "$SERVICE_NAME.service" 2>/dev/null || true
    systemctl disable "$SERVICE_NAME.service" >/dev/null 2>&1 || true
    log "Stopped and disabled $SERVICE_NAME"
else
    log "$SERVICE_NAME service not present - skipped"
fi
if [ -f "$UNIT_PATH" ]; then
    rm -f "$UNIT_PATH"
    log "Removed $UNIT_PATH"
fi
systemctl daemon-reload
systemctl reset-failed "$SERVICE_NAME.service" 2>/dev/null || true

# ---------- 2) filebeat ----------
if [ "$KEEP_FILEBEAT" = "1" ]; then
    systemctl stop filebeat 2>/dev/null || true
    systemctl disable filebeat >/dev/null 2>&1 || true
    rm -f /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.bak.* 2>/dev/null || true
    log "Stopped filebeat and removed the config this system wrote (package kept: KEEP_FILEBEAT=1)"
else
    systemctl stop filebeat 2>/dev/null || true
    systemctl disable filebeat >/dev/null 2>&1 || true

    if command -v apt-get >/dev/null 2>&1 && dpkg -s filebeat >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq filebeat >/dev/null 2>&1 \
            && log "Purged the filebeat package" \
            || warn "Could not purge filebeat via apt - remove it yourself if it is still there"
    else
        warn "filebeat package not registered with dpkg - skipping package removal"
    fi

    rm -rf /etc/filebeat /var/lib/filebeat /var/log/filebeat 2>/dev/null || true
    REPO_REMOVED=0
    [ -f /etc/apt/sources.list.d/elastic-8.x.list ] && { rm -f /etc/apt/sources.list.d/elastic-8.x.list; REPO_REMOVED=1; }
    [ -f /usr/share/keyrings/elastic.gpg ]          && { rm -f /usr/share/keyrings/elastic.gpg;          REPO_REMOVED=1; }
    [ "$REPO_REMOVED" = "1" ] && log "Removed the Elastic apt repo + keyring that the installer had added"
    log "Removed filebeat config, registry and logs"
fi

# ---------- 3) ลบ ufw rule ของ agent (เฉพาะที่มีป้าย SecureLog agent) ----------
if command -v ufw >/dev/null 2>&1; then
    mapfile -t OUR_RULES < <(ufw show added 2>/dev/null | grep -F "comment '$FW_TAG" || true)
    if [ "${#OUR_RULES[@]}" -eq 0 ]; then
        log "No ufw rule tagged '$FW_TAG' - nothing to remove"
    else
        for line in "${OUR_RULES[@]}"; do
            spec="${line#ufw }"
            spec="${spec% comment *}"
            # shellcheck disable=SC2086
            if ufw --force delete $spec >/dev/null 2>&1; then
                log "Removed ufw rule: $spec"
            else
                warn "Could not remove ufw rule automatically: $spec"
                warn "  Remove it yourself: sudo ufw delete $spec"
            fi
        done
    fi
    warn "ufw logging is left as it is (it is a machine-wide setting; turn it off yourself if you want: sudo ufw logging off)"
else
    log "ufw not installed - no firewall rule to remove"
fi

# ---------- 4) ลบโฟลเดอร์ agent ----------
if [ "$IS_AGENT_DIR" = "1" ]; then
    rm -rf "$AGENT_DIR"
    if [ -d "$AGENT_DIR" ]; then
        warn "Some files under $AGENT_DIR could not be removed - delete it yourself: sudo rm -rf $AGENT_DIR"
    else
        log "Deleted the agent folder: $AGENT_DIR"
    fi
else
    warn "Left '$AGENT_DIR' in place (it did not look like an agent folder) - delete it yourself if it is one"
fi

echo ""
log "SecureLog agent removed from this machine."
echo "     Remember to remove this agent on the dashboard's Agents page too (its IP binding stays on central)."
