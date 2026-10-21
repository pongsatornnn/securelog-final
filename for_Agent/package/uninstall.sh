#!/usr/bin/env bash
#
# SecureLog Client — uninstall the service, filebeat, and client files
#
# Usage:
#   sudo ./uninstall.sh                       # choose whether to keep firewall rules
#   sudo ./uninstall.sh --yes                 # keep rules, skip prompts
#   sudo ./uninstall.sh --yes --remove-rules  # remove SecureLog-owned rules
#   sudo ./uninstall.sh --yes --keep-rules    # explicitly keep rules
#   sudo KEEP_FILEBEAT=1 ./uninstall.sh       # keep filebeat installed
#
# ทำงานเฉพาะฝั่ง agent ไม่ยุ่งกับ central
set -euo pipefail

SERVICE_NAME="securelog-agent"          # ชื่อเป๊ะ ห้าม glob (central มี securelog-agent-monitor)
UNIT_PATH="/etc/systemd/system/$SERVICE_NAME.service"

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

remove_securelog_rules() {
    if ! command -v ufw >/dev/null 2>&1; then
        log "ufw not installed - no firewall rules to remove"
        return 0
    fi
    local ufw_status line number i
    local -a managed_numbers=()
    ufw_status="$(ufw status numbered 2>&1)" || die "could not inspect ufw rules; no files or rules were removed: $ufw_status"
    if [[ "$ufw_status" == *"Status: inactive"* ]]; then
        die "ufw is inactive, so numbered rules cannot be inspected safely; use --keep-rules or inspect ufw before retrying"
    fi
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*\[[[:space:]]*([0-9]+)\] ]] || continue
        number="${BASH_REMATCH[1]}"
        if [[ "$line" =~ [[:space:]](DENY|REJECT)[[:space:]]+IN[[:space:]] ]] \
           && [[ "$line" =~ \#[[:space:]]*(Securelog:|central_blacklist([:[:space:]]|$)) ]]; then
            managed_numbers+=("$number")
        elif [[ "$line" =~ [[:space:]]ALLOW[[:space:]]+OUT[[:space:]] ]] \
             && [[ "$line" =~ \#[[:space:]]*SecureLog[[:space:]]agent([[:space:]]|$) ]]; then
            managed_numbers+=("$number")
        fi
    done <<< "$ufw_status"

    if [ "${#managed_numbers[@]}" -eq 0 ]; then
        log "No SecureLog-tagged ufw rules found"
    else
        # Use rule numbers rather than a spec that could match an unrelated rule.
        # Deleting highest numbers first keeps the remaining numbers stable.
        for ((i=${#managed_numbers[@]}-1; i>=0; i--)); do
            number="${managed_numbers[i]}"
            ufw --force delete "$number" >/dev/null 2>&1 \
                || die "could not remove SecureLog ufw rule #$number; uninstall stopped"
            log "Removed SecureLog ufw rule #$number"
        done
    fi
    log "Other firewall rules and ufw logging were left unchanged"
}

# ---------- อ่าน flag ----------
ASSUME_YES="${FORCE:-0}"
KEEP_FILEBEAT="${KEEP_FILEBEAT:-0}"
RULE_ACTION=""
for arg in "$@"; do
    case "$arg" in
        -y|--yes)        ASSUME_YES=1 ;;
        --keep-filebeat) KEEP_FILEBEAT=1 ;;
        --keep-rules)    [ "$RULE_ACTION" != "remove" ] || die "choose only one of --keep-rules or --remove-rules"; RULE_ACTION="keep" ;;
        --remove-rules)  [ "$RULE_ACTION" != "keep" ] || die "choose only one of --keep-rules or --remove-rules"; RULE_ACTION="remove" ;;
        -h|--help)
            sed -n '3,11p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) die "unknown option: $arg (use --help for options)" ;;
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

# Decide before stopping the Client. A non-interactive uninstall keeps rules
# unless --remove-rules was explicitly requested.
if [ -z "$RULE_ACTION" ]; then
    if [ "$ASSUME_YES" = "1" ]; then
        RULE_ACTION="keep"
    else
        [ -t 0 ] || die "no tty - choose --yes --keep-rules or --yes --remove-rules"
        echo ""
        echo "Firewall rules after uninstall:"
        echo "  1) Keep rules (default)"
        echo "  2) Remove SecureLog rules"
        while true; do
            read -rp "Select [1/2]: " choice || die "aborted - nothing was removed"
            case "$choice" in
                ""|1) RULE_ACTION="keep"; break ;;
                2) RULE_ACTION="remove"; break ;;
                *) warn "Enter 1 or 2" ;;
            esac
        done
    fi
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
if [ "$RULE_ACTION" = "remove" ]; then
    echo "     - remove SecureLog-tagged ufw block and outbound rules only"
else
    echo "     - keep all firewall rules"
fi
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

# Stop the Client first so it cannot recreate a rule during cleanup.
systemctl stop "$SERVICE_NAME.service" 2>/dev/null || true

# ---------- 1) firewall selection takes effect before files are removed ----------
if [ "$RULE_ACTION" = "remove" ]; then
    remove_securelog_rules
else
    log "Kept all firewall rules"
fi

# ---------- 2) securelog-agent service ----------
if systemctl list-unit-files --plain --no-legend "$SERVICE_NAME.service" 2>/dev/null | grep -q .; then
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

# ---------- 3) filebeat ----------
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
echo "     Remember to remove this Client on the dashboard's Clients page too (its IP binding stays on central)."
