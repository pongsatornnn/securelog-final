#!/usr/bin/env bash

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$DIR")"

[ "$(id -u)" -eq 0 ] || { echo "Must be run as root: sudo ./install.sh" >&2; exit 1; }


if [ "${SKIP_GEN:-0}" != "1" ]; then
    bash "$DIR/_gen.sh"
fi


if [ ! -x "$PROJECT_DIR/venv/bin/python" ]; then
    echo "!! $PROJECT_DIR/venv/bin/python not found - create the venv before installing the services:" >&2
    echo "   python3 -m venv $PROJECT_DIR/venv && $PROJECT_DIR/venv/bin/pip install -r $PROJECT_DIR/requirements.txt" >&2
    exit 1
fi


MANUAL=""
while read -r pid rest; do
    [ -n "${pid:-}" ] || continue
    grep -qE '/system\.slice/[^/]*\.service' "/proc/$pid/cgroup" 2>/dev/null && continue
    MANUAL="$MANUAL$pid $rest"$'\n'
done < <(
    pgrep -af "$PROJECT_DIR" \
        | grep -E "uvicorn|process_log_detect|process_agent|blacklist_expiry|alert_subscriber|webhook_app" \
        || true
)
MANUAL="${MANUAL%$'\n'}"
if [ -n "$MANUAL" ]; then
    echo "!! Found manually started processes - stop them first or they will clash with the services:"
    echo "$MANUAL"
    read -rp "Kill them now? [y/N] " ans
    if [ "${ans,,}" = "y" ]; then
        echo "$MANUAL" | awk '{print $1}' | xargs -r kill
        sleep 2
    else
        echo "Aborted - stop those processes yourself, then run this again" >&2
        exit 1
    fi
fi

cp "$DIR"/securelog-*.service "$DIR"/securelog.target "$DIR"/centralredis.service /etc/systemd/system/
systemctl daemon-reload


systemctl enable centralredis.service >/dev/null 2>&1
if ! systemctl is-active --quiet centralredis.service; then
    echo ">> Starting centralredis.service (not running yet)"
    systemctl start centralredis.service
else
    echo ">> centralredis.service already running - skipped (after a config change, reload it yourself: systemctl restart centralredis.service)"
fi


systemctl enable securelog.target >/dev/null 2>&1
systemctl restart securelog.target


if [ "${QUIET_STATUS:-0}" != "1" ]; then
    echo ""
    echo "=== Status ==="
    sleep 2
    systemctl --no-pager --plain list-units 'securelog-*' || true
    echo ""
    echo "View logs:  journalctl -u <service name> -f"
    echo "Whole stack: sudo systemctl restart securelog.target"
fi
