#!/usr/bin/env bash
#
# ติดตั้ง/อัปเดต systemd units ของ SecureLog (ฝั่ง server)
#   sudo ./install.sh
#
# สร้าง unit ใหม่จาก `_gen.sh` ให้ทุกครั้งก่อน copy — path/user/IP จึงตรงกับ "ที่ที่โปรเจกต์
# วางอยู่ตอนนี้" เสมอ ย้ายโฟลเดอร์ไปไหนก็แค่รันไฟล์นี้ซ้ำ ไม่ต้องไปไล่แก้ unit เอง
# (จะข้ามขั้นตอนสร้างใหม่แล้วใช้ไฟล์ที่มีอยู่: SKIP_GEN=1 sudo ./install.sh)
#
# ครั้งแรกจะถาม "IP ที่จะ bind" แยกกันระหว่าง dashboard (:8000) กับ LINE webhook (:8080) โดยโชว์
# interface ที่มีบนเครื่องให้เลือก หรือ 0.0.0.0 = ทุกเส้น · คำตอบถูกจำไว้ใน .env รอบหน้าไม่ถามซ้ำ
#   เปลี่ยนทีหลัง:  ASK_HOSTS=1 sudo ./install.sh   (หรือแก้ WEB_BIND_HOST/WEBHOOK_BIND_HOST ใน .env)
#
# รันซ้ำได้ — แก้โค้ด/ย้ายที่แล้วรันใหม่ = regenerate + copy ทับ + daemon-reload + restart
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$DIR")"

[ "$(id -u)" -eq 0 ] || { echo "Must be run as root: sudo ./install.sh" >&2; exit 1; }

# ---- สร้าง unit ตามที่ตั้งจริงของโปรเจกต์ก่อน (ค่าที่ export มาจะชนะการหาเองใน _gen.sh) ----
if [ "${SKIP_GEN:-0}" != "1" ]; then
    bash "$DIR/_gen.sh"
fi

# unit ทุกตัวชี้ไป venv ของโปรเจกต์ — ไม่มี venv = systemd ตอบ 203/EXEC ทุกตัวโดยไม่บอกสาเหตุ
if [ ! -x "$PROJECT_DIR/venv/bin/python" ]; then
    echo "!! $PROJECT_DIR/venv/bin/python not found - create the venv before installing the services:" >&2
    echo "   python3 -m venv $PROJECT_DIR/venv && $PROJECT_DIR/venv/bin/pip install -r $PROJECT_DIR/requirements.txt" >&2
    exit 1
fi

# กันเคสรัน service ซ้อนกับ process ที่รันมือค้างในเทอร์มินัล
# (web จะ bind port 8000 ไม่ได้ / detector 2 ตัวบนคิวเดียวกันจะแบ่ง log กันคนละครึ่ง)
# match ด้วย path จริงของโปรเจกต์ ไม่ใช่ชื่อโฟลเดอร์ตายตัว — วางไว้ที่ไหน/ชื่ออะไรก็ยังเจอ
#
# ⚠️ แยก "ของ systemd" ออกด้วย **cgroup** ไม่ใช่ข้อความใน cmdline:
#   systemd จัดการ -> /system.slice/<unit>.service   ·   รันมือจากเทอร์มินัล -> /user.slice/...scope
# ของเดิมใช้ `grep -v systemd` ซึ่งกรองจาก cmdline แต่ cmdline ของ service ไม่มีคำว่า systemd
# อยู่เลย (เป็น `.../venv/bin/python -m process_log_detect.normalize_log`) จึงกรองไม่ออก แล้ว
# เตือนผิดว่า service ทั้ง 9 ตัวของตัวเองคือ process ที่รันมือ — ตอบ y ก็ไป kill service ตัวเอง
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

# centralredis = infrastructure (แยกจาก securelog.target โดยตั้งใจ) — enable ให้ start ตอน boot
# แต่ "start เฉพาะตอนยังไม่ทำงาน" ไม่ restart ตัวที่รันอยู่ เพราะ restart Redis = ตัดคิว log +
# connection ของ agent ทุกตัวพร้อมกัน (ถ้าแก้ redis-mtls.conf/users.acl แล้วต้องการ reload ให้สั่งเอง)
systemctl enable centralredis.service >/dev/null 2>&1
if ! systemctl is-active --quiet centralredis.service; then
    echo ">> Starting centralredis.service (not running yet)"
    systemctl start centralredis.service
else
    echo ">> centralredis.service already running - skipped (after a config change, reload it yourself: systemctl restart centralredis.service)"
fi

# enable แค่ target ตัวเดียวพอ — ทุก service ถูกดึงผ่าน Wants= ใน target
# (service ไม่ enable ตรงกับ multi-user เอง จะ start/stop ตาม target เท่านั้น)
systemctl enable securelog.target >/dev/null 2>&1
systemctl restart securelog.target

echo ""
echo "=== Status ==="
sleep 2
systemctl --no-pager --plain list-units 'securelog-*' || true
echo ""
echo "View logs:  journalctl -u <service name> -f"
echo "Whole stack: sudo systemctl restart securelog.target"
