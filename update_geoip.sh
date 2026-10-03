#!/usr/bin/env bash
# โหลด/อัปเดตไฟล์ฐานข้อมูลประเทศของ IP (DB-IP Lite Country) — ใช้แสดงธงข้าง Attacker IP
# DB-IP ออกไฟล์ใหม่ทุกเดือน แนะนำรันเดือนละครั้ง (เช่นใส่ cron) · service จะอ่านไฟล์ใหม่เองไม่ต้อง restart
#
# วิธีใช้ (รันในโฟลเดอร์โปรเจกต์):  bash update_geoip.sh
# ข้อมูล IP โดย DB-IP (https://db-ip.com) — สัญญาอนุญาต CC BY 4.0

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
DEST_DIR="$PROJECT_DIR/main/database/geoip"
DEST="$DEST_DIR/dbip-country-lite.mmdb"

# โหลดด้วย curl ถ้ามี ไม่มีก็ใช้ python3 (เครื่อง server ขั้นต่ำบางเครื่องไม่ได้ลง curl)
fetch() {  # fetch URL OUTFILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --max-time 120 -o "$2" "$1"
    else
        python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$1" "$2" 2>/dev/null
    fi
}

mkdir -p "$DEST_DIR"
TMP="$(mktemp "$DEST_DIR/.download.XXXXXX")"
trap 'rm -f "$TMP" "$TMP.gz"' EXIT

# ไฟล์ของเดือนนี้ยังไม่ออก (ต้นเดือน) -> ถอยไปใช้ของเดือนก่อน
for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"; do
    url="${GEOIP_URL_BASE:-https://download.db-ip.com/free}/dbip-country-lite-${month}.mmdb.gz"
    if fetch "$url" "$TMP.gz"; then
        gunzip -c "$TMP.gz" > "$TMP"
        # ไฟล์ mmdb ต้องมี marker นี้ท้ายไฟล์ — กันได้หน้า error HTML มาแทน
        if ! grep -aq 'MaxMind.com' "$TMP"; then
            echo "ไฟล์ที่โหลดมาไม่ใช่ mmdb: $url" >&2
            exit 1
        fi
        chmod 644 "$TMP"
        mv -f "$TMP" "$DEST"
        echo "อัปเดตฐานข้อมูลประเทศของ IP แล้ว: $DEST ($month)"
        exit 0
    fi
done

echo "โหลดไฟล์ GeoIP ไม่สำเร็จ — เช็คว่าเครื่องออกเน็ตไป download.db-ip.com ได้" >&2
exit 1
