#!/usr/bin/env bash
# โหลด/อัปเดตข้อมูลประเทศของ IP 2 ชุด — service อ่านไฟล์ใหม่เองไม่ต้อง restart · แนะนำรันเดือนละครั้ง
#   1) ประเทศผู้ถือ IP: ไฟล์สถิติการแจก IP ของผู้ดูแล IP ทั้ง 5 แห่ง (RIPE/ARIN/APNIC/LACNIC/AFRINIC)
#      ย่อเป็น main/database/geoip/holder-country.txt.gz — แสดงในหน้ารายละเอียด alert
#      ไม่ใช่ตัวหลัก: โหลดไม่ได้แค่เตือน ไม่ทำให้สคริปต์ล้ม · โหลดไม่ครบ 5 แห่ง = ใช้ไฟล์เดิมต่อ
#   2) ประเทศที่ใช้งาน: DB-IP Lite Country (.mmdb) — ธงข้าง Attacker IP · โหลดไม่ได้ = exit 1
#
# วิธีใช้ (รันในโฟลเดอร์โปรเจกต์):  bash update_geoip.sh
# ข้อมูล IP โดย DB-IP (https://db-ip.com) — สัญญาอนุญาต CC BY 4.0
# เครือข่ายปิด: ตั้ง RIR_STATS_MIRROR=<url ที่มีไฟล์ delegated-<rir>-extended-latest> ให้โหลดจาก mirror แทน

set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
DEST_DIR="$PROJECT_DIR/main/database/geoip"
DEST="$DEST_DIR/dbip-country-lite.mmdb"

# โหลดด้วย curl ถ้ามี ไม่มีก็ใช้ python3 (เครื่อง server ขั้นต่ำบางเครื่องไม่ได้ลง curl)
fetch() {  # fetch URL OUTFILE
    if command -v curl >/dev/null 2>&1; then
        curl -fsL --max-time 120 -o "$2" "$1"   # -s ไม่มี -S: ข้อความ error ของ curl ไม่ปนสรุปของสคริปต์
    else
        python3 -c 'import sys, urllib.request; urllib.request.urlretrieve(sys.argv[1], sys.argv[2])' "$1" "$2" 2>/dev/null
    fi
}

mkdir -p "$DEST_DIR"
TMP="$(mktemp "$DEST_DIR/.download.XXXXXX")"
HOLDER_TMP="$(mktemp -d "$DEST_DIR/.holder.XXXXXX")"
trap 'rm -rf "$TMP" "$TMP.gz" "$HOLDER_TMP"' EXIT

# ───── 1) ประเทศผู้ถือ IP ─────
HOLDER_DEST="$DEST_DIR/holder-country.txt.gz"
RIR_URLS=(
    "ripencc https://ftp.ripe.net/pub/stats/ripencc/delegated-ripencc-extended-latest"
    "arin    https://ftp.arin.net/pub/stats/arin/delegated-arin-extended-latest"
    "apnic   https://ftp.apnic.net/stats/apnic/delegated-apnic-extended-latest"
    "lacnic  https://ftp.lacnic.net/pub/stats/lacnic/delegated-lacnic-extended-latest"
    "afrinic https://ftp.afrinic.net/pub/stats/afrinic/delegated-afrinic-extended-latest"
)

update_holder() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "ข้ามประเทศผู้ถือ IP: เครื่องนี้ไม่มี python3"
        return 0
    fi

    local got=() missing=() rir url file
    for entry in "${RIR_URLS[@]}"; do
        read -r rir url <<< "$entry"
        [ -n "${RIR_STATS_MIRROR:-}" ] && url="${RIR_STATS_MIRROR%/}/delegated-${rir}-extended-latest"
        file="$HOLDER_TMP/$rir"
        # ไฟล์จริงมีบรรทัดหัว "<เวอร์ชัน>|<ชื่อผู้ดูแล>|..." (เช่น 2|ripencc · 2.3|arin) — APNIC มีคอมเมนต์
        # นำหน้า จึงค้นทั้งไฟล์ ไม่ดูแค่บรรทัดแรก · กันได้หน้า error HTML มาแทน
        if fetch "$url" "$file" && grep -m1 -qE "^[0-9][0-9.]*\|${rir}\|" "$file"; then
            got+=("$file")
        else
            missing+=("$rir")
        fi
    done

    if [ "${#missing[@]}" -eq 0 ] || { [ ! -s "$HOLDER_DEST" ] && [ "${#got[@]}" -gt 0 ]; }; then
        if python3 "$PROJECT_DIR/main/geoip_holder.py" build "${got[@]}" "$HOLDER_DEST" >/dev/null; then
            chmod 644 "$HOLDER_DEST"
            if [ "${#missing[@]}" -eq 0 ]; then
                echo "อัปเดตประเทศผู้ถือ IP แล้ว (ครบ 5 แหล่ง): $HOLDER_DEST"
            else
                echo "สร้างประเทศผู้ถือ IP จากเท่าที่โหลดได้ (ขาด: ${missing[*]}) — รันใหม่ภายหลังให้ครบ"
            fi
        else
            echo "สร้างตารางประเทศผู้ถือ IP ไม่สำเร็จ — ใช้ไฟล์เดิมต่อ (ถ้ามี)"
        fi
    elif [ "${#got[@]}" -gt 0 ]; then
        echo "โหลดประเทศผู้ถือ IP ไม่ครบ (ขาด: ${missing[*]}) — ใช้ไฟล์เดิมต่อ"
    else
        echo "โหลดประเทศผู้ถือ IP ไม่ได้ — ใช้ไฟล์เดิมต่อ (ถ้ามี)"
    fi
}

update_holder

# ───── 2) ประเทศที่ใช้งาน (DB-IP Lite Country) ─────

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
