#!/usr/bin/env bash


set -euo pipefail

PROJECT_DIR="${PROJECT_DIR:-$(cd "$(dirname "$0")" && pwd)}"
DEST_DIR="$PROJECT_DIR/main/database/geoip"
DEST="$DEST_DIR/dbip-country-lite.mmdb"


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
        echo "Skipping IP holder country data: python3 is not installed"
        return 0
    fi

    local got=() missing=() rir url file
    for entry in "${RIR_URLS[@]}"; do
        read -r rir url <<< "$entry"
        [ -n "${RIR_STATS_MIRROR:-}" ] && url="${RIR_STATS_MIRROR%/}/delegated-${rir}-extended-latest"
        file="$HOLDER_TMP/$rir"


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
                echo "Updated IP holder country data (all 5 sources): $HOLDER_DEST"
            else
                echo "Built IP holder country data from available sources (missing: ${missing[*]}); rerun later"
            fi
        else
            echo "Could not build IP holder country data; keeping the existing file if available"
        fi
    elif [ "${#got[@]}" -gt 0 ]; then
        echo "IP holder country download incomplete (missing: ${missing[*]}); keeping the existing file"
    else
        echo "Could not download IP holder country data; keeping the existing file if available"
    fi
}

update_holder


for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m)"; do
    url="${GEOIP_URL_BASE:-https://download.db-ip.com/free}/dbip-country-lite-${month}.mmdb.gz"
    if fetch "$url" "$TMP.gz"; then
        gunzip -c "$TMP.gz" > "$TMP"

        if ! grep -aq 'MaxMind.com' "$TMP"; then
            echo "Downloaded file is not an MMDB database: $url" >&2
            exit 1
        fi
        chmod 644 "$TMP"
        mv -f "$TMP" "$DEST"
        echo "Updated IP country database: $DEST ($month)"
        exit 0
    fi
done

echo "GeoIP download failed; check access to download.db-ip.com" >&2
exit 1
