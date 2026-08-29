#!/usr/bin/env bash
# ตัวช่วยเรื่อง "IP ที่แต่ละ service จะ bind" — ใช้ร่วมกันระหว่าง setup-server.sh กับ systemd/_gen.sh

# IPv4 ทุกเส้นบนเครื่อง -> "IP<TAB>ชื่อ interface" (เส้น global ก่อน แล้วค่อย loopback)
list_host_ips() {
    ip -4 -o addr show scope global 2>/dev/null | awk '{split($4,a,"/"); print a[1]"\t"$2}'
    ip -4 -o addr show scope host   2>/dev/null | awk '{split($4,a,"/"); print a[1]"\t"$2}'
}

# IP หลักของเครื่อง = เส้นที่ออกเน็ต ใช้เป็นค่า default ตอนไม่มีอะไรให้อ้างอิงเลย
detect_primary_ip() {
    local ip
    # || true ทุกบรรทัด: เครื่องที่ไม่มี default route จะทำให้ pipefail ของสคริปต์แม่ตายทั้งตัว
    ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')" || true
    [ -n "$ip" ] || ip="$(list_host_ips | awk 'NR==1{print $1}')" || true
    printf '%s' "$ip"
}

# --host ที่ unit ซึ่งติดตั้งอยู่ "ตอนนี้" ใช้อยู่จริง — เอามาเป็นค่า default ของคำถาม
installed_bind_host() {  # installed_bind_host UNIT_NAME
    local unit="${SYSTEMD_UNIT_DIR:-/etc/systemd/system}/$1"
    [ -f "$unit" ] || return 0
    sed -nE 's/.*ExecStart=.*--host[[:space:]]+([^[:space:]]+).*/\1/p' "$unit" 2>/dev/null | head -1 || true
}

# กันพิมพ์ตกอย่าง "192.168.56" หรือ "300.1.1.1" ที่ทำให้ uvicorn ตายตอน start (systemd ขึ้นแค่ code=1)
valid_host() {
    local h="$1" o
    case "$h" in ''|*[[:space:]]*) return 1 ;; esac
    if printf '%s' "$h" | grep -qE '^[0-9.]+$'; then
        printf '%s' "$h" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || return 1
        for o in ${h//./ }; do [ "$o" -le 255 ] || return 1; done
        return 0
    fi
    printf '%s' "$h" | grep -qE '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
}

# พอร์ต TCP ที่ service ของเรา bind — ใช้ร่วมกันระหว่าง setup-server.sh (ตอนถาม) กับ
valid_port() {  # valid_port PORT
    local p="$1"
    printf '%s' "$p" | grep -qE '^[1-9][0-9]{0,4}$' || return 1
    [ "$p" -ge 1024 ] && [ "$p" -le 65535 ]
}

# pick_bind_host VAR "คำถาม" "ค่า default" [allow_any=1] [คำอธิบายเพิ่ม]
pick_bind_host() {
    local var="$1" title="$2" def="${3:-}" allow_any="${4:-1}" hint="${5:-}"
    local cur ans i ip iface mark
    local -a choices=() labels=()

    cur="$(eval "printf '%s' \"\${$var:-}\"")"
    [ -n "$cur" ] && return 0
    if [ ! -t 0 ]; then eval "$var=\$def"; return 0; fi

    if [ "$allow_any" = "1" ]; then
        choices+=("0.0.0.0"); labels+=("all interfaces")
    fi
    while IFS=$'\t' read -r ip iface; do
        [ -n "$ip" ] || continue
        choices+=("$ip")
        if [ "$iface" = "lo" ]; then labels+=("$iface (this machine only)"); else labels+=("$iface"); fi
    done < <(list_host_ips)

    echo ""
    echo "  $title"
    [ -n "$hint" ] && echo "    $hint"
    for i in "${!choices[@]}"; do
        mark=""
        [ "${choices[$i]}" = "$def" ] && mark="  <- default"
        printf '    %d) %-15s %s%s\n' "$((i+1))" "${choices[$i]}" "${labels[$i]}" "$mark"
    done

    while :; do
        read -rp "    Pick a number, or type a value${def:+ [$def]}: " ans
        ans="${ans:-$def}"
        # ตัวเลขล้วน = เลือกจากเมนู (เลขโดด ๆ ไม่มีทางเป็น IP ที่ถูกต้องอยู่แล้ว จึงไม่กำกวม)
        if printf '%s' "$ans" | grep -qE '^[0-9]+$'; then
            if [ "$ans" -ge 1 ] && [ "$ans" -le "${#choices[@]}" ]; then
                ans="${choices[$((ans-1))]}"
            else
                echo "    !! No option $ans in the list (1-${#choices[@]}) - try again"
                continue
            fi
        fi
        if [ "$ans" = "0.0.0.0" ] && [ "$allow_any" != "1" ]; then
            echo "    !! 0.0.0.0 is not valid here - it must be a real IP other machines can reach"
            continue
        fi
        valid_host "$ans" && break
        echo "    !! '$ans' is not a valid IP or hostname - try again"
    done
    eval "$var=\$ans"
}

# อ่านค่าจาก .env (รองรับทั้ง KEY=value และ KEY = "value" ที่ปนกันอยู่ในไฟล์จริง)
env_get() {  # env_get KEY FILE
    local key="$1" file="$2" line val
    [ -f "$file" ] || return 0
    line="$(grep -E "^[[:space:]]*$key[[:space:]]*=" "$file" 2>/dev/null | head -1)" || true
    [ -n "$line" ] || return 0
    val="${line#*=}"
    printf '%s' "$val" \
        | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' -e 's/^"\(.*\)"$/\1/' -e "s/^'\(.*\)'\$/\1/"
}

# เขียนค่าลง .env — มีคีย์อยู่แล้วแทนที่บรรทัดนั้น ไม่มีก็ต่อท้าย
env_set() {  # env_set KEY VALUE FILE
    local key="$1" val="$2" file="$3" tmp
    [ -f "$file" ] || return 0
    if grep -qE "^[[:space:]]*$key[[:space:]]*=" "$file"; then
        tmp="$(mktemp)"
        KEY="$key" VAL="$val" awk '
            BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VAL"] }
            !done && $0 ~ "^[[:space:]]*" k "[[:space:]]*=" { print k "=" v; done = 1; next }
            { print }
        ' "$file" > "$tmp"
        cat "$tmp" > "$file"
        rm -f "$tmp"
    else
        printf '%s=%s\n' "$key" "$val" >> "$file"
    fi
}
