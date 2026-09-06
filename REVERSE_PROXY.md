# เสิร์ฟ dashboard ใต้ sub-path + วาง reverse proxy ไว้ข้างหน้า

ตัว SecureLog ทำแค่ฝั่งระบบ: เสิร์ฟตัวเองใต้ path ที่ตั้งไว้ และเชื่อ `X-Forwarded-For` จาก proxy
ที่ระบุเท่านั้น — **ตัวติดตั้งไม่ยุ่งกับ config ของ nginx/HAProxy เลย** ใครจะเอาอะไรมาครอบก็เขียนเอง

---

## 1. ฝั่งระบบ: ตั้ง root path

`sudo ./setup-server.sh` จะถาม
```
Root path of the dashboard - / for the whole site, or a sub-path like /securelog [/]:
```
| ตอบ | ผลลัพธ์ |
|---|---|
| `/` (ค่าเริ่มต้น) | เข้าที่ `https://<ip>:8000/` เหมือนเดิมทุกอย่าง |
| `/securelog` | ทั้งเว็บย้ายไปอยู่ใต้ `https://<ip>:8000/securelog/` (เข้าที่รากจะได้ 404) |

- พิมพ์แบบไหนก็ได้ — `xxx`, `/xxx/`, `//a//b//` ระบบตัดให้เหลือ `/xxx`, `/a/b`
- **cookie ผูกกับ path นั้นด้วย**: `access_token_securelog`, `csrf_token_securelog` ที่ `Path=/securelog`
  → ไม่ชนกับ service อื่นที่อยู่โฮสต์+พอร์ตเดียวกัน และไม่หลุดไปให้ service นั้นอ่าน
- **อยู่ที่ราก (`/`) ก็ยังไม่ชน**: ชื่อ cookie จะเป็น `access_token_securelog` (เอาชื่อระบบมาต่อท้ายแทน
  prefix) ต่างจากเวอร์ชันก่อนที่ใช้ `access_token` เฉย ๆ แล้วโดน service อื่นชื่อซ้ำทับได้
  · อยากได้ชื่อเดิมล้วน ๆ ตั้ง `COOKIE_SUFFIX=off` ใน `.env` (แล้วรับความเสี่ยงชนเอง)
- แก้ทีหลังได้: รัน `sudo ./setup-server.sh` อีกรอบแล้วตอบใหม่ (คนที่ล็อกอินค้างต้องล็อกอินใหม่
  เพราะชื่อ cookie เปลี่ยนตาม path)
- แบบไม่ถาม: `sudo ROOT_PATH=/securelog ./setup-server.sh`

## 2. ฝั่งระบบ: พร้อมรับ proxy อยู่แล้วตั้งแต่ติดตั้ง

ตัวติดตั้งเขียน `FORWARDED_ALLOW_IPS=127.0.0.1` ลง `.env` ให้เสมอ → unit ของ web ได้
`--proxy-headers --forwarded-allow-ips` มาตั้งแต่แรก **วันไหนเอา proxy มาครอบก็ใช้ได้ทันที**

- ไม่มี proxy ก็ไม่เสียอะไร: uvicorn เชื่อ `X-Forwarded-For` เฉพาะที่มาจาก IP ในรายการนี้
- **proxy อยู่คนละเครื่อง**: `sudo FORWARDED_ALLOW_IPS=<ip ของ proxy> ./setup-server.sh`
- ถ้าไม่ตั้งค่านี้ทั้งที่มี proxy: app จะเห็น IP ของ proxy เป็นทุกคน → **login lockout กับ rate limit
  จะนับรวมกันหมด คนเดียวใส่รหัสผิดจนโดนล็อก = ล็อกทุกคน**

## 3. ฝั่ง proxy: ชี้มาที่ไหน

ตอนจบสคริปต์จะบอก URL ที่ต้องชี้มา เช่น
```
proxy ready   : trusts X-Forwarded-For from 127.0.0.1
                put any proxy in front of https://<ip ของเครื่อง>:8000/securelog/ - keep the whole path
```
กติกาเดียวคือ **ส่ง path เดิมทั้งเส้น** (`/securelog/xxx` ต้องถึง app เป็น `/securelog/xxx`)

### ตัวอย่าง nginx (ทดสอบกับ nginx 1.24 บน Ubuntu 24.04)

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name securelog.example.ac.th;          # โดเมนจริง

    ssl_certificate     /etc/letsencrypt/live/securelog.example.ac.th/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/securelog.example.ac.th/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location = /securelog { return 301 /securelog/; }

    location /securelog/ {
        # ⚠️ ห้ามมี / ปิดท้าย — ต้องส่ง path เต็มเข้า app (ROOT_PATH ฝั่ง app คือ /securelog)
        proxy_pass https://127.0.0.1:8000;        # หรือ IP ที่ dashboard bind อยู่จริง
        proxy_ssl_verify off;                     # cert ของ backend เซ็นด้วย CA ของโปรเจกต์เอง

        proxy_http_version 1.1;                   # 4 บรรทัดนี้คือชีวิตของ SSE (alert เด้ง real-time)
        proxy_set_header Connection "";
        proxy_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;

        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # service อื่นบนพอร์ตเดียวกันก็เพิ่ม location ได้เลย
    # location /app2/ { proxy_pass http://127.0.0.1:9000/; }
}
```

### proxy ตัวอื่น
- **HAProxy / Apache / Traefik**: หลักการเดียวกัน — ส่ง path เต็ม, ปิด buffering สำหรับ
  `/<root path>/api/stream/alerts` (SSE), ส่ง `X-Forwarded-For` และอย่าลืมตั้ง timeout ยาวสำหรับสาย SSE
- **`X-Accel-Buffering: no`** ที่ app ส่งมาให้ มีแต่ nginx ที่เข้าใจ — proxy ตัวอื่นต้องปิด buffering ที่ config เอง

## 4. ท่าที่ปลอดภัยที่สุด (proxy อยู่เครื่องเดียวกัน)

ตอบ `127.0.0.1` ในคำถาม "which IP to listen on" ตอนติดตั้ง แล้ว:
- ทางเข้าเดียวคือ proxy · ตัวติดตั้งจะถอน rule ufw ของ 8000 ให้เอง
- ไม่มีใครยิงตรงข้าม proxy เข้ามาปลอม `X-Forwarded-For` ได้

ถ้าจำเป็นต้องเปิด `:8000` ให้ proxy เครื่องอื่น ควรจำกัดด้วย
```bash
sudo ufw delete allow 8000/tcp
sudo ufw allow from <ip ของ proxy> to any port 8000 proto tcp
```

## 5. กับดักที่เจอจริง (วัดมาแล้วทั้งหมด)

| อาการ | สาเหตุ |
|---|---|
| 404 ทั้งเว็บผ่าน proxy | `proxy_pass` มี `/` ปิดท้าย (proxy ตัด prefix ทิ้ง) หรือ `location` ไม่ตรงกับ `ROOT_PATH` |
| หน้าเปิดได้แต่ alert ไม่เด้ง | ลืม `proxy_http_version 1.1` / `Connection ""` / `proxy_buffering off` → SSE ค้าง |
| คนเดียวใส่รหัสผิด แล้วล็อกทุกคน | ไม่ได้ตั้ง `FORWARDED_ALLOW_IPS` → app เห็นทุก request เป็น IP ของ proxy |
| ปลอม IP ได้ | ตั้ง `FORWARDED_ALLOW_IPS` แล้วแต่ยังเปิด `:8000` ให้ทั้งเครือข่าย |
| 502 หลังย้าย IP | `proxy_pass` ยังชี้ IP เดิม (ตัวติดตั้งไม่แตะ config ของ proxy ให้ ต้องแก้เอง) |
| หลุด login เมื่ออยู่พอร์ตเดียวกับ service อื่น | ปกติกันให้แล้ว: ชื่อ cookie ของระบบไม่ซ้ำใครเสมอ (`access_token_securelog` ที่ราก · `access_token_xxx` เมื่ออยู่ใต้ `/xxx`) — จะเจอก็ต่อเมื่อตั้ง `COOKIE_SUFFIX=off` เอง |

## 6. ตรวจว่าเวิร์ค

```bash
curl -k -o /dev/null -w '%{http_code}\n' https://<host>/securelog/login          # 200
curl -k -o /dev/null -w '%{http_code}\n' https://<host>/securelog/static/csrf.js # 200
curl -kN --max-time 8 https://<host>/securelog/api/stream/alerts                 # ต้องเห็น : connected แล้ว heartbeat ทุก 5 วิ
journalctl -u securelog-web -n 5                                                 # IP ที่ขึ้นต้องเป็นของ client จริง ไม่ใช่ของ proxy
```

## 7. สิ่งที่ proxy ไม่เกี่ยว
- **agent ส่ง log เข้า Redis mTLS พอร์ต 6380 ตรง ๆ** ไม่ผ่าน proxy — พอร์ตนั้นยังต้องเปิดให้เครื่อง agent
- **LINE webhook** เป็นคนละ app ที่พอร์ต 8080 (path `/line/webhook`) ไม่ได้อยู่ใต้ `ROOT_PATH`
  ถ้าจะให้ LINE เรียกผ่าน proxy ต้องทำ location แยกให้มัน
