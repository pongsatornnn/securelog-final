# SecureLog — Central Server (ชุดติดตั้ง)

ชุดไฟล์สำหรับติดตั้ง **ฝั่ง Central** ของระบบตรวจจับและตอบสนองภัยคุกคามอัตโนมัติ SecureLog
บนเครื่อง server ใหม่ — มีเฉพาะโค้ดกับสคริปต์ที่ใช้ติดตั้งจริง ไม่มีเอกสาร/รูป/ไฟล์วิจัย

## ต้องมีอะไรก่อน

- Ubuntu / Debian (สคริปต์ใช้ `apt-get`)
- สิทธิ์ root (`sudo`)
- **IP ที่เครื่อง agent ใช้เรียกเข้ามาถึง central** — ต้องรู้ก่อนติดตั้ง สคริปต์เดาแทนไม่ได้
  เพราะค่านี้ไปอยู่ใน SAN ของ cert, `REDIS_HOST` และชุดติดตั้ง agent ถ้าใส่ผิดต้องออก cert ใหม่ทั้งชุด

## ติดตั้ง

```bash
sudo apt update && sudo apt install -y git
sudo git clone https://github.com/pongsatornnn/securelog-final.git /srv/securelog
cd /srv/securelog
sudo ./setup-server.sh
```

ระบบติดตั้ง **ตรงที่วางโปรเจกต์ไว้** — clone ลงที่ไหนก็ติดตั้งที่นั่น ไม่ผูกกับ `/srv`

> ถ้าวางไว้ใน `/home/<คนอื่น>/` ต้องส่ง `APP_USER=<เจ้าของ home นั้น>` ด้วย ไม่งั้น service
> เข้าไปอ่านไฟล์ไม่ได้ (home ปกติเป็น 750) — หรือวางนอก home ไปเลยเช่น `/srv`, `/usr/local`

สคริปต์จะถามทีละข้อ: user ที่ service ใช้รัน · IP 3 ช่อง · ชื่อ/รหัส PostgreSQL · รหัส Redis 2 ชุด
กด Enter เพื่อรับค่า default ได้ · **รันซ้ำได้ (idempotent)** ไม่ทับ `.env`/cert/รหัสที่ตั้งไว้แล้ว

รันแบบไม่ถาม (preset ผ่าน env):

```bash
sudo APP_USER=deploy BIND_HOST=10.0.0.5 DB_PASSWORD=xxx REDIS_PASS=yyy ./setup-server.sh
```

ติดตั้งไปที่ path อื่นโดยไม่ต้อง clone ใหม่: `sudo INSTALL_DIR=/srv/securelog ./setup-server.sh`

## สคริปต์ทำอะไรให้บ้าง

- ลง apt: `python3-venv`, `python3-pip`, `postgresql`, `redis-server` (ปิด redis default :6379 ให้ด้วย)
- สร้าง `venv/` + ติดตั้งตาม `requirements.txt`
- สร้าง `.env` — สุ่ม `JWT_SECRET_KEY` / `CSRF_SECRET` ให้เอง, mode 600
- สร้าง PostgreSQL role + database (ตารางกับข้อมูลตั้งต้นถูกสร้างอัตโนมัติตอน service start ครั้งแรก)
- ออก cert ทั้งชุดใน `cert/` — Root CA → central mTLS → HTTPS ของ dashboard (SAN ตรงกับ IP ที่กรอก)
- เขียน `redis/users.acl` 3 บัญชีด้วยรหัสจริง (ไม่เหลือค่า default) + `redis/redis-mtls.conf`
- เขียน `for_Agent/package/site.conf` ให้ zip ของ agent ฝังค่าถูกต้องตั้งแต่ครั้งแรก
- `chown -R` ทั้งโฟลเดอร์เป็น user ที่เลือก
- generate + ติดตั้ง systemd unit 10 ตัว (`securelog-*` 9 + `centralredis`) แล้ว start

เสร็จแล้วเข้า `https://<BIND_HOST>:8000` — ล็อกอินครั้งแรก `admin` / `admin` **เปลี่ยนรหัสทันที**

รหัสที่สคริปต์สุ่มให้จะโชว์ครั้งเดียวตอนจบ ให้เก็บไว้ (อยู่ใน `.env` และ `redis/users.acl` ด้วย)

## ไฟล์ที่ไม่อยู่ใน git (สร้างตอนติดตั้ง)

| ไฟล์ | |
|---|---|
| `.env` | ค่าตั้งของเครื่อง |
| `.settings_key` | กุญแจถอดรหัส secret ในตาราง `app_settings` — สร้างเองครั้งแรกที่ใช้ |
| `cert/` | cert ทั้งชุด ออกตาม IP ของเครื่องนั้น |
| `venv/` | |
| `redis/users.acl`, `redis/redis-mtls.conf` | รหัส Redis จริง 3 บัญชี |
| `for_Agent/package/site.conf` | ค่าที่ฝังไปกับ zip ของ agent |
| `systemd/securelog-*.service`, `systemd/centralredis.service` | unit ที่ generate ตาม path/user/IP ของเครื่อง |

## ย้ายเครื่อง / กู้ระบบ

ถ้าเป็นการ **ย้ายระบบเดิม** ไม่ใช่ติดตั้งใหม่ ต้องเอา 3 อย่างนี้จากเครื่องเก่ามาวางก่อนรัน `setup-server.sh`:

1. `.env` — รหัส DB/Redis เดิม
2. `.settings_key` — **ขาดไม่ได้** ถ้าไม่มี ค่า secret ในตาราง `app_settings` (LINE token ฯลฯ) จะถอดรหัสไม่ออก
3. dump ของ PostgreSQL

## อัปเดตทีหลัง

```bash
sudo git config --global --add safe.directory /srv/securelog   # ครั้งแรกครั้งเดียว
cd /srv/securelog
sudo git pull
sudo ./systemd/install.sh                  # เฉพาะตอนที่ systemd unit หรือค่า bind มีการแก้
sudo systemctl restart securelog.target
```

ต้องตั้ง `safe.directory` เพราะ `setup-server.sh` chown โฟลเดอร์เป็น `$APP_USER` ไปแล้ว
แต่ `git pull` รันด้วย root — git จะฟ้อง `detected dubious ownership` ถ้าไม่ตั้ง

`git pull` ไม่ชนกับไฟล์ที่ generate ไว้ เพราะทั้งหมดอยู่ใน `.gitignore` แล้ว

## คำสั่งที่ใช้บ่อย

```bash
systemctl --plain list-units 'securelog-*'     # สถานะ service ทั้งหมด
sudo systemctl restart securelog.target        # restart ทั้งระบบ
journalctl -u securelog-web -f                 # log ของ dashboard
journalctl -u centralredis -f                  # log ของ Redis
```

## ⚠️ ห้ามทำ

ห้ามตั้ง `user default off` ใน `redis/users.acl` — log จาก agent ทุกตัวจะหยุดไหลทันที
