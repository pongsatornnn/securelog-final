# SecureLog Agent — ชุดติดตั้ง

ไฟล์ในโฟลเดอร์นี้คือทุกอย่างที่ต้องเอาไปวางบนเครื่อง agent (ยกเว้น cert/token ซึ่งมากับ zip เฉพาะเครื่อง)

| ไฟล์ | หน้าที่ |
|---|---|
| `agent_core.py` | ตัว agent: รับคำสั่ง block/unblock/sync จาก central + ส่ง metrics — path ทุกอย่าง relative อ่านค่าจาก `agent_info.txt` + `agent_config.json` ไม่ต้องแก้โค้ด |
| `setup.sh` | สคริปต์ติดตั้ง/อัปเดต (idempotent รันซ้ำได้) — อ่านค่า site (IP central, รหัส Redis) จาก `site.conf` |
| `site.conf.example` | แม่แบบค่า site — ขึ้น git ได้ (ไม่มีความลับจริง) |
| `site.conf` | ค่า site จริง (มีรหัสผ่าน Redis) — **ไม่ขึ้น git** (`.gitignore`), copy จาก `site.conf.example` แล้วใส่ค่าจริง |
| `filebeat.yml.template` | แม่แบบ config filebeat — setup.sh แทนค่าแล้วติดตั้งให้เอง |
| `securelog-agent.service` | แม่แบบ systemd unit — setup.sh ติดตั้งให้เอง |
| `requirements.txt` | dependency ของ agent (redis, psutil) ลงใน venv ของตัวเอง ไม่แตะ system python |

## ตั้งค่าครั้งแรก (ทำที่เครื่อง central ครั้งเดียว ก่อนสร้าง agent package แรก)

```bash
cd for_Agent/package
cp site.conf.example site.conf
# แก้ CENTRAL_HOST / รหัส Redis ใน site.conf ให้ตรง site จริง
```

จากนั้น zip ที่โหลดจากหน้า Agents บน dashboard จะมี `site.conf` ติดไปด้วยอัตโนมัติทุกครั้ง (`create_agent_zip()`
รวมทุกไฟล์ในโฟลเดอร์นี้เข้า zip) ไม่ต้องมาแก้ค่า site ต่อเครื่อง agent อีก

## วิธีติดตั้งบนเครื่อง agent

zip ที่โหลดจากหน้า Agents บน dashboard (ลิงก์ใช้ได้ครั้งเดียว อายุ 2 นาที) รวมไฟล์ทุกอย่างในโฟลเดอร์นี้ไว้แล้ว
(setup.sh, agent_core.py, filebeat.yml.template ฯลฯ + agent_info.txt/cert เฉพาะเครื่อง) — แตก zip อย่างเดียวจบ ไม่ต้อง copy package แยก:

```bash
# 1. วางโฟลเดอร์ปลายทาง + แตก zip ของ agent ลงตรงนั้นเลย
sudo mkdir -p /opt/securelog-agent
sudo unzip Agent_XXX.zip -d /opt/securelog-agent

# 2. (เครื่องที่ยังไม่มี filebeat) ถ้ามีเน็ตออก setup.sh ลงให้เองผ่าน Elastic APT repo — ข้ามขั้นนี้ได้
#    ถ้าเครื่องไม่มีเน็ต (air-gapped) ให้วาง filebeat-<version>-amd64.deb ไว้ในโฟลเดอร์แทน (โหลดจาก elastic.co มาเอง)

# 3. รัน setup.sh (site.conf ติดมากับ zip แล้ว ไม่ต้องแก้อะไรเพิ่ม ปกติ)
cd /opt/securelog-agent
sudo ./setup.sh
```

ระหว่างติดตั้ง สคริปต์จะ **แสดง interface ทุกใบที่มี IPv4 พร้อม IP ของแต่ละใบ แล้วให้เลือก**
ว่าจะใช้ใบไหนเป็น IP ของ agent นี้ (มีใบเดียวจะเลือกให้เอง / กด Enter เฉย ๆ = ใบที่ route
ออกไปหา central ซึ่งเป็นตัวเลือกที่ถูกในเกือบทุกกรณี):

```
[SETUP] interface ที่มี IPv4 บนเครื่องนี้:
    1) enp0s3       10.0.2.15
    2) enp0s8       192.168.56.101

เลือก interface ที่จะใช้เป็น IP ของ agent นี้ [1-2] (Enter = 2 ซึ่งเป็นขาที่ออกไปหา central):
```

**IP นี้ถูกผูกกับ Agent ID ที่ฝั่ง central แบบถาวร** — ข้อมูลที่ส่งเข้าระบบต้องมาจาก IP นี้เท่านั้น
ไม่งั้นถูกปฏิเสธทั้งหมด (ทั้ง metrics และ log)

- การผูกเกิดขึ้นที่ central **ตอนเชื่อมต่อสำเร็จครั้งแรก** ไม่ใช่ตอนรัน setup.sh
- สิ่งที่เก็บไว้บนเครื่องคือ **ชื่อ interface ไม่ใช่ตัวเลข IP** — `agent_core.py` อ่าน IP จาก
  interface นั้นใหม่ทุก 30 วินาที การยกโฟลเดอร์นี้ไปรันที่เครื่องอื่นจึงรายงาน IP ของเครื่อง
  นั้นออกมาเองแล้วถูก central ปฏิเสธ (ถ้าเก็บเป็นตัวเลข ค่าจะถูกยกตามไปด้วย = ตรวจไม่เจอ)
- **ผูกแล้วเปลี่ยนไม่ได้** — เครื่องย้าย network หรือ DHCP เปลี่ยน IP เมื่อไหร่ ข้อมูลจะถูก
  ปฏิเสธทันที ทางแก้ทางเดียวคือกด **"สร้าง Download Link ใหม่"** ในหน้า Agents (ยกเลิก
  token ชุดเดิม + ปลด IP ที่ผูกไว้) แล้วติดตั้งด้วย package ชุดใหม่ที่เครื่องนั้น
- **เครื่องที่ IP ไม่นิ่ง ควรตั้ง static IP หรือจอง DHCP reservation ก่อนติดตั้ง**

เสร็จแล้วโครงจะเป็น:

```
/opt/securelog-agent/
├── agent_core.py
├── agent_info.txt        # id + secret token (600)
├── site.conf              # ค่า site (มากับ zip แล้ว)
├── agent_config.json     # ค่า site ที่ setup.sh เขียนให้ (600)
├── cert/                 # <Agent_ID>.crt/.key + ca.crt (key 600)
├── state/                # central_blacklist.json / central_whitelist.json
├── venv/                 # python แยกของ agent (สร้างสดบนเครื่องนี้ ห้าม copy ข้ามเครื่อง)
└── setup.sh ฯลฯ
```

## อัปเดตโค้ด/ config ภายหลัง

copy ไฟล์ใหม่ทับ (เช่น `agent_core.py`) แล้วรัน `sudo ./setup.sh` ซ้ำ — script จะ restart service ให้เอง
(registry ของ filebeat จะไม่ถูกลบในรอบอัปเดต ตำแหน่งอ่าน log ไม่หาย)

## เช็คว่าทำงาน

```bash
systemctl status securelog-agent filebeat
journalctl -u securelog-agent -f        # log ของ agent (แทน print ในเทอร์มินัล)
```

แล้วดูหน้า Agents บน dashboard — เครื่องนี้ต้องขึ้น online ภายใน ~15 วินาที

## ถ้า central ย้าย IP

ไม่ต้องลง agent ใหม่ ถ้าฝั่ง central รัน `setup-server.sh` ตอนย้าย (มันประกาศที่อยู่ใหม่ให้เอง)
agent จะเก็บที่อยู่ใหม่ไว้เป็นตัวสำรอง แล้วย้ายไปเองพร้อมชี้ Filebeat ตามให้ ภายในไม่เกินราวครึ่งนาที
หลังที่อยู่เดิมล่ม

- ที่อยู่ที่ agent รู้จักอยู่ดูได้จาก `central_host` + `central_candidates` ใน `agent_config.json`
  หรือบรรทัด `[CONFIG]` ตอน service เริ่มทำงาน
- เติมที่อยู่สำรองเองได้ที่ `CENTRAL_CANDIDATES` ใน `site.conf` แล้ว `sudo ./setup.sh` ซ้ำ
  (ลงซ้ำไม่ลบที่อยู่ที่เคยรู้ — รวมให้ทั้งหมด)
- agent จะยอมย้ายเฉพาะที่อยู่ที่คุย mTLS ผ่านด้วย CA ใบเดิมเท่านั้น สั่งลอย ๆ ให้ไปเกาะเครื่องอื่นไม่ได้

รายละเอียดทั้งหมดอยู่ใน `CENTRAL_MOVE.md` ฝั่ง central
