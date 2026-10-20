# SecureLog — Central Server (ชุดติดตั้ง)

ชุดไฟล์สำหรับติดตั้ง **ฝั่ง Central** ของระบบตรวจจับและตอบสนองภัยคุกคามอัตโนมัติ

## ต้องมีอะไรก่อน

- Ubuntu / Debian (สคริปต์ใช้ `apt-get`)
- สิทธิ์ root (`sudo`)
- **IP ที่เครื่อง agent ใช้เรียกเข้ามาถึง central** 

## ติดตั้ง

```bash
sudo apt update && sudo apt install -y git
sudo git clone https://github.com/pongsatornnn/securelog-final.git /srv/securelog
cd /srv/securelog
sudo ./setup-server.sh
```

ระบบติดตั้ง **ตรงที่วางโปรเจกต์ไว้** — clone ลงที่ไหนก็ติดตั้งที่นั่น ไม่ผูกกับ `/srv`

ครั้งแรก `setup-server.sh` จะดาวน์โหลด Filebeat ที่รองรับ Redis ACL จาก GitHub Release
ของ repo นี้และตรวจ SHA-256 ก่อนใช้งาน repo เป็น private: ให้เครื่องมี GitHub credential
สำหรับ repo นี้ (`git credential fill`) หรือส่ง `GH_TOKEN`/`GITHUB_TOKEN` ตอนรันสคริปต์
หากดาวน์โหลดไม่ได้ สคริปต์จะดาวน์โหลด Go และ Elastic Beats เพื่อ build จาก source อัตโนมัติ
หากต้องการ build จาก source ตั้งแต่ต้น ให้ใช้
`sudo FILEBEAT_BUILD_FROM_SOURCE=1 ./setup-server.sh` ซึ่งจะดาวน์โหลด Go 1.26.8
และ Elastic Beats v8.19.23 เพื่อ compile
รอบต่อไปใช้ binary เดิมใน `for_Agent/build/`

## อัปเกรดเครื่องที่ติดตั้งรุ่นเก่าแล้ว

อัปเดตโค้ดก่อน แล้วรัน `sudo ./setup-server.sh` เลือก **1) Keep these settings**
เพื่อคง `.env`/ฐานข้อมูลเดิมและติดตั้งส่วนที่ขาด ตัวติดตั้งสำรอง `redis/users.acl`
ก่อนแปลง ACL รุ่นเก่า: เก็บบัญชี Central กับบัญชี `agent_<number>` ที่มีอยู่,
ปิดบัญชี `default` และเลิกใช้ `agent_node` อย่าลบ ACL เดิมเองหรือคัดลอก ACL
เก่าทับหลังติดตั้ง หากมีคำเตือนว่ารหัส Central ใน `.env` ไม่ตรงกับ ACL
ให้แก้ผ่านหน้า System Settings หรือทบทวนไฟล์สำรองก่อนใช้ `FORCE_ACL=1`.

Agent ที่ยังใช้บัญชีร่วมรุ่นเก่าต้องกด **Regenerate package** ในหน้า Agents,
ดาวน์โหลด ZIP ใหม่ แล้วรัน `sudo ./setup.sh` จาก ZIP บนเครื่อง Agent แต่ละเครื่อง
การรันตัวติดตั้ง Server อย่างเดียวไม่สามารถเปลี่ยนรหัสใน Agent ที่ลงไปแล้วได้
รายละเอียดสิทธิ์ Redis อยู่ใน [redis/README.md](redis/README.md).
