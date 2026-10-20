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
ของ repo นี้และตรวจ SHA-256 ก่อนใช้งาน ไม่ต้องลง Go หรือ compile บนเครื่องที่ clone มา
repo เป็น private: ให้เครื่องมี GitHub credential สำหรับ repo นี้ (`git credential fill`)
หรือส่ง `GH_TOKEN`/`GITHUB_TOKEN` ตอนรันสคริปต์ หากดาวน์โหลดไม่ได้ สคริปต์จะหยุด
พร้อมบอกวิธีแก้ ไม่ดาวน์โหลด Go เอง หากต้องการ build จาก source เอง ให้ใช้
`sudo FILEBEAT_BUILD_FROM_SOURCE=1 ./setup-server.sh` ซึ่งจะดาวน์โหลด Go 1.26.8
และ Elastic Beats v8.19.23 เพื่อ compile
รอบต่อไปใช้ binary เดิมใน `for_Agent/build/`
