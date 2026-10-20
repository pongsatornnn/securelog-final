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

ครั้งแรก `setup-server.sh` จะดาวน์โหลด Elastic Beats v8.19.23 และ Go 1.26.8
เพื่อสร้าง Filebeat ที่รองรับ Redis ACL ให้เอง ต้องมีอินเทอร์เน็ตและพื้นที่ว่าง
สำหรับ compile; รอบต่อไปใช้ binary ที่สร้างไว้แล้วใน `for_Agent/build/`
