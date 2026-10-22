ตัวติดตั้งเขียน `FORWARDED_ALLOW_IPS=127.0.0.1` ลง `.env` ให้เสมอ → unit ของ web ได้
`--proxy-headers --forwarded-allow-ips` มาตั้งแต่แรก **วันไหนเอา proxy มาครอบก็ใช้ได้ทันที**

- ไม่มี proxy ก็ไม่เสียอะไร: uvicorn เชื่อ `X-Forwarded-For` เฉพาะที่มาจาก IP ในรายการนี้
- **proxy อยู่คนละเครื่อง**: `sudo FORWARDED_ALLOW_IPS=<ip ของ proxy> ./setup-server.sh`

`setup-server.sh` ถามพอร์ต Dashboard (`WEB_PORT`, ค่าเริ่มต้น 8000) และ LINE webhook
(`WEBHOOK_PORT`, ค่าเริ่มต้น 8080) ด้วย เมื่อเปลี่ยนพอร์ตต้องแก้ proxy หรือ tunnel
ที่ชี้เข้ามาให้ตรงกับพอร์ตใหม่

