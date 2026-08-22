"""
App เล็กที่มี "เฉพาะ" endpoint /line/webhook — เอาไว้เปิด public ผ่าน tunnel
(cloudflared/ngrok) เพื่อให้ LINE เรียกเข้ามาได้ โดย **ไม่ต้องเปิดระบบหลัก
(dashboard/API) ออก public** ระบบหลักยังรันแยกอีก process/port อยู่หลังบ้าน

รัน (คนละ port กับ app หลัก เช่น 8080):
    cd main && ../venv/bin/uvicorn LINE_API.webhook_app:app --host 0.0.0.0 --port 8080

แล้วให้ tunnel ชี้มาที่ port 8080 นี้เท่านั้น:
    cloudflared tunnel --url http://localhost:8080
    -> Webhook URL ใน LINE Console = https://<tunnel>/line/webhook

app นี้แชร์ DB เดียวกับระบบหลัก (เขียนตาราง line_recipients ให้ pending)
ตารางถูกสร้างโดย app หลักตอน startup อยู่แล้ว จึงไม่ต้อง create ซ้ำที่นี่
"""

from fastapi import FastAPI

from routes import line


app = FastAPI(docs_url=None, redoc_url=None)

# มีแค่ webhook อันเดียว — ไม่มี dashboard, ไม่มี admin API, ไม่มี static
app.include_router(line.webhook_router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
