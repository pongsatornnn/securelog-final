# App เล็กที่มี "เฉพาะ" endpoint ของ LINE webhook — เอาไว้เปิด public ผ่าน tunnel
# path ตั้งได้ที่ LINE_WEBHOOK_PATH ใน .env (ค่าเดิม /line/webhook)

from fastapi import FastAPI

from base_path import LINE_WEBHOOK_PATH
from routes import line


app = FastAPI(docs_url=None, redoc_url=None)

# มีแค่ webhook อันเดียว — ไม่มี dashboard, ไม่มี admin API, ไม่มี static
app.include_router(line.webhook_router)

# print ตอน start เพื่อให้รู้ว่าต้องเอา URL อะไรไปใส่ใน LINE Developers Console
# (ค่านี้อ่านจาก .env ตอน import — ดูจาก log ง่ายกว่าไปไล่เปิดไฟล์)
print(f"[LINE-WEBHOOK] endpoint: POST {LINE_WEBHOOK_PATH}")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
