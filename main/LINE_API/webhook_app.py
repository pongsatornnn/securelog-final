# App เล็กที่มี "เฉพาะ" endpoint /line/webhook — เอาไว้เปิด public ผ่าน tunnel

from fastapi import FastAPI

from routes import line


app = FastAPI(docs_url=None, redoc_url=None)

# มีแค่ webhook อันเดียว — ไม่มี dashboard, ไม่มี admin API, ไม่มี static
app.include_router(line.webhook_router)


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
