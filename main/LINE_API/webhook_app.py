


from fastapi import FastAPI

from base_path import LINE_WEBHOOK_PATH
from routes import line


app = FastAPI(docs_url=None, redoc_url=None)


app.include_router(line.webhook_router)


print(f"[LINE-WEBHOOK] endpoint: POST {LINE_WEBHOOK_PATH}")


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}
