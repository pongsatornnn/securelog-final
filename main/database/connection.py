import os
import time
from dotenv import load_dotenv
from sqlalchemy import text
from sqlalchemy.engine import URL
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = os.getenv("DB_PORT", "5432")
DB_NAME = os.getenv("DB_NAME")

# ★ ต้องใช้ URL.create ไม่ใช่ f-string — ตัวแยก URL ตัดที่ "@" ตัวแรก รหัสที่มี @ อยู่ข้างใน
#   (ซึ่ง setup-server.sh อนุญาตให้ใช้) จะทำให้ host เพี้ยนเป็น "<ท้ายรหัส>@localhost"
#   แล้วล้มตอน getaddrinfo — URL.create รับค่าดิบแล้ว escape ให้เองตอน render
DATABASE_URL = URL.create(
    "postgresql+asyncpg",
    username=DB_USER,
    password=DB_PASSWORD,
    host=DB_HOST,
    port=int(DB_PORT) if str(DB_PORT).isdigit() else None,
    database=DB_NAME,
)

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

Base = declarative_base()


async def get_db():
    async with AsyncSessionLocal() as session:
        yield session


async def init_db():
    import database.models  

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# ---------------------------------------------------------------------------
# ★ ตารางทั้งหมดถูกสร้างโดย "เว็บ" ตอน start — worker ตัวอื่น (detector / sweeper) ขึ้นพร้อมกัน
#   จึงมาถึงก่อนตารางมีจริงได้ตอนติดตั้งใหม่เอี่ยม · ของเดิมจะล้มแล้วปล่อยผ่าน (ทำงานต่อแบบมือเปล่า
#   จนกว่าจะครบรอบ refresh) พร้อม log error น่าตกใจทั้งที่ไม่ใช่ของพัง — ใช้ตัวนี้รอก่อนเริ่มงานจริง
DB_WAIT_SECONDS = 3           # เว้นกี่วินาทีต่อรอบ
DB_WAIT_MAX_SECONDS = 180     # ยอมรอนานสุดเท่าไร (เกินนี้ก็ทำงานต่อ ไม่ตาย — พฤติกรรมเดิม)


async def wait_for_table(table: str, log_prefix: str) -> bool:
    # table ต้องเป็นค่าคงที่จากโค้ดเราเองเท่านั้น (ไม่ใช่ค่าที่รับมาจากผู้ใช้)
    # คืน True = อ่านตารางได้แล้ว · False = รอจนหมดเวลา ผู้เรียกตัดสินใจเองว่าจะไปต่อไหม
    deadline = time.monotonic() + DB_WAIT_MAX_SECONDS
    said_waiting = False
    while True:
        try:
            async with AsyncSessionLocal() as db:
                # มีตารางแล้วแต่ยังไม่มีข้อมูล = ผ่าน (0 แถวก็ถือว่าพร้อม)
                await db.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))
            if said_waiting:
                print(f"[{log_prefix}] ฐานข้อมูลพร้อมแล้ว")
            return True
        except Exception as e:
            if time.monotonic() >= deadline:
                print(f"[{log_prefix}] ฐานข้อมูลยังไม่พร้อมเกิน {DB_WAIT_MAX_SECONDS} วิ ({e}) — เริ่มทำงานต่อ")
                return False
            if not said_waiting:
                # พิมพ์ครั้งเดียวพอ ไม่ต้องถล่ม log ทุก 3 วินาที
                print(f"[{log_prefix}] ฐานข้อมูลยังไม่พร้อม (ตารางยังไม่ถูกสร้าง) — รอแล้วลองใหม่")
                said_waiting = True
            time.sleep(DB_WAIT_SECONDS)
