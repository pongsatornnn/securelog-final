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


DB_WAIT_SECONDS = 3           # เว้นกี่วินาทีต่อรอบ
DB_WAIT_MAX_SECONDS = 180     # ยอมรอนานสุดเท่าไร (เกินนี้ก็ทำงานต่อ ไม่ตาย — พฤติกรรมเดิม)


async def wait_for_table(table: str, log_prefix: str) -> bool:


    deadline = time.monotonic() + DB_WAIT_MAX_SECONDS
    said_waiting = False
    while True:
        try:
            async with AsyncSessionLocal() as db:

                await db.execute(text(f"SELECT 1 FROM {table} LIMIT 1"))
            if said_waiting:
                print(f"[{log_prefix}] ฐานข้อมูลพร้อมแล้ว")
            return True
        except Exception as e:
            if time.monotonic() >= deadline:
                print(f"[{log_prefix}] ฐานข้อมูลยังไม่พร้อมเกิน {DB_WAIT_MAX_SECONDS} วิ ({e}) — เริ่มทำงานต่อ")
                return False
            if not said_waiting:

                print(f"[{log_prefix}] ฐานข้อมูลยังไม่พร้อม (ตารางยังไม่ถูกสร้าง) — รอแล้วลองใหม่")
                said_waiting = True
            time.sleep(DB_WAIT_SECONDS)
