import os
import sys
import asyncio

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MAIN_DIR = os.path.dirname(CURRENT_DIR)

if MAIN_DIR not in sys.path:
    sys.path.insert(0, MAIN_DIR)

from database.connection import engine, Base
import database.models


async def reset_tables():
    async with engine.begin() as conn:
        print("Dropping old tables...")
        await conn.run_sync(Base.metadata.drop_all)

        print("Creating new tables from models.py...")
        await conn.run_sync(Base.metadata.create_all)

    print("Reset tables success")


if __name__ == "__main__":
    asyncio.run(reset_tables())