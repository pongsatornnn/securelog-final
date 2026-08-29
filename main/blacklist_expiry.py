# Blacklist expiry sweeper (background worker)

import asyncio
from datetime import datetime

from database.connection import AsyncSessionLocal
from database.crud import get_expired_active_blacklist, deactivate_blacklist
from process_log_detect.security_response import publish_unblock_ip_command


SWEEP_INTERVAL_SECONDS = 30


async def sweep_once() -> int:
    now = datetime.now()

    async with AsyncSessionLocal() as db:
        expired = await get_expired_active_blacklist(db, now)

        for row in expired:
            await deactivate_blacklist(db, row)
            publish_unblock_ip_command(row.ip_address, event=f"expired:{row.event}")
            print(
                f"[AUTO-EXPIRY] {row.ip_address} หมดอายุ "
                f"(block ครั้งที่ {row.block_count}, เหตุ {row.event}) -> unblock + inactive"
            )

    return len(expired)


async def run() -> None:
    print("[AUTO-EXPIRY] started (blacklist expiry sweeper)")
    print(f"[AUTO-EXPIRY] interval: {SWEEP_INTERVAL_SECONDS}s")

    while True:
        try:
            n = await sweep_once()
            if n:
                print(f"[AUTO-EXPIRY] sweep: unblocked {n} expired IP")
        except Exception as e:
            print(f"[AUTO-EXPIRY] error: {e}")

        await asyncio.sleep(SWEEP_INTERVAL_SECONDS)


if __name__ == "__main__":
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        print("\n[AUTO-EXPIRY] stopped")
