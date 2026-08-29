"""CLI ดู/แก้ TTL ของ blacklist (ระยะเวลา block ก่อนหมดอายุ ต่อ detection_type)"""

import sys
import asyncio
import argparse

from database.connection import AsyncSessionLocal
from database.crud import get_all_blacklist_ttl
from blacklist_policy import BASE_TTL_SECONDS
from blacklist_ttl_cache import get_ttl, update_ttl


def fmt_ttl(ttl_seconds: int | None) -> str:
    if ttl_seconds is None:
        return "ถาวร (ไม่หมดอายุ)"
    h = ttl_seconds / 3600
    if ttl_seconds % 3600 == 0:
        return f"{ttl_seconds}s ({int(h)} ชม.)"
    return f"{ttl_seconds}s ({round(ttl_seconds/60, 1)} นาที)"


async def cmd_show() -> None:
    # seed default ของทุกชนิดที่รู้จักก่อน เพื่อให้เห็นครบ
    for dt in BASE_TTL_SECONDS:
        await get_ttl(dt)

    async with AsyncSessionLocal() as db:
        rows = await get_all_blacklist_ttl(db)

    print("\nBlacklist TTL (ระยะเวลา block ต่อ detection_type):")
    print("-" * 60)
    for row in rows:
        print(f"  {row.detection_type:22} -> {fmt_ttl(row.ttl_seconds)}")
    print("-" * 60)
    print("แก้: python manage_blacklist_ttl.py set <type> --hours N | --minutes N | --permanent\n")


async def cmd_set(detection_type: str, ttl_seconds: int | None) -> None:
    await update_ttl(detection_type, ttl_seconds)
    print(f"อัปเดตแล้ว: {detection_type} -> {fmt_ttl(ttl_seconds)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="จัดการ TTL ของ blacklist")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("show", help="แสดง TTL ทั้งหมด")

    p_set = sub.add_parser("set", help="ตั้ง TTL ของ detection_type")
    p_set.add_argument("detection_type")
    g = p_set.add_mutually_exclusive_group(required=True)
    g.add_argument("--seconds", type=int)
    g.add_argument("--minutes", type=int)
    g.add_argument("--hours", type=int)
    g.add_argument("--permanent", action="store_true", help="ไม่หมดอายุ")

    args = parser.parse_args()

    if args.command == "show":
        asyncio.run(cmd_show())
        return

    if args.command == "set":
        if args.permanent:
            ttl = None
        elif args.seconds is not None:
            ttl = args.seconds
        elif args.minutes is not None:
            ttl = args.minutes * 60
        else:
            ttl = args.hours * 3600

        if ttl is not None and ttl <= 0:
            print("ค่า TTL ต้องมากกว่า 0 (หรือใช้ --permanent)")
            sys.exit(1)

        asyncio.run(cmd_set(args.detection_type, ttl))


if __name__ == "__main__":
    main()
