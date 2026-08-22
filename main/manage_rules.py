import argparse
import asyncio

from rule_cache import get_rule, update_rule, DEFAULT_RULES


def parse_args():
    parser = argparse.ArgumentParser(description="ดู/แก้ detection rule (threshold, window)")
    subparsers = parser.add_subparsers(dest="action", required=True)

    show_parser = subparsers.add_parser("show", help="แสดง rule ปัจจุบันทั้งหมด")

    set_parser = subparsers.add_parser("set", help="แก้ rule แล้วเคลียร์ cache ทันที")
    set_parser.add_argument("rule_key", choices=list(DEFAULT_RULES.keys()))
    set_parser.add_argument("--window", type=int, required=True, help="window_seconds ใหม่")
    set_parser.add_argument("--threshold", type=int, required=True, help="threshold ใหม่")
    set_parser.add_argument("--disable", action="store_true", help="ปิดใช้งาน rule นี้ชั่วคราว")

    return parser.parse_args()


async def show_all():
    for rule_key in DEFAULT_RULES:
        rule = await get_rule(rule_key)
        print(f"{rule_key}: window={rule['window_seconds']}s threshold={rule['threshold']} is_active={rule['is_active']}")


async def main():
    args = parse_args()

    if args.action == "show":
        await show_all()
        return

    if args.action == "set":
        updated = await update_rule(
            args.rule_key,
            window_seconds=args.window,
            threshold=args.threshold,
            is_active=not args.disable,
        )
        print(f"อัปเดตสำเร็จ: {updated}")
        return


if __name__ == "__main__":
    asyncio.run(main())
