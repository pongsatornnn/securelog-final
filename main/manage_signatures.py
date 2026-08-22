import argparse
import asyncio

from signature_cache import (
    DEFAULT_SIGNATURES,
    list_signatures,
    add_signature,
    set_signature_active,
    remove_signature,
)


def parse_args():
    parser = argparse.ArgumentParser(
        description="ดู/เพิ่ม/ปิด/ลบ signature (regex) ของ Signature-based detector"
    )
    subparsers = parser.add_subparsers(dest="action", required=True)

    show_parser = subparsers.add_parser("show", help="แสดง signature ทั้งหมด")
    show_parser.add_argument(
        "--type",
        dest="detection_type",
        choices=list(DEFAULT_SIGNATURES.keys()),
        help="กรองเฉพาะ detection_type นี้",
    )

    add_parser = subparsers.add_parser("add", help="เพิ่ม signature ใหม่ (validate regex ก่อน)")
    add_parser.add_argument("detection_type", choices=list(DEFAULT_SIGNATURES.keys()))
    add_parser.add_argument("pattern", help="regex pattern (ใส่ใน quote)")
    add_parser.add_argument("--description", default=None, help="คำอธิบาย")

    enable_parser = subparsers.add_parser("enable", help="เปิดใช้งาน signature ตาม id")
    enable_parser.add_argument("id", type=int)

    disable_parser = subparsers.add_parser("disable", help="ปิดใช้งาน signature ตาม id")
    disable_parser.add_argument("id", type=int)

    delete_parser = subparsers.add_parser("delete", help="ลบ signature ตาม id")
    delete_parser.add_argument("id", type=int)

    return parser.parse_args()


async def show_all(detection_type=None):
    rows = await list_signatures(detection_type)

    if not rows:
        print("(ยังไม่มี signature — จะถูก seed อัตโนมัติเมื่อ detector รันครั้งแรก)")
        return

    current_type = None
    for row in rows:
        if row["detection_type"] != current_type:
            current_type = row["detection_type"]
            print(f"\n[{current_type}]")

        state = "on " if row["is_active"] else "OFF"
        print(f"  #{row['id']:<4} [{state}] {row['pattern']}")


async def main():
    args = parse_args()

    if args.action == "show":
        await show_all(args.detection_type)
        return

    if args.action == "add":
        result = await add_signature(
            args.detection_type,
            args.pattern,
            description=args.description,
        )
        if result.get("duplicated"):
            print(f"มี pattern นี้อยู่แล้ว (id={result['id']}) ไม่เพิ่มซ้ำ")
        else:
            print(f"เพิ่มสำเร็จ: id={result['id']} type={result['detection_type']} pattern={result['pattern']!r}")
        return

    if args.action in ("enable", "disable"):
        result = await set_signature_active(args.id, is_active=(args.action == "enable"))
        if not result:
            print(f"ไม่พบ signature id={args.id}")
        else:
            print(f"อัปเดตสำเร็จ: id={result['id']} is_active={result['is_active']}")
        return

    if args.action == "delete":
        result = await remove_signature(args.id)
        if not result:
            print(f"ไม่พบ signature id={args.id}")
        else:
            print(f"ลบสำเร็จ: id={result['id']} type={result['detection_type']} pattern={result['pattern']!r}")
        return


if __name__ == "__main__":
    asyncio.run(main())
