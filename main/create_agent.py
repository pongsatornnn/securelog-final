"""
CLI สร้าง Agent + package (ทางเลือกแทนการกดผ่านหน้า Agents บน dashboard)

ไม่รับ IP เป็น argument แล้ว — IP ของ agent ถูกผูกตอนที่ agent ติดต่อเข้ามาสำเร็จครั้งแรก
จาก interface ที่เลือกตอนรัน setup.sh บนเครื่องจริง แล้วเปลี่ยนไม่ได้อีก
(ตอนสร้าง package ยังไม่มีทางรู้ว่าจะไปติดตั้งที่เครื่อง IP อะไร)
"""

import sys
import asyncio

from manage_agent.create_agent_package import create_agent_package


async def main():
    if len(sys.argv) < 2:
        print("Usage: python create_agent.py <Agent-ID> [Hostname]")
        print("Example: python create_agent.py Agent-01 web-server-01")
        return

    agent_id = sys.argv[1]
    hostname = sys.argv[2] if len(sys.argv) >= 3 else None

    result = await create_agent_package(
        agent_id=agent_id,
        hostname=hostname,
    )

    print("\nCreate Agent Success")
    print("====================")
    print(f"Agent ID      : {result['agent_id']}")
    print(f"Hostname      : {hostname or '-'}")
    print(f"Zip Path      : {result['zip_path']}")
    print(f"Download Token: {result['download_token']}")
    print(f"Download URL  : {result['download_url']}")
    print("\nToken นี้แสดงครั้งเดียว เก็บไว้ให้ดี")
    print("IP ของเครื่องจะถูกผูกอัตโนมัติตอนรัน setup.sh แล้วเชื่อมต่อสำเร็จครั้งแรก")


if __name__ == "__main__":
    asyncio.run(main())
