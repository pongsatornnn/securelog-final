"""
FastAPI entrypoint — สร้าง app, mount static, ผูก rate-limit handler,
และรวม router ทั้งหมดจาก routes/*.py (logic จริงของแต่ละ endpoint อยู่ในนั้น)
"""

from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from slowapi.errors import RateLimitExceeded
from starlette.exceptions import HTTPException as StarletteHTTPException
from sqlalchemy import text

from database.connection import engine, Base
import database.models

from shared import limiter
from csrf import CSRFMiddleware
from errors import register_error_handlers, http_exception_handler

from routes import (
    auth_routes,
    pages,
    agents,
    blacklist,
    whitelist,
    alerts,
    rules,
    signatures,
    settings,
    line,
    users,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # migration เล็กๆ: create_all() สร้างเฉพาะตารางที่ยังไม่มี ไม่แก้ตารางที่มีอยู่แล้ว
        # ตาราง users มีมาก่อน must_change_password จะถูกเพิ่มเข้าโมเดล ต้องเติมคอลัมน์เอง
        # (IF NOT EXISTS กันพังตอนรันซ้ำ/เครื่องที่สร้างตารางใหม่อยู่แล้วมีคอลัมน์นี้ครบ)
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS "
            "must_change_password BOOLEAN NOT NULL DEFAULT false"
        ))
        # เพิ่มทีหลัง: ชื่อที่แสดง (display name) แก้ได้ในหน้า Profile Setting — ตารางเก่ายังไม่มีคอลัมน์นี้
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS name VARCHAR(100)"
        ))
        # เพิ่มทีหลัง: จุดที่ผู้ใช้คนนี้เห็นรายการ alert ถึงแล้ว (คุม badge ที่เมนู Alerts)
        # ย้ายมาจาก localStorage เพื่อให้ซิงค์ตามบัญชีทุกเครื่อง — ปล่อยเป็น NULL ไว้ ให้
        # request แรกของแต่ละบัญชีตั้งค่าเอง (ดู /api/alerts_unread_count) badge จะได้ไม่
        # เด้งเป็นจำนวน alert ทั้งตารางตอน deploy เวอร์ชันนี้ครั้งแรก
        await conn.execute(text(
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS last_seen_alert_id INTEGER"
        ))
        # ตาราง app_settings (ค่าตั้งจากหน้า System Settings) create_all สร้างให้เองตอนยังไม่มี
        # — ไม่ต้อง ALTER อะไรเพิ่ม เพราะเป็นตารางใหม่ทั้งใบ
        #
        # เพิ่มทีหลัง: รูปโปรไฟล์ LINE ของผู้รับแจ้งเตือน (โชว์ในหน้า LINE Recipients)
        # ปล่อยเป็น NULL ไว้ = "ยังไม่เคยดึง profile" — webhook จะเติมให้เองตอนคนนั้นมี
        # event เข้ามาครั้งถัดไป (ดู LineRecipient.picture_url) ไม่ต้อง backfill ตอน deploy
        await conn.execute(text(
            "ALTER TABLE line_recipients ADD COLUMN IF NOT EXISTS picture_url VARCHAR(512)"
        ))

        # เพิ่มทีหลัง: "ใครเป็นคนเพิ่ม IP นี้" — ชื่อผู้ใช้ที่กดเพิ่มเอง หรือ detector:<ชนิด> เมื่อระบบบล็อกเอง
        # ปล่อยเป็น NULL สำหรับแถวเก่า (ไม่มีข้อมูลย้อนหลังให้ backfill — หน้าเว็บแสดงเป็น "ไม่ทราบ")
        #
        # เก็บสองช่องคู่กันโดยตั้งใจ: ชื่อ (ค่าคงที่ของประวัติ) + user id (FK ไว้ join กับตาราง users)
        # FK เป็น ON DELETE SET NULL ไม่ใช่ CASCADE — ลบผู้ใช้แล้วต้องไม่ลบ "ของที่เขาเคยทำ" ทิ้งไปด้วย
        for table in ("ip_black_list", "ip_white_list"):
            await conn.execute(text(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS created_by VARCHAR(50)"
            ))
            await conn.execute(text(
                f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS created_by_user_id INTEGER"
            ))

        # ตาราง app_setting_changes (ประวัติการแก้ค่าตั้ง) create_all สร้างให้เองตอนยังไม่มี
        # — ยกเว้นตอนอัปเกรดจากเวอร์ชันที่มีตารางนี้แล้วแต่ยังไม่มีคอลัมน์ id ของผู้ใช้
        await conn.execute(text(
            "ALTER TABLE app_setting_changes ADD COLUMN IF NOT EXISTS changed_by_user_id INTEGER"
        ))

        # FK ของสามคอลัมน์ข้างบน — Postgres ไม่มี ADD CONSTRAINT IF NOT EXISTS จึงเช็ค pg_constraint เอง
        # (lifespan รันทุกครั้งที่ start ต้อง idempotent) · แถวเก่าเป็น NULL อยู่แล้วจึงไม่มีปัญหากำพร้า
        for table, column in (
            ("ip_black_list", "created_by_user_id"),
            ("ip_white_list", "created_by_user_id"),
            ("app_setting_changes", "changed_by_user_id"),
        ):
            await conn.execute(text(f"""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint
                        WHERE conname = 'fk_{table}_{column}'
                          AND conrelid = '{table}'::regclass
                    ) THEN
                        ALTER TABLE {table}
                            ADD CONSTRAINT fk_{table}_{column}
                            FOREIGN KEY ({column}) REFERENCES users (id)
                            ON DELETE SET NULL;
                    END IF;
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_indexes
                        WHERE tablename = '{table}' AND indexname = 'ix_{table}_{column}'
                    ) THEN
                        CREATE INDEX ix_{table}_{column} ON {table} ({column});
                    END IF;
                END $$;
            """))

        # เพิ่มทีหลัง: FK agent_downloads.agent_id -> agents.agent_id (ON DELETE CASCADE)
        # DB ที่สร้างก่อนหน้านี้ไม่มี constraint นี้ (create_all ไม่แก้ตารางที่มีอยู่แล้ว)
        # Postgres ไม่มี ADD CONSTRAINT IF NOT EXISTS จึงต้องเช็ค pg_constraint เองใน DO block
        # (lifespan รันทุกครั้งที่ start — ต้อง idempotent ไม่งั้น restart รอบสองพัง)
        #
        # ถ้ามีแถวกำพร้าค้างอยู่ (agent ถูกลบไปแล้วแต่แถว download ยังอยู่) จะไม่ยอมลบข้อมูล
        # ให้เอง แต่ใส่ constraint แบบ NOT VALID ไว้ก่อน — ของเก่าไม่ถูกตรวจ แต่ INSERT ใหม่
        # และ ON DELETE CASCADE มีผลทันที แล้วเตือนใน log ให้แอดมินมาเคลียร์เอง
        # (ถ้า ALTER ล้มกลางคัน transaction ของ lifespan จะ abort ทั้งก้อน = app start ไม่ขึ้น)
        await conn.execute(text("""
            DO $$
            DECLARE
                orphan_count integer;
            BEGIN
                IF EXISTS (
                    SELECT 1 FROM pg_constraint
                    WHERE conname = 'fk_agent_downloads_agent_id'
                      AND conrelid = 'agent_downloads'::regclass
                ) THEN
                    RETURN;
                END IF;

                SELECT count(*) INTO orphan_count
                FROM agent_downloads d
                LEFT JOIN agents a ON a.agent_id = d.agent_id
                WHERE a.agent_id IS NULL;

                IF orphan_count > 0 THEN
                    ALTER TABLE agent_downloads
                        ADD CONSTRAINT fk_agent_downloads_agent_id
                        FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                        ON DELETE CASCADE NOT VALID;
                    RAISE WARNING
                        'agent_downloads: พบแถวกำพร้า % แถว (agent ถูกลบไปแล้ว) '
                        'ใส่ FK แบบ NOT VALID ไว้ก่อน — เคลียร์ด้วย '
                        'DELETE FROM agent_downloads d WHERE NOT EXISTS '
                        '(SELECT 1 FROM agents a WHERE a.agent_id = d.agent_id); '
                        'แล้วสั่ง ALTER TABLE agent_downloads VALIDATE CONSTRAINT '
                        'fk_agent_downloads_agent_id;', orphan_count;
                ELSE
                    ALTER TABLE agent_downloads
                        ADD CONSTRAINT fk_agent_downloads_agent_id
                        FOREIGN KEY (agent_id) REFERENCES agents (agent_id)
                        ON DELETE CASCADE;
                END IF;
            END $$;
        """))

        # เพิ่มทีหลัง: index ที่โมเดลประกาศไว้แต่ DB เก่ายังไม่มี (create_all ไม่แก้ตารางเดิม)
        # 2 ตัวแรกเป็น UNIQUE บน ip_address — สำคัญกว่าเรื่องความเร็ว เพราะ get_blacklist_by_ip/
        # get_whitelist_by_ip ใช้ scalar_one_or_none() ถ้ามีแถวซ้ำจะโยน MultipleResultsFound
        # ทำให้เส้นทางตอบสนองของ detector พังทั้งเส้น — unique index ทำให้ "ซ้ำไม่ได้ตั้งแต่ต้น"
        # ชื่อ index ตั้งให้ตรงกับที่ create_all จะสร้างบนเครื่องใหม่ (ix_<table>_<column>)
        # ไม่งั้นเครื่องใหม่กับเครื่องเก่าจะมี index คนละชื่อทั้งที่ทำหน้าที่เดียวกัน
        #
        # ถ้ามีข้อมูลซ้ำค้างอยู่ จะไม่ลบให้เอง แต่ข้ามการสร้างแล้วเตือนใน log
        # (ถ้าปล่อยให้ CREATE ล้ม transaction ของ lifespan จะ abort ทั้งก้อน = app start ไม่ขึ้น)
        await conn.execute(text("""
            DO $$
            DECLARE
                tbl text;
                idx text;
                dup_count integer;
            BEGIN
                FOREACH tbl IN ARRAY ARRAY['ip_black_list', 'ip_white_list'] LOOP
                    idx := 'ix_' || tbl || '_ip_address';

                    IF EXISTS (
                        SELECT 1 FROM pg_class
                        WHERE relname = idx AND relnamespace = 'public'::regnamespace
                    ) THEN
                        CONTINUE;
                    END IF;

                    EXECUTE format(
                        'SELECT count(*) FROM (SELECT ip_address FROM %I '
                        'GROUP BY ip_address HAVING count(*) > 1) d', tbl
                    ) INTO dup_count;

                    IF dup_count > 0 THEN
                        RAISE WARNING
                            '%: พบ ip_address ซ้ำ % ค่า จึงยังสร้าง unique index ไม่ได้ '
                            '— เคลียร์ตัวซ้ำให้เหลือแถวเดียวต่อ IP (เก็บ id น้อยสุดไว้) แล้วสั่ง '
                            'CREATE UNIQUE INDEX %I ON %I (ip_address);',
                            tbl, dup_count, idx, tbl;
                    ELSE
                        EXECUTE format(
                            'CREATE UNIQUE INDEX %I ON %I (ip_address)', idx, tbl
                        );
                    END IF;
                END LOOP;
            END $$;
        """))

        # index ธรรมดา (ไม่มีเรื่องข้อมูลซ้ำ จึงใช้ IF NOT EXISTS ตรงๆ ได้)
        # คอลัมน์ 2 ตัวนี้ถูกเพิ่มเข้าตาราง security_alerts ทีหลัง index จึงไม่เคยถูกสร้าง
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_security_alerts_response_action "
            "ON security_alerts (response_action)"
        ))
        await conn.execute(text(
            "CREATE INDEX IF NOT EXISTS ix_security_alerts_updated_at "
            "ON security_alerts (updated_at)"
        ))

    # เติมค่าเริ่มต้นลง DB (detection rule / blacklist TTL / severity / signature / บัญชี admin)
    # เดิมค่าพวกนี้ถูก seed แบบ lazy ตอน detector เจอ log ตัวแรกของชนิดนั้น เครื่องที่เพิ่ง
    # deploy ใหม่จึงเห็นหน้า /rules /signatures ว่างจนกว่าจะมีการโจมตีจริงเข้ามา — ย้ายมาทำ
    # ตอน startup ทีเดียว และดึงค่าจาก snapshot (database/seed_data.json) ถ้ามี
    # "เติมเฉพาะที่ยังไม่มี" เสมอ ไม่เขียนทับค่าที่แอดมินปรับไว้เอง (ดู database/seed.py)
    from database.seed import seed_defaults
    await seed_defaults()

    # เติมค่าจากตาราง app_settings เข้า Redis cache ตั้งแต่ตอน start — โค้ด sync ที่อ่านค่า
    # (line_client / gemini_client) อ่านจาก cache อย่างเดียว ถ้าไม่อุ่นไว้ก่อน request แรก
    # จะได้ค่าจาก .env แทนค่าที่แอดมินตั้งไว้ (ดูหมายเหตุใน settings_cache.py)
    from settings_cache import (
        encrypt_existing_secrets,
        load_all_into_cache,
        seed_agent_settings_from_site_conf,
    )
    await seed_agent_settings_from_site_conf()
    # ค่า secret ในตารางถูกเข้ารหัสไว้ (secret_box) — แถวที่ตั้งไว้ก่อนมีการเข้ารหัสจะถูก
    # แปลงให้ตอน start ครั้งแรกหลังอัปเกรด รันซ้ำได้ ไม่แตะแถวที่เข้ารหัสแล้ว
    await encrypt_existing_secrets()
    await load_all_into_cache()

    yield


app = FastAPI(
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
)

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

if STATIC_DIR.exists():
    app.mount(
        "/static",
        StaticFiles(directory=str(STATIC_DIR)),
        name="static",
    )

app.state.limiter = limiter

# บังคับ CSRF ทุก endpoint ที่เปลี่ยนข้อมูล (double-submit cookie) — ดู csrf.py
app.add_middleware(CSRFMiddleware)


# หน้า error แบบ HTML สำหรับ browser / JSON เหมือนเดิมสำหรับ /api/* (ดู errors.py)
register_error_handlers(app)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    # ส่งต่อให้ handler กลางตัดสินใจว่าจะตอบเป็น HTML หรือ JSON ตามผู้เรียก
    return await http_exception_handler(
        request,
        StarletteHTTPException(status_code=429, detail="ลองใหม่อีกครั้งในภายหลัง"),
    )


app.include_router(auth_routes.router)
app.include_router(pages.router)
app.include_router(agents.router)
app.include_router(blacklist.router)
app.include_router(whitelist.router)
app.include_router(alerts.router)
app.include_router(rules.router)
app.include_router(signatures.router)
app.include_router(line.router)
app.include_router(line.webhook_router)
app.include_router(users.router)
app.include_router(settings.router)
