# LINE Messaging API client — ใช้ urllib (stdlib) ไม่ต้องเพิ่ม dependency

import base64
import hashlib
import hmac
import json
import urllib.error
import urllib.request

from LINE_API import config


def verify_signature(body: bytes, signature: str | None) -> bool:
    # ตรวจว่า request มาจาก LINE จริง — HMAC-SHA256(channel_secret, raw_body) base64
    if not signature or not config.channel_secret():
        return False

    digest = hmac.new(
        config.channel_secret().encode("utf-8"),
        body,
        hashlib.sha256,
    ).digest()
    expected = base64.b64encode(digest)

    # เทียบเป็น bytes ไม่ใช่ str — compare_digest โยน TypeError ถ้า str ฝั่งใดมีอักขระนอก ASCII
    return hmac.compare_digest(expected, signature.encode("utf-8", "surrogateescape"))


def _post(url: str, payload: dict, timeout: int = 10) -> tuple[int, str]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {config.channel_access_token()}",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except Exception as e:
        return 0, str(e)


def get_profile(user_id: str, timeout: int = 10) -> dict | None:
    # ดึง profile ({displayName, userId, ...}) — คืน None ถ้าไม่สำเร็จ
    if not config.channel_access_token():
        return None

    req = urllib.request.Request(
        f"{config.PROFILE_URL}/{user_id}",
        method="GET",
        headers={"Authorization": f"Bearer {config.channel_access_token()}"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[LINE] get_profile ไม่สำเร็จ ({user_id}): {e}")
        return None


def get_bot_info(timeout: int = 10) -> tuple[int, dict]:
    # ข้อมูลของ OA ตัวเอง — ใช้เช็คว่า channel access token ที่ตั้งไว้ใช้ได้จริงไหม
    req = urllib.request.Request(
        config.BOT_INFO_URL,
        method="GET",
        headers={"Authorization": f"Bearer {config.channel_access_token()}"},
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(body)
        except Exception:
            return e.code, {"message": body.strip()[:300]}
    except Exception as e:
        print(f"[LINE] get_bot_info ไม่สำเร็จ: {e}")
        return 0, {"message": str(e)}


def push_text(user_id: str, text: str) -> bool:
    # ส่งข้อความ text หา userId เดียว
    status, body = _post(
        config.PUSH_URL,
        {"to": user_id, "messages": [{"type": "text", "text": text}]},
    )
    ok = status == 200
    if not ok:
        print(f"[LINE] push ไม่สำเร็จ ({user_id}): {status} {body}")
    return ok


def multicast_text(user_ids: list[str], text: str) -> bool:
    # ส่งข้อความ text หาหลาย userId (สูงสุด 500/ครั้ง — แบ่ง batch ให้เอง)
    if not user_ids:
        return True

    message = {"type": "text", "text": text}
    all_ok = True

    for i in range(0, len(user_ids), config.MULTICAST_MAX):
        batch = user_ids[i : i + config.MULTICAST_MAX]
        status, body = _post(
            config.MULTICAST_URL,
            {"to": batch, "messages": [message]},
        )
        if status != 200:
            all_ok = False
            print(f"[LINE] multicast batch ไม่สำเร็จ: {status} {body}")

    return all_ok
