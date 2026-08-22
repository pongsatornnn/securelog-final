"""
Gemini REST client — ใช้ urllib (stdlib) ไม่ต้องเพิ่ม dependency
(แนวเดียวกับ LINE_API/line_client.py)

เรียก generateContent แล้วคืน (ok, text_or_error) ไม่โยน exception ดิบให้ route
"""

import json
import urllib.error
import urllib.request

from AI_API import config


def _extract_text(data: dict) -> str:
    """ดึงข้อความจาก response ของ generateContent (candidates[0].content.parts[*].text)"""
    candidates = data.get("candidates") or []

    if not candidates:
        # ไม่มี candidate = prompt โดน safety filter บล็อก
        reason = (data.get("promptFeedback") or {}).get("blockReason")
        raise ValueError(f"Gemini ไม่ส่งคำตอบกลับมา (blockReason={reason})")

    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    text = "".join(part.get("text", "") for part in parts).strip()
    finish = candidates[0].get("finishReason")

    if not text:
        raise ValueError(f"Gemini ส่งคำตอบว่าง (finishReason={finish})")

    # MAX_TOKENS = คำตอบถูกตัดกลางคัน (ไม่จบประโยค/ไม่ครบหัวข้อ) — ต้องไม่เอาไปเก็บลง DB
    # เพราะแอดมินจะเห็นสรุปครึ่ง ๆ กลาง ๆ โดยไม่รู้ว่ามันไม่ครบ
    if finish == "MAX_TOKENS":
        raise ValueError(
            "คำตอบจาก AI ยาวเกินเพดานที่ตั้งไว้เลยถูกตัดกลางคัน "
            "(ปรับ GEMINI_MAX_OUTPUT_TOKENS ใน .env ให้สูงขึ้น)"
        )

    return text


def generate(prompt: str) -> tuple[bool, str]:
    """
    ส่ง prompt ไป Gemini — คืน (True, ข้อความสรุป) หรือ (False, ข้อความ error ที่อ่านรู้เรื่อง)

    เป็นฟังก์ชัน blocking (urllib) — ฝั่ง FastAPI ต้องเรียกผ่าน asyncio.to_thread
    ไม่งั้นจะบล็อก event loop ทั้ง process ระหว่างรอ AI ตอบ (นานได้หลายวินาที)
    """
    if not config.is_configured():
        return False, "ยังไม่ได้ตั้งค่า API Key ของ Gemini — ตั้งได้ที่หน้า System Settings"

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {
            # temperature ต่ำ: งานสรุป log ต้องการความคงเส้นคงวา ไม่ใช่ความสร้างสรรค์
            "temperature": 0.2,
            "maxOutputTokens": config.MAX_OUTPUT_TOKENS,
            # กันโมเดลคิดจนกิน maxOutputTokens หมดแล้วคำตอบโดนตัด (ดูคำอธิบายใน config.py)
            "thinkingConfig": {"thinkingBudget": config.THINKING_BUDGET},
        },
    }

    req = urllib.request.Request(
        config.generate_url(),
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-goog-api-key": config.api_key(),
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=config.TIMEOUT_SEC) as resp:
            data = json.loads(resp.read().decode("utf-8"))

        return True, _extract_text(data)

    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")

        try:
            message = json.loads(body)["error"]["message"]
        except Exception:
            message = body[:300]

        print(f"[AI] Gemini HTTP {e.code}: {message}")

        if e.code == 429:
            return False, "เรียก AI บ่อยเกินโควตา ลองใหม่อีกครั้งในภายหลัง"
        if e.code in (401, 403):
            return False, "GEMINI_API_KEY ไม่ถูกต้องหรือไม่มีสิทธิ์ใช้งาน"

        return False, f"เรียก AI ไม่สำเร็จ (HTTP {e.code})"

    except Exception as e:
        print(f"[AI] Gemini error: {e}")
        return False, f"เรียก AI ไม่สำเร็จ: {e}"
