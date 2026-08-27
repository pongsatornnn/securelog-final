"""
Gemini REST client — ใช้ urllib (stdlib) ไม่ต้องเพิ่ม dependency
(แนวเดียวกับ LINE_API/line_client.py)

เรียก generateContent แล้วคืน (ok, text_or_error) ไม่โยน exception ดิบให้ route

**ข้อความ error ต้องมีต้นฉบับจาก Google ติดมาด้วยเสมอ** (GeminiError.full_message):
เดิมคืนแค่ "เรียก AI ไม่สำเร็จ (HTTP 404)" ซึ่งบอกไม่ได้ว่าต้องไปแก้อะไร ทั้งที่ Google
ส่งคำตอบมาชัดเจนอยู่แล้ว เช่น "This model models/gemini-2.5-flash is no longer available
to new users. Please update your code to use models/gemini-3.6-flash"
"""

import json
import re
import urllib.error
import urllib.request

from AI_API import config


# ชื่อโมเดลขึ้นต้นด้วย gemini-<เวอร์ชัน> — ใช้ตัดสินใจว่าจะส่ง thinkingConfig แบบไหน
_MODEL_VERSION_RE = re.compile(r"^gemini-(\d+(?:\.\d+)?)")


class GeminiError(Exception):
    """
    error ที่รู้ที่มา — เก็บทั้งข้อความไทยที่สรุปแล้ว และคำตอบดิบจาก Google ไว้ด้วยกัน
    (`api_message` คือ error.message ใน body ของ Google ตัวที่บอกสาเหตุจริง)
    """

    def __init__(self, summary: str, *, http_code=None, api_status=None, api_message=None):
        self.summary = summary
        self.http_code = http_code
        self.api_status = api_status
        self.api_message = api_message
        super().__init__(summary)

    @property
    def full_message(self) -> str:
        """ข้อความที่เอาไปโชว์ให้แอดมินได้เลย — สรุปไทยบรรทัดแรก ต้นฉบับจาก Google บรรทัดถัดไป"""
        if not self.api_message:
            return self.summary
        return f"{self.summary}\nGoogle ตอบกลับ: {self.api_message}"


def _http_error(e: urllib.error.HTTPError) -> GeminiError:
    """แปลง HTTPError เป็น GeminiError — อ่าน body ให้จบก่อนเสมอ ไม่งั้นข้อความจริงหายไป"""
    body = e.read().decode("utf-8", "replace")
    api_message = None
    api_status = None

    try:
        error = json.loads(body).get("error") or {}
        api_message = error.get("message")
        api_status = error.get("status")
    except Exception:
        # ไม่ใช่ JSON (เช่นหน้า HTML ของ proxy ที่คั่นอยู่) — เอา body ดิบไปแสดงเท่าที่พออ่านไหว
        api_message = body.strip()[:500] or None

    where = f"HTTP {e.code}" + (f" {api_status}" if api_status else "")

    summary = {
        400: f"คำขอไม่ถูกต้อง — โมเดล {config.model()} อาจไม่รับค่าที่ตั้งไว้ ({where})",
        401: f"API Key ไม่ถูกต้องหรือหมดอายุ ({where})",
        403: f"API Key นี้ไม่มีสิทธิ์ใช้โมเดล {config.model()} ({where})",
        404: f"คีย์นี้ใช้โมเดล {config.model()} ไม่ได้ — เลือกโมเดลอื่นจากรายชื่อ ({where})",
        429: f"เรียกบ่อยเกินโควตาของคีย์นี้ ({where})",
    }.get(e.code)

    if summary is None:
        summary = (
            f"ฝั่ง Google ขัดข้องชั่วคราว ({where})" if e.code >= 500
            else f"เรียก AI ไม่สำเร็จ ({where})"
        )

    return GeminiError(summary, http_code=e.code, api_status=api_status, api_message=api_message)


def _request(url: str, payload: dict | None = None) -> dict:
    """
    ยิงไป Gemini API แล้วคืน body ที่ parse แล้ว — ผิดพลาดโยน GeminiError ที่มีข้อความจาก Google
    payload = None -> GET (ใช้กับ ListModels) · มี payload -> POST
    """
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None

    headers = {"x-goog-api-key": config.api_key()}
    if data is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers=headers)

    # อ่านครั้งเดียวต่อคำขอ — ใช้ทั้งตอนยิงและตอนประกอบข้อความ error ให้เป็นตัวเลขเดียวกัน
    timeout = config.timeout_sec()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    except urllib.error.HTTPError as e:
        raise _http_error(e) from e

    except urllib.error.URLError as e:
        # ต่อไม่ติดเลย (DNS/เน็ต/ไฟร์วอลล์) — e.reason คือสาเหตุจริงที่ต้องบอกต่อ
        raise GeminiError(f"ต่อ Google ไม่ได้: {e.reason}") from e

    except TimeoutError as e:
        raise GeminiError(
            f"หมดเวลารอ Google ตอบกลับ ({timeout} วินาที) — "
            "โมเดลบางตัวช้ากว่าเพดานนี้ ลองเปลี่ยนโมเดลหรือเพิ่มค่า Timeout ที่หน้า System Settings"
        ) from e

    except Exception as e:
        raise GeminiError(f"เรียก AI ไม่สำเร็จ: {e}") from e


def _thinking_config() -> dict | None:
    """
    รุ่น 2.5 คุมการคิดด้วย `thinkingBudget` (จำนวน token) — รุ่น 3 ขึ้นไปเปลี่ยนเป็น
    `thinkingLevel` และ **ไม่รับ budget=0 อีกแล้ว** (ตอบ 400 INVALID_ARGUMENT ทันที)

    ชื่อที่อ่านเวอร์ชันไม่ได้ (gemini-flash-latest, gemma-*) ไม่ส่งอะไรไปเลย ปล่อยใช้ค่า
    default ของโมเดลนั้น — เดาผิดแล้วพังทั้งคำขอ ไม่คุ้มกับ token ที่ประหยัดได้
    """
    match = _MODEL_VERSION_RE.match(config.model().strip())
    if not match:
        return None

    if float(match.group(1)) >= 3:
        return {"thinkingLevel": config.THINKING_LEVEL}

    return {"thinkingBudget": config.THINKING_BUDGET}


def _payload(prompt: str, thinking: dict | None) -> dict:
    generation_config = {
        # temperature ต่ำ: งานสรุป log ต้องการความคงเส้นคงวา ไม่ใช่ความสร้างสรรค์
        "temperature": 0.2,
        "maxOutputTokens": config.MAX_OUTPUT_TOKENS,
    }

    if thinking:
        # กันโมเดลคิดจนกิน maxOutputTokens หมดแล้วคำตอบโดนตัด (ดูคำอธิบายใน config.py)
        generation_config["thinkingConfig"] = thinking

    return {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": generation_config,
    }


def _generate_content(prompt: str) -> dict:
    """
    ยิง generateContent ด้วยค่าที่ตั้งไว้ — ถ้าโมเดลไม่รับ thinkingConfig (400) ลองใหม่แบบไม่ส่ง

    การลองซ้ำมีไว้รองรับโมเดลรุ่นใหม่ที่ยังไม่รู้จักในตอนเขียนโค้ด: ทั้งชื่อและรูปแบบ
    thinkingConfig ของ Google เปลี่ยนมาแล้วหลายรอบ ไม่ควรให้แอดมินเลือกโมเดลไม่ได้เพราะเรื่องนี้
    """
    thinking = _thinking_config()

    try:
        return _request(config.generate_url(), _payload(prompt, thinking))
    except GeminiError as e:
        if e.http_code != 400 or thinking is None:
            raise

        print(f"[AI] {config.model()} ไม่รับ thinkingConfig ({e.api_message}) — ลองใหม่แบบไม่ส่ง")
        return _request(config.generate_url(), _payload(prompt, None))


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

    try:
        return True, _extract_text(_generate_content(prompt))

    except GeminiError as e:
        print(f"[AI] {e.summary} · {e.api_message or '-'}")
        return False, e.full_message

    except ValueError as e:
        # คำตอบมาแต่ใช้ไม่ได้ (โดน safety filter / ว่าง / โดนตัด) — ข้อความไทยครบอยู่แล้ว
        print(f"[AI] {e}")
        return False, str(e)


def list_models() -> tuple[bool, list[dict] | str]:
    """
    โมเดลที่ **คีย์ปัจจุบัน** เรียกได้จริง — หน้า Settings เอาไปทำตัวเลือกใน dropdown
    คืน (True, [{"name", "label"}, ...]) หรือ (False, ข้อความ error)

    กรองด้วย allowlist (`config.MODEL_ALLOWLIST`) — เหลือเฉพาะตัวที่ระบบรองรับและคีย์ใบนี้
    เห็นจริง · เรียงตามลำดับใน allowlist ไม่ใช่ลำดับที่ Google ส่งมา (ตัวแนะนำต้องอยู่บนสุด)
    """
    if not config.is_configured():
        return False, "ยังไม่ได้ตั้ง API Key — ตั้งคีย์แล้วบันทึกก่อนถึงจะดึงรายชื่อได้"

    try:
        data = _request(config.LIST_MODELS_URL)
    except GeminiError as e:
        print(f"[AI] ดึงรายชื่อโมเดลไม่สำเร็จ: {e.summary} · {e.api_message or '-'}")
        return False, e.full_message

    models = []
    for entry in data.get("models") or []:
        name = (entry.get("name") or "").split("/")[-1]

        if name not in config.MODEL_ALLOWLIST:
            continue

        # ถึงจะอยู่ใน allowlist ก็ยังต้องเช็ก เผื่อ Google เปลี่ยนโมเดลตัวนั้นไปทำอย่างอื่น
        if "generateContent" not in (entry.get("supportedGenerationMethods") or []):
            continue

        models.append({"name": name, "label": entry.get("displayName") or name})

    models.sort(key=lambda m: config.MODEL_ALLOWLIST.index(m["name"]))

    return True, models


def test_connection() -> dict:
    """
    ยิงของจริงหนึ่งครั้งด้วยคีย์+โมเดลที่ตั้งอยู่ตอนนี้ — คืนผลที่หน้า Settings แสดงได้เลย
    prompt สั้นที่สุดเท่าที่จะสั้นได้ จุดประสงค์คือดูว่าคีย์/โมเดลใช้ได้ ไม่ได้เอาคำตอบ
    """
    if not config.is_configured():
        return {"ok": False, "message": "ยังไม่ได้ตั้ง API Key"}

    if not config.model().strip():
        return {"ok": False, "message": "ยังไม่ได้เลือก Model"}

    try:
        _extract_text(_generate_content("ตอบกลับคำว่า OK คำเดียว"))

    except GeminiError as e:
        return {
            "ok": False,
            "message": e.full_message,
            "detail": {
                "model": config.model(),
                "http_code": e.http_code,
                "api_status": e.api_status,
                "api_message": e.api_message,
            },
        }

    except ValueError as e:
        return {"ok": False, "message": str(e), "detail": {"model": config.model()}}

    return {
        "ok": True,
        "message": f"เชื่อมต่อได้ — โมเดล {config.model()} ตอบกลับแล้ว",
        "detail": {"model": config.model()},
    }
