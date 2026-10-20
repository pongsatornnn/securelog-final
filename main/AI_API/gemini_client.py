

import json
import re
import urllib.error
import urllib.request

from AI_API import config


_MODEL_VERSION_RE = re.compile(r"^gemini-(\d+(?:\.\d+)?)")


class GeminiError(Exception):


    def __init__(self, summary: str, *, http_code=None, api_status=None, api_message=None):
        self.summary = summary
        self.http_code = http_code
        self.api_status = api_status
        self.api_message = api_message
        super().__init__(summary)

    @property
    def full_message(self) -> str:

        if not self.api_message:
            return self.summary
        return f"{self.summary}\nGoogle ตอบกลับ: {self.api_message}"


def _http_error(e: urllib.error.HTTPError) -> GeminiError:

    body = e.read().decode("utf-8", "replace")
    api_message = None
    api_status = None

    try:
        error = json.loads(body).get("error") or {}
        api_message = error.get("message")
        api_status = error.get("status")
    except Exception:

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

    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") if payload is not None else None

    headers = {"x-goog-api-key": config.api_key()}
    if data is not None:
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, method="POST" if data else "GET", headers=headers)


    timeout = config.timeout_sec()

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    except urllib.error.HTTPError as e:
        raise _http_error(e) from e

    except urllib.error.URLError as e:

        raise GeminiError(f"ต่อ Google ไม่ได้: {e.reason}") from e

    except TimeoutError as e:
        raise GeminiError(
            f"หมดเวลารอ Google ตอบกลับ ({timeout} วินาที) — "
            "โมเดลบางตัวช้ากว่าเพดานนี้ ลองเปลี่ยนโมเดลหรือเพิ่มค่า Timeout ที่หน้า System Settings"
        ) from e

    except Exception as e:
        raise GeminiError(f"เรียก AI ไม่สำเร็จ: {e}") from e


def _thinking_config() -> dict | None:

    match = _MODEL_VERSION_RE.match(config.model().strip())
    if not match:
        return None

    if float(match.group(1)) >= 3:
        return {"thinkingLevel": config.THINKING_LEVEL}

    return {"thinkingBudget": config.THINKING_BUDGET}


def _payload(prompt: str, thinking: dict | None) -> dict:
    generation_config = {

        "temperature": 0.2,
        "maxOutputTokens": config.MAX_OUTPUT_TOKENS,
    }

    if thinking:

        generation_config["thinkingConfig"] = thinking

    return {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": generation_config,
    }


def _generate_content(prompt: str) -> dict:

    thinking = _thinking_config()

    try:
        return _request(config.generate_url(), _payload(prompt, thinking))
    except GeminiError as e:
        if e.http_code != 400 or thinking is None:
            raise

        print(f"[AI] {config.model()} ไม่รับ thinkingConfig ({e.api_message}) — ลองใหม่แบบไม่ส่ง")
        return _request(config.generate_url(), _payload(prompt, None))


def _extract_text(data: dict) -> str:

    candidates = data.get("candidates") or []

    if not candidates:

        reason = (data.get("promptFeedback") or {}).get("blockReason")
        raise ValueError(f"Gemini ไม่ส่งคำตอบกลับมา (blockReason={reason})")

    parts = ((candidates[0].get("content") or {}).get("parts")) or []
    text = "".join(part.get("text", "") for part in parts).strip()
    finish = candidates[0].get("finishReason")

    if not text:
        raise ValueError(f"Gemini ส่งคำตอบว่าง (finishReason={finish})")


    if finish == "MAX_TOKENS":
        raise ValueError(
            "คำตอบจาก AI ยาวเกินเพดานที่ตั้งไว้เลยถูกตัดกลางคัน "
            "(ปรับ GEMINI_MAX_OUTPUT_TOKENS ใน .env ให้สูงขึ้น)"
        )

    return text


def generate(prompt: str) -> tuple[bool, str]:

    if not config.is_configured():
        return False, "ยังไม่ได้ตั้งค่า API Key ของ Gemini — ตั้งได้ที่หน้า System Settings"

    try:
        return True, _extract_text(_generate_content(prompt))

    except GeminiError as e:
        print(f"[AI] {e.summary} · {e.api_message or '-'}")
        return False, e.full_message

    except ValueError as e:

        print(f"[AI] {e}")
        return False, str(e)


def list_models() -> tuple[bool, list[dict] | str]:

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


        if "generateContent" not in (entry.get("supportedGenerationMethods") or []):
            continue

        models.append({"name": name, "label": entry.get("displayName") or name})

    models.sort(key=lambda m: config.MODEL_ALLOWLIST.index(m["name"]))

    return True, models


def test_connection() -> dict:

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
