from pydantic import BaseModel, Field


class UpdateAlertReadStateRequest(BaseModel):
    """
    body ของ POST /api/alerts_read_state — ส่งมาอย่างใดอย่างหนึ่งหรือทั้งคู่ก็ได้

    opened_ids   = alert ที่เพิ่งกดดูรายละเอียด (คุมจุด "ยังไม่ได้อ่าน" หน้าแถว)
    last_seen_id = id ล่าสุดที่เห็นในรายการแล้ว (คุมตัวเลข badge ที่เมนู Alerts)

    จำกัด opened_ids ไว้ 500 ตัวเท่ากับเพดาน cache ฝั่ง browser (alert-notify.js) — กัน
    body ใหญ่เกินจำเป็นตอน browser ดันรายการที่ค้างอยู่ขึ้นมาซิงค์รอบแรก
    """

    opened_ids: list[int] = Field(default_factory=list, max_length=500)
    last_seen_id: int | None = None
