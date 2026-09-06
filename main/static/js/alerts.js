// ย้ายมาจาก templates/alerts.html (บล็อก <script> เดิม)
// จำนวน raw log ที่โชว์ก่อนต้องกด "แสดงทั้งหมด" — พอให้เห็นรูปแบบของการโจมตีแล้ว
// โดยที่กล่องรายละเอียดยังเลื่อนดูส่วนอื่นได้สะดวก
const LOG_PREVIEW = 20

// จำนวนแถวต่อหน้า — ค่าเริ่มต้นต้องตรงกับ DEFAULT_PER_PAGE ฝั่ง server
// และทุกค่าในลิสต์ต้องไม่เกิน MAX_PER_PAGE (200) ไม่งั้น server จะบีบลงเงียบ ๆ
const DEFAULT_PER_PAGE = 50
const PER_PAGE_CHOICES = [25, 50, 100, 200]

// จำค่าที่ผู้ใช้เลือกไว้ข้ามการรีเฟรช — เก็บที่ browser แบบเดียวกับสถานะย่อ/กางเมนู
// (base.html) เพราะเป็นความชอบเรื่องการแสดงผล ไม่ใช่ข้อมูลของระบบ · ต่างจาก
// last_seen_alert_id ที่ย้ายไปเก็บใน DB เพราะต้องซิงค์ตามบัญชีข้ามเครื่อง
const PER_PAGE_KEY = 'securelog.alerts.perPage'

function loadPerPage() {
  try {
    const saved = Number(window.localStorage.getItem(PER_PAGE_KEY))

    // ต้องเป็นค่าที่มีใน dropdown จริงเท่านั้น — กันค่าที่ค้างจากเวอร์ชันเก่าหรือถูกแก้เอง
    // หลุดไปถึง server แล้วโดนบีบลงเงียบ ๆ จนตัวเลือกที่เห็นไม่ตรงกับจำนวนแถวจริง
    if (PER_PAGE_CHOICES.includes(saved)) return saved
  } catch (err) {
    /* localStorage ใช้ไม่ได้ (private mode) -> ใช้ค่าเริ่มต้น */
  }

  return DEFAULT_PER_PAGE
}

function savePerPage(value) {
  try {
    window.localStorage.setItem(PER_PAGE_KEY, String(value))
  } catch (err) {
    /* จำข้ามรอบไม่ได้ แต่ยังใช้ค่าที่เลือกในหน้านี้ได้ตามปกติ */
  }
}

// จำนวนเลขหน้าที่โชว์รอบ ๆ หน้าปัจจุบัน (ข้างละเท่านี้) ก่อนจะย่อเป็น "…"
const PAGE_WINDOW = 1

// หน่วงก่อนดึงข้อมูลใหม่หลังมี alert เข้ามาตอนอยู่หน้า 1 — ยิงรวดเดียวตอนพายุสงบ
// ไม่ใช่ทุกครั้งที่ event เข้า (ตอนโดนยิงรัว ๆ event มาได้เป็นสิบครั้งในไม่กี่วินาที)
const RESYNC_DEBOUNCE_MS = 2500

// ย่อรายการเลขหน้าให้เหลือ: หน้าแรก · ช่วงรอบหน้าปัจจุบัน · หน้าสุดท้าย (คั่นด้วย '…')
// เช่น 12 หน้า อยู่หน้า 5 -> [1, '…', 4, 5, 6, '…', 12]
function buildPageList(page, pages) {
  if (pages <= 1) return [1]

  const wanted = new Set([1, pages])
  for (let p = page - PAGE_WINDOW; p <= page + PAGE_WINDOW; p++) {
    if (p >= 1 && p <= pages) wanted.add(p)
  }

  const sorted = Array.from(wanted).sort((a, b) => a - b)
  const list = []

  sorted.forEach((p, i) => {
    // ห่างจากตัวก่อนหน้าแค่ 1 ช่อง = ใส่เลขนั้นไปเลย สั้นกว่าและกดได้ ไม่ต้องเป็น '…'
    if (i > 0) {
      const gap = p - sorted[i - 1]
      if (gap === 2) list.push(p - 1)
      else if (gap > 2) list.push('…')
    }
    list.push(p)
  })

  return list
}

// ขอบวันที่ของตัวกรองยึดเวลาไทยเสมอ ไม่ใช่โซนของเครื่องที่เปิดหน้าเว็บ — คอลัมน์เวลา
// ในตารางแสดงเป็นเวลาไทยตายตัวอยู่แล้ว (formatTime ใน common.js) ถ้าขอบวันคิดตามโซน
// ของ browser ผู้ใช้ที่อยู่คนละโซนจะเลือกวันที่เห็นบนจอแล้วได้แถวไม่ครบ
const TH_OFFSET = '+07:00'

// ─── วันที่ที่ผู้ใช้เห็นเป็น dd/mm/yy แต่ค่าที่เก็บ/ส่งให้ server เป็น YYYY-MM-DD เสมอ ───
// (ISO เรียงลำดับด้วยการเทียบ string ได้ตรง ๆ และเป็นรูปแบบเดียวกับที่ input[type=date] ใช้)

// 'YYYY-MM-DD' -> 'dd/mm/yy'
function toDisplayDate(iso) {
  if (!iso) return ''

  const [year, month, day] = iso.split('-')
  return day + '/' + month + '/' + year.slice(2)
}

// 'dd/mm/yy' (รับ dd/mm/yyyy ด้วย เผื่อวางทับมาทั้งปี) -> 'YYYY-MM-DD' / '' ถ้าไม่ใช่วันที่จริง
function toIsoDate(text) {
  const parts = String(text || '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{2}|\d{4})$/)
  if (!parts) return ''

  const day   = Number(parts[1])
  const month = Number(parts[2])
  // ปี 2 หลักคิดเป็น ค.ศ. 20xx — log ในระบบนี้เป็นของยุคปัจจุบันทั้งหมด ไม่มีเคสกำกวม
  const year  = parts[3].length === 2 ? 2000 + Number(parts[3]) : Number(parts[3])

  const iso = [
    String(year).padStart(4, '0'),
    String(month).padStart(2, '0'),
    String(day).padStart(2, '0'),
  ].join('-')

  // Date ปัดวันที่ไม่มีจริงให้กลายเป็นวันถัดไปเงียบ ๆ (31/02 -> 03/03) — เทียบค่าที่ได้กลับมา
  // เพื่อจับเคสนั้น ไม่งั้นผู้ใช้จะได้ผลลัพธ์ของวันที่ที่ไม่ได้พิมพ์
  const parsed = new Date(iso + 'T00:00:00Z')

  return !Number.isNaN(parsed.getTime()) && parsed.toISOString().slice(0, 10) === iso ? iso : ''
}

function alertsApp() {
  return {
    alerts     : [],
    showModal  : false,
    detail     : null,
    aiLoading  : false,
    aiError    : '',
    statusClass: 'connecting',
    statusText : 'กำลังเชื่อมต่อ...',
    wasDisconnected: false,

    // แยก "กำลังโหลด" กับ "โหลดไม่สำเร็จ" ออกจาก "ไม่พบการโจมตี" — สำคัญเป็นพิเศษในหน้านี้
    // เพราะ "ไม่พบการโจมตี" ตอน API พังคือข้อความที่ทำให้เข้าใจผิดว่าระบบปกติดี
    loading  : true,
    loadError: '',

    // สถานะของ modal รายละเอียด (เดิมโหลดไม่สำเร็จแล้ว modal เปิดค้างเป็นกล่องว่าง)
    detailId     : null,
    detailLoading: false,
    detailError  : '',

    // เหตุการณ์เดียวอาจมี raw log หลายร้อยบรรทัด (ที่พบจริงในระบบนี้สูงสุด 720) ซึ่งมัก
    // เป็นบรรทัดหน้าตาเดียวกันซ้ำ ๆ — แสดงตัวอย่างแค่ส่วนแรกก่อน แล้วให้กดกางเอง
    showAllLogs: false,

    // ค่าว่าง = ไม่กรองข้อนั้น (ตรงกับ query param ที่ server ถือว่า "ไม่ส่งมา")
    filters: { start: '', end: '', host: '', attack_type: '', severity: '' },

    // ข้อความ dd/mm/yy ที่โชว์ในช่อง — แยกจาก filters.start/end ที่เป็น YYYY-MM-DD เพราะ
    // ระหว่างพิมพ์ยังไม่เป็นวันที่ที่สมบูรณ์ (เช่น "31/0") ซึ่งเอาไปกรองไม่ได้
    dateText: { start: '', end: '' },
    dateInvalid: { start: false, end: false },

    // ─── แบ่งหน้า ─── (page/pages/total เป็นค่าที่ server บอกมา ไม่ได้คำนวณเอง)
    page    : 1,
    pages   : 1,
    total   : 0,
    // อ่านค่าที่เลือกไว้ครั้งก่อนตั้งแต่ตอนสร้าง state — โหลดรอบแรกจึงใช้ค่านั้นเลย
    // ไม่ต้องโหลดด้วยค่า default ก่อนแล้วค่อยยิงซ้ำ
    perPage : loadPerPage(),
    perPageChoices: PER_PAGE_CHOICES,

    // จำนวนเหตุการณ์ใหม่ที่เข้ามาตอนอยู่หน้า 2+ — นับเป็น Set ของ id ไม่ใช่ตัวเลขบวกเพิ่ม
    // เพราะเหตุการณ์เดียวที่ถูก merge จะ publish ซ้ำด้วย id เดิม (นับเป็นตัวเลขจะเฟ้อ)
    newIds: null,
    newWhileAway: 0,

    _resyncTimer: null,

    // ตัวเลือกใน dropdown มาจากค่าที่มีอยู่จริงในตาราง alert — ระหว่างที่ยังโหลดไม่เสร็จ
    // ให้เป็นลิสต์ว่างไว้ก่อน (เหลือแต่ตัวเลือก "ทั้งหมด" ซึ่งเป็นค่าเริ่มต้นอยู่แล้ว)
    options: { hosts: [], attack_types: [], severities: [] },

    get visibleLogs() {
      if (!this.detail) return []
      return this.showAllLogs ? this.detail.raw_logs : this.detail.raw_logs.slice(0, LOG_PREVIEW)
    },

    get hasFilter() {
      return Object.values(this.filters).some(value => value !== '')
    },

    get countText() {
      const label = this.total + ' รายการ'
      return this.hasFilter ? label + ' (ตามตัวกรอง)' : label
    },

    // "หน้า 2 จาก 3" — ปุ่มที่ไฮไลต์บอกได้แค่ว่าอยู่หน้าไหน ไม่ได้บอกว่ามีทั้งหมดกี่หน้า
    // เมื่อรายการถูกย่อด้วย "…" (เช่น 1 … 4 5 6 … 12 ตอนอยู่หน้าท้าย ๆ ก็ยังต้องไล่ดูเอง)
    get pageText() {
      return `หน้า ${this.page} จาก ${this.pages}`
    },

    // "· แสดง 51–100 จาก 137 รายการ" — ต่อท้าย pageText จึงขึ้นต้นด้วยตัวคั่น
    get rangeText() {
      if (this.total === 0) return '· ไม่มีรายการ'

      const from = (this.page - 1) * this.perPage + 1
      const to   = Math.min(from + this.alerts.length - 1, this.total)

      return `· แสดง ${from}–${to} จาก ${this.total} รายการ`
    },

    get pageList() {
      return buildPageList(this.page, this.pages)
    },

    // ขอบล่าง/ขอบบนของช่วงวันที่ในหน่วย epoch ms — null = ไม่ได้เลือกวันนั้นไว้
    // ขอบบนคือ 23:59:59.999 ของวันที่เลือก เพื่อให้ "ถึงวันที่" รวมทั้งวันนั้นด้วย
    rangeStartMs() {
      return this.filters.start ? Date.parse(this.filters.start + 'T00:00:00.000' + TH_OFFSET) : null
    },

    rangeEndMs() {
      return this.filters.end ? Date.parse(this.filters.end + 'T23:59:59.999' + TH_OFFSET) : null
    },

    init() {
      // Set ไม่ใช่ reactive ใน Alpine (proxy ไม่ครอบ Set) — เก็บไว้เฉย ๆ แล้วสะท้อนจำนวน
      // ออกทาง newWhileAway ที่เป็นตัวเลขธรรมดาแทน หน้าจอจึงอัปเดตตามจริง
      this.newIds = new Set()

      // ไม่เปิด EventSource ของตัวเองแล้ว — ใช้เส้นที่ base.html เปิดไว้ให้ทุกหน้า
      // (static/js/alert-stream.js) ไม่งั้นเปิดหน้านี้จะกิน connection + Redis pubsub
      // ฝั่ง server เพิ่มอีกเส้นทั้งที่ข้อมูลเหมือนกัน
      AlertStream.on('alert', (alert) => this.onAlert(alert))
      AlertStream.on('state', (state) => this.applyState(state))
      this.applyState(AlertStream.state())

      this.loadFilterOptions()
      this.loadHistory()
      this.openFocusFromUrl()
    },

    // ตัวเลือกใน dropdown — พลาดก็ไม่ต้องแจ้ง เพราะตัวกรองที่ใช้ไม่ได้ชั่วคราวไม่ควรบัง
    // ตารางหลักที่ยังโหลดได้ปกติ (ผู้ใช้เห็นเองว่าลิสต์มีแต่ "ทั้งหมด")
    async loadFilterOptions() {
      try {
        const res = await fetch(window.APP_BASE + '/api/alerts_filter_options')
        if (!res.ok) return

        this.options = await res.json()
      } catch (err) {
        console.error('โหลดตัวเลือกตัวกรองไม่สำเร็จ', err)
      }
    },

    // ตัวกรอง + ตำแหน่งหน้า -> query string ของ /api/alerts (ข้อที่ไม่ได้เลือกไม่ต้องส่งไป)
    // วันที่ส่งเป็น ISO UTC ที่คำนวณขอบวันตามเวลาไทยมาแล้ว server จึงไม่ต้องเดาโซนเวลา
    filterQuery() {
      const params = new URLSearchParams()
      const startMs = this.rangeStartMs()
      const endMs   = this.rangeEndMs()

      if (startMs !== null) params.set('start', new Date(startMs).toISOString())
      if (endMs   !== null) params.set('end',   new Date(endMs).toISOString())
      if (this.filters.host)        params.set('host', this.filters.host)
      if (this.filters.attack_type) params.set('attack_type', this.filters.attack_type)
      if (this.filters.severity)    params.set('severity', this.filters.severity)

      params.set('page', this.page)
      params.set('per_page', this.perPage)

      return '?' + params.toString()
    },

    // เปลี่ยนตัวกรองแล้วต้องกลับหน้า 1 เสมอ — จำนวนหน้าของผลลัพธ์ชุดใหม่ไม่เกี่ยวกับชุดเดิม
    // (อยู่หน้า 7 แล้วกรองเหลือ 2 หน้า = ค้างอยู่หน้าที่ไม่มีอะไร)
    applyFilters() {
      this.page = 1
      this.loadHistory()
    },

    clearFilters() {
      this.filters     = { start: '', end: '', host: '', attack_type: '', severity: '' }
      this.dateText    = { start: '', end: '' }
      this.dateInvalid = { start: false, end: false }
      this.applyFilters()
    },

    goToPage(page) {
      const target = Math.min(Math.max(1, page), this.pages)
      if (target === this.page || this.loading) return

      this.page = target
      this.loadHistory()

      // เลื่อนขึ้นไปหัวตาราง ไม่งั้นกดเปลี่ยนหน้าจากปุ่มด้านล่างแล้วยังค้างอยู่ท้ายรายการ
      // ทั้งที่เนื้อหาเปลี่ยนไปหมดแล้ว
      window.scrollTo({ top: 0, behavior: 'smooth' })
    },

    // เปลี่ยนจำนวนแถวต่อหน้า -> ขอบของทุกหน้าเปลี่ยนหมด กลับไปหน้า 1 เพื่อไม่ให้กระโดด
    // ไปโผล่กลางรายการแบบเดาตำแหน่งไม่ถูก
    changePerPage() {
      savePerPage(this.perPage)
      this.page = 1
      this.loadHistory()
    },

    // เติม "/" ให้เองระหว่างพิมพ์ ผู้ใช้จึงพิมพ์แต่ตัวเลขรวดเดียวได้ (31072026 -> 31/07/2026)
    // รับได้ถึง 8 หลักเผื่อพิมพ์/วางปีมาเต็ม 4 หลัก แล้วค่อยย่อเป็น yy ตอน commit
    maskDate(key, el) {
      const digits = el.value.replace(/\D/g, '').slice(0, 8)

      let text = digits.slice(0, 2)
      if (digits.length > 2) text += '/' + digits.slice(2, 4)
      if (digits.length > 4) text += '/' + digits.slice(4)

      this.dateText[key] = text
      el.value = text          // :value ไม่ re-render ถ้าค่าที่ผูกไว้ไม่เปลี่ยน (เช่นพิมพ์ตัวอักษร)
    },

    // ยืนยันค่าที่พิมพ์ -> กรองจริง (เรียกตอน change/blur/Enter ซึ่งซ้ำกันได้ ไม่มีผลข้างเคียง
    // เพราะถ้าค่าไม่เปลี่ยนจะไม่ยิงโหลดใหม่)
    commitDate(key) {
      const text = (this.dateText[key] || '').trim()

      if (!text) {
        this.dateInvalid[key] = false
        if (this.filters[key]) {
          this.filters[key] = ''
          this.applyFilters()
        }
        return
      }

      const iso = toIsoDate(text)

      this.dateInvalid[key] = !iso
      if (!iso) return         // คงตัวกรองเดิมไว้ + ขึ้นข้อความบอกว่าพิมพ์ผิด

      this.dateText[key] = toDisplayDate(iso)   // ย่อให้เป็น dd/mm/yy เสมอหลังยืนยัน

      if (iso !== this.filters[key]) {
        this.filters[key] = iso
        this.applyFilters()
      }
    },

    // เลือกจากปฏิทินของ browser — ได้ YYYY-MM-DD มาตรง ๆ ไม่ต้อง parse
    setDate(key, iso) {
      this.dateInvalid[key] = false
      this.dateText[key]    = toDisplayDate(iso)

      if (iso !== this.filters[key]) {
        this.filters[key] = iso
        this.applyFilters()
      }
    },

    openPicker(el) {
      if (!el) return

      // showPicker() ต้องถูกเรียกจาก event ของผู้ใช้ (ปุ่มนี้) — browser เก่าที่ยังไม่มีจะ
      // throw ให้ตกมาที่ focus แทน อย่างน้อยก็เปิดปฏิทินด้วยคีย์บอร์ดต่อได้
      try {
        el.showPicker()
      } catch (err) {
        el.focus()
      }
    },

    // alert ที่วิ่งเข้ามาทาง SSE ต้องผ่านเงื่อนไขเดียวกับที่ส่งไปกรองที่ server ก่อนจะโผล่
    // ในตาราง ไม่งั้นแถวที่ไม่เข้าเงื่อนไขจะแทรกขึ้นมาเองทั้งที่ตัวกรองยังเปิดอยู่
    matchesFilters(alert) {
      if (this.filters.host && alert.agent_id !== this.filters.host) return false
      if (this.filters.attack_type && alert.detection_type !== this.filters.attack_type) return false
      if (this.filters.severity && alert.severity !== this.filters.severity) return false

      const startMs = this.rangeStartMs()
      const endMs   = this.rangeEndMs()
      const alertMs = Date.parse(alert.timestamp)

      if (Number.isNaN(alertMs)) return true      // ไม่มีเวลาให้เทียบ = อย่าเผลอซ่อนทิ้ง
      if (startMs !== null && alertMs < startMs) return false
      if (endMs   !== null && alertMs > endMs)   return false

      return true
    },

    async loadHistory() {
      this.loading = true

      // ยกเลิกการ resync ที่ค้างคิวอยู่ — กำลังจะได้ข้อมูลสดกว่าจากรอบนี้อยู่แล้ว
      clearTimeout(this._resyncTimer)

      try {
        const res = await fetch(window.APP_BASE + '/api/alerts' + this.filterQuery())

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        const data = await res.json()

        this.alerts    = (data.items || []).map(a => ({ ...a, isNew: false }))
        this.total     = data.total
        this.pages     = data.pages
        // server บีบหน้าที่เลยขอบให้อยู่ในช่วงที่มีจริงแล้ว — ยึดค่าที่มันใช้จริง ไม่ใช่ค่าที่ขอไป
        this.page      = data.page
        this.perPage   = data.per_page
        this.loadError = ''

        // กลับมาอยู่หน้า 1 แล้ว = เห็นของใหม่ครบแล้ว แถบแจ้งเตือนจึงหมดหน้าที่
        if (this.page === 1) this.clearNewMarker()

        // เห็นรายการครบแล้ว -> เคลียร์ badge "ยังไม่ได้อ่าน" ที่เมนู Alerts
        // (markRead กันค่าถอยหลังอยู่แล้ว หน้าลึก ๆ ที่ id ต่ำกว่าจึงไม่ดึงค่าย้อนกลับ)
        const maxId = this.alerts.reduce((max, a) => (a.id > max ? a.id : max), 0)
        if (maxId) this.$store.alerts.markRead(maxId)
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด alert ไม่สำเร็จ', err)
      } finally {
        this.loading = false
      }
    },

    clearNewMarker() {
      this.newIds.clear()
      this.newWhileAway = 0
    },

    // เปิด detail ตาม ?focus= (ลิงก์ "ดู" จากหน้า Dashboard) — ต้องทำครั้งเดียวตอนเข้าหน้า
    // เท่านั้น เพราะ loadHistory() ถูกเรียกซ้ำทุกครั้งที่ SSE reconnect ด้วย
    openFocusFromUrl() {
      const focusId = new URLSearchParams(window.location.search).get('focus')
      if (focusId) {
        this.openDetail(Number(focusId))
      }
    },

    // alert ใหม่จากสตรีมกลาง — การต่อ/ต่อใหม่/ถอยเวลา retry เป็นหน้าที่ของ alert-stream.js
    // หน้านี้แค่เอาไปแสดงในตาราง (popup กับ badge ที่เมนู alert-notify.js จัดการแยก)
    onAlert(alert) {
      // ไม่เข้าตัวกรองที่เปิดอยู่ = ไม่เกี่ยวกับสิ่งที่ผู้ใช้กำลังดู ไม่ต้องแตะอะไรทั้งนั้น
      // (ยกเว้นถ้ามันเคยอยู่ในตาราง — เคสนั้นจัดการต่อด้านล่าง)
      const matched = this.matchesFilters(alert)
      const existingIndex = this.alerts.findIndex(a => a.id === alert.id)

      // อยู่หน้า 2 ขึ้นไป: ห้ามแตะตารางเด็ดขาด แค่จำไว้ว่ามีของใหม่แล้วขึ้นแถบบอก
      // (แทรกแถวตรงนี้จะทำให้ขอบของทุกหน้าเลื่อน = แถวซ้ำ/แถวหายในหน้าที่กำลังอ่านอยู่)
      if (this.page !== 1) {
        if (matched && !this.newIds.has(alert.id)) {
          this.newIds.add(alert.id)
          this.newWhileAway = this.newIds.size
        }
        return
      }

      // ถ้า id นี้เคยแสดงอยู่แล้ว (เหตุการณ์เดิมที่ backend merge เข้าแถวเดิม)
      // เอาแถวเก่าออกก่อน แล้วเอาแถวที่อัปเดตแล้วขึ้นบนสุดแทน ไม่ใช่เพิ่มแถวใหม่ซ้อน
      if (existingIndex !== -1) {
        this.alerts.splice(existingIndex, 1)
      }

      // เหตุการณ์ที่ merge แล้ว "เวลาล่าสุด" ขยับไปข้างหน้าได้ — แถวที่เคยเข้าเงื่อนไขจึง
      // หลุดช่วงวันที่ที่กรองไว้ได้ ต้องเอาออกจริง (ลบข้างบนไปแล้ว) ไม่ใช่แค่ไม่เพิ่มใหม่
      if (!matched) {
        if (existingIndex !== -1) this.scheduleResync()
        return
      }

      this.alerts.unshift({ ...alert, isNew: true })

      // เกินโควตาของหน้า -> ตัดแถวท้ายทิ้ง มันไหลไปเป็นแถวแรกของหน้า 2 แล้ว
      if (this.alerts.length > this.perPage) {
        this.alerts.pop()
      }

      // total/pages ที่ถูกต้องรู้ได้จาก server เท่านั้น (แยกไม่ออกจากตรงนี้ว่า id ที่เพิ่งเข้ามา
      // เป็นเหตุการณ์ใหม่จริง หรือเป็นของเดิมที่ merge แล้วอยู่หน้าอื่น) -> ขอค่าจริงตามไป
      this.scheduleResync()

      // ต้องหาแถวจาก this.alerts (ผ่าน proxy ของ Alpine) แล้วค่อยแก้ ไม่ใช่แก้ object ที่รับ
      // มาตรง ๆ — แก้ object ดิบไม่ทำให้ re-render ไฟกระพริบแถวใหม่เลยค้างไม่ยอมดับ
      setTimeout(() => {
        const row = this.alerts.find(a => a.id === alert.id)
        if (row) row.isNew = false
      }, 600)
    },

    // ดึงหน้าปัจจุบันใหม่แบบเงียบ ๆ หลังพายุ alert สงบ เพื่อให้จำนวนรวม/จำนวนหน้าตรงกับ
    // ความจริง — หน่วงไว้เพราะตอนโดนยิงรัว ๆ event เข้ามาได้เป็นสิบครั้งในไม่กี่วินาที
    // และแถวบนสุดถูกแทรกให้เห็นทันทีไปแล้ว ไม่ได้รอรอบนี้
    scheduleResync() {
      clearTimeout(this._resyncTimer)

      this._resyncTimer = setTimeout(() => {
        // ระหว่างรอผู้ใช้อาจเปลี่ยนไปหน้าอื่น — หน้าอื่นมีแถบ "มีของใหม่" ทำหน้าที่แทนแล้ว
        // ถ้าโหลดทับตอนนั้นตารางจะขยับเองทั้งที่ผู้ใช้ไม่ได้สั่ง
        if (this.page === 1 && !this.loading) this.loadHistory()
      }, RESYNC_DEBOUNCE_MS)
    },

    // สถานะการเชื่อมต่อของสตรีมกลาง -> จุดสี + ข้อความข้างหัวข้อตาราง
    applyState(state) {
      if (state === 'connected') {
        this.statusClass = 'connected'
        this.statusText  = 'กำลังตรวจจับ'

        // เพิ่งกลับมาต่อได้: ช่วงที่หลุดอาจมี alert เข้ามาแต่ไม่ได้รับ -> ดึงรายการใหม่ทั้งชุด
        if (this.wasDisconnected) {
          this.wasDisconnected = false
          this.loadHistory()
        }
        return
      }

      if (state === 'disconnected') {
        this.statusClass = 'disconnected'
        this.statusText  = 'หลุดการเชื่อมต่อ กำลังเชื่อมใหม่...'
        this.wasDisconnected = true
        return
      }

      this.statusClass = 'connecting'
      this.statusText  = 'กำลังเชื่อมต่อ...'
    },

    async openDetail(id) {
      this.detail        = null
      this.showModal     = true
      this.aiError       = ''
      this.aiLoading     = false
      this.detailId      = id
      this.detailError   = ''
      this.detailLoading = true
      this.showAllLogs   = false   // เปิดเคสใหม่ = เริ่มที่มุมมองย่อเสมอ

      // กดดูแล้ว = ตรวจสอบเคสนี้แล้ว -> จุด "ยังไม่ได้อ่าน" หน้าแถวหายทันที
      this.$store.alerts.markOpened(id)

      try {
        const res = await fetch(window.APP_BASE + `/api/alerts/${id}`)

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        this.detail = await res.json()
      } catch (err) {
        // เดิมเงียบสนิท — modal เปิดค้างเป็นกล่องว่างโดยไม่บอกว่าเกิดอะไรขึ้น
        this.detailError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลดรายละเอียดไม่สำเร็จ', err)
      } finally {
        this.detailLoading = false
      }
    },

    // เรียก AI เฉพาะตอนกดปุ่มเท่านั้น (force=true = เคยวิเคราะห์แล้วแต่อยากได้ผลใหม่)
    async analyze(force = false) {
      if (this.aiLoading || !this.detail) return

      const id = this.detail.id

      this.aiLoading = true
      this.aiError   = ''

      try {
        const res  = await fetch(window.APP_BASE + `/api/alerts/${id}/ai-summary?force=${force}`, {
          method: 'POST'
        })
        const data = await res.json()

        if (!res.ok) {
          this.aiError = data.detail || 'วิเคราะห์ไม่สำเร็จ'
          return
        }

        // ระหว่างรอ AI แอดมินอาจปิด modal แล้วเปิด alert อื่น -> อย่าเอาผลไปใส่ผิดแถว
        if (this.detail && this.detail.id === id) {
          this.detail.ai_summary    = data.ai_summary
          this.detail.ai_summary_at = data.ai_summary_at
        }
      } catch (err) {
        console.error('เรียก AI ไม่สำเร็จ', err)
        this.aiError = 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้ ลองใหม่อีกครั้ง'
      } finally {
        this.aiLoading = false
      }
    },

  }
}
