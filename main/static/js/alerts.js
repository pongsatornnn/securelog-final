


const LOG_PREVIEW = 20


const DEFAULT_PER_PAGE = 50
const PER_PAGE_CHOICES = [25, 50, 100, 200]


const PER_PAGE_KEY = 'securelog.alerts.perPage'

function loadPerPage() {
  try {
    const saved = Number(window.localStorage.getItem(PER_PAGE_KEY))


    if (PER_PAGE_CHOICES.includes(saved)) return saved
  } catch (err) {

  }

  return DEFAULT_PER_PAGE
}

function savePerPage(value) {
  try {
    window.localStorage.setItem(PER_PAGE_KEY, String(value))
  } catch (err) {

  }
}


const PAGE_WINDOW = 1


const RESYNC_DEBOUNCE_MS = 2500


function buildPageList(page, pages) {
  if (pages <= 1) return [1]

  const wanted = new Set([1, pages])
  for (let p = page - PAGE_WINDOW; p <= page + PAGE_WINDOW; p++) {
    if (p >= 1 && p <= pages) wanted.add(p)
  }

  const sorted = Array.from(wanted).sort((a, b) => a - b)
  const list = []

  sorted.forEach((p, i) => {

    if (i > 0) {
      const gap = p - sorted[i - 1]
      if (gap === 2) list.push(p - 1)
      else if (gap > 2) list.push('…')
    }
    list.push(p)
  })

  return list
}


const TH_OFFSET = '+07:00'


function toDisplayDate(iso) {
  if (!iso) return ''

  const [year, month, day] = iso.split('-')
  return day + '/' + month + '/' + year.slice(2)
}


function toIsoDate(text) {
  const parts = String(text || '').trim().match(/^(\d{1,2})\/(\d{1,2})\/(\d{2}|\d{4})$/)
  if (!parts) return ''

  const day   = Number(parts[1])
  const month = Number(parts[2])

  const year  = parts[3].length === 2 ? 2000 + Number(parts[3]) : Number(parts[3])

  const iso = [
    String(year).padStart(4, '0'),
    String(month).padStart(2, '0'),
    String(day).padStart(2, '0'),
  ].join('-')


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


    loading  : true,
    loadError: '',


    detailId     : null,
    detailLoading: false,
    detailError  : '',


    showAllLogs: false,


    filters: { start: '', end: '', host: '', attack_type: '', severity: '' },


    dateText: { start: '', end: '' },
    dateInvalid: { start: false, end: false },


    page    : 1,
    pages   : 1,
    total   : 0,


    perPage : loadPerPage(),
    perPageChoices: PER_PAGE_CHOICES,


    newIds: null,
    newWhileAway: 0,

    _resyncTimer: null,


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


    get pageText() {
      return `หน้า ${this.page} จาก ${this.pages}`
    },


    get rangeText() {
      if (this.total === 0) return '· ไม่มีรายการ'

      const from = (this.page - 1) * this.perPage + 1
      const to   = Math.min(from + this.alerts.length - 1, this.total)

      return `· แสดง ${from}–${to} จาก ${this.total} รายการ`
    },

    get pageList() {
      return buildPageList(this.page, this.pages)
    },


    rangeStartMs() {
      return this.filters.start ? Date.parse(this.filters.start + 'T00:00:00.000' + TH_OFFSET) : null
    },

    rangeEndMs() {
      return this.filters.end ? Date.parse(this.filters.end + 'T23:59:59.999' + TH_OFFSET) : null
    },

    init() {


      this.newIds = new Set()


      AlertStream.on('alert', (alert) => this.onAlert(alert))
      AlertStream.on('state', (state) => this.applyState(state))
      this.applyState(AlertStream.state())

      this.loadFilterOptions()
      this.loadHistory()
      this.openFocusFromUrl()
    },


    async loadFilterOptions() {
      try {
        const res = await fetch(window.APP_BASE + '/api/alerts_filter_options')
        if (!res.ok) return

        this.options = await res.json()
      } catch (err) {
        console.error('โหลดตัวเลือกตัวกรองไม่สำเร็จ', err)
      }
    },


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


      window.scrollTo({ top: 0, behavior: 'smooth' })
    },


    changePerPage() {
      savePerPage(this.perPage)
      this.page = 1
      this.loadHistory()
    },


    maskDate(key, el) {
      const digits = el.value.replace(/\D/g, '').slice(0, 8)

      let text = digits.slice(0, 2)
      if (digits.length > 2) text += '/' + digits.slice(2, 4)
      if (digits.length > 4) text += '/' + digits.slice(4)

      this.dateText[key] = text
      el.value = text          // :value ไม่ re-render ถ้าค่าที่ผูกไว้ไม่เปลี่ยน (เช่นพิมพ์ตัวอักษร)
    },


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


      try {
        el.showPicker()
      } catch (err) {
        el.focus()
      }
    },


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

        this.page      = data.page
        this.perPage   = data.per_page
        this.loadError = ''


        if (this.page === 1) this.clearNewMarker()


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


    openFocusFromUrl() {
      const focusId = new URLSearchParams(window.location.search).get('focus')
      if (focusId) {
        this.openDetail(Number(focusId))
      }
    },

    closeDetail() {
      this.showModal = false

      // ลิงก์จาก Dashboard ใช้ ?focus= เปิดรายละเอียดตอนเข้าหน้าเว็บ
      // เมื่อตรวจดูแล้วปิดกล่อง ให้ลบค่านี้เพื่อไม่ให้ F5 เปิดซ้ำ
      const url = new URL(window.location.href)
      if (url.searchParams.has('focus')) {
        url.searchParams.delete('focus')
        window.history.replaceState(window.history.state, '', url)
      }
    },

    // alert ใหม่จากสตรีมกลาง — การต่อ/ต่อใหม่/ถอยเวลา retry เป็นหน้าที่ของ alert-stream.js
    // หน้านี้แค่เอาไปแสดงในตาราง (popup กับ badge ที่เมนู alert-notify.js จัดการแยก)
    onAlert(alert) {


      const matched = this.matchesFilters(alert)
      const existingIndex = this.alerts.findIndex(a => a.id === alert.id)


      if (this.page !== 1) {
        if (matched && !this.newIds.has(alert.id)) {
          this.newIds.add(alert.id)
          this.newWhileAway = this.newIds.size
        }
        return
      }


      if (existingIndex !== -1) {
        this.alerts.splice(existingIndex, 1)
      }


      if (!matched) {
        if (existingIndex !== -1) this.scheduleResync()
        return
      }

      this.alerts.unshift({ ...alert, isNew: true })


      if (this.alerts.length > this.perPage) {
        this.alerts.pop()
      }


      this.scheduleResync()


      setTimeout(() => {
        const row = this.alerts.find(a => a.id === alert.id)
        if (row) row.isNew = false
      }, 600)
    },


    scheduleResync() {
      clearTimeout(this._resyncTimer)

      this._resyncTimer = setTimeout(() => {


        if (this.page === 1 && !this.loading) this.loadHistory()
      }, RESYNC_DEBOUNCE_MS)
    },


    applyState(state) {
      if (state === 'connected') {
        this.statusClass = 'connected'
        this.statusText  = 'กำลังตรวจจับ'


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


      this.$store.alerts.markOpened(id)

      try {
        const res = await fetch(window.APP_BASE + `/api/alerts/${id}`)

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        this.detail = await res.json()
      } catch (err) {

        this.detailError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลดรายละเอียดไม่สำเร็จ', err)
      } finally {
        this.detailLoading = false
      }
    },


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
