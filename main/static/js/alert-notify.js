// แจ้งเตือน alert ใหม่: popup มุมขวาล่าง + ตัวเลข "ยังไม่ได้อ่าน" ที่เมนู Alerts
(function () {
  var BASE = window.APP_BASE || ''
  var READ_STATE_URL = BASE + '/api/alerts_read_state'
  var UNREAD_COUNT_URL = BASE + '/api/alerts_unread_count'

  // key ของ cache ใน localStorage — สองตัวนี้คนละความหมายกัน:
  var READ_KEY = 'securelog.alerts.lastReadId'
  var OPENED_KEY = 'securelog.alerts.openedIds'
  var MAX_OPENED = 500

  var TOAST_TTL_MS = 8000
  var MAX_TOASTS = 4
  var REFRESH_DEBOUNCE_MS = 400

  function setLastReadId(id) {
    try {
      window.localStorage.setItem(READ_KEY, String(id))
    } catch (err) {
    }
  }

  function readOpenedIds() {
    try {
      var raw = JSON.parse(window.localStorage.getItem(OPENED_KEY) || '[]')
      return Array.isArray(raw) ? raw : []
    } catch (err) {
      return []
    }
  }

  function writeOpenedIds(ids) {
    try {
      window.localStorage.setItem(OPENED_KEY, JSON.stringify(ids))
    } catch (err) {
    }
  }

  document.addEventListener('alpine:init', function () {
    Alpine.store('alerts', {
      unread: 0,
      toasts: [],

      // map id -> 1 (ไม่ใช่ array) เพราะตารางเรียก isOpened() ทุกแถวทุกครั้งที่ render
      opened: {},

      // จุดที่เห็นรายการถึงแล้ว — สำเนาของ users.last_seen_alert_id ฝั่ง browser
      _lastSeenId: null,

      _timers: {},
      _refreshTimer: null,

      // ตั้งชื่อ start ไม่ใช่ init เพราะ Alpine เรียก init() ของ store ให้เองอัตโนมัติ
      start() {
        this.loadOpened()
        this.syncReadState()
        this.refreshUnread()

        AlertStream.on('alert', (alert) => this.onAlert(alert))

        AlertStream.on('state', (state) => {
          // กลับมาต่อได้แล้ว = ช่วงที่หลุดอาจมี alert เข้ามา หรืออีกเครื่องอาจกดอ่านไปแล้ว
          if (state !== 'connected') return

          this.refreshUnread()
          this.syncReadState()
        })

        // ทำอะไรไปที่ tab อื่นแล้ว (localStorage แชร์กันทุก tab) tab นี้ต้องตามด้วย
        window.addEventListener('storage', (event) => {
          if (event.key === READ_KEY) this.refreshUnread()
          if (event.key === OPENED_KEY) this.loadOpened()
        })
      },

      // ─── "ยังไม่ได้เปิดดูรายละเอียด" รายตัว (จุดหน้าแถวในหน้า Alerts + Dashboard) ───

      loadOpened() {
        this.setOpened(readOpenedIds())
      },

      setOpened(ids) {
        var map = {}

        ids.forEach(function (id) {
          map[id] = 1
        })

        this.opened = map
      },

      // ตัดให้เหลือ id ใหม่สุด MAX_OPENED ตัว แล้วเก็บลงทั้ง store และ cache
      applyOpened(ids) {
        // id เรียงจากมากไปน้อย = ใหม่สุดอยู่ต้น ตัดท้ายทิ้งได้ตรง ๆ เวลาเกินเพดาน
        var unique = {}
        ids.forEach(function (id) { unique[id] = 1 })

        var trimmed = Object.keys(unique)
          .map(Number)
          .sort(function (a, b) { return b - a })
          .slice(0, MAX_OPENED)

        this.setOpened(trimmed)
        writeOpenedIds(trimmed)
      },

      isOpened(id) {
        return !!this.opened[id]
      },

      // ดึงรายการที่ "เปิดดูแล้ว" ของบัญชีนี้จาก server มาทับของในเครื่อง
      async syncReadState() {
        var cached = Object.keys(this.opened).map(Number)

        try {
          const res = await fetch(READ_STATE_URL, { cache: 'no-store' })
          if (!res.ok) return

          const data = await res.json()
          var serverIds = Array.isArray(data.opened_ids) ? data.opened_ids : []

          var onServer = {}
          serverIds.forEach(function (id) { onServer[id] = 1 })

          // id ที่เครื่องนี้เปิดไปแล้วแต่ server ไม่รู้ — POST ตอนนั้นพลาด หรือเป็นของที่ค้าง
          var missing = cached.filter(function (id) { return !onServer[id] })

          this.applyOpened(serverIds.concat(missing))

          if (missing.length) this.pushReadState({ opened_ids: missing })
        } catch (err) {
          // เงียบไว้ — cache ยังใช้ได้ ไว้รอบหน้าค่อยซิงค์ใหม่
        }
      },

      // ส่งสถานะขึ้น server — คืน true เมื่อ server รับไปแล้วจริง
      async pushReadState(payload) {
        try {
          const res = await fetch(READ_STATE_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
          })
          return res.ok
        } catch (err) {
          return false
        }
      },

      // หน้า Alerts เรียกตอนกดดูรายละเอียด (รวมถึงตอนเปิดจากลิงก์ ?focus= ด้วย)
      markOpened(id) {
        if (!id || this.opened[id]) return

        // อัปเดตหน้าจอ + cache ทันทีโดยไม่รอ server — ยิงพลาดก็แค่ค้างอยู่ใน cache แล้ว
        this.applyOpened(Object.keys(this.opened).map(Number).concat([id]))

        this.pushReadState({ opened_ids: [id] })
      },

      get isAlertsPage() {
        return document.body.dataset.page === 'alerts'
      },

      async refreshUnread() {
        try {
          const res = await fetch(UNREAD_COUNT_URL, { cache: 'no-store' })
          if (!res.ok) return

          const data = await res.json()

          // server เป็นตัวจริงเสมอ (รวมถึงเคสเข้าใช้ครั้งแรกที่ server ตั้งค่าเริ่มต้นให้เอง)
          this._lastSeenId = data.last_seen_id || 0

          this.unread = this.isAlertsPage ? 0 : (data.count || 0)
        } catch (err) {
          // เงียบไว้ — badge ไม่สำคัญพอจะรบกวนผู้ใช้ (ถ้า session ตาย session.js เด้งเอง)
        }
      },

      // หน้า Alerts เรียกเข้ามาเมื่อรายการถูกแสดงแล้ว
      markRead(id) {
        if (!id) return

        this.unread = 0

        // alert ที่ถูก merge แล้ว publish ซ้ำจะใช้ id เดิม (เก่ากว่า) — ห้ามให้ค่าถอยหลัง
        if (this._lastSeenId !== null && id <= this._lastSeenId) return

        // เลื่อนค่าใน memory ต่อเมื่อ server รับไปแล้วเท่านั้น — ถ้าเลื่อนไปก่อนแล้วยิงพลาด
        this.pushReadState({ last_seen_id: id }).then((ok) => {
          if (!ok) return

          this._lastSeenId = id
          setLastReadId(id)
        })
      },

      onAlert(alert) {
        this.pushToast(alert)

        if (this.isAlertsPage) {
          // อยู่หน้า Alerts อยู่แล้ว แถวใหม่เด้งขึ้นบนสุดให้เห็นทันที = ถือว่าอ่านแล้ว
          this.markRead(alert.id)
          return
        }

        // ไม่ +1 เองเพราะ alert เดิมที่ backend merge แล้ว publish ซ้ำจะใช้ id เดิม
        clearTimeout(this._refreshTimer)
        this._refreshTimer = setTimeout(() => this.refreshUnread(), REFRESH_DEBOUNCE_MS)
      },

      pushToast(alert) {
        var item = {
          id: alert.id,
          severity: alert.severity || 'LOW',
          attack_type: alert.attack_type || '-',
          source_ip: alert.source_ip || '-',
          hostname: alert.hostname || '-',
          fail_count: alert.fail_count,
          timestamp: alert.timestamp,
        }

        var existing = this.toasts.findIndex((t) => t.id === item.id)

        if (existing !== -1) {
          // เหตุการณ์เดิมที่ยิงต่อเนื่องแล้ว merge เข้าแถวเดิม -> อัปเดตใบเดิม ไม่ซ้อนใบใหม่
          this.toasts.splice(existing, 1, item)
        } else {
          this.toasts.unshift(item)

          while (this.toasts.length > MAX_TOASTS) {
            this.clearTimer(this.toasts.pop().id)
          }
        }

        this.startTimer(item.id)
      },

      startTimer(id) {
        this.clearTimer(id)
        this._timers[id] = setTimeout(() => this.dismiss(id), TOAST_TTL_MS)
      },

      clearTimer(id) {
        if (!this._timers[id]) return
        clearTimeout(this._timers[id])
        delete this._timers[id]
      },

      // ชี้เมาส์ค้างไว้แล้วยังไม่ให้หาย (กันอ่านไม่ทันตอนมาหลายใบพร้อมกัน)
      hold(id) {
        this.clearTimer(id)
      },

      release(id) {
        this.startTimer(id)
      },

      dismiss(id) {
        this.clearTimer(id)

        var index = this.toasts.findIndex((t) => t.id === id)
        if (index !== -1) this.toasts.splice(index, 1)
      },

      open(id) {
        window.location.href = window.APP_BASE + '/alerts?focus=' + id
      },
    })

    Alpine.store('alerts').start()
  })
})()
