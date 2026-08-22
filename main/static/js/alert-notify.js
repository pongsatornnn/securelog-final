// แจ้งเตือน alert ใหม่: popup มุมขวาล่าง + ตัวเลข "ยังไม่ได้อ่าน" ที่เมนู Alerts
//
// เก็บสถานะเป็น Alpine store ชื่อ 'alerts' เพราะ markup 2 จุดใน base.html (badge ใน sidebar
// กับกล่อง toast ที่อยู่นอก .layout) เป็น component แยกกัน แต่ต้องอ่านค่าชุดเดียวกัน
//
// "อ่านแล้ว" เก็บที่ server ผูกกับบัญชีผู้ใช้ (ตาราง alert_reads + users.last_seen_alert_id —
// ดู routes/alerts.py) เดิมเก็บใน localStorage อย่างเดียวจึงผูกกับ "เครื่อง" ไม่ใช่ "บัญชี":
// คนเดิม login จากอีกเครื่องเลยเห็นเป็นยังไม่ได้อ่านทั้งหมด
//
// localStorage ยังใช้อยู่แต่ลดบทบาทเหลือแค่ cache — โหลดหน้ามาแล้ววาดจุดได้ทันทีโดยไม่ต้องรอ
// server ตอบ (ไม่งั้นจุดจะขึ้นครบทุกแถวแล้วค่อยหายไป) จากนั้น syncReadState() เอาของจริงจาก
// server มาทับ พร้อมดัน id ที่เครื่องนี้เปิดไปแล้วแต่ server ยังไม่รู้ขึ้นไปให้ครบ
(function () {
  var READ_STATE_URL = '/api/alerts_read_state'
  var UNREAD_COUNT_URL = '/api/alerts_unread_count'

  // key ของ cache ใน localStorage — สองตัวนี้คนละความหมายกัน:
  //   READ_KEY   = เห็นรายการมาถึงไหนแล้ว  -> คุมตัวเลข badge ที่เมนู (เข้าหน้า Alerts = เคลียร์)
  //   OPENED_KEY = ตรวจสอบตัวไหนไปแล้วบ้าง -> คุมเครื่องหมาย "ยังไม่ได้อ่าน" ของแต่ละแถว
  //
  // READ_KEY เขียนอย่างเดียวไม่ได้อ่านกลับ (ตัวจริงมาจาก server ทุกครั้งที่โหลดหน้า) — เขียนไว้
  // เป็นสัญญาณให้แท็บอื่นในเครื่องเดียวกันรู้ผ่าน event 'storage' ว่าต้องเคลียร์ badge ตาม
  var READ_KEY = 'securelog.alerts.lastReadId'
  var OPENED_KEY = 'securelog.alerts.openedIds'
  var MAX_OPENED = 500             // เก็บเฉพาะ id ใหม่สุด กัน localStorage โตไม่จำกัด

  var TOAST_TTL_MS = 8000          // popup อยู่บนจอกี่ ms ก่อนหายเอง
  var MAX_TOASTS = 4               // เกินนี้ใบเก่าสุดหายไป กัน alert รัว ๆ ท่วมจอ
  var REFRESH_DEBOUNCE_MS = 400

  function setLastReadId(id) {
    try {
      window.localStorage.setItem(READ_KEY, String(id))
    } catch (err) {
      /* ไม่เป็นไร — server เป็นตัวจริงอยู่แล้ว แค่แท็บอื่นจะไม่รู้ตัวทันที */
    }
  }

  function readOpenedIds() {
    try {
      var raw = JSON.parse(window.localStorage.getItem(OPENED_KEY) || '[]')
      return Array.isArray(raw) ? raw : []
    } catch (err) {
      return []                          // ค่าเสีย/localStorage ใช้ไม่ได้ -> รอ server ตอบอย่างเดียว
    }
  }

  function writeOpenedIds(ids) {
    try {
      window.localStorage.setItem(OPENED_KEY, JSON.stringify(ids))
    } catch (err) {
      /* ไม่เป็นไร — server เป็นตัวจริง แค่รอบหน้าต้องรอ server ตอบก่อนจุดถึงหาย */
    }
  }

  document.addEventListener('alpine:init', function () {
    Alpine.store('alerts', {
      unread: 0,
      toasts: [],

      // map id -> 1 (ไม่ใช่ array) เพราะตารางเรียก isOpened() ทุกแถวทุกครั้งที่ render
      // เก็บใน store ให้เป็น reactive ด้วย พอ markOpened() แถวนั้นจะเปลี่ยนหน้าตาทันที
      opened: {},

      // จุดที่เห็นรายการถึงแล้ว — สำเนาของ users.last_seen_alert_id ฝั่ง browser
      // null = ยังไม่ได้ถาม server ในรอบโหลดหน้านี้
      _lastSeenId: null,

      _timers: {},        // id -> timeout ของ popup แต่ละใบ (ไม่ได้เอาไป render)
      _refreshTimer: null,

      // ตั้งชื่อ start ไม่ใช่ init เพราะ Alpine เรียก init() ของ store ให้เองอัตโนมัติ
      // จะกลายเป็นผูก listener ซ้ำสองรอบ
      start() {
        this.loadOpened()       // cache ก่อน -> จุดขึ้นถูกต้องทันทีไม่ต้องรอ server
        this.syncReadState()    // แล้วค่อยเอาของจริงจาก server มาทับ
        this.refreshUnread()

        AlertStream.on('alert', (alert) => this.onAlert(alert))

        AlertStream.on('state', (state) => {
          // กลับมาต่อได้แล้ว = ช่วงที่หลุดอาจมี alert เข้ามา หรืออีกเครื่องอาจกดอ่านไปแล้ว
          // -> ถามสถานะจริงจาก server ใหม่ทั้งคู่
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
          // มาจากตอนที่ยังเก็บใน localStorage อย่างเดียว -> ดันขึ้นไป ไม่งั้นเครื่องอื่นไม่มีวันเห็น
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
        // syncReadState() รอบหน้าดันขึ้นไปให้เอง
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
          // ถ้าค่าใน memory เคยเดินหน้าไปแล้วแต่ POST ตอนนั้นพลาด ค่าจะถูกดึงกลับมาตรงนี้
          // แล้ว markRead() ครั้งถัดไปยิงซ้ำให้เอง
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
        // ครั้งถัดไปจะติดเงื่อนไข "ห้ามถอยหลัง" ด้านบนจนไม่มีใครยิงซ้ำให้อีกเลย
        this.pushReadState({ last_seen_id: id }).then((ok) => {
          if (!ok) return

          this._lastSeenId = id
          setLastReadId(id)     // สัญญาณให้แท็บอื่นในเครื่องเดียวกันเคลียร์ badge ตาม
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
        // ถ้านับทุก event ตัวเลขจะเฟ้อกว่าความจริง — ถาม server เอาจำนวนจริงแทน
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
        window.location.href = '/alerts?focus=' + id
      },
    })

    Alpine.store('alerts').start()
  })
})()
