// UI กลางที่ทุกหน้าใช้ร่วมกัน — 3 เรื่องที่เดิมเป็นกล่องของเบราว์เซอร์หรือไม่มีเลย:
//
//   1. $store.ui.confirm(...)  แทน window.confirm()  -> กล่องยืนยันในหน้าเว็บ (คืน Promise)
//   2. $store.ui.notify(...)   แทน window.alert()    -> แถบแจ้งผลมุมขวาล่าง หายเอง
//   3. a11y ของ modal ทุกหน้า                        -> role/aria, focus trap, Escape
//
// ข้อ 3 ทำแบบ "จับจาก DOM" ไม่ใช่แก้ markup ทีละ modal เพราะทุกหน้าใช้โครงเดียวกัน
// (.modal-backdrop > .modal) อยู่แล้ว — เพิ่มหน้าใหม่ก็ได้พฤติกรรมนี้ฟรีโดยไม่ต้องจำ
//
// โหลดก่อน alpine.min.js (ที่เป็น defer) เพราะต้องผูก event 'alpine:init' ให้ทัน
(function () {
  var NOTIFY_TTL_MS = 5000        // แถบแจ้งผลอยู่บนจอกี่ ms ก่อนหายเอง
  var NOTIFY_TTL_ERROR_MS = 8000  // ข้อความ error ให้เวลาอ่านนานกว่า
  var MAX_NOTIFY = 3              // เกินนี้ใบเก่าสุดหายไป

  var noticeSeq = 0

  // ─────────────────────────────────────────────────────────────
  // Alpine store
  // ─────────────────────────────────────────────────────────────

  document.addEventListener('alpine:init', function () {
    Alpine.store('ui', {
      // กล่องยืนยันมีได้ทีละใบ (ทุกหน้าใช้ markup ชุดเดียวใน base.html) — ถ้ามีการเรียกซ้อน
      // ใบเก่าจะถูกตอบ false ทิ้งไปก่อน ดู confirm() ด้านล่าง
      dialog: {
        open: false,
        title: '',
        message: '',
        detail: '',
        confirmText: 'ยืนยัน',
        cancelText: 'ยกเลิก',
        danger: false,
        busy: false,
      },

      notices: [],

      _resolve: null,
      _timers: {},

      // ─── กล่องยืนยัน ───

      // ใช้แทน confirm(): `if (!await $store.ui.confirm({...})) return`
      //
      //   title       หัวข้อ (บังคับ)
      //   message     คำอธิบายบรรทัดหลัก
      //   detail      ข้อมูลประกอบ เช่น IP/agent id — แสดงเป็นบล็อก monospace
      //   danger      true = ปุ่มยืนยันเป็นสีแดง (ใช้กับการลบ/ปลดบล็อก)
      confirm(options) {
        var opts = options || {}

        // เรียกซ้อนตอนใบเก่ายังเปิดอยู่: ปิดใบเก่าแบบ "ไม่ยืนยัน" ไม่ทิ้ง Promise ค้าง
        this._settle(false)

        this.dialog.title       = opts.title || 'ยืนยันการทำรายการ'
        this.dialog.message     = opts.message || ''
        this.dialog.detail      = opts.detail || ''
        this.dialog.confirmText = opts.confirmText || 'ยืนยัน'
        this.dialog.cancelText  = opts.cancelText || 'ยกเลิก'
        this.dialog.danger      = !!opts.danger
        this.dialog.busy        = false
        this.dialog.open        = true

        return new Promise((resolve) => {
          this._resolve = resolve
        })
      },

      accept() {
        this._settle(true)
      },

      cancel() {
        this._settle(false)
      },

      _settle(answer) {
        var resolve = this._resolve

        this._resolve    = null
        this.dialog.open = false

        if (resolve) resolve(answer)
      },

      // ─── แถบแจ้งผล ───

      // ใช้แทน alert(): $store.ui.notify('ลบไม่สำเร็จ', 'error')
      // kind: 'success' | 'error' | 'info'
      notify(message, kind) {
        if (!message) return

        var item = {
          id: ++noticeSeq,
          kind: kind || 'info',
          message: String(message),
        }

        this.notices.unshift(item)

        while (this.notices.length > MAX_NOTIFY) {
          this._clearTimer(this.notices.pop().id)
        }

        this._startTimer(item.id, item.kind === 'error' ? NOTIFY_TTL_ERROR_MS : NOTIFY_TTL_MS)
      },

      success(message) {
        this.notify(message, 'success')
      },

      error(message) {
        this.notify(message, 'error')
      },

      _startTimer(id, ttl) {
        this._clearTimer(id)
        this._timers[id] = setTimeout(() => this.dismiss(id), ttl)
      },

      _clearTimer(id) {
        if (!this._timers[id]) return
        clearTimeout(this._timers[id])
        delete this._timers[id]
      },

      // ชี้เมาส์ค้าง = ยังไม่ให้หาย (เหมือน toast ของ alert)
      hold(id) {
        this._clearTimer(id)
      },

      release(id) {
        this._startTimer(id, NOTIFY_TTL_MS)
      },

      dismiss(id) {
        this._clearTimer(id)

        var index = this.notices.findIndex((n) => n.id === id)
        if (index !== -1) this.notices.splice(index, 1)
      },
    })
  })

  // ─────────────────────────────────────────────────────────────
  // a11y ของ modal ทุกหน้า
  //
  // ทุก modal ในโปรเจกต์เป็น `.modal-backdrop` ที่ซ่อน/แสดงด้วย x-show (Alpine เขียน
  // display:none ลง inline style) — เลยเฝ้าดู attribute `style` แล้วเทียบสถานะเอา
  // ไม่ต้องให้แต่ละหน้ามาเรียกอะไรเพิ่ม
  // ─────────────────────────────────────────────────────────────

  var FOCUSABLE = [
    'a[href]', 'button:not([disabled])', 'input:not([disabled])',
    'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
  ].join(',')

  var openBackdrops = []     // เรียงตามลำดับที่เปิด — ใบท้ายสุด = ใบที่อยู่บนสุด
  var lastFocused = null     // element ที่โฟกัสอยู่ก่อนเปิด modal ใบแรก

  function isShown(el) {
    return window.getComputedStyle(el).display !== 'none'
  }

  function focusableIn(el) {
    return Array.prototype.filter.call(
      el.querySelectorAll(FOCUSABLE),
      function (node) {
        return node.offsetWidth > 0 || node.offsetHeight > 0 || node === document.activeElement
      }
    )
  }

  function onOpen(backdrop) {
    var panel = backdrop.querySelector('.modal')
    if (!panel) return

    if (openBackdrops.length === 0) lastFocused = document.activeElement

    openBackdrops.push(backdrop)

    panel.setAttribute('role', 'dialog')
    panel.setAttribute('aria-modal', 'true')

    // ผูกหัวข้อ modal เข้ากับกล่องเพื่อให้ screen reader อ่านชื่อ modal ตอนเปิด
    var title = panel.querySelector('.modal-title')
    if (title) {
      if (!title.id) title.id = 'modal-title-' + (++noticeSeq)
      panel.setAttribute('aria-labelledby', title.id)
    }

    // โฟกัสตัวแรกที่กดได้ในกล่อง — ถ้าไม่มีเลย โฟกัสตัวกล่องเองไว้ก่อน (กันโฟกัสค้าง
    // อยู่ข้างหลัง backdrop แล้วผู้ใช้แป้นพิมพ์หลงไปกดของที่มองไม่เห็น)
    var targets = focusableIn(panel)

    if (targets.length) {
      targets[0].focus()
    } else {
      panel.setAttribute('tabindex', '-1')
      panel.focus()
    }
  }

  function onClose(backdrop) {
    var index = openBackdrops.indexOf(backdrop)
    if (index !== -1) openBackdrops.splice(index, 1)

    // คืนโฟกัสให้ปุ่มที่กดเปิด modal เฉพาะตอนปิดใบสุดท้ายจริง ๆ
    if (openBackdrops.length === 0 && lastFocused && document.contains(lastFocused)) {
      lastFocused.focus()
      lastFocused = null
    }
  }

  function sync() {
    var all = document.querySelectorAll('.modal-backdrop')

    Array.prototype.forEach.call(all, function (backdrop) {
      var shown  = isShown(backdrop)
      var wasOpen = openBackdrops.indexOf(backdrop) !== -1

      if (shown && !wasOpen) onOpen(backdrop)
      if (!shown && wasOpen) onClose(backdrop)
    })
  }

  function topBackdrop() {
    return openBackdrops.length ? openBackdrops[openBackdrops.length - 1] : null
  }

  document.addEventListener('keydown', function (event) {
    var backdrop = topBackdrop()
    if (!backdrop) return

    // Escape: หน้าที่เขียน @keydown.escape.window ไว้เองแล้วปล่อยให้ Alpine จัดการต่อ
    // ไม่งั้นยิง click ที่ backdrop ให้ @click.self ของหน้านั้นทำงาน (click() ตั้ง target
    // เป็นตัว backdrop เอง ตรงเงื่อนไขของ .self พอดี)
    if (event.key === 'Escape') {
      if (!backdrop.hasAttribute('@keydown.escape.window')) backdrop.click()
      return
    }

    if (event.key !== 'Tab') return

    var panel = backdrop.querySelector('.modal')
    if (!panel) return

    var targets = focusableIn(panel)
    if (!targets.length) return

    var first = targets[0]
    var last  = targets[targets.length - 1]

    // วนกลับหัวท้ายแทนที่จะหลุดออกไปข้างหลัง backdrop
    if (event.shiftKey && (document.activeElement === first || !panel.contains(document.activeElement))) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  })

  // ─────────────────────────────────────────────────────────────
  // ผูก <label class="form-label"> เข้ากับช่องกรอกที่มันอธิบาย
  //
  // ทุกฟอร์มเขียนเป็น `<label class="form-label">ชื่อ</label>` ตามด้วย `.form-input`
  // แยกกันอยู่ (ไม่ได้ครอบ input ไว้ และไม่มี for=) — คลิกที่ป้ายจึงไม่โฟกัสช่อง และ
  // screen reader ก็ไม่รู้ว่าป้ายไหนคู่กับช่องไหน ทำตรงนี้ทีเดียวแทนการไล่ใส่ id ทุกหน้า
  //
  // ตัวที่เป็น <div class="form-label"> ไม่ถูกแตะ เพราะนั่นคือหัวคอลัมน์ของแถวซ้ำ ๆ
  // (bulk row) ไม่ใช่ป้ายของช่องใดช่องหนึ่ง
  // ─────────────────────────────────────────────────────────────

  var labelSeq = 0

  function linkFormLabels(root) {
    var labels = (root || document).querySelectorAll('label.form-label:not([for])')

    Array.prototype.forEach.call(labels, function (label) {
      var field = label.parentElement && label.parentElement.querySelector('.form-input')
      if (!field) return

      // ช่องเดียวกันอาจถูกจับคู่ไปแล้วจากรอบก่อน (MutationObserver เรียกซ้ำได้)
      if (field.id && document.querySelector('label[for="' + field.id + '"]')) return

      if (!field.id) field.id = 'field-' + (++labelSeq)
      label.setAttribute('for', field.id)
    })
  }

  document.addEventListener('DOMContentLoaded', function () {
    sync()
    linkFormLabels()

    // x-show เปลี่ยนแค่ inline style ไม่ได้เพิ่ม/ลบ node — ดู attribute อย่างเดียวพอ
    // ส่วน childList เผื่อ modal/ฟอร์มที่ถูก render ทีหลัง (เช่นอยู่ใน template x-if/x-for)
    new MutationObserver(function () {
      sync()
      linkFormLabels()
    }).observe(document.body, {
      subtree: true,
      childList: true,
      attributes: true,
      attributeFilter: ['style', 'class'],
    })
  })
})()
