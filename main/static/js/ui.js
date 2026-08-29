// UI กลางที่ทุกหน้าใช้ร่วมกัน — 3 เรื่องที่เดิมเป็นกล่องของเบราว์เซอร์หรือไม่มีเลย:
(function () {
  var NOTIFY_TTL_MS = 5000
  var NOTIFY_TTL_ERROR_MS = 8000
  var MAX_NOTIFY = 3

  var noticeSeq = 0

  // ─────────────────────────────────────────────────────────────

  document.addEventListener('alpine:init', function () {
    Alpine.store('ui', {
      // กล่องยืนยันมีได้ทีละใบ (ทุกหน้าใช้ markup ชุดเดียวใน base.html) — ถ้ามีการเรียกซ้อน
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

  var FOCUSABLE = [
    'a[href]', 'button:not([disabled])', 'input:not([disabled])',
    'select:not([disabled])', 'textarea:not([disabled])', '[tabindex]:not([tabindex="-1"])',
  ].join(',')

  var openBackdrops = []
  var lastFocused = null

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
