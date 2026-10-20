
(function () {
  var BASE = window.APP_BASE || ''
  var READ_STATE_URL = BASE + '/api/alerts_read_state'
  var UNREAD_COUNT_URL = BASE + '/api/alerts_unread_count'


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


      opened: {},


      _lastSeenId: null,

      _timers: {},
      _refreshTimer: null,


      allRead: document.body.dataset.allRead === '1',


      start() {
        this.loadOpened()
        this.syncReadState()
        this.refreshUnread()

        AlertStream.on('alert', (alert) => this.onAlert(alert))

        AlertStream.on('state', (state) => {

          if (state !== 'connected') return

          this.refreshUnread()
          this.syncReadState()
        })


        window.addEventListener('storage', (event) => {
          if (event.key === READ_KEY) this.refreshUnread()
          if (event.key === OPENED_KEY) this.loadOpened()
        })
      },


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


      applyOpened(ids) {

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
        return this.allRead || !!this.opened[id]
      },


      async syncReadState() {
        var cached = Object.keys(this.opened).map(Number)

        try {
          const res = await fetch(READ_STATE_URL, { cache: 'no-store' })
          if (!res.ok) return

          const data = await res.json()
          if (data.all_read) {
            this.allRead = true
            return
          }
          var serverIds = Array.isArray(data.opened_ids) ? data.opened_ids : []

          var onServer = {}
          serverIds.forEach(function (id) { onServer[id] = 1 })


          var missing = cached.filter(function (id) { return !onServer[id] })

          this.applyOpened(serverIds.concat(missing))

          if (missing.length) this.pushReadState({ opened_ids: missing })
        } catch (err) {

        }
      },


      async pushReadState(payload) {
        if (this.allRead) return true  // บัญชี View ไม่บันทึกสถานะอ่านแล้ว
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


      markOpened(id) {
        if (!id || this.allRead || this.opened[id]) return


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
          if (data.all_read) this.allRead = true


          this._lastSeenId = data.last_seen_id || 0

          this.unread = (this.isAlertsPage || this.allRead) ? 0 : (data.count || 0)
        } catch (err) {

        }
      },


      markRead(id) {
        if (!id) return

        this.unread = 0
        if (this.allRead) return


        if (this._lastSeenId !== null && id <= this._lastSeenId) return


        this.pushReadState({ last_seen_id: id }).then((ok) => {
          if (!ok) return

          this._lastSeenId = id
          setLastReadId(id)
        })
      },

      onAlert(alert) {
        this.pushToast(alert)

        if (this.isAlertsPage) {

          this.markRead(alert.id)
          return
        }


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
