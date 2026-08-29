// SSE เส้นเดียวของ alert ที่ทุกหน้าใช้ร่วมกัน (โหลดจาก base.html)
window.AlertStream = (function () {
  var BASE_RETRY_MS = 3000
  var MAX_RETRY_MS = 30000

  var listeners = { alert: [], state: [] }
  var state = 'connecting'
  var source = null
  var retryTimer = null
  var retryMs = BASE_RETRY_MS

  function emit(type, payload) {
    var fns = listeners[type]

    for (var i = 0; i < fns.length; i++) {
      // listener ตัวหนึ่งพังต้องไม่ทำให้ตัวที่เหลือไม่ได้รับ event
      try {
        fns[i](payload)
      } catch (err) {
        console.error('[AlertStream] listener error', err)
      }
    }
  }

  function setState(next) {
    if (state === next) return
    state = next
    emit('state', next)
  }

  function connect() {
    if (source) return

    setState('connecting')

    source = new EventSource('/api/stream/alerts')

    source.onopen = function () {
      retryMs = BASE_RETRY_MS
      setState('connected')
    }

    source.onmessage = function (event) {
      var alert

      try {
        alert = JSON.parse(event.data)
      } catch (err) {
        console.error('[AlertStream] payload ไม่ใช่ JSON', err)
        return
      }

      emit('alert', alert)
    }

    source.onerror = function () {
      setState('disconnected')
      source.close()
      source = null

      clearTimeout(retryTimer)
      retryTimer = setTimeout(probeThenReconnect, retryMs)

      // ถ้า server ล่ม/Redis ล่ม จะ error ทันทีทุกครั้งที่ต่อ — ถอยห่างขึ้นเรื่อย ๆ ไม่ยิงรัว
      retryMs = Math.min(retryMs * 2, MAX_RETRY_MS)
    }
  }

  // EventSource ไม่ได้วิ่งผ่าน window.fetch จึงไม่โดน session guard (static/session.js)
  function probeThenReconnect() {
    fetch('/api/alerts_unread_count', { cache: 'no-store' })
      .then(function () {
        connect()
      })
      .catch(function () {
        retryTimer = setTimeout(probeThenReconnect, retryMs)
        retryMs = Math.min(retryMs * 2, MAX_RETRY_MS)
      })
  }

  function stop() {
    clearTimeout(retryTimer)

    if (source) {
      source.onerror = null
      source.close()
      source = null
    }

    setState('disconnected')
  }

  // ─── วงจรชีวิตของ connection ───
  window.addEventListener('pagehide', stop)

  // ถูกปลุกกลับจาก bfcache (กด back/forward) = หน้าเดิมถูกใช้ต่อทั้งที่เราปิดเส้นไปแล้ว
  window.addEventListener('pageshow', function (event) {
    if (event.persisted) connect()
  })

  connect()

  return {
    on: function (type, fn) {
      if (listeners[type]) listeners[type].push(fn)
    },

    state: function () {
      return state
    }
  }
})()
