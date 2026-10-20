
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

    source = new EventSource(window.APP_BASE + '/api/stream/alerts')

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


      retryMs = Math.min(retryMs * 2, MAX_RETRY_MS)
    }
  }


  function probeThenReconnect() {
    fetch(window.APP_BASE + '/api/alerts_unread_count', { cache: 'no-store' })
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


  window.addEventListener('pagehide', stop)


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
