// SSE เส้นเดียวของ alert ที่ทุกหน้าใช้ร่วมกัน (โหลดจาก base.html)
//
// เดิม EventSource ถูกสร้างใน alerts.html หน้าเดียว = ได้รู้ว่ามี alert ใหม่เฉพาะตอนเปิดหน้านั้น
// ค้างไว้เท่านั้น ย้ายมาไว้ที่นี่เพื่อให้แจ้งเตือน (popup + badge) ทำงานได้ทุกหน้า
//
// ใครอยากใช้: AlertStream.on('alert', fn) รับ alert ใหม่ / AlertStream.on('state', fn) รับ
// สถานะการเชื่อมต่อ ('connecting' | 'connected' | 'disconnected') — ห้ามสร้าง EventSource
// เองเพิ่ม เพราะ 1 connection = 1 Redis pubsub ฝั่ง server (ดู routes/alerts.py)
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
    if (source) return          // มีเส้นอยู่แล้ว ห้ามเปิดซ้อน (กันเปิดซ้ำตอนถูกปลุกจาก bfcache)

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
  // ถ้า session หมดอายุ /api/stream/alerts จะตอบ 303 ไป /login ซึ่งไม่ใช่ text/event-stream
  // EventSource เลย fail ถาวร แล้วโค้ด reconnect จะวนไม่รู้จบโดยผู้ใช้ไม่รู้ตัวว่าหลุด login
  //
  // จึงยิง fetch เบา ๆ นำก่อนต่อใหม่ทุกครั้ง: session ตาย -> session.js เด้งไป /login เอง
  // แล้ว promise ค้างไว้ (ไม่ต่อใหม่) / เน็ตล่ม -> reject แล้วลองใหม่ / ปกติ -> ต่อ SSE ใหม่
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
      source.onerror = null     // ปิดเอง ไม่ใช่หลุด — ห้ามให้ onerror ไปตั้ง reconnect ต่อ
      source.close()
      source = null
    }

    setState('disconnected')
  }

  // ─── วงจรชีวิตของ connection ───
  //
  // ต้องปิดเส้นนี้ให้ขาดจริงตอนออกจากหน้า ไม่งั้นเจอบั๊กนี้: เบราว์เซอร์เก็บหน้าเก่าไว้ใน
  // bfcache (เพื่อให้กด back กลับมาได้ทันที) โดย**ไม่ปิด connection ที่ค้างอยู่** พอไล่เปิด
  // หลายหน้าติดกัน SSE ของหน้าเก่าจะค้างสะสมจนครบ 6 เส้น = เพดาน connection ต่อโฮสต์ของ
  // HTTP/1.1 พอดี → fetch อื่นทั้งหมด (เช่น /api/agents ที่หน้า Agents poll ทุก 3 วิ) ไม่มี
  // ช่องเหลือ ต้องรอคิวเป็นนาที หน้าเว็บเลยดูเหมือนค้าง แล้วยิงทะลักออกมาทีเดียวตอน slot ว่าง
  //
  // pagehide ครอบทั้งการปิดแท็บ, เปลี่ยนหน้า และการถูกแช่เข้า bfcache (unload ใช้ไม่ได้:
  // หน้าที่ผูก unload จะไม่เข้า bfcache และบางเบราว์เซอร์เลิกรองรับแล้ว)
  window.addEventListener('pagehide', stop)

  // ถูกปลุกกลับจาก bfcache (กด back/forward) = หน้าเดิมถูกใช้ต่อทั้งที่เราปิดเส้นไปแล้ว
  // ต้องต่อใหม่ ไม่งั้นหน้านั้นจะเงียบไปเลยทั้งที่ดูเหมือนใช้งานได้ปกติ
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
