// helper ที่ทุกหน้าใช้ร่วมกัน — เดิมเขียนซ้ำอยู่ใน <script> ของแต่ละ template
(function () {
  // แสดงเวลาเป็นโซนไทยแบบ ค.ศ. (ไม่ใช่ พ.ศ.) — ts ว่าง/null คืน '-'
  window.formatTime = function (ts) {
    if (!ts) return '-'
    return new Date(ts).toLocaleString('th-TH-u-ca-gregory', {
      hour12: false,
      timeZone: 'Asia/Bangkok'
    })
  }

  // IPv4 แบบ 4 octet 0-255 และไม่ยอมรับเลข 0 นำหน้า (01.2.3.4)
  var IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

  window.isValidIPv4 = function (value) {
    return IPV4.test(String(value == null ? '' : value).trim())
  }

  // address พิเศษของทราฟฟิก broadcast — ไม่ใช่เครื่องจริง บล็อกไปก็ไม่มีผล
  var NON_BLOCKABLE_IPS = ['0.0.0.0', '255.255.255.255']

  window.isBlockableIPv4 = function (value) {
    var ip = String(value == null ? '' : value).trim()
    return isValidIPv4(ip) && NON_BLOCKABLE_IPS.indexOf(ip) === -1
  }

  // กันพิมพ์ตัวอักษรอื่นในช่อง IP (เหลือแต่ตัวเลขกับจุด)
  window.normalizeIpInput = function (value) {
    return String(value == null ? '' : value).replace(/[^0-9.]/g, '')
  }

  // ─────────────────────────────────────────────────────────────

  var PERMANENT = 'permanent'

  var UNIT_SECONDS = {
    minutes: 60,
    hours: 3600,
    days: 86400,
  }

  // เพดานเดียวกับ MAX_TTL_SECONDS ฝั่ง Python (blacklist_policy.py) = 10 ปี
  var MAX_DURATION_SECONDS = 10 * 365 * 24 * 3600

  window.PERMANENT_DURATION_UNIT = PERMANENT
  window.MAX_DURATION_SECONDS = MAX_DURATION_SECONDS

  window.newDuration = function (unit, amount) {
    return { amount: amount == null ? 1 : amount, unit: unit || PERMANENT }
  }

  window.isPermanentDuration = function (duration) {
    return !duration || duration.unit === PERMANENT
  }

  // คืนวินาที หรือ null = ถาวร — เรียกได้ก็ต่อเมื่อ isValidDuration() ผ่านแล้ว
  window.durationSeconds = function (duration) {
    if (isPermanentDuration(duration)) return null
    return Number(duration.amount) * (UNIT_SECONDS[duration.unit] || 0)
  }

  window.isValidDuration = function (duration) {
    if (isPermanentDuration(duration)) return true

    var per = UNIT_SECONDS[duration.unit]
    if (!per) return false

    var amount = Number(duration.amount)
    return Number.isInteger(amount) && amount >= 1 && amount * per <= MAX_DURATION_SECONDS
  }

  // วินาที -> ตัวเลข+หน่วยที่คนกรอก (ใช้ตอนเปิดฟอร์มมาแก้ค่าที่บันทึกไว้แล้ว)
  window.durationFromSeconds = function (seconds) {
    if (seconds === null || seconds === undefined) return newDuration(PERMANENT)
    if (seconds % 86400 === 0) return newDuration('days', seconds / 86400)
    if (seconds % 3600 === 0) return newDuration('hours', seconds / 3600)
    return newDuration('minutes', Math.max(1, Math.round(seconds / 60)))
  }

  window.formatDuration = function (seconds) {
    if (seconds === null || seconds === undefined) return 'ถาวร (ไม่หมดอายุ)'
    if (seconds % 86400 === 0) return (seconds / 86400) + ' วัน'
    if (seconds % 3600 === 0) return (seconds / 3600) + ' ชั่วโมง'
    if (seconds % 60 === 0) return (seconds / 60) + ' นาที'
    return seconds + ' วินาที'
  }

  // บรรทัดสรุปใต้ช่องกรอก — บอกเป็นวันเวลาจริงว่าบล็อกถึงเมื่อไร
  window.durationExpiryText = function (duration) {
    if (isPermanentDuration(duration)) return 'บล็อกถาวร จนกว่าจะกดปลดบล็อกเอง'
    if (!isValidDuration(duration)) return ''

    var seconds = durationSeconds(duration)
    var until = new Date(Date.now() + seconds * 1000)

    return 'บล็อก ' + formatDuration(seconds) + ' · ปลดบล็อกอัตโนมัติประมาณ ' + formatTime(until.toISOString())
  }
})()
