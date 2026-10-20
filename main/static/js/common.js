
(function () {

  window.formatTime = function (ts) {
    if (!ts) return '-'
    return new Date(ts).toLocaleString('th-TH-u-ca-gregory', {
      hour12: false,
      timeZone: 'Asia/Bangkok'
    })
  }


  window.flagUrl = function (country) {
    var name = country && country.code ? String(country.code).toLowerCase() : '_lan'
    return window.APP_BASE + '/static/flags/' + name + '.svg'
  }


  var IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

  window.isValidIPv4 = function (value) {
    return IPV4.test(String(value == null ? '' : value).trim())
  }


  var IPV4_CIDR = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\/(3[0-2]|[12]\d|\d)$/

  window.isValidIPv4Cidr = function (value) {
    return IPV4_CIDR.test(String(value == null ? '' : value).trim())
  }


  window.isValidIpOrCidr = function (value) {
    var v = String(value == null ? '' : value).trim()
    return isValidIPv4(v) || isValidIPv4Cidr(v)
  }


  window.MIN_WHITELIST_PREFIXLEN = 8


  window.isTooBroadCidr = function (value) {
    var v = String(value == null ? '' : value).trim()

    if (!isValidIPv4Cidr(v)) return false

    return parseInt(v.split('/')[1], 10) < MIN_WHITELIST_PREFIXLEN
  }


  window.isAllowedWhitelistEntry = function (value) {
    return isValidIpOrCidr(value) && !isTooBroadCidr(value)
  }


  window.cidrHostCount = function (value) {
    var v = String(value == null ? '' : value).trim()

    if (!isValidIPv4Cidr(v)) return isValidIPv4(v) ? 1 : 0

    var prefix = parseInt(v.split('/')[1], 10)
    var total = Math.pow(2, 32 - prefix)

    return prefix <= 30 ? total - 2 : total
  }


  var NON_BLOCKABLE_IPS = ['0.0.0.0', '255.255.255.255']

  window.isBlockableIPv4 = function (value) {
    var ip = String(value == null ? '' : value).trim()
    return isValidIPv4(ip) && NON_BLOCKABLE_IPS.indexOf(ip) === -1
  }


  window.normalizeIpInput = function (value) {
    return String(value == null ? '' : value).replace(/[^0-9.]/g, '')
  }


  window.normalizeIpCidrInput = function (value) {
    return String(value == null ? '' : value).replace(/[^0-9./]/g, '')
  }


  var PERMANENT = 'permanent'

  var UNIT_SECONDS = {
    minutes: 60,
    hours: 3600,
    days: 86400,
  }


  var MAX_DURATION_SECONDS = 10 * 365 * 24 * 3600

  window.PERMANENT_DURATION_UNIT = PERMANENT
  window.MAX_DURATION_SECONDS = MAX_DURATION_SECONDS

  window.newDuration = function (unit, amount) {
    return { amount: amount == null ? 1 : amount, unit: unit || PERMANENT }
  }

  window.isPermanentDuration = function (duration) {
    return !duration || duration.unit === PERMANENT
  }


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


  window.durationExpiryText = function (duration) {
    if (isPermanentDuration(duration)) return 'บล็อกถาวร จนกว่าจะกดปลดบล็อกเอง'
    if (!isValidDuration(duration)) return ''

    var seconds = durationSeconds(duration)
    var until = new Date(Date.now() + seconds * 1000)

    return 'บล็อก ' + formatDuration(seconds) + ' · ปลดบล็อกอัตโนมัติประมาณ ' + formatTime(until.toISOString())
  }
})()
