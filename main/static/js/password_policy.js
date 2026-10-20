

window.PasswordPolicy = {
  loaded: false,
  rules: [],
  minLength: 8,

  async load() {
    if (this.loaded) return this
    try {
      const res = await fetch(window.APP_BASE + '/api/password-policy')
      if (!res.ok) throw new Error('โหลดนโยบายรหัสผ่านไม่สำเร็จ')
      const data = await res.json()
      this.rules = data.rules || []
      this.minLength = data.min_length || 8
      this.loaded = true
    } catch (e) {

      this.loaded = false
    }
    return this
  },

  testRule(rule, password) {
    switch (rule.kind) {
      case 'length':
        return password.length >= rule.min && password.length <= rule.max
      case 'regex':
        return new RegExp(rule.pattern).test(password)
      default:
        return true
    }
  },


  check(password) {
    const pw = password || ''
    return this.rules.map(r => ({ id: r.id, label: r.label, passed: this.testRule(r, pw) }))
  },

  allPassed(password) {
    const list = this.check(password)
    return list.length > 0 && list.every(r => r.passed)
  },
}
