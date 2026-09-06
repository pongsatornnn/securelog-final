// ตรวจรหัสผ่านด้วย "กฎชุดเดียวกับฝั่ง server" — ดึงกฎมาจาก /api/password-policy ตอนเปิดหน้า
// (นิยามกฎอยู่ที่ main/password_policy.py ที่เดียว ที่นี่แค่ประเมินตามชนิดของกฎ)
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
      // โหลดไม่ได้ = ไม่แสดง checklist แต่ฝั่ง server ยังบังคับอยู่เหมือนเดิม
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

  // คืนสถานะทุกข้อไว้ให้หน้าเว็บ render เป็น checklist
  check(password) {
    const pw = password || ''
    return this.rules.map(r => ({ id: r.id, label: r.label, passed: this.testRule(r, pw) }))
  },

  allPassed(password) {
    const list = this.check(password)
    return list.length > 0 && list.every(r => r.passed)
  },
}
