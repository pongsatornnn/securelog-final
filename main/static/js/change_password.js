// ย้ายมาจาก templates/change_password.html (บล็อก <script> เดิม)
function changePasswordApp() {
  return {
    newPassword: '',
    confirmPassword: '',
    loading: false,
    error: '',
    shaking: false,
    policyReady: false,

    async init() {
      await window.PasswordPolicy.load()
      this.policyReady = window.PasswordPolicy.loaded
    },

    // checklist สด ๆ ตามที่พิมพ์ — กฎมาจาก server ชุดเดียวกับที่ server บังคับ
    passwordChecks() {
      if (!this.policyReady) return []
      return window.PasswordPolicy.check(this.newPassword)
    },

    policyOk() {
      const checks = this.passwordChecks()
      return checks.length > 0 && checks.every(c => c.passed)
    },

    canSubmit() {
      return this.policyOk() && this.newPassword === this.confirmPassword
    },

    async submit() {
      if (this.loading) return

      if (!this.newPassword || !this.confirmPassword) {
        this.setError('กรุณากรอกข้อมูลให้ครบ')
        return
      }
      if (!this.policyOk()) {
        const bad = this.passwordChecks().filter(c => !c.passed).map(c => c.label)
        this.setError('รหัสผ่านยังไม่ผ่านนโยบาย: ' + bad.join(' · '))
        return
      }
      if (this.newPassword !== this.confirmPassword) {
        this.setError('ยืนยันรหัสผ่านใหม่ไม่ตรงกัน')
        return
      }

      this.loading = true
      this.error = ''

      try {
        const res = await fetch(window.APP_BASE + '/api/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            new_password: this.newPassword,
          }),
        })

        const data = await res.json()

        if (res.status === 429) throw new Error('ลองใหม่อีกครั้งในภายหลัง')
        if (!res.ok) throw new Error(data.detail || 'เปลี่ยนรหัสผ่านไม่สำเร็จ')

        window.location.href = window.APP_BASE + '/dashboard'

      } catch (err) {
        this.setError(err.message)
      } finally {
        this.loading = false
      }
    },

    async logout() {
      await fetch(window.APP_BASE + '/api/logout', { method: 'POST' })
      window.location.href = window.APP_BASE + '/login'
    },

    setError(msg) {
      this.error = msg
      this.shaking = true
      setTimeout(() => this.shaking = false, 350)
    }
  }
}
