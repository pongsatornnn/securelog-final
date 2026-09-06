// ย้ายมาจาก templates/profile.html (บล็อก <script> เดิม)
// ค่าที่มาจาก server อ่านผ่าน window.PAGE_DATA ที่ template ประกาศไว้
function profileApp() {
  return {
    username: window.PAGE_DATA.username,
    name: window.PAGE_DATA.name,
    savedName: window.PAGE_DATA.name,
    savingName: false,
    nameError: '',
    nameSuccess: false,

    showPwModal: false,
    pwLoading: false,
    pwError: '',
    pwSuccess: false,
    pw: { current: '', next: '', confirm: '' },
    policyReady: false,

    // ตัวอักษรแรกของชื่อที่แสดง (ไม่มีชื่อก็ใช้ username) สำหรับวงกลม avatar
    initial() {
      return (this.savedName || this.username || '?').trim().charAt(0)
    },

    canSaveName() {
      return this.name.trim().length >= 1 && this.name.trim() !== this.savedName
    },

    async saveName() {
      if (this.savingName || !this.canSaveName()) return

      this.nameError = ''
      this.nameSuccess = false
      this.savingName = true

      try {
        const res = await fetch(window.APP_BASE + '/api/profile/name', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ name: this.name.trim() }),
        })

        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'บันทึกชื่อไม่สำเร็จ')

        this.savedName = data.name
        this.name = data.name
        this.nameSuccess = true
        // อัปเดตคำทักทาย "Hello <name>" มุมขวาบนทันที ไม่ต้องรอเปลี่ยนหน้า
        const greet = document.getElementById('topbarName')
        if (greet) greet.textContent = data.name
        setTimeout(() => this.nameSuccess = false, 2500)
      } catch (err) {
        this.nameError = err.message
      } finally {
        this.savingName = false
      }
    },

    openPwModal() {
      this.pw = { current: '', next: '', confirm: '' }
      this.pwError = ''
      this.pwSuccess = false
      this.showPwModal = true
    },

    closePwModal() {
      if (this.pwLoading) return
      this.showPwModal = false
    },

    async init() {
      await window.PasswordPolicy.load()
      this.policyReady = window.PasswordPolicy.loaded
    },

    // checklist สด ๆ ของรหัสใหม่ (กฎมาจาก server ชุดเดียวกับที่ server บังคับ)
    passwordChecks() {
      if (!this.policyReady) return []
      return window.PasswordPolicy.check(this.pw.next)
    },

    policyOk() {
      const checks = this.passwordChecks()
      return checks.length > 0 && checks.every(c => c.passed)
    },

    canChangePw() {
      return this.pw.current && this.policyOk() && this.pw.next === this.pw.confirm
    },

    async changePassword() {
      if (this.pwLoading) return

      if (!this.pw.current || !this.pw.next || !this.pw.confirm) {
        this.pwError = 'กรุณากรอกข้อมูลให้ครบ'
        return
      }
      if (this.pw.next.length < 8) {
        this.pwError = 'รหัสผ่านใหม่ต้องมีอย่างน้อย 8 ตัวอักษร'
        return
      }
      if (this.pw.next !== this.pw.confirm) {
        this.pwError = 'ยืนยันรหัสผ่านใหม่ไม่ตรงกัน'
        return
      }

      this.pwLoading = true
      this.pwError = ''

      try {
        const res = await fetch(window.APP_BASE + '/api/change-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            current_password: this.pw.current,
            new_password: this.pw.next,
          }),
        })

        const data = await res.json()
        if (res.status === 429) throw new Error('ลองใหม่อีกครั้งในภายหลัง')
        if (!res.ok) throw new Error(data.detail || 'เปลี่ยนรหัสผ่านไม่สำเร็จ')

        this.pwSuccess = true
        this.pw = { current: '', next: '', confirm: '' }
        setTimeout(() => {
          this.showPwModal = false
          this.pwSuccess = false
        }, 1500)
      } catch (err) {
        this.pwError = err.message
      } finally {
        this.pwLoading = false
      }
    },
  }
}
