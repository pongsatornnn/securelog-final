// ย้ายมาจาก templates/login.html (บล็อก <script> เดิม)
function loginApp() {
  return {
    username: '',     
    password: '',     
    loading : false,  
    error   : '',     
    shaking : false,  

    async submit() {
      if (this.loading) return

      if (!this.username || !this.password) {
        this.setError('กรุณากรอกข้อมูลให้ครบ')
        return
      }

      this.loading = true
      this.error   = ''

      try {
        const res = await fetch(window.APP_BASE + '/api/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          },
          body: new URLSearchParams({
            username: this.username,
            password: this.password,
          }),
        })

        const data = await res.json()

        if (res.status === 429) throw new Error('ลองใหม่อีกครั้งในภายหลัง')
        if (!res.ok)           throw new Error(data.detail || 'เข้าสู่ระบบไม่สำเร็จ')

        window.location.href = window.APP_BASE + '/dashboard'

      } catch (err) {
        this.setError(err.message)
      } finally {
        this.loading = false
      }
    },

    setError(msg) {
      this.error   = msg
      this.shaking = true
      setTimeout(() => this.shaking = false, 350)
    }
  }
}
