// ย้ายมาจาก templates/manage_users.html (บล็อก <script> เดิม)
// ค่าที่มาจาก server อ่านผ่าน window.PAGE_DATA ที่ template ประกาศไว้
function manageUsersApp() {
  return {
    users: [],

    // แยก "กำลังโหลด" กับ "โหลดไม่สำเร็จ" ออกจาก "ไม่มีข้อมูล" (ดู state-box ด้านบน)
    loading: true,
    loadError: '',

    showCreateModal: false,
    creating: false,
    createError: '',
    createForm: { username: '', password: '', role: 'user' },

    showResetModal: false,
    resetting: false,
    resetError: '',
    resetTarget: null,
    policyReady: false,
    resetForm: { newPassword: '' },

    currentUsername: window.PAGE_DATA.username,

    showDeleteModal: false,
    deleting: false,
    deleteError: '',
    deleteTarget: null,

    async loadUsers() {
      this.loading = true

      try {
        const res = await fetch(window.APP_BASE + '/api/users')
        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }
        this.users = await res.json()
        this.loadError = ''
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด users ไม่สำเร็จ', err)
      } finally {
        this.loading = false
      }
    },

    openCreateModal() {
      this.createError = ''
      this.createForm = { username: '', password: '', role: 'user' }
      this.showCreateModal = true
    },

    closeCreateModal() {
      if (this.creating) return
      this.showCreateModal = false
    },

    async init() {
      await window.PasswordPolicy.load()
      this.policyReady = window.PasswordPolicy.loaded
    },

    // checklist ของรหัสที่ admin ตั้งให้ (ตอนสร้างบัญชี / ตอนรีเซ็ตรหัสให้คนอื่น)
    createChecks() {
      if (!this.policyReady) return []
      return window.PasswordPolicy.check(this.createForm.password)
    },

    resetChecks() {
      if (!this.policyReady) return []
      return window.PasswordPolicy.check(this.resetForm.newPassword)
    },

    allPassed(checks) {
      return checks.length > 0 && checks.every(c => c.passed)
    },

    canCreate() {
      return this.createForm.username.trim().length >= 3
        && this.allPassed(this.createChecks())
        && this.createForm.role.trim()
    },

    canReset() {
      return this.allPassed(this.resetChecks())
    },

    async createUser() {
      this.createError = ''
      this.creating = true

      try {
        const res = await fetch(window.APP_BASE + '/api/users', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: this.createForm.username.trim(),
            password: this.createForm.password,
            role: this.createForm.role.trim(),
          }),
        })

        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'สร้าง user ไม่สำเร็จ')

        await this.loadUsers()
        this.showCreateModal = false
      } catch (err) {
        this.createError = err.message
      } finally {
        this.creating = false
      }
    },

    openResetModal(u) {
      this.resetError = ''
      this.resetTarget = u
      this.resetForm = { newPassword: '' }
      this.showResetModal = true
    },

    closeResetModal() {
      if (this.resetting) return
      this.showResetModal = false
      this.resetTarget = null
    },

    async resetPassword() {
      if (!this.resetTarget) return

      this.resetError = ''
      this.resetting = true

      try {
        const res = await fetch(window.APP_BASE + `/api/users/${this.resetTarget.id}/reset-password`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ new_password: this.resetForm.newPassword }),
        })

        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'ตั้งรหัสผ่านใหม่ไม่สำเร็จ')

        await this.loadUsers()
        this.showResetModal = false
      } catch (err) {
        this.resetError = err.message
      } finally {
        this.resetting = false
      }
    },

    openDeleteModal(u) {
      this.deleteError = ''
      this.deleteTarget = u
      this.showDeleteModal = true
    },

    closeDeleteModal() {
      if (this.deleting) return
      this.showDeleteModal = false
      this.deleteTarget = null
    },

    async deleteUser() {
      if (!this.deleteTarget) return

      this.deleteError = ''
      this.deleting = true

      try {
        const res = await fetch(window.APP_BASE + `/api/users/${this.deleteTarget.id}`, {
          method: 'DELETE',
        })

        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'ลบ user ไม่สำเร็จ')

        await this.loadUsers()
        this.showDeleteModal = false
        this.deleteTarget = null
      } catch (err) {
        this.deleteError = err.message
      } finally {
        this.deleting = false
      }
    },

    async changeRole(u, newRole) {
      if (newRole === u.role) return

      const ok = await this.$store.ui.confirm({
        title: 'เปลี่ยนสิทธิ์ผู้ใช้',
        message: newRole === 'admin'
          ? 'ผู้ใช้คนนี้จะได้สิทธิ์ทั้งหมดในระบบ'
          : 'ผู้ใช้คนนี้จะเสียสิทธิ์ admin ทันที ',
        detail: `${u.username}: ${u.role} → ${newRole}`,
        confirmText: 'เปลี่ยนสิทธิ์',
        danger: newRole !== 'admin',
      })

      if (!ok) {
        await this.loadUsers()   // ยกเลิก -> รีเซ็ต dropdown กลับค่าเดิม
        return
      }

      try {
        const res = await fetch(window.APP_BASE + `/api/users/${u.id}/set-role`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ role: newRole }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'เปลี่ยน role ไม่สำเร็จ')

        this.$store.ui.success(`เปลี่ยน ${u.username} เป็น ${newRole} แล้ว`)
      } catch (err) {
        this.$store.ui.error(err.message)
      } finally {
        await this.loadUsers()
      }
    },

    async toggleActive(u) {
      const next = !u.is_active

      if (!next) {
        const ok = await this.$store.ui.confirm({
          title: 'ปิดใช้งานบัญชี',
          message: 'ผู้ใช้จะถูกเด้งออกจากระบบทันทีในคำขอถัดไป และเข้าสู่ระบบใหม่ไม่ได้จนกว่าจะเปิดใช้งานอีกครั้ง',
          detail: u.username,
          confirmText: 'ปิดใช้งาน',
          danger: true,
        })
        if (!ok) return
      }

      try {
        const res = await fetch(window.APP_BASE + `/api/users/${u.id}/set-active`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_active: next }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'อัปเดตสถานะไม่สำเร็จ')

        this.$store.ui.success(
          (next ? 'เปิดใช้งาน' : 'ปิดใช้งาน') + ` ${u.username} แล้ว`
        )
      } catch (err) {
        this.$store.ui.error(err.message)
      } finally {
        await this.loadUsers()
      }
    },
  }
}
