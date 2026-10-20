
function lineRecipientsApp() {
  return {
    recipients: [],
    groups: [],
    busyId: null,


    oa: { oa_id: '', add_friend_url: null },
    oaLoaded: false,


    brokenAvatars: [],

    markAvatarBroken(id) {
      if (!this.brokenAvatars.includes(id)) this.brokenAvatars.push(id)
    },


    loading: true,
    loadError: '',

    statusOrder: ['pending', 'approved', 'rejected'],

    statusLabels: {
      pending: 'รออนุมัติ',
      approved: 'อนุมัติแล้ว',
      rejected: 'โดนระงับ',
    },

    statusLabel(s) { return this.statusLabels[s] || s },

    groupRecipients() {
      this.groups = this.statusOrder.map(status => ({
        status,
        items: this.recipients.filter(r => r.status === status),
      }))
    },

    async loadOa() {
      try {
        const res = await fetch(window.APP_BASE + '/api/line/oa')
        if (!res.ok) throw new Error(`เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        this.oa = await res.json()
      } catch (err) {

        console.error('โหลด LINE OA ไม่สำเร็จ', err)
      } finally {
        this.oaLoaded = true
      }
    },

    async copyText(text) {
      if (!text) return

      try {
        await navigator.clipboard.writeText(text)
        this.$store.ui.success('คัดลอกแล้ว')
      } catch (err) {

        const box = document.createElement('textarea')
        box.value = text
        box.style.position = 'fixed'
        box.style.opacity = '0'
        document.body.appendChild(box)
        box.select()

        try {
          document.execCommand('copy')
          this.$store.ui.success('คัดลอกแล้ว')
        } catch (e) {
          this.$store.ui.error('คัดลอกอัตโนมัติไม่ได้ — กดเลือกข้อความแล้วคัดลอกเอง')
        } finally {
          document.body.removeChild(box)
        }
      }
    },

    async loadRecipients() {
      this.loading = true

      try {
        const res = await fetch(window.APP_BASE + '/api/line/recipients')
        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }
        this.recipients = await res.json()
        this.groupRecipients()

        this.brokenAvatars = []
        this.loadError = ''
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลดรายชื่อไม่สำเร็จ', err)
      } finally {
        this.loading = false
      }
    },

    async setStatus(r, action) {
      const name = r.display_name || r.line_user_id


      if (action === 'approve') {
        const ok = await this.$store.ui.confirm({
          title: 'อนุมัติผู้รับแจ้งเตือน',
          message: 'บัญชีนี้จะได้รับแจ้งเตือนการโจมตีทุกครั้งที่ระบบตรวจพบ ผ่าน LINE',
          detail: name,
          confirmText: 'อนุมัติ',
        })
        if (!ok) return
      }

      this.busyId = r.id
      try {
        const res = await fetch(window.APP_BASE + `/api/line/recipients/${r.id}/${action}`, { method: 'POST' })
        if (!res.ok) {
          const data = await res.json()
          this.$store.ui.error(data.detail || 'อัปเดตไม่สำเร็จ')
          return
        }
        await this.loadRecipients()
        this.$store.ui.success(
          (action === 'approve' ? 'อนุมัติ' : 'ระงับ') + ` ${name} แล้ว`
        )
      } catch (err) {
        console.error('อัปเดตไม่สำเร็จ', err)
        this.$store.ui.error('อัปเดตไม่สำเร็จ')
      } finally {
        this.busyId = null
      }
    },

    async deleteRecipient(r) {
      const name = r.display_name || r.line_user_id

      const ok = await this.$store.ui.confirm({


        title: 'ลบผู้รับแจ้งเตือน',
        message: 'บัญชีนี้จะไม่ได้รับแจ้งเตือนการโจมตีทาง LINE อีก ',
        detail: name,
        confirmText: 'ลบผู้รับ',
        danger: true,
      })
      if (!ok) return

      this.busyId = r.id
      try {
        const res = await fetch(window.APP_BASE + `/api/line/recipients/${r.id}`, { method: 'DELETE' })
        if (!res.ok) {
          const data = await res.json()
          this.$store.ui.error(data.detail || 'ลบไม่สำเร็จ')
          return
        }
        await this.loadRecipients()
        this.$store.ui.success(`ลบ ${name} แล้ว`)
      } catch (err) {
        console.error('ลบไม่สำเร็จ', err)
        this.$store.ui.error('ลบไม่สำเร็จ')
      } finally {
        this.busyId = null
      }
    },
  }
}
