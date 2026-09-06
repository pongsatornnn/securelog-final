// ย้ายมาจาก templates/line_recipients.html (บล็อก <script> เดิม)
function lineRecipientsApp() {
  return {
    recipients: [],
    groups: [],
    busyId: null,

    // LINE OA ที่ระบบใช้ส่งแจ้งเตือน — โหลดแยกจากรายชื่อผู้รับ เพราะเป็นคนละ endpoint
    // และไม่ควรทำให้ทั้งหน้าพังถ้าฝั่งนี้พลาด (แถบหายไปเฉย ๆ รายชื่อยังใช้งานได้)
    oa: { oa_id: '', add_friend_url: null },
    oaLoaded: false,

    // id ของคนที่รูปโหลดไม่ขึ้น (URL หมดอายุ / เครื่องนี้ออกเน็ตไม่ได้) — สลับไปใช้ไอคอนแทน
    // ถ้าไม่จำไว้ <img> ที่พังจะขึ้นเป็นรูปแตกค้างอยู่ในการ์ด
    brokenAvatars: [],

    markAvatarBroken(id) {
      if (!this.brokenAvatars.includes(id)) this.brokenAvatars.push(id)
    },

    // แยก "กำลังโหลด" กับ "โหลดไม่สำเร็จ" ออกจาก "ไม่มีข้อมูล" (ดู state-box ด้านบน)
    loading: true,
    loadError: '',

    statusOrder: ['pending', 'approved', 'rejected'],
    // คำเดียวกันทั้งหัวข้อกลุ่มและป้ายบนการ์ด — ผู้ใช้จะได้ไม่ต้องแปลว่าสองคำนี้คือสถานะเดียวกัน
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
        // ไม่ขึ้น error ให้ผู้ใช้ — แถบนี้เป็นข้อมูลประกอบ ไม่ใช่งานหลักของหน้า
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
        // clipboard API ใช้ไม่ได้ (เบราว์เซอร์เก่า/ไม่ใช่ secure context) — ถอยไปใช้วิธีเดิม
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
        // กด Refresh = ให้โอกาสรูปที่เคยพังโหลดใหม่ (เจ้าตัวเปลี่ยนรูป/เน็ตกลับมาแล้ว)
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

      // อนุมัติ = เริ่มส่ง alert การโจมตีเข้า LINE ของคนนี้ทันที ต้องถามก่อน
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
        // ไม่ใช้ #id เป็นหัวข้อแล้ว เพราะตารางไม่ได้โชว์ id ให้เทียบ — ชื่อที่แสดงอยู่ใน
        // detail ด้านล่างคือสิ่งที่ผู้ใช้เอาไปตรวจสอบได้จริงว่ากำลังลบคนถูกคน
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
