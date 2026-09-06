// ย้ายมาจาก templates/blacklist.html (บล็อก <script> เดิม)
function blacklistApp() {
  return {
    blacklist: [],
    showAddModal: false,
    isSubmitting: false,
    bulkResult: null,
    movingId: null,        // id ของแถวที่กำลังย้ายไป Whitelist (กันกดรัว)

    // แยก "กำลังโหลด" กับ "โหลดไม่สำเร็จ" ออกจาก "ไม่มีข้อมูล" (ดู state-box ด้านบน)
    loading: true,
    loadError: '',

    form: {
      items: [
        {
          ip_address: '',
          event: 'manual_blacklist'
        }
      ],
      // กรอกเวลาเองแล้วเลือกหน่วย (นาที/ชั่วโมง/วัน) หรือเลือก 'permanent' = ถาวร
      // helper ทั้งชุดอยู่ที่ static/js/common.js — ดู macro duration_picker
      duration: newDuration('permanent')
    },

    // ยุบผลลัพธ์ที่ API ส่งมาเป็น 5 หมวด (added/reblocked/invalid/blocked_by_whitelist/skipped)
    // ให้เหลือลิสต์เดียว 1 บรรทัด = 1 IP พร้อมเหตุผล — ผู้ใช้จะได้ไม่ต้องไล่อ่านหลายกล่อง
    // key ต้องมีชื่อหมวดนำหน้าด้วย เพราะ IP เดียวกันโผล่ได้ 2 หมวด (เช่น พิมพ์ซ้ำในชุดเดียวกัน)
    get bulkLines() {
      const r = this.bulkResult && this.bulkResult.results
      if (!r) return []

      const lines = []

      for (const item of r.added || []) {
        lines.push({
          key: 'added:' + item.ip_address,
          ok: true,
          ip_address: item.ip_address,
          reason: 'บันทึกแล้ว'
        })
      }

      // IP ที่ถูกบล็อกอยู่แล้ว — ไม่ได้เพิ่มแถวใหม่ แต่ส่งคำสั่ง block ซ้ำให้ agent แล้ว
      // ถือว่าสำเร็จ (ok) เพราะผลลัพธ์ที่แอดมินต้องการคือ IP นี้โดนบล็อกอยู่จริงทั้งสองฝั่ง
      for (const item of r.reblocked || []) {
        lines.push({
          key: 'reblocked:' + item.ip_address,
          ok: true,
          ip_address: item.ip_address,
          reason: item.reason || 'ส่งคำสั่งบล็อกซ้ำแล้ว'
        })
      }

      // หมวดที่ไม่ได้บันทึก — reason จาก API เป็นภาษาไทยอยู่แล้ว ใช้ตรง ๆ ได้
      for (const group of ['invalid', 'blocked_by_whitelist', 'skipped']) {
        for (const item of r[group] || []) {
          lines.push({
            key: group + ':' + item.ip_address,
            ok: false,
            ip_address: item.ip_address,
            reason: item.reason || 'บันทึกไม่สำเร็จ'
          })
        }
      }

      return lines
    },

    // ครั้งที่เท่าไรของรอบบล็อกนี้ — ตัวเลขเดียวกับที่ใช้คูณระยะเวลาตามนโยบาย escalation
    // (แถวที่แอดมินเพิ่งปลดบล็อกเองจะเป็น 0 แต่แถวพวกนั้นไม่ active จึงไม่ขึ้นในตารางนี้)
    formatBlockCount(count) {
      if (!count) return 'ครั้งแรก'
      return count === 1 ? 'ครั้งแรก' : `ครั้งที่ ${count}`
    },

    // ระบบบล็อกเอง -> แสดงแค่ 'system' · ชนิดการโจมตีไม่ต้องซ้ำตรงนี้ เพราะคอลัมน์
    // Reason / Event ข้าง ๆ บอกอยู่แล้ว (ค่าใน DB ยังเก็บเป็น detector:<ชนิด> ไว้เหมือนเดิม
    // เผื่อ query ย้อนหลัง — เอามาใส่ tooltip ให้ hover ดูได้)
    // ว่าง = แถวที่มีอยู่ก่อนระบบเก็บข้อมูลนี้ (ไม่มีให้ backfill ย้อนหลัง)
    formatAddedBy(createdBy) {
      if (!createdBy) return 'ไม่ทราบ'
      if (createdBy.startsWith('detector:')) return 'system'
      return createdBy
    },

    formatExpiry(item) {
      if (!item.expires_at) return 'ถาวร'
      const d = new Date(item.expires_at)
      return d.toLocaleString('th-TH-u-ca-gregory', {
        timeZone: 'Asia/Bangkok',
        dateStyle: 'short',
        timeStyle: 'short'
      })
    },

    openAddModal() {
      this.showAddModal = true
      this.bulkResult = null

      if (this.form.items.length === 0) {
        this.addBlacklistRow()
      }
    },

    closeAddModal() {
      this.showAddModal = false
      this.bulkResult = null
    },

    addBlacklistRow() {
      this.form.items.push({
        ip_address: '',
        event: 'manual_blacklist'
      })
    },

    removeBlacklistRow(index) {
      if (this.form.items.length === 1) {
        return
      }

      this.form.items.splice(index, 1)
    },

    resetBlacklistForm() {
      this.form.items = [
        {
          ip_address: '',
          event: 'manual_blacklist'
        }
      ]
    },

    canSubmitBlacklist() {
      const items = this.form.items
        .map(item => ({
          ip_address: item.ip_address.trim(),
          event: item.event.trim() || 'manual_blacklist'
        }))
        .filter(item => item.ip_address.length > 0)

      if (items.length === 0) {
        return false
      }

      if (!isValidDuration(this.form.duration)) {
        return false
      }

      return items.every(item => isBlockableIPv4(item.ip_address))
    },

    async loadBlacklist() {
      this.loading = true

      try {
        const res = await fetch(window.APP_BASE + '/api/get_blacklist')

        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        this.blacklist = await res.json()
        this.loadError = ''
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('error to load IP Blacklist', err)
      } finally {
        this.loading = false
      }
    },

    async addBlacklistBulk() {
      const items = this.form.items
        .map(item => ({
          ip_address: item.ip_address.trim(),
          event: item.event.trim() || 'manual_blacklist'
        }))
        .filter(item => item.ip_address.length > 0)

      if (items.length === 0) {
        this.$store.ui.error('กรุณากรอก IP Address อย่างน้อย 1 รายการ')
        return
      }

      const invalidItems = items.filter(item => !isValidIPv4(item.ip_address))

      if (invalidItems.length > 0) {
        this.$store.ui.error('กรุณากรอก IP Address ให้ถูกต้อง')
        return
      }

      const nonBlockableItems = items.filter(item => !isBlockableIPv4(item.ip_address))

      if (nonBlockableItems.length > 0) {
        this.$store.ui.error(
          `บล็อก ${nonBlockableItems.map(item => item.ip_address).join(', ')} ไม่ได้ ` +
          'เป็น address ของทราฟฟิก broadcast ไม่ใช่เครื่องจริง'
        )
        return
      }

      if (!isValidDuration(this.form.duration)) {
        this.$store.ui.error('ระยะเวลาบล็อกไม่ถูกต้อง — กรอกเป็นจำนวนเต็ม 1 ขึ้นไป และไม่เกิน 10 ปี')
        return
      }

      this.isSubmitting = true
      this.bulkResult = null

      try {
        const res = await fetch(window.APP_BASE + '/api/add_blacklist_bulk', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            items: items,
            duration_seconds: durationSeconds(this.form.duration)   // null = ถาวร
          })
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'เพิ่ม Blacklist ไม่สำเร็จ')
          return
        }

        this.bulkResult = data

        await this.loadBlacklist()

        const summary = data.summary || {}
        const added = summary.added || 0
        const reblocked = summary.reblocked || 0

        if (added > 0 || reblocked > 0) {
          this.resetBlacklistForm()
        }

        // บอกระยะเวลาที่เลือกไว้ในข้อความด้วย — ตอนนี้กรอกเองได้ทุกค่า ไม่ใช่ตัวเลือกตายตัวแล้ว
        const blockLabel = formatDuration(durationSeconds(this.form.duration))

        if (added > 0 && reblocked > 0) {
          this.$store.ui.success(
            `เพิ่ม ${added} IP เข้า Blacklist (${blockLabel}) และส่งคำสั่งบล็อกซ้ำอีก ${reblocked} IP แล้ว`
          )
        } else if (added > 0) {
          this.$store.ui.success(`เพิ่ม ${added} IP เข้า Blacklist แล้ว · ${blockLabel}`)
        } else if (reblocked > 0) {
          this.$store.ui.success(`ส่งคำสั่งบล็อกซ้ำ ${reblocked} IP ไปยัง Client Server แล้ว`)
        }

      } catch (err) {
        console.error('ไม่สามารถเพิ่ม Blacklist ได้', err)
        this.$store.ui.error('ไม่สามารถเพิ่ม Blacklist ได้')
      } finally {
        this.isSubmitting = false
      }
    },

    async deleteBlacklist(item) {
      const ok = await this.$store.ui.confirm({
        title: 'ปลดบล็อก IP',
        message:
          'คำสั่งปลดบล็อกจะถูกส่งไปยัง Client Server ทุกเครื่องทันที ',
        detail: item.ip_address ,
        confirmText: 'ปลดบล็อก',
        danger: true,
      })
      if (!ok) return

      try {
        const res = await fetch(window.APP_BASE + `/api/delete_blacklist/${item.id}`, {
          method: 'POST'
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'ไม่สามารถปลดบล็อกได้')
          return
        }

        await this.loadBlacklist()
        this.$store.ui.success(`ปลดบล็อก ${item.ip_address} แล้ว · ล้างจำนวนครั้งเป็น 0`)

      } catch (err) {
        console.error('ไม่สามารถปลดบล็อกได้', err)
        this.$store.ui.error('ไม่สามารถปลดบล็อกได้')
      }
    },

    // ปลดบล็อก + เพิ่มเข้า Whitelist ในคำขอเดียว — ถ้าทำมือทีละหน้าต้องกด Unblock
    // ที่นี่ก่อนแล้วค่อยไปหน้า Whitelist ไม่งั้นจะติดเงื่อนไข "IP กำลังถูกบล็อกอยู่"
    async moveToWhitelist(item) {
      const ok = await this.$store.ui.confirm({
        title: 'ย้าย IP ไป Whitelist',
        message:
          'จะปลดบล็อก IP นี้ที่ Client Server ทุกเครื่อง แล้วเพิ่มเข้า Whitelist ' +
          '— หลังจากนี้ระบบจะไม่บล็อก IP นี้อัตโนมัติอีกแม้ตรวจพบว่าโจมตี',
        detail: item.ip_address,
        confirmText: 'ย้ายไป Whitelist',
      })
      if (!ok) return

      this.movingId = item.id

      try {
        const res = await fetch(window.APP_BASE + `/api/move_to_whitelist/${item.id}`, {
          method: 'POST'
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'ย้ายไป Whitelist ไม่สำเร็จ')
          return
        }

        await this.loadBlacklist()
        this.$store.ui.success(`ย้าย ${item.ip_address} ไป Whitelist แล้ว`)

      } catch (err) {
        console.error('ย้ายไป Whitelist ไม่สำเร็จ', err)
        this.$store.ui.error('ย้ายไป Whitelist ไม่สำเร็จ')
      } finally {
        this.movingId = null
      }
    }
  }
}
