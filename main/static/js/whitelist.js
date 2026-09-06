// ย้ายมาจาก templates/whitelist.html (บล็อก <script> เดิม)
function whitelistApp() {
  return {
    // แยก "กำลังโหลด" กับ "โหลดไม่สำเร็จ" ออกจาก "ไม่มีข้อมูล" (ดู state-box ด้านบน)
    loading: true,
    loadError: '',

    whitelist: [],
    showAddModal: false,
    isSubmitting: false,
    bulkResult: null,
    movingId: null,        // id ของแถวที่กำลังย้ายไป Blacklist (กันกดรัว)

    // ย้ายไป Blacklist — ต้องเลือกระยะเวลาบล็อกก่อน จึงเป็น modal ไม่ใช่กล่องยืนยันธรรมดา
    showMoveModal: false,
    moveTarget: null,
    isMoving: false,

    moveForm: {
      // ค่าตั้งต้น = ถาวร (พฤติกรรมเดิมของปุ่มนี้) แก้เป็นนาที/ชั่วโมง/วันได้
      duration: newDuration('permanent')
    },

    form: {
      items: [
        {
          ip_address: '',
          description: 'manual_whitelist'
        }
      ]
    },

    // ยุบผลลัพธ์ที่ API ส่งมาเป็น 4 หมวด (added/invalid/blocked_by_blacklist/skipped)
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

      // หมวดที่ไม่ได้บันทึก — reason จาก API เป็นภาษาไทยอยู่แล้ว ใช้ตรง ๆ ได้
      for (const group of ['invalid', 'blocked_by_blacklist', 'skipped']) {
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

    openAddModal() {
      this.showAddModal = true
      this.bulkResult = null

      if (this.form.items.length === 0) {
        this.addWhitelistRow()
      }
    },

    closeAddModal() {
      this.showAddModal = false
      this.bulkResult = null
    },

    addWhitelistRow() {
      this.form.items.push({
        ip_address: '',
        description: 'manual_whitelist'
      })
    },

    removeWhitelistRow(index) {
      if (this.form.items.length === 1) {
        return
      }

      this.form.items.splice(index, 1)
    },

    resetWhitelistForm() {
      this.form.items = [
        {
          ip_address: '',
          description: 'manual_whitelist'
        }
      ]
    },

    canSubmitWhitelist() {
      const items = this.form.items
        .map(item => ({
          ip_address: item.ip_address.trim(),
          description: item.description.trim() || 'manual_whitelist'
        }))
        .filter(item => item.ip_address.length > 0)

      if (items.length === 0) {
        return false
      }

      return items.every(item => isValidIPv4(item.ip_address))
    },

    async loadWhitelist() {
      this.loading = true

      try {
        const res = await fetch(window.APP_BASE + '/api/get_whitelist')

        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        this.whitelist = await res.json()
        this.loadError = ''
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('error to load IP Whitelist', err)
      } finally {
        this.loading = false
      }
    },

    async addWhitelistBulk() {
      const items = this.form.items
        .map(item => ({
          ip_address: item.ip_address.trim(),
          description: item.description.trim() || 'manual_whitelist'
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

      this.isSubmitting = true
      this.bulkResult = null

      try {
        const res = await fetch(window.APP_BASE + '/api/add_whitelist_bulk', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            items: items
          })
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'เพิ่ม Whitelist ไม่สำเร็จ')
          return
        }

        this.bulkResult = data

        await this.loadWhitelist()

        if (data.summary && data.summary.added > 0) {
          this.resetWhitelistForm()
          this.$store.ui.success(`เพิ่ม ${data.summary.added} IP เข้า Whitelist แล้ว`)
        }

      } catch (err) {
        console.error('ไม่สามารถเพิ่ม Whitelist ได้', err)
        this.$store.ui.error('ไม่สามารถเพิ่ม Whitelist ได้')
      } finally {
        this.isSubmitting = false
      }
    },

    async deleteWhitelist(item) {
      const ok = await this.$store.ui.confirm({
        title: 'ลบ IP ออกจาก Whitelist',
        message: 'หลังจากนี้ระบบจะบล็อก IP นี้อัตโนมัติได้ตามปกติเมื่อตรวจพบว่าโจมตี',
        detail: item.ip_address,
        confirmText: 'ลบออกจาก Whitelist',
        danger: true,
      })
      if (!ok) return

      try {
        const res = await fetch(window.APP_BASE + `/api/delete_whitelist/${item.id}`, {
          method: 'POST'
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'ไม่สามารถลบ Whitelist ได้')
          return
        }

        await this.loadWhitelist()
        this.$store.ui.success(`ลบ ${item.ip_address} ออกจาก Whitelist แล้ว`)

      } catch (err) {
        console.error('ไม่สามารถลบ Whitelist ได้', err)
        this.$store.ui.error('ไม่สามารถลบ Whitelist ได้')
      }
    },

    openMoveModal(item) {
      this.moveTarget = item
      this.showMoveModal = true
    },

    closeMoveModal() {
      if (this.isMoving) return    // กำลังยิงคำขออยู่ ปิดทิ้งกลางคันไม่ได้

      this.showMoveModal = false
      this.moveTarget = null
    },

    // เอาออกจาก Whitelist + บล็อกตามเวลาที่เลือกในคำขอเดียว — ทำมือทีละหน้าต้องกด Remove
    // ที่นี่ก่อนแล้วค่อยไปหน้า Blacklist ไม่งั้นจะติดเงื่อนไข "IP อยู่ใน Whitelist"
    async moveToBlacklist() {
      const item = this.moveTarget
      if (!item) return

      if (!isValidDuration(this.moveForm.duration)) {
        this.$store.ui.error('ระยะเวลาบล็อกไม่ถูกต้อง — กรอกเป็นจำนวนเต็ม 1 ขึ้นไป และไม่เกิน 10 ปี')
        return
      }

      const seconds = durationSeconds(this.moveForm.duration)   // null = ถาวร

      this.isMoving = true
      this.movingId = item.id

      try {
        const res = await fetch(window.APP_BASE + `/api/move_to_blacklist/${item.id}`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            duration_seconds: seconds
          })
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'ย้ายไป Blacklist ไม่สำเร็จ')
          return
        }

        this.isMoving = false
        this.closeMoveModal()

        await this.loadWhitelist()
        this.$store.ui.success(`ย้าย ${item.ip_address} ไป Blacklist แล้ว · ${formatDuration(seconds)}`)

      } catch (err) {
        console.error('ย้ายไป Blacklist ไม่สำเร็จ', err)
        this.$store.ui.error('ย้ายไป Blacklist ไม่สำเร็จ')
      } finally {
        this.isMoving = false
        this.movingId = null
      }
    }
  }
}
