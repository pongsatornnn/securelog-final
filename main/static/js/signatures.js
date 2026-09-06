// ย้ายมาจาก templates/signatures.html (บล็อก <script> เดิม)
function signaturesApp() {
  return {
    // แท็บที่เลือกอยู่ = detection_type — ค่าเริ่มต้นตั้งไม่ได้ตั้งแต่ต้นเพราะหมวดมาจากข้อมูล
    // (ดู groupSignatures ที่ตกไปหมวดแรกให้เมื่อค่าปัจจุบันใช้ไม่ได้)
    tab: '',

    // จำแท็บไว้ใน URL hash — รีเฟรชแล้วยังอยู่หมวดเดิม และส่งลิงก์ตรงไปหมวดที่ต้องการได้
    initTab() {
      const fromHash = decodeURIComponent(window.location.hash.replace('#', ''))
      if (fromHash) this.tab = fromHash     // ถูกหรือไม่ ค่อยเช็คตอนข้อมูลมาถึง
    },

    selectTab(name) {
      this.tab = name

      // replaceState ไม่ใช่เซ็ต location.hash ตรง ๆ — กันเบราว์เซอร์กระโดดสกรอลล์หา
      // element ที่ id ตรงกัน และกันประวัติสะสมจนกด back ต้องย้อนทีละแท็บ
      history.replaceState(null, '', '#' + name)
    },

    signatures: [],
    groupedSignatures: [],
    showFormModal: false,
    editingId: null,       // null = โหมดเพิ่ม, มีค่า = โหมดแก้ไข signature id นั้น
    isSubmitting: false,
    busyId: null,
    isRestoring: false,
    formError: '',

    // แยก "กำลังโหลด" กับ "โหลดไม่สำเร็จ" ออกจาก "ไม่มีข้อมูล" (ดู state-box ด้านบน)
    loading: true,
    loadError: '',

    detectionTypes: ['sql_injection', 'xss', 'path_traversal', 'command_injection'],

    typeLabels: {
      sql_injection: 'SQL Injection',
      xss: 'Cross-Site Scripting (XSS)',
      path_traversal: 'Path Traversal',
      command_injection: 'Command Injection',
    },

    form: {
      detection_type: 'sql_injection',
      pattern: '',
      description: '',
    },

    typeLabel(t) {
      return this.typeLabels[t] || t
    },

    groupSignatures() {
      const order = this.detectionTypes
      const groups = {}

      for (const sig of this.signatures) {
        const t = sig.detection_type || 'other'
        if (!groups[t]) groups[t] = []
        groups[t].push(sig)
      }

      this.groupedSignatures = Object.keys(groups)
        .sort((a, b) => {
          const ia = order.indexOf(a), ib = order.indexOf(b)
          return (ia === -1 ? 99 : ia) - (ib === -1 ? 99 : ib)
        })
        .map(t => ({
          detection_type: t,
          items: groups[t],
          activeCount: groups[t].filter(s => s.is_active).length,
          // แยกให้เห็นว่าปุ่มคืนค่าจะแตะกี่แถว และเหลือของแอดมินกี่แถวที่ไม่ถูกแตะ
          defaultCount: groups[t].filter(s => s.is_default).length,
          customCount: groups[t].filter(s => !s.is_default).length,
        }))

      // แท็บที่ค้างอยู่อาจใช้ไม่ได้แล้ว: เพิ่งเข้าหน้า (ยังว่าง), มาจาก hash ที่สะกดผิด,
      // หรือ signature หมวดนั้นถูกลบจนหมด -> ตกไปที่หมวดแรกที่มีจริง
      if (!this.groupedSignatures.some(g => g.detection_type === this.tab)) {
        this.tab = this.groupedSignatures.length ? this.groupedSignatures[0].detection_type : ''
      }
    },

    async loadSignatures() {
      this.loading = true

      try {
        const res = await fetch(window.APP_BASE + '/api/signatures')
        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }
        this.signatures = await res.json()
        this.groupSignatures()
        this.loadError = ''
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด signatures ไม่สำเร็จ', err)
      } finally {
        this.loading = false
      }
    },

    openAddModal() {
      this.formError = ''
      this.editingId = null
      // เปิดจากแท็บไหนก็ตั้งชนิดเป็นแท็บนั้นให้เลย (เดิมเด้งกลับไป sql_injection ทุกครั้ง)
      this.form = {
        detection_type: this.tab || 'sql_injection',
        pattern: '',
        description: '',
      }
      this.showFormModal = true
    },

    openEditModal(sig) {
      this.formError = ''
      this.editingId = sig.id
      this.form = {
        detection_type: sig.detection_type,
        pattern: sig.pattern,
        description: sig.description || '',
      }
      this.showFormModal = true
    },

    closeFormModal() {
      this.showFormModal = false
      this.editingId = null
    },

    // ปุ่มเดียวใช้ทั้งเพิ่มและบันทึก — แยกที่ editingId (ดู modal ด้านบน)
    async submitForm() {
      if (!this.form.pattern.trim()) return
      this.isSubmitting = true
      this.formError = ''

      const editing = this.editingId !== null

      const url = window.APP_BASE + (editing ? `/api/signatures/${this.editingId}/edit` : '/api/signatures')
      const body = editing
        ? {
            pattern: this.form.pattern.trim(),
            description: this.form.description.trim(),
          }
        : {
            detection_type: this.form.detection_type,
            pattern: this.form.pattern.trim(),
            description: this.form.description.trim() || null,
          }

      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        })

        const data = await res.json()

        if (!res.ok) {
          this.formError = data.detail || (editing ? 'บันทึกไม่สำเร็จ' : 'เพิ่ม signature ไม่สำเร็จ')
          return
        }

        const editedId = this.editingId

        await this.loadSignatures()
        this.closeFormModal()

        if (editing) {
          this.$store.ui.success(`แก้ไข signature #${editedId} แล้ว`)
        }
      } catch (err) {
        console.error(editing ? 'บันทึก signature ไม่สำเร็จ' : 'เพิ่ม signature ไม่สำเร็จ', err)
        this.formError = editing ? 'บันทึกไม่สำเร็จ' : 'เพิ่ม signature ไม่สำเร็จ'
      } finally {
        this.isSubmitting = false
      }
    },

    async toggleActive(sig) {
      this.busyId = sig.id
      try {
        const res = await fetch(window.APP_BASE + `/api/signatures/${sig.id}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ is_active: !sig.is_active }),
        })

        if (!res.ok) {
          const data = await res.json()
          this.$store.ui.error(data.detail || 'อัปเดตไม่สำเร็จ')
          return
        }
        await this.loadSignatures()
        this.$store.ui.success(
          (sig.is_active ? 'ปิดใช้งาน' : 'เปิดใช้งาน') + ` signature #${sig.id} แล้ว`
        )
      } catch (err) {
        console.error('อัปเดตไม่สำเร็จ', err)
        this.$store.ui.error('อัปเดตไม่สำเร็จ')
      } finally {
        this.busyId = null
      }
    },

    // ── คืนค่า default ────────────────────────────────────────────────
    // ปุ่มบนหัวหน้ากับปุ่มในแท็บยิง endpoint เดียวกัน ต่างกันแค่ส่ง detection_type หรือไม่
    async restoreDefaults(detectionType) {
      this.isRestoring = true

      try {
        const res = await fetch(window.APP_BASE + '/api/signatures_restore_defaults', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(detectionType ? { detection_type: detectionType } : {}),
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'คืนค่า default ไม่สำเร็จ')
          return
        }

        await this.loadSignatures()
        this.$store.ui.success(data.message || 'คืนค่า default แล้ว')

      } catch (err) {
        console.error('คืนค่า default ไม่สำเร็จ', err)
        this.$store.ui.error('คืนค่า default ไม่สำเร็จ')
      } finally {
        this.isRestoring = false
      }
    },

    async restoreType(group) {
      const custom = group.customCount
      const ok = await this.$store.ui.confirm({
        title: `คืนค่า default ของ ${this.typeLabel(group.detection_type)}`,
        message: 'pattern ของระบบที่ถูกลบจะกลับมา ที่ถูกปิดจะเปิดคืน และที่ถูกแก้จะกลับเป็นของเดิม'
               + (custom ? ` · signature ที่เพิ่มเอง ${custom} รายการไม่ถูกแตะ` : ''),
        detail: group.defaultCount + ' pattern ของระบบ',
        confirmText: 'คืนค่า default',
        danger: true,
      })
      if (!ok) return

      await this.restoreDefaults(group.detection_type)
    },

    async restoreAll() {
      const custom = this.signatures.filter(s => !s.is_default).length
      const ok = await this.$store.ui.confirm({
        title: 'คืนค่า default ของ signature ทุกชนิด',
        message: 'pattern ของระบบที่ถูกลบจะกลับมา ที่ถูกปิดจะเปิดคืน และที่ถูกแก้จะกลับเป็นของเดิม'
               + (custom ? ` · signature ที่เพิ่มเอง ${custom} รายการไม่ถูกแตะ` : ''),
        detail: this.signatures.filter(s => s.is_default).length + ' pattern ของระบบ',
        confirmText: 'คืนค่า default',
        danger: true,
      })
      if (!ok) return

      await this.restoreDefaults(null)
    },

    async deleteSignature(sig) {
      const ok = await this.$store.ui.confirm({
        title: `ลบ signature #${sig.id}`,
        message: 'detector จะเลิกใช้ pattern นี้ตรวจจับทันทีหลังลบ',
        detail: sig.pattern,
        confirmText: 'ลบ signature',
        danger: true,
      })
      if (!ok) return

      this.busyId = sig.id
      try {
        const res = await fetch(window.APP_BASE + `/api/signatures/${sig.id}`, { method: 'DELETE' })

        if (!res.ok) {
          const data = await res.json()
          this.$store.ui.error(data.detail || 'ลบไม่สำเร็จ')
          return
        }
        await this.loadSignatures()
        this.$store.ui.success(`ลบ signature #${sig.id} แล้ว`)
      } catch (err) {
        console.error('ลบไม่สำเร็จ', err)
        this.$store.ui.error('ลบไม่สำเร็จ')
      } finally {
        this.busyId = null
      }
    },
  }
}
