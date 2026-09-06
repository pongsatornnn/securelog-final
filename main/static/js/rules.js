// ย้ายมาจาก templates/rules.html (บล็อก <script> เดิม)
// แท็บที่มีในหน้านี้ — ใช้เป็นทั้งค่าใน state และชื่อใน URL hash
const RULE_TABS = ['rules', 'policy']

// เดิมแยกเป็น 2 แท็บ (#ttl / #severity) ตอนนี้รวมเป็นแท็บเดียว — ลิงก์เก่าที่ใครบุ๊กมาร์กไว้
// หรือที่เขียนอยู่ในเอกสารยังเปิดเข้าแท็บที่ถูกต้องได้
const LEGACY_TAB_ALIASES = { ttl: 'policy', severity: 'policy' }

function rulesApp() {
  return {
    tab: 'rules',

    // จำแท็บที่เปิดอยู่ไว้ใน URL (#policy) — รีเฟรชหน้าแล้วยังอยู่แท็บเดิม
    // และส่งลิงก์ตรงไปยังแท็บที่ต้องการให้คนอื่นได้
    initTab() {
      const fromHash = window.location.hash.replace('#', '')
      const name = LEGACY_TAB_ALIASES[fromHash] || fromHash
      if (RULE_TABS.includes(name)) this.tab = name
    },

    selectTab(name) {
      this.tab = name

      // replaceState ไม่ใช่การเซ็ต location.hash ตรง ๆ เพราะ (1) การเซ็ต hash ทำให้
      // เบราว์เซอร์กระโดดสกรอลล์ไปหา element ที่ id ตรงกัน (2) จะสะสมประวัติจนกด back
      // แล้วต้องย้อนทีละแท็บกว่าจะออกจากหน้านี้
      history.replaceState(null, '', name === 'rules' ? window.location.pathname : '#' + name)
    },

    rules: [],
    groupedRules: [],
    showEditModal: false,
    editing: null,
    isSubmitting: false,
    isRestoring: false,

    // 3 ชุดข้อมูลของหน้านี้โหลดคนละ endpoint กัน — แยกสถานะ "กำลังโหลด/โหลดไม่สำเร็จ" ของแต่ละชุด
    // ไม่งั้นชุดที่โหลดพลาดจะดูเหมือน "ยังไม่มีข้อมูล" ทั้งที่ค่าจริงมีอยู่ใน DB
    // (severity กับ TTL แสดงรวมในแท็บเดียว แต่ยังแยกสถานะกันเพื่อบอกได้ว่าพลาดฝั่งไหน)
    loadingRules: true,
    rulesError: '',
    loadingTtl: true,
    ttlError: '',
    loadingSeverity: true,
    severityError: '',

    form: {
      window_seconds: 0,
      threshold: 0,
      is_active: true,
    },

    // ข้อมูลดิบของ 2 endpoint เก็บแยกกันเหมือนเดิม ส่วน policyItems คือผลรวมที่ตารางใช้แสดง
    ttlItems: [],
    severityItems: [],
    policyItems: [],

    showPolicyEditModal: false,
    editingPolicy: null,
    isSubmittingPolicy: false,

    // นโยบาย escalation — มากับ /api/blacklist_ttl ก้อนเดียวกับ ttlItems
    // escSaved = ค่าที่บันทึกอยู่จริง ใช้เทียบว่าฟอร์มเปลี่ยนหรือยัง (กันกดบันทึกซ้ำโดยไม่ได้แก้)
    escSaved: { multiplier: 2, max_block_count: 5 },
    escForm: { multiplier: 2, max_block_count: 5 },
    isSubmittingEsc: false,

    policyForm: {
      severity: 'LOW',
      // กรอกตัวเลขเอง + เลือกหน่วย นาที/ชั่วโมง/วัน/ถาวร (ชุดเดียวกับหน้า Blacklist/Whitelist)
      // helper อยู่ที่ static/js/common.js — ดู macro duration_picker
      duration: newDuration('hours'),
    },

    // severity กับ TTL ใช้ key ชุดเดียวกัน (detection_type) จึงใช้ label ชุดเดียวร่วมกัน
    attackLabels: {
      ssh_brute_force: 'SSH Brute Force',
      sudo_failed: 'Sudo Authentication Failure',
      sql_injection: 'SQL Injection',
      xss: 'Cross-Site Scripting (XSS)',
      path_traversal: 'Path Traversal',
      command_injection: 'Command Injection',
      http_flood: 'HTTP Flood (App-level DoS)',
      firewall_deny_rate: 'Firewall Deny Flood',
      port_scan: 'Port Scan',
    },

    attackLabel(key) {
      return this.attackLabels[key] || key
    },

    policyError() {
      const parts = []
      if (this.severityError) parts.push('ระดับความรุนแรง: ' + this.severityError)
      if (this.ttlError) parts.push('ระยะเวลา Block: ' + this.ttlError)
      return parts.join(' · ')
    },

    // รวม 2 ชุดเป็นแถวเดียวต่อประเภทการโจมตี — ใช้ union ของ key ไม่ใช่ฝั่งใดฝั่งหนึ่งเป็นหลัก
    // เพื่อให้ประเภทที่มีค่าอยู่ฝั่งเดียวยังโผล่ในตาราง (เห็นว่าอีกฝั่งขาด) ไม่ใช่หายไปเงียบ ๆ
    buildPolicyItems() {
      const bySeverity = new Map(this.severityItems.map(i => [i.severity_key, i]))
      const byTtl = new Map(this.ttlItems.map(i => [i.detection_type, i]))

      // เรียงตาม key เหมือนที่ทั้ง 2 endpoint เรียงมา (ORDER BY ฝั่ง DB)
      const keys = [...new Set([...bySeverity.keys(), ...byTtl.keys()])].sort()

      this.policyItems = keys.map(key => {
        const sev = bySeverity.get(key)
        const ttl = byTtl.get(key)

        // 2 ตารางมี updated_at คนละอัน — คอลัมน์เดียวจึงแสดงอันที่ใหม่กว่า
        const updated = [sev && sev.updated_at, ttl && ttl.updated_at].filter(Boolean).sort()

        return {
          key,
          hasSeverity: !!sev,
          severity: sev ? sev.severity : null,
          hasTtl: !!ttl,
          ttl_seconds: ttl ? ttl.ttl_seconds : undefined,   // null = ถาวร (ต่างจาก undefined = ไม่มีแถว)
          updated_at: updated.length ? updated[updated.length - 1] : null,
        }
      })
    },

    // โหลดทั้ง 2 ฝั่งพร้อมกัน — ทั้งตอนเข้าหน้า ตอนกด Refresh และตอนกดลองใหม่
    async loadPolicy() {
      await Promise.all([this.loadAlertSeverity(), this.loadBlacklistTtl()])
    },

    async loadAlertSeverity() {
      this.loadingSeverity = true

      try {
        const res = await fetch(window.APP_BASE + '/api/alert_severity')

        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        const data = await res.json()
        this.severityItems = data.items
        this.severityError = ''
      } catch (err) {
        this.severityError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด alert severity ไม่สำเร็จ', err)
      } finally {
        this.loadingSeverity = false
        this.buildPolicyItems()
      }
    },

    // หน่วยเดียวกับที่ช่องกรอกใน modal ใช้ (common.js) — คอลัมน์ "ระยะเวลา Block"
    // กับค่าที่กรอกไว้จะได้อ่านตรงกันเสมอ
    formatTtl(seconds) {
      return formatDuration(seconds)
    },

    async loadBlacklistTtl() {
      this.loadingTtl = true

      try {
        const res = await fetch(window.APP_BASE + '/api/blacklist_ttl')

        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        const data = await res.json()
        this.ttlItems = data.items

        this.escSaved = {
          multiplier: data.escalation_multiplier,
          max_block_count: data.max_block_count_before_permanent,
        }
        // ไม่เขียนทับสิ่งที่ผู้ใช้กำลังพิมพ์ค้างอยู่ระหว่างกดบันทึก
        if (!this.isSubmittingEsc) this.escForm = { ...this.escSaved }

        this.ttlError = ''
      } catch (err) {
        this.ttlError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด blacklist TTL ไม่สำเร็จ', err)
      } finally {
        this.loadingTtl = false
        this.buildPolicyItems()
      }
    },

    // ─── นโยบาย escalation ───

    // ใช้ประเภทที่ "มีวันหมดอายุ" ตัวแรกเป็นตัวอย่าง — ถ้าเลือกประเภทที่ตั้งถาวรไว้
    // ตัวอย่างจะขึ้นว่าถาวรทุกครั้ง ซึ่งไม่ช่วยให้เห็นผลของตัวคูณเลย
    get escSampleItem() {
      return this.ttlItems.find(i => i.ttl_seconds !== null && i.ttl_seconds > 0) || null
    },

    get escSampleKey() {
      return this.escSampleItem ? this.escSampleItem.detection_type : '-'
    },

    get escSampleBase() {
      return this.escSampleItem ? this.escSampleItem.ttl_seconds : 3600
    },

    // เฉพาะแถวตัวอย่าง escalation — ค่าที่คูณแล้วโตเป็นหลักพันชั่วโมงได้
    // ถ้าใช้ formatTtl ตัวเดิมจะขึ้นว่า "87600 ชั่วโมง" ซึ่งอ่านแล้วไม่เห็นภาพ
    // (ไม่ไปแตะ formatTtl เพราะคอลัมน์ "ระยะเวลา Block" ต้องคงหน่วยเดิมที่ตรงกับช่องกรอกใน modal)
    formatEscTtl(seconds) {
      const DAY = 86400
      const YEAR = 365 * DAY

      if (seconds >= YEAR) {
        const y = seconds / YEAR
        return (Number.isInteger(y) ? y : y.toFixed(1)) + ' ปี'
      }
      if (seconds >= 2 * DAY) {
        const d = seconds / DAY
        return (Number.isInteger(d) ? d : d.toFixed(1)) + ' วัน'
      }
      return this.formatTtl(seconds)
    },

    escValid() {
      const m = this.escForm.multiplier
      const c = this.escForm.max_block_count
      return Number.isInteger(m) && m >= 1 && m <= 100
          && Number.isInteger(c) && c >= 1 && c <= 1000
    },

    escChanged() {
      return this.escForm.multiplier !== this.escSaved.multiplier
          || this.escForm.max_block_count !== this.escSaved.max_block_count
    },

    // คิดแบบเดียวกับ blacklist_policy.escalated_ttl_seconds ฝั่ง Python เป๊ะ ๆ
    // (base × multiplier^(n-1) ตัดที่เพดาน 10 ปี · n เกิน max = ถาวร)
    // ถ้าสูตรสองฝั่งหลุดจากกันเมื่อไร ตัวอย่างจะโกหกผู้ใช้ทันที
    escPreview() {
      if (!this.escValid()) return []

      const MAX_TTL = 10 * 365 * 24 * 3600
      const base = this.escSampleBase
      const { multiplier, max_block_count } = this.escForm

      // โชว์ครั้งแรก ๆ ไม่เกิน 5 ช่อง แล้วปิดท้ายด้วยครั้งที่กลายเป็นถาวรเสมอ
      const shown = Math.min(max_block_count, 5)
      const steps = []

      for (let n = 1; n <= shown; n++) {
        const ttl = Math.min(base * Math.pow(multiplier, n - 1), MAX_TTL)
        steps.push({ n: String(n), label: this.formatEscTtl(ttl), permanent: false })
      }

      // มีครั้งที่ถูกข้ามไป (max มากกว่าที่โชว์ไหว) บอกให้รู้ว่าไม่ได้ต่อกัน
      if (max_block_count > shown) {
        steps.push({ n: '…', label: '…', permanent: false })
      }

      steps.push({ n: `${max_block_count + 1} ขึ้นไป`, label: 'ถาวร', permanent: true })
      return steps
    },

    async saveEscalation() {
      if (!this.escValid() || !this.escChanged()) return

      this.isSubmittingEsc = true

      try {
        const res = await fetch(window.APP_BASE + '/api/escalation_policy', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            multiplier: this.escForm.multiplier,
            max_block_count: this.escForm.max_block_count,
          }),
        })

        const data = await res.json().catch(() => ({}))

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'บันทึกนโยบาย escalation ไม่สำเร็จ')
          return
        }

        this.escSaved = { ...this.escForm }
        this.$store.ui.success(
          `ตั้ง escalation — คูณ ×${this.escSaved.multiplier} · ` +
          `เกิน ${this.escSaved.max_block_count} ครั้งบล็อกถาวร (มีผลกับการบล็อกครั้งถัดไป)`
        )
      } catch (err) {
        console.error('บันทึกนโยบาย escalation ไม่สำเร็จ', err)
        this.$store.ui.error('บันทึกนโยบาย escalation ไม่สำเร็จ')
      } finally {
        this.isSubmittingEsc = false
      }
    },

    openPolicyEditModal(item) {
      this.editingPolicy = item

      // แปลงวินาทีกลับเป็นตัวเลข+หน่วยที่คนกรอก (วัน > ชั่วโมง > นาที ตามที่หารลงตัว)
      // undefined = ไม่มีแถว TTL (ช่องนี้จะถูกซ่อนอยู่แล้ว) — ตั้งเป็นชั่วโมงไว้เฉย ๆ
      this.policyForm = {
        severity: item.severity || 'LOW',
        duration: item.ttl_seconds === undefined
          ? newDuration('hours')
          : durationFromSeconds(item.ttl_seconds),
      }

      this.showPolicyEditModal = true
    },

    closePolicyEditModal() {
      this.showPolicyEditModal = false
      this.editingPolicy = null
    },

    canSubmitPolicy() {
      if (!this.editingPolicy) return false
      if (!this.editingPolicy.hasTtl) return true
      return isValidDuration(this.policyForm.duration)
    },

    async savePolicy() {
      if (!this.editingPolicy) return

      const item = this.editingPolicy
      const label = this.attackLabel(item.key)

      const ttl_seconds = durationSeconds(this.policyForm.duration)   // null = ถาวร

      // ยิงเฉพาะฝั่งที่ค่าเปลี่ยนจริง — เปิด modal มาแก้อย่างเดียวแล้วกดบันทึก จะไม่ไปแตะ
      // updated_at ของอีกตารางและไม่ล้าง cache ของฝั่งที่ไม่ได้แก้โดยไม่จำเป็น
      const jobs = []

      if (item.hasSeverity && this.policyForm.severity !== item.severity) {
        jobs.push({
          what: 'ระดับความรุนแรง',
          url: window.APP_BASE + `/api/alert_severity/${item.key}`,
          body: { severity: this.policyForm.severity },
          done: `ระดับความรุนแรง = ${this.policyForm.severity}`,
        })
      }

      if (item.hasTtl && ttl_seconds !== item.ttl_seconds) {
        jobs.push({
          what: 'ระยะเวลา Block',
          url: window.APP_BASE + `/api/blacklist_ttl/${item.key}`,
          body: { ttl_seconds },
          done: `ระยะเวลา Block = ${this.formatTtl(ttl_seconds)}`,
        })
      }

      if (jobs.length === 0) {
        this.closePolicyEditModal()
        return
      }

      this.isSubmittingPolicy = true

      try {
        const saved = []

        // เป็นคนละ endpoint กัน ไม่มี transaction ครอบ — ยิงเรียงกันแล้วหยุดทันทีที่ตัวใดพลาด
        // ตัวที่ผ่านไปก่อนหน้ามีผลไปแล้ว จึงโหลดใหม่ทั้งคู่ให้ตารางตรงกับของจริงเสมอ
        for (const job of jobs) {
          const res = await fetch(job.url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(job.body),
          })

          const data = await res.json().catch(() => ({}))

          if (!res.ok) {
            this.$store.ui.error(data.detail || `อัปเดต${job.what}ไม่สำเร็จ`)
            await this.loadPolicy()
            return
          }

          saved.push(job.done)
        }

        await this.loadPolicy()
        this.closePolicyEditModal()
        this.$store.ui.success(`ตั้ง ${label} — ${saved.join(' · ')} แล้ว`)

      } catch (err) {
        console.error('อัปเดตความรุนแรง/ระยะเวลา Block ไม่สำเร็จ', err)
        this.$store.ui.error('อัปเดตความรุนแรง / ระยะเวลา Block ไม่สำเร็จ')
        await this.loadPolicy()
      } finally {
        this.isSubmittingPolicy = false
      }
    },

    categoryLabels: {
      auth: 'Auth Log',
      web: 'Web Access Log',
      firewall: 'Firewall Log',
      login: 'Dashboard Login',
    },

    ruleLabels: {
      ssh_brute_force: 'SSH Brute Force',
      sudo_failed: 'Sudo Authentication Failure',
      web_sql_injection: 'SQL Injection',
      web_xss: 'Cross-Site Scripting (XSS)',
      web_path_traversal: 'Path Traversal',
      web_command_injection: 'Command Injection',
      web_http_flood: 'HTTP Flood (App-level DoS)',
      firewall_port_scan: 'Port Scan',
      firewall_deny_rate: 'Firewall Deny Flood',
      login_lockout: 'Login Lockout',
    },

    categoryLabel(category) {
      return this.categoryLabels[category] || category
    },

    ruleLabel(ruleKey) {
      return this.ruleLabels[ruleKey] || ruleKey
    },

    formatWindow(seconds) {
      if (!seconds) return '-'

      if (seconds % 60 === 0) {
        return (seconds / 60) + ' นาที'
      }

      return seconds + ' วินาที'
    },

    groupRules() {
      const groups = {}

      for (const rule of this.rules) {
        const category = rule.category || 'other'

        if (!groups[category]) {
          groups[category] = []
        }

        groups[category].push(rule)
      }

      this.groupedRules = Object.keys(groups)
        .sort()
        .map(category => ({ category, items: groups[category] }))
    },

    async loadRules() {
      this.loadingRules = true

      try {
        const res = await fetch(window.APP_BASE + '/api/rules')

        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        this.rules = await res.json()
        this.groupRules()
        this.rulesError = ''
      } catch (err) {
        this.rulesError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด rules ไม่สำเร็จ', err)
      } finally {
        this.loadingRules = false
      }
    },

    openEditModal(rule) {
      this.editing = rule
      this.form = {
        window_seconds: rule.window_seconds,
        threshold: rule.threshold,
        is_active: rule.is_active,
      }
      this.showEditModal = true
    },

    closeEditModal() {
      this.showEditModal = false
      this.editing = null
    },

    canSubmit() {
      return this.form.window_seconds > 0 && this.form.threshold > 0
    },

    // ── คืนค่า default ────────────────────────────────────────────────
    // ทั้งสองปุ่มยิง endpoint เดียวกัน ต่างกันแค่ส่ง rule_key มาด้วยหรือไม่
    async restoreRules(ruleKey) {
      this.isRestoring = true

      try {
        const res = await fetch(window.APP_BASE + '/api/rules_restore_defaults', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(ruleKey ? { rule_key: ruleKey } : {}),
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'คืนค่า default ไม่สำเร็จ')
          return false
        }

        await this.loadRules()
        this.$store.ui.success(data.message || 'คืนค่า default แล้ว')
        return true

      } catch (err) {
        console.error('คืนค่า default ไม่สำเร็จ', err)
        this.$store.ui.error('คืนค่า default ไม่สำเร็จ')
        return false
      } finally {
        this.isRestoring = false
      }
    },

    async restoreAllRules() {
      const ok = await this.$store.ui.confirm({
        title: 'คืนค่า default ของ detection rule ทั้งหมด',
        message: 'Window / Threshold / สถานะเปิด-ปิด ของทุก rule จะกลับเป็นค่าตั้งต้นของระบบ '
               + 'ค่าที่ปรับเองไว้จะหายทั้งหมด และมีผลกับ detector ทันที',
        detail: this.rules.filter(r => r.is_default).length + ' rule',
        confirmText: 'คืนค่า default',
        danger: true,
      })
      if (!ok) return

      await this.restoreRules(null)
    },

    async restoreOneRule() {
      if (!this.editing) return

      const rule = this.editing
      const ok = await this.$store.ui.confirm({
        title: `คืนค่า default ของ ${this.ruleLabel(rule.rule_key)}`,
        message: 'Window / Threshold / สถานะเปิด-ปิด ของ rule นี้จะกลับเป็นค่าตั้งต้นของระบบ '
               + 'และมีผลกับ detector ทันที',
        detail: rule.rule_key,
        confirmText: 'คืนค่า default',
        danger: true,
      })
      if (!ok) return

      if (await this.restoreRules(rule.rule_key)) {
        this.closeEditModal()
      }
    },

    async saveRule() {
      if (!this.editing) return

      this.isSubmitting = true

      try {
        const res = await fetch(window.APP_BASE + `/api/rules/${this.editing.rule_key}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(this.form),
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'อัปเดต rule ไม่สำเร็จ')
          return
        }

        const ruleKey = this.editing.rule_key
        await this.loadRules()
        this.closeEditModal()
        this.$store.ui.success(`บันทึก rule ${ruleKey} แล้ว (มีผลทันที)`)

      } catch (err) {
        console.error('อัปเดต rule ไม่สำเร็จ', err)
        this.$store.ui.error('อัปเดต rule ไม่สำเร็จ')
      } finally {
        this.isSubmitting = false
      }
    },
  }
}
