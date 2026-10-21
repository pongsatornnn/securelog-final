// ย้ายมาจาก templates/rules.html (บล็อก <script> เดิม)
// แท็บที่มีในหน้านี้ — ใช้เป็นทั้งค่าใน state และชื่อใน URL hash
const RULE_TABS = ['rules', 'policy', 'agent-rules']


const LEGACY_TAB_ALIASES = { ttl: 'policy', severity: 'policy' }

function rulesApp() {
  return {
    tab: 'rules',


    initTab() {
      const fromHash = window.location.hash.replace('#', '')
      const name = LEGACY_TAB_ALIASES[fromHash] || fromHash
      if (RULE_TABS.includes(name)) this.tab = name
    },

    selectTab(name) {
      this.tab = name


      history.replaceState(null, '', name === 'rules' ? window.location.pathname : '#' + name)
    },

    rules: [],
    groupedRules: [],
    agentRules: [],
    ruleAgents: [],
    disabledByAgent: {},
    selectedAgentId: '',
    agentRuleDisabled: [],
    loadingAgentRules: true,
    agentRulesError: '',
    savingAgentRules: false,
    showEditModal: false,
    editing: null,
    isSubmitting: false,
    isRestoring: false,


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


    ttlItems: [],
    severityItems: [],
    policyItems: [],

    showPolicyEditModal: false,
    editingPolicy: null,
    isSubmittingPolicy: false,


    escSaved: { multiplier: 2, max_block_count: 5 },
    escForm: { multiplier: 2, max_block_count: 5 },
    isSubmittingEsc: false,

    policyForm: {
      severity: 'LOW',

      response: 'block',

      notify_line: true,


      duration: newDuration('hours'),
    },


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
      if (this.ttlError) parts.push('การตอบสนอง: ' + this.ttlError)
      return parts.join(' · ')
    },


    buildPolicyItems() {
      const bySeverity = new Map(this.severityItems.map(i => [i.severity_key, i]))
      const byTtl = new Map(this.ttlItems.map(i => [i.detection_type, i]))


      const keys = [...new Set([...bySeverity.keys(), ...byTtl.keys()])].sort()

      this.policyItems = keys.map(key => {
        const sev = bySeverity.get(key)
        const ttl = byTtl.get(key)


        const updated = [sev && sev.updated_at, ttl && ttl.updated_at].filter(Boolean).sort()

        return {
          key,
          hasSeverity: !!sev,
          severity: sev ? sev.severity : null,
          hasTtl: !!ttl,
          ttl_seconds: ttl ? ttl.ttl_seconds : undefined,   // null = ถาวร (ต่างจาก undefined = ไม่มีแถว)

          auto_block: ttl ? ttl.auto_block !== false : true,

          notify_line: ttl ? ttl.notify_line !== false : true,
          updated_at: updated.length ? updated[updated.length - 1] : null,
        }
      })
    },


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


    get escSampleItem() {
      return this.ttlItems.find(i => i.ttl_seconds !== null && i.ttl_seconds > 0) || null
    },

    get escSampleKey() {
      return this.escSampleItem ? this.escSampleItem.detection_type : '-'
    },

    get escSampleBase() {
      return this.escSampleItem ? this.escSampleItem.ttl_seconds : 3600
    },


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


    escPreview() {
      if (!this.escValid()) return []

      const MAX_TTL = 10 * 365 * 24 * 3600
      const base = this.escSampleBase
      const { multiplier, max_block_count } = this.escForm


      const shown = Math.min(max_block_count, 5)
      const steps = []

      for (let n = 1; n <= shown; n++) {
        const ttl = Math.min(base * Math.pow(multiplier, n - 1), MAX_TTL)
        steps.push({ n: String(n), label: this.formatEscTtl(ttl), permanent: false })
      }


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


      this.policyForm = {
        severity: item.severity || 'LOW',
        response: item.auto_block === false ? 'alert_only' : 'block',
        notify_line: item.notify_line !== false,


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

      if (this.policyForm.response === 'alert_only') return true
      return isValidDuration(this.policyForm.duration)
    },

    async savePolicy() {
      if (!this.editingPolicy) return

      const item = this.editingPolicy
      const label = this.attackLabel(item.key)

      const auto_block = this.policyForm.response !== 'alert_only'


      const ttl_seconds = auto_block
        ? durationSeconds(this.policyForm.duration)   // null = ถาวร
        : item.ttl_seconds


      const notify_line = auto_block ? item.notify_line : this.policyForm.notify_line


      const jobs = []

      if (item.hasSeverity && this.policyForm.severity !== item.severity) {
        jobs.push({
          what: 'ระดับความรุนแรง',
          url: window.APP_BASE + `/api/alert_severity/${item.key}`,
          body: { severity: this.policyForm.severity },
          done: `ระดับความรุนแรง = ${this.policyForm.severity}`,
        })
      }


      if (item.hasTtl && (ttl_seconds !== item.ttl_seconds
                          || auto_block !== item.auto_block
                          || notify_line !== item.notify_line)) {
        jobs.push({
          what: 'การตอบสนอง',
          url: window.APP_BASE + `/api/blacklist_ttl/${item.key}`,
          body: { ttl_seconds, auto_block, notify_line },
          done: auto_block
            ? `Block ${this.formatTtl(ttl_seconds)}`
            : 'แจ้งเตือนอย่างเดียว (ไม่ Block)' + (notify_line ? ' + แจ้ง LINE' : ' · ไม่แจ้ง LINE'),
        })
      }

      if (jobs.length === 0) {
        this.closePolicyEditModal()
        return
      }

      this.isSubmittingPolicy = true

      try {
        const saved = []


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
        console.error('อัปเดตความรุนแรง/การตอบสนอง ไม่สำเร็จ', err)
        this.$store.ui.error('อัปเดตความรุนแรง / การตอบสนอง ไม่สำเร็จ')
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

    async loadAgentRules() {
      this.loadingAgentRules = true
      try {
        const res = await fetch(window.APP_BASE + '/api/agent_rule_settings')
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)

        this.ruleAgents = data.agents
        this.agentRules = data.rules
        this.disabledByAgent = data.disabled_by_agent
        if (!this.ruleAgents.some(agent => agent.agent_id === this.selectedAgentId)) {
          this.selectedAgentId = this.ruleAgents[0]?.agent_id || ''
        }
        this.selectRuleAgent()
        this.agentRulesError = ''
      } catch (err) {
        this.agentRulesError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลด Rule ราย Client ไม่สำเร็จ', err)
      } finally {
        this.loadingAgentRules = false
      }
    },

    selectRuleAgent() {
      this.agentRuleDisabled = [...(this.disabledByAgent[this.selectedAgentId] || [])]
    },

    agentRuleEnabled(ruleKey) {
      return !this.agentRuleDisabled.includes(ruleKey)
    },

    toggleAgentRule(ruleKey, enabled) {
      const disabled = new Set(this.agentRuleDisabled)
      if (enabled) disabled.delete(ruleKey)
      else disabled.add(ruleKey)
      this.agentRuleDisabled = [...disabled]
    },

    agentRulesChanged() {
      const saved = this.disabledByAgent[this.selectedAgentId] || []
      return [...saved].sort().join(',') !== [...this.agentRuleDisabled].sort().join(',')
    },

    get groupedAgentRules() {
      const categories = ['auth', 'web', 'firewall']
      return categories.map(category => ({
        category,
        items: this.agentRules.filter(rule => rule.category === category),
      })).filter(group => group.items.length)
    },

    discardAgentRuleChanges() {
      this.selectRuleAgent()
    },

    async saveAgentRules() {
      if (!this.selectedAgentId || this.savingAgentRules || !this.agentRulesChanged()) return
      this.savingAgentRules = true
      try {
        const res = await fetch(window.APP_BASE + `/api/agent_rule_settings/${encodeURIComponent(this.selectedAgentId)}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ disabled_rules: this.agentRuleDisabled }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        this.disabledByAgent[this.selectedAgentId] = data.disabled_rules
        this.agentRuleDisabled = [...data.disabled_rules]
        this.$store.ui.success(`บันทึก Rule ของ ${this.selectedAgentId} แล้ว`)
      } catch (err) {
        this.$store.ui.error(err.message || 'บันทึก Rule ราย Client ไม่สำเร็จ')
        console.error('บันทึก Rule ราย Client ไม่สำเร็จ', err)
      } finally {
        this.savingAgentRules = false
      }
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
