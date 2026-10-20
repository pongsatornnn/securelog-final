
function settingsApp() {
  return {
    items: [],
    groups: [],


    drafts: {},
    revealed: [],

    loading: true,
    loadError: '',
    isSaving: false,


    selects: {},


    models: { list: [], busy: false, note: '' },

    testing: null,
    testResults: {},


    redis: {
      open: false,
      mode: 'generate',     // 'manual' = พิมพ์เอง · 'generate' = ให้ server สุ่มให้
      current: '',          // รหัสเดิมที่พิมพ์ยืนยัน — ไม่เก็บค้างไว้หลังปิด popup
      manual: '',
      confirm: '',
      generated: '',
      busy: false,
      error: '',
      info: null,           // ผล preflight: ต่อ Redis ได้ไหม เขียนไฟล์ได้ไหม
      result: null,         // ผลสำเร็จ: รหัสใหม่ + ชื่อไฟล์สำรอง + คำสั่ง restart
    },


    keyModal: { open: false, item: null, current: '', next: '', confirm: '', busy: false, error: '', success: false },


    restart: { info: null, busy: false },


    history: { open: false, key: '', label: '', rows: [], busy: false, error: '' },

    actionLabel(row) {
      const action = { set: 'ตั้งค่า', reset: 'คืนค่า .env', rotate: 'เปลี่ยนรหัสของจริง' }[row.action] || row.action
      const source = { settings: '', rules: ' (หน้า Rules)', startup: ' (ตอนระบบ start)', cli: ' (สคริปต์)' }[row.source] || ''
      return action + source
    },

    async openHistory(item) {
      this.history = { open: true, key: item.key, label: item.label, rows: [], busy: true, error: '' }

      try {
        const res = await fetch(window.APP_BASE + '/api/settings/history?setting_key=' + encodeURIComponent(item.key))
        if (!res.ok) throw new Error(`เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        this.history.rows = (await res.json()).items
      } catch (err) {
        this.history.error = 'โหลดประวัติไม่สำเร็จ: ' + err.message
      } finally {
        this.history.busy = false
      }
    },

    closeHistory() { this.history.open = false },

    dirtyCount() { return Object.keys(this.drafts).length },

    async loadRestartStatus() {
      this.restart.busy = true

      try {
        const res = await fetch(window.APP_BASE + '/api/settings/restart-status')
        if (!res.ok) throw new Error(`เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        this.restart.info = await res.json()
      } catch (err) {

        console.error('ตรวจสถานะ service ไม่ได้', err)
        this.restart.info = null
      } finally {
        this.restart.busy = false
      }
    },


    passwordProblem(value) {
      if (!value) return 'ยังไม่ได้กรอกรหัสใหม่'
      if (value.length < 12) return 'รหัสสั้นเกินไป ต้องยาวอย่างน้อย 12 ตัวอักษร'
      if (value.length > 128) return 'รหัสยาวเกิน 128 ตัวอักษร'
      if (!/^[A-Za-z0-9_\-.~@%+=:,/]+$/.test(value)) return 'รหัสมีอักขระที่ใช้ไม่ได้ — ห้ามเว้นวรรคและ # \' " $ ` \\ !'
      if (new Set(value).size < 6) return 'รหัสซ้ำตัวอักษรเดิมมากเกินไป'
      return ''
    },


    openKeyModal(item) {
      this.keyModal = { open: true, item, current: '', next: '', confirm: '', busy: false, error: '', success: false }
    },

    closeKeyModal() {
      if (this.keyModal.busy) return
      this.keyModal.open = false
    },

    keyModalProblem() {
      const m = this.keyModal
      if (!m.item) return ''

      if (m.item.confirm_current && !m.current) return 'ต้องกรอกรหัสเดิมก่อน'

      if (m.item.password_rules) {
        const problem = this.passwordProblem(m.next)
        if (problem) return problem
      } else if (!m.next) {
        return 'ยังไม่ได้กรอกค่าใหม่'
      }

      if (m.next !== m.confirm) return 'ยืนยันรหัสใหม่ไม่ตรงกัน'
      return ''
    },

    async submitKeyModal() {
      const m = this.keyModal
      if (m.busy || this.keyModalProblem()) return

      m.busy = true
      m.error = ''

      try {
        const res = await fetch(window.APP_BASE + '/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            values: { [m.item.key]: m.next },
            current_values: { [m.item.key]: m.current },
          }),
        })

        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'บันทึกไม่สำเร็จ')

        m.success = true
        await this.loadSettings()

        setTimeout(() => { this.keyModal.open = false; this.keyModal.success = false }, 1500)
      } catch (err) {
        m.error = err.message
      } finally {
        m.busy = false
      }
    },

    redisPassword() {
      return this.redis.mode === 'manual' ? this.redis.manual : this.redis.generated
    },


    redisProblem() {
      if (!this.redis.current && !this.redisPassword()) return ''
      if (!this.redis.current) return 'ต้องกรอกรหัสเดิมก่อน'
      if (!this.redisPassword()) return ''

      const problem = this.passwordProblem(this.redisPassword())
      if (problem) return problem


      if (this.redis.mode === 'manual' && this.redis.manual !== this.redis.confirm) return 'ยืนยันรหัสใหม่ไม่ตรงกัน'
      return ''
    },


    redisPasswordReady() {
      return !!(this.redis.info && this.redis.info.ok)
        && !!this.redis.current
        && !!this.redisPassword()
        && !this.redisProblem()
    },

    openRedisModal() {
      Object.assign(this.redis, {
        open: true, mode: 'generate', current: '', manual: '', confirm: '',
        generated: '', busy: false, error: '', result: null,
      })
    },

    closeRedisModal() {
      if (this.redis.busy) return
      this.redis.open = false

      Object.assign(this.redis, { current: '', manual: '', confirm: '', generated: '', result: null, error: '' })
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

    async loadRedisInfo() {
      try {
        const res = await fetch(window.APP_BASE + '/api/settings/redis-admin-password')
        if (!res.ok) throw new Error(`เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        this.redis.info = await res.json()
      } catch (err) {
        console.error('เช็คความพร้อมของการเปลี่ยนรหัส Redis ไม่ได้', err)
        this.redis.info = { ok: false, username: 'admin', problem: 'เช็คความพร้อมไม่ได้ — ' + err.message }
      }
    },

    async generateRedisPassword() {
      this.redis.busy = true

      try {
        const res = await fetch(window.APP_BASE + '/api/settings/redis-admin-password/generate', { method: 'POST' })
        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'สุ่มรหัสไม่สำเร็จ')
          return
        }

        this.redis.generated = data.password
      } catch (err) {
        console.error('สุ่มรหัสไม่สำเร็จ', err)
        this.$store.ui.error('สุ่มรหัสไม่สำเร็จ')
      } finally {
        this.redis.busy = false
      }
    },


    async rotateRedisPassword() {
      if (this.redis.busy || !this.redisPasswordReady()) return

      this.redis.busy = true
      this.redis.error = ''
      const password = this.redisPassword()

      try {
        const res = await fetch(window.APP_BASE + '/api/settings/redis-admin-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ password, current_password: this.redis.current }),
        })

        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || 'เปลี่ยนรหัสไม่สำเร็จ')


        this.redis.result = { ...data, password }
        this.redis.current = ''       // รหัสเดิมใช้ไม่ได้แล้ว ไม่มีเหตุให้ค้างอยู่ในช่อง
        this.redis.manual = ''
        this.redis.confirm = ''
        this.redis.generated = ''

        this.$store.ui.success(data.message)
        await this.loadRedisInfo()
        await this.loadRestartStatus()      // ตอนนี้ทุกตัวที่เหลือกลายเป็น "ค้างรีสตาร์ต" แล้ว
      } catch (err) {
        console.error('เปลี่ยนรหัสไม่สำเร็จ', err)
        this.redis.error = err.message      // ค้างไว้ใน popup ไม่ใช่ toast ที่หายเอง
      } finally {
        this.redis.busy = false
      }
    },


    currentValue(item) {
      return this.drafts[item.key] !== undefined ? this.drafts[item.key] : item.value
    },


    optionsFor(item) {
      const live = item.key === 'gemini_model' && this.models.list.length ? this.models.list : null
      const options = live ? live.slice() : item.choices.map(name => ({ name, label: name }))

      const current = this.currentValue(item)
      if (current && !options.some(o => o.name === current)) {
        options.unshift({ name: current, label: current + ' (ค่าที่ตั้งไว้ตอนนี้)' })
      }

      return options
    },


    syncSelects() {
      for (const item of this.items) {
        if (!item.choices.length) continue
        this.selects[item.key] = this.currentValue(item) || '__custom__'
      }
    },


    applySelectValue(item, el) {
      const value = this.selects[item.key]
      this.optionsFor(item)
      this.$nextTick(() => { el.value = value })
    },

    onSelectChange(item, value) {
      this.selects[item.key] = value

      if (value !== '__custom__') this.setDraft(item, value)
    },


    async loadGeminiModels() {
      this.models.busy = true

      try {
        const res = await fetch(window.APP_BASE + '/api/settings/gemini/models')
        const data = await res.json()

        if (!res.ok || !data.ok) {
          this.models.list = []
          this.models.note = 'ดึงรายชื่อโมเดลจาก Google ไม่ได้ (ใช้รายชื่อตั้งต้นแทน) — '
            + (data.message || data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
          return
        }

        this.models.list = data.models

        this.models.note = ''
      } catch (err) {
        console.error('ดึงรายชื่อโมเดลไม่สำเร็จ', err)
        this.models.list = []
        this.models.note = 'ดึงรายชื่อโมเดลไม่ได้ (ใช้รายชื่อตั้งต้นแทน) — ' + err.message
      } finally {
        this.models.busy = false
        this.syncSelects()
      }
    },

    setDraft(item, value) {

      if (!item.is_secret && value === item.value) {
        delete this.drafts[item.key]
        return
      }
      this.drafts[item.key] = value
    },


    canFillOaId() {
      const r = this.testResults.line
      if (!r || !r.ok || !r.detail || !r.detail.basic_id) return false

      const item = this.items.find(i => i.key === 'line_oa_id')
      if (!item) return false

      const current = this.drafts.line_oa_id !== undefined ? this.drafts.line_oa_id : item.value
      return current !== r.detail.basic_id
    },

    fillOaId() {
      const item = this.items.find(i => i.key === 'line_oa_id')
      if (item) this.setDraft(item, this.testResults.line.detail.basic_id)
    },

    toggleReveal(key) {
      const i = this.revealed.indexOf(key)
      if (i === -1) this.revealed.push(key)
      else this.revealed.splice(i, 1)
    },

    discardDrafts() {
      this.drafts = {}
      this.revealed = []
      this.syncSelects()
    },

    groupItems() {
      const order = []
      const byGroup = {}

      for (const item of this.items) {
        if (!byGroup[item.group]) {
          byGroup[item.group] = { name: item.group, label: item.group_label, items: [] }
          order.push(item.group)
        }
        byGroup[item.group].items.push(item)
      }

      this.groups = order.map(name => byGroup[name])
    },

    async loadSettings() {
      this.loading = true

      try {
        const res = await fetch(window.APP_BASE + '/api/settings')
        if (!res.ok) {
          const data = await res.json().catch(() => ({}))
          throw new Error(data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}`)
        }

        const data = await res.json()
        this.items = data.items
        this.groupItems()
        this.discardDrafts()
        this.loadError = ''


        if (this.items.some(i => i.key === 'gemini_api_key' && i.is_set)) this.loadGeminiModels()


        this.loadRedisInfo()
        this.loadRestartStatus()
      } catch (err) {
        this.loadError = err.message || 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้'
        console.error('โหลดค่าตั้งไม่สำเร็จ', err)
      } finally {
        this.loading = false
      }
    },

    async saveSettings() {
      if (this.dirtyCount() === 0) return

      this.isSaving = true

      try {
        const res = await fetch(window.APP_BASE + '/api/settings', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ values: this.drafts }),
        })

        const data = await res.json()

        if (!res.ok) {
          this.$store.ui.error(data.detail || 'บันทึกไม่สำเร็จ')
          return
        }

        const n = this.dirtyCount()
        await this.loadSettings()

        this.testResults = {}
        this.$store.ui.success(`บันทึก ${n} รายการแล้ว — มีผลทันที ไม่ต้องรีสตาร์ต`)
      } catch (err) {
        console.error('บันทึกไม่สำเร็จ', err)
        this.$store.ui.error('บันทึกไม่สำเร็จ')
      } finally {
        this.isSaving = false
      }
    },

    async testService(service) {
      this.testing = service

      try {
        const res = await fetch(window.APP_BASE + `/api/settings/test/${service}`, { method: 'POST' })
        const data = await res.json()

        if (!res.ok) {
          this.testResults[service] = { ok: false, message: data.detail || `เซิร์ฟเวอร์ตอบกลับ ${res.status}` }
          return
        }

        this.testResults[service] = data
      } catch (err) {
        console.error('ทดสอบไม่สำเร็จ', err)
        this.testResults[service] = { ok: false, message: 'เชื่อมต่อเซิร์ฟเวอร์ไม่ได้' }
      } finally {
        this.testing = null
      }
    },
  }
}
