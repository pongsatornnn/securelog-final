function agentsApp() {
    return {
      agents: [],
      refreshTimer: null,
      filter: 'all',
      showCreateModal: false,
      showCreateSuccessModal: false,
      showDetailModal: false,
      showEditModal: false,
      showRegenModal: false,
      showGuideModal: false,
      selectedAgent: null,
      editAgentId: '',
      editError: '',
      savingEdit: false,
      regenAgentId: '',
      regenDownloadUrl: '',
      regenError: '',
      copiedRegenDownloadLink: false,
      copiedRegenDownloadCommand: false,
      editForm: {
        host_ip: '',        // แสดงอย่างเดียว ไม่ได้ส่งกลับไปที่ API (IP ที่ผูกไว้แก้ไม่ได้)
        hostname: '',
        description: '',
        is_active: true
      },
      downloadUrl: '',
      createdAgentId: '',
      copiedDownloadLink: false,
      copiedDownloadCommand: false,
      linkTtlSeconds: 120,
      linkRemaining: 0,
      linkCountdownTimer: null,
      error: '',
      creating: false,

      // สถานะการโหลดรายการ — ต้องแยก "กำลังโหลด" / "โหลดไม่สำเร็จ" / "ไม่มีข้อมูล" ออกจากกัน
      // ไม่งั้นตอน API ล่มหน้าจะขึ้นว่า "ยังไม่มี Agent" ซึ่งอ่านแล้วเข้าใจผิดว่าไม่มีเครื่องในระบบ
      loading: true,
      loadError: '',

      form: {
        hostname: '',
        description: ''
      },

      init() {
        this.loadAgents()

        this.refreshTimer = setInterval(() => {
          this.loadAgents()
        }, 3000)
      },

      async loadAgents() {
        try {
          const res = await fetch('/api/agents', {
            headers: {
              'Accept': 'application/json'
            },
            cache: 'no-store'
          })

          if (!res.ok) throw new Error('โหลด Client Server ไม่สำเร็จ')

          const data = await res.json()
          this.agents = data.map(agent => ({
            ...agent,
            is_active: this.isActive(agent.is_active)
          }))

          this.loadError = ''

          if (this.selectedAgent) {
            const latest = this.agents.find(
              agent => agent.agent_id === this.selectedAgent.agent_id
            )

            if (latest) {
              this.selectedAgent = latest
            }
          }
        } catch (err) {
          // หน้านี้ refresh เองทุก 3 วิ — ถ้าเคยโหลดสำเร็จแล้วเน็ตสะดุดรอบเดียว ไม่ต้องล้าง
          // ตารางทิ้งให้ตกใจ แค่แจ้งว่าค่าที่เห็นอาจไม่สดแล้ว
          this.loadError = err.message || 'โหลด Client Server ไม่สำเร็จ'
          console.error(err)
        } finally {
          this.loading = false
        }
      },

      filteredAgents() {
        return this.agents.filter(agent => {
          return this.filter === 'all' || agent.status === this.filter
        })
      },

      countByStatus(status) {
        return this.agents.filter(agent => agent.status === status).length
      },

      statusText(status) {
        if (status === 'online') return 'Online'
        if (status === 'offline') return 'Offline'
        if (status === 'pending') return 'Pending Setup'
        return status || '-'
      },

      openCreateModal() {
        this.error = ''
        this.downloadUrl = ''
        this.createdAgentId = ''
        this.copiedDownloadLink = false
        this.copiedDownloadCommand = false
        this.form = {
          hostname: '',
          description: ''
        }

        this.showCreateSuccessModal = false
        this.showCreateModal = true
      },

      closeCreateModal() {
        if (this.creating) return
        this.showCreateModal = false
      },

      closeCreateSuccessModal() {
        this.showCreateSuccessModal = false
        this.downloadUrl = ''
        this.createdAgentId = ''
        this.copiedDownloadLink = false
        this.copiedDownloadCommand = false
        this.stopLinkCountdown()
      },

      closeRegenModal() {
        this.showRegenModal = false
        this.regenDownloadUrl = ''
        this.regenAgentId = ''
        this.regenError = ''
        this.copiedRegenDownloadLink = false
        this.copiedRegenDownloadCommand = false
        this.stopLinkCountdown()
      },

      // นับถอยหลังอายุลิงก์ดาวน์โหลด (ตรงกับ DOWNLOAD_LINK_TTL ฝั่ง server = 2 นาที)
      // ใช้ตัวเดียวร่วมกันทั้ง modal create-success และ regen เพราะเปิดได้ทีละอัน
      startLinkCountdown() {
        this.stopLinkCountdown()
        this.linkRemaining = this.linkTtlSeconds

        this.linkCountdownTimer = setInterval(() => {
          this.linkRemaining -= 1
          if (this.linkRemaining <= 0) {
            this.linkRemaining = 0
            this.stopLinkCountdown()
          }
        }, 1000)
      },

      stopLinkCountdown() {
        if (this.linkCountdownTimer) {
          clearInterval(this.linkCountdownTimer)
          this.linkCountdownTimer = null
        }
      },

      linkExpired() {
        return this.linkRemaining <= 0
      },

      linkCountdownText() {
        const minutes = Math.floor(this.linkRemaining / 60)
        const seconds = this.linkRemaining % 60
        return `${minutes}:${String(seconds).padStart(2, '0')}`
      },

      async copyTextToClipboard(text, copiedKey) {
        if (!text) return

        try {
          await navigator.clipboard.writeText(text)
        } catch (err) {
          const textarea = document.createElement('textarea')
          textarea.value = text
          textarea.style.position = 'fixed'
          textarea.style.opacity = '0'
          document.body.appendChild(textarea)
          textarea.select()
          document.execCommand('copy')
          document.body.removeChild(textarea)
        }

        this[copiedKey] = true

        setTimeout(() => {
          this[copiedKey] = false
        }, 1800)
      },

      buildFullDownloadUrl(url) {
        if (!url) return ''
        return new URL(url, window.location.origin).href
      },

      buildLinuxDownloadCommand(url) {
        const fullUrl = this.buildFullDownloadUrl(url)
        if (!fullUrl) return ''
        // เครื่อง agent ยังไม่มี ca.crt ของเรา (มันอยู่ *ใน* zip ที่กำลังจะโหลด — ไก่กับไข่)
        // เลยยังตรวจ cert ปกติไม่ได้ตอน bootstrap ครั้งแรก ต้องข้ามด้วย --no-check-certificate
        // ยังเข้ารหัสผ่าน TLS อยู่ แค่ไม่ verify CA + token ใช้ได้ครั้งเดียวหมดอายุไว (2 นาที) อยู่แล้ว
        return `wget --no-check-certificate -O agent_package.zip "${fullUrl}"`
      },

      async copyToClipboard(url, copiedKey) {
        const fullUrl = this.buildFullDownloadUrl(url)
        return this.copyTextToClipboard(fullUrl, copiedKey)
      },

      copyDownloadLink(url) {
        return this.copyToClipboard(url, 'copiedDownloadLink')
      },

      copyDownloadCommand(url) {
        return this.copyTextToClipboard(this.buildLinuxDownloadCommand(url), 'copiedDownloadCommand')
      },

      copyRegenDownloadLink(url) {
        return this.copyToClipboard(url, 'copiedRegenDownloadLink')
      },

      copyRegenDownloadCommand(url) {
        return this.copyTextToClipboard(this.buildLinuxDownloadCommand(url), 'copiedRegenDownloadCommand')
      },

      // ไม่ต้องตรวจ Host IP แล้ว — ไม่มีช่องให้กรอก ระบบผูกเองจากที่ agent รายงานเข้ามาครั้งแรก
      validateAgentForm(form) {
        if (!String(form.hostname || '').trim()) return 'กรุณากรอก Hostname'

        return ''
      },

      async createAgent() {
        this.error = ''
        this.downloadUrl = ''
        this.copiedDownloadLink = false
        this.copiedDownloadCommand = false

        const validationError = this.validateAgentForm(this.form)
        if (validationError) {
          this.error = validationError
          return
        }

        this.creating = true

        try {
          const res = await fetch('/api/agents', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              hostname: this.form.hostname.trim(),
              description: this.form.description.trim() || null
            })
          })

          const data = await res.json()

          if (!res.ok) {
            throw new Error(data.detail || 'สร้าง Client Server Package ไม่สำเร็จ')
          }

          this.createdAgentId = data.agent_id || ''
          this.downloadUrl = data.download_url
          this.startLinkCountdown()

          await this.loadAgents()

          this.showCreateModal = false
          this.showCreateSuccessModal = true
        } catch (err) {
          this.error = err.message
        } finally {
          this.creating = false
        }
      },

      openEditModal(agent) {
        const latestAgent = this.agents.find(item => item.agent_id === agent.agent_id) || agent

        this.showDetailModal = false
        this.editError = ''
        this.editAgentId = latestAgent.agent_id
        this.editForm = {
          host_ip: latestAgent.host_ip || '',
          hostname: latestAgent.hostname || '',
          description: latestAgent.description || '',
          is_active: this.isActive(latestAgent.is_active) ? 'true' : 'false'
        }
        this.showEditModal = true
      },

      closeEditModal() {
        this.showEditModal = false
        this.editAgentId = ''
        this.editError = ''
      },

      async saveEditAgent() {
        if (!this.editAgentId) return

        this.editError = ''
        const validationError = this.validateAgentForm(this.editForm)
        if (validationError) {
          this.editError = validationError
          return
        }

        this.savingEdit = true

        try {
          const res = await fetch(`/api/agents/${encodeURIComponent(this.editAgentId)}`, {
            method: 'PUT',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
              hostname: this.editForm.hostname.trim(),
              description: this.editForm.description.trim() || null,
              is_active: this.editForm.is_active === 'true'
            })
          })

          const data = await res.json()
          if (!res.ok) throw new Error(data.detail || 'แก้ไข Client Server ไม่สำเร็จ')

          await this.loadAgents()
          this.closeEditModal()
        } catch (err) {
          this.editError = err.message
        } finally {
          this.savingEdit = false
        }
      },

      async regenDownload(agent) {
        const ok = await this.$store.ui.confirm({
          title: 'สร้าง Download Link ใหม่',
          message: `ลิงก์และ SECRET_TOKEN ชุดเดิมของ ${agent.hostname || agent.agent_id} จะใช้ไม่ได้ทันที ` +
                   'ถ้าเครื่องนี้ติดตั้ง Client Server ไปแล้วจะต้องติดตั้งใหม่ด้วย token ชุดใหม่',
          detail: `Agent ID: ${agent.agent_id}`,
          confirmText: 'สร้างลิงก์ใหม่',
        })
        if (!ok) return

        this.regenError = ''
        this.regenDownloadUrl = ''
        this.regenAgentId = agent.agent_id
        this.copiedRegenDownloadLink = false
        this.copiedRegenDownloadCommand = false
        this.showDetailModal = false
        this.showRegenModal = true

        try {
          const res = await fetch(`/api/agents/${encodeURIComponent(agent.agent_id)}/regen-download`, {
            method: 'POST'
          })

          const data = await res.json()
          if (!res.ok) throw new Error(data.detail || 'สร้าง Download Link ใหม่ไม่สำเร็จ')

          this.regenAgentId = data.agent_id || agent.agent_id
          this.regenDownloadUrl = data.download_url
          this.startLinkCountdown()
          await this.loadAgents()
        } catch (err) {
          this.regenError = err.message
        }
      },

      async deleteAgent(agent) {
        // log/alert ของเครื่องนี้ถูกลบไปด้วยและกู้คืนไม่ได้ — ต้องบอกจำนวนก่อนกด ไม่ใช่มารู้ทีหลัง
        // ส่วน IP ที่บล็อกไว้ "ไม่หาย" ก็ต้องบอกเหมือนกัน เพราะคนมักเข้าใจว่าลบ agent = ปลดบล็อกหมด
        const alertCount = agent.alert_count || 0
        const ok = await this.$store.ui.confirm({
          title: 'ลบ Client Server',
          message: 'ยืนยันที่จะลบ Client Server',
          // ใส่ป้ายกำกับหน้าค่า เพราะลำพัง agent_id กับ hostname ลอย ๆ 2 บรรทัดแยกไม่ออกว่าอันไหนคืออะไร
          detail:
            `Agent id : ${agent.agent_id}\nHostname : ${agent.hostname || '-'}\n` +
            `Log/Alert ที่จะถูกลบ : ${alertCount.toLocaleString('th-TH')} รายการ (กู้คืนไม่ได้)\n` +
            `IP ที่บล็อกไว้ : ยังบล็อกต่อตามกติกาเดิม ไม่ถูกปลดตาม`,
          confirmText: 'ลบ Client Server',
          danger: true,
        })
        if (!ok) return

        try {
          const res = await fetch(`/api/agents/${encodeURIComponent(agent.agent_id)}`, {
            method: 'DELETE'
          })

          const data = await res.json()
          if (!res.ok) throw new Error(data.detail || 'ลบ Client Server ไม่สำเร็จ')

          await this.loadAgents()
          this.showDetailModal = false
          this.selectedAgent = null
          this.$store.ui.success(data.message || `ลบ ${agent.agent_id} แล้ว`)
        } catch (err) {
          this.$store.ui.error(err.message)
        }
      },

      openDetail(agent) {
        const latestAgent = this.agents.find(item => item.agent_id === agent.agent_id) || agent
        this.selectedAgent = latestAgent
        this.showDetailModal = true
      },

      isActive(value) {
        if (value === false || value === 0 || value === '0') return false
        if (String(value).toLowerCase() === 'false') return false
        return true
      },

      safePercent(value) {
        const number = Number(value)

        if (!Number.isFinite(number)) return 0
        if (number < 0) return 0
        if (number > 100) return 100

        return number
      },

      formatPercent(value) {
        const number = Number(value)

        if (!Number.isFinite(number)) return '-'

        return `${number.toFixed(1)}%`
      },

      metricClass(value) {
        const number = Number(value)

        if (!Number.isFinite(number)) return 'unknown'
        if (number >= 85) return 'danger'
        if (number >= 65) return 'warn'

        return ''
      },

    }
  }
