


const VIS_COLORS = [
  '#6092c0', '#d36086', '#9170b8', '#ca8eae', '#d6bf57', '#b9a888', '#da8b45',
]

const TZ = 'Asia/Bangkok'

function dashboardApp() {
  return {
    alerts         : [],
    agents         : [],
    severityCounts : { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },


    totalAlerts : 0,
    todayAlerts : 0,
    dailyStats  : [],
    attackTypes : [],


    loading   : true,
    loadError : '',

    get alertsToday() {
      return this.todayAlerts
    },

    get agentsOnline() {
      return this.agents.filter(a => a.status === 'online').length
    },


    get dailyCounts() {

      return this.dailyStats.map(day => ({
        key   : day.date,
        label : new Date(day.date + 'T00:00:00+07:00')
          .toLocaleDateString('th-TH', { timeZone: TZ, day: 'numeric', month: 'numeric' }),
        count : day.count,
      }))
    },


    get dailyMax() {
      return Math.max(1, ...this.dailyCounts.map(b => b.count))
    },


    get attackTypeStats() {

      const sorted = this.attackTypes


      const shown = sorted.slice(0, 6)
      const rest  = sorted.slice(6)

      if (rest.length > 0) {
        shown.push([
          'อื่น ๆ (' + rest.length + ' ประเภท)',
          rest.reduce((sum, entry) => sum + entry[1], 0),
        ])
      }

      const total = this.totalAlerts || 1
      let start = 0

      return shown.map(([name, count], index) => {
        const pct = (count / total) * 100


        const segment = { name, count, pct, start, color: VIS_COLORS[index % VIS_COLORS.length] }

        start += pct
        return segment
      })
    },


    get donutMarkup() {
      const arcs = this.attackTypeStats.map(seg =>
        '<circle class="donut-seg" cx="21" cy="21" r="15.9155"' +
        ' stroke="' + seg.color + '"' +
        ' stroke-dasharray="' + seg.pct + ' ' + (100 - seg.pct) + '"' +
        ' stroke-dashoffset="' + (-seg.start) + '"></circle>'
      )

      return '<circle class="donut-track" cx="21" cy="21" r="15.9155"></circle>' + arcs.join('')
    },

    async loadAll() {
      const results = await Promise.allSettled([
        this.loadAlerts(), this.loadStats(), this.loadAgents(),
      ])


      const failed = results
        .filter(r => r.status === 'rejected')
        .map(r => r.reason && r.reason.message)
        .filter(Boolean)

      this.loadError = failed.join(' / ')
      this.loading   = false
    },

    async loadAlerts() {
      try {

        const res = await fetch(window.APP_BASE + '/api/alerts?per_page=5')

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `โหลด alert ไม่สำเร็จ (${res.status})`)
        }

        this.alerts = (await res.json()).items || []
      } catch (err) {
        console.error('โหลด alert ไม่สำเร็จ', err)
        throw new Error(err.message || 'โหลด alert ไม่สำเร็จ')
      }
    },

    async loadStats() {
      try {
        const res = await fetch(window.APP_BASE + '/api/alerts_stats')

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `โหลดสถิติ alert ไม่สำเร็จ (${res.status})`)
        }

        const stats = await res.json()
        this.totalAlerts    = stats.total
        this.todayAlerts    = stats.today
        this.severityCounts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0, ...stats.severity_counts }
        this.dailyStats     = stats.daily || []
        this.attackTypes    = stats.attack_types || []
      } catch (err) {
        console.error('โหลดสถิติ alert ไม่สำเร็จ', err)
        throw new Error(err.message || 'โหลดสถิติ alert ไม่สำเร็จ')
      }
    },

    async loadAgents() {
      try {
        const res = await fetch(window.APP_BASE + '/api/agents')

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `โหลด Client Server ไม่สำเร็จ (${res.status})`)
        }

        this.agents = await res.json()
      } catch (err) {
        console.error('โหลด agent ไม่สำเร็จ', err)
        throw new Error(err.message || 'โหลด Client Server ไม่สำเร็จ')
      }
    },

  }
}
