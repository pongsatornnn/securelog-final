// ย้ายมาจาก templates/dashboard.html (บล็อก <script> เดิม)
// ชุดสีของกราฟ — ต้องตรงกับ --vis-0..6 ใน app.css (ส่วนโค้งของโดนัทกับจุดสีใน legend
// ใช้สีคนละตัวต่อรายการ จึงต้องผูกค่าสีที่ตัว element ไม่ใช่ผ่าน class)
const VIS_COLORS = [
  '#6092c0', '#d36086', '#9170b8', '#ca8eae', '#d6bf57', '#b9a888', '#da8b45',
]

const TZ = 'Asia/Bangkok'

// วันที่แบบ YYYY-MM-DD ตามเวลาไทย — ใช้เป็นคีย์จับกลุ่มรายวัน (เทียบสตริงตรง ๆ ได้)
function bangkokDate(value) {
  return new Date(value).toLocaleDateString('en-CA', { timeZone: TZ })
}

function dashboardApp() {
  return {
    alerts         : [],
    agents         : [],
    severityCounts : { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 },

    // หน้านี้ refresh เองทุก 15 วิ — แยก "โหลดครั้งแรกอยู่" ออกจาก "รอบล่าสุดพลาด"
    // เพราะสองอย่างนี้ต้องแสดงคนละแบบ (กล่องกำลังโหลด vs แถบเตือนว่าข้อมูลไม่สด)
    loading   : true,
    loadError : '',

    get alertsToday() {
      const today = bangkokDate(new Date())
      return this.alerts.filter(a => a.timestamp && bangkokDate(a.timestamp) === today).length
    },

    get agentsOnline() {
      return this.agents.filter(a => a.status === 'online').length
    },

    // ─── กราฟแท่ง: จำนวน alert ต่อวัน ย้อนหลัง 7 วัน ───

    get dailyCounts() {
      const DAYS = 7
      const buckets = []
      const byDate  = {}

      for (let i = DAYS - 1; i >= 0; i--) {
        const day = new Date(Date.now() - i * 86400000)

        const bucket = {
          key   : bangkokDate(day),
          label : day.toLocaleDateString('th-TH', { timeZone: TZ, day: 'numeric', month: 'numeric' }),
          count : 0,
        }

        byDate[bucket.key] = bucket
        buckets.push(bucket)
      }

      for (const alert of this.alerts) {
        if (!alert.timestamp) continue

        // alert ที่เก่ากว่า 7 วันไม่มีช่องให้ลง — ข้ามไป ไม่ใช่ยัดรวมกับวันแรก
        const bucket = byDate[bangkokDate(alert.timestamp)]
        if (bucket) bucket.count++
      }

      return buckets
    },

    // อย่างน้อย 1 กันหารด้วยศูนย์ตอนไม่มี alert เลยในช่วง 7 วัน
    get dailyMax() {
      return Math.max(1, ...this.dailyCounts.map(b => b.count))
    },

    // ─── โดนัท: สัดส่วนประเภทการโจมตี ───

    get attackTypeStats() {
      const counts = {}

      for (const alert of this.alerts) {
        const key = alert.attack_type || 'ไม่ระบุ'
        counts[key] = (counts[key] || 0) + 1
      }

      const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1])

      // เกิน 7 ก้อนเริ่มอ่านไม่ออก (สีเริ่มซ้ำ + legend ยาวเกินพาเนล) — ที่เหลือยุบรวมกัน
      const shown = sorted.slice(0, 6)
      const rest  = sorted.slice(6)

      if (rest.length > 0) {
        shown.push([
          'อื่น ๆ (' + rest.length + ' ประเภท)',
          rest.reduce((sum, entry) => sum + entry[1], 0),
        ])
      }

      const total = this.alerts.length || 1
      let start = 0

      return shown.map(([name, count], index) => {
        const pct = (count / total) * 100

        // start = จุดเริ่มของส่วนโค้งนี้ (หน่วยเป็น % ของเส้นรอบวง) ใช้เป็น
        // stroke-dashoffset ค่าลบ เพื่อเลื่อนส่วนโค้งไปต่อท้ายก้อนก่อนหน้า
        const segment = { name, count, pct, start, color: VIS_COLORS[index % VIS_COLORS.length] }

        start += pct
        return segment
      })
    },

    // ส่วนโค้งของโดนัทประกอบเป็นสตริงเอง (ดูเหตุผลที่ไม่ใช้ x-for ใน markup)
    // ค่าที่ประกอบเข้าไปมีแค่ตัวเลขที่คำนวณเองกับสีจาก VIS_COLORS — ไม่มีข้อความจาก
    // ฐานข้อมูลปนเข้ามา จึงไม่มีช่องให้ยัด markup แปลกปลอม (ชื่อประเภทอยู่ใน legend
    // ที่เป็น HTML ปกติและผูกด้วย x-text อยู่แล้ว)
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
      const results = await Promise.allSettled([this.loadAlerts(), this.loadAgents()])

      // ส่วนไหนพลาดก็บอกเฉพาะส่วนนั้น ไม่ทิ้งทั้งหน้า (alert กับ agent คนละ endpoint)
      const failed = results
        .filter(r => r.status === 'rejected')
        .map(r => r.reason && r.reason.message)
        .filter(Boolean)

      this.loadError = failed.join(' / ')
      this.loading   = false
    },

    async loadAlerts() {
      try {
        // ขอ 200 แถวแรกตรง ๆ — หน้านี้ใช้ 5 แถวล่าสุดกับนับสัดส่วนความรุนแรงจากก้อนนี้
        // (เท่าเดิมกับตอนที่ /api/alerts ยังคืน 200 แถวเสมอก่อนมีการแบ่งหน้า)
        const res = await fetch(window.APP_BASE + '/api/alerts?per_page=200')

        if (!res.ok) {
          const err = await res.json().catch(() => ({}))
          throw new Error(err.detail || `โหลด alert ไม่สำเร็จ (${res.status})`)
        }

        const data = (await res.json()).items || []
        this.alerts = data

        const counts = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
        for (const alert of data) {
          if (counts[alert.severity] !== undefined) {
            counts[alert.severity]++
          }
        }
        this.severityCounts = counts
      } catch (err) {
        console.error('โหลด alert ไม่สำเร็จ', err)
        throw new Error(err.message || 'โหลด alert ไม่สำเร็จ')
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
