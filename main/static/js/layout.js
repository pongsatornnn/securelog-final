// ย้ายมาจาก templates/base.html (บล็อก <script> เดิม)
// สถานะของโครงหน้า (เมนูซ้าย) — ไม่เกี่ยวกับข้อมูลของระบบ จึงเก็บที่ browser
// ย่อ/กางเมนูค้างไว้ข้ามหน้าได้ (Wazuh ก็จำสถานะนี้ให้เหมือนกัน)
function shell() {
  var KEY = 'securelog.nav.collapsed'

  return {
    navOpen: false,          // เมนูแบบ off-canvas บนจอมือถือ
    collapsed: false,        // ย่อเหลือแต่ไอคอนบนจอใหญ่

    init() {
      try {
        this.collapsed = window.localStorage.getItem(KEY) === '1'
      } catch (err) {
        /* localStorage ใช้ไม่ได้ (private mode) -> ใช้ค่าเริ่มต้น ไม่ต้องพัง */
      }
    },

    toggleRail() {
      this.collapsed = !this.collapsed

      try {
        window.localStorage.setItem(KEY, this.collapsed ? '1' : '0')
      } catch (err) {
        /* จำข้ามหน้าไม่ได้ แต่ยังย่อ/กางในหน้านี้ได้ตามปกติ */
      }
    },
  }
}
