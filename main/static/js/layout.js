


function shell() {
  var KEY = 'securelog.nav.collapsed'

  return {
    navOpen: false,          // เมนูแบบ off-canvas บนจอมือถือ
    collapsed: false,        // ย่อเหลือแต่ไอคอนบนจอใหญ่

    init() {
      try {
        this.collapsed = window.localStorage.getItem(KEY) === '1'
      } catch (err) {

      }
    },

    toggleRail() {
      this.collapsed = !this.collapsed

      try {
        window.localStorage.setItem(KEY, this.collapsed ? '1' : '0')
      } catch (err) {

      }
    },
  }
}
