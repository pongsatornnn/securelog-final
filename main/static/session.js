// เด้งกลับหน้า login อัตโนมัติเมื่อ session หมดอายุ/ถูกเพิกถอน แทนที่จะปล่อยให้หน้าค้าง
(function () {
  // endpoint ที่ 401 = "ข้อมูลที่กรอกไม่ถูกต้อง" ไม่ใช่ session หมดอายุ ห้ามเด้ง
  var AUTH_ENDPOINTS = ['/api/login', '/api/change-password'];

  var origFetch = window.fetch;
  if (!origFetch) return;

  var redirecting = false;

  function pathOf(url) {
    try {
      return new URL(url, window.location.origin).pathname;
    } catch (e) {
      return '';
    }
  }

  function isAuthEndpoint(url) {
    var path = pathOf(url);
    for (var i = 0; i < AUTH_ENDPOINTS.length; i++) {
      if (path === AUTH_ENDPOINTS[i]) return true;
    }
    return false;
  }

  function goLogin() {
    // อยู่หน้า login อยู่แล้วไม่ต้องเด้ง (กันลูป) และเด้งครั้งเดียวพอถึงจะมีหลาย request พร้อมกัน
    if (redirecting || window.location.pathname === '/login') return false;
    redirecting = true;
    window.location.href = '/login';
    return true;
  }

  window.fetch = function (input, init) {
    var isReqObj = input && typeof input === 'object';
    var url = (typeof input === 'string') ? input : (isReqObj && input.url) || '';

    return origFetch.apply(this, arguments).then(function (res) {
      if (isAuthEndpoint(url)) return res;

      var bouncedToLogin = res.redirected && pathOf(res.url) === '/login';

      if (bouncedToLogin || res.status === 401) {
        if (goLogin()) {
          // ค้าง promise ไว้เฉย ๆ ระหว่างที่ browser กำลังเปลี่ยนหน้า เพื่อไม่ให้ผู้ใช้เห็น
          return new Promise(function () {});
        }
      }

      return res;
    });
  };
})();
