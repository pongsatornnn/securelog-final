// เพิ่ม header X-CSRF-Token อัตโนมัติให้ทุก fetch ที่ "เปลี่ยนข้อมูล" (POST/PUT/PATCH/DELETE)
// แบบ same-origin โดยอ่าน token จาก cookie `csrf_token` (ตั้งโดย CSRFMiddleware ฝั่ง server)
// โหลดแบบ synchronous ก่อน script อื่น เพื่อ patch window.fetch ให้ทันก่อนหน้าจะยิง request ใด ๆ
(function () {
  function getCookie(name) {
    var parts = document.cookie ? document.cookie.split('; ') : [];
    for (var i = 0; i < parts.length; i++) {
      var idx = parts[i].indexOf('=');
      if (idx > -1 && parts[i].slice(0, idx) === name) {
        return decodeURIComponent(parts[i].slice(idx + 1));
      }
    }
    return '';
  }

  var UNSAFE = { POST: 1, PUT: 1, PATCH: 1, DELETE: 1 };
  var origFetch = window.fetch;
  if (!origFetch) return;

  window.fetch = function (input, init) {
    init = init || {};

    var isReqObj = input && typeof input === 'object';
    var method = (init.method || (isReqObj && input.method) || 'GET').toUpperCase();
    var url = (typeof input === 'string') ? input : (isReqObj && input.url) || '';
    var sameOrigin = url.indexOf('/') === 0 || url.indexOf(window.location.origin) === 0;

    if (UNSAFE[method] && sameOrigin) {
      var token = getCookie('csrf_token');
      if (token) {
        var headers = new Headers(init.headers || (isReqObj ? input.headers : null) || {});
        if (!headers.has('X-CSRF-Token')) headers.set('X-CSRF-Token', token);
        init = Object.assign({}, init, { headers: headers });
      }
    }

    return origFetch.call(this, input, init);
  };
})();
