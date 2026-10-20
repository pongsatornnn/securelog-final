
(function () {

  var BASE = window.APP_BASE || '';
  var AUTH_ENDPOINTS = [BASE + '/api/login', BASE + '/api/change-password'];

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

    if (redirecting || window.location.pathname === BASE + '/login') return false;
    redirecting = true;
    window.location.href = BASE + '/login';
    return true;
  }

  window.fetch = function (input, init) {
    var isReqObj = input && typeof input === 'object';
    var url = (typeof input === 'string') ? input : (isReqObj && input.url) || '';

    return origFetch.apply(this, arguments).then(function (res) {
      if (isAuthEndpoint(url)) return res;

      var bouncedToLogin = res.redirected && pathOf(res.url) === BASE + '/login';

      if (bouncedToLogin || res.status === 401) {
        if (goLogin()) {

          return new Promise(function () {});
        }
      }

      return res;
    });
  };
})();
