// ═══════════════════════════════════════════════════════════
//  auth-shared.js — shared authenticated-fetch helper (Phase 8)
//
//  Used by every portal tool that calls the Worker API directly
//  (inventory.html, budget.html, teachers.html today; included in
//  the other iframe tools too for forward-compatibility even though
//  they currently send/receive data via postMessage to index.html
//  instead of calling the Worker themselves).
//
//  The session token is issued by the Worker at login (in
//  index.html) and stored ONLY in sessionStorage, under the same
//  'portalRoleSession' key index.html uses — readable here because
//  this file always runs same-origin as the parent portal shell.
//  NEVER stored in localStorage.
//
//  Every Worker call in these files must go through
//  PortalAuth.authFetch() so the Authorization header can never be
//  silently omitted, and so a 401/403 is handled consistently.
// ═══════════════════════════════════════════════════════════
(function () {
  var SESSION_KEY = 'portalRoleSession';
  var PORTAL_ORIGIN = window.location.origin; // dynamic: same value in prod and staging since this file always runs same-origin as the parent portal

  function getSession() {
    try { return JSON.parse(sessionStorage.getItem(SESSION_KEY)); } catch (_) { return null; }
  }
  function getToken() {
    var s = getSession();
    return (s && s.token) || null;
  }
  function clearSession() {
    try { sessionStorage.removeItem(SESSION_KEY); } catch (_) {}
  }

  function showAccessDenied(msg) {
    var el = document.getElementById('__portalAuthBanner');
    if (!el) {
      el = document.createElement('div');
      el.id = '__portalAuthBanner';
      el.style.cssText = 'position:fixed;bottom:16px;left:16px;right:16px;z-index:99999;' +
        'background:#7f1d1d;color:#fff;padding:10px 14px;border-radius:8px;' +
        'font-size:0.85rem;text-align:center;box-shadow:0 2px 10px rgba(0,0,0,.3);direction:rtl;';
      document.body.appendChild(el);
    }
    el.textContent = msg || 'אין הרשאה לביצוע פעולה זו.';
    el.style.display = 'block';
    clearTimeout(el._hideTimer);
    el._hideTimer = setTimeout(function () { el.style.display = 'none'; }, 4000);
  }

  // On 401: clear the local session and hand control back to the
  // top-level portal shell (index.html), which owns the login screen.
  // This file's own tool (inventory/budget/teachers) is always loaded
  // as an iframe — it has no login UI of its own.
  function handleUnauthorized() {
    clearSession();
    if (window.top !== window.self) {
      try { window.parent.postMessage({ type: 'session-expired' }, PORTAL_ORIGIN); } catch (_) {}
      showAccessDenied('פג תוקף ההתחברות. יש להתחבר מחדש.');
    } else {
      // Opened directly, not inside the portal shell — no parent to relay to.
      showAccessDenied('פג תוקף ההתחברות. יש לחזור לפורטל הראשי ולהתחבר מחדש.');
    }
  }

  async function authFetch(url, options) {
    options = options || {};
    var token = getToken();
    var headers = Object.assign({}, options.headers || {});
    if (token) headers['Authorization'] = 'Bearer ' + token;
    if (options.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';

    var res = await fetch(url, Object.assign({}, options, { headers: headers }));

    if (res.status === 401) {
      handleUnauthorized();
      throw new Error('unauthorized');
    }
    if (res.status === 403) {
      showAccessDenied('אין הרשאה לביצוע פעולה זו.');
      throw new Error('forbidden');
    }
    return res;
  }

  window.PortalAuth = { getSession: getSession, getToken: getToken, authFetch: authFetch, showAccessDenied: showAccessDenied };
})();
