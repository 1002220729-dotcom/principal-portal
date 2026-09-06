import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const html = fs.readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const shared = fs.readFileSync(new URL('./auth-shared.js', import.meta.url), 'utf8');
function source(name) {
  const match = html.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n\\}`));
  assert.ok(match, name);
  return match[0];
}
function harness(child = false) {
  const store = new Map();
  const elements = new Map();
  const messages = [];
  const requests = [];
  const state = { _initDone: true, _dataLoadStarted: true, _pendingIframeReady: [] };
  const context = vm.createContext({
    PORTAL_SESSION_KEY: 'portalRoleSession', WORKER_URL_AUTH: 'https://api.example', PS: state,
    sessionStorage: {
      getItem: key => store.get(key) ?? null,
      setItem: (key, value) => store.set(key, value), removeItem: key => store.delete(key),
    },
    document: {
      getElementById(id) {
        if (!elements.has(id)) elements.set(id, { style: {}, src: 'tool.html', textContent: '' });
        return elements.get(id);
      },
    },
    window: { location: { origin: 'https://portal.example' }, top: {}, self: {},
      parent: { postMessage: message => messages.push(message) } },
    fetch: (url, options) => new Promise(resolve => requests.push({ url, options, resolve })),
    setTimeout: () => 1, clearTimeout() {}, AbortController,
    toast() {}, applyRoleUI: (...args) => messages.push({ ui: args }),
  });
  if (child) vm.runInContext(shared, context);
  else vm.runInContext([
    'getPortalSession', 'setPortalSession', 'clearPortalSession', 'getSessionToken',
    'authFetch', 'expirePortalSession', 'showLoginError', 'setLoginStatus',
  ].map(source).join('\n'), context);
  const login = token => store.set('portalRoleSession', JSON.stringify({ token, portalRole: 'principal' }));
  const current = () => JSON.parse(store.get('portalRoleSession') ?? 'null');
  const fetch = child ? context.window.PortalAuth.authFetch : context.authFetch;
  return { context, login, current, fetch, requests, messages, state, elements };
}

for (const child of [false, true]) {
  const label = child ? 'child helper' : 'portal shell';
  test(`${label}: no anonymous background request during login`, async () => {
    const h = harness(child);
    await assert.rejects(h.fetch('/data'), /unauthorized/);
    assert.equal(h.requests.length, 0);
    assert.equal(h.messages.length, 0);
  });
  for (const status of [200, 401, 403]) {
    test(`${label}: late ${status} cannot alter a newer session`, async () => {
      const h = harness(child);
      h.login('old-test-session');
      const request = h.fetch('/data');
      const rejection = assert.rejects(request, /stale-session/);
      h.login('new-test-session');
      h.requests[0].resolve({ status });
      await rejection;
      assert.equal(h.current().token, 'new-test-session');
      assert.equal(h.messages.length, 0);
    });
  }
  test(`${label}: current successful response is usable and authenticated`, async () => {
    const h = harness(child);
    h.login('test-session');
    const pending = h.fetch('/data');
    assert.equal(h.requests[0].options.headers.Authorization, 'Bearer test-session');
    const response = { status: 200 };
    h.requests[0].resolve(response);
    assert.equal(await pending, response);
  });
}

test('current shell 401 really logs out and resets loaders for a fresh login', async () => {
  const h = harness();
  h.login('expired-test-session');
  const rejected = assert.rejects(h.fetch('/data'), /unauthorized/);
  h.requests[0].resolve({ status: 401 });
  await rejected;
  assert.equal(h.current(), null);
  assert.equal(h.state._dataLoadStarted, false);
  assert.equal(h.state._initDone, false);
  assert.equal(h.elements.get('planFrame').src, 'about:blank');
  assert.match(h.elements.get('loginError').textContent, /S2/);
});

test('child current 401 asks parent to verify rather than erasing shared storage', async () => {
  const h = harness(true);
  h.login('test-session');
  const rejected = assert.rejects(h.fetch('/data'), /unauthorized/);
  h.requests[0].resolve({ status: 401 });
  await rejected;
  assert.equal(h.current().token, 'test-session');
  assert.equal(h.messages[0].type, 'session-expired');
});

test('a delayed iframe expiry message verifies the new session with the server', async () => {
  const h = harness();
  vm.runInContext('let _sessionRecheck = null;\n' + source('recheckSessionFromFrame'), h.context);
  h.login('new-test-session');
  h.context.recheckSessionFromFrame();
  h.context.recheckSessionFromFrame();
  assert.equal(h.requests.length, 1, 'coalesces concurrent expiry messages');
  assert.equal(h.requests[0].url, 'https://api.example/api/auth/role');
  h.requests[0].resolve({ status: 200 });
  await vm.runInContext('_sessionRecheck', h.context);
  assert.equal(h.current().token, 'new-test-session');
  assert.equal(h.messages.length, 0);
});

test('session storage failure is explicit, not a false successful login', () => {
  const h = harness();
  h.context.sessionStorage.setItem = () => {};
  assert.throws(() => h.context.setPortalSession({ token: 'test-session' }), /S1/);
  h.context.sessionStorage.setItem = () => { throw new Error('denied'); };
  assert.throws(() => h.context.setPortalSession({ token: 'test-session' }), /S1/);
});

test('focus while logged out or initializing never triggers background refresh', () => {
  const h = harness();
  vm.runInContext(source('reloadFrameData'), h.context);
  h.state.school = 'test-school'; h.state.year = '2026-2027';
  h.context.reloadFrameData();
  h.login('test-session'); h.state._initDone = false;
  h.context.reloadFrameData();
  assert.equal(h.requests.length, 0);
});

test('old initial data loads cannot finish initialization for a new session', async () => {
  const h = harness();
  h.context.performance = { now: () => 0 };
  vm.runInContext(source('loadPortalDataAndNotifyFrames'), h.context);
  h.state.school = 'test-school'; h.state.year = '2026-2027';
  h.state._dataLoadStarted = false; h.state._initDone = false;
  h.login('old-test-session');
  const pending = h.context.loadPortalDataAndNotifyFrames();
  assert.equal(h.requests.length, 5);
  h.login('new-test-session');
  for (const request of h.requests) request.resolve({ status: 200, ok: true, text: async () => '{}' });
  await pending;
  assert.equal(h.state._initDone, false);
  assert.equal(h.state.planData, undefined);
});

test('Google callback completes once, checks the server and persists before showing the portal', async () => {
  const h = harness();
  let shown = 0, loaded = 0;
  Object.assign(h.context, {
    parseJwt: () => ({}), getUrlSchoolYearHint: () => ({}),
    ensureSchoolYear: year => year, persistResolvedSchoolYear() {}, esc: x => x,
    applyRoleUI: () => { assert.equal(h.current().token, 'server-test-session'); shown++; },
    loadPortalDataAndNotifyFrames: () => loaded++,
  });
  vm.runInContext("let _googleLoginInFlight = false, _googleWaitTimer = null, _pendingRole = 'principal';\n" + source('handleGoogleCredential'), h.context);
  const pending = h.context.handleGoogleCredential({ credential: 'test-credential' });
  await h.context.handleGoogleCredential({ credential: 'test-credential' });
  assert.equal(h.requests.length, 1);
  assert.match(h.elements.get('loginStatus').textContent, /G2/);
  assert.equal(JSON.parse(h.requests[0].options.body).requestedRole, 'principal');
  h.requests[0].resolve({ ok: true, json: async () => ({ ok: true, token: 'server-test-session',
    session: { role: 'principal', username: 'test@example.org', school: 'test-school', year: '2026-2027' } }) });
  await pending;
  assert.equal(shown, 1); assert.equal(loaded, 1);
  assert.equal(vm.runInContext('_googleLoginInFlight', h.context), false);
});

test('tool documents are deferred until login; all inline scripts remain valid', () => {
  for (const name of ['plan', 'gantt', 'mtss', 'calendar']) {
    assert.match(html, new RegExp(`<iframe id="${name}Frame" src="about:blank"`));
  }
  for (const match of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/gi)) {
    if (match[1].trim()) new vm.Script(match[1]);
  }
});
