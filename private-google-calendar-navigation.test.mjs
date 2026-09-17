import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

// Exercise the real parent message handler, including its existing source and
// origin checks. Synthetic responses only: no browser, account or network access.
const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const start = html.indexOf('let _privateCalendarConnectInFlight = false;');
assert.ok(start >= 0);
const end = html.indexOf('\n});', start) + 5;
const parentHandler = html.slice(start, end);
const clientId = html.match(/const GOOGLE_CLIENT_ID\s*=\s*'([^']+)'/)[1];
const childScript = readFileSync(new URL('./private-google-calendar.js', import.meta.url), 'utf8');
const childStart = childScript.indexOf("find('connect').addEventListener('click', async () => {");
const childConnect = childScript.slice(childStart, childScript.indexOf("  find('disconnect').addEventListener", childStart));

function fixture({ staging = true, portal, token: initialToken = 'session-a', response } = {}) {
  let token = initialToken;
  const origin = portal || (staging ? 'https://staging.principal-portal.pages.dev' : 'https://principal-portal.pages.dev');
  const worker = staging ? 'https://principal-api-staging.1002220729.workers.dev' : 'https://principal-api.1002220729.workers.dev';
  const requests = [], redirects = [], replies = [];
  const calendar = { postMessage: (data, target) => replies.push({ data, target }) };
  const frames = Object.fromEntries(['plan', 'gantt', 'mtss', 'teachers'].map(name => [name + 'Frame', { contentWindow: {} }]));
  frames.calendarFrame = { contentWindow: calendar };
  const authorization = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  authorization.search = new URLSearchParams({ client_id: clientId,
    redirect_uri: worker + '/api/private-google-calendar/callback', response_type: 'code',
    state: 'a'.repeat(64), code_challenge: 'b'.repeat(43), code_challenge_method: 'S256',
    scope: 'openid email https://www.googleapis.com/auth/calendar.events.owned.readonly' }).toString();
  let handler;
  const window = { addEventListener(name, fn) { assert.equal(name, 'message'); handler = fn; },
    location: { assign: url => redirects.push(url) } };
  vm.runInNewContext(parentHandler, { window, document: { getElementById: id => frames[id] },
    PORTAL_ORIGIN: origin, WORKER_URL_AUTH: worker, GOOGLE_CLIENT_ID: clientId,
    getSessionToken: () => token, URL, AbortController, setTimeout, clearTimeout,
    authFetch: async (url, options) => { requests.push({ url, options });
      return response ? response(authorization.href) : Response.json({ authorizationUrl: authorization.href }); },
  });
  return { origin, worker, calendar, frames, authorization, requests, redirects, replies,
    setToken(value) { token = value; },
    send(overrides = {}) { return handler({ origin, source: calendar,
      data: { type: 'private-google-calendar-connect', requestId: 'request:1' }, ...overrides }); },
  };
}

test('production and staging connect through their authenticated parent and exact callback', async () => {
  for (const staging of [false, true]) {
    const f = fixture({ staging });
    await f.send();
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].url, f.worker + '/api/private-google-calendar/connect');
    assert.equal(f.requests[0].options.method, 'POST');
    assert.equal(f.requests[0].options.cache, 'no-store');
    assert.equal(f.requests[0].options.credentials, 'omit');
    assert.equal(f.requests[0].options.body, '{}');
    assert.deepEqual(f.redirects, [f.authorization.href]);
    assert.equal(f.replies[0].data.ok, true);
    assert.equal(f.replies[0].target, f.origin);
  }
  const calendarTag = html.match(/<iframe id="calendarFrame"[^>]+>/)[0];
  assert.doesNotMatch(calendarTag, /allow-top-navigation/);
  assert.doesNotMatch(childScript, /parentWindow\.location\.assign/);
});

test('hostile origin, wrong iframe, unknown window and missing session cannot initiate OAuth', async () => {
  const f = fixture();
  await f.send({ origin: 'https://attacker.example' });
  await f.send({ source: f.frames.planFrame.contentWindow });
  await f.send({ source: {} });
  await f.send({ data: { type: 'private-google-calendar-connect', requestId: {} } });
  f.setToken(null);
  await f.send();
  assert.equal(f.requests.length, 0);
  assert.equal(f.redirects.length, 0);
  const preview = fixture({ portal: 'https://random-preview.principal-portal.pages.dev' });
  await preview.send();
  assert.equal(preview.requests.length, 0);
});

test('child-supplied destination and credentials are ignored', async () => {
  const f = fixture();
  await f.send({ data: { type: 'private-google-calendar-connect', requestId: 'request:2',
    authorizationUrl: 'https://attacker.example', token: 'not-a-session', events: ['private'] } });
  assert.deepEqual(f.redirects, [f.authorization.href]);
  assert.equal(f.requests[0].options.body, '{}');
  assert.equal(f.replies[0].data.events, undefined);
});

test('server OAuth destinations must match Google, client, environment callback and PKCE shape', async t => {
  const mutations = {
    'other origin': u => { u.hostname = 'attacker.example'; },
    'HTTP': u => { u.protocol = 'http:'; },
    'wrong path': u => { u.pathname = '/other'; },
    'URL credentials': u => { u.username = 'unexpected'; },
    'fragment': u => { u.hash = '#unexpected'; },
    'different client': u => u.searchParams.set('client_id', 'other.apps.googleusercontent.com'),
    'production callback on staging': u => u.searchParams.set('redirect_uri', 'https://principal-api.1002220729.workers.dev/api/private-google-calendar/callback'),
    'duplicate callback': u => u.searchParams.append('redirect_uri', 'https://attacker.example'),
    'duplicate client': u => u.searchParams.append('client_id', clientId),
    'implicit flow': u => u.searchParams.set('response_type', 'token'),
    'missing state': u => u.searchParams.delete('state'),
    'bad challenge': u => u.searchParams.set('code_challenge', 'short'),
    'plain PKCE': u => u.searchParams.set('code_challenge_method', 'plain'),
  };
  for (const [name, mutate] of Object.entries(mutations)) await t.test(name, async () => {
    const f = fixture({ response: valid => { const url = new URL(valid); mutate(url); return Response.json({ authorizationUrl: url.href }); } });
    await f.send();
    assert.equal(f.redirects.length, 0);
    assert.equal(f.replies[0].data.ok, false);
    assert.equal(f.replies[0].data.error, 'calendar_unavailable');
  });
});

test('session switch or removed calendar discards an in-flight OAuth result', async () => {
  for (const change of ['session', 'frame']) {
    let release;
    const f = fixture({ response: url => new Promise(resolve => { release = () => resolve(Response.json({ authorizationUrl: url })); }) });
    const pending = f.send();
    if (change === 'session') f.setToken('session-b');
    else f.frames.calendarFrame = { contentWindow: {} };
    release();
    await pending;
    assert.equal(f.redirects.length, 0);
    assert.equal(f.replies.length, 0);
  }
});

test('session is rechecked after JSON parsing, and duplicate requests do not create multiple OAuth states', async () => {
  let release;
  const f = fixture({ response: url => ({ ok: true, json: () => new Promise(resolve => { release = () => resolve({ authorizationUrl: url }); }) }) });
  const pending = f.send();
  await Promise.resolve();
  await f.send({ data: { type: 'private-google-calendar-connect', requestId: 'request:2' } });
  assert.equal(f.requests.length, 1);
  assert.equal(f.replies[0].data.ok, false);
  f.setToken('session-b');
  release();
  await pending;
  assert.equal(f.redirects.length, 0);
});

test('failures return only safe status codes and do not auto-retry', async () => {
  for (const error of ['too_many_connections', 'private-upstream-secret']) {
    const f = fixture({ response: () => Response.json({ error }, { status: 429 }) });
    await f.send();
    assert.equal(f.requests.length, 1);
    assert.equal(f.redirects.length, 0);
    assert.equal(f.replies[0].data.error, error === 'too_many_connections' ? error : 'calendar_unavailable');
  }
  const f = fixture({ response: () => { throw new Error('private-network-details'); } });
  await f.send();
  assert.equal(f.replies[0].data.error, 'calendar_unavailable');
});

test('child sends only connect intent and accepts only its correlated parent response', async () => {
  let click, listener;
  const posted = [], timers = new Map();
  const origin = 'https://staging.principal-portal.pages.dev';
  const parent = { postMessage: (data, target) => posted.push({ data, target }) };
  const context = { parentWindow: parent, location: { origin }, generation: 1, Date, Promise, Error,
    clearPrivate() {}, buttons() {}, stillCurrent: () => true, status: {}, message: error => error.message,
    find: () => ({ addEventListener: (_, fn) => { click = fn; } }),
    window: { addEventListener: (_, fn) => { listener = fn; }, removeEventListener: () => { listener = null; } },
    setTimeout: fn => { timers.set(1, fn); return 1; }, clearTimeout: id => timers.delete(id),
  };
  vm.runInNewContext(childConnect, context);
  let complete = false;
  const pending = click().then(() => { complete = true; });
  assert.deepEqual(Object.keys(posted[0].data).sort(), ['requestId', 'type']);
  assert.equal(posted[0].target, origin);
  assert.equal(posted[0].data.type, 'private-google-calendar-connect');
  const data = { type: 'private-google-calendar-connect-result', requestId: posted[0].data.requestId, ok: true };
  listener({ source: {}, origin, data });
  listener({ source: parent, origin: 'https://attacker.example', data });
  listener({ source: parent, origin, data: { ...data, requestId: 'other' } });
  await Promise.resolve();
  assert.equal(complete, false);
  listener({ source: parent, origin, data });
  await pending;
  assert.equal(complete, true);
  assert.equal(listener, null);
  assert.equal(timers.size, 0);
});
