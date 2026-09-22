// Private Google Calendar bridge. No event is persisted in portal_data.
// Deploy only after the additive migration and runtime secrets are installed.
export const CALENDAR_PREFIX = '/api/private-google-calendar';
export const CALENDAR_SCOPE = 'https://www.googleapis.com/auth/calendar.events.owned.readonly';
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const WINDOW_MS = 10 * 60 * 1000;
const IDLE_MS = 10 * 60 * 60 * 1000;

class CalendarError extends Error {
  constructor(status, code, diagnosticReason = code) {
    super(code); this.status = status; this.code = code; this.diagnosticReason = diagnosticReason;
  }
}
function fail(status, code, diagnosticReason) { throw new CalendarError(status, code, diagnosticReason); }
function bytesHex(bytes) { return [...bytes].map(b => b.toString(16).padStart(2, '0')).join(''); }
function randomHex() { return bytesHex(crypto.getRandomValues(new Uint8Array(32))); }
async function digest(value) { return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value))); }
async function hash(value) { return bytesHex(await digest(value)); }
function b64(bytes) { return btoa(String.fromCharCode(...bytes)); }
function unb64(value) { return Uint8Array.from(atob(value), c => c.charCodeAt(0)); }
function base64url(bytes) { return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }

function environment(request, env) {
  const host = new URL(request.url).hostname;
  const portal = host === 'principal-api.1002220729.workers.dev'
    ? 'https://principal-portal.pages.dev'
    : host === 'principal-api-staging.1002220729.workers.dev'
      ? 'https://staging.principal-portal.pages.dev' : null;
  if (!portal) fail(403, 'unsupported_host');
  const owner = String(env.GOOGLE_CALENDAR_ALLOWED_EMAIL || '').trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(owner)) fail(503, 'not_configured');
  return { portal, owner, callback: 'https://' + host + CALENDAR_PREFIX + '/callback' };
}
function configured(env) {
  return env.GOOGLE_CALENDAR_ENABLED === 'true' &&
    /^[\w-]+\.apps\.googleusercontent\.com$/.test(env.GOOGLE_CALENDAR_CLIENT_ID || '') &&
    typeof env.GOOGLE_CALENDAR_CLIENT_SECRET === 'string' && !!env.GOOGLE_CALENDAR_CLIENT_SECRET &&
    /^[0-9a-f]{64}$/i.test(env.GOOGLE_CALENDAR_ENCRYPTION_KEY || '');
}
function headers(origin) {
  return {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'private, no-store, max-age=0',
    'Pragma': 'no-cache', 'Vary': 'Origin, Authorization',
    'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer',
    ...(origin ? {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'GET, POST, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type',
    } : {}),
  };
}
function json(value, status, origin) {
  return new Response(JSON.stringify(value), { status, headers: headers(origin) });
}

// AES-GCM binds ciphertext to its owner/purpose. Encryption keys are Worker
// secrets, never committed, returned to the browser, or stored beside tokens.
async function key(env) {
  if (!/^[0-9a-f]{64}$/i.test(env.GOOGLE_CALENDAR_ENCRYPTION_KEY || '')) fail(503, 'not_configured');
  const raw = Uint8Array.from(env.GOOGLE_CALENDAR_ENCRYPTION_KEY.match(/../g), x => parseInt(x, 16));
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}
export async function seal(env, value, purpose) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: encoder.encode(purpose) }, await key(env), encoder.encode(value)));
  return 'v1.' + b64(iv) + '.' + b64(ciphertext);
}
export async function unseal(env, value, purpose) {
  const parts = String(value).split('.');
  if (parts.length !== 3 || parts[0] !== 'v1') fail(503, 'connection_unavailable');
  return decoder.decode(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: unb64(parts[1]), additionalData: encoder.encode(purpose) },
    await key(env), unb64(parts[2])));
}
async function sessionByHash(env, tokenHash, owner) {
  const session = await env.DB.prepare(`SELECT username, role, school, year, expires_at, last_seen_at, revoked_at
    FROM staffsessions WHERE token_hash = ?`).bind(tokenHash).first();
  const expiry = Date.parse(session?.expires_at);
  const seen = Date.parse(session?.last_seen_at);
  if (!session || session.revoked_at || !Number.isFinite(expiry) || expiry <= Date.now() ||
      !Number.isFinite(seen) || Date.now() - seen > IDLE_MS) fail(401, 'session_expired');
  // No system-admin override. No client-supplied email/school can select owner.
  if (session.username !== owner || !['principal', 'systemadmin'].includes(session.role)) fail(403, 'private_calendar_forbidden');
  return { ...session, tokenHash };
}
async function sessionFor(request, env, owner) {
  const match = /^Bearer ([a-f0-9]{64})$/.exec(request.headers.get('Authorization') || '');
  if (!match) fail(401, 'session_required');
  return sessionByHash(env, await hash(match[1]), owner);
}

async function boundedJson(response, maxBytes = 524288) {
  if (!response.body) fail(502, 'google_unavailable');
  const reader = response.body.getReader();
  let size = 0;
  const chunks = [];
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) { await reader.cancel(); fail(502, 'google_response_too_large'); }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length; }
  try { return JSON.parse(decoder.decode(bytes)); } catch { fail(502, 'google_unavailable'); }
}
async function googleFetch(fetcher, url, options = {}) {
  try {
    // Workers supports manual redirects; reject them before reading any body
    // so credentials are never forwarded to an upstream redirect destination.
    const response = await fetcher(url, { ...options, redirect: 'manual', signal: AbortSignal.timeout(15000) });
    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      fail(502, 'google_unavailable');
    }
    return response;
  } catch { fail(502, 'google_unavailable'); }
}
async function exchange(fetcher, env, fields) {
  const response = await googleFetch(fetcher, 'https://oauth2.googleapis.com/token', {
    method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ ...fields, client_id: env.GOOGLE_CALENDAR_CLIENT_ID,
      client_secret: env.GOOGLE_CALENDAR_CLIENT_SECRET }).toString(),
  });
  const result = await boundedJson(response, 32768);
  if (!response.ok) {
    if (result.error === 'invalid_grant') fail(409, 'reconnect_required', 'invalid_grant');
    if (result.error === 'invalid_client') fail(502, 'google_unavailable', 'invalid_client');
    fail(502, 'google_unavailable', 'token_rejected');
  }
  if (typeof result.access_token !== 'string' || result.access_token.length > 8192 || !result.access_token) fail(502, 'google_unavailable');
  return result;
}
async function identity(fetcher, accessToken, owner) {
  const response = await googleFetch(fetcher, 'https://openidconnect.googleapis.com/v1/userinfo', {
    headers: { Authorization: 'Bearer ' + accessToken },
  });
  const value = await boundedJson(response, 32768);
  if (!response.ok || value.email_verified !== true || String(value.email || '').toLowerCase() !== owner ||
      typeof value.sub !== 'string' || !value.sub || value.sub.length > 255) fail(403, 'account_mismatch');
  return value.sub;
}
function requireScope(tokens) {
  if (!String(tokens.scope || '').split(' ').includes(CALENDAR_SCOPE)) fail(409, 'calendar_permission_missing');
}
async function getConnection(env, owner) {
  return env.DB.prepare('SELECT owner, google_sub, refresh_cipher, version FROM private_google_calendar_connections WHERE owner = ?')
    .bind(owner).first();
}
const CALLBACK_STAGES = new Set(['state', 'state_claim', 'state_validation', 'session', 'code',
  'decrypt', 'token', 'scope', 'identity', 'refresh_token', 'session_recheck', 'encrypt', 'save', 'save_result']);
const CALLBACK_REASONS = new Set(['invalid_state', 'session_expired', 'private_calendar_forbidden',
  'invalid_code', 'connection_unavailable', 'not_configured', 'google_unavailable', 'google_response_too_large',
  'reconnect_required', 'connection_changed', 'invalid_client', 'invalid_grant', 'token_rejected']);
function callbackDiagnostic(env, config, stage, error) {
  if (env.GOOGLE_CALENDAR_DIAGNOSTICS !== 'true' ||
      config.portal !== 'https://staging.principal-portal.pages.dev') return undefined;
  // Only fixed labels leave this function: never exception text, upstream data,
  // callback parameters, identities, hashes, or credentials. No diagnostic logs.
  return {
    stage: CALLBACK_STAGES.has(stage) ? stage : 'callback',
    reason: error instanceof CalendarError && CALLBACK_REASONS.has(error.diagnosticReason)
      ? error.diagnosticReason : 'internal',
  };
}
function returnToPortal(config, outcome, session, diagnostic) {
  const target = new URL(config.portal + '/');
  target.searchParams.set('gcal', outcome);
  if (outcome === 'failed' && diagnostic) {
    target.searchParams.set('gcal_stage', diagnostic.stage);
    target.searchParams.set('gcal_reason', diagnostic.reason);
  }
  if (session?.school) target.searchParams.set('school', session.school);
  if (session?.year) target.searchParams.set('year', session.year);
  return new Response(null, { status: 303, headers: { ...headers(), Location: target.href } });
}
async function callback(request, env, config, fetcher) {
  let session, stateHash, claimed = false;
  let stage = 'state';
  try {
    const url = new URL(request.url);
    const state = url.searchParams.get('state');
    if (!/^[a-f0-9]{64}$/.test(state || '')) fail(400, 'invalid_state');
    stateHash = await hash(state);
    // Atomic single-use claim prevents replay, while retaining a cancellation
    // marker until the credential write. Disconnect also cancels in-flight OAuth.
    stage = 'state_claim';
    const pending = await env.DB.prepare(`UPDATE private_google_calendar_states SET claimed_at = ?
      WHERE state_hash = ? AND claimed_at IS NULL RETURNING owner, session_hash, verifier_cipher, expires_at`)
      .bind(new Date().toISOString(), stateHash).first();
    claimed = !!pending;
    stage = 'state_validation';
    if (!pending || pending.owner !== config.owner || !Number.isFinite(Date.parse(pending.expires_at)) ||
        Date.parse(pending.expires_at) <= Date.now()) fail(400, 'invalid_state');
    stage = 'session';
    session = await sessionByHash(env, pending.session_hash, config.owner);
    if (url.searchParams.has('error')) return returnToPortal(config, 'denied', session);
    stage = 'code';
    const code = url.searchParams.get('code');
    if (!code || code.length > 4096) fail(400, 'invalid_code');
    stage = 'decrypt';
    const verifier = await unseal(env, pending.verifier_cipher, 'state:' + stateHash);
    stage = 'token';
    const tokens = await exchange(fetcher, env, { code, code_verifier: verifier,
      grant_type: 'authorization_code', redirect_uri: config.callback });
    stage = 'scope';
    requireScope(tokens);
    stage = 'identity';
    const sub = await identity(fetcher, tokens.access_token, config.owner);
    stage = 'refresh_token';
    if (typeof tokens.refresh_token !== 'string' || !tokens.refresh_token || tokens.refresh_token.length > 8192) fail(409, 'reconnect_required');
    stage = 'session_recheck';
    await sessionByHash(env, pending.session_hash, config.owner);
    stage = 'encrypt';
    const encrypted = await seal(env, tokens.refresh_token, 'refresh:' + config.owner);
    stage = 'save';
    const now = new Date().toISOString();
    const saved = await env.DB.prepare(`INSERT INTO private_google_calendar_connections (owner, google_sub, refresh_cipher, version, connected_at)
      SELECT ?, ?, ?, ?, ? WHERE EXISTS (SELECT 1 FROM private_google_calendar_states
        WHERE state_hash = ? AND owner = ? AND claimed_at IS NOT NULL AND expires_at > ?)
      AND EXISTS (SELECT 1 FROM staffsessions WHERE token_hash = ? AND username = ?
        AND role IN ('principal', 'systemadmin') AND revoked_at IS NULL AND expires_at > ? AND last_seen_at > ?)
      ON CONFLICT(owner) DO UPDATE SET google_sub = excluded.google_sub,
      refresh_cipher = excluded.refresh_cipher, version = excluded.version, connected_at = excluded.connected_at`)
      .bind(config.owner, sub, encrypted, crypto.randomUUID(), now, stateHash, config.owner, now,
        pending.session_hash, config.owner, now, new Date(Date.now() - IDLE_MS).toISOString()).run();
    stage = 'save_result';
    if (saved.meta?.changes !== 1) fail(409, 'connection_changed');
    return returnToPortal(config, 'connected', session);
  } catch (error) {
    const outcome = error instanceof CalendarError && ['account_mismatch', 'calendar_permission_missing'].includes(error.code)
      ? error.code : 'failed';
    // Never log callback URLs, codes, tokens, private event data, or upstream errors.
    return returnToPortal(config, outcome, session,
      outcome === 'failed' ? callbackDiagnostic(env, config, stage, error) : undefined);
  } finally {
    if (claimed && stateHash) {
      try { await env.DB.prepare('DELETE FROM private_google_calendar_states WHERE state_hash = ?').bind(stateHash).run(); }
      catch { /* Claimed states cannot be replayed and expire without granting access. */ }
    }
  }
}

export function eventRange(url) {
  const month = url.searchParams.get('month') || '';
  if (!/^20\d{2}-(0[1-9]|1[0-2])$/.test(month)) fail(400, 'invalid_month');
  const [year, index] = month.split('-').map(Number);
  // A small UTC buffer includes midnight events across Israeli DST boundaries.
  return { month, start: new Date(Date.UTC(year, index - 1, 1) - 86400000).toISOString(),
    end: new Date(Date.UTC(year, index, 1) + 86400000).toISOString() };
}
function cleanEvent(event) {
  if (!event || event.status === 'cancelled') return null;
  const allDay = !!event.start?.date;
  const start = allDay ? event.start.date : event.start?.dateTime;
  const end = allDay ? event.end?.date : event.end?.dateTime;
  if (typeof start !== 'string' || typeof end !== 'string' || !Number.isFinite(Date.parse(start)) || !Number.isFinite(Date.parse(end))) return null;
  let link = '';
  try {
    const url = new URL(event.htmlLink);
    if (url.protocol === 'https:' && !url.username && !url.password &&
        (url.hostname === 'calendar.google.com' || (url.hostname === 'www.google.com' && url.pathname.startsWith('/calendar/')))) link = url.href;
  } catch { /* no link */ }
  return { id: String(event.id || '').slice(0, 256), title: String(event.summary || 'פגישה ללא כותרת').slice(0, 500),
    location: String(event.location || '').slice(0, 500), start, end, allDay, link };
}
async function events(request, env, session, config, fetcher) {
  const range = eventRange(new URL(request.url));
  const connection = await getConnection(env, config.owner);
  if (!connection) fail(409, 'not_connected');
  const refresh = await unseal(env, connection.refresh_cipher, 'refresh:' + config.owner);
  const tokens = await exchange(fetcher, env, { grant_type: 'refresh_token', refresh_token: refresh });
  // Refresh responses may omit scope; access never broadens the scopes requested.
  if (tokens.scope) requireScope(tokens);
  if (await identity(fetcher, tokens.access_token, config.owner) !== connection.google_sub) fail(403, 'account_mismatch');
  const found = new Map();
  let next = '';
  for (let page = 0; page < 10; page++) {
    const url = new URL('https://www.googleapis.com/calendar/v3/calendars/primary/events');
    url.search = new URLSearchParams({ timeMin: range.start, timeMax: range.end,
      singleEvents: 'true', showDeleted: 'false', orderBy: 'startTime', maxResults: '100', timeZone: 'Asia/Jerusalem',
      fields: 'nextPageToken,items(id,status,summary,location,start,end,htmlLink)', ...(next ? { pageToken: next } : {}) }).toString();
    const response = await googleFetch(fetcher, url.href, { headers: { Authorization: 'Bearer ' + tokens.access_token } });
    const data = await boundedJson(response);
    if (response.status === 401) fail(409, 'reconnect_required');
    if (response.status === 403) fail(409, 'calendar_permission_missing');
    if (response.status === 429) fail(429, 'google_rate_limited');
    if (!response.ok || (data.items !== undefined && !Array.isArray(data.items))) fail(502, 'google_unavailable');
    for (const item of data.items || []) { const event = cleanEvent(item); if (event?.id) found.set(event.id, event); }
    next = typeof data.nextPageToken === 'string' ? data.nextPageToken : '';
    if (!next) break;
    if (next.length > 4096) fail(502, 'google_unavailable');
  }
  if (next) fail(422, 'too_many_events'); // Never silently present an incomplete month.
  await sessionByHash(env, session.tokenHash, config.owner);
  if ((await getConnection(env, config.owner))?.version !== connection.version) fail(409, 'connection_changed');
  return { events: [...found.values()], month: range.month, timeZone: 'Asia/Jerusalem', fetchedAt: new Date().toISOString() };
}

export async function handlePrivateGoogleCalendar(request, env, fetcher = fetch) {
  let origin;
  try {
    const config = environment(request, env);
    const path = new URL(request.url).pathname;
    if (path === CALENDAR_PREFIX + '/callback' && request.method === 'GET') {
      if (!configured(env)) return returnToPortal(config, 'unavailable');
      return await callback(request, env, config, fetcher);
    }
    if (request.headers.get('Origin') !== config.portal) fail(403, 'origin_forbidden');
    origin = config.portal;
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: headers(origin) });
    const session = await sessionFor(request, env, config.owner);
    if (path === CALENDAR_PREFIX + '/status' && request.method === 'GET') {
      if (!configured(env)) return json({ available: false, connected: false }, 200, origin);
      return json({ available: true, connected: !!(await getConnection(env, config.owner)), email: config.owner }, 200, origin);
    }
    if (!configured(env)) fail(503, 'not_configured');
    if (path === CALENDAR_PREFIX + '/connect' && request.method === 'POST') {
      if (!request.headers.get('Content-Type')?.startsWith('application/json')) fail(415, 'json_required');
      const now = new Date().toISOString();
      await env.DB.prepare('DELETE FROM private_google_calendar_states WHERE expires_at <= ?').bind(now).run();
      const recent = await env.DB.prepare(`SELECT COUNT(*) AS count FROM private_google_calendar_states WHERE owner = ?`)
        .bind(config.owner).first();
      if (Number(recent?.count || 0) >= 5) fail(429, 'too_many_connections');
      const state = randomHex(), verifier = randomHex(), stateHash = await hash(state);
      await env.DB.prepare(`INSERT INTO private_google_calendar_states
        (state_hash, owner, session_hash, verifier_cipher, expires_at) VALUES (?, ?, ?, ?, ?)`)
        .bind(stateHash, config.owner, session.tokenHash, await seal(env, verifier, 'state:' + stateHash), new Date(Date.now() + WINDOW_MS).toISOString()).run();
      const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      url.search = new URLSearchParams({ client_id: env.GOOGLE_CALENDAR_CLIENT_ID, redirect_uri: config.callback,
        response_type: 'code', scope: 'openid email ' + CALENDAR_SCOPE, access_type: 'offline',
        prompt: 'consent', include_granted_scopes: 'false', login_hint: config.owner,
        state, code_challenge: base64url(await digest(verifier)), code_challenge_method: 'S256' }).toString();
      return json({ authorizationUrl: url.href }, 200, origin);
    }
    if (path === CALENDAR_PREFIX + '/connection' && request.method === 'DELETE') {
      // Local unlink only: do not revoke other Google grants used by this project.
      await env.DB.batch([
        env.DB.prepare('DELETE FROM private_google_calendar_states WHERE owner = ?').bind(config.owner),
        env.DB.prepare('DELETE FROM private_google_calendar_connections WHERE owner = ?').bind(config.owner),
      ]);
      return json({ ok: true }, 200, origin);
    }
    if (path === CALENDAR_PREFIX + '/events' && request.method === 'GET') return json(await events(request, env, session, config, fetcher), 200, origin);
    return json({ error: 'not_found' }, 404, origin);
  } catch (error) {
    return json({ error: error instanceof CalendarError ? error.code : 'calendar_unavailable' },
      error instanceof CalendarError ? error.status : 503, origin);
  }
}
