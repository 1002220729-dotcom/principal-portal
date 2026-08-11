// ═══════════════════════════════════════════════════════════
//  worker.js — Cloudflare Worker (SECURITY-HARDENED REWRITE)
//  Implements Phases 1-6 of the security remediation spec:
//    CORS allowlist, real revocable sessions, centralized
//    authorization + tenant isolation, IDOR elimination,
//    input validation, DB hardening (see accompanying migrations),
//    baseline audit logging + login rate limiting (Phase 7 seed).
//
//  Role convention (standardized, no underscores):
//    'systemadmin' | 'principal' | 'staffmember'
//  This matches the `staff.role` CHECK constraint. Two legacy
//  routes (GET /api/auth/role, staff-login) previously returned
//  'system_admin' / 'staff_member' — normalized below.
//
//  KNOWN OPEN ITEM (flagged, not silently patched):
//  The frontend's Google Sign-In flow (index.html handleGoogleCredential)
//  currently decodes the Google JWT CLIENT-SIDE and sends the decoded
//  email as a plain query param to GET /api/auth/role. That endpoint
//  now REQUIRES a valid session and no longer trusts an email query
//  param for authorization — closing the impersonation hole — but the
//  frontend must be updated to call POST /api/auth/google-login with
//  the raw `response.credential` JWT instead. Until the frontend is
//  updated, Google-based login will 401. Username/password staff login
//  is unaffected.
// ═══════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────
//  CORS — Phase 1
// ─────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = new Set([
  'https://principal-portal.pages.dev',
  'https://staging.principal-portal.pages.dev',
]);
const PREVIEW_ORIGIN_RE = /^https:\/\/[a-z0-9-]+\.principal-portal\.pages\.dev$/;

function getCorsHeaders(request) {
  const origin = request.headers.get('Origin');
  if (!origin || (!ALLOWED_ORIGINS.has(origin) && !PREVIEW_ORIGIN_RE.test(origin))) {
    return { Vary: 'Origin' };
  }
  return {
    'Access-Control-Allow-Origin': origin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '600',
    Vary: 'Origin',
  };
}

function json(data, status, cors) {
  return new Response(JSON.stringify(data), {
    status: status || 200,
    headers: {
      ...(cors || {}),
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    },
  });
}
function err(msg, status, cors) { return json({ error: msg }, status || 400, cors); }

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

// ─────────────────────────────────────────────────────────
//  Crypto helpers
// ─────────────────────────────────────────────────────────
function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return arr;
}
async function sha256Hex(str) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  return bytesToHex(new Uint8Array(digest));
}

// PBKDF2-SHA256 password hashing. Iteration count is stored per-row
// (staff_auth.password_iterations) so it can be raised over time
// without invalidating existing passwords — verified accounts are
// transparently re-hashed at next successful login (see staff-login).
// NOTE: Argon2id is preferable but requires a WASM dependency not
// wired into this Worker yet; PBKDF2 is retained deliberately, with
// the iteration count raised for new/changed passwords and the
// upgrade-on-login path below. Revisit if a WASM Argon2id build
// becomes available for the Workers runtime.
// Cloudflare Workers currently caps a single WebCrypto PBKDF2 operation at
// 100,000 iterations. Going above that throws before the D1 write, which makes
// account creation and password resets fail with a generic 500 response.
const CURRENT_PBKDF2_ITERATIONS = 100000;
const LEGACY_PBKDF2_ITERATIONS = 100000; // fallback for rows predating the iterations column

async function hashPassword(password, salt, iterations) {
  const iter = iterations || CURRENT_PBKDF2_ITERATIONS;
  const saltBytes = salt ? hexToBytes(salt) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' }, keyMaterial, 256);
  return { hash: bytesToHex(new Uint8Array(bits)), salt: bytesToHex(saltBytes), iterations: iter };
}
async function verifyPassword(password, storedHash, storedSalt, storedIterations) {
  const { hash } = await hashPassword(password, storedSalt, storedIterations || LEGACY_PBKDF2_ITERATIONS);
  // Compare the fixed-size hash bytes without an early exit. The validity check is
  // deliberately evaluated only after the full comparison loop.
  const storedHex = String(storedHash || '');
  const storedIsValid = /^[0-9a-f]{64}$/i.test(storedHex);
  const computedBytes = hexToBytes(hash);
  const storedBytes = storedIsValid ? hexToBytes(storedHex) : new Uint8Array(32);
  let difference = 0;
  for (let i = 0; i < computedBytes.length; i++) difference |= computedBytes[i] ^ storedBytes[i];
  return storedIsValid && difference === 0;
}

function generateToken() {
  return bytesToHex(crypto.getRandomValues(new Uint8Array(32))); // 256-bit raw token
}
async function hashToken(rawToken) { return sha256Hex(rawToken); }

// ─────────────────────────────────────────────────────────
//  Validators — Phase 6
// ─────────────────────────────────────────────────────────
const ALLOWED_CONDITIONS = new Set(['good', 'repair', 'discard']);
const ALLOWED_BUDGET_TYPES = new Set(['income', 'expense']);
const ALLOWED_BUDGET_SOURCES = new Set(['parents', 'gapan', 'authority']);
const ALLOWED_ENTRY_TYPES = new Set(['חיזוק', 'אתגר', 'שיחת משוב', 'אירוע', 'מעבר']);
const ALLOWED_ROLES = new Set(['systemadmin', 'principal', 'staffmember']);
const ALLOWED_DATA_TYPES = new Set(['plan', 'gantt', 'mtss', 'calendar', 'teachers', 'custom_links']);
const PERM_LEVELS = { none: 0, view: 1, edit: 2, admin: 3 };

// Maps an api/data `type` (and inventory/budget) to the staff
// permission-grid keys defined in index.html's SECTION_GROUPS.
// LIMITATION (documented, not silently assumed away): the "plan"
// payload bundles many client-side sections (s0-s6, splan, s_hours,
// etc.) into one JSON blob. This backend enforces access at the
// resource level — "does the caller hold the required level on ANY
// of this resource's section keys" — it cannot yet enforce per-section
// field-level access within a single stored blob. If that granularity
// is required, the payload should be split per section server-side.
const MODULE_PERMISSION_KEYS = {
  plan: ['s0', 's1', 's2', 's3', 's4', 's5', 's6', 's_dash', 'splan', 's_hours', 's_schedule', 's_hanam_hrs', 's_absences', 'sdefects'],
  gantt: ['gantt'],
  mtss: ['mtss'],
  calendar: ['calendar'],
  budget: ['sbudget'],
  inventory: ['sinventory'],
  custom_links: [], // no dedicated grid key; treated as general-portal, principal/admin write only
  teachers: [], // HR — staff have no permission-grid delegation by default (see authorization matrix)
};

function reqStr(v, maxLen) {
  if (typeof v !== 'string') return null;
  const t = v.trim();
  if (!t || t.length > (maxLen || 200)) return null;
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x08\x0B\x0C\x0E-\x1F]/.test(t)) return null; // control chars
  return t;
}
function validSchool(v) { return reqStr(v, 120); }
function validYear(v) { return reqStr(v, 20); }
function validEmail(v) {
  const t = reqStr(v, 254);
  if (!t) return null;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(t) ? t.toLowerCase() : null;
}
function validUsername(v) {
  const t = reqStr(v, 64);
  if (!t) return null;
  const normalized = t.normalize('NFKC').toLowerCase();
  return /^[\p{L}\p{N}._-]+$/u.test(normalized) ? normalized : null;
}
function validPathUsername(v) {
  try {
    return validUsername(decodeURIComponent(String(v || '')));
  } catch {
    return null;
  }
}
function validId(v) {
  if (typeof v === 'string' && !/^[1-9]\d*$/.test(v)) return null;
  const n = typeof v === 'string' ? Number(v) : v;
  return Number.isInteger(n) && n > 0 && n <= Number.MAX_SAFE_INTEGER ? n : null;
}
function validAmount(v) {
  const n = Number(v);
  return Number.isFinite(n) && Math.abs(n) < 1e12 ? n : null;
}
function validQuantity(v) {
  const n = Number(v);
  return Number.isInteger(n) && n >= 0 && n < 1e9 ? n : null;
}
function validDate(v) {
  const t = reqStr(v, 10);
  if (!t) return null;
  return /^\d{4}-\d{2}-\d{2}$/.test(t) ? t : null;
}
function validEnum(v, set) {
  const t = typeof v === 'string' ? v.trim() : '';
  return set.has(t) ? t : null;
}

// ─────────────────────────────────────────────────────────
//  Server-derived "latest year with data" resolver (unchanged logic)
// ─────────────────────────────────────────────────────────
async function resolveLatestYear(env, school) {
  if (!school) return '';
  try {
    const row = await env.DB.prepare(
      `SELECT year FROM portal_data WHERE school = ? AND year IS NOT NULL AND year != '' ORDER BY updated_at DESC LIMIT 1`
    ).bind(school).first();
    return row?.year || '';
  } catch { return ''; }
}

// ─────────────────────────────────────────────────────────
//  Login lockout / password policy
// ─────────────────────────────────────────────────────────
const MAX_FAILED_ATTEMPTS = 3;
const LOCKOUT_MINUTES = 15;         // temporary lockout, not permanent — avoids self-DoS
const PASSWORD_EXPIRY_DAYS = 90;
const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 1024;
const SESSION_LIFETIME_HOURS = 10;  // absolute max lifetime
const SESSION_IDLE_HOURS = 10;      // idle expiry (same window for simplicity)

function checkPasswordExpired(passwordChangedAt) {
  if (!passwordChangedAt) return true;
  const diffDays = (Date.now() - new Date(passwordChangedAt).getTime()) / 86400000;
  return diffDays > PASSWORD_EXPIRY_DAYS;
}
function normaliseRole(raw) {
  if (!raw) return 'staffmember';
  const r = String(raw).toLowerCase().trim();
  if (r === 'systemadmin' || r === 'system_admin' || r === 'admin') return 'systemadmin';
  if (r === 'principal') return 'principal';
  return 'staffmember';
}

// ─────────────────────────────────────────────────────────
//  Sessions — Phase 2
// ─────────────────────────────────────────────────────────
async function createSession(env, { username, school, year, role }, request) {
  const rawToken = generateToken();
  const tokenHash = await hashToken(rawToken);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + SESSION_LIFETIME_HOURS * 3600 * 1000).toISOString();
  const ipHash = await sha256Hex(request.headers.get('CF-Connecting-IP') || 'unknown');
  const uaHash = await sha256Hex(request.headers.get('User-Agent') || 'unknown');

  await env.DB.prepare(`
    INSERT INTO staffsessions
      (token_hash, username, school, year, role, created_at, expires_at, last_seen_at, ip_hash, user_agent_hash)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(tokenHash, username, school || '', year || '', role, now.toISOString(), expiresAt, now.toISOString(), ipHash, uaHash).run();

  return { token: rawToken, expiresAt };
}

// Loads authoritative permissions for a staffmember session (short-TTL
// cached in KV; principal/systemadmin sessions carry no per-module grid).
async function loadPermissions(env, username, school, year, role) {
  if (role !== 'staffmember') return {};
  const cacheKey = `perm:${username}:${school}:${year}`;
  try {
    const cached = await env.SESSIONS_KV.get(cacheKey, 'json');
    if (cached) return cached;
  } catch (_) { /* fall through to D1 */ }

  const row = await env.DB.prepare(
    'SELECT permissions FROM staff_permissions WHERE email = ? AND school = ? AND year = ?'
  ).bind(username, school, year).first();
  let permissions = {};
  if (row) { try { permissions = JSON.parse(row.permissions); } catch (_) {} }

  try {
    await env.SESSIONS_KV.put(cacheKey, JSON.stringify(permissions), { expirationTtl: 60 }); // short TTL, Phase 2 requirement
  } catch (_) { /* non-fatal */ }
  return permissions;
}

async function validateSession(request, env, allowedRoles) {
  const authHeader = request.headers.get('Authorization') || '';
  const rawToken = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
  if (!rawToken || rawToken.length < 32) return { ok: false, error: 'Authorization token missing or malformed' };

  const tokenHash = await hashToken(rawToken);
  const row = await env.DB.prepare(
    `SELECT username, school, year, role, expires_at, last_seen_at, revoked_at FROM staffsessions WHERE token_hash = ?`
  ).bind(tokenHash).first();

  if (!row) return { ok: false, error: 'Invalid session' };
  if (row.revoked_at) return { ok: false, error: 'Session revoked' };
  if (new Date(row.expires_at) < new Date()) return { ok: false, error: 'Session expired' };
  if (row.last_seen_at) {
    const idleMs = Date.now() - new Date(row.last_seen_at).getTime();
    if (!Number.isFinite(idleMs) || idleMs > SESSION_IDLE_HOURS * 3600 * 1000) {
      await revokeSession(env, tokenHash);
      return { ok: false, error: 'Session expired' };
    }
  }

  // Best-effort last_seen_at bump (non-blocking correctness, ignore failures)
  try {
    await env.DB.prepare('UPDATE staffsessions SET last_seen_at = ? WHERE token_hash = ?')
      .bind(new Date().toISOString(), tokenHash).run();
  } catch (_) {}

  if (allowedRoles && allowedRoles.length > 0 && !allowedRoles.includes(row.role)) {
    return { ok: false, error: `Access denied — requires role: ${allowedRoles.join(' | ')}` };
  }

  let passwordChangeRequired = false;
  if (row.role === 'staffmember') {
    const authState = await env.DB.prepare(
      'SELECT must_change_password, password_changed_at FROM staff_auth WHERE username = ?'
    ).bind(row.username).first();
    passwordChangeRequired = !!authState &&
      (authState.must_change_password === 1 || checkPasswordExpired(authState.password_changed_at));
  }

  const permissions = await loadPermissions(env, row.username, row.school, row.year, row.role);
  return {
    ok: true,
    username: row.username,
    school: row.school,
    year: row.year,
    role: row.role,
    permissions,
    tokenHash,
    passwordChangeRequired,
  };
}

async function requireSession(request, env, options) {
  const session = await validateSession(request, env);
  if (!session.ok) throw new HttpError(401, session.error || 'Unauthorized');
  if (session.passwordChangeRequired && !options?.allowPasswordChangeRequired) {
    throw new HttpError(403, 'Password change required');
  }
  return session;
}
async function requireRole(request, env, allowedRoles) {
  const session = await validateSession(request, env, allowedRoles);
  if (!session.ok) throw new HttpError(session.error && session.error.includes('token') ? 401 : 403, session.error || 'Forbidden');
  return session;
}
function requireSameSchool(session, requestedSchool) {
  if (session.role === 'systemadmin') return;
  if (!requestedSchool || session.school !== requestedSchool) {
    throw new HttpError(403, 'Cross-school access denied');
  }
}
function requireSameStaffAuthTenant(session, requestedSchool, requestedYear) {
  if (session.role === 'systemadmin') return;
  if (!requestedSchool || !requestedYear ||
      session.school !== requestedSchool || session.year !== requestedYear) {
    throw new HttpError(403, 'Cross-school/year access denied');
  }
}
function requirePermission(session, moduleName, requiredLevel) {
  if (session.role === 'systemadmin' || session.role === 'principal') return; // full school/global access per matrix
  const keys = MODULE_PERMISSION_KEYS[moduleName] || [];
  const needed = PERM_LEVELS[requiredLevel] || 0;
  const granted = keys.some(k => (PERM_LEVELS[session.permissions?.[k]] || 0) >= needed);
  if (!granted) throw new HttpError(403, `Forbidden — insufficient permission for ${moduleName}`);
}

async function revokeSession(env, tokenHash) {
  await env.DB.prepare('UPDATE staffsessions SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL')
    .bind(new Date().toISOString(), tokenHash).run();
}
async function revokeAllSessionsForUser(env, username) {
  await env.DB.prepare('UPDATE staffsessions SET revoked_at = ? WHERE username = ? AND revoked_at IS NULL')
    .bind(new Date().toISOString(), username).run();
}

// ─────────────────────────────────────────────────────────
//  Google ID token verification (server-side signature check)
// ─────────────────────────────────────────────────────────
const GOOGLE_CLIENT_ID = '492239820935-ov9bvrgcf05jejdsnburactcnpm9d5qb.apps.googleusercontent.com';
async function verifyGoogleIdToken(idToken) {
  if (!idToken || typeof idToken !== 'string' || idToken.length > 4096) return null;
  let res;
  try {
    res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${encodeURIComponent(idToken)}`);
  } catch (_) { return null; }
  if (!res.ok) return null;
  let data;
  try { data = await res.json(); } catch (_) { return null; }
  if (data.aud !== GOOGLE_CLIENT_ID) return null;
  if (data.email_verified !== 'true' && data.email_verified !== true) return null;
  if (!data.email) return null;
  if (data.exp && Date.now() / 1000 > Number(data.exp)) return null;
  return { email: String(data.email).toLowerCase() };
}

// ─────────────────────────────────────────────────────────
//  Audit log — Phase 7 (baseline)
// ─────────────────────────────────────────────────────────
async function audit(env, request, { session, action, resourceType, resourceId, targetSchool, targetYear, outcome, metadata }) {
  try {
    const ipHash = await sha256Hex(request.headers.get('CF-Connecting-IP') || 'unknown');
    const uaHash = await sha256Hex(request.headers.get('User-Agent') || 'unknown');
    await env.DB.prepare(`
      INSERT INTO audit_log
        (occurred_at, request_id, actor_username, actor_role, actor_school, action, resource_type,
         resource_id, target_school, target_year, outcome, ip_hash, user_agent_hash, metadata_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      new Date().toISOString(),
      crypto.randomUUID(),
      session?.username || null,
      session?.role || null,
      session?.school || null,
      action,
      resourceType,
      resourceId != null ? String(resourceId) : null,
      targetSchool || null,
      targetYear || null,
      outcome || 'unknown',
      ipHash, uaHash,
      JSON.stringify(metadata || {})
    ).run();
  } catch (e) {
    console.error('[audit] write failed (non-fatal):', e.message);
  }
}

// ─────────────────────────────────────────────────────────
//  Simple KV-backed rate limiting (best-effort; fails open on KV outage)
// ─────────────────────────────────────────────────────────
async function rateLimit(env, key, limit, windowSeconds) {
  try {
    const raw = await env.SESSIONS_KV.get(key);
    const count = raw ? parseInt(raw, 10) : 0;
    if (count >= limit) return false;
    await env.SESSIONS_KV.put(key, String(count + 1), { expirationTtl: windowSeconds });
    return true;
  } catch (_) { return true; } // KV outage should not brick login entirely
}

// ═══════════════════════════════════════════════════════════
export default {
  async fetch(request, env, ctx) {
    const cors = getCorsHeaders(request);
    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    const url = new URL(request.url);
    const path = url.pathname.replace(/^\//, '');
    const method = request.method;
    const q = p => url.searchParams.get(p) || '';
    const body = async () => { try { return await request.json(); } catch { return {}; } };
    const seg = path.split('/').filter(Boolean);
    const lastSeg = seg[seg.length - 1];
    const numId = validId(lastSeg);

    try {
      // ═══════════════════════════════════════════════
      //  HEALTH CHECK (public, no internal config leaked)
      // ═══════════════════════════════════════════════
      if (method === 'GET' && path === 'api/health') {
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  AUTHENTICATION
      // ═══════════════════════════════════════════════

      // POST /api/auth/staff-login  (public)
      if (method === 'POST' && path === 'api/auth/staff-login') {
        const { username, password, year } = await body();
        const cleanUsername = validUsername(username);
        if (!cleanUsername || typeof password !== 'string' || !password || password.length > MAX_PASSWORD_LENGTH) {
          return err('שם משתמש וסיסמא נדרשים', 400, cors);
        }

        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const rlOk = await rateLimit(env, `rl:login:${ip}:${cleanUsername}`, 10, 300); // 10 attempts / 5 min per ip+user
        if (!rlOk) {
          await audit(env, request, { action: 'login', resourceType: 'staff_auth', outcome: 'rate_limited', metadata: { username: cleanUsername } });
          return err('יותר מדי ניסיונות. נסה/י שוב בעוד מספר דקות.', 429, cors);
        }

        const authRow = await env.DB.prepare('SELECT * FROM staff_auth WHERE username = ?').bind(cleanUsername).first();

        // Generic error — do not reveal whether the username exists.
        const genericFail = () => json({ ok: false, error: 'שם משתמש או סיסמא שגויים' }, 401, cors);
        if (!authRow) { await audit(env, request, { action: 'login', resourceType: 'staff_auth', outcome: 'unknown_user' }); return genericFail(); }

        if (authRow.locked_at) {
          const lockedSince = new Date(authRow.locked_at).getTime();
          const unlockAt = lockedSince + LOCKOUT_MINUTES * 60000;
          if (Date.now() < unlockAt) {
            await audit(env, request, { action: 'login', resourceType: 'staff_auth', outcome: 'locked', metadata: { username: cleanUsername } });
            return json({ ok: false, error: `החשבון נעול זמנית עקב ניסיונות כושלים. נסה/י שוב בעוד כ-${LOCKOUT_MINUTES} דקות.`, locked: true }, 403, cors);
          }
          // Temporary lockout window elapsed — clear it and allow this attempt to proceed to a normal password check.
          await env.DB.prepare('UPDATE staff_auth SET locked_at = NULL, failed_attempts = 0 WHERE username = ?').bind(cleanUsername).run();
          authRow.locked_at = null;
          authRow.failed_attempts = 0;
        }

        const valid = await verifyPassword(password, authRow.password_hash, authRow.password_salt, authRow.password_iterations);
        if (!valid) {
          const newFailed = (authRow.failed_attempts || 0) + 1;
          const now = new Date().toISOString();
          if (newFailed >= MAX_FAILED_ATTEMPTS) {
            await env.DB.prepare('UPDATE staff_auth SET failed_attempts=?, locked_at=?, updated_at=? WHERE username=?')
              .bind(newFailed, now, now, cleanUsername).run();
            await audit(env, request, { action: 'login', resourceType: 'staff_auth', outcome: 'locked_out', metadata: { username: cleanUsername } });
            return json({ ok: false, error: `יותר מ-${MAX_FAILED_ATTEMPTS} ניסיונות כושלים — החשבון ננעל זמנית.`, locked: true }, 403, cors);
          }
          await env.DB.prepare('UPDATE staff_auth SET failed_attempts=?, updated_at=? WHERE username=?').bind(newFailed, now, cleanUsername).run();
          await audit(env, request, { action: 'login', resourceType: 'staff_auth', outcome: 'bad_password', metadata: { username: cleanUsername } });
          return genericFail();
        }

        // Success — reset counters, transparently upgrade PBKDF2 iterations if stale.
        const now = new Date().toISOString();
        await env.DB.prepare('UPDATE staff_auth SET failed_attempts=0, last_login=?, updated_at=? WHERE username=?')
          .bind(now, now, cleanUsername).run();
        if ((authRow.password_iterations || LEGACY_PBKDF2_ITERATIONS) < CURRENT_PBKDF2_ITERATIONS) {
          const upgraded = await hashPassword(password, null, CURRENT_PBKDF2_ITERATIONS);
          await env.DB.prepare('UPDATE staff_auth SET password_hash=?, password_salt=?, password_iterations=? WHERE username=?')
            .bind(upgraded.hash, upgraded.salt, upgraded.iterations, cleanUsername).run();
        }

        const passwordExpired = checkPasswordExpired(authRow.password_changed_at);
        const targetSchool = authRow.school || '';
        // Password-authenticated staff accounts are year-scoped. A URL/body
        // hint must never move the caller into another year's tenant.
        const targetYear = authRow.year || (targetSchool ? await resolveLatestYear(env, targetSchool) : '');

        const { token, expiresAt } = await createSession(env, { username: cleanUsername, school: targetSchool, year: targetYear, role: 'staffmember' }, request);
        const permissions = await loadPermissions(env, cleanUsername, targetSchool, targetYear, 'staffmember');

        await audit(env, request, { session: { username: cleanUsername, role: 'staffmember', school: targetSchool }, action: 'login', resourceType: 'staff_auth', outcome: 'success' });

        return json({
          ok: true,
          token,
          session: {
            username: cleanUsername,
            name: authRow.name || cleanUsername,
            role: 'staffmember',
            school: targetSchool,
            year: targetYear,
            roleTitle: authRow.role_title || '',
            permissions,
            expiresAt,
            passwordExpired,
            mustChangePassword: authRow.must_change_password === 1 || passwordExpired,
          },
        }, 200, cors);
      }

      // POST /api/auth/google-login  (public — verifies Google ID token server-side)
      if (method === 'POST' && path === 'api/auth/google-login') {
        const { idToken, requestedRole, school: hintSchool, year: hintYear } = await body();
        const verified = await verifyGoogleIdToken(idToken);
        if (!verified) return err('אימות Google נכשל', 401, cors);
        const email = verified.email;

        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const rlOk = await rateLimit(env, `rl:glogin:${ip}:${email}`, 20, 300);
        if (!rlOk) return err('יותר מדי ניסיונות. נסה/י שוב בעוד מספר דקות.', 429, cors);

        let role = null, name = email, resolvedSchool = validSchool(hintSchool) || '', resolvedYear = validYear(hintYear) || '';

        if (requestedRole !== 'staffmember') {
          const admin = await env.DB.prepare('SELECT * FROM admins WHERE email = ?').bind(email).first();
          if (admin) { role = 'systemadmin'; name = admin.name || email; }
          if (!role) {
            const principal = await env.DB.prepare('SELECT * FROM principals WHERE email = ?').bind(email).first();
            if (principal) {
              role = 'principal';
              name = principal.name || email;
              resolvedSchool = principal.school || resolvedSchool;
              resolvedYear = resolvedYear || await resolveLatestYear(env, resolvedSchool);
            }
          }
        }
        if (!role && resolvedSchool) {
          resolvedYear = resolvedYear || await resolveLatestYear(env, resolvedSchool);
          if (resolvedYear) {
            const staff = await env.DB.prepare('SELECT * FROM staff_permissions WHERE email = ? AND school = ? AND year = ?')
              .bind(email, resolvedSchool, resolvedYear).first();
            if (staff) { role = 'staffmember'; name = staff.name || email; }
          }
        }

        if (!role) {
          await audit(env, request, { action: 'login', resourceType: 'google_auth', outcome: 'unauthorized', metadata: { email } });
          return json({ ok: false, error: 'המשתמש/ת אינו/ה מורשה/ת לגשת לפורטל זה.' }, 403, cors);
        }

        const { token, expiresAt } = await createSession(env, { username: email, school: resolvedSchool, year: resolvedYear, role }, request);
        const permissions = await loadPermissions(env, email, resolvedSchool, resolvedYear, role);
        await audit(env, request, { session: { username: email, role, school: resolvedSchool }, action: 'login', resourceType: 'google_auth', outcome: 'success' });

        return json({ ok: true, token, session: { username: email, name, role, school: resolvedSchool, year: resolvedYear, permissions, expiresAt } }, 200, cors);
      }

      // GET /api/auth/role — now a "who am I" refresh endpoint. Requires
      // a valid session; no longer resolves role from a client-supplied
      // email (see file header — closes the impersonation vulnerability).
      if (method === 'GET' && path === 'api/auth/role') {
        const session = await requireSession(request, env);
        return json({ role: session.role, school: session.school, year: session.year, permissions: session.permissions, username: session.username }, 200, cors);
      }

      // POST /api/auth/logout
      if (method === 'POST' && path === 'api/auth/logout') {
        const session = await requireSession(request, env);
        await revokeSession(env, session.tokenHash);
        try { await env.SESSIONS_KV.delete(`perm:${session.username}:${session.school}:${session.year}`); } catch (_) {}
        await audit(env, request, { session, action: 'logout', resourceType: 'session', outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // POST /api/auth/staff-change-password
      if (method === 'POST' && path === 'api/auth/staff-change-password') {
        const session = await requireSession(request, env, { allowPasswordChangeRequired: true });
        const { username, currentPassword, newPassword } = await body();
        const cleanUsername = validUsername(username);
        if (
          !cleanUsername ||
          typeof currentPassword !== 'string' ||
          typeof newPassword !== 'string' ||
          !currentPassword ||
          !newPassword ||
          currentPassword.length > MAX_PASSWORD_LENGTH ||
          newPassword.length > MAX_PASSWORD_LENGTH
        ) return err('username, currentPassword, newPassword נדרשים', 400, cors);
        if (session.role !== 'staffmember' || session.username !== cleanUsername) {
          return err('forbidden', 403, cors);
        }
        if (newPassword.length < MIN_PASSWORD_LENGTH) return err(`הסיסמא חייבת להכיל לפחות ${MIN_PASSWORD_LENGTH} תווים`, 400, cors);

        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const rlOk = await rateLimit(env, `rl:password-change:${ip}:${cleanUsername}`, 5, 900);
        if (!rlOk) return err('יותר מדי ניסיונות. נסה/י שוב בעוד מספר דקות.', 429, cors);

        const authRow = await env.DB.prepare('SELECT * FROM staff_auth WHERE username = ?').bind(cleanUsername).first();
        if (!authRow) return err('forbidden', 403, cors);

        const valid = await verifyPassword(currentPassword, authRow.password_hash, authRow.password_salt, authRow.password_iterations);
        if (!valid) return json({ ok: false, error: 'הסיסמא הנוכחית שגויה' }, 401, cors);

        const { hash, salt, iterations } = await hashPassword(newPassword, null, CURRENT_PBKDF2_ITERATIONS);
        const now = new Date().toISOString();
        await env.DB.prepare(`
          UPDATE staff_auth
          SET password_hash=?, password_salt=?, password_iterations=?, password_changed_at=?, must_change_password=0,
              failed_attempts=0, locked_at=NULL, updated_at=?
          WHERE username=?
        `).bind(hash, salt, iterations, now, now, cleanUsername).run();

        await revokeAllSessionsForUser(env, cleanUsername); // Phase 2: password change revokes all sessions
        await audit(env, request, { action: 'password_change', resourceType: 'staff_auth', outcome: 'success', metadata: { username: cleanUsername } });
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  ADMIN: staff_auth account management.
      //  Principals are restricted to the school + year in their session;
      //  systemadmins retain global access.
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/admin/staff-auth/list') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (session.role === 'principal') {
          if (!school || !year) return err('school, year required', 400, cors);
          requireSameStaffAuthTenant(session, school, year);
        }
        let stmt;
        if (school && year) {
          stmt = env.DB.prepare(
            'SELECT username, name, email, school, year, role_title, failed_attempts, locked_at, last_login, password_changed_at, must_change_password, created_at FROM staff_auth WHERE school=? AND year=? ORDER BY name'
          ).bind(school, year);
        } else {
          stmt = env.DB.prepare(
            'SELECT username, name, email, school, year, role_title, failed_attempts, locked_at, last_login, password_changed_at, must_change_password, created_at FROM staff_auth ORDER BY school, name'
          );
        }
        const { results } = await stmt.all();
        await audit(env, request, { session, action: 'list', resourceType: 'staff_auth', outcome: 'success' });
        return json((results || []).map(r => ({ ...r, isLocked: !!r.locked_at, passwordExpired: checkPasswordExpired(r.password_changed_at) })), 200, cors);
      }

      if (method === 'POST' && path === 'api/admin/staff-auth') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const { username, password, name, email, school, year, roleTitle, mustChangePassword } = await body();
        const cleanUsername = validUsername(username);
        const cleanSchool = validSchool(school) || '';
        const cleanYear = validYear(year) || '';
        const cleanEmail = email ? validEmail(email) : `${cleanUsername}@local`;
        if (!cleanUsername || typeof password !== 'string' || !password || password.length > MAX_PASSWORD_LENGTH) {
          return err('username ו-password נדרשים', 400, cors);
        }
        if (password.length < MIN_PASSWORD_LENGTH) return err(`הסיסמא חייבת להכיל לפחות ${MIN_PASSWORD_LENGTH} תווים`, 400, cors);
        if (!cleanEmail) return err('email לא תקין', 400, cors);
        if (session.role === 'principal' && (!cleanSchool || !cleanYear)) return err('school, year required', 400, cors);
        requireSameStaffAuthTenant(session, cleanSchool, cleanYear);

        const existing = await env.DB.prepare('SELECT username FROM staff_auth WHERE username = ?').bind(cleanUsername).first();
        if (existing) return err('שם משתמש כבר קיים במערכת', 409, cors);

        const { hash, salt, iterations } = await hashPassword(password, null, CURRENT_PBKDF2_ITERATIONS);
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO staff_auth
            (username, password_hash, password_salt, password_iterations, name, email, school, year,
             role_title, must_change_password, failed_attempts, password_changed_at, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?, ?)
        `).bind(cleanUsername, hash, salt, iterations, name || '', cleanEmail, cleanSchool, cleanYear,
                roleTitle || '', mustChangePassword ? 1 : 0, now, now, now).run();

        await audit(env, request, { session, action: 'create', resourceType: 'staff_auth', resourceId: cleanUsername, targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true, username: cleanUsername }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/admin/staff-auth/') && path.endsWith('/reset-password')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const username = validPathUsername(seg[seg.length - 2]);
        const { newPassword } = await body();
        if (!username || typeof newPassword !== 'string' || !newPassword || newPassword.length > MAX_PASSWORD_LENGTH) {
          return err('username ו-newPassword נדרשים', 400, cors);
        }
        if (newPassword.length < MIN_PASSWORD_LENGTH) return err(`הסיסמא חייבת להכיל לפחות ${MIN_PASSWORD_LENGTH} תווים`, 400, cors);

        const existing = await env.DB.prepare('SELECT username, school, year FROM staff_auth WHERE username = ?').bind(username).first();
        if (!existing) return err('משתמש לא נמצא', 404, cors);
        requireSameStaffAuthTenant(session, existing.school, existing.year);

        const { hash, salt, iterations } = await hashPassword(newPassword, null, CURRENT_PBKDF2_ITERATIONS);
        const now = new Date().toISOString();
        await env.DB.prepare(`
          UPDATE staff_auth
          SET password_hash=?, password_salt=?, password_iterations=?, password_changed_at=?, must_change_password=1,
              failed_attempts=0, locked_at=NULL, updated_at=?
          WHERE username=? AND school=? AND year=?
        `).bind(hash, salt, iterations, now, now, username, existing.school, existing.year).run();

        await revokeAllSessionsForUser(env, username); // Phase 2: reset revokes all sessions
        await audit(env, request, { session, action: 'password_reset', resourceType: 'staff_auth', resourceId: username, targetSchool: existing.school, targetYear: existing.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/admin/staff-auth/') && path.endsWith('/unlock')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const username = validPathUsername(seg[seg.length - 2]);
        if (!username) return err('username נדרש', 400, cors);
        const existing = await env.DB.prepare('SELECT username, school, year FROM staff_auth WHERE username = ?').bind(username).first();
        if (!existing) return err('משתמש לא נמצא', 404, cors);
        requireSameStaffAuthTenant(session, existing.school, existing.year);
        const now = new Date().toISOString();
        await env.DB.prepare('UPDATE staff_auth SET locked_at=NULL, failed_attempts=0, updated_at=? WHERE username=? AND school=? AND year=?')
          .bind(now, username, existing.school, existing.year).run();
        await audit(env, request, { session, action: 'unlock', resourceType: 'staff_auth', resourceId: username, targetSchool: existing.school, targetYear: existing.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path.startsWith('api/admin/staff-auth/') && !path.endsWith('/unlock') && !path.endsWith('/reset-password')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const username = validPathUsername(lastSeg);
        if (!username) return err('username נדרש', 400, cors);
        const existing = await env.DB.prepare('SELECT username, school, year FROM staff_auth WHERE username = ?').bind(username).first();
        if (!existing) return json({ ok: false, error: `משתמש "${username}" לא נמצא` }, 404, cors);
        requireSameStaffAuthTenant(session, existing.school, existing.year);
        const result = await env.DB.prepare('DELETE FROM staff_auth WHERE username = ? AND school = ? AND year = ?')
          .bind(username, existing.school, existing.year).run();
        const changes = result.meta?.changes ?? 0;
        await revokeAllSessionsForUser(env, username);
        await audit(env, request, { session, action: 'delete', resourceType: 'staff_auth', resourceId: username, targetSchool: existing.school, targetYear: existing.year, outcome: changes ? 'success' : 'not_found' });
        if (changes === 0) return json({ ok: false, error: `משתמש "${username}" לא נמצא` }, 404, cors);
        return json({ ok: true, deleted: username }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  LOOKUPS  (principal / admin / supervisor / instructor)
      //  Previously unauthenticated by-email lookups exposing
      //  personal data to anyone who knew/guessed an email.
      //  Now requires a session; non-systemadmin callers may
      //  only look up their own record.
      // ═══════════════════════════════════════════════
      if (method === 'GET' && path === 'api/principal') {
        const session = await requireSession(request, env);
        const email = validEmail(q('email'));
        if (!email) return err('email required', 400, cors);
        if (session.role !== 'systemadmin' && session.username !== email) return err('forbidden', 403, cors);
        const row = await env.DB.prepare('SELECT * FROM principals WHERE email = ?').bind(email).first();
        if (!row) return err('not found', 404, cors);
        return json({ ...row }, 200, cors);
      }

      if (method === 'GET' && path === 'api/admin') {
        const session = await requireSession(request, env);
        const email = validEmail(q('email'));
        if (!email) return err('email required', 400, cors);
        if (session.role !== 'systemadmin' && session.username !== email) return err('forbidden', 403, cors);
        const row = await env.DB.prepare('SELECT * FROM admins WHERE email = ?').bind(email).first();
        if (!row) return err('not found', 404, cors);
        return json({ ...row }, 200, cors);
      }

      if (method === 'GET' && path === 'api/supervisors') {
        await requireRole(request, env, ['systemadmin']);
        const { results } = await env.DB.prepare('SELECT * FROM supervisors').all();
        return json(results || [], 200, cors);
      }

      if (method === 'GET' && path === 'api/supervisor') {
        const session = await requireSession(request, env);
        const email = validEmail(q('email'));
        if (!email) return err('email required', 400, cors);
        if (session.role !== 'systemadmin' && session.username !== email) return err('forbidden', 403, cors);
        const row = await env.DB.prepare('SELECT * FROM supervisors WHERE email = ?').bind(email).first();
        if (!row) return err('not found', 404, cors);
        return json({ ...row }, 200, cors);
      }

      if (method === 'GET' && path === 'api/instructor') {
        const session = await requireSession(request, env);
        const email = validEmail(q('email'));
        if (!email) return err('email required', 400, cors);
        if (session.role !== 'systemadmin' && session.username !== email) return err('forbidden', 403, cors);
        const row = await env.DB.prepare('SELECT * FROM instructors WHERE email = ?').bind(email).first();
        if (!row) return err('not found', 404, cors);
        return json({ ...row }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  STAFF PERMISSIONS  (school-scoped)
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/staff') {
        const session = await requireSession(request, env);
        const email = validEmail(q('email'));
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!email || !school || !year) return err('email, school, year required', 400, cors);
        if (session.role === 'staffmember' && session.username !== email) return err('forbidden', 403, cors);
        requireSameSchool(session, school);
        const row = await env.DB.prepare('SELECT * FROM staff_permissions WHERE email = ? AND school = ? AND year = ?').bind(email, school, year).first();
        if (!row) return err('not found', 404, cors);
        let permissions = {}; try { permissions = JSON.parse(row.permissions); } catch (_) {}
        return json({ ...row, permissions }, 200, cors);
      }

      if (method === 'GET' && path === 'api/staff/list') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!school || !year) return err('school, year required', 400, cors);
        requireSameSchool(session, school);
        const { results } = await env.DB.prepare('SELECT * FROM staff_permissions WHERE school = ? AND year = ?').bind(school, year).all();
        const rows = (results || []).map(r => { let permissions = {}; try { permissions = JSON.parse(r.permissions); } catch (_) {} return { ...r, permissions }; });
        return json(rows, 200, cors);
      }

      // Permission-record writes: uses ON CONFLICT DO UPDATE instead of
      // INSERT OR REPLACE (Non-Negotiable Rules — avoid silent row
      // recreation of security-relevant records; preserves created_by/created_at).
      if (method === 'POST' && path === 'api/staff-permissions') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const { email, name, roleTitle, school, year, permissions } = await body();
        const cleanEmail = validEmail(email);
        const cleanSchool = validSchool(school);
        const cleanYear = validYear(year);
        if (!cleanEmail || !cleanSchool || !cleanYear) return err('email, school, year required', 400, cors);
        requireSameSchool(session, cleanSchool);

        // Validate permission values against the allowlisted level enum.
        const permObj = typeof permissions === 'object' && permissions ? permissions : {};
        for (const [k, v] of Object.entries(permObj)) {
          if (!(k in PERM_LEVELS) && !['none', 'view', 'edit', 'admin'].includes(v)) { /* level check below covers value */ }
          if (!['none', 'view', 'edit', 'admin'].includes(v)) return err(`invalid permission level for ${k}`, 400, cors);
        }
        const permStr = JSON.stringify(permObj);
        const now = new Date().toISOString();
        const actor = session.username; // server-derived, not client-supplied

        await env.DB.prepare(`
          INSERT INTO staff_permissions (email, school, year, name, role_title, permissions, created_by, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(email, school, year) DO UPDATE SET
            name=excluded.name, role_title=excluded.role_title, permissions=excluded.permissions, updated_at=excluded.updated_at
        `).bind(cleanEmail, cleanSchool, cleanYear, name || '', roleTitle || '', permStr, actor, now, now).run();

        try { await env.SESSIONS_KV.delete(`perm:${cleanEmail}:${cleanSchool}:${cleanYear}`); } catch (_) {}
        await audit(env, request, { session, action: 'update', resourceType: 'staff_permissions', resourceId: cleanEmail, targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path === 'api/staff') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const email = validEmail(q('email'));
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!email || !school || !year) return err('email, school, year required', 400, cors);
        requireSameSchool(session, school);
        await env.DB.prepare('DELETE FROM staff_permissions WHERE email = ? AND school = ? AND year = ?').bind(email, school, year).run();
        await revokeAllSessionsForUser(env, email);
        const { results: linkedAccounts } = await env.DB.prepare(
          'SELECT username FROM staff_auth WHERE email = ?'
        ).bind(email).all();
        for (const account of linkedAccounts || []) {
          await revokeAllSessionsForUser(env, account.username);
        }
        try { await env.SESSIONS_KV.delete(`perm:${email}:${school}:${year}`); } catch (_) {}
        await audit(env, request, { session, action: 'delete', resourceType: 'staff_permissions', resourceId: email, targetSchool: school, targetYear: year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  HR MODULE — staff registry (school-scoped, principal/systemadmin only)
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/staff-hr' && seg.length === 2) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!school || !year) return err('school, year required', 400, cors);
        requireSameSchool(session, school);
        const { results } = await env.DB.prepare(`
          SELECT id, school, year, name, roletitle, role, subject, email, status, created_at, updated_at
          FROM staff WHERE school = ? AND year = ? AND status != 'archived' ORDER BY name
        `).bind(school, year).all();
        return json(results || [], 200, cors);
      }

      if (method === 'POST' && path === 'api/staff-hr' && seg.length === 2) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const { name, school, year, roletitle, subject, email } = await body();
        const cleanSchool = validSchool(school);
        const cleanYear = validYear(year);
        const cleanName = reqStr(name, 200);
        if (!cleanName || !cleanSchool || !cleanYear) return err('name, school, year required', 400, cors);
        requireSameSchool(session, cleanSchool);
        const cleanEmail = email ? (validEmail(email) || '') : '';
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          INSERT INTO staff (school, year, name, roletitle, role, subject, email, status, created_at, updated_at)
          VALUES (?, ?, ?, ?, 'staffmember', ?, ?, 'active', ?, ?)
        `).bind(cleanSchool, cleanYear, cleanName, reqStr(roletitle, 200) || '', reqStr(subject, 200) || '', cleanEmail, now, now).run();
        await audit(env, request, { session, action: 'create', resourceType: 'staff_hr', resourceId: result.meta?.lastrowid, targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true, id: result.meta?.lastrowid }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/staff-hr/') && seg.length === 3) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const staffId = validId(seg[2]);
        if (!staffId) return err('invalid staff id', 400, cors);
        const record = await env.DB.prepare('SELECT id, school FROM staff WHERE id = ?').bind(staffId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);

        const { name, roletitle, subject, email, status } = await body();
        if (status && !['active', 'archived'].includes(status)) return err('invalid status', 400, cors);
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          UPDATE staff SET
            name = COALESCE(?, name), roletitle = COALESCE(?, roletitle), subject = COALESCE(?, subject),
            email = COALESCE(?, email), status = COALESCE(?, status), updated_at = ?
          WHERE id = ? AND school = ?
        `).bind(name ?? null, roletitle ?? null, subject ?? null, email ?? null, status ?? null, now, staffId, record.school).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'update', resourceType: 'staff_hr', resourceId: staffId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path.startsWith('api/staff-hr/') && seg.length === 3) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const staffId = validId(seg[2]);
        if (!staffId) return err('invalid staff id', 400, cors);
        const record = await env.DB.prepare('SELECT id, school FROM staff WHERE id = ?').bind(staffId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);

        const linked = await env.DB.prepare("SELECT id FROM teachers WHERE staff_id = ? AND status != 'archived'").bind(staffId).first();
        if (linked) return err('לא ניתן למחוק — איש הצוות מקושר לרשומת מורה פעילה. יש לארכב את המורה קודם.', 409, cors);

        const result = await env.DB.prepare('DELETE FROM staff WHERE id = ? AND school = ?').bind(staffId, record.school).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'delete', resourceType: 'staff_hr', resourceId: staffId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  TEACHERS HR
      //  Read: any authenticated session, school-scoped.
      //  Write/archive: principal | systemadmin only.
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/teachers') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!school || !year) return err('school, year required', 400, cors);
        requireSameSchool(session, school);
        const { results } = await env.DB.prepare(`
          SELECT t.id, t.staff_id, t.school, t.year, t.notes, t.status, t.created_at, t.updated_at, t.created_by, t.updated_by,
                 s.name, s.role, s.roletitle, s.subject
          FROM teachers t JOIN staff s ON s.id = t.staff_id
          WHERE t.school = ? AND t.year = ? AND t.status != 'archived' ORDER BY s.name
        `).bind(school, year).all();
        return json(results || [], 200, cors);
      }

      if (method === 'POST' && path === 'api/teachers') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const { staffId, school, year, notes } = await body();
        const cleanStaffId = validId(staffId);
        const cleanSchool = validSchool(school);
        const cleanYear = validYear(year);
        if (!cleanStaffId || !cleanSchool || !cleanYear) return err('staffId, school, year required', 400, cors);
        requireSameSchool(session, cleanSchool);

        const staffRow = await env.DB.prepare('SELECT id, school FROM staff WHERE id = ?').bind(cleanStaffId).first();
        if (!staffRow || staffRow.school !== cleanSchool) return err('staff record not found in this school', 404, cors);

        const actor = session.username;
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          INSERT INTO teachers (staff_id, school, year, notes, status, created_at, updated_at, created_by, updated_by)
          VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
        `).bind(cleanStaffId, cleanSchool, cleanYear, reqStr(notes, 4000) || '', now, now, actor, actor).run();
        await audit(env, request, { session, action: 'create', resourceType: 'teachers', resourceId: result.meta?.lastrowid, targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true, id: result.meta?.lastrowid }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/teachers/') && !path.endsWith('/archive')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const teacherId = validId(seg[seg.length - 1]);
        if (!teacherId) return err('invalid teacher id', 400, cors);
        const record = await env.DB.prepare('SELECT id, staff_id, school FROM teachers WHERE id = ?').bind(teacherId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);

        const { notes, subject } = await body();
        const actor = session.username;
        const now = new Date().toISOString();
        if (notes !== undefined) {
          await env.DB.prepare('UPDATE teachers SET notes=?, updated_at=?, updated_by=? WHERE id=? AND school=?')
            .bind(reqStr(notes, 4000) || '', now, actor, teacherId, record.school).run();
        }
        if (subject !== undefined) {
          await env.DB.prepare('UPDATE staff SET subject=?, updated_at=? WHERE id=? AND school=?')
            .bind(reqStr(subject, 200) || '', now, record.staff_id, record.school).run();
        }
        await audit(env, request, { session, action: 'update', resourceType: 'teachers', resourceId: teacherId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/teachers/') && path.endsWith('/archive')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const teacherId = validId(seg[seg.length - 2]);
        if (!teacherId) return err('invalid teacher id', 400, cors);
        const record = await env.DB.prepare('SELECT id, school FROM teachers WHERE id = ?').bind(teacherId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        const now = new Date().toISOString();
        const result = await env.DB.prepare("UPDATE teachers SET status='archived', updated_at=?, updated_by=? WHERE id=? AND school=?")
          .bind(now, session.username, teacherId, record.school).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'archive', resourceType: 'teachers', resourceId: teacherId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ── teacher_entries ─────────────────────────────────
      if (method === 'GET' && path === 'api/teacher-entries') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const teacherId = validId(q('teacherId'));
        if (!teacherId) return err('teacherId required', 400, cors);
        const teacher = await env.DB.prepare('SELECT school FROM teachers WHERE id = ?').bind(teacherId).first();
        if (!teacher) return err('not found', 404, cors);
        requireSameSchool(session, teacher.school);
        const { results } = await env.DB.prepare(`
          SELECT * FROM teacher_entries WHERE teacher_id = ? AND status != 'archived' ORDER BY entry_date DESC
        `).bind(teacherId).all();
        return json(results || [], 200, cors);
      }

      if (method === 'POST' && path === 'api/teacher-entries') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const { teacherId, entryType, content, entryDate } = await body();
        const cleanTeacherId = validId(teacherId);
        const cleanEntryType = validEnum(entryType, ALLOWED_ENTRY_TYPES);
        const cleanDate = validDate(entryDate);
        if (!cleanTeacherId || !cleanEntryType || !cleanDate) return err('teacherId, entryType, entryDate required/invalid', 400, cors);
        const teacher = await env.DB.prepare('SELECT school FROM teachers WHERE id = ?').bind(cleanTeacherId).first();
        if (!teacher) return err('teacher not found', 404, cors);
        requireSameSchool(session, teacher.school);

        const actor = session.username;
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          INSERT INTO teacher_entries (teacher_id, entry_type, content, entry_date, status, created_at, updated_at, created_by, updated_by)
          VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
        `).bind(cleanTeacherId, cleanEntryType, reqStr(content, 4000) || '', cleanDate, now, now, actor, actor).run();
        await audit(env, request, { session, action: 'create', resourceType: 'teacher_entries', resourceId: result.meta?.lastrowid, targetSchool: teacher.school, outcome: 'success' });
        return json({ ok: true, id: result.meta?.lastrowid }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/teacher-entries/') && !path.endsWith('/archive')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const entryId = validId(seg[seg.length - 1]);
        if (!entryId) return err('invalid entry id', 400, cors);
        const record = await env.DB.prepare(
          `SELECT te.id, t.school FROM teacher_entries te JOIN teachers t ON t.id = te.teacher_id WHERE te.id = ?`
        ).bind(entryId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);

        const { entryType, content, entryDate } = await body();
        const cleanEntryType = entryType !== undefined ? validEnum(entryType, ALLOWED_ENTRY_TYPES) : null;
        if (entryType !== undefined && !cleanEntryType) return err('entryType לא חוקי', 400, cors);
        const cleanDate = entryDate !== undefined ? validDate(entryDate) : null;
        if (entryDate !== undefined && !cleanDate) return err('entryDate לא חוקי', 400, cors);

        const actor = session.username;
        const now = new Date().toISOString();
        await env.DB.prepare(`
          UPDATE teacher_entries SET entry_type=COALESCE(?,entry_type), content=COALESCE(?,content),
            entry_date=COALESCE(?,entry_date), updated_at=?, updated_by=? WHERE id=?
        `).bind(cleanEntryType, content !== undefined ? (reqStr(content, 4000) || '') : null, cleanDate, now, actor, entryId).run();
        await audit(env, request, { session, action: 'update', resourceType: 'teacher_entries', resourceId: entryId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/teacher-entries/') && path.endsWith('/archive')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const entryId = validId(seg[seg.length - 2]);
        if (!entryId) return err('invalid entry id', 400, cors);
        const record = await env.DB.prepare(
          `SELECT te.id, t.school FROM teacher_entries te JOIN teachers t ON t.id = te.teacher_id WHERE te.id = ?`
        ).bind(entryId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        const now = new Date().toISOString();
        await env.DB.prepare("UPDATE teacher_entries SET status='archived', updated_at=?, updated_by=? WHERE id=?")
          .bind(now, session.username, entryId).run();
        await audit(env, request, { session, action: 'archive', resourceType: 'teacher_entries', resourceId: entryId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ── teacher_bonuses ─────────────────────────────────
      if (method === 'GET' && path === 'api/teacher-bonuses') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const teacherId = validId(q('teacherId'));
        if (!teacherId) return err('teacherId required', 400, cors);
        const teacher = await env.DB.prepare('SELECT school FROM teachers WHERE id = ?').bind(teacherId).first();
        if (!teacher) return err('not found', 404, cors);
        requireSameSchool(session, teacher.school);
        const { results } = await env.DB.prepare(`
          SELECT * FROM teacher_bonuses WHERE teacher_id = ? AND status != 'archived' ORDER BY bonus_date DESC
        `).bind(teacherId).all();
        return json(results || [], 200, cors);
      }

      if (method === 'POST' && path === 'api/teacher-bonuses') {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const { teacherId, bonusType, description, amount, bonusDate } = await body();
        const cleanTeacherId = validId(teacherId);
        const cleanDate = validDate(bonusDate);
        if (!cleanTeacherId || !cleanDate) return err('teacherId, bonusDate required/invalid', 400, cors);
        const cleanAmount = amount !== undefined ? validAmount(amount) : 0;
        if (cleanAmount === null) return err('invalid amount', 400, cors);
        const teacher = await env.DB.prepare('SELECT school FROM teachers WHERE id = ?').bind(cleanTeacherId).first();
        if (!teacher) return err('teacher not found', 404, cors);
        requireSameSchool(session, teacher.school);

        const actor = session.username;
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          INSERT INTO teacher_bonuses (teacher_id, bonus_type, description, amount, bonus_date, status, created_at, updated_at, created_by, updated_by)
          VALUES (?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
        `).bind(cleanTeacherId, reqStr(bonusType, 100) || '', reqStr(description, 1000) || '', cleanAmount, cleanDate, now, now, actor, actor).run();
        await audit(env, request, { session, action: 'create', resourceType: 'teacher_bonuses', resourceId: result.meta?.lastrowid, targetSchool: teacher.school, outcome: 'success' });
        return json({ ok: true, id: result.meta?.lastrowid }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/teacher-bonuses/') && !path.endsWith('/archive')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const bonusId = validId(seg[seg.length - 1]);
        if (!bonusId) return err('invalid bonus id', 400, cors);
        const record = await env.DB.prepare(
          `SELECT tb.id, t.school FROM teacher_bonuses tb JOIN teachers t ON t.id = tb.teacher_id WHERE tb.id = ?`
        ).bind(bonusId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);

        const { bonusType, description, amount, bonusDate } = await body();
        const cleanDate = bonusDate !== undefined ? validDate(bonusDate) : null;
        if (bonusDate !== undefined && !cleanDate) return err('invalid bonusDate', 400, cors);
        const cleanAmount = amount !== undefined ? validAmount(amount) : null;
        if (amount !== undefined && cleanAmount === null) return err('invalid amount', 400, cors);

        const actor = session.username;
        const now = new Date().toISOString();
        await env.DB.prepare(`
          UPDATE teacher_bonuses SET bonus_type=COALESCE(?,bonus_type), description=COALESCE(?,description),
            amount=COALESCE(?,amount), bonus_date=COALESCE(?,bonus_date), updated_at=?, updated_by=? WHERE id=?
        `).bind(bonusType !== undefined ? (reqStr(bonusType, 100) || '') : null,
                description !== undefined ? (reqStr(description, 1000) || '') : null,
                cleanAmount, cleanDate, now, actor, bonusId).run();
        await audit(env, request, { session, action: 'update', resourceType: 'teacher_bonuses', resourceId: bonusId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/teacher-bonuses/') && path.endsWith('/archive')) {
        const session = await requireRole(request, env, ['principal', 'systemadmin']);
        const bonusId = validId(seg[seg.length - 2]);
        if (!bonusId) return err('invalid bonus id', 400, cors);
        const record = await env.DB.prepare(
          `SELECT tb.id, t.school FROM teacher_bonuses tb JOIN teachers t ON t.id = tb.teacher_id WHERE tb.id = ?`
        ).bind(bonusId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        const now = new Date().toISOString();
        await env.DB.prepare("UPDATE teacher_bonuses SET status='archived', updated_at=?, updated_by=? WHERE id=?")
          .bind(now, session.username, bonusId).run();
        await audit(env, request, { session, action: 'archive', resourceType: 'teacher_bonuses', resourceId: bonusId, targetSchool: record.school, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ── POST api/migrate-staff (systemadmin only — was previously UNPROTECTED) ──
      if (method === 'POST' && path === 'api/migrate-staff') {
        const session = await requireRole(request, env, ['systemadmin']);
        const { mode = 'dry', ignoreConflicts = false } = await body();
        const isDryRun = mode !== 'live';
        const now = new Date().toISOString();

        const { results: planRows } = await env.DB.prepare("SELECT school, year, payload FROM portal_data WHERE type = 'plan'").all();
        if (!planRows || planRows.length === 0) {
          return json({ ok: true, dryRun: isDryRun, inserted: 0, skipped: 0, conflicts: [], message: 'No plan rows found' }, 200, cors);
        }

        const candidates = [];
        for (const planRow of planRows) {
          let payload;
          try { payload = JSON.parse(planRow.payload); } catch { continue; }
          const staffRows = Array.isArray(payload?.staffRows) ? payload.staffRows : [];
          for (const s of staffRows) {
            candidates.push({
              school: (s.school || planRow.school || '').trim(),
              year: (s.year || planRow.year || '').trim(),
              name: (s.name || '').trim(),
              roletitle: (s.roletitle || s.role || '').trim(),
              role: normaliseRole(s.role),
              subject: (s.subject || '').trim(),
            });
          }
        }

        const seen = new Map();
        const conflicts = [];
        for (const c of candidates) {
          if (!c.name || !c.school || !c.year) continue;
          const key = `${c.name}|${c.school}|${c.year}`;
          if (seen.has(key)) {
            conflicts.push({ key, existing: seen.get(key), duplicate: c, reason: 'duplicate name+school+year in source data' });
          } else { seen.set(key, c); }
        }

        const dbConflicts = [];
        for (const [key, c] of seen.entries()) {
          const existing = await env.DB.prepare('SELECT id FROM staff WHERE name=? AND school=? AND year=?').bind(c.name, c.school, c.year).first();
          if (existing) dbConflicts.push({ key, candidate: c, existingId: existing.id, reason: 'already exists in staff table' });
        }
        const allConflicts = [...conflicts, ...dbConflicts];

        if (isDryRun) {
          await audit(env, request, { session, action: 'migrate_dry_run', resourceType: 'staff', outcome: 'success', metadata: { candidates: candidates.length, conflicts: allConflicts.length } });
          return json({
            ok: true, dryRun: true, candidates: candidates.length, toInsert: seen.size - dbConflicts.length, conflicts: allConflicts,
            message: allConflicts.length > 0 ? 'Conflicts found — review, then POST with mode="live"' : 'No conflicts — safe to run live',
          }, 200, cors);
        }

        if (allConflicts.length > 0 && !ignoreConflicts) {
          return json({ ok: false, dryRun: false, conflicts: allConflicts, message: 'Live run blocked — conflicts found.' }, 409, cors);
        }

        const dbConflictKeys = new Set(dbConflicts.map(c => c.key));
        const toInsert = [...seen.values()].filter(c => !dbConflictKeys.has(`${c.name}|${c.school}|${c.year}`));
        let inserted = 0;
        for (const c of toInsert) {
          await env.DB.prepare(`
            INSERT INTO staff (school, year, name, roletitle, role, subject, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?)
          `).bind(c.school, c.year, c.name, c.roletitle, c.role, c.subject, now, now).run();
          inserted++;
        }
        await audit(env, request, { session, action: 'migrate_live', resourceType: 'staff', outcome: 'success', metadata: { inserted, skipped: dbConflicts.length } });
        return json({ ok: true, dryRun: false, inserted, skipped: dbConflicts.length, conflicts: allConflicts }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  INVENTORY  (permission-gated, IDOR-safe)
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/inventory') {
        const session = await requireSession(request, env);
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!school || !year) return err('school, year required', 400, cors);
        requireSameSchool(session, school);
        requirePermission(session, 'inventory', 'view');
        const { results } = await env.DB.prepare('SELECT * FROM inventory WHERE school = ? AND year = ? ORDER BY category, item_name').bind(school, year).all();
        return json(results || [], 200, cors);
      }

      if (method === 'POST' && path === 'api/inventory') {
        const session = await requireSession(request, env);
        const { school, year, category, itemName, quantity, condition, notes } = await body();
        const cleanSchool = validSchool(school);
        const cleanYear = validYear(year);
        if (!cleanSchool || !cleanYear) return err('school, year required', 400, cors);
        requireSameSchool(session, cleanSchool);
        requirePermission(session, 'inventory', 'edit');
        const cleanQty = quantity !== undefined ? validQuantity(quantity) : 0;
        if (cleanQty === null) return err('invalid quantity', 400, cors);
        const cleanCondition = condition ? validEnum(condition, ALLOWED_CONDITIONS) : 'good';
        if (condition && !cleanCondition) return err('invalid condition', 400, cors);
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          INSERT INTO inventory (school, year, category, item_name, quantity, condition, notes, updated_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(cleanSchool, cleanYear, reqStr(category, 100) || '', reqStr(itemName, 200) || '', cleanQty, cleanCondition || 'good', reqStr(notes, 1000) || '', now).run();
        await audit(env, request, { session, action: 'create', resourceType: 'inventory', resourceId: result.meta?.lastrowid, targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true, id: result.meta?.lastrowid }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/inventory/') && numId) {
        const session = await requireSession(request, env);
        const record = await env.DB.prepare('SELECT id, school, year FROM inventory WHERE id = ?').bind(numId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        requirePermission(session, 'inventory', 'edit');

        const { category, itemName, quantity, condition, notes } = await body();
        const cleanQty = quantity !== undefined ? validQuantity(quantity) : 0;
        if (cleanQty === null) return err('invalid quantity', 400, cors);
        const cleanCondition = condition ? validEnum(condition, ALLOWED_CONDITIONS) : 'good';
        if (condition && !cleanCondition) return err('invalid condition', 400, cors);
        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          UPDATE inventory SET category=?, item_name=?, quantity=?, condition=?, notes=?, updated_at=?
          WHERE id=? AND school=? AND year=?
        `).bind(reqStr(category, 100) || '', reqStr(itemName, 200) || '', cleanQty, cleanCondition || 'good', reqStr(notes, 1000) || '', now, numId, record.school, record.year).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'update', resourceType: 'inventory', resourceId: numId, targetSchool: record.school, targetYear: record.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path.startsWith('api/inventory/') && numId) {
        const session = await requireSession(request, env);
        const record = await env.DB.prepare('SELECT id, school, year FROM inventory WHERE id = ?').bind(numId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        requirePermission(session, 'inventory', 'edit');
        const result = await env.DB.prepare('DELETE FROM inventory WHERE id = ? AND school = ? AND year = ?').bind(numId, record.school, record.year).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'delete', resourceType: 'inventory', resourceId: numId, targetSchool: record.school, targetYear: record.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  BUDGET  (permission-gated, IDOR-safe)
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/budget') {
        const session = await requireSession(request, env);
        const school = validSchool(q('school'));
        const year = validYear(q('year'));
        if (!school || !year) return err('school, year required', 400, cors);
        requireSameSchool(session, school);
        requirePermission(session, 'budget', 'view');

        const { results: entries } = await env.DB.prepare('SELECT * FROM budget_entries WHERE school = ? AND year = ? ORDER BY date DESC').bind(school, year).all();
        const { results: allocations } = await env.DB.prepare('SELECT * FROM budget_allocations WHERE school = ? AND year = ?').bind(school, year).all();

        const sources = ['parents', 'gapan', 'authority'];
        const bySource = {};
        for (const s of sources) {
          const srcEntries = (entries || []).filter(e => e.source === s);
          const totalIncome = srcEntries.filter(e => e.type === 'income').reduce((a, e) => a + (e.amount || 0), 0);
          const totalExpense = srcEntries.filter(e => e.type === 'expense').reduce((a, e) => a + (e.amount || 0), 0);
          const allocated = (allocations || []).filter(a => a.source === s).reduce((a, r) => a + (r.allocated || 0), 0);
          bySource[s] = { totalIncome, totalExpense, balance: totalIncome - totalExpense, allocated, remaining: totalIncome - totalExpense };
        }
        const total = {
          totalIncome: Object.values(bySource).reduce((a, s) => a + s.totalIncome, 0),
          totalExpense: Object.values(bySource).reduce((a, s) => a + s.totalExpense, 0),
          balance: Object.values(bySource).reduce((a, s) => a + s.balance, 0),
        };
        return json({ entries: entries || [], allocations: allocations || [], summary: { bySource, total } }, 200, cors);
      }

      if (method === 'POST' && path === 'api/budget/entry') {
        const session = await requireSession(request, env);
        const { school, year, source, type, category, description, amount, date } = await body();
        const cleanSchool = validSchool(school);
        const cleanYear = validYear(year);
        if (!cleanSchool || !cleanYear) return err('school, year required', 400, cors);
        requireSameSchool(session, cleanSchool);
        requirePermission(session, 'budget', 'edit');
        const cleanSource = source ? validEnum(source, ALLOWED_BUDGET_SOURCES) : '';
        if (source && !cleanSource) return err('invalid source', 400, cors);
        const cleanType = type ? validEnum(type, ALLOWED_BUDGET_TYPES) : '';
        if (type && !cleanType) return err('invalid type', 400, cors);
        const cleanAmount = amount !== undefined ? validAmount(amount) : 0;
        if (cleanAmount === null) return err('invalid amount', 400, cors);
        const cleanDate = date ? (validDate(date) || '') : '';
        if (date && !cleanDate) return err('invalid date', 400, cors);

        const now = new Date().toISOString();
        const result = await env.DB.prepare(`
          INSERT INTO budget_entries (school, year, source, type, category, description, amount, date, created_by, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(cleanSchool, cleanYear, cleanSource, cleanType, reqStr(category, 100) || '', reqStr(description, 1000) || '', cleanAmount, cleanDate, session.username, now).run();
        await audit(env, request, { session, action: 'create', resourceType: 'budget_entries', resourceId: result.meta?.lastrowid, targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true, id: result.meta?.lastrowid }, 200, cors);
      }

      if (method === 'PUT' && path.startsWith('api/budget/entry/') && numId) {
        const session = await requireSession(request, env);
        const record = await env.DB.prepare('SELECT id, school, year FROM budget_entries WHERE id = ?').bind(numId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        requirePermission(session, 'budget', 'edit');

        const { source, type, category, description, amount, date } = await body();
        const cleanSource = source ? validEnum(source, ALLOWED_BUDGET_SOURCES) : '';
        if (source && !cleanSource) return err('invalid source', 400, cors);
        const cleanType = type ? validEnum(type, ALLOWED_BUDGET_TYPES) : '';
        if (type && !cleanType) return err('invalid type', 400, cors);
        const cleanAmount = amount !== undefined ? validAmount(amount) : 0;
        if (cleanAmount === null) return err('invalid amount', 400, cors);
        const cleanDate = date ? (validDate(date) || '') : '';
        if (date && !cleanDate) return err('invalid date', 400, cors);

        const result = await env.DB.prepare(`
          UPDATE budget_entries SET source=?, type=?, category=?, description=?, amount=?, date=? WHERE id=? AND school=? AND year=?
        `).bind(cleanSource, cleanType, reqStr(category, 100) || '', reqStr(description, 1000) || '', cleanAmount, cleanDate, numId, record.school, record.year).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'update', resourceType: 'budget_entries', resourceId: numId, targetSchool: record.school, targetYear: record.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path.startsWith('api/budget/entry/') && numId) {
        const session = await requireSession(request, env);
        const record = await env.DB.prepare('SELECT id, school, year FROM budget_entries WHERE id = ?').bind(numId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        requirePermission(session, 'budget', 'edit');
        const result = await env.DB.prepare('DELETE FROM budget_entries WHERE id = ? AND school = ? AND year = ?').bind(numId, record.school, record.year).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'delete', resourceType: 'budget_entries', resourceId: numId, targetSchool: record.school, targetYear: record.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'POST' && path === 'api/budget/allocation') {
        const session = await requireSession(request, env);
        const { school, year, source, category, allocated } = await body();
        const cleanSchool = validSchool(school);
        const cleanYear = validYear(year);
        const cleanSource = validEnum(source, ALLOWED_BUDGET_SOURCES);
        const cleanCategory = reqStr(category, 100);
        if (!cleanSchool || !cleanYear || !cleanSource || !cleanCategory) return err('school, year, source, category required/invalid', 400, cors);
        requireSameSchool(session, cleanSchool);
        requirePermission(session, 'budget', 'edit');
        const cleanAllocated = allocated !== undefined ? validAmount(allocated) : 0;
        if (cleanAllocated === null) return err('invalid allocated amount', 400, cors);

        const now = new Date().toISOString();
        // ON CONFLICT DO UPDATE instead of INSERT OR REPLACE — avoids
        // unexpected row/id churn on the (school,year,source,category) upsert key.
        await env.DB.prepare(`
          INSERT INTO budget_allocations (school, year, source, category, allocated, created_at)
          VALUES (?, ?, ?, ?, ?, ?)
          ON CONFLICT(school, year, source, category) DO UPDATE SET allocated=excluded.allocated
        `).bind(cleanSchool, cleanYear, cleanSource, cleanCategory, cleanAllocated, now).run();
        await audit(env, request, { session, action: 'upsert', resourceType: 'budget_allocations', targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path.startsWith('api/budget/allocation/') && numId) {
        const session = await requireSession(request, env);
        const record = await env.DB.prepare('SELECT id, school, year FROM budget_allocations WHERE id = ?').bind(numId).first();
        if (!record) return err('not found', 404, cors);
        requireSameSchool(session, record.school);
        requirePermission(session, 'budget', 'edit');
        const result = await env.DB.prepare('DELETE FROM budget_allocations WHERE id = ? AND school = ? AND year = ?').bind(numId, record.school, record.year).run();
        if ((result.meta?.changes ?? 0) !== 1) return err('not found', 404, cors);
        await audit(env, request, { session, action: 'delete', resourceType: 'budget_allocations', resourceId: numId, targetSchool: record.school, targetYear: record.year, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  PRINCIPALS (systemadmin only — role-granting records)
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/principals/list') {
        await requireRole(request, env, ['systemadmin']);
        const { results } = await env.DB.prepare('SELECT * FROM principals ORDER BY school, name').all();
        return json(results || [], 200, cors);
      }

      if (method === 'POST' && path === 'api/principals') {
        const session = await requireRole(request, env, ['systemadmin']);
        const { email, name, school } = await body();
        const cleanEmail = validEmail(email);
        if (!cleanEmail) return err('valid email required', 400, cors);
        const cleanSchool = validSchool(school) || '';
        const now = new Date().toISOString();
        await env.DB.prepare(`
          INSERT INTO principals (email, name, school, year) VALUES (?, ?, ?, '')
          ON CONFLICT(email) DO UPDATE SET name=excluded.name, school=excluded.school
        `).bind(cleanEmail, reqStr(name, 200) || '', cleanSchool).run();
        await revokeAllSessionsForUser(env, cleanEmail); // role/scope changed — force re-auth
        await audit(env, request, { session, action: 'upsert', resourceType: 'principals', resourceId: cleanEmail, targetSchool: cleanSchool, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      if (method === 'DELETE' && path === 'api/principals') {
        const session = await requireRole(request, env, ['systemadmin']);
        const email = validEmail(q('email'));
        if (!email) return err('email required', 400, cors);
        await env.DB.prepare('DELETE FROM principals WHERE email = ?').bind(email).run();
        await revokeAllSessionsForUser(env, email);
        await audit(env, request, { session, action: 'delete', resourceType: 'principals', resourceId: email, outcome: 'success' });
        return json({ ok: true }, 200, cors);
      }

      // ═══════════════════════════════════════════════
      //  PORTAL DATA  (plan / gantt / mtss / calendar / teachers / custom_links)
      //  Permission-gated, tenant-scoped.
      // ═══════════════════════════════════════════════

      if (method === 'GET' && path === 'api/data') {
        const session = await requireSession(request, env);
        const type = validEnum(q('type'), ALLOWED_DATA_TYPES);
        if (!type) return err('type required/invalid', 400, cors);
        const school = validSchool(q('school')) || '';
        const year = validYear(q('year')) || '';
        if (school) requireSameSchool(session, school);
        requirePermission(session, type, 'view');
        const row = await env.DB.prepare('SELECT payload FROM portal_data WHERE type = ? AND school = ? AND year = ?').bind(type, school, year).first();
        if (!row) return json(null, 200, cors);
        try { return json(JSON.parse(row.payload), 200, cors); } catch { return json(null, 200, cors); }
      }

      if (method === 'POST' && path === 'api/data') {
        const session = await requireSession(request, env);
        const { type, school, year, payload } = await body();
        const cleanType = validEnum(type, ALLOWED_DATA_TYPES);
        if (!cleanType) return err('type required/invalid', 400, cors);
        const cleanSchool = validSchool(school) || '';
        const cleanYear = validYear(year) || '';
        if (cleanSchool) requireSameSchool(session, cleanSchool);
        requirePermission(session, cleanType, 'edit');

        const now = new Date().toISOString();
        const payloadStr = typeof payload === 'string' ? payload : JSON.stringify(payload || {});
        if (payloadStr.length > 5_000_000) return err('payload too large', 400, cors);
        await env.DB.prepare(`
          INSERT INTO portal_data (type, school, year, payload, updated_at)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(type, school, year) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at
        `).bind(cleanType, cleanSchool, cleanYear, payloadStr, now).run();
        await audit(env, request, { session, action: 'upsert', resourceType: 'portal_data', targetSchool: cleanSchool, targetYear: cleanYear, outcome: 'success', metadata: { type: cleanType } });
        return json({ ok: true }, 200, cors);
      }

      return err('not found', 404, cors);

    } catch (e) {
      if (e instanceof HttpError) {
        return err(e.message, e.status, cors);
      }
      console.error(e);
      return err('internal error', 500, cors); // do not leak e.message to the client
    }
  },

  // ── nightly hard-delete of long-archived records (cron: "0 3 * * *") ──
  async scheduled(event, env, ctx) {
    try {
      const cutoff = new Date();
      cutoff.setDate(cutoff.getDate() - 90);
      const cutoffISO = cutoff.toISOString();
      const entriesResult = await env.DB.prepare(`DELETE FROM teacher_entries WHERE status = 'archived' AND updated_at < ?`).bind(cutoffISO).run();
      const bonusesResult = await env.DB.prepare(`DELETE FROM teacher_bonuses WHERE status = 'archived' AND updated_at < ?`).bind(cutoffISO).run();
      console.log(`[scheduled/hard-delete] entries=${entriesResult.meta?.changes ?? 0} bonuses=${bonusesResult.meta?.changes ?? 0} cutoff=${cutoffISO}`);
    } catch (e) {
      console.error('[scheduled/hard-delete] ERROR:', e.message);
    }
  },
};
