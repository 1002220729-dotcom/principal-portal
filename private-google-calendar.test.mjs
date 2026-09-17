import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { handlePrivateGoogleCalendar as handle, seal, unseal, eventRange, CALENDAR_SCOPE } from './private-google-calendar-worker.js';
import entry from './worker-with-private-calendar.js';

const origin = 'https://principal-portal.pages.dev';
const base = 'https://principal-api.1002220729.workers.dev/api/private-google-calendar';
const owner = 'principal@example.edu';
const token = 'a'.repeat(64), other = 'b'.repeat(64);
const sha = value => createHash('sha256').update(value).digest('hex');
const migration = readFileSync(new URL('./migrations/0002_private_google_calendar.sql', import.meta.url), 'utf8');
const sqlCalls = [];
function fixture() {
  const sqlite = new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE staffsessions(token_hash TEXT PRIMARY KEY, username TEXT, role TEXT, school TEXT, year TEXT,
    expires_at TEXT, last_seen_at TEXT, revoked_at TEXT);
    CREATE TABLE portal_data (data TEXT); INSERT INTO portal_data VALUES ('shared-original');`);
  sqlite.exec(migration);
  sqlite.exec(migration); // Idempotent, additive migration.
  for (const [raw, username] of [[token, owner], [other, 'other@example.edu']]) {
    sqlite.prepare('INSERT INTO staffsessions VALUES (?, ?, ?, ?, ?, ?, ?, NULL)')
      .run(sha(raw), username, 'principal', 'school', '2026-2027', new Date(Date.now()+3600000).toISOString(), new Date().toISOString());
  }
  const DB = {
    prepare(query) {
      sqlCalls.push(query);
      const statement = sqlite.prepare(query);
      let args = [];
      return { bind(...values) { args = values; return this; },
        async first() { return statement.get(...args) || null; },
        async run() { return { meta:statement.run(...args) }; },
        async all() { return { results:statement.all(...args) }; } };
    },
    async batch(statements) {
      sqlite.exec('BEGIN');
      try { const result = await Promise.all(statements.map(s => s.run())); sqlite.exec('COMMIT'); return result; }
      catch (error) { sqlite.exec('ROLLBACK'); throw error; }
    },
  };
  const env = { DB, GOOGLE_CALENDAR_ALLOWED_EMAIL:owner, GOOGLE_CALENDAR_ENABLED:'true',
    GOOGLE_CALENDAR_CLIENT_ID:'test-client.apps.googleusercontent.com', GOOGLE_CALENDAR_CLIENT_SECRET:'fake-test-secret',
    GOOGLE_CALENDAR_ENCRYPTION_KEY:'12'.repeat(32) };
  const requests = [];
  let email = owner, scope = CALENDAR_SCOPE, pageItems = [], pages = [], onEvent, tokenError;
  async function fetcher(url, options) {
    requests.push({ url, options });
    assert.equal(options.redirect, 'error');
    assert.ok(options.signal instanceof AbortSignal);
    if (url === 'https://oauth2.googleapis.com/token') {
      if (tokenError) return Response.json({ error:tokenError }, { status:400 });
      return Response.json({ access_token:'fake-access', refresh_token:'fake-refresh', scope });
    }
    if (url === 'https://openidconnect.googleapis.com/v1/userinfo') return Response.json({ email, email_verified:true, sub:'google-owner-sub' });
    if (url.startsWith('https://www.googleapis.com/calendar/v3/calendars/primary/events?')) {
      if (onEvent) onEvent();
      return Response.json(pages.length ? pages.shift() : { items:pageItems });
    }
    throw new Error('Unexpected test request');
  }
  function request(path, method='GET', raw=token, requestOrigin=origin) {
    return new Request(base+path, { method, headers:{ Origin:requestOrigin, Authorization:'Bearer '+raw,
      ...(method==='POST'?{'Content-Type':'application/json'}:{}) } });
  }
  async function start() {
    const response = await handle(request('/connect','POST'), env, fetcher);
    assert.equal(response.status,200);
    return new URL((await response.json()).authorizationUrl);
  }
  async function connect() {
    const auth = await start();
    const response = await handle(new Request(base+'/callback?state='+auth.searchParams.get('state')+'&code=test-code'),env,fetcher);
    assert.equal(new URL(response.headers.get('Location')).searchParams.get('gcal'),'connected');
    return auth;
  }
  return { env,sqlite,request,fetcher,requests,start,connect,
    setEmail:value=>email=value, setScope:value=>scope=value, setEvents:value=>pageItems=value,
    setPages:value=>pages=value, onEvent:value=>onEvent=value, tokenError:value=>tokenError=value };
}
const sampleEvent = (id='one') => ({ id,status:'confirmed',summary:'פגישה פרטית',location:'משרד',
  start:{dateTime:'2026-09-17T10:00:00+03:00'},end:{dateTime:'2026-09-17T11:00:00+03:00'},htmlLink:'https://calendar.google.com/calendar/event?eid=example' });

test('unauthenticated, wrong origin and unsupported hosts fail closed', async () => {
  const f=fixture();
  assert.equal((await handle(f.request('/events?month=2026-09','GET','bad'),f.env,f.fetcher)).status,401);
  assert.equal((await handle(f.request('/connect','POST',token,'https://evil.example'),f.env,f.fetcher)).status,403);
  assert.equal((await handle(new Request('https://evil.example/api/private-google-calendar/status'),f.env,f.fetcher)).status,403);
  assert.equal(f.requests.length,0);
});
test('another principal or systemadmin cannot see private events or status', async () => {
  const f=fixture(); await f.connect();
  for (const role of ['principal','systemadmin']) {
    f.sqlite.prepare('UPDATE staffsessions SET role=? WHERE token_hash=?').run(role,sha(other));
    for (const path of ['/status','/events?month=2026-09']) {
      const r=await handle(f.request(path,'GET',other),f.env,f.fetcher);
      assert.equal(r.status,403); assert.doesNotMatch(await r.text(),/fake-refresh|פגישה פרטית|principal@example/);
    }
    assert.equal((await handle(f.request('/connection','DELETE',other),f.env,f.fetcher)).status,403);
  }
});
test('staff role and revoked, malformed or expired sessions cannot connect', async () => {
  for (const [column,value] of [['role','staffmember'],['revoked_at',new Date().toISOString()],['expires_at','invalid'],['expires_at','2020-01-01'],['last_seen_at','2020-01-01']]) {
    const f=fixture(); f.sqlite.prepare('UPDATE staffsessions SET '+column+'=? WHERE token_hash=?').run(value,sha(token));
    const r=await handle(f.request('/connect','POST'),f.env,f.fetcher);
    assert.ok([401,403].includes(r.status)); assert.equal(f.requests.length,0);
  }
});
test('disabled configuration is safe and does not call Google',async()=>{
  const f=fixture(); delete f.env.GOOGLE_CALENDAR_CLIENT_SECRET;
  const r=await handle(f.request('/status'),f.env,f.fetcher);
  assert.deepEqual(await r.json(),{available:false,connected:false});
  assert.equal((await handle(f.request('/connect','POST'),f.env,f.fetcher)).status,503);
  assert.equal(f.requests.length,0);
});
test('authorization requests only owned-event read scope, CSRF state and PKCE',async()=>{
  const f=fixture(), auth=await f.start();
  assert.equal(auth.origin,'https://accounts.google.com');
  assert.equal(auth.searchParams.get('scope'),'openid email '+CALENDAR_SCOPE);
  assert.equal(auth.searchParams.get('include_granted_scopes'),'false');
  assert.equal(auth.searchParams.get('code_challenge_method'),'S256');
  assert.equal(auth.searchParams.get('login_hint'),owner);
  const state=auth.searchParams.get('state'); assert.match(state,/^[a-f0-9]{64}$/);
  const row=f.sqlite.prepare('SELECT * FROM private_google_calendar_states').get();
  assert.equal(row.state_hash,sha(state)); assert.notEqual(row.state_hash,state);
  const verifier=await unseal(f.env,row.verifier_cipher,'state:'+row.state_hash);
  assert.equal(createHash('sha256').update(verifier).digest('base64url'),auth.searchParams.get('code_challenge'));
  assert.doesNotMatch(JSON.stringify(row),new RegExp(verifier));
});
test('callback binds owner, consumes state once, encrypts refresh token and changes no shared data',async()=>{
  const f=fixture(),auth=await f.connect();
  const row=f.sqlite.prepare('SELECT * FROM private_google_calendar_connections').get();
  assert.equal(await unseal(f.env,row.refresh_cipher,'refresh:'+owner),'fake-refresh');
  assert.doesNotMatch(JSON.stringify(row),/fake-refresh|fake-access/);
  const again=await handle(new Request(base+'/callback?state='+auth.searchParams.get('state')+'&code=again'),f.env,f.fetcher);
  assert.equal(new URL(again.headers.get('Location')).searchParams.get('gcal'),'failed');
  assert.equal(f.sqlite.prepare('SELECT data FROM portal_data').get().data,'shared-original');
  const tokenCall=f.requests.find(r=>r.url.endsWith('/token'));
  assert.equal(new URLSearchParams(tokenCall.options.body).get('grant_type'),'authorization_code');
  assert.ok(new URLSearchParams(tokenCall.options.body).get('code_verifier'));
});
test('encryption rejects different owner, ciphertext tampering and wrong key',async()=>{
  const f=fixture(),encrypted=await seal(f.env,'refresh-token','refresh:'+owner);
  await assert.rejects(unseal(f.env,encrypted,'refresh:another@example.edu'));
  await assert.rejects(unseal({...f.env,GOOGLE_CALENDAR_ENCRYPTION_KEY:'34'.repeat(32)},encrypted,'refresh:'+owner));
  const parts=encrypted.split('.'); parts[2]=(parts[2][0]==='A'?'B':'A')+parts[2].slice(1);
  await assert.rejects(unseal(f.env,parts.join('.'),'refresh:'+owner));
});
test('wrong Google account, missing consent or cancelled callback stores no credentials',async()=>{
  for (const kind of ['account','scope','denied','expired','revoked']) {
    const f=fixture(),auth=await f.start();
    if(kind==='account')f.setEmail('wrong@example.edu');
    if(kind==='scope')f.setScope('openid email');
    if(kind==='expired')f.sqlite.exec("UPDATE private_google_calendar_states SET expires_at='2000-01-01'");
    if(kind==='revoked')f.sqlite.exec("UPDATE staffsessions SET revoked_at='revoked'");
    const r=await handle(new Request(base+'/callback?state='+auth.searchParams.get('state')+(kind==='denied'?'&error=access_denied':'&code=test')),f.env,f.fetcher);
    assert.equal(r.status,303);assert.notEqual(new URL(r.headers.get('Location')).searchParams.get('gcal'),'connected');
    assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS n FROM private_google_calendar_connections').get().n,0);
  }
});
test('connection start is bounded to five pending authorizations',async()=>{
  const f=fixture();for(let i=0;i<5;i++)await f.start();
  assert.equal((await handle(f.request('/connect','POST'),f.env,f.fetcher)).status,429);
});
test('events paginate, include recurrence, filter cancellations and never return tokens or unsafe URLs',async()=>{
  const f=fixture();await f.connect();
  f.setPages([{items:[sampleEvent('one')],nextPageToken:'next'}, {items:[sampleEvent('one'),
    {...sampleEvent('deleted'),status:'cancelled'}, {...sampleEvent('two'),htmlLink:'javascript:alert(1)',summary:'<img onerror=alert(1)>'}]}]);
  const r=await handle(f.request('/events?month=2026-09&email=other@example.edu&school=other'),f.env,f.fetcher);
  assert.equal(r.status,200);assert.match(r.headers.get('Cache-Control'),/no-store/);
  const data=await r.json();assert.equal(data.events.length,2);assert.equal(data.events[1].link,'');
  assert.doesNotMatch(JSON.stringify(data),/fake-access|fake-refresh|fake-test-secret/);
  const calls=f.requests.filter(r=>r.url.includes('/primary/events?'));
  assert.equal(calls.length,2);
  assert.equal(new URL(calls[1].url).searchParams.get('pageToken'),'next');
  assert.equal(new URL(calls[0].url).searchParams.get('singleEvents'),'true');
  assert.equal(new URL(calls[0].url).searchParams.get('timeZone'),'Asia/Jerusalem');
  assert.equal(f.sqlite.prepare('SELECT data FROM portal_data').get().data,'shared-original');
});
test('invalid month fails before upstream calls; leap years and December work',async()=>{
  assert.throws(()=>eventRange(new URL(base+'/events?month=2026-13')));
  assert.throws(()=>eventRange(new URL(base+'/events?month=../all')));
  assert.equal(eventRange(new URL(base+'/events?month=2028-02')).end,'2028-03-02T00:00:00.000Z');
  assert.equal(eventRange(new URL(base+'/events?month=2026-12')).end,'2027-01-02T00:00:00.000Z');
  const f=fixture(); const r=await handle(f.request('/events?month=bad'),f.env,f.fetcher);
  assert.equal(r.status,400);assert.equal(f.requests.length,0);
});
test('no partially truncated month is silently returned',async()=>{
  const f=fixture();await f.connect();
  f.setPages(Array.from({length:10},(_,i)=>({items:[sampleEvent(String(i))],nextPageToken:'more'})));
  const r=await handle(f.request('/events?month=2026-09'),f.env,f.fetcher);
  assert.equal(r.status,422);assert.equal((await r.json()).error,'too_many_events');
});
test('revocation or disconnect during fetch prevents returning in-flight events',async()=>{
  for(const change of ['session','connection']){
    const f=fixture();await f.connect();f.setEvents([sampleEvent()]);
    f.onEvent(()=>f.sqlite.exec(change==='session' ? "UPDATE staffsessions SET revoked_at='revoked'" : 'DELETE FROM private_google_calendar_connections'));
    const r=await handle(f.request('/events?month=2026-09'),f.env,f.fetcher);
    assert.ok([401,409].includes(r.status));assert.doesNotMatch(await r.text(),/פגישה פרטית/);
  }
});
test('disconnect removes credentials and pending states but never deletes Google events',async()=>{
  const f=fixture();await f.connect();await f.start();const count=f.requests.length;
  const r=await handle(f.request('/connection','DELETE'),f.env,f.fetcher);
  assert.equal(r.status,200);assert.equal(f.requests.length,count);
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS n FROM private_google_calendar_connections').get().n,0);
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS n FROM private_google_calendar_states').get().n,0);
});
test('disconnect during the OAuth callback cannot silently recreate the connection',async()=>{
  const f=fixture(), auth=await f.start();
  const intercept=async(url,options)=>{
    if(url.endsWith('/userinfo')){
      const unlink=await handle(f.request('/connection','DELETE'),f.env,f.fetcher);
      assert.equal(unlink.status,200);
    }
    return f.fetcher(url,options);
  };
  const response=await handle(new Request(base+'/callback?state='+auth.searchParams.get('state')+'&code=test'),f.env,intercept);
  assert.equal(new URL(response.headers.get('Location')).searchParams.get('gcal'),'failed');
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS n FROM private_google_calendar_connections').get().n,0);
});
test('Google refresh failure is recoverable and not treated as a portal login failure',async()=>{
  const f=fixture();await f.connect();f.tokenError('invalid_grant');
  const r=await handle(f.request('/events?month=2026-09'),f.env,f.fetcher);
  assert.equal(r.status,409);assert.equal((await r.json()).error,'reconnect_required');
  assert.equal(f.sqlite.prepare('SELECT revoked_at FROM staffsessions WHERE token_hash=?').get(sha(token)).revoked_at,null);
});
test('upstream body limits and failures do not leak raw errors',async()=>{
  const f=fixture();await f.connect();
  const r=await handle(f.request('/events?month=2026-09'),f.env,async()=>new Response('x'.repeat(40000)));
  assert.equal(r.status,502);assert.doesNotMatch(await r.text(),/fake-refresh|xxxxx/);
});
test('wrapper leaves existing health route intact; new routes fail closed without configuration',async()=>{
  const r=await entry.fetch(new Request('https://principal-api.1002220729.workers.dev/api/health'),{},{});
  assert.equal(r.status,200);assert.deepEqual(await r.json(),{ok:true});
  const privateResponse=await entry.fetch(new Request(base+'/status'),{},{});
  assert.equal(privateResponse.status,503);
});
test('UI keeps private data outside shared storage, renders text safely and hides on print',()=>{
  const source=readFileSync(new URL('./private-google-calendar.js',import.meta.url),'utf8').replace(/^\s*\/\/.*$/gm,'');
  assert.doesNotMatch(source,/localStorage\.|sessionStorage\.|appData\.|PS\.|saveToPortal\(/);
  assert.equal((source.match(/postMessage\(/g)||[]).length,1);
  assert.match(source,/parentWindow\.postMessage\(\{ type:'private-google-calendar-connect', requestId \}, location\.origin\)/);
  assert.doesNotMatch(source,/parentWindow\.location\.assign/);
  assert.match(source,/title\.textContent = event\.title/);
  assert.match(source,/@media print\{#privateGoogleCalendar\{display:none!important\}\}/);
  assert.match(source,/parentWindow\.getSessionToken\(\) === token/);
  assert.match(source,/epoch !== generation/);
  assert.match(source,/private_calendar_forbidden.*dispose\(\)/);
});

test('release wiring stages the extension disabled without changing the production entrypoint',()=>{
  const config=JSON.parse(readFileSync(new URL('./wrangler.jsonc',import.meta.url),'utf8'));
  assert.equal(config.main,'worker.js');
  assert.equal(config.env.staging.main,'worker-with-private-calendar.js');
  assert.equal(config.env.staging.vars.GOOGLE_CALENDAR_ENABLED,'false');
  assert.equal(config.env.staging.vars.GOOGLE_CALENDAR_ALLOWED_EMAIL,'1002220729@educ.org.il');
  assert.notEqual(config.d1_databases[0].database_id,config.env.staging.d1_databases[0].database_id);
  assert.equal(config.env.staging.vars.GOOGLE_CALENDAR_CLIENT_SECRET,undefined);
  assert.equal(config.env.staging.vars.GOOGLE_CALENDAR_ENCRYPTION_KEY,undefined);
  const html=readFileSync(new URL('./calendar.html',import.meta.url),'utf8');
  assert.equal((html.match(/<script src="private-google-calendar\.js"><\/script>/g)||[]).length,1);
  assert.ok(html.lastIndexOf('private-google-calendar.js')>html.lastIndexOf('function demoInit'));
});
