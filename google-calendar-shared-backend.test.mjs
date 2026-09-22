import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { handlePrivateGoogleCalendar as handle, seal, CALENDAR_SCOPE } from './private-google-calendar-worker.js';
import portal from './worker.js';

const origin='https://principal-portal.pages.dev', api='https://principal-api.1002220729.workers.dev';
const prefix='/api/private-google-calendar', owner='owner@example.edu', token='a'.repeat(64), other='b'.repeat(64);
const target={school:'school',year:'2026-2027'};
const sha=value=>createHash('sha256').update(value).digest('hex');
const sample=(id='event-1',title='Google meeting')=>({id,status:'confirmed',summary:title,
  start:{dateTime:'2026-09-17T10:00:00+03:00'},end:{dateTime:'2026-09-17T11:00:00+03:00'}});
const native=()=>({docType:'calendar',...target,custom:'untouched',meetings:{
  events:[{id:'manual',title:'School meeting'},{id:'gantt',isFromGantt:true,title:'Gantt meeting'}],
  settings:{syncedFromGantt:true,lastSyncAt:'earlier'}}});

async function fixture({row=true}={}) {
  const sqlite=new DatabaseSync(':memory:');
  sqlite.exec(`CREATE TABLE staffsessions(token_hash TEXT PRIMARY KEY,username TEXT,role TEXT,school TEXT,year TEXT,
    expires_at TEXT,last_seen_at TEXT,revoked_at TEXT);
    CREATE TABLE portal_data(type TEXT,school TEXT,year TEXT,payload TEXT,updated_at TEXT,PRIMARY KEY(type,school,year));
    CREATE TABLE staff_auth(username TEXT,must_change_password INTEGER,password_changed_at TEXT);
    CREATE TABLE staff_permissions(email TEXT,school TEXT,year TEXT,permissions TEXT);
    CREATE TABLE audit_log(occurred_at,request_id,actor_username,actor_role,actor_school,action,resource_type,
      resource_id,target_school,target_year,outcome,ip_hash,user_agent_hash,metadata_json);`);
  sqlite.exec(readFileSync(new URL('./migrations/0002_private_google_calendar.sql',import.meta.url),'utf8'));
  for (const [raw,name] of [[token,owner],[other,'other@example.edu']])
    sqlite.prepare('INSERT INTO staffsessions VALUES(?,?,?,?,?,?,?,NULL)').run(sha(raw),name,'principal',
      target.school,target.year,new Date(Date.now()+3600000).toISOString(),new Date().toISOString());
  if(row)sqlite.prepare('INSERT INTO portal_data VALUES(?,?,?,?,?)').run('calendar',target.school,target.year,JSON.stringify(native()),'before');
  const calls=[],writes=[];
  let beforePublish, google=async()=>({items:[sample()]});
  const DB={prepare(sql){
    const statement=sqlite.prepare(sql);let args=[];
    return {bind(...values){args=values;return this;},async first(){return statement.get(...args)||null;},
      async all(){return {results:statement.all(...args)};},async run(){
        if(sql.startsWith('WITH current') && beforePublish){const hook=beforePublish;beforePublish=null;await hook();}
        writes.push(sql);return {meta:statement.run(...args)};
      }};
  }};
  const env={DB,SESSIONS_KV:{async get(){return null;},async put(){}},GOOGLE_CALENDAR_ALLOWED_EMAIL:owner,
    GOOGLE_CALENDAR_ENABLED:'true',GOOGLE_CALENDAR_SHARED_ENABLED:'true',GOOGLE_CALENDAR_CLIENT_ID:'test.apps.googleusercontent.com',
    GOOGLE_CALENDAR_CLIENT_SECRET:'synthetic-secret',GOOGLE_CALENDAR_ENCRYPTION_KEY:'12'.repeat(32)};
  sqlite.prepare('INSERT INTO private_google_calendar_connections VALUES(?,?,?,?,?)')
    .run(owner,'sub',await seal(env,'synthetic-refresh','refresh:'+owner),'connection-v1',new Date().toISOString());
  const request=(path,method='GET',raw=token,body)=>new Request(api+path,{method,headers:{Origin:origin,
    Authorization:'Bearer '+raw,...(body!==undefined?{'Content-Type':'application/json'}:{})},
    ...(body!==undefined?{body:JSON.stringify(body)}:{})});
  const fetcher=async(url,options)=>{
    calls.push(url);assert.equal(options.redirect,'manual');
    if(url==='https://oauth2.googleapis.com/token')return Response.json({access_token:'synthetic-access',scope:CALENDAR_SCOPE});
    if(url==='https://openidconnect.googleapis.com/v1/userinfo')return Response.json({email:owner,email_verified:true,sub:'sub'});
    if(url.startsWith('https://www.googleapis.com/calendar/v3/calendars/primary/events?')){
      const result=await google(url);return result instanceof Response?result:Response.json(result);
    }
    throw new Error('Unexpected outbound URL');
  };
  const sync=(month='2026-09',body=target,raw=token)=>handle(request(prefix+'/sync-shared?month='+month,'POST',raw,body),env,fetcher);
  const load=()=>{const row=sqlite.prepare("SELECT payload FROM portal_data WHERE type='calendar' AND school=? AND year=?").get(target.school,target.year);return row?JSON.parse(row.payload):null;};
  const save=(payload,type='calendar',raw=token)=>portal.fetch(request('/api/data','POST',raw,{type,...target,payload}),env,{});
  return {sqlite,env,calls,writes,request,fetcher,sync,load,save,setGoogle:value=>google=value,
    beforePublish:hook=>beforePublish=hook,close:()=>sqlite.close()};
}

test('sharing requires explicit flag, configured owner and exact nonempty session school/year, including admin',async()=>{
  const f=await fixture();
  try {
    f.env.GOOGLE_CALENDAR_SHARED_ENABLED='false';
    assert.equal((await f.sync()).status,503);
    assert.equal((await (await handle(f.request(prefix+'/status'),f.env,f.fetcher)).json()).sharedEnabled,false);
    f.env.GOOGLE_CALENDAR_SHARED_ENABLED='true';
    for(const body of [{school:'other',year:target.year},{school:target.school,year:'2025-2026'},
      {school:'',year:target.year},{school:target.school,year:''},{...target,owner:'forged'}])
      assert.ok([400,403].includes((await f.sync('2026-09',body)).status));
    for(const role of ['principal','systemadmin']){
      f.sqlite.prepare('UPDATE staffsessions SET role=? WHERE token_hash=?').run(role,sha(other));
      assert.equal((await f.sync('2026-09',target,other)).status,403);
      f.sqlite.prepare('UPDATE staffsessions SET role=? WHERE token_hash=?').run(role,sha(token));
      assert.equal((await f.sync('2026-09',{...target,school:'other'})).status,403);
    }
    f.sqlite.prepare('UPDATE staffsessions SET role=? WHERE token_hash=?').run('staffmember',sha(token));
    assert.equal((await f.sync()).status,403);assert.equal(f.calls.length,0);assert.equal(f.writes.length,0);
  }finally{f.close();}
});

test('complete Google month snapshots preserve all native/Gantt data, update idempotently and replace with empty cancellations',async()=>{
  const f=await fixture();
  try{
    const first=await f.sync();assert.equal(first.status,200);const result=await first.json();
    assert.deepEqual(Object.keys(result).sort(),['month','ok','school','snapshot','year']);
    assert.deepEqual(Object.keys(result.snapshot).sort(),['events','fetchedAt']);
    assert.equal(result.snapshot.events.length,1);assert.equal(result.school,target.school);
    const persisted=f.load(), google=persisted.meetings.googleCalendar;
    delete persisted.meetings.googleCalendar;assert.deepEqual(persisted,native());
    assert.equal(google.owner,owner);assert.equal(google.calendar,'primary');
    assert.equal((await f.sync()).status,200);
    assert.equal(f.load().meetings.googleCalendar.months['2026-09'].events.length,1);
    f.setGoogle(async()=>({items:[sample('event-1','Updated title')]}));
    assert.equal((await f.sync()).status,200);
    assert.equal(f.load().meetings.googleCalendar.months['2026-09'].events[0].title,'Updated title');
    f.setGoogle(async()=>({items:[]}));assert.equal((await f.sync()).status,200);
    assert.deepEqual(f.load().meetings.googleCalendar.months['2026-09'].events,[]);
    assert.deepEqual(f.load().meetings.events,native().meetings.events);
    assert.doesNotMatch(JSON.stringify(f.load()),/synthetic-refresh|synthetic-access|synthetic-secret/);
  }finally{f.close();}
});

test('first publication creates only a calendar row for the exact target and ordinary forged inserts cannot publish',async()=>{
  const f=await fixture({row:false});
  try{
    assert.equal((await f.sync()).status,200);
    assert.deepEqual(f.load().meetings.events,[]);
    assert.deepEqual(f.load().meetings.settings,{});
    f.sqlite.exec('DELETE FROM portal_data');
    const forged={...native(),meetings:{events:[],googleCalendar:{owner,months:{'2026-09':{events:['forged']}}}}};
    assert.equal((await f.save(forged)).status,200);assert.equal(f.load().meetings.googleCalendar,undefined);
    assert.equal((await f.sync()).status,200);assert.deepEqual(f.load().meetings.events,[]);
    assert.equal(f.sqlite.prepare('SELECT count(*) AS n FROM portal_data').get().n,1);
  }finally{f.close();}
});

test('ordinary calendar saves atomically preserve the server snapshot against missing or forged client copies; other types unchanged',async()=>{
  const f=await fixture();
  try{
    assert.equal((await f.sync()).status,200);const expected=f.load().meetings.googleCalendar;
    for(const googleCalendar of [undefined,{owner:'attacker',months:{}}]){
      const payload=native();payload.meetings.events.push({id:'manual-new',title:'New manual'});
      if(googleCalendar!==undefined)payload.meetings.googleCalendar=googleCalendar;
      assert.equal((await f.save(payload)).status,200);
      assert.deepEqual(f.load().meetings.googleCalendar,expected);
      assert.equal(f.load().meetings.events.length,3);
    }
    const otherPayload={meetings:{googleCalendar:{arbitrary:'unchanged'}}};
    assert.equal((await f.save(otherPayload,'plan')).status,200);
    assert.deepEqual(JSON.parse(f.sqlite.prepare("SELECT payload FROM portal_data WHERE type='plan'").get().payload),otherPayload);
  }finally{f.close();}
});

test('manual save while Google fetch is pending survives snapshot publication',async()=>{
  const f=await fixture();
  try{
    f.setGoogle(async()=>{const newer=native();newer.meetings.events.push({id:'during-fetch'});
      newer.meetings.settings.extra='keep';assert.equal((await f.save(newer)).status,200);return {items:[sample()]};});
    assert.equal((await f.sync()).status,200);
    assert.equal(f.load().meetings.events.at(-1).id,'during-fetch');
    assert.equal(f.load().meetings.settings.extra,'keep');
  }finally{f.close();}
});

test('overlapping same-month requests reject stale completion without overwriting the newer snapshot',async()=>{
  const f=await fixture();let release,entered;
  try{
    const started=new Promise(resolve=>entered=resolve),pending=new Promise(resolve=>release=resolve);let count=0;
    f.setGoogle(async()=>{if(++count===1){entered();await pending;return {items:[sample('event-1','OLD')]};}
      return {items:[sample('event-1','NEW')]};});
    const old=f.sync();await started;
    assert.equal((await f.sync()).status,200);release();
    const stale=await old;assert.equal(stale.status,409);assert.equal((await stale.json()).error,'shared_sync_conflict');
    assert.equal(f.load().meetings.googleCalendar.months['2026-09'].events[0].title,'NEW');
  }finally{release?.();f.close();}
});

test('concurrent different months merge without deleting previously published history',async()=>{
  const f=await fixture();
  try{
    const responses=await Promise.all([f.sync('2026-09'),f.sync('2026-10')]);
    assert.deepEqual(responses.map(r=>r.status),[200,200]);
    assert.deepEqual(Object.keys(f.load().meetings.googleCalendar.months).sort(),['2026-09','2026-10']);
    assert.deepEqual(f.load().meetings.events,native().meetings.events);
  }finally{f.close();}
});

test('provider failure, malformed event, malformed pagination and incomplete month leave persisted snapshots untouched',async()=>{
  for(const provider of [async()=>new Response('upstream failed',{status:502}),
    async()=>({items:[{id:'broken',start:{dateTime:'invalid'},end:{dateTime:'invalid'}}]}),
    async()=>({items:[sample()],nextPageToken:{invalid:true}}),
    async()=>({items:[sample()],nextPageToken:'another-page'})]){
    const f=await fixture();
    try{
      assert.equal((await f.sync()).status,200);const before=JSON.stringify(f.load());const writeCount=f.writes.length;
      f.setGoogle(provider);assert.ok([422,502].includes((await f.sync()).status));
      assert.equal(JSON.stringify(f.load()),before);assert.equal(f.writes.length,writeCount);
    }finally{f.close();}
  }
});

test('session/tenant/connection changes at the atomic publication boundary cannot publish',async()=>{
  for(const mutation of [f=>f.sqlite.prepare('UPDATE staffsessions SET revoked_at=? WHERE token_hash=?').run('revoked',sha(token)),
    f=>f.sqlite.prepare('UPDATE staffsessions SET school=? WHERE token_hash=?').run('other-school',sha(token)),
    f=>f.sqlite.prepare('UPDATE staffsessions SET year=? WHERE token_hash=?').run('2025-2026',sha(token)),
    f=>f.sqlite.prepare('UPDATE staffsessions SET role=? WHERE token_hash=?').run('staffmember',sha(token)),
    f=>f.sqlite.prepare('UPDATE staffsessions SET expires_at=? WHERE token_hash=?').run('2020-01-01',sha(token)),
    f=>f.sqlite.prepare('UPDATE private_google_calendar_connections SET version=?').run('new-version')]){
    const f=await fixture();
    try{
      f.beforePublish(()=>mutation(f));const before=JSON.stringify(f.load());
      assert.equal((await f.sync()).status,409);assert.equal(JSON.stringify(f.load()),before);
    }finally{f.close();}
  }
});

test('sync final payload bound counts UTF-8 bytes of preserved manual content atomically',async()=>{
  const f=await fixture();
  try{
    const large=native();large.notes='א'.repeat(1000000);
    assert.ok(JSON.stringify(large).length<2000000);
    assert.ok(Buffer.byteLength(JSON.stringify(large))>2000000);
    f.sqlite.prepare("UPDATE portal_data SET payload=? WHERE type='calendar'").run(JSON.stringify(large));
    const before=JSON.stringify(f.load());
    assert.equal((await f.sync()).status,409);assert.equal(JSON.stringify(f.load()),before);
  }finally{f.close();}
});

test('36-month/storage bounds reject overflow and retain history; an existing month remains refreshable',async()=>{
  const f=await fixture();
  try{
    const payload=native();payload.meetings.googleCalendar={owner,calendar:'primary',months:{}};
    for(let year=2024;year<2027;year++)for(let month=1;month<=12;month++)
      payload.meetings.googleCalendar.months[`${year}-${String(month).padStart(2,'0')}`]={revision:'old',startedAt:'2020',fetchedAt:'2020',events:[]};
    f.sqlite.prepare("UPDATE portal_data SET payload=? WHERE type='calendar'").run(JSON.stringify(payload));
    const before=JSON.stringify(f.load());assert.equal((await f.sync('2027-01')).status,422);
    assert.equal(JSON.stringify(f.load()),before);assert.equal(f.calls.length,0);
    assert.equal((await f.sync('2026-09')).status,200);
    const huge=f.load();huge.meetings.googleCalendar.months['2024-01'].padding='x'.repeat(2000001);
    f.sqlite.prepare("UPDATE portal_data SET payload=? WHERE type='calendar'").run(JSON.stringify(huge));
    const full=JSON.stringify(f.load());assert.equal((await f.sync()).status,409);assert.equal(JSON.stringify(f.load()),full);
  }finally{f.close();}
});

test('existing calendar readers receive published snapshots but unauthorized readers and staff sync are denied',async()=>{
  const f=await fixture();
  try{
    assert.equal((await f.sync()).status,200);
    f.sqlite.prepare('UPDATE staffsessions SET role=? WHERE token_hash=?').run('staffmember',sha(other));
    f.sqlite.prepare('INSERT INTO staff_permissions VALUES(?,?,?,?)').run('other@example.edu',target.school,target.year,JSON.stringify({calendar:'view'}));
    const route='/api/data?type=calendar&school=school&year=2026-2027';
    const allowed=await portal.fetch(f.request(route,'GET',other),f.env,{});assert.equal(allowed.status,200);
    assert.equal((await allowed.json()).meetings.googleCalendar.months['2026-09'].events.length,1);
    assert.equal((await f.sync('2026-09',target,other)).status,403);
    f.sqlite.exec('DELETE FROM staff_permissions');
    assert.equal((await portal.fetch(f.request(route,'GET',other),f.env,{})).status,403);
  }finally{f.close();}
});
