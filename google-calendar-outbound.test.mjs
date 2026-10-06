import test from 'node:test';
import assert from 'node:assert/strict';
import {DatabaseSync} from 'node:sqlite';
import {readFileSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {handlePrivateGoogleCalendar as handle,runGoogleCalendarOutbox,seal,CALENDAR_SCOPE,CALENDAR_WRITE_SCOPE} from './private-google-calendar-worker.js';
import {outboundEvent,outboundIdentity,israelToday} from './google-calendar-outbound-worker.js';

const owner='owner@example.edu',token='a'.repeat(64),origin='https://principal-portal.pages.dev',api='https://principal-api.1002220729.workers.dev';
const prefix='/api/private-google-calendar',target={school:'school',year:'2026-2027'};
const sha=v=>createHash('sha256').update(v).digest('hex');
const day=(offset=0)=>new Date(Date.parse(israelToday()+'T00:00:00Z')+offset*86400000).toISOString().slice(0,10);
const meeting=(id='one',offset=0)=>({id,title:'ישיבת הנהלה',date:day(offset),timeStart:'09:00',timeEnd:'10:00',location:'משרד',attendees:'רכזים',agenda:'סדר יום',summary:''});
async function fixture({write=true}={}) {
 const sqlite=new DatabaseSync(':memory:');
 sqlite.exec(`CREATE TABLE staffsessions(token_hash TEXT PRIMARY KEY,username TEXT,role TEXT,school TEXT,year TEXT,expires_at TEXT,last_seen_at TEXT,revoked_at TEXT);
 CREATE TABLE portal_data(type TEXT,school TEXT,year TEXT,payload TEXT,updated_at TEXT,PRIMARY KEY(type,school,year));
 CREATE TABLE principals(email TEXT,school TEXT);CREATE TABLE admins(email TEXT);`);
 for(const file of ['migrations/0002_private_google_calendar.sql','google-calendar-outbound.sql'])sqlite.exec(readFileSync(new URL(file,import.meta.url),'utf8'));
 sqlite.exec(readFileSync(new URL('google-calendar-outbound.sql',import.meta.url),'utf8'));
 sqlite.prepare('INSERT INTO staffsessions VALUES(?,?,?,?,?,?,?,NULL)').run(sha(token),owner,'principal',target.school,target.year,new Date(Date.now()+3600000).toISOString(),new Date().toISOString());
 sqlite.prepare('INSERT INTO principals VALUES(?,?)').run(owner,target.school);
 const DB={prepare(sql){const s=sqlite.prepare(sql);let args=[];return{bind(...v){args=v;return this;},async first(){return s.get(...args)||null;},async all(){return{results:s.all(...args)};},async run(){return{meta:s.run(...args)};}};},async batch(statements){sqlite.exec('BEGIN');try{const rows=[];for(const s of statements)rows.push(await s.run());sqlite.exec('COMMIT');return rows;}catch(e){sqlite.exec('ROLLBACK');throw e;}}};
 const env={DB,GOOGLE_CALENDAR_ENABLED:'true',GOOGLE_CALENDAR_SHARED_ENABLED:'true',GOOGLE_CALENDAR_OUTBOUND_ENABLED:'true',GOOGLE_CALENDAR_OUTBOUND_API_ORIGIN:api,GOOGLE_CALENDAR_ALLOWED_EMAIL:owner,GOOGLE_CALENDAR_CLIENT_ID:'test.apps.googleusercontent.com',GOOGLE_CALENDAR_CLIENT_SECRET:'synthetic-secret',GOOGLE_CALENDAR_ENCRYPTION_KEY:'12'.repeat(32)};
 sqlite.prepare('INSERT INTO private_google_calendar_connections VALUES(?,?,?,?,?)').run(owner,'sub',await seal(env,'refresh','refresh:'+owner),'v1',new Date().toISOString());
 if(write)sqlite.prepare('INSERT INTO google_calendar_write_grants VALUES(?,?)').run(owner,'v1');
 let scope=write?CALENDAR_WRITE_SCOPE:CALENDAR_SCOPE,hook=null,failNext=null,identityEmail=owner;
 const remote=new Map(),calls=[];
 async function fetcher(url,options={}) {
  assert.equal(options.redirect,'manual');assert.ok(options.signal instanceof AbortSignal);
  if(url==='https://oauth2.googleapis.com/token')return Response.json({access_token:'synthetic-access',refresh_token:'synthetic-refresh',scope});
  if(url==='https://openidconnect.googleapis.com/v1/userinfo')return Response.json({email:identityEmail,email_verified:true,sub:'sub'});
  const u=new URL(url);assert.equal(u.hostname,'www.googleapis.com');const method=options.method||'GET';
  calls.push({url,method,body:options.body?JSON.parse(options.body):undefined,headers:options.headers});
  if(hook){const h=hook;hook=null;await h({url,method});}
  if(failNext){const failure=failNext;failNext=null;if(failure==='timeout')throw Error('synthetic timeout');return Response.json({}, {status:failure});}
  const id=u.pathname.split('/events/')[1];
  if(!id&&method==='GET')return Response.json({items:[...remote.values()].filter(e=>e.status!=='cancelled')});
  if(method==='GET')return remote.has(id)?Response.json(remote.get(id)):Response.json({}, {status:404});
  assert.equal(u.searchParams.get('sendUpdates'),'none');
  const body=JSON.parse(options.body);assert.equal(body.attendees,undefined);assert.equal(body.recurrence,undefined);
  if(method==='POST'){if(remote.has(body.id))return Response.json({}, {status:409});remote.set(body.id,{...body,status:'confirmed',etag:'"1"'});return Response.json(remote.get(body.id));}
  assert.equal(method,'PATCH');const old=remote.get(id);assert.ok(old);assert.equal(options.headers['If-Match'],old.etag);
  const next={...old,...body,etag:'"'+(Number(old.etag.replaceAll('"',''))+1)+'"'};remote.set(id,next);return Response.json(next);
 }
 function request(path,method='POST',body=target,raw=token,requestOrigin=origin){return new Request(api+prefix+path,{method,headers:{Origin:requestOrigin,Authorization:'Bearer '+raw,...(method==='POST'?{'Content-Type':'application/json'}:{})},...(method==='POST'?{body:JSON.stringify(body)}:{})});}
 const call=(path,body=target,raw=token)=>handle(request(path,'POST',body,raw),env,fetcher);
 const save=(events,scopeTarget=target)=>sqlite.prepare(`INSERT INTO portal_data VALUES('calendar',?,?,?,?) ON CONFLICT(type,school,year) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at`).run(scopeTarget.school,scopeTarget.year,JSON.stringify({meetings:{events,settings:{}}}),new Date().toISOString());
 const retry=()=>sqlite.prepare('UPDATE google_calendar_outbound_targets SET retry_at=NULL').run();
 save([meeting()]);
 return{sqlite,env,fetcher,remote,calls,request,call,save,retry,setScope:v=>scope=v,setEmail:v=>identityEmail=v,onNext:v=>hook=v,failNext:v=>failNext=v,close:()=>sqlite.close()};
}
test('Israel cutoff, timed/all-day events and missing ends keep wall-clock times across DST',()=>{
 assert.equal(israelToday(Date.parse('2026-10-05T22:30:00Z')),'2026-10-06');
 for(const date of ['2026-03-27','2026-10-25'])assert.deepEqual(outboundEvent({...meeting(),date}).start,{dateTime:date+'T09:00:00',timeZone:'Asia/Jerusalem'});
 const all=outboundEvent({...meeting(),date:'2026-12-31',timeStart:'',timeEnd:''});assert.deepEqual(all.end,{date:'2027-01-01'});
 const startOnly=outboundEvent({...meeting(),date:'2026-12-31',timeStart:'23:30',timeEnd:''});assert.equal(startOnly.end.dateTime,'2027-01-01T00:30:00');
 for(const bad of [{date:'2026-02-30'},{timeStart:'25:00'},{timeEnd:'08:59'},{title:''},{attendees:['mail@example.edu']}])assert.throws(()=>outboundEvent({...meeting(),...bad}));
});
test('write OAuth is explicit, single-use and grants only the verified connection version',async()=>{
 const f=await fixture({write:false});try{
  assert.equal((await f.call('/outbound-enable')).status,409);
  const r=await f.call('/connect?mode=write',{});assert.equal(r.status,200);const u=new URL((await r.json()).authorizationUrl);
  assert.equal(u.searchParams.get('scope'),'openid email '+CALENDAR_WRITE_SCOPE);
  const callback=new Request(api+prefix+'/callback?state='+u.searchParams.get('state')+'&code=synthetic');
  const rejected=await handle(callback,f.env,f.fetcher);assert.equal(new URL(rejected.headers.get('Location')).searchParams.get('gcal'),'calendar_write_permission_missing');
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS n FROM google_calendar_write_grants').get().n,0);
  f.setScope(CALENDAR_WRITE_SCOPE);const started=await f.call('/connect?mode=write',{}),auth=new URL((await started.json()).authorizationUrl);
  const successful=new Request(api+prefix+'/callback?state='+auth.searchParams.get('state')+'&code=synthetic');
  assert.equal(new URL((await handle(successful,f.env,f.fetcher)).headers.get('Location')).searchParams.get('gcal'),'connected');
  const connection=f.sqlite.prepare('SELECT version FROM private_google_calendar_connections').get();assert.equal(f.sqlite.prepare('SELECT connection_version FROM google_calendar_write_grants').get().connection_version,connection.version);
  assert.notEqual(new URL((await handle(successful,f.env,f.fetcher)).headers.get('Location')).searchParams.get('gcal'),'connected');
  assert.equal((await f.call('/outbound-enable')).status,200);
 }finally{f.close();}
});
test('owner, origin, feature, session and exact school/year gates block writes before Google',async()=>{
 const f=await fixture();try{
  for(const body of [{...target,school:'other'},{...target,year:'2025-2026'},{...target,events:[]},{...target,year:''}])assert.ok([400,403].includes((await f.call('/outbound-enable',body)).status));
  assert.equal((await handle(f.request('/outbound-enable','POST',target,token,'https://evil.example'),f.env,f.fetcher)).status,403);
  assert.equal((await f.call('/outbound-enable',target,'b'.repeat(64))).status,401);
  f.env.GOOGLE_CALENDAR_OUTBOUND_ENABLED='false';assert.equal((await f.call('/outbound-enable')).status,503);f.env.GOOGLE_CALENDAR_OUTBOUND_ENABLED='true';
  f.sqlite.prepare("UPDATE staffsessions SET username='other@example.edu'").run();assert.equal((await f.call('/outbound-enable')).status,403);assert.equal(f.calls.length,0);
 }finally{f.close();}
});
test('only today onward native meetings export once; Google, old and cancelled meetings never do',async()=>{
 const f=await fixture();try{
  f.save([meeting('old',-1),meeting('today'),meeting('future',7),{...meeting('google'),isFromGoogle:true},{...meeting('cancel'),status:'cancelled'}]);
  assert.equal((await f.call('/outbound-enable')).status,200);assert.equal((await f.call('/outbound-sync')).status,200);assert.equal(f.remote.size,2);
  assert.equal((await f.call('/outbound-sync')).status,200);assert.equal(f.calls.filter(c=>c.method==='POST').length,2);
  const status=await(await f.call('/outbound-status')).json();assert.equal(status.pending,0);assert.equal(status.sinceDate,israelToday());
  for(const e of f.remote.values()){assert.equal(e.attendees,undefined);assert.match(e.description,/רכזים/);assert.equal(e.extendedProperties.private.principalPortalSource,'portal');}
 }finally{f.close();}
});
test('stable IDs isolate school, year and deployment, and each recurring occurrence updates/cancels independently',async()=>{
 const f=await fixture();try{
  f.save([meeting('series-1'),meeting('series-2',7)]);await f.call('/outbound-enable');await f.call('/outbound-sync');
  const identity=await outboundIdentity({portal:origin,owner},target,'series-1');assert.match(identity.id,/^[0-9a-v]{5,1024}$/);
  for(const other of [{school:'other',year:target.year},{school:target.school,year:'2027-2028'}])assert.notEqual((await outboundIdentity({portal:origin,owner},other,'series-1')).id,identity.id);
  assert.notEqual((await outboundIdentity({portal:'https://staging.principal-portal.pages.dev',owner},target,'series-1')).id,identity.id);
  f.save([{...meeting('series-1'),title:'Changed',timeStart:'11:00',timeEnd:'12:00'},meeting('series-2',7)]);await f.call('/outbound-sync');assert.equal(f.remote.get(identity.id).summary,'Changed');
  f.save([meeting('series-2',7)]);await f.call('/outbound-sync');assert.equal(f.remote.get(identity.id).status,'cancelled');assert.equal([...f.remote.values()].filter(e=>e.status==='confirmed').length,1);
  await f.call('/outbound-sync');assert.equal(f.calls.filter(c=>c.method==='POST').length,2);
 }finally{f.close();}
});
test('timed-out inserts recover by deterministic ID without creating a second event',async()=>{
 const f=await fixture();try{
  await f.call('/outbound-enable');
  // Simulate a response lost after Google accepted the insert.
  const losing=async(url,options)=>{const r=await f.fetcher(url,options);if(options.method==='POST'&&url.startsWith('https://www.googleapis.com/calendar/'))throw Error('lost response');return r;};
  assert.equal((await handle(f.request('/outbound-sync'),f.env,losing)).status,502);assert.equal(f.remote.size,1);f.retry();
  assert.equal((await f.call('/outbound-sync')).status,200);assert.equal(f.remote.size,1);assert.equal(f.calls.filter(c=>c.method==='POST').length,1);
 }finally{f.close();}
});
test('unknown remote markers, ETag races, invalid saved data and identity changes never overwrite unrelated meetings',async()=>{
 const f=await fixture();try{
  await f.call('/outbound-enable');const identity=await outboundIdentity({portal:origin,owner},target,'one');
  f.remote.set(identity.id,{id:identity.id,status:'confirmed',etag:'"1"',summary:'Unrelated'});
  assert.equal((await f.call('/outbound-sync')).status,409);assert.equal(f.remote.get(identity.id).summary,'Unrelated');assert.equal(f.calls.some(c=>c.method==='PATCH'),false);
  f.remote.clear();f.retry();await f.call('/outbound-sync');f.save([{...meeting(),title:'changed'}]);f.failNext(412);
  assert.equal((await f.call('/outbound-sync')).status,409);assert.equal(f.remote.get(identity.id).summary,'ישיבת הנהלה');
  f.retry();f.save([{...meeting(),date:'invalid'}]);const before=f.calls.length;assert.equal((await f.call('/outbound-sync')).status,409);assert.equal(f.calls.length,before);
  f.retry();f.save([{...meeting(),title:'changed'}]);f.setEmail('wrong@example.edu');assert.equal((await f.call('/outbound-sync')).status,403);assert.equal(f.remote.get(identity.id).summary,'ישיבת הנהלה');
 }finally{f.close();}
});
test('lease, changed saved revision, session expiry and stop guard in-flight side effects',async()=>{
 for(const change of ['revision','session','stop']){
  const f=await fixture();try{
   await f.call('/outbound-enable');f.onNext(()=>{
    if(change==='revision')f.save([{...meeting(),title:'newer'}]);
    if(change==='session')f.sqlite.prepare("UPDATE staffsessions SET revoked_at='now'").run();
    if(change==='stop')f.sqlite.prepare('UPDATE google_calendar_outbound_targets SET enabled=0').run();
   });
   assert.ok([401,409].includes((await f.call('/outbound-sync')).status));assert.equal(f.remote.size,0);
  }finally{f.close();}
 }
 const f=await fixture();try{
  await f.call('/outbound-enable');f.sqlite.prepare('UPDATE google_calendar_outbound_targets SET lease_until=?').run(new Date(Date.now()+60000).toISOString());
  assert.equal((await(await f.call('/outbound-sync')).json()).busy,true);assert.equal(f.calls.length,0);
 }finally{f.close();}
});
test('large batches retain durable pending work and continue without an open browser; removed membership stops it',async()=>{
 const f=await fixture();try{
  f.save(Array.from({length:15},(_,i)=>meeting('batch-'+i,i)));await f.call('/outbound-enable');
  const first=await(await f.call('/outbound-sync')).json();assert.equal(first.written,12);assert.equal(first.pending,3);
  await runGoogleCalendarOutbox(f.env,f.fetcher);assert.equal(f.remote.size,15);assert.equal((await(await f.call('/outbound-status')).json()).pending,0);
  f.save([meeting('another',20)]);f.sqlite.prepare('DELETE FROM principals').run();const before=f.calls.length;await runGoogleCalendarOutbox(f.env,f.fetcher);assert.equal(f.calls.length,before);
  f.sqlite.prepare('INSERT INTO principals VALUES(?,?)').run(owner,target.school);await f.call('/outbound-stop');await runGoogleCalendarOutbox(f.env,f.fetcher);assert.equal(f.calls.length,before);
 }finally{f.close();}
});
test('return import suppresses only recorded same-context mirrors and still imports original Google meetings',async()=>{
 const f=await fixture();try{
  await f.call('/outbound-enable');await f.call('/outbound-sync');
  f.remote.set('original',{id:'original',status:'confirmed',summary:'Original Google',start:{date:day()},end:{date:day(1)}});
  const result=await(await f.call('/sync-shared?month='+day().slice(0,7))).json();assert.equal(result.ok,true);assert.deepEqual(result.snapshot.events.map(e=>e.id),['original']);
 }finally{f.close();}
});
test('read-only reconnect removes stale grant, owned scope still reads, and disconnect disables all outbound targets',async()=>{
 const f=await fixture();try{
  await f.call('/outbound-enable');const auth=new URL((await(await f.call('/connect',{})).json()).authorizationUrl);f.setScope(CALENDAR_SCOPE);
  assert.equal(new URL((await handle(new Request(api+prefix+'/callback?state='+auth.searchParams.get('state')+'&code=test'),f.env,f.fetcher)).headers.get('Location')).searchParams.get('gcal'),'connected');
  assert.equal(f.sqlite.prepare('SELECT COUNT(*) AS n FROM google_calendar_write_grants').get().n,0);assert.equal((await f.call('/outbound-sync')).status,409);
  assert.equal((await handle(f.request('/events?month='+day().slice(0,7),'GET'),f.env,f.fetcher)).status,200);
  assert.equal((await handle(f.request('/connection','DELETE'),f.env,f.fetcher)).status,200);assert.equal(f.sqlite.prepare('SELECT enabled FROM google_calendar_outbound_targets').get().enabled,0);
 }finally{f.close();}
});
