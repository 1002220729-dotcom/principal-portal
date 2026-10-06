// Durable portal -> Google mirror. Only the server's saved calendar is a source.
// All occurrences keep their local IDs; neither recurrence rules nor invitations
// are sent to Google. A single cancelled occurrence stays an independent event.
const dayMs = 86400000;
const eventURL = 'https://www.googleapis.com/calendar/v3/calendars/primary/events';
const encoder = new TextEncoder();
export const OUTBOUND_CRON = '* * * * *';
export function israelToday(now = Date.now()) {
  const parts = new Intl.DateTimeFormat('en-CA', {timeZone:'Asia/Jerusalem',year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(now));
  return ['year','month','day'].map(key=>parts.find(p=>p.type===key).value).join('-');
}
function validDay(value) {
  return typeof value === 'string' && /^20\d{2}-\d{2}-\d{2}$/.test(value) &&
    Number.isFinite(Date.parse(value+'T00:00:00Z')) && new Date(value+'T00:00:00Z').toISOString().slice(0,10) === value;
}
const validTime = value => typeof value === 'string' && /^(?:[01]\d|2[0-3]):[0-5]\d$/.test(value);
async function digest(value) {
  return [...new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(value)))].map(b=>b.toString(16).padStart(2,'0')).join('');
}
export async function outboundIdentity(config, target, localId) {
  const context = await digest(JSON.stringify([config.portal,config.owner,target.school,target.year]));
  return {context,id:'pp'+await digest(JSON.stringify([context,localId]))};
}
// Convert local wall time with an explicit IANA zone. Google applies Israeli DST.
// A missing end time gets one hour, including a rollover past midnight.
export function outboundEvent(event) {
  if (!event || typeof event !== 'object' || Array.isArray(event) || typeof event.id !== 'string' ||
      !event.id || event.id.length > 512 || typeof event.title !== 'string' || !event.title.trim() ||
      event.title.length > 1000 || !validDay(event.date)) throw Error('invalid_outbound_calendar');
  const nextDay = date => new Date(Date.parse(date+'T00:00:00Z')+dayMs).toISOString().slice(0,10);
  let start,end;
  if (!event.timeStart && !event.timeEnd) {
    start={date:event.date};end={date:nextDay(event.date)};
  } else {
    if (!validTime(event.timeStart) || (event.timeEnd && !validTime(event.timeEnd))) throw Error('invalid_outbound_calendar');
    let endDate=event.date,endTime=event.timeEnd;
    if (!endTime) {
      const minutes=Number(event.timeStart.slice(0,2))*60+Number(event.timeStart.slice(3))+60;
      if(minutes>=1440)endDate=nextDay(event.date);
      endTime=String(Math.floor(minutes%1440/60)).padStart(2,'0')+':'+String(minutes%60).padStart(2,'0');
    } else if(endTime<=event.timeStart)throw Error('invalid_outbound_calendar');
    start={dateTime:event.date+'T'+event.timeStart+':00',timeZone:'Asia/Jerusalem'};
    end={dateTime:endDate+'T'+endTime+':00',timeZone:'Asia/Jerusalem'};
  }
  const notes=[];
  for(const [key,label] of [['attendees','משתתפים'],['agenda','סדר יום'],['summary','סיכום']]) {
    if(event[key]!==undefined&&typeof event[key]!=='string')throw Error('invalid_outbound_calendar');
    if(event[key])notes.push(label+': '+event[key]);
  }
  if(event.location!==undefined&&typeof event.location!=='string')throw Error('invalid_outbound_calendar');
  const body={summary:event.title.trim(),location:event.location||'',description:notes.join('\n\n'),start,end};
  if(encoder.encode(JSON.stringify(body)).length>32768)throw Error('invalid_outbound_calendar');
  return body;
}
async function desiredEvents(env,config,target,fail) {
  const row=await env.DB.prepare("SELECT payload FROM portal_data WHERE type='calendar' AND school=? AND year=?")
    .bind(target.school,target.year).first();
  // An absent/broken calendar cannot authorize cancellation of its Google mirror.
  if(!row)fail(409,'invalid_outbound_calendar');
  let payload;try{payload=JSON.parse(row.payload);}catch{fail(409,'invalid_outbound_calendar');}
  const events=payload?.meetings?.events;
  if(!Array.isArray(events)||events.length>10000)fail(409,'invalid_outbound_calendar');
  const found=new Map(),ids=new Set();
  for(const event of events) {
    if(event?.isFromGoogle===true)continue;
    if(!event||typeof event.id!=='string'||ids.has(event.id))fail(409,'invalid_outbound_calendar');
    ids.add(event.id);
    if(!validDay(event.date))fail(409,'invalid_outbound_calendar');
    if(event.date<target.since_date)continue;
    if(['cancelled','בוטל'].includes(event.status))continue;
    let body;try{body=outboundEvent(event);}catch{fail(409,'invalid_outbound_calendar');}
    const identity=await outboundIdentity(config,target,event.id);
    body.extendedProperties={private:{principalPortalSource:'portal',principalPortalContext:identity.context}};
    found.set(event.id,{localId:event.id,googleId:identity.id,body,hash:await digest(JSON.stringify(body))});
  }
  return found;
}
async function targetRow(env,config,target) {
  return env.DB.prepare('SELECT * FROM google_calendar_outbound_targets WHERE owner=? AND school=? AND year=?')
    .bind(config.owner,target.school,target.year).first();
}
async function writeAllowed(env,config,connection) {
  return !!connection && !!await env.DB.prepare('SELECT owner FROM google_calendar_write_grants WHERE owner=? AND connection_version=?')
    .bind(config.owner,connection.version).first();
}
export async function outboundStatus(env,config,target,connection,fail) {
  const row=await targetRow(env,config,target);
  const desired=await desiredEvents(env,config,row||{...target,since_date:israelToday()},fail);
  const records=(await env.DB.prepare('SELECT local_id,synced_hash,cancelled FROM google_calendar_outbound_events WHERE owner=? AND school=? AND year=?')
    .bind(config.owner,target.school,target.year).all()).results;
  let pending=0;
  for(const [id,item] of desired)if(!records.some(r=>r.local_id===id&&r.synced_hash===item.hash&&!r.cancelled))pending++;
  for(const row of records)if(!row.cancelled&&!desired.has(row.local_id))pending++;
  return {enabled:row?.enabled===1,writeAuthorized:await writeAllowed(env,config,connection),sinceDate:row?.since_date||israelToday(),
    total:desired.size,pending,lastSyncedAt:row?.last_synced_at||null,error:row?.last_error||null};
}
export async function enableOutbound(env,config,target,connection,fail) {
  if(!await writeAllowed(env,config,connection))fail(409,'calendar_write_permission_missing');
  await desiredEvents(env,config,{...target,since_date:israelToday()},fail);
  // Re-enabling keeps the original cutoff and mirror IDs. It never duplicates.
  await env.DB.prepare(`INSERT INTO google_calendar_outbound_targets(owner,school,year,since_date,enabled)
    VALUES(?,?,?,?,1) ON CONFLICT(owner,school,year) DO UPDATE SET enabled=1,revision=revision+1,retry_at=NULL`)
    .bind(config.owner,target.school,target.year,israelToday()).run();
  return {ok:true,...await outboundStatus(env,config,target,connection,fail)};
}
export async function pauseOutbound(env,config,target) {
  await env.DB.prepare('UPDATE google_calendar_outbound_targets SET enabled=0,lease_token=NULL,lease_until=NULL WHERE owner=? AND school=? AND year=?')
    .bind(config.owner,target.school,target.year).run();
  return {ok:true,enabled:false};
}
function safeError(error) {
  return ['calendar_write_permission_missing','calendar_permission_missing','google_rate_limited','reconnect_required',
    'account_mismatch','connection_changed','outbound_conflict','invalid_outbound_calendar','google_unavailable','session_expired'].includes(error.code||error.message)
    ? error.code||error.message : 'google_unavailable';
}
export async function syncOutbound(env,config,target,helpers,{recheck=async()=>{},limit=12}={}) {
  const {fail}=helpers,now=new Date().toISOString(),lease=crypto.randomUUID();
  const claimed=await env.DB.prepare(`UPDATE google_calendar_outbound_targets SET lease_token=?,lease_until=?
    WHERE owner=? AND school=? AND year=? AND enabled=1 AND (lease_until IS NULL OR lease_until<?)
      AND (retry_at IS NULL OR retry_at<=?) RETURNING *`)
    .bind(lease,new Date(Date.now()+60000).toISOString(),config.owner,target.school,target.year,now,now).first();
  if(!claimed)return {ok:true,busy:true};
  let written=0;
  try {
    const connection=await helpers.getConnection();
    if(!await writeAllowed(env,config,connection))fail(409,'calendar_write_permission_missing');
    const desired=await desiredEvents(env,config,claimed,fail);
    const records=(await env.DB.prepare('SELECT * FROM google_calendar_outbound_events WHERE owner=? AND school=? AND year=?')
      .bind(config.owner,target.school,target.year).all()).results;
    const existing=new Map(records.map(r=>[r.local_id,r])),jobs=[];
    for(const [id,item] of desired){const prior=existing.get(id);if(!prior||prior.synced_hash!==item.hash||prior.cancelled)jobs.push({...item,cancel:false});}
    for(const row of records)if(!row.cancelled&&!desired.has(row.local_id))jobs.push({localId:row.local_id,googleId:row.google_id,cancel:true,hash:'cancelled'});
    if(!jobs.length) {
      await env.DB.prepare(`UPDATE google_calendar_outbound_targets SET synced_revision=?,last_synced_at=?,last_error=NULL,retry_at=NULL
        WHERE owner=? AND school=? AND year=? AND enabled=1 AND lease_token=?`).bind(claimed.revision,now,config.owner,target.school,target.year,lease).run();
      return {ok:true,pending:0,written:0};
    }
    const access=await helpers.access(connection,true),start=Date.now();
    async function guard() {
      await recheck();
      const active=await env.DB.prepare(`UPDATE google_calendar_outbound_targets SET lease_until=? WHERE owner=? AND school=? AND year=?
        AND enabled=1 AND lease_token=? AND lease_until>? AND revision=? RETURNING owner`)
        .bind(new Date(Date.now()+60000).toISOString(),config.owner,target.school,target.year,lease,new Date().toISOString(),claimed.revision).first();
      if(!active||(await helpers.getConnection())?.version!==connection.version||!await writeAllowed(env,config,connection))fail(409,'connection_changed');
    }
    async function google(url,method,body,etag) {
      await guard();
      const response=await helpers.googleFetch(url,{method,headers:{Authorization:'Bearer '+access,
        ...(body?{'Content-Type':'application/json'}:{}),...(etag?{'If-Match':etag}:{})},...(body?{body:JSON.stringify(body)}:{})});
      if(response.status===401)fail(409,'reconnect_required');
      if(response.status===403)fail(409,'calendar_write_permission_missing');
      if(response.status===429)fail(429,'google_rate_limited');
      if(response.status===412)fail(409,'outbound_conflict');
      return response;
    }
    for(const job of jobs.slice(0,limit)) {
      if(Date.now()-start>20000)break;
      // Save identity before the remote side effect. A timed-out insert can be
      // recovered by GET of this deterministic ID rather than inserted twice.
      await env.DB.prepare(`INSERT INTO google_calendar_outbound_events(owner,school,year,local_id,google_id)
        VALUES(?,?,?,?,?) ON CONFLICT(owner,school,year,local_id) DO NOTHING`)
        .bind(config.owner,target.school,target.year,job.localId,job.googleId).run();
      const url=eventURL+'/'+job.googleId;
      let response=await google(url+'?fields=id,status,etag,extendedProperties','GET');
      let remote=null;
      if(response.ok)remote=await helpers.boundedJson(response,65536);
      else if(![404,410].includes(response.status))fail(502,'google_unavailable');
      const identity=await outboundIdentity(config,target,job.localId);
      if(remote) {
        // Unknown event IDs and marker collisions never authorize overwriting.
        if(remote.id!==job.googleId||remote.extendedProperties?.private?.principalPortalSource!=='portal'||
          remote.extendedProperties?.private?.principalPortalContext!==identity.context)fail(409,'outbound_conflict');
        if(typeof remote.etag!=='string'||!remote.etag)fail(502,'google_unavailable');
        if(!(job.cancel&&remote.status==='cancelled')) {
          response=await google(url+'?sendUpdates=none','PATCH',job.cancel?{status:'cancelled'}:{...job.body,status:'confirmed'},remote.etag);
          if(!response.ok)fail(502,'google_unavailable');
          const updated=await helpers.boundedJson(response,65536);
          if(updated.id!==job.googleId)fail(502,'google_unavailable');
        }
      } else if(!job.cancel) {
        response=await google(eventURL+'?sendUpdates=none','POST',{id:job.googleId,...job.body});
        if(response.status===409)fail(409,'outbound_conflict');
        if(!response.ok)fail(502,'google_unavailable');
        const created=await helpers.boundedJson(response,65536);
        if(created.id!==job.googleId)fail(502,'google_unavailable');
      }
      await guard();
      await env.DB.prepare(`UPDATE google_calendar_outbound_events SET synced_hash=?,cancelled=?
        WHERE owner=? AND school=? AND year=? AND local_id=?`)
        .bind(job.hash,job.cancel?1:0,config.owner,target.school,target.year,job.localId).run();
      written++;
    }
    await env.DB.prepare(`UPDATE google_calendar_outbound_targets SET synced_revision=CASE WHEN ?=0 THEN ? ELSE synced_revision END,
      last_synced_at=?,last_error=NULL,retry_at=NULL WHERE owner=? AND school=? AND year=? AND enabled=1 AND lease_token=?`)
      .bind(jobs.length-written,claimed.revision,new Date().toISOString(),config.owner,target.school,target.year,lease).run();
    return {ok:true,pending:jobs.length-written,written};
  } catch(error) {
    await env.DB.prepare(`UPDATE google_calendar_outbound_targets SET last_error=?,retry_at=?
      WHERE owner=? AND school=? AND year=? AND lease_token=?`).bind(safeError(error),new Date(Date.now()+60000).toISOString(),config.owner,target.school,target.year,lease).run();
    throw error;
  } finally {
    await env.DB.prepare('UPDATE google_calendar_outbound_targets SET lease_token=NULL,lease_until=NULL WHERE owner=? AND school=? AND year=? AND lease_token=?')
      .bind(config.owner,target.school,target.year,lease).run();
  }
}
