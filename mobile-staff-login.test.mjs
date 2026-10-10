import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import worker from './worker.js';

const html = fs.readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const functionSource = name => {
  const match = html.match(new RegExp(`(?:async )?function ${name}\\([^]*?\\n\\}`));
  assert.ok(match, name);
  return match[0];
};
const school = 'synthetic-school', year = '2026-2027';
const email = 'synthetic-teacher@educ.org.il';
const clientId = html.match(/const GOOGLE_CLIENT_ID\s*=\s*'([^']+)'/)[1];

function serverFixture() {
  const db = new DatabaseSync(':memory:');
  db.exec(`CREATE TABLE principals(email TEXT, name TEXT, school TEXT);
    CREATE TABLE admins(email TEXT,name TEXT);
    CREATE TABLE staff_permissions(email TEXT,school TEXT,year TEXT,name TEXT,permissions TEXT);
    CREATE TABLE portal_data(type TEXT,school TEXT,year TEXT,payload TEXT,updated_at TEXT);
    CREATE TABLE staffsessions(token_hash TEXT PRIMARY KEY,username TEXT,school TEXT,year TEXT,role TEXT,
      created_at TEXT,expires_at TEXT,last_seen_at TEXT,ip_hash TEXT,user_agent_hash TEXT,revoked_at TEXT);
    CREATE TABLE staff_auth(username TEXT,must_change_password INTEGER,password_changed_at TEXT);
    CREATE TABLE audit_log(occurred_at TEXT,request_id TEXT,actor_username TEXT,actor_role TEXT,
      actor_school TEXT,action TEXT,resource_type TEXT,resource_id TEXT,target_school TEXT,target_year TEXT,
      outcome TEXT,ip_hash TEXT,user_agent_hash TEXT,metadata_json TEXT);`);
  const cache = new Map();
  const env = {
    DB: { prepare(sql) { const statement = db.prepare(sql); return {
      args: [], bind(...args) { this.args = args; return this; },
      async first() { return statement.get(...this.args) || null; },
      async all() { return { results: statement.all(...this.args) }; },
      async run() { return { meta: { changes: statement.run(...this.args).changes } }; },
    }; } },
    SESSIONS_KV: {
      async get(key, mode) { const value = cache.get(key); return mode === 'json' && value ? JSON.parse(value) : value ?? null; },
      async put(key,value) { cache.set(key,value); }, async delete(key) { cache.delete(key); },
    },
  };
  const authorize = (perms, recordYear = year, recordSchool = school) => db.prepare('INSERT INTO staff_permissions VALUES(?,?,?,?,?)')
    .run(email,recordSchool,recordYear,'Synthetic Teacher',JSON.stringify(perms));
  const request = (path, body, token) => worker.fetch(new Request('https://principal-api.1002220729.workers.dev'+path, {
    method: body ? 'POST' : 'GET', headers: { Origin:'https://principal-portal.pages.dev',
      ...(body ? {'Content-Type':'application/json'} : {}), ...(token ? {Authorization:'Bearer '+token} : {}) },
    ...(body ? {body:JSON.stringify(body)} : {}),
  }), env, {});
  return {db,env,authorize,request,close:()=>db.close()};
}

test('server verifies EDU identity, resolves the staff role and preserves only granted permissions', async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async url => {
      assert.ok(String(url).startsWith('https://oauth2.googleapis.com/tokeninfo?id_token='));
      return Response.json({aud:clientId,email_verified:'true',email,exp:Date.now()/1000+3600});
    };
    for (const [perms,type,expected] of [
      [{s0:'view'},'plan',200], [{s_absences:'edit'},'plan',200],
      [{calendar:'view'},'calendar',200], [{gantt:'edit'},'gantt',200],
      [{mtss:'view'},'mtss',200], [{calendar:'view'},'plan',403],
      [{s0:'view'},'teachers',403], [{s0:'view'},'calendar',403],
    ]) {
      const h = serverFixture();
      try {
        h.authorize(perms);
        const res = await h.request('/api/auth/google-login',{idToken:'synthetic-verified-token',requestedRole:'staffmember',school,year});
        assert.equal(res.status,200);
        const data = await res.json();
        assert.equal(data.session.role,'staffmember');
        assert.equal(data.session.school,school);
        assert.equal(data.session.year,year);
        assert.deepEqual(data.session.permissions,perms);
        assert.equal((await h.request('/api/data?type='+type+'&school='+school+'&year='+year, null,data.token)).status,expected);
      } finally { h.close(); }
    }
  } finally { globalThis.fetch=originalFetch; }
});

for (const [label, claims] of [
  ['wrong client',{aud:'another-app'}],['unverified email',{email_verified:false}],
  ['expired credential',{exp:Date.now()/1000-3600}],['missing identity',{email:''}],
]) test('server denies '+label, async()=>{
  const h=serverFixture(),originalFetch=globalThis.fetch;
  try {
    h.authorize({s0:'view'});
    globalThis.fetch=async()=>Response.json({aud:clientId,email_verified:true,email,exp:Date.now()/1000+3600,...claims});
    assert.equal((await h.request('/api/auth/google-login',{idToken:'synthetic-token',requestedRole:'staffmember',school,year})).status,401);
    assert.equal(h.db.prepare('SELECT COUNT(*) AS n FROM staffsessions').get().n,0);
  } finally { globalThis.fetch=originalFetch;h.close(); }
});

for(const [label,hints,grant] of [
  ['no school in shared link',{year},true], ['wrong school',{school:'other-school',year},true],
  ['wrong year',{school,year:'2025-2026'},true], ['no staff grant',{school,year},false],
])test('server safely denies '+label,async()=>{
  const h=serverFixture(),originalFetch=globalThis.fetch;
  try {
    if(grant)h.authorize({s0:'view'});
    globalThis.fetch=async()=>Response.json({aud:clientId,email_verified:true,email,exp:Date.now()/1000+3600});
    assert.equal((await h.request('/api/auth/google-login',{idToken:'synthetic-token',requestedRole:'staffmember',...hints})).status,403);
    assert.equal(h.db.prepare('SELECT COUNT(*) AS n FROM staffsessions').get().n,0);
  } finally { globalThis.fetch=originalFetch;h.close(); }
});

test('principal access alone does not grant staff access, and choosing staff cannot grant principal privileges',async()=>{
  const h=serverFixture(),originalFetch=globalThis.fetch;
  try {
    h.db.prepare('INSERT INTO principals VALUES(?,?,?)').run(email,'Synthetic Principal',school);
    globalThis.fetch=async()=>Response.json({aud:clientId,email_verified:true,email,exp:Date.now()/1000+3600});
    assert.equal((await h.request('/api/auth/google-login',{idToken:'synthetic-token',requestedRole:'staffmember',school,year})).status,403);
    h.authorize({calendar:'view'});
    const response=await h.request('/api/auth/google-login',{idToken:'synthetic-token',requestedRole:'staffmember',school,year});
    assert.equal((await response.json()).session.role,'staffmember');
  } finally {globalThis.fetch=originalFetch;h.close();}
});

function uiFixture(width=284) {
  const nodes = new Map(),tasks=new Map(),renders=[],listeners=[],messages=[];
  let timer=0;
  const node=id=>{
    if(!nodes.has(id))nodes.set(id,{
      id,style:{display:''},dataset:{},innerHTML:'',textContent:'',src:'about:blank',isConnected:true,
      classList:{add(){},remove(){},contains(){return false;}},focus(){},
      getBoundingClientRect(){return {width:this.style.display==='none'?0:width};},
      contentWindow:{postMessage:m=>messages.push(m)},
      addEventListener:(type,fn)=>listeners.push({id,type,fn}),
    });
    return nodes.get(id);
  };
  const sectionIds=Array.from(html.matchAll(/\{ id:'(s[^']+)'/g),m=>m[1]);
  const context=vm.createContext({
    console:{log(){}},_googleIdentityInitialized:false,_googleLoginInFlight:false,_googleWaitTimer:null,
    _pendingRole:null,GOOGLE_CLIENT_ID:clientId,handleGoogleCredential(){},onGoogleLoginClick(){},
    PS:{_framePerms:{}},PORTAL_ORIGIN:'https://portal.example',SECTION_LIST:sectionIds,
    PORTAL_FRAMES:['gantt','mtss','calendar','teachers'],
    document:{getElementById:node,querySelectorAll:()=>[]},window:{google:{}},
    google:{accounts:{id:{initialize(){},renderButton:(el,options)=>renders.push({el,options,width:el.getBoundingClientRect().width})}}},
    setTimeout:(fn,ms)=>{const id=++timer;tasks.set(id,{fn,ms});return id;},clearTimeout:id=>tasks.delete(id),
  });
  const names=['initializeGoogleIdentity','resetGoogleButton','renderGoogleLoginButton','switchLoginMethod','selectRole','loadAllIframes'];
  if(html.includes('function getStaffFramePermission('))names.push('getStaffFramePermission');
  vm.runInContext(names.map(functionSource).join('\n'),context);
  return {context,node,nodes,renders,listeners,messages,tasks,
    flush(){const pending=[...tasks.values()];tasks.clear();for(const t of pending)t.fn();}};
}

test('Google button is not created while hidden behind staff password tab',()=>{
  const h=uiFixture();
  h.context.selectRole('staffmember',h.node('roleBtnStaff'));
  h.flush();
  assert.ok(h.renders.every(r=>r.width>0),'a hidden Google button was marked rendered');
});

test('Google button fits the available mobile content width',()=>{
  const h=uiFixture(244);
  h.context.selectRole('staffmember',h.node('roleBtnStaff'));
  h.flush();
  h.context.switchLoginMethod('google',h.node('tabGoogle'));
  assert.equal(h.renders.length,1);
  assert.ok(Number(h.renders[0].options.width)<=244,'Google button overflows the mobile card');
});

for(const [label,perms,expected] of [
  ['one allowed section',{s0:'view'},'view'],['another allowed section',{s_absences:'edit'},'edit'],
  ['mixed view and edit sections',{s0:'view',s2:'edit'},'edit'],
  ['inventory wrapper only',{sinventory:'view'},'view'],['no plan sections',{calendar:'view'},'none'],
])test('staff frame loading uses '+label,()=>{
  const h=uiFixture();h.context.loadAllIframes(perms);
  assert.equal(h.context.PS._framePerms.plan,expected);
  assert.equal(h.node('planFrame').src,expected==='none'?'about:blank':'tknyt.html');
});

test('principal frame loading remains unrestricted',()=>{
  const h=uiFixture();h.context.loadAllIframes(null);
  for(const name of ['plan','gantt','mtss','calendar'])assert.equal(h.context.PS._framePerms[name],'edit');
});

test('a hidden Google method neither initializes nor marks a button ready',()=>{
  const h=uiFixture();
  const container=h.node('loginGoogleBtnAlt');container.style.display='none';
  h.context.renderGoogleLoginButton(container);
  assert.equal(h.renders.length,0);
  assert.equal(container.dataset.googleButtonRendered,undefined);
});

function navigationFixture(perms, activeFrame='plan') {
  const h=uiFixture();
  const buttons=[
    {dataset:{target:'plan',section:'s0',perm:'plan'}},
    {dataset:{target:'plan',section:'s_absences',perm:'plan'}},
    {dataset:{target:'calendar',perm:'calendar'}},
  ].map(btn=>({...btn,classList:{contains:()=>false}}));
  h.context.document.querySelectorAll=()=>buttons;
  h.context.PS.activeFrame=activeFrame;
  h.context.getPortalSession=()=>({portalRole:'staffmember',permissions:perms});
  const opened=[];h.context.navClick=btn=>opened.push(btn.dataset);
  vm.runInContext(['openStaffStartPage','sendStaffPlanContext'].map(functionSource).join('\n'),h.context);
  return {...h,opened};
}

for(const [perms,target,section] of [
  [{s_absences:'edit'},'plan','s_absences'],[{calendar:'view'},'calendar',undefined],
])test('staff starts on an allowed page instead of a blank default: '+JSON.stringify(perms),()=>{
  const h=navigationFixture(perms);h.context.openStaffStartPage(perms);
  assert.equal(h.opened[0].target,target);assert.equal(h.opened[0].section,section);
  assert.equal(h.node('staffAccessNotice').style.display,'none');
});

test('empty permissions show an explicit notice without opening unauthorized pages',()=>{
  const h=navigationFixture({});h.context.openStaffStartPage({});
  assert.equal(h.opened.length,0);assert.equal(h.node('staffAccessNotice').style.display,'block');
});

test('staff permissions and latest selected section are replayed when the plan iframe becomes ready',()=>{
  const h=navigationFixture({s_absences:'view'});
  h.context.PS._requestedPlanSection='s_absences';
  h.context.sendStaffPlanContext(h.node('planFrame').contentWindow);
  assert.equal(h.messages[0].type,'set-section-permissions');
  assert.equal(h.messages[1].type,'switch-section');
  assert.equal(h.messages[1].section,'s_absences');
});

test('a stale unauthorized section is not replayed after staff login',()=>{
  const h=navigationFixture({s_absences:'view'});
  h.context.PS._requestedPlanSection='s0';
  h.context.sendStaffPlanContext(h.node('planFrame').contentWindow);
  assert.equal(h.messages.length,1);assert.equal(h.messages[0].type,'set-section-permissions');
});

function dataLoadingFixture(perms,role='staffmember') {
  const h=uiFixture(),requests=[];
  h.context.getPortalSession=()=>({portalRole:role,permissions:perms});
  h.context.getSessionToken=()=> 'synthetic-session';
  h.context.PS.school=school;h.context.PS.year=year;
  h.context.PS._pendingIframeReady=[];
  h.context.performance={now:()=>0};h.context.WORKER_URL_AUTH='https://api.example';
  h.context.CUSTOM_LINKS_TYPE='custom_links';h.context.updateBadges=()=>{};
  h.context.updateStatus=()=>{};h.context.renderCustomLinks=()=>{};
  h.context.authFetch=async url=>{
    const type=new URL(url).searchParams.get('type');requests.push(type);
    return Response.json(type==='custom_links'?[]:{schoolName:school,year});
  };
  vm.runInContext(['canLoadPortalResource','loadPortalDataAndNotifyFrames','loadCustomLinks','reloadFrameData'].map(functionSource).join('\n'),h.context);
  return {...h,requests};
}

for(const [perms,expected] of [
  [{s_absences:'view'},['plan']], [{calendar:'view'},['calendar']],
  [{gantt:'edit',mtss:'view'},['gantt','mtss']], [{},[]],
])test('successful staff login loads only granted server resources: '+JSON.stringify(perms),async()=>{
  const h=dataLoadingFixture(perms);
  await h.context.loadCustomLinks();await h.context.loadPortalDataAndNotifyFrames();
  assert.deepEqual(h.requests,expected);assert.equal(h.context.PS._initDone,true);
});

test('principal data loading still loads every portal resource and custom links',async()=>{
  const h=dataLoadingFixture({},'principal');
  await h.context.loadCustomLinks();await h.context.loadPortalDataAndNotifyFrames();
  assert.deepEqual(h.requests,['custom_links','plan','gantt','mtss','calendar','teachers']);
});

test('returning to a staff tab does not request unrelated gantt or HR data',async()=>{
  const h=dataLoadingFixture({calendar:'view'});
  h.context.PS._initDone=true;h.context.PS.calendarReady=true;h.context.PS.teachersReady=true;
  h.context.reloadFrameData();await Promise.resolve();await Promise.resolve();
  assert.deepEqual(h.requests,['calendar']);
});
