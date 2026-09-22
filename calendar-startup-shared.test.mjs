import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('./index.html', import.meta.url), 'utf8');
const source = html.match(/async function loadPortalDataAndNotifyFrames\([^]*?\n\}/)?.[0];
assert.ok(source);
const clone = value => JSON.parse(JSON.stringify(value));

function fixture(calendarResponse) {
  const messages = [], requests = [];
  let token = 'current-session';
  const state = { school:'test-school', year:'2026-2027', _dataLoadStarted:false,
    _initDone:false, _pendingIframeReady:[{data:{docType:'calendar'}}] };
  const frame = {contentWindow:{postMessage:(message, origin)=>messages.push({message, origin})}};
  const context = vm.createContext({ PS:state,
    PORTAL_ORIGIN:'https://principal-portal.pages.dev', WORKER_URL_AUTH:'https://api.example.test',
    getSessionToken:()=>token, performance:{now:()=>0}, console:{log(){}},
    document:{getElementById:id=>id === 'calendarFrame' ? frame : null},
    updateBadges(){}, updateStatus(){}, sendFrameReadOnlyIfNeeded(){},
    async authFetch(url, options) {
      requests.push({url, options});
      if (new URL(url).searchParams.get('type') === 'calendar') return await calendarResponse();
      return {ok:true, text:async()=> 'null'};
    }
  });
  vm.runInContext(source, context);
  return {state,messages,requests,run:()=>context.loadPortalDataAndNotifyFrames(),changeSession:()=>{token='new-session';}};
}

test('successful missing calendar reaches an already waiting iframe as loaded empty data for the requested tenant', async () => {
  const f = fixture(async()=>({ok:true,status:200,text:async()=> 'null'}));
  await f.run();
  assert.equal(f.state._initDone, true);
  assert.equal(f.messages.length, 1);
  assert.equal(f.messages[0].origin, 'https://principal-portal.pages.dev');
  assert.deepEqual(clone(f.messages[0].message), {type:'load-data',payload:{
    school:'test-school',year:'2026-2027',meetings:{events:[],settings:{}}
  }});
  assert.equal(f.messages[0].message.payload, f.state.calendarData);
  assert.equal(f.state._pendingIframeReady.length, 0);
  assert.equal(f.requests.length, 5);
  assert.ok(f.requests.every(({options})=>!options.method || options.method === 'GET'));
});

test('forbidden, failed, malformed and unavailable calendar responses never become loaded empty data', async () => {
  const failures = [
    async()=>({ok:false,status:403,text:async()=> 'null'}),
    async()=>({ok:false,status:500,text:async()=> 'null'}),
    async()=>({ok:true,status:200,text:async()=> '{broken'}),
    async()=>{throw new Error('network unavailable');}
  ];
  for (const response of failures) {
    const f = fixture(response);
    await f.run();
    assert.equal(f.state.calendarData, undefined);
    assert.equal(f.messages.length, 1);
    assert.equal(f.messages[0].message.type, 'school-data-update');
    assert.equal(f.messages.some(({message})=>message.type === 'load-data'), false);
  }
});

test('existing calendar data, including published snapshots, is forwarded without replacing its content', async () => {
  const payload = {school:'test-school',year:'2026-2027',meetings:{events:[{id:'manual-1'}],
    googleCalendar:{owner:'owner@example.test',months:{'2026-09':{events:[],fetchedAt:'2026-09-23T00:00:00Z'}}}}};
  const f = fixture(async()=>({ok:true,status:200,text:async()=>JSON.stringify(payload)}));
  await f.run();
  assert.deepEqual(clone(f.state.calendarData), payload);
  assert.deepEqual(clone(f.messages[0].message), {type:'load-data',payload});
});

test('a successful empty response from the old session cannot initialize or send data to the new session', async () => {
  let resolveCalendar;
  const deferred = new Promise(resolve=>{resolveCalendar=resolve;});
  const f = fixture(()=>deferred);
  const pending = f.run();
  f.changeSession();
  resolveCalendar({ok:true,status:200,text:async()=> 'null'});
  await pending;
  assert.equal(f.state._initDone, false);
  assert.equal(f.state.calendarData, undefined);
  assert.equal(f.messages.length, 0);
  assert.equal(f.state._pendingIframeReady.length, 1);
});
