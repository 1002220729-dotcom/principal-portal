import test from 'node:test';import assert from 'node:assert/strict';import fs from 'node:fs';import vm from 'node:vm';
const html=fs.readFileSync(new URL('./index.html',import.meta.url),'utf8');
const source=html.slice(html.indexOf('let _staffRows = [];'),html.indexOf('// SM TAB SWITCHING'));
function setup(fetcher, role='principal'){
 const elements=new Map(['staffPermModal','staffPermStatus','staffPermAdd','staffPermSave','staffPermTbody'].map(id=>[id,{style:{},textContent:'',innerHTML:'',disabled:false}]));
 const calls=[],toasts=[],c=vm.createContext({PS:{school:'test-school',year:'2026-2027'},WORKER_URL_AUTH:'https://api.example',getPortalSession:()=>({role,school:'test-school',year:'2026-2027'}),document:{getElementById:id=>elements.get(id),querySelectorAll:()=>[]},authFetch:async(url,opts)=>{calls.push({url,opts});return fetcher(url,opts)},toast:(...args)=>toasts.push(args),SECTION_LIST:['s0','calendar'],SECTION_GROUPS:[],esc:s=>String(s).replaceAll('<','&lt;')});
 vm.runInContext(source,c);return {c,elements,calls,toasts,rows:()=>vm.runInContext('_staffRows',c),setRows:rows=>{c.testRows=rows;vm.runInContext('_staffRows=testRows',c)}};
}
const response=(rows,status=200)=>({ok:status===200,status,json:async()=>rows});
test('principal loads saved staff without calling the systemadmin-only principal list',async()=>{
 const x=setup(async url=>{if(url.includes('/api/principals'))throw Error('forbidden');return response([{email:'staff@example.com',name:'Saved Teacher',permissions:{s0:'view'}}]);});
 assert.equal(await x.c.openStaffPermissions(),undefined);assert.equal(x.calls.length,1);assert.match(x.calls[0].url,/school=test-school&year=2026-2027/);assert.equal(x.rows()[0].name,'Saved Teacher');assert.match(x.elements.get('staffPermTbody').innerHTML,/Saved Teacher/);assert.match(x.elements.get('staffPermStatus').textContent,/1/);
});
test('failed staff load retains visible records and reports an error instead of a false empty list',async()=>{
 const x=setup(async()=>response({error:'server'},500));x.setRows([{email:'staff@example.com',name:'Keep Me'}]);await x.c.loadStaffPermissions();assert.equal(x.rows()[0].name,'Keep Me');assert.match(x.elements.get('staffPermStatus').textContent,/לא ניתן/);assert.match(x.elements.get('staffPermTbody').innerHTML,/Keep Me/);
});
test('successful save reads back stored names and keeps the permission list open',async()=>{
 let saved=[];const x=setup(async(url,o)=>{if(o?.method==='POST'){saved.push(JSON.parse(o.body));return response({ok:true});}return response(saved);});
 await x.c.openStaffPermissions();x.setRows([{email:'staff@example.com',name:'Saved Name',roleTitle:'Teacher',permissions:{s0:'view'},_type:'staff'}]);await x.c.saveStaffPermissions();assert.equal(saved[0].name,'Saved Name');assert.equal(saved[0].school,'test-school');assert.equal(x.elements.get('staffPermModal').style.display,'block');assert.match(x.elements.get('staffPermTbody').innerHTML,/Saved Name/);assert.equal(x.calls.filter(r=>r.opts?.method==='POST').length,1);
});
test('partial save failure keeps all entered records and does not replace them with a server list',async()=>{
 const x=setup(async(url,o)=>response({},JSON.parse(o.body).email==='failed@example.com'?500:200));x.elements.get('staffPermModal').style.display='block';x.setRows([{email:'ok@example.com',name:'OK'},{email:'failed@example.com',name:'Retry'}]);await x.c.saveStaffPermissions();assert.equal(x.rows().length,2);assert.equal(x.elements.get('staffPermModal').style.display,'block');assert.match(x.elements.get('staffPermStatus').textContent,/1 לא נשמרו/);assert.equal(x.calls.length,2);
});
test('a late list response after close cannot repopulate a reopened or closed panel',async()=>{
 let resolve;const x=setup(()=>new Promise(r=>resolve=r));const pending=x.c.loadStaffPermissions();x.c.closeStaffPermissions();resolve(response([{name:'Late'}]));await pending;assert.equal(x.rows().length,0);assert.equal(x.elements.get('staffPermModal').style.display,'none');
});
test('blank email prevents a misleading saved message and no permission write occurs',async()=>{
 const x=setup(()=>{throw Error('should not write')});x.setRows([{email:'',name:'Incomplete'}]);await x.c.saveStaffPermissions();assert.equal(x.calls.length,0);assert.match(x.elements.get('staffPermStatus').textContent,/למלא אימייל/);
});
