import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html=fs.readFileSync(new URL('./index.html',import.meta.url),'utf8');
const source=html.slice(html.indexOf('let _staffRows = [];'),html.indexOf('// SM TAB SWITCHING'));
function setup() {
  const elements=new Map(['staffPermModal','staffPermStatus','staffPermAdd','staffPermSave','staffPermTbody'].map(id=>[id,{style:{},textContent:'',innerHTML:'',disabled:false}]));
  let editor=[];
  const saved=[];
  const c=vm.createContext({PS:{school:'test-school',year:'2026-2027'},WORKER_URL_AUTH:'https://api.example',getPortalSession:()=>({role:'principal'}),
    document:{getElementById:id=>elements.get(id),querySelectorAll:()=>editor},
    authFetch:async(url,options)=>{if(options?.method==='POST')saved.push(JSON.parse(options.body));return {ok:true,json:async()=>saved};},
    toast:()=>{},SECTION_LIST:['s0','calendar'],SECTION_GROUPS:[],esc:s=>String(s).replaceAll('&','&amp;').replaceAll('<','&lt;').replaceAll('"','&quot;')});
  vm.runInContext(source,c);
  const rows=[{email:'first@example.com',name:'First',permissions:{calendar:'edit'}},{email:'second@example.com',name:'Second',permissions:{s0:'view'}}];
  c.records=rows;vm.runInContext('_staffRows=records',c);
  return {c,rows,saved,elements,setEditor:(index,values)=>{editor=[{dataset:{staffIndex:String(index)},querySelectorAll:()=>values.map(value=>({value}))}];}};
}

test('saving an expanded second staff member preserves the first identity and its permissions',async()=>{
  const x=setup();x.c.toggleStaffPermissionEditor(1);
  x.setEditor(1,['second@example.com','Second Updated','Teacher']);
  await x.c.saveStaffPermissions();
  assert.equal(x.saved[0].email,'first@example.com');assert.equal(x.saved[0].name,'First');assert.equal(x.saved[0].permissions.calendar,'edit');
  assert.equal(x.saved[1].email,'second@example.com');assert.equal(x.saved[1].name,'Second Updated');assert.equal(x.saved[1].roleTitle,'Teacher');assert.equal(x.saved[1].permissions.s0,'view');
  assert.equal(vm.runInContext('_staffPermOpenRow',x.c),null);
});

test('switching to another staff editor preserves unblurred identity fields and permission edits',()=>{
  const x=setup();x.c.toggleStaffPermissionEditor(1);x.setEditor(1,['second@example.com','Second Draft','Coordinator']);
  const button={closest:()=>({querySelectorAll:()=>[]}),classList:{add:()=>{}}};
  x.c.setPermission(1,'calendar','view',button);x.c.toggleStaffPermissionEditor(0);
  assert.equal(x.rows[1].name,'Second Draft');assert.equal(x.rows[1].roleTitle,'Coordinator');assert.equal(x.rows[1].permissions.calendar,'view');assert.equal(x.rows[0].permissions.calendar,'edit');
  assert.equal(vm.runInContext('_staffPermOpenRow',x.c),0);
});

test('adding a new staff member keeps the existing draft and starts with no access',()=>{
  const x=setup();x.c.toggleStaffPermissionEditor(1);x.setEditor(1,['second@example.com','Draft Name','Teacher']);x.c.addStaffRow();
  assert.equal(x.rows[1].name,'Draft Name');assert.equal(x.rows.length,3);assert.equal(x.rows[2].email,'');assert.equal(x.rows[2].permissions.s0,'none');assert.equal(x.rows[2].permissions.calendar,'none');
  assert.equal(vm.runInContext('_staffPermOpenRow',x.c),2);
});
