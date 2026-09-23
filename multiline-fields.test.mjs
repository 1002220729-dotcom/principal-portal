import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const read=name=>fs.readFileSync(new URL(name,import.meta.url),'utf8');
const plan=read('tknyt.html');
const inventory=read('inventory.html');
function fn(html,name,next){return html.slice(html.indexOf(`function ${name}(`),html.indexOf(`function ${next}(`));}
const prose='שורה ראשונה\nשורה שנייה עם <script> ולא קוד\nשורה שלישית';

test('focus area save retains multiline value after replacing its input',()=>{
  const appData={};
  const div={dataset:{fid:'stable'},querySelector:s=>s==='textarea'?{value:prose}:null};
  const context=vm.createContext({appData,document:{querySelectorAll:()=>[div]}});
  vm.runInContext(fn(plan,'collectFocusAreasFromDOM','collectGoalsFromDOM'),context);
  context.collectFocusAreasFromDOM();
  assert.equal(JSON.parse(JSON.stringify(appData)).focusAreas[0].text,prose);
  assert.equal(appData.focusAreas[0].id,'stable');
});

test('inventory textarea uses its current value, preserves inner newlines and existing quantity',()=>{
  const item={id:'stable',quantity:7,notes:'old'};
  const state={categories:{test:[item]}};
  const field={tagName:'TEXTAREA',value:prose,textContent:'stale initial value',dataset:{field:'notes'},closest:()=>({dataset:{cat:'test',id:'stable'}})};
  const context=vm.createContext({STATE:state,updateSummary(){}});
  vm.runInContext(fn(inventory,'cellBlur','cycleCondition'),context);
  context.cellBlur(field);
  assert.equal(item.notes,prose);
  assert.equal(item.quantity,7);
});

test('inventory request-data persists textareas before blur using the same payload schema',()=>{
  const item={id:'stable',quantity:7,notes:'old'};
  let posted;
  const field={tagName:'TEXTAREA',value:prose,dataset:{field:'notes'},closest:()=>({dataset:{cat:'test',id:'stable'}})};
  const start=inventory.indexOf('async function saveToPortal()');
  const end=inventory.indexOf('\n}',start)+2;
  const context=vm.createContext({STATE:{school:'test',year:'2026',categories:{test:[item]}},PORTAL_ORIGIN:'http://local',
    document:{querySelectorAll:()=>[field]},window:{parent:{postMessage:p=>{posted=p;}}}});
  vm.runInContext(inventory.slice(start,end),context);
  context.saveToPortal();
  assert.equal(item.notes,prose);
  assert.equal(posted.payload.rows[0].notes, prose);
});

test('calendar CSV preserves quoted multiline prose',()=>{
  const calendar=read('calendar.html');
  const context=vm.createContext({});
  vm.runInContext(fn(calendar,'meetingCsvCell','exportMeetingsCSV'),context);
  assert.equal(context.meetingCsvCell(prose), '"'+prose+'"');
});

test('all portal documents include common multiline support; specialized controls stay typed',()=>{
  for(const name of ['index','tknyt','gantt','calendar','mtss','teachers','inventory','budget']){
    const html=read(name+'.html');
    assert.ok(html.includes('href="multiline-fields.css"'),name);
    assert.ok(html.includes('src="multiline-fields.js"'),name);
  }
  const cal=read('calendar.html');
  assert.match(cal, /<input type="date" id="meetModalDate"/);
  assert.match(cal, /<input type="time" id="meetModalTimeStart"/);
  assert.match(read('teachers.html'), /<input id="smEmail" type="email"/);
  assert.match(read('teachers.html'), /<input id="listSearch" type="search"/);
});
