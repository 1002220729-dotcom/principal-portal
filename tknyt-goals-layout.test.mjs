import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';

const html = fs.readFileSync(new URL('./tknyt.html', import.meta.url), 'utf8');
function source(name, next) {
  return html.slice(html.indexOf(`function ${name}(`), html.indexOf(`function ${next}(`));
}

test('all five goal text fields are multiline; values are never interpolated as HTML', () => {
  const fields = Object.fromEntries(['title','domain','metric','baseline','target'].map(k => [`.g_${k}`, {value:''}]));
  const row = {dataset:{}, innerHTML:'', querySelector: key => fields[key]};
  let appended;
  const context = vm.createContext({document:{createElement:()=>row, getElementById:()=>({appendChild:r=>{appended=r;}})},
    newId:()=> 'new', requestAnimationFrame:()=>{}, refreshGoalTextLayout:()=>{}});
  vm.runInContext(source('appendGoalRow','addGoalRow'), context);
  const value = 'שורה ראשונה\nשורה שנייה </textarea><script>bad()</script> & "';
  context.appendGoalRow({id:'stable', title:value, domain:value, metric:value, baseline:value, target:value, status:'todo'},0);
  assert.equal(appended.dataset.gid, 'stable');
  for (const [selector, field] of Object.entries(fields)) {
    assert.equal(field.value, value);
    assert.match(row.innerHTML, new RegExp(`<textarea rows="3" class="${selector.slice(1)}"`));
  }
  assert.ok(!row.innerHTML.includes('<script>bad()'));
});

test('collecting and serializing goals preserves newlines, id and status', () => {
  const values = {g_title:'יעד\nשני',g_domain:'תחום',g_metric:'מדד\nשני',g_baseline:'נוכחי',g_target:'יעד\nשנה',g_status:'done'};
  const row = {dataset:{gid:'stable'},querySelector:s=>({value:values[s.slice(1)]})};
  const appData = {};
  const context = vm.createContext({appData, document:{querySelectorAll:()=>[row]}});
  vm.runInContext(source('collectGoalsFromDOM','collectArenasFromDOM'),context);
  context.collectGoalsFromDOM();
  const saved = JSON.parse(JSON.stringify(appData.strategicGoals[0]));
  assert.equal(saved.id,'stable');
  assert.equal(saved.status,'done');
  for (const key of ['title','domain','metric','baseline','target']) assert.equal(saved[key],values[`g_${key}`]);
});

test('automatic height fits text but preserves manually saved dimensions and skips hidden fields', () => {
  const appData = {fieldSizes:{}};
  const context = vm.createContext({appData,getResizableFieldKey:()=> 'key',normalizeResizableFieldSize:s=>s});
  vm.runInContext(source('fitGoalTextField','refreshGoalTextLayout'),context);
  const field = {isConnected:true,getBoundingClientRect:()=>({width:150}),scrollHeight:210,style:{}};
  context.fitGoalTextField(field);
  assert.equal(field.style.height,'212px');
  appData.fieldSizes.key={width:1500,height:140};
  field.style.height='140px';
  context.fitGoalTextField(field);
  assert.equal(field.style.height,'140px');
  field.getBoundingClientRect=()=>({width:0});
  appData.fieldSizes={};
  context.fitGoalTextField(field);
  assert.equal(field.style.height,'140px');
});

test('scoped fixed layout constrains old oversized widths without changing other tables', () => {
  assert.match(html, /#goalsTable \{ table-layout: fixed; width: 100%; min-width: 0; \}/);
  assert.match(html, /#goalsTable textarea, #goalsTable select \{\s*width: 100% !important; min-width: 0 !important; max-width: 100% !important;/);
  assert.match(html, /#goalsTable textarea \{[\s\S]*?white-space: pre-wrap;[\s\S]*?resize: vertical !important;/);
  assert.match(html, /max-width: 760px[\s\S]*?#goalsTable td\[aria-label\]::before/);
  assert.doesNotMatch(source('appendGoalRow','addGoalRow'), /<td data-/, 'cell labels must not change the existing row-based resize keys');
  assert.match(html, /if \(id === 's2'\) requestAnimationFrame\(refreshGoalTextLayout\)/);
});
