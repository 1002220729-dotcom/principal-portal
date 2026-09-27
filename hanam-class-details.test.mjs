import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
const html=fs.readFileSync(new URL('./tknyt.html',import.meta.url),'utf8');
const source=html.slice(html.indexOf('function hanamClassCount('),html.indexOf('function collectHanamClassDetails('));
function helpers(){const c=vm.createContext({});vm.runInContext(source,c);return c;}
test('legacy totals are preserved with blank per-class rows, without inventing a distribution',()=>{
 const c=helpers(), rows=c.resizeHanamClassDetails(undefined,2);
 assert.equal(rows.length,2);assert.equal(rows[0].students,'');
 assert.equal(c.summarizeHanamClasses(rows,2,'18',7).students,18);
 assert.equal(c.summarizeHanamClasses(rows,2,'18',7).complete,false);
 rows[0].students='8';assert.equal(c.summarizeHanamClasses(rows,2,'18',7).students,18);
 rows[1].students='10';assert.equal(c.summarizeHanamClasses(rows,2,'18',7).complete,true);
});
test('complete details sum exactly and assess each class using the existing threshold',()=>{
 const c=helpers(),r=c.summarizeHanamClasses([{students:'6'},{students:'12'}],2,99,7);
 assert.equal(r.students,18);assert.equal(r.standardClasses,1);
 assert.equal(c.summarizeHanamClasses([{students:'5'},{students:'4'}],2,0,5).standardClasses,1);
 assert.equal(c.summarizeHanamClasses([{students:'0'}],1,18,7).students,0);
});
test('decrease, save, reload and increase retain surplus class names and counts',()=>{
 const c=helpers(),original=[{name:'א1',students:'8'},{name:'ב2',students:'10'}];
 let rows=c.resizeHanamClassDetails(original,1);
 assert.equal(c.summarizeHanamClasses(rows,1,18,7).students,8);
 rows=c.resizeHanamClassDetails(JSON.parse(JSON.stringify(rows)),2);
 assert.equal(rows[1].name,'ב2');assert.equal(rows[1].students,'10');
 assert.equal(c.summarizeHanamClasses(rows,2,8,7).students,18);
 assert.equal(c.resizeHanamClassDetails(rows,3)[2].students,'');
});
test('invalid or incomplete pupil counts do not silently replace the existing total',()=>{
 const c=helpers();for(const students of ['',' ','-1','2.5','abc']){
  const r=c.summarizeHanamClasses([{students}],1,18,7);assert.equal(r.complete,false);assert.equal(r.students,18);
 }
 assert.equal(c.hanamClassCount(-3),0);assert.equal(c.hanamClassCount('2'),2);
});
test('DOM collection retains hidden surplus rows and isolates categories',()=>{
 const c=helpers();c.appData={hanam:{ll:{classDetails:[{name:'old',students:'1'},{name:'keep',students:'10'}]},tik:{classDetails:[{name:'other',students:'5'}]}}};
 c.document={querySelectorAll:()=>[{dataset:{index:'0'},querySelector:s=>({value:s==='.hc-name'?'updated':'8'})}]};
 vm.runInContext(html.slice(html.indexOf('function collectHanamClassDetails('),html.indexOf('function renderHanamClassDetails(')),c);
 c.collectHanamClassDetails('ll');assert.equal(c.appData.hanam.ll.classDetails[0].students,'8');assert.equal(c.appData.hanam.ll.classDetails[1].name,'keep');assert.equal(c.appData.hanam.tik.classDetails[0].name,'other');
});
