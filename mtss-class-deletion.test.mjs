import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';

const html = fs.readFileSync(new URL('mtss.html', import.meta.url), 'utf8');
const helpers = html.slice(html.indexOf('        const DEFAULT_POPULATION_GRADES'), html.indexOf('        // End population class helpers.'));
const context = vm.createContext({});
vm.runInContext(helpers + '\nthis.api = {populationGradesFromData, deletePopulationGrade, deletePopulationClass};', context);
const plain = value => JSON.parse(JSON.stringify(value));
const { populationGradesFromData, deletePopulationGrade, deletePopulationClass } = context.api;
const fixture = () => ({
  classes: ['א', 'ב', 'י', 'יא'],
  classStructure: { 'א': ['1', '10'], 'ב': ['1'], 'י': ['1'], 'יא': ['1'] },
  populationsData: { 'א-gifted': ['grade'], 'א1-gifted': ['one'], 'א10-gifted': ['ten'], 'ב1-gifted': ['other'], 'י1-gifted': ['yod'], 'יא1-gifted': ['eleven'] },
  studentNotes: { 'א-gifted-grade': 'grade note', 'א1-gifted-one': 'one note', 'א10-gifted-ten': 'ten note', 'ב1-gifted-other': 'other note', 'י1-gifted-yod': 'yod note', 'יא1-gifted-eleven': 'eleven note' },
  items: { learning: [{ id: 'untouched' }] }
});

test('deleting a grade removes its row, subclasses, students and notes without changing other arenas', () => {
  const before = fixture(), original = plain(before), next = deletePopulationGrade(before, 'א');
  assert.deepEqual(plain(next.classes), ['ב', 'י', 'יא']);
  assert.equal(next.classStructure['א'], undefined);
  for (const key of ['א-gifted', 'א1-gifted', 'א10-gifted']) assert.equal(next.populationsData[key], undefined);
  assert.ok(Object.keys(next.studentNotes).every(key => !key.startsWith('א-') && !key.startsWith('א1-') && !key.startsWith('א10-')));
  assert.deepEqual(plain(next.populationsData['ב1-gifted']), ['other']);
  assert.equal(next.studentNotes['ב1-gifted-other'], 'other note');
  assert.equal(next.items, before.items);
  assert.deepEqual(before, original, 'input remains unchanged');
});

test('deleting grade י preserves grade יא and its students and notes', () => {
  const next = deletePopulationGrade(fixture(), 'י');
  assert.deepEqual(plain(next.classes), ['א', 'ב', 'יא']);
  assert.equal(next.populationsData['י1-gifted'], undefined);
  assert.deepEqual(plain(next.populationsData['יא1-gifted']), ['eleven']);
  assert.equal(next.studentNotes['יא1-gifted-eleven'], 'eleven note');
});

test('deleting class 1 preserves class 10 and grade-level students', () => {
  const before = fixture(), original = plain(before), next = deletePopulationClass(before, 'א', '1');
  assert.deepEqual(plain(next.classStructure['א']), ['10']);
  assert.equal(next.populationsData['א1-gifted'], undefined);
  assert.equal(next.studentNotes['א1-gifted-one'], undefined);
  assert.deepEqual(plain(next.populationsData['א10-gifted']), ['ten']);
  assert.equal(next.studentNotes['א10-gifted-ten'], 'ten note');
  assert.deepEqual(plain(next.populationsData['א-gifted']), ['grade']);
  assert.deepEqual(before, original);
});

test('legacy data loads all twelve grades, but explicit empty or partial lists survive backup round trips', () => {
  assert.equal(populationGradesFromData({classStructure: {'א': []}}).length, 12);
  for (const classes of [[], ['ב', 'יא']]) {
    assert.deepEqual(plain(populationGradesFromData(JSON.parse(JSON.stringify({classes})))), classes);
  }
  assert.deepEqual(plain(populationGradesFromData({classes: ['יא', 'ב', 'ב', 'unknown']})), ['ב', 'יא']);
});

test('deleting the last grade remains empty on reload; restoring a grade does not revive students', () => {
  let state = {...fixture(), classes: ['א']};
  state = deletePopulationGrade(state, 'א');
  assert.deepEqual(plain(populationGradesFromData(plain(state))), []);
  state.classes = populationGradesFromData({classes: [...state.classes, 'א']});
  state.classStructure['א'] = [];
  assert.deepEqual(plain(state.classes), ['א']);
  assert.deepEqual(plain(state.classStructure['א']), []);
  assert.equal(state.populationsData['א1-gifted'], undefined);
});

function componentFunction(name, next) {
  const start = html.indexOf('            const ' + name + ' =');
  const end = html.indexOf('            const ' + next + ' =', start);
  assert.ok(start >= 0 && end > start);
  return html.slice(start, end);
}

test('actual save snapshot includes the active grade list for local and portal persistence', () => {
  const state = {...fixture(), schoolName: 'synthetic'};
  state.classes = ['ב', 'יא'];
  const ctx = vm.createContext(state);
  vm.runInContext(componentFunction('getCurrentState', 'applyLoadedData') + '\nthis.snapshot = getCurrentState();', ctx);
  const saved = plain(ctx.snapshot);
  assert.deepEqual(saved.classes, ['ב', 'יא']);
  assert.deepEqual(plain(populationGradesFromData(saved)), ['ב', 'יא']);
});

test('actual local reload applies saved classes, including an empty list', () => {
  for (const classes of [[], ['יא']]) {
    let loaded;
    const ctx = vm.createContext({localStorage: {getItem: () => JSON.stringify({...fixture(), classes})},
      loadPopulationGrades: data => {loaded = plain(populationGradesFromData(data));},
      setSchoolName(){}, setItems(){}, setPopulationsData(){}, setStudentNotes(){}, setClassStructure(){},
      useEffect(){}, window:{addEventListener(){}}, console});
    const code = componentFunction('loadFromLocalStorage', 'handleLoadData');
    // Only the local loader, before its surrounding React effects.
    vm.runInContext(code.slice(0, code.indexOf('            // Load data on mount')) + '\nloadFromLocalStorage();', ctx);
    assert.deepEqual(loaded, classes);
  }
});

test('actual grade/class delete handlers do not confirm or change state for view-only users', () => {
  let confirmations = 0, writes = 0;
  const ctx = vm.createContext({...fixture(), blockIfReadOnly: () => true, confirm: () => {confirmations++; return true;},
    setClasses(){writes++;}, setClassStructure(){writes++;}, setPopulationsData(){writes++;}, setStudentNotes(){writes++;},
    setExpandedGrades(){writes++;}, setShowAddClassDialog(){writes++;}, setShowEditNoteDialog(){writes++;}});
  vm.runInContext(componentFunction('removePopulationGrade', 'getTotalForClass') + '\nremovePopulationGrade("א"); removeClassFromGrade("א", "1");', ctx);
  assert.equal(confirmations, 0);
  assert.equal(writes, 0);
});

test('cancelled grade/class deletion makes no changes', () => {
  let writes = 0;
  const ctx = vm.createContext({...fixture(), blockIfReadOnly: () => false, confirm: () => false,
    setClasses(){writes++;}, setClassStructure(){writes++;}, setPopulationsData(){writes++;}, setStudentNotes(){writes++;},
    setExpandedGrades(){writes++;}, setShowAddClassDialog(){writes++;}, setShowEditNoteDialog(){writes++;}});
  vm.runInContext(componentFunction('removePopulationGrade', 'getTotalForClass') + '\nremovePopulationGrade("א"); removeClassFromGrade("א", "1");', ctx);
  assert.equal(writes, 0);
});

test('the loaded snapshot is skipped once; the next edit saves even during the portal loading window', () => {
  let writes = 0, effect;
  const ctx = vm.createContext({...fixture(), schoolName:'synthetic', skipNextAutoSaveRef:{current:true},
    window:{__mtss_loading_from_portal:true}, useEffect: callback => {effect=callback;}, saveToLocalStorage(){writes++;}});
  const start = html.indexOf('            // Auto-save whenever data changes');
  const end = html.indexOf('            // Chart instances storage', start);
  vm.runInContext(html.slice(start,end), ctx);
  effect();
  assert.equal(writes, 0, 'loading does not overwrite the saved data');
  effect();
  assert.equal(writes, 1, 'an immediate user edit is saved');
});

test('actual JSON export includes the current partial grade list', () => {
  let exported;
  const ctx = vm.createContext({...fixture(), classes:['ב','יא'], schoolName:'synthetic',
    Blob: class {constructor(parts){exported=JSON.parse(parts[0]);}},
    document:{createElement:()=>({click(){}})}, URL:{createObjectURL:()=> 'blob:synthetic',revokeObjectURL(){}}, setTimeout(){}});
  vm.runInContext(componentFunction('exportAsJSON','importFromJSON') + '\nexportAsJSON();', ctx);
  assert.deepEqual(exported.classes, ['ב','יא']);
});

test('actual JSON import restores an empty grade list instead of defaulting to twelve grades', () => {
  let loaded;
  const ctx = vm.createContext({anyArenaReadOnly:()=>false, alert(){},console,
    FileReader:class {readAsText(file){this.onload({target:{result:JSON.stringify(file.data)}});}},
    loadPopulationGrades:data=>{loaded=plain(populationGradesFromData(data));},
    setItems(){},setPopulationsData(){},setStudentNotes(){},setClassStructure(){},setSchoolName(){},setShowImportDialog(){}});
  vm.runInContext(componentFunction('importFromJSON','handleMultipleFiles') + '\nimportFromJSON({target:{files:[{data:{classes:[],items:{}}}]}});', ctx);
  assert.deepEqual(loaded, []);
});

test('actual portal load replaces the previous grade list and suppresses its save echo', () => {
  let loaded;
  const ctx = vm.createContext({skipNextAutoSaveRef:{current:false},
    loadPopulationGrades:data=>{loaded=plain(populationGradesFromData(data));},
    setItems(){},setPopulationsData(){},setStudentNotes(){},setClassStructure(){},setSchoolName(){}});
  vm.runInContext(componentFunction('handleLoadData','handleReset') + '\nhandleLoadData({detail:{classes:["יא"]}});', ctx);
  assert.deepEqual(loaded,['יא']);
  assert.equal(ctx.skipNextAutoSaveRef.current,true);
});

test('actual merge collects only active grades from modern backups and supports legacy backups', () => {
  let preview;
  const ctx = vm.createContext({populationGradesFromData, setMergePreview:value=>{preview=value;}});
  vm.runInContext(componentFunction('generateMergePreview','executeMerge') + '\nthis.merge=generateMergePreview;', ctx);
  ctx.merge([{fileName:'one.json',data:{classes:['ב']}},{fileName:'empty.json',data:{classes:[]}},{fileName:'two.json',data:{classes:['יא']}}]);
  assert.deepEqual(plain(preview.classes),['ב','יא']);
  ctx.merge([{fileName:'legacy.json',data:{classStructure:{'א':[]}}}]);
  assert.equal(preview.classes.length,12);
});
