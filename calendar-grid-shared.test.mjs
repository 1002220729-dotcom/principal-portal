import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import {readFileSync} from 'node:fs';

const html=readFileSync(new URL('./calendar.html',import.meta.url),'utf8');
const adapter=readFileSync(new URL('./google-calendar-shared.js',import.meta.url),'utf8');
const start=html.lastIndexOf('<script>')+8;
const script=html.slice(start,html.indexOf('</script>',start));
const manual=i=>({id:'manual_'+i,title:'כותרת ארוכה מאוד '.repeat(30)+i,date:'2026-09-16',timeStart:'10:00',timeEnd:'11:00',color:'#123456',type:'meeting',priority:'medium',status:'upcoming'});
function fixture(events=[],google){
  const elements=new Map();
  const element=id=>({id,innerHTML:'',textContent:'',hidden:false,style:{},value:'',disabled:false,
    classList:{toggle(){}},focus(){},scrollIntoView(){},querySelector(){return {focus(){}};},
    removeAttribute(name){delete this[name];}});
  for(const id of ['meetingCalGrid','meetingMonthTitle','meetingDayPanel','meetingListContainer','meetingByPeriodContainer',
    'meetingKpiGrid','meetingModal','meetModalId','meetModalTitle','meetGoogleLink','meetModalTitleInput','meetModalDate',
    'meetModalTimeStart','meetModalTimeEnd','meetModalType','meetModalPriority','meetModalStatus','meetModalLocation',
    'meetModalAttendees','meetModalColor','meetModalAgenda','meetModalSummary','meetModalDeleteBtn'])elements.set(id,element(id));
  const saveButton=element('save');const messages=[],listeners=new Map();let mobile=false;
  const document={getElementById:id=>elements.get(id)||null,querySelector:selector=>selector==='#meetingModal .btn-save'?saveButton:null,
    body:{classList:{toggle(){}}},querySelectorAll:()=>[]};
  const window={location:{origin:'https://principal-portal.pages.dev'},parent:{postMessage:m=>messages.push(m)},
    matchMedia:()=>({get matches(){return mobile;},addEventListener(){}}),addEventListener:(name,fn)=>listeners.set(name,fn)};
  const context=vm.createContext({window,document,Intl,Date,URL,TextEncoder,console,setTimeout:()=>1,clearTimeout(){},confirm:()=>true});
  vm.runInContext(adapter,context);vm.runInContext(script,context);
  context.initial={school:'test-school',year:'2026-2027',meetings:{events,googleCalendar:google,settings:{}}};
  vm.runInContext('_meetingViewYear=2026;_meetingViewMonth=8;_applyPortalData(initial)',context);
  return {context,elements,saveButton,messages,message(data){listeners.get('message')({origin:window.location.origin,data});},setMobile(){mobile=true;context.renderMeetingMonthView();}};
}
const snapshots={owner:'owner@example.edu',months:{'2026-09':{fetchedAt:'2026-09-22T10:00:00Z',events:[
  {id:'google-one',title:'פגישה מ־Google <img src=x>',start:'2026-09-16T09:00:00+03:00',end:'2026-09-16T09:30:00+03:00',allDay:false,location:'חדר צוות',link:'https://calendar.google.com/calendar/event?eid=qa'}]}}};

test('busy days keep only three compact rows and open all meetings in their own day panel',()=>{
  const f=fixture(Array.from({length:6},(_,i)=>manual(i)),snapshots);
  const grid=f.elements.get('meetingCalGrid').innerHTML;
  assert.equal((grid.match(/class="meeting-cal-event"/g)||[]).length,3);
  assert.match(grid,/\+4 פגישות נוספות/);assert.match(grid,/openMeetingDay\('2026-09-16'\)/);
  assert.match(html,/grid-template-columns:repeat\(7,minmax\(0,1fr\)\)/);
  assert.match(html,/\.meeting-cal-day\{height:142px;min-width:0;overflow:hidden/);
  f.context.openMeetingDay('2026-09-16');
  const panel=f.elements.get('meetingDayPanel');assert.equal(panel.hidden,false);
  assert.equal((panel.innerHTML.match(/class="meeting-day-entry"/g)||[]).length,7);
  assert.match(panel.innerHTML,/&lt;img src=x&gt;/);assert.doesNotMatch(panel.innerHTML,/<img/);
  f.context.navigateMeetingMonth(1);assert.equal(panel.hidden,true);
});

test('Google snapshots are visible in shared desktop/mobile/list/period/export data without duplicating native events',()=>{
  const native=[manual(1)],before=JSON.stringify(native),f=fixture(native,snapshots);
  assert.equal(f.context.allCalendarMeetings().length,2);
  assert.equal(f.context.sharedMeetingsForExport().length,2);
  f.context.renderMeetingList();assert.match(f.elements.get('meetingListContainer').innerHTML,/Google/);
  f.context.renderMeetingByPeriod();assert.match(f.elements.get('meetingByPeriodContainer').innerHTML,/Google/);
  f.setMobile();assert.match(f.elements.get('meetingCalGrid').innerHTML,/פגישה מ־Google &lt;img src=x&gt;/);
  assert.equal(JSON.stringify(native),before);
});

test('Google details remain read-only, while manually created appointments can still be edited',()=>{
  const f=fixture([manual(1)],snapshots);const imported=f.context.allCalendarMeetings().find(e=>e.isFromGoogle);
  f.context.openMeetingModal(imported.id,null);
  assert.equal(f.elements.get('meetModalTitleInput').disabled,true);assert.equal(f.saveButton.style.display,'none');
  assert.equal(f.elements.get('meetGoogleLink').hidden,false);assert.match(f.elements.get('meetGoogleLink').href,/^https:\/\/calendar.google.com/);
  const before=f.messages.length;f.context.saveMeetingModal();f.context.deleteMeeting(imported.id);assert.equal(f.messages.length,before);
  f.context.openMeetingModal('manual_1',null);assert.equal(f.elements.get('meetModalTitleInput').disabled,false);
  assert.equal(f.elements.get('meetGoogleLink').hidden,true);
});

test('applying an atomically published snapshot updates only its current scope and never triggers a whole-calendar save',()=>{
  const f=fixture([manual(1)]);const before=f.messages.length;
  const payload={school:'test-school',year:'2026-2027',month:'2026-09',owner:snapshots.owner,snapshot:snapshots.months['2026-09']};
  assert.equal(f.context.applyGoogleCalendarSnapshot({...payload,school:'another-school'}),false);
  assert.equal(f.context.applyGoogleCalendarSnapshot({...payload,month:'2026-10'}),false);
  assert.equal(f.context.applyGoogleCalendarSnapshot(payload),true);
  assert.equal(f.context.applyGoogleCalendarSnapshot({...payload,snapshot:{events:[],fetchedAt:'2026-09-21T10:00:00Z'}}),false);
  assert.equal(f.context.allCalendarMeetings().length,2);assert.equal(f.messages.length,before);
});

test('Hebrew day thirty and invalid values never render undefined',()=>{
  const f=fixture();assert.equal(f.context.hebrewDayLetters(30),'ל׳');
  assert.equal(f.context.hebrewDayLetters(NaN),'');assert.equal(f.context.hebrewDayLetters(31),'');
});

test('a delayed parent load cannot erase a newer published snapshot, but a different school never inherits it',()=>{
  const f=fixture([manual(1)],snapshots);
  f.context._applyPortalData({school:'test-school',year:'2026-2027',meetings:{events:[manual(2)],settings:{},googleCalendar:{
    owner:snapshots.owner,months:{'2026-09':{fetchedAt:'2026-09-21T10:00:00Z',events:[]}}}}});
  assert.equal(f.context.allCalendarMeetings().length,2);
  assert.equal(f.context.allCalendarMeetings()[0].id,'manual_2');
  f.context._applyPortalData({school:'another-school',year:'2026-2027',meetings:{events:[],settings:{}}});
  assert.equal(f.context.allCalendarMeetings().length,0);
});

test('school context changes require fresh matching server data before another shared sync',()=>{
  const f=fixture([manual(1)],snapshots);assert.equal(f.context.getGoogleCalendarContext().ready,true);
  f.message({type:'school-data-update',schoolName:'another-school',year:'2027-2028'});
  assert.equal(f.context.getGoogleCalendarContext().ready,false);assert.equal(f.context.allCalendarMeetings().length,0);
  f.context._applyPortalData({school:'another-school',year:'2027-2028',meetings:{events:[]}});
  assert.equal(f.context.getGoogleCalendarContext().ready,true);
});

test('a Google appointment spanning several days is counted once in calendar statistics',()=>{
  const google=JSON.parse(JSON.stringify(snapshots));Object.assign(google.months['2026-09'].events[0],{allDay:true,start:'2026-09-16',end:'2026-09-19'});
  const f=fixture([manual(1)],google);assert.equal(f.context.allCalendarMeetings().length,4);
  assert.equal(f.context.calendarMeetingCount(f.context.allCalendarMeetings()),2);
});
