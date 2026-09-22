import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('./calendar.html', import.meta.url), 'utf8');
const start = html.lastIndexOf('<script>') + '<script>'.length;
const source = html.slice(start, html.indexOf('</script>', start));
const privateMarker = 'PRIVATE-GOOGLE-EVENT-MUST-NOT-EXPORT';

function fixture(events, filters = {}) {
  const elements = new Map(Object.entries(filters).map(([id, value]) => [id, { value }]));
  const downloads = [], frames = [], timers = [], messages = [], revoked = [];
  const document = {
    getElementById: id => elements.get(id) || null,
    body: {
      textContent: privateMarker,
      innerHTML: `<section id="privateGoogleCalendar">${privateMarker}</section>`,
      appendChild(element) {
        elements.set(element.id, element);
        if (element.tagName === 'iframe') frames.push(element);
      },
    },
    createElement(tagName) {
      const listeners = new Map(), attributes = {};
      const element = { tagName, style:{}, attributes, listeners, removed:false,
        setAttribute(name, value) { attributes[name] = value; },
        addEventListener(name, callback) { listeners.set(name, callback); },
        remove() { this.removed = true; elements.delete(this.id); },
        click() { downloads.push({ href:this.href, filename:this.download }); },
      };
      if (tagName === 'iframe') {
        element.contentWindow = { listeners:new Map(), prints:0, focused:false,
          addEventListener(name, callback) { this.listeners.set(name, callback); },
          focus() { this.focused = true; }, print() { this.prints++; },
        };
      }
      return element;
    },
  };
  let capturedBlob;
  const window = { location:{origin:'https://principal-portal.pages.dev'},
    parent:{postMessage:message=>messages.push(message)},
    matchMedia:()=>({matches:false,addEventListener(){}}), addEventListener(){},
  };
  const context = vm.createContext({ window, document, Blob, Date, Intl, console,
    URL:{createObjectURL(blob){capturedBlob=blob;return 'blob:synthetic-export';},
      revokeObjectURL(url){revoked.push(url);}},
    setTimeout(callback){timers.push(callback);return timers.length;},clearTimeout(){},
  });
  vm.runInContext(source, context);
  context.testEvents = events;
  vm.runInContext('appData.meetings.events = testEvents;', context);
  return {context,document,downloads,frames,timers,messages,revoked,blob:()=>capturedBlob};
}

const meeting = (overrides={}) => ({ date:'2026-09-25',timeStart:'09:00',timeEnd:'10:00',
  title:'פגישה משותפת',type:'meeting',status:'upcoming',priority:'medium',location:'חדר צוות',
  attendees:'צוות בית הספר',agenda:'נושא ראשון\nנושא שני',summary:'',...overrides });

// Parse the resulting artifact independently, including embedded quotes/newlines.
function parseCsv(text) {
  const rows=[];let row=[],cell='',quoted=false;
  for(let i=0;i<text.length;i++) {
    const ch=text[i];
    if(ch==='"') {
      if(quoted && text[i+1]==='"') {cell+='"';i++;} else quoted=!quoted;
    } else if(!quoted && ch===',') {row.push(cell);cell='';}
    else if(!quoted && ch==='\r' && text[i+1]==='\n') {row.push(cell);rows.push(row);row=[];cell='';i++;}
    else cell+=ch;
  }
  assert.equal(quoted,false);
  row.push(cell);rows.push(row);return rows;
}

test('existing list buttons invoke working CSV and print handlers',()=>{
  const f=fixture([]);
  assert.match(html,/onclick="exportMeetingsCSV\(\)"/);
  assert.match(html,/onclick="printMeetings\(\)"/);
  assert.equal(typeof f.context.exportMeetingsCSV,'function');
  assert.equal(typeof f.context.printMeetings,'function');
});

test('CSV exports filtered shared meetings in date/time order, preserves Hebrew and excludes private DOM',async()=>{
  const events=[meeting({title:'מאוחר, "מיוחד"',timeStart:'11:00'}),meeting({title:'מוקדם'}),
    meeting({title:'אירוע שאינו בסינון',type:'event'})];
  const before=JSON.stringify(events),f=fixture(events,{meetFilterType:'meeting'});
  f.context.exportMeetingsCSV();
  assert.equal(f.downloads.length,1);assert.match(f.downloads[0].filename,/^shared-calendar-\d{4}-\d{2}-\d{2}\.csv$/);
  const bytes=new Uint8Array(await f.blob().arrayBuffer());
  assert.deepEqual([...bytes.slice(0,3)],[0xef,0xbb,0xbf]);
  assert.equal(f.blob().type,'text/csv;charset=utf-8');
  const csv=new TextDecoder().decode(bytes),rows=parseCsv(csv);
  assert.equal(rows.length,3);assert.equal(rows[0][3],'כותרת');
  assert.equal(rows[1][3],'מוקדם');assert.equal(rows[2][3],'מאוחר, "מיוחד"');
  assert.equal(rows[1][9],'נושא ראשון\nנושא שני');assert.equal(rows[1][4],'פגישה');
  assert.doesNotMatch(csv,new RegExp(privateMarker+'|אירוע שאינו בסינון'));
  assert.equal(JSON.stringify(events),before);assert.equal(f.messages.length,1);
  f.timers.forEach(callback=>callback());assert.deepEqual(f.revoked,['blob:synthetic-export']);
});

test('CSV neutralizes formula-like cells, including whitespace and all text columns',async()=>{
  const values=['=1+1','+1+1','-1+1','@SUM(A1:A2)','  =HYPERLINK("https://untrusted.example")',
    '\tvalue','\rvalue','\nvalue','\uFEFF=1'];
  for(const value of values) {
    const event=Object.fromEntries(['date','timeStart','timeEnd','title','type','status','priority','location','attendees','agenda','summary']
      .map(name=>[name,value]));
    const f=fixture([event]);f.context.exportMeetingsCSV();
    const row=parseCsv(await f.blob().text())[1];
    assert.equal(row.length,11);
    for(const cell of row)assert.equal(cell,"'"+value);
  }
});

test('print report contains only escaped shared fields, never clones private DOM and cleans up after printing',()=>{
  const attack='<img src=x onerror="alert(1)"></script><script>alert(2)</script>&';
  const event=meeting(Object.fromEntries(['date','timeStart','timeEnd','title','type','status','priority','location','attendees','agenda','summary']
    .map(name=>[name,attack])));
  const f=fixture([event]);
  f.context.testSchool=attack;vm.runInContext('_portalSchool=testSchool;_portalYear="2026-2027";',f.context);
  f.context.printMeetings();
  const frame=f.frames[0];assert.ok(frame);assert.equal(frame.contentWindow.prints,0);
  assert.match(frame.srcdoc,/<html lang="he" dir="rtl">/);
  assert.match(frame.srcdoc,/&lt;img src=x onerror=&quot;alert\(1\)&quot;&gt;/);
  assert.match(frame.srcdoc,/&lt;\/script&gt;&lt;script&gt;alert\(2\)&lt;\/script&gt;&amp;/);
  assert.doesNotMatch(frame.srcdoc,/<script|<img|PRIVATE-GOOGLE-EVENT/);
  assert.equal(frame.attributes.sandbox,'allow-same-origin allow-modals');
  frame.listeners.get('load')();assert.equal(frame.contentWindow.prints,1);assert.equal(frame.contentWindow.focused,true);
  frame.contentWindow.listeners.get('afterprint')();assert.equal(frame.removed,true);
  assert.match(f.document.body.innerHTML,new RegExp(privateMarker));assert.equal(f.messages.length,1);
});

test('print honors list filters and empty results without including hidden shared or private records',()=>{
  const f=fixture([meeting({title:'MATCH',status:'done',priority:'high',attendees:'יעל'}),
    meeting({title:'FILTERED-OUT',status:'upcoming',priority:'high'})],
    {meetFilterStatus:'done',meetFilterPriority:'high',meetSearch:'יעל'});
  f.context.printMeetings();assert.match(f.frames[0].srcdoc,/MATCH/);
  assert.doesNotMatch(f.frames[0].srcdoc,/FILTERED-OUT|PRIVATE-GOOGLE-EVENT/);
  f.document.getElementById('meetSearch').value='no matches';
  f.context.printMeetings();assert.equal(f.frames[0].removed,true);
  assert.match(f.frames[1].srcdoc,/אין פגישות להצגה/);
  assert.doesNotMatch(f.frames[1].srcdoc,/MATCH|FILTERED-OUT|PRIVATE-GOOGLE-EVENT/);
});
