import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { readFileSync } from 'node:fs';

const html = readFileSync(new URL('./calendar.html', import.meta.url), 'utf8');
const start = html.lastIndexOf('<script>') + 8;
const script = html.slice(start, html.indexOf('</script>', start));
const adapter = readFileSync(new URL('./google-calendar-shared.js', import.meta.url), 'utf8');
const plain = value => JSON.parse(JSON.stringify(value));

function fixture(initialEvents = []) {
  const elements = new Map(Array.from(html.matchAll(/id="([^"]+)"/g), match => [match[1], {
    style: {}, value: '', checked: false, disabled: false, hidden: false, textContent: '', innerHTML: '',
    classList: { toggle() {} }, focus() {}, removeAttribute(name) { delete this[name]; }
  }]));
  const days = Array.from({ length: 7 }, (_, day) => ({ value: String(day), checked: false, disabled: false }));
  const save = { style: {}, textContent: '' }, messages = [], confirmations = [];
  const document = {
    getElementById: id => elements.get(id) || null,
    querySelector: selector => selector === '#meetingModal .btn-save' ? save : null,
    querySelectorAll: selector => selector === '#meetRecurrenceDays input' ? days :
      selector === '#meetRecurrenceDays input:checked' ? days.filter(day => day.checked) : [],
    body: { classList: { toggle() {} } }
  };
  const window = { location: { origin: 'https://example.test' }, parent: { postMessage: message => messages.push(plain(message)) },
    addEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {} }) };
  const context = vm.createContext({ window, document, Intl, Date, URL, console, setTimeout: () => 1, clearTimeout() {},
    confirm: text => { confirmations.push(text); return true; } });
  vm.runInContext(adapter, context); vm.runInContext(script, context);
  context.initial = { school: 'synthetic-school', year: '2026-2027', meetings: { events: plain(initialEvents), settings: {} } };
  vm.runInContext('_applyPortalData(initial)', context);
  const set = (id, value) => { elements.get(id).value = value; };
  return { context, elements, days, save, messages, confirmations, set,
    events: () => plain(vm.runInContext('appData.meetings.events', context)),
    draft() {
      context.openMeetingModal(null, '2026-09-01');
      set('meetModalTitleInput', 'ישיבת הנהלה'); set('meetModalTimeStart', '09:00'); set('meetModalTimeEnd', '10:00');
      set('meetModalRepeatUntil', '2027-06-30'); elements.get('meetModalRepeat').checked = true;
      days.forEach(day => { day.checked = day.value === '2'; });
    }
  };
}

test('the requested school-year schedule includes 44 Tuesdays with inclusive bounds', () => {
  const f = fixture(); const dates = plain(f.context.recurringMeetingDates('2026-09-01', '2027-06-30', [2]));
  assert.equal(dates.length, 44); assert.equal(dates[0], '2026-09-01'); assert.equal(dates.at(-1), '2027-06-29');
  assert.ok(dates.every(date => new Date(date + 'T00:00:00Z').getUTCDay() === 2));
  assert.deepEqual(plain(f.context.recurringMeetingDates('2026-09-01', '2026-09-01', [2])), ['2026-09-01']);
});

test('multiple weekdays, leap days and DST boundaries use calendar days without duplicate dates', () => {
  const f = fixture();
  assert.deepEqual(plain(f.context.recurringMeetingDates('2026-10-23', '2026-10-27', [5, 0, 2, 2])),
    ['2026-10-23', '2026-10-25', '2026-10-27']);
  assert.deepEqual(plain(f.context.recurringMeetingDates('2028-02-28', '2028-03-01', [1, 2, 3])),
    ['2028-02-28', '2028-02-29', '2028-03-01']);
});

test('invalid, inverted, empty and excessive schedules are rejected before any calendar change', () => {
  const f = fixture();
  for (const args of [ ['2026-02-30', '2026-03-10', [2]], ['', '2026-09-01', [2]],
    ['2026-09-02', '2026-09-01', [2]], ['2026-09-01', '2026-09-10', []],
    ['2026-09-01', '2026-09-10', [7]], ['2026-09-01', '2026-09-01', [1]],
    ['2026-09-01', '2035-09-01', [2]], ['2026-09-01', '2029-09-01', [0, 1, 2, 3, 4, 5, 6]] ]) {
    assert.throws(() => f.context.recurringMeetingDates(...args));
  }
  f.draft(); f.set('meetModalRepeatUntil', '2026-08-31'); f.context.saveMeetingModal();
  assert.deepEqual(f.events(), []); assert.equal(f.messages.filter(m => m.type === 'save-request').length, 0);
  assert.equal(f.elements.get('meetingModal').style.display, 'flex');
});

test('creation saves independent occurrences in one payload, preserving existing meetings and hours', () => {
  const existing = { id: 'existing', title: 'פגישה קיימת', date: '2026-09-01', timeStart: '09:00', isFromGantt: true, linkedPeriodId: 'period' };
  const f = fixture([existing]); f.draft(); f.context.updateMeetingRecurrencePreview();
  assert.match(f.elements.get('meetRecurrencePreview').textContent, /44 פגישות/);
  f.context.saveMeetingModal(); const events = f.events(), created = events.slice(1);
  assert.equal(created.length, 44); assert.equal(new Set(events.map(event => event.id)).size, 45);
  assert.deepEqual(events[0], existing);
  assert.ok(created.every(event => event.timeStart === '09:00' && event.timeEnd === '10:00' && !event.isFromGantt));
  assert.equal(new Set(created.map(event => event.recurrence.seriesId)).size, 1);
  assert.equal(f.messages.filter(m => m.type === 'save-request').length, 1);
  assert.deepEqual(f.messages.at(-1).payload.meetings.events, events);
});

test('editing and deleting a holiday occurrence affects only that occurrence and remains deleted after reload', () => {
  const f = fixture(); f.draft(); f.context.saveMeetingModal(); const original = f.events();
  const holiday = original.find(event => event.date === '2026-12-08');
  f.context.openMeetingModal(holiday.id); assert.equal(f.elements.get('meetRecurrenceCreateControls').hidden, true);
  assert.equal(f.elements.get('meetRecurrenceOccurrence').hidden, false);
  f.set('meetModalLocation', 'חדר חדש'); f.context.saveMeetingModal();
  assert.deepEqual(f.events().filter(event => event.id !== holiday.id), original.filter(event => event.id !== holiday.id));
  assert.deepEqual(f.events().find(event => event.id === holiday.id).recurrence, holiday.recurrence);
  f.context.deleteMeeting(holiday.id); assert.match(f.confirmations.at(-1), /רק פגישה זו/);
  const saved = f.messages.at(-1).payload; assert.equal(saved.meetings.events.length, 43);
  f.context.reloaded = plain(saved); vm.runInContext('_applyPortalData(reloaded)', f.context);
  f.context.navigateMeetingMonth(1); f.context.navigateMeetingMonth(-1);
  assert.equal(f.events().length, 43); assert.ok(!f.events().some(event => event.date === holiday.date));
  assert.equal(f.context.sharedMeetingsForExport().length, 43);
});

test('recurring creation requires valid hours and is blocked if edit permission is withdrawn', () => {
  const f = fixture();
  for (const [start, end] of [['', '10:00'], ['09:00', ''], ['10:00', '09:00'], ['09:00', '09:00']]) {
    f.draft(); f.set('meetModalTimeStart', start); f.set('meetModalTimeEnd', end); f.context.saveMeetingModal();
    assert.deepEqual(f.events(), []);
  }
  f.draft(); f.context._applyReadOnly(true); f.context.saveMeetingModal();
  assert.deepEqual(f.events(), []); assert.ok(f.days.every(day => day.disabled));
  assert.equal(f.elements.get('meetRecurrenceCreateControls').hidden, true);
  assert.equal(f.messages.filter(m => m.type === 'save-request').length, 0);
});

test('a pending school load cannot create or submit a partial series', () => {
  const f = fixture(); f.draft(); vm.runInContext('_dataLoadedFromServer=false', f.context);
  f.context.saveMeetingModal(); assert.deepEqual(f.events(), []);
  assert.equal(f.messages.filter(m => m.type === 'save-request').length, 0);
  assert.match(f.elements.get('_meetingsToast').textContent, /עדיין בטעינה/);
});

test('single appointments and duplicate copies remain independent of the series', () => {
  const f = fixture(); f.draft(); f.elements.get('meetModalRepeat').checked = false; f.context.saveMeetingModal();
  assert.equal(f.events().length, 1); assert.equal(f.events()[0].recurrence, undefined);
  f.draft(); f.context.saveMeetingModal(); const occurrence = f.events()[1];
  f.context.duplicateMeeting(occurrence.id); const copy = f.events().at(-1);
  assert.equal(copy.date, occurrence.date); assert.equal(copy.recurrence, undefined); assert.notEqual(copy.id, occurrence.id);
});
