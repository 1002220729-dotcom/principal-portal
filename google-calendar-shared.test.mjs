import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

const source = readFileSync(new URL('./google-calendar-shared.js', import.meta.url), 'utf8');
const context = vm.createContext({ Intl, Date, URL, window: {} });
vm.runInContext(source, context);
const merge = (...args) => context.GoogleCalendarShared.mergeMeetings(...args);
const owner = 'owner@example.test';
const now = '2026-09-01T00:00:00Z';
const event = (overrides = {}) => ({ id: 'event-1', title: 'ישיבת צוות', location: 'חדר מורים',
  start: '2026-09-22T09:00:00+03:00', end: '2026-09-22T10:00:00+03:00', allDay: false,
  link: 'https://calendar.google.com/calendar/event?eid=test', ...overrides });
const calendar = (events, month = '2026-09', overrides = {}) => ({ owner,
  months: { [month]: { events, fetchedAt: '2026-09-01T00:00:00Z' } }, ...overrides });
const plain = value => JSON.parse(JSON.stringify(value));

test('exposes the same pure API to browser window and global VM, preserving manual values and references', () => {
  assert.equal(context.window.GoogleCalendarShared, context.GoogleCalendarShared);
  const manual = Object.freeze({ id: 'manual', date: '2026-09-23', title: 'עריכה מקומית', nested: { keep: true } });
  const input = Object.freeze([manual]);
  const data = calendar([event()]);
  const before = JSON.stringify(data);
  const merged = merge(input, data, now);
  assert.equal(merged.length, 2);
  assert.notEqual(merged, input);
  assert.equal(merged[0], manual);
  assert.equal(JSON.stringify(data), before);
  assert.equal(merged[1].isFromGoogle, true);
  assert.equal(merged[1].readOnly, true);
  assert.equal(merged[1].timeStart, '09:00');
  assert.equal(merged[1].timeEnd, '10:00');
  assert.equal(merged[1].type, 'meeting');
  assert.equal(merged[1].status, 'upcoming');
});

test('UTC overnight events split at Jerusalem midnight, retaining the true per-day local times', () => {
  const rows = merge([], calendar([event({ start: '2026-09-22T20:30:00Z', end: '2026-09-22T22:15:00Z' })]), now);
  assert.deepEqual(plain(rows.map(row => [row.date, row.timeStart, row.timeEnd])), [
    ['2026-09-22', '23:30', '00:00'], ['2026-09-23', '00:00', '01:15']
  ]);
  assert.match(rows[0].agenda, /חצות בסוף היום/);
  assert.match(rows[1].agenda, /2026-09-22 23:30 — 2026-09-23 01:15/);
  assert.notEqual(rows[0].id, rows[1].id);
});

test('exclusive midnight does not add the following day, including Jerusalem month boundaries', () => {
  const rows = merge([], calendar([
    event({ id: 'midnight', start: '2026-09-22T20:00:00Z', end: '2026-09-22T21:00:00Z' }),
    event({ id: 'month-end', start: '2026-09-30T20:00:00Z', end: '2026-09-30T21:00:00Z' }),
    event({ id: 'next-month', start: '2026-09-30T21:00:00Z', end: '2026-09-30T22:00:00Z' })
  ]), now);
  assert.deepEqual(plain(rows.map(row => row.date)), ['2026-09-22', '2026-09-30']);
  assert.ok(rows.every(row => row.timeEnd === '00:00'));
});

test('all-day spans use an exclusive end and clip each snapshot to its own actual month', () => {
  const span = event({ id: 'all-day', start: '2026-09-29', end: '2026-10-03', allDay: true });
  const stale = event({ id: 'old-buffer', start: '2026-10-01', end: '2026-10-02', allDay: true });
  const data = { owner, months: {
    '2026-09': { events: [span, stale] },
    '2026-10': { events: [span] }
  } };
  const rows = merge([], data, now);
  assert.deepEqual(plain(rows.map(row => row.date)), ['2026-09-29', '2026-09-30', '2026-10-01', '2026-10-02']);
  assert.ok(rows.every(row => !row.timeStart && !row.timeEnd && row.agenda.includes('כל היום')));
  assert.ok(rows.every(row => row.googleEventId !== 'old-buffer'));
  assert.match(rows[0].agenda, /2026-09-29 — 2026-10-02 \(כולל\)/);
  data.months['2026-10'] = { events: [] };
  assert.deepEqual(plain(merge([], data, now).map(row => row.date)), ['2026-09-29', '2026-09-30']);
});

test('DST changes use Jerusalem wall-clock time instead of an assumed fixed UTC offset', () => {
  const autumn = merge([], calendar([event({ start: '2026-10-24T20:30:00Z', end: '2026-10-25T01:30:00Z' })], '2026-10'), now);
  assert.deepEqual(plain(autumn.map(row => [row.date, row.timeStart, row.timeEnd])), [
    ['2026-10-24', '23:30', '00:00'], ['2026-10-25', '00:00', '03:30']
  ]);
  const spring = merge([], calendar([event({ start: '2026-03-26T23:30:00Z', end: '2026-03-27T01:30:00Z' })], '2026-03'), now);
  assert.deepEqual(plain(spring.map(row => [row.date, row.timeStart, row.timeEnd])), [['2026-03-27', '01:30', '04:30']]);
});

test('deduplicates same event/day and remains stable across repeated rendering and already-merged input', () => {
  const one = event();
  const data = calendar([one, { ...one }, event({ id: 'other' })]);
  const manual = [{ id: 'manual', title: 'מקורי' }];
  const first = merge(manual, data, now), second = merge(manual, data, now);
  assert.equal(first.length, 3);
  assert.deepEqual(plain(first), plain(second));
  assert.deepEqual(plain(merge(first, data, now)), plain(first));
  assert.equal(manual.length, 1);
});

test('safe stable IDs use full SHA-256 of owner, arbitrary Unicode event ID and day', () => {
  for (const id of ['short', 'a'.repeat(4096), 'עברית/😀?"<script>'.repeat(40), '\ud800']) {
    const row = merge([], calendar([event({ id })]), now)[0];
    const digest = createHash('sha256').update(JSON.stringify([owner, id, '2026-09-22'])).digest('hex');
    assert.equal(row.id, `gcal_${digest}_20260922`);
    assert.match(row.id, /^[A-Za-z0-9_-]{1,100}$/);
  }
  const first = merge([], calendar([event()]), now)[0];
  const second = merge([], calendar([event()], '2026-09', { owner: 'other@example.test' }), now)[0];
  assert.notEqual(first.id, second.id);
  assert.equal(merge([], calendar([event()], '2026-09', { owner: ' OWNER@EXAMPLE.TEST ' }), now)[0].id, first.id);
});

test('only allowlisted HTTPS Google Calendar links survive, with all event fields kept as plain text', () => {
  const invalid = ['javascript:alert(1)', 'http://calendar.google.com/calendar/',
    'https://calendar.google.com.evil.test/', 'https://www.google.com/other/',
    'https://evil@calendar.google.com/calendar/', 'https://calendar.google.com:8443/calendar/',
    'https://calendar.google.com/\ncalendar/', '//calendar.google.com/calendar/', null, {}];
  for (const link of invalid) assert.equal(merge([], calendar([event({ link })]), now)[0].googleLink, '');
  for (const link of ['https://calendar.google.com/calendar/event?eid=test', 'https://www.google.com/calendar/event?eid=test']) {
    assert.equal(merge([], calendar([event({ link })]), now)[0].googleLink, link);
  }
  const attack = '<img src=x onerror=alert(1)>"</script>';
  const row = merge([], calendar([event({ title: attack, location: attack })]), now)[0];
  assert.equal(row.title, attack);
  assert.equal(row.location, attack);
  assert.equal(row.attendees, '');
  assert.equal(row.summary, '');
});

test('malformed snapshots and impossible dates are ignored without changing manual meetings', () => {
  const manual = [{ id: 'keep' }];
  for (const data of [null, {}, { owner }, { owner, months: null }, { owner: '', months: {} }]) {
    const result = merge(manual, data, now);
    assert.equal(result.length, 1); assert.equal(result[0], manual[0]);
  }
  const invalid = [null, {}, event({ id: '' }), event({ id: {} }), event({ id: 'x'.repeat(4097) }),
    event({ start: 'bad' }), event({ start: '2026-02-30T09:00:00Z' }), event({ allDay: 'true' }),
    event({ start: '2026-09-22T10:00:00+03:00' }), event({ end: '2026-09-22T08:00:00+03:00' }),
    event({ start: '2026-09-22T09:00:00', end: '2026-09-22T10:00:00' }),
    event({ allDay: true, start: '2026-02-30', end: '2026-03-02' }),
    event({ allDay: true, start: '2026-09-22', end: '2026-09-22' })];
  assert.equal(merge(manual, calendar(invalid), now).length, 1);
  assert.equal(merge([], { owner, months: { '2026-13': { events: [event()] }, '2026-09': null } }, now).length, 0);
  assert.equal(merge([], calendar([event()]), 'invalid').length, 0);
});

test('status uses actual event end and Israel-local all-day end without timezone-dependent tests', () => {
  const timed = calendar([event()]);
  assert.equal(merge([], timed, '2026-09-22T07:00:00Z')[0].status, 'upcoming');
  assert.equal(merge([], timed, '2026-09-22T07:00:00.001Z')[0].status, 'done');
  const allDay = calendar([event({ allDay: true, start: '2026-09-22', end: '2026-09-23' })]);
  assert.equal(merge([], allDay, '2026-09-22T20:59:59Z')[0].status, 'upcoming');
  assert.equal(merge([], allDay, '2026-09-22T21:00:00Z')[0].status, 'upcoming');
  assert.equal(merge([], allDay, '2026-09-22T21:00:00.001Z')[0].status, 'done');
});

test('expansion is bounded by snapshot month even when a valid event spans centuries', () => {
  const rows = merge([], calendar([event({ allDay: true, start: '1900-01-01', end: '9999-12-31' })], '2028-02'), now);
  assert.equal(rows.length, 29);
  assert.equal(rows[0].date, '2028-02-01');
  assert.equal(rows.at(-1).date, '2028-02-29');
});
