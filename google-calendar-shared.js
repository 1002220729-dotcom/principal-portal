/* Pure display adapter: shared Google snapshots stay separate from editable meetings. */
(function (root) {
  'use strict';

  const localFormat = new Intl.DateTimeFormat('en-CA', {
    timeZone: 'Asia/Jerusalem', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'
  });
  const dayMs = 86400000;
  const shaConstants = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];

  // SHA-256 is synchronous here because this adapter runs during synchronous rendering.
  // The complete digest of a JSON tuple avoids unsafe/overlong HTML IDs and ambiguous joins.
  // These are identifiers, not credentials; tests compare the result with Node's SHA-256.
  function stableId(owner, eventId, day) {
    const bytes = [];
    for (const character of JSON.stringify([owner, eventId, day])) {
      let point = character.codePointAt(0);
      if (point >= 0xd800 && point <= 0xdfff) point = 0xfffd;
      if (point < 0x80) bytes.push(point);
      else if (point < 0x800) bytes.push(0xc0 | point >> 6, 0x80 | point & 63);
      else if (point < 0x10000) bytes.push(0xe0 | point >> 12, 0x80 | point >> 6 & 63, 0x80 | point & 63);
      else bytes.push(0xf0 | point >> 18, 0x80 | point >> 12 & 63, 0x80 | point >> 6 & 63, 0x80 | point & 63);
    }
    const bitLength = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    // Inputs are bounded far below 2^32 bits, so the high length word is zero.
    bytes.push(0, 0, 0, 0, bitLength >>> 24, bitLength >>> 16 & 255, bitLength >>> 8 & 255, bitLength & 255);
    const state = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    const rotate = (value, shift) => value >>> shift | value << (32 - shift);
    for (let offset = 0; offset < bytes.length; offset += 64) {
      const words = new Array(64);
      for (let i = 0; i < 16; i++) {
        const at = offset + i * 4;
        words[i] = bytes[at] << 24 | bytes[at + 1] << 16 | bytes[at + 2] << 8 | bytes[at + 3];
      }
      for (let i = 16; i < 64; i++) {
        const a = words[i - 15], b = words[i - 2];
        words[i] = (words[i - 16] + (rotate(a, 7) ^ rotate(a, 18) ^ a >>> 3) +
          words[i - 7] + (rotate(b, 17) ^ rotate(b, 19) ^ b >>> 10)) | 0;
      }
      let [a, b, c, d, e, f, g, h] = state;
      for (let i = 0; i < 64; i++) {
        const one = (h + (rotate(e, 6) ^ rotate(e, 11) ^ rotate(e, 25)) +
          ((e & f) ^ (~e & g)) + shaConstants[i] + words[i]) | 0;
        const two = ((rotate(a, 2) ^ rotate(a, 13) ^ rotate(a, 22)) +
          ((a & b) ^ (a & c) ^ (b & c))) | 0;
        h = g; g = f; f = e; e = (d + one) | 0; d = c; c = b; b = a; a = (one + two) | 0;
      }
      [a, b, c, d, e, f, g, h].forEach((value, i) => { state[i] = (state[i] + value) | 0; });
    }
    return 'gcal_' + state.map(value => (value >>> 0).toString(16).padStart(8, '0')).join('') + '_' + day.replace(/-/g, '');
  }

  function validDay(value) {
    if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(value)) return false;
    const timestamp = Date.parse(value + 'T00:00:00Z');
    return Number.isFinite(timestamp) && new Date(timestamp).toISOString().slice(0, 10) === value;
  }

  function timestamp(value) {
    if (typeof value !== 'string' || value.length > 64 ||
        !/^\d{4}-\d{2}-\d{2}T(?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d{1,9})?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.test(value) ||
        !validDay(value.slice(0, 10))) return NaN;
    return Date.parse(value);
  }

  function localParts(value) {
    const parts = {};
    for (const part of localFormat.formatToParts(new Date(value))) parts[part.type] = part.value;
    return { date: `${parts.year}-${parts.month}-${parts.day}`, time: `${parts.hour}:${parts.minute}`,
      afterMidnight: parts.hour !== '00' || parts.minute !== '00' || parts.second !== '00' || value % 1000 !== 0 };
  }

  function safeLink(value) {
    if (typeof value !== 'string' || value.length > 2048 || /[\u0000-\u0020\u007f]/.test(value)) return '';
    try {
      const url = new URL(value);
      return url.protocol === 'https:' && !url.username && !url.password && !url.port &&
        (url.hostname === 'calendar.google.com' ||
          (url.hostname === 'www.google.com' && url.pathname.startsWith('/calendar/'))) ? url.href : '';
    } catch { return ''; }
  }

  function text(value, fallback = '') {
    return typeof value === 'string' && value.trim() ? value.slice(0, 500) : fallback;
  }

  function normalize(event, now, localNow) {
    if (!event || typeof event !== 'object' || typeof event.id !== 'string' ||
        !event.id.trim() || event.id.length > 4096 || typeof event.allDay !== 'boolean') return null;
    if (event.allDay) {
      if (!validDay(event.start) || !validDay(event.end) || event.end <= event.start) return null;
      const lastDay = new Date(Date.parse(event.end + 'T00:00:00Z') - dayMs).toISOString().slice(0, 10);
      return { firstDay: event.start, lastDay, startTime: '', endTime: '', endDay: event.end,
        agenda: event.start === lastDay ? 'כל היום' : `כל היום · ${event.start} — ${lastDay} (כולל)`,
        done: localNow.date > event.end || (localNow.date === event.end && localNow.afterMidnight) };
    }
    const start = timestamp(event.start), end = timestamp(event.end);
    if (!Number.isFinite(start) || !Number.isFinite(end) || end <= start) return null;
    const first = localParts(start), last = localParts(end - 1), finish = localParts(end);
    return { firstDay: first.date, lastDay: last.date, endDay: finish.date,
      startTime: first.time, endTime: finish.time, done: end < now,
      agenda: first.date === finish.date ? '' :
        `פגישה מתמשכת · ${first.date} ${first.time} — ${finish.date} ${finish.time} (שעון ישראל)` };
  }

  /** Returns editable meetings unchanged, followed by read-only, per-day Google rows.
   * Snapshot month is authoritative: its buffered events cannot repopulate another month.
   * Optional now accepts a Date, timestamp or ISO string for repeatable callers/tests.
   * Values are plain text; the UI must escape them when rendering HTML as for manual rows.
   */
  function mergeMeetings(manualEvents, googleCalendar, now = Date.now()) {
    const result = Array.isArray(manualEvents) ? manualEvents.slice() : [];
    if (!googleCalendar || typeof googleCalendar !== 'object' ||
        typeof googleCalendar.owner !== 'string' || !googleCalendar.owner.trim() ||
        googleCalendar.owner.length > 320 || !googleCalendar.months || typeof googleCalendar.months !== 'object') return result;
    const owner = googleCalendar.owner.trim().toLowerCase();
    const nowValue = typeof now === 'number' ? now : new Date(now).getTime();
    if (!Number.isFinite(nowValue) || Math.abs(nowValue) > 8640000000000000) return result;
    const localNow = localParts(nowValue);
    const seen = new Set(result.filter(event => event && event.isFromGoogle).map(event => event.id));
    const added = [];
    for (const month of Object.keys(googleCalendar.months).sort()) {
      if (!/^\d{4}-(?:0[1-9]|1[0-2])$/.test(month) || !validDay(month + '-01')) continue;
      const snapshot = googleCalendar.months[month];
      if (!snapshot || !Array.isArray(snapshot.events)) continue;
      const days = [];
      for (let day = 1; day <= 31; day++) {
        const date = month + '-' + String(day).padStart(2, '0');
        if (validDay(date)) days.push(date);
      }
      for (const event of snapshot.events) {
        const range = normalize(event, nowValue, localNow);
        if (!range) continue;
        for (const date of days) {
          if (date < range.firstDay || date > range.lastDay) continue;
          const id = stableId(owner, event.id, date);
          if (seen.has(id)) continue;
          seen.add(id);
          const nextMidnight = !event.allDay && date < range.endDay;
          added.push({ id, date, timeStart: event.allDay ? '' : date === range.firstDay ? range.startTime : '00:00',
            timeEnd: event.allDay ? '' : nextMidnight ? '00:00' : range.endTime,
            title: text(event.title, 'פגישה ללא כותרת'), type: 'meeting', status: range.done ? 'done' : 'upcoming',
            priority: 'medium', location: text(event.location), attendees: '',
            agenda: range.agenda + (nextMidnight ? '\nסיום המקטע היומי: חצות בסוף היום' : ''),
            summary: '', color: '#087d83', isFromGoogle: true, readOnly: true,
            googleLink: safeLink(event.link), googleEventId: event.id });
        }
      }
    }
    added.sort((a, b) => a.date.localeCompare(b.date) || a.timeStart.localeCompare(b.timeStart) || a.id.localeCompare(b.id));
    return result.concat(added);
  }

  const api = Object.freeze({ mergeMeetings });
  root.GoogleCalendarShared = api;
  if (typeof window !== 'undefined') window.GoogleCalendarShared = api;
})(globalThis);
