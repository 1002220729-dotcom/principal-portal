// Private events stay separate from shared data. Shared snapshots are published
// by the server and applied through the calendar's dedicated in-memory adapter.
// Load at the end of calendar.html. The parent remains the session authority.
(() => {
  'use strict';
  if (window.parent === window || !document.getElementById('scalendar')) return;
  let parentWindow;
  try {
    if (window.parent.location.origin !== location.origin) return;
    parentWindow = window.parent;
    if (typeof parentWindow.getSessionToken !== 'function') return;
  } catch { return; }
  const apiOrigin = location.hostname === 'principal-portal.pages.dev'
    ? 'https://principal-api.1002220729.workers.dev'
    : location.hostname === 'staging.principal-portal.pages.dev'
      ? 'https://principal-api-staging.1002220729.workers.dev' : null;
  if (!apiOrigin) return;
  const api = apiOrigin + '/api/private-google-calendar';
  let token = parentWindow.getSessionToken();
  if (!token) return;
  let generation = 0, controller, connected = false, available = false, disposed = false, busyOperation = false;
  let sharedEnabled = false, owner = '', sharedContextKey = null, connectionOperation = false;
  const root = document.createElement('section');
  root.id = 'privateGoogleCalendar';
  root.className = 'card';
  root.dir = 'rtl';
  root.hidden = true;
  root.innerHTML = `
    <h3 data-gcal-heading>🔒 יומן Google שלי — פרטי</h3>
    <p data-gcal-description>מוצג רק בחשבון המחובר. אינו נכלל ביומן המשותף, בהדפסה או בייצוא שלו. קריאה בלבד.</p>
    <p data-gcal-email dir="ltr"></p>
    <div class="gcal-actions">
      <button type="button" data-gcal-connect>חיבור יומן Google</button>
      <button type="button" data-gcal-refresh hidden>רענון פגישות</button>
      <button type="button" data-gcal-disconnect hidden>ניתוק מהאתר</button>
    </div>
    <div class="gcal-month" hidden>
      <button type="button" data-gcal-prev aria-label="חודש קודם">‹ חודש קודם</button>
      <label>חודש <input type="month" data-gcal-month aria-label="חודש להצגת פגישות פרטיות"></label>
      <button type="button" data-gcal-next aria-label="חודש הבא">חודש הבא ›</button>
    </div>
    <p data-gcal-status role="status" aria-live="polite"></p>
    <ul data-gcal-events></ul>`;
  const style = document.createElement('style');
  style.textContent = `
    #privateGoogleCalendar{margin:0 0 18px;padding:18px;border:1px solid #bcd8dc;border-right:4px solid #087d83}
    #privateGoogleCalendar[hidden],#privateGoogleCalendar [hidden]{display:none!important}
    #privateGoogleCalendar h3{margin:0 0 8px;color:#175563;font-size:1.1rem}
    #privateGoogleCalendar p{margin:8px 0;overflow-wrap:anywhere}
    #privateGoogleCalendar .gcal-actions,#privateGoogleCalendar .gcal-month{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:12px 0}
    #privateGoogleCalendar button,#privateGoogleCalendar input{font:inherit;min-height:44px;padding:8px 12px;border:1px solid #bed0dd;border-radius:8px;background:#f5f9fc;color:#193c59;cursor:pointer;max-width:100%}
    #privateGoogleCalendar button:disabled{opacity:.5;cursor:wait}
    #privateGoogleCalendar ul{list-style:none;padding:0;margin:0;display:grid;gap:8px}
    #privateGoogleCalendar li{padding:12px;border:1px solid #dce7ed;border-radius:8px;overflow-wrap:anywhere}
    #privateGoogleCalendar li strong,#privateGoogleCalendar li span{display:block;white-space:pre-wrap}
    #privateGoogleCalendar li a{display:inline-block;margin-top:6px;color:#006a79;text-decoration:underline}
    #privateGoogleCalendar.gcal-shared{padding:12px 16px}
    #privateGoogleCalendar.gcal-shared h3{font-size:1rem}
    #privateGoogleCalendar.gcal-shared .gcal-actions{margin:8px 0}
    @media(max-width:480px){#privateGoogleCalendar{padding:12px}#privateGoogleCalendar .gcal-month>*{flex:1 1 120px}}
    @media print{#privateGoogleCalendar{display:none!important}}`;
  document.head.appendChild(style);
  document.getElementById('scalendar').prepend(root);
  const find = name => root.querySelector('[data-gcal-' + name + ']');
  const status = find('status'), list = find('events'), month = find('month');
  const controls = root.querySelector('.gcal-month');
  const dateParts = (value, allDay) => {
    if (allDay) return value.slice(0, 10);
    const parts = new Intl.DateTimeFormat('en-CA', { timeZone:'Asia/Jerusalem', year:'numeric', month:'2-digit', day:'2-digit' }).formatToParts(new Date(value));
    return ['year','month','day'].map(type => parts.find(p => p.type === type).value).join('-');
  };
  month.value = dateParts(new Date().toISOString(), false).slice(0, 7);
  function stillCurrent() { return !disposed && token && parentWindow.getSessionToken() === token; }
  function clearPrivate() {
    generation++;
    controller?.abort();
    list.replaceChildren();
  }
  function dispose() {
    clearPrivate(); disposed = true; token = null; connected = false;
    document.removeEventListener('calendar-month-change', sharedContextChanged);
    document.removeEventListener('calendar-context-ready', sharedContextChanged);
    root.remove(); style.remove(); clearInterval(sessionGuard); clearInterval(refreshTimer);
  }
  async function request(path, method = 'GET', body = {}) {
    if (!stillCurrent()) throw new Error('stale_session');
    controller?.abort();
    const activeController = new AbortController(); controller = activeController;
    const timeout = setTimeout(() => activeController.abort(), 30000);
    try {
      const response = await fetch(api + path, { method, cache:'no-store', credentials:'omit',
        headers: { Authorization:'Bearer ' + token, ...(method === 'POST' ? { 'Content-Type':'application/json' } : {}) },
        ...(method === 'POST' ? { body:JSON.stringify(body) } : {}), signal:activeController.signal });
      if (!stillCurrent()) throw new Error('stale_session');
      const data = await response.json();
      if (!stillCurrent()) throw new Error('stale_session');
      if (response.status === 401) {
        parentWindow.recheckSessionFromFrame?.();
        throw new Error('session_expired');
      }
      if (!response.ok) throw new Error(data.error || 'calendar_unavailable');
      return data;
    } finally { clearTimeout(timeout); }
  }
  function message(error) {
    const messages = {
      reconnect_required:'הרשאת Google פגה או בוטלה. יש לחבר מחדש את היומן.',
      calendar_permission_missing:'Google לא אישרה קריאת יומן. ייתכן שנדרש אישור מנהל הארגון.',
      account_mismatch:'נבחר חשבון Google אחר. יש להתחבר עם החשבון שמחובר לאתר.',
      not_connected:'היומן אינו מחובר. לחץ על חיבור יומן Google.',
      not_configured:sharedEnabled ? 'חיבור Google עדיין בהגדרה.' : 'החיבור הפרטי עדיין בהגדרה.',
      session_expired:'הכניסה לאתר פגה. יש להתחבר מחדש.',
      too_many_connections:'בוצעו מספר ניסיונות חיבור. אפשר לנסות שוב בעוד עשר דקות.',
      google_rate_limited:'Google הגבילה זמנית את הבקשות. אפשר לנסות שוב בהמשך.',
      too_many_events:'בחודש הזה יש יותר מדי פגישות לתצוגה. לא הוצגה רשימה חלקית.',
    };
    return messages[error.message] || (sharedEnabled
      ? 'לא ניתן לסנכרן כרגע מ־Google. הפגישות שכבר פורסמו נשארו ביומן; אפשר לנסות רענון.'
      : 'לא ניתן לטעון כרגע את היומן הפרטי. בדוק את החיבור ונסה רענון; היומן המשותף לא השתנה.');
  }
  function buttons(busy = false) {
    busyOperation = busy;
    for (const button of root.querySelectorAll('button')) button.disabled = busy;
    month.disabled = busy;
    find('connect').hidden = !available;
    find('connect').textContent = connected ? 'חיבור מחדש ל־Google' : 'חיבור יומן Google';
    find('refresh').hidden = !connected;
    find('refresh').textContent = sharedEnabled ? 'סנכרון החודש המוצג' : 'רענון פגישות';
    find('disconnect').hidden = !connected;
    controls.hidden = sharedEnabled || !connected;
    list.hidden = sharedEnabled;
  }
  function displayMode() {
    root.classList.toggle('gcal-shared', sharedEnabled);
    find('heading').textContent = sharedEnabled ? 'יומן Google — סנכרון ליומן המנהל' : '🔒 יומן Google שלי — פרטי';
    find('description').textContent = sharedEnabled
      ? 'פגישות Google מוצגות ביומן הרגיל למורשי הגישה ליומן, ונכללות בהדפסה וב־CSV. השינויים בפגישות נעשים ב־Google בלבד.'
      : 'מוצג רק בחשבון המחובר. אינו נכלל ביומן המשותף, בהדפסה או בייצוא שלו. קריאה בלבד.';
    if (sharedEnabled) list.replaceChildren();
    buttons();
  }
  function sharedContext() {
    try {
      const value = window.getGoogleCalendarContext?.();
      if (!value || value.ready !== true || typeof value.school !== 'string' || !value.school.trim() ||
          typeof value.year !== 'string' || !value.year.trim() || !/^20\d{2}-(0[1-9]|1[0-2])$/.test(value.month)) return null;
      return { school:value.school, year:value.year, month:value.month };
    } catch { return null; }
  }
  const contextKey = context => context ? JSON.stringify([context.school, context.year, context.month]) : null;
  function sharedContextChanged() {
    if (!sharedEnabled || !stillCurrent()) return;
    const context = sharedContext(), nextKey = contextKey(context);
    // Rendering the applied snapshot emits another month event. It must not
    // trigger a second sync for the same school, year and month.
    if (nextKey === sharedContextKey) return;
    sharedContextKey = nextKey;
    if (connectionOperation) return;
    clearPrivate();
    if (connected) void refreshShared();
  }
  async function refreshShared() {
    if (!stillCurrent() || !connected || connectionOperation) return;
    const context = sharedContext(), key = contextKey(context);
    sharedContextKey = key;
    clearPrivate(); const epoch = generation;
    if (!context) { buttons(); status.textContent = 'ממתין לטעינת בית הספר ושנת הלימודים לפני הסנכרון.'; return; }
    buttons(true); status.textContent = 'מסנכרן את החודש המוצג מ־Google ליומן המנהל…';
    const isCurrent = () => epoch === generation && stillCurrent() && sharedEnabled && connected &&
      contextKey(sharedContext()) === key;
    try {
      const data = await request('/sync-shared?month=' + encodeURIComponent(context.month), 'POST',
        { school:context.school, year:context.year });
      if (!isCurrent()) return;
      if (data.ok !== true || data.school !== context.school || data.year !== context.year || data.month !== context.month ||
          !data.snapshot || !Array.isArray(data.snapshot.events) || !Number.isFinite(Date.parse(data.snapshot.fetchedAt)) ||
          typeof window.applyGoogleCalendarSnapshot !== 'function') throw new Error('calendar_unavailable');
      // The server already persisted this snapshot. Never call the ordinary
      // calendar save path, which could overwrite unrelated school events.
      const applied = window.applyGoogleCalendarSnapshot({ ...context, snapshot:data.snapshot, owner });
      if (!isCurrent() || applied === false) return;
      status.textContent = 'החודש המוצג סונכרן מ־Google ב־' +
        new Intl.DateTimeFormat('he-IL', { hour:'2-digit', minute:'2-digit' }).format(new Date(data.snapshot.fetchedAt)) +
        '. הפגישות זמינות למורשי הגישה ליומן ונכללות בהדפסה וב־CSV.';
    } catch (error) { if (isCurrent()) status.textContent = message(error); }
    finally { if (epoch === generation && stillCurrent()) buttons(); }
  }
  function humanDate(value, allDay) {
    return new Intl.DateTimeFormat('he-IL', { timeZone:allDay ? 'UTC' : 'Asia/Jerusalem', dateStyle:'medium',
      ...(allDay ? {} : { timeStyle:'short' }) }).format(new Date(value));
  }
  function render(data) {
    list.replaceChildren();
    const startMonth = month.value + '-01';
    const [y, m] = month.value.split('-').map(Number);
    const endMonth = new Date(Date.UTC(y, m, 1)).toISOString().slice(0, 10);
    const events = data.events.filter(event => {
      const start = dateParts(event.start, event.allDay), end = dateParts(event.end, event.allDay);
      return start < endMonth && (event.allDay ? end > startMonth : end >= startMonth);
    });
    for (const event of events) {
      const item = document.createElement('li'), title = document.createElement('strong');
      title.textContent = event.title; item.append(title);
      const time = document.createElement('span');
      const end = event.allDay ? new Date(Date.parse(event.end) - 86400000).toISOString().slice(0, 10) : event.end;
      time.textContent = humanDate(event.start, event.allDay) +
        (event.allDay && event.start === end ? '' : ' — ' + humanDate(end, event.allDay)) + (event.allDay ? ' · כל היום' : ' · שעון ישראל');
      item.append(time);
      if (event.location) { const place = document.createElement('span'); place.textContent = event.location; item.append(place); }
      if (event.link) {
        try {
          const url = new URL(event.link);
          if (url.protocol === 'https:' && ['calendar.google.com','www.google.com'].includes(url.hostname)) {
            const link = document.createElement('a'); link.textContent = 'פתיחה ב־Google Calendar';
            link.href = url.href; link.target = '_blank'; link.rel = 'noopener noreferrer'; item.append(link);
          }
        } catch { /* ignore malformed links */ }
      }
      list.append(item);
    }
    status.textContent = (events.length ? events.length + ' פגישות בחודש הנבחר.' : 'אין פגישות בחודש הנבחר.') +
      ' עודכן ב־' + new Intl.DateTimeFormat('he-IL', { hour:'2-digit', minute:'2-digit' }).format(new Date(data.fetchedAt));
  }
  async function refresh() {
    if (!stillCurrent() || !connected) return;
    if (sharedEnabled) return refreshShared();
    clearPrivate(); const epoch = generation; buttons(true); status.textContent = 'טוען פגישות פרטיות מ־Google…';
    try {
      const data = await request('/events?month=' + encodeURIComponent(month.value));
      if (epoch !== generation || !stillCurrent()) return;
      render(data);
    } catch (error) {
      if (epoch !== generation || !stillCurrent()) return;
      list.replaceChildren(); status.textContent = message(error);
    } finally { if (epoch === generation && stillCurrent()) buttons(); }
  }
  find('connect').addEventListener('click', async () => {
    connectionOperation = true;
    clearPrivate(); buttons(true);
    try {
      if (!stillCurrent()) throw new Error('stale_session');
      // The sandboxed iframe cannot navigate its parent. Send only an intent;
      // the parent obtains and validates the OAuth URL using its current session.
      const requestId = Date.now().toString(36) + ':' + generation;
      await new Promise((resolve, reject) => {
        const finish = error => {
          clearTimeout(timeout);
          window.removeEventListener('message', onResult);
          error ? reject(error) : resolve();
        };
        const onResult = event => {
          if (event.source !== parentWindow || event.origin !== location.origin ||
              event.data?.type !== 'private-google-calendar-connect-result' || event.data.requestId !== requestId) return;
          if (!stillCurrent()) { finish(new Error('stale_session')); return; }
          finish(event.data.ok ? null : new Error(event.data.error || 'calendar_unavailable'));
        };
        const timeout = setTimeout(() => finish(new Error('calendar_unavailable')), 35000);
        window.addEventListener('message', onResult);
        try { parentWindow.postMessage({ type:'private-google-calendar-connect', requestId }, location.origin); }
        catch (error) { finish(error); }
      });
    } catch (error) { connectionOperation = false; if (stillCurrent()) { status.textContent = message(error); buttons(); } }
  });
  find('disconnect').addEventListener('click', async () => {
    if (!window.confirm(sharedEnabled
      ? 'להפסיק את הסנכרון מ־Google? הפגישות שכבר פורסמו יישארו ביומן המנהל. הפגישות ב־Google לא יימחקו.'
      : 'לנתק את היומן הפרטי מהאתר? הפגישות ב־Google לא יימחקו.')) return;
    connectionOperation = true;
    clearPrivate(); buttons(true);
    try {
      await request('/connection', 'DELETE');
      if (!stillCurrent()) return;
      connected = false; status.textContent = sharedEnabled
        ? 'הסנכרון מ־Google הופסק והרשאת החיבור השמורה נמחקה. הפגישות שכבר פורסמו נשארו ביומן המנהל.'
        : 'היומן נותק מהאתר והרשאת החיבור השמורה נמחקה. ניתן לבטל את הרשאת Google גם בהגדרות חשבון Google.';
    } catch (error) { if (stillCurrent()) status.textContent = message(error); }
    finally { connectionOperation = false; if (stillCurrent()) buttons(); }
  });
  find('refresh').addEventListener('click', refresh);
  month.addEventListener('change', () => { if (/^20\d{2}-(0[1-9]|1[0-2])$/.test(month.value)) void refresh(); });
  for (const [name, delta] of [['prev',-1],['next',1]]) find(name).addEventListener('click', () => {
    const [year, index] = month.value.split('-').map(Number);
    month.value = new Date(Date.UTC(year, index - 1 + delta, 1)).toISOString().slice(0, 7);
    void refresh();
  });
  document.addEventListener('calendar-month-change', sharedContextChanged);
  document.addEventListener('calendar-context-ready', sharedContextChanged);
  const sessionGuard = setInterval(() => { if (!stillCurrent()) dispose(); else sharedContextChanged(); }, 500);
  const visible = () => !document.hidden && !!window.frameElement?.getClientRects().length;
  const refreshTimer = setInterval(() => { if (visible() && !busyOperation) void refresh(); }, 300000);
  // Clear private text before bfcache/navigation; recheck the connection on return.
  window.addEventListener('pagehide', clearPrivate);
  parentWindow.addEventListener('pagehide', clearPrivate);
  window.addEventListener('pageshow', event => { if (event.persisted && stillCurrent()) void init(); });
  parentWindow.addEventListener('pageshow', event => { if (event.persisted && stillCurrent()) void init(); });
  document.addEventListener('visibilitychange', () => { if (visible() && stillCurrent() && connected && !busyOperation) void refresh(); });
  async function init() {
    try {
      const data = await request('/status');
      if (!stillCurrent()) return;
      available = !!data.available; connected = !!data.connected; root.hidden = false;
      sharedEnabled = data.sharedEnabled === true; owner = data.email || '';
      connectionOperation = false;
      find('email').textContent = owner;
      displayMode();
      if (!available) { status.textContent = sharedEnabled ? 'חיבור Google עדיין בהגדרה.' : 'חיבור היומן הפרטי עדיין בהגדרה.'; return; }
      const params = new URL(parentWindow.location.href);
      const result = params.searchParams.get('gcal');
      if (result) { params.searchParams.delete('gcal'); parentWindow.history.replaceState(null, '', params.href); }
      if (result && result !== 'connected') {
        status.textContent = result === 'denied' ? 'החיבור לא אושר ב־Google. אפשר לנסות שוב כשיתאים.' : message(new Error(result));
        return;
      }
      if (connected) await refresh(); else status.textContent = 'לחץ על חיבור היומן ואשר קריאה בלבד במסך Google.';
    } catch (error) {
      if (!stillCurrent()) return;
      if (error.message === 'private_calendar_forbidden') { dispose(); return; }
      root.hidden = false; status.textContent = message(error); buttons();
    }
  }
  void init();
})();
