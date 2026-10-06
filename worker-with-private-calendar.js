// Isolated extension: existing portal routes and authentication stay unchanged.
import portal from './worker.js';
import { CALENDAR_PREFIX, handlePrivateGoogleCalendar, runGoogleCalendarOutbox } from './private-google-calendar-worker.js';
import { OUTBOUND_CRON } from './google-calendar-outbound-worker.js';

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    if (path === CALENDAR_PREFIX || path.startsWith(CALENDAR_PREFIX + '/')) {
      return handlePrivateGoogleCalendar(request, env);
    }
    const response=await portal.fetch(request, env, ctx);
    if (request.method==='POST' && path==='/api/data' && response.ok && env.GOOGLE_CALENDAR_OUTBOUND_ENABLED==='true')
      ctx?.waitUntil?.(runGoogleCalendarOutbox(env));
    return response;
  },
  async scheduled(event,env,ctx) {
    if(event.cron===OUTBOUND_CRON)ctx.waitUntil(runGoogleCalendarOutbox(env));
  },
};
