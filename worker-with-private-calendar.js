// Isolated extension: existing portal routes and authentication stay unchanged.
import portal from './worker.js';
import { CALENDAR_PREFIX, handlePrivateGoogleCalendar } from './private-google-calendar-worker.js';

export default {
  async fetch(request, env, ctx) {
    const path = new URL(request.url).pathname;
    if (path === CALENDAR_PREFIX || path.startsWith(CALENDAR_PREFIX + '/')) {
      return handlePrivateGoogleCalendar(request, env);
    }
    return portal.fetch(request, env, ctx);
  },
};
