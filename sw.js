// ═══════════════════════════════════════════════════════
//  sw.js — Service Worker בסיסי עבור PWA
//  install / activate / fetch pass-through בלבד.
//  אין caching מורכב, אין יירוט של קריאות API.
// ═══════════════════════════════════════════════════════

self.addEventListener('install', (event) => {
  // מדלגים ישר להפעלה, בלי לשמור שום דבר ב-cache
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  // משתלטים מיד על הלקוחות הפתוחים
  event.waitUntil(self.clients.claim());
});

self.addEventListener('fetch', (event) => {
  // Pass-through בלבד — כל בקשה ממשיכה ישירות לרשת,
  // בלי caching ובלי יירוט של קריאות API / D1 / Worker.
  event.respondWith(fetch(event.request));
});
