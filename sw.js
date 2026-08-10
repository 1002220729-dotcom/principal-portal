// Minimal PWA service worker. It owns no cache and intentionally has no
// fetch handler, so normal browser networking handles HTML, static assets,
// redirects, and API requests without turning transient failures into
// rejected FetchEvents.
self.addEventListener('install', (event) => {
  event.waitUntil(self.skipWaiting());
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});
