// System Health service worker (increment 1 stub; the full WebCrypto verifier lands next).
self.addEventListener('install', function (e) { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (e) {
  // Pass-through for now. The verifier body (nonce -> fetch -> verify -> render)
  // replaces this stub in increment 2 per docs/system-health.md v4.
  e.respondWith(fetch(e.request));
});
