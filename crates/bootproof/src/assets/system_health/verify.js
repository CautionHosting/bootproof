// === baked trust anchors (SPKI-SHA256 hex) ===
// These MUST equal the Rust trust anchors in bootproof::snp. The drift-killer
// test in crates/bootproof/src/system_health.rs recompiles the pins from
// AMD_ARK_MILAN_PEM / AMD_ASVK_MILAN_PEM and asserts they equal the two strings
// below, so a change to either side fails the build. The browser verifies the
// SNP report's VLEK against ARK (and the KDS ASVK) using THESE pins, baked in
// at compile time so they cannot be swapped by a compromised server.
const ARK_MILAN_SPKI_SHA256 = "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9";
const ASVK_MILAN_SPKI_SHA256 = "66450a123ea5876206df67f2514a4fea224c0f63b18313423078b0edc4535e33";

// System Health service worker (increment 1 stub; the full WebCrypto verifier lands next).
self.addEventListener('install', function (e) { self.skipWaiting(); });
self.addEventListener('activate', function (e) { e.waitUntil(self.clients.claim()); });
self.addEventListener('fetch', function (e) {
  // Pass-through for now. The verifier body (nonce -> fetch -> verify -> render)
  // replaces this stub in increment 2 per docs/system-health.md v4.
  e.respondWith(fetch(e.request));
});
