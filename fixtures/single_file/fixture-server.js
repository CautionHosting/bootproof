#!/usr/bin/env node
// fixture-server.js — zero-dep local static server for the single-file CDP
// fixture gate. Serves exactly what the ?fixture=1 page fetches:
//   /bootproof.html  the artifact (also its own self-measurement target; the
//                    page fetches location.href, which carries ?fixture=1, so
//                    the server answers the query-stringed path too)
//   /health/api      the golden envelope (the hermetic fixture)
//   /fixture.nonce   the frozen nonce the envelope binds
// No cache headers, everything text/plain or the right content type, LF bytes
// verbatim from disk. Bind 127.0.0.1, ephemeral port, printed on stdout as
//   LISTENING <port>
// so the driver can discover it. Exits on SIGTERM (the driver owns its life).
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..'); // repo root
const HTML = path.join(ROOT, 'crates', 'bootproof', 'src', 'assets', 'single_file', 'bootproof.html');

// Which fixture envelope: --fixture <path> (default golden.json). The gate
// drives golden.json; tamper twins can be pointed at the same server later.
const argv = process.argv.slice(2);
const fi = argv.indexOf('--fixture');
const FIXTURE = fi >= 0 ? path.resolve(argv[fi + 1]) : path.join(ROOT, 'fixtures', 'system_health', 'golden.json');
const META = path.join(path.dirname(FIXTURE), (path.basename(FIXTURE).replace(/\.json$/, '')) + '.meta.json');

const envelope = fs.readFileSync(FIXTURE);
// The frozen nonce: golden.meta.json carries nonce_hex; tamper twins share the
// golden meta (their tampering is inside the envelope, not the nonce).
const metaPath = fs.existsSync(META) ? META : path.join(ROOT, 'fixtures', 'system_health', 'golden.meta.json');
const nonce = JSON.parse(fs.readFileSync(metaPath, 'utf8')).nonce_hex;

const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  const p = u.pathname;
  res.setHeader('Cache-Control', 'no-store');
  if (p === '/bootproof.html' || p === '/') {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(fs.readFileSync(HTML));
  } else if (p === '/health/api') {
    res.setHeader('Content-Type', 'application/json');
    res.end(envelope);
  } else if (p === '/fixture.nonce') {
    res.setHeader('Content-Type', 'text/plain');
    res.end(nonce);
  } else {
    res.statusCode = 404;
    res.end('not found');
  }
});

srv.listen(0, '127.0.0.1', () => {
  console.log('LISTENING ' + srv.address().port);
});
process.on('SIGTERM', () => { srv.close(); process.exit(0); });
