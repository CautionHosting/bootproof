#!/usr/bin/env node
// fixture-server.js — zero-dep local static server for the DEMO page's
// hermetic CDP fixture gate. Mirrors fixtures/single_file/fixture-server.js
// with one swap: the HTML it serves is the DEMO artifact. Serves exactly what
// the ?fixture=1 page fetches:
//   /  |  /index.html  |  /bootproof.html   the demo artifact (the page
//                        self-measures location.href, so every path the gate
//                        might use must return the same bytes)
//   /health/api        the golden envelope (hermetic fixture)
//   /fixture.nonce     the frozen nonce the envelope binds
// Bind 127.0.0.1, ephemeral port, "LISTENING <port>" on stdout. Exits on
// SIGTERM (the driver owns its life).
'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..'); // repo root
const HTML = path.join(ROOT, 'crates', 'bootproof', 'src', 'assets', 'demo', 'index.html');

const argv = process.argv.slice(2);
const fi = argv.indexOf('--fixture');
const FIXTURE = fi >= 0 ? path.resolve(argv[fi + 1]) : path.join(ROOT, 'fixtures', 'system_health', 'golden.json');
const META = path.join(path.dirname(FIXTURE), (path.basename(FIXTURE).replace(/\.json$/, '')) + '.meta.json');

const envelope = fs.readFileSync(FIXTURE);
const metaPath = fs.existsSync(META) ? META : path.join(ROOT, 'fixtures', 'system_health', 'golden.meta.json');
const nonce = JSON.parse(fs.readFileSync(metaPath, 'utf8')).nonce_hex;

const srv = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://127.0.0.1');
  const p = u.pathname;
  res.setHeader('Cache-Control', 'no-store');
  if (p === '/' || p === '/index.html' || p === '/bootproof.html') {
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
