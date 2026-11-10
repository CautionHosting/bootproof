#!/usr/bin/env node
// CDP paint-poll acceptance driver (zero deps: node >= 18 stdlib only).
//
// WHY: the acceptance rule for the status page is "verdict renders in the
// browser (CDP paint-poll, not dump-dom)". dump-dom proves the bytes
// arrived; paint proves the browser PARSED, ran, and DISPLAYED them. This
// drives a real headless Chrome over the DevTools Protocol and reports
// whether a marker was painted, plus every certificate/network/console
// error the page hit while waiting.
//
// The two modes mirror the cert arc:
//   --bypass-cert   pre-cert stage: the golden box serves a self-signed
//                   leaf today; bypass so the run witnesses page/JS/API/
//                   verdict, with the ONLY delta at cert-time the trust
//                   leg itself.
//   (default)       cert-night: NO bypass. A failing chain shows up as an
//                   error page (no marker painted) + Security/Network
//                   failures, and the run exits non-zero, loudly.
//
// Usage:
//   node cdp-paint-poll.js <url> [--marker <substring|regex>] [--bypass-cert]
//        [--timeout <secs>] [--port <n>]
//        [--expect-row <label[=VERDICT]>]... [--permissive]
//        [--chrome <path>]   pin the browser binary (default /usr/bin/google-chrome);
//                            the path + `--version` are recorded in the output JSON
//   --expect-row <label>          requires the row to paint PROVEN (fail-closed)
//   --expect-row <label=VERDICT>  requires that exact verdict (NOT PROVEN etc.)
//   --permissive                  opt back into the old lenient non-FAILED rule
// Defaults: marker "bootproof-verdict" (the shell's verdict container id;
// override to match the shipped client), timeout 60, port 0 = ephemeral.
//
// --expect-row (repeatable): per-row doctrine, FAIL-CLOSED BY DEFAULT
// (T-D, 2026-11-10; supersedes the permissive 08:28Z ruling-iii default).
// For each label (e.g. identity_link), the driver finds the row by DOM id
// (r-<label> / v-<label>) and reads the verdict chip's own text. The
// pending-first page names rows by id; a text-window scan would let a
// dotted label (identity_link.pin) match its parent rollup's row.
//
// A declared row carries an EXPECTED verdict: `--expect-row LABEL=VERDICT`.
//   * A bare `--expect-row LABEL` means the expected verdict is PROVEN
//     (the strict, fail-closed default: a row you name must PROVE).
//   * `LABEL=NOT PROVEN` declares an honest non-proven claim (ruling iii:
//     identity_link is a pin claim; "never dress a pin fact in a PROVEN
//     costume"). A PROVEN there is now a MISMATCH, not a flagged pass.
// The gate is fail-closed: the painted verdict must EQUAL the expected
// verdict, else the run fails. This catches BOTH directions an overclaim-
// prone verifier can go green under a permissive gate:
//   * OVERCLAIM  -- a tampered verifier paints identity_link=PROVEN when the
//                    harness declared `identity_link=NOT PROVEN` -> mismatch,
//                    fail. (The old gate only flagged this in prose.)
//   * UNDERCLAIM -- a verifier that fails to prove a required row paints
//                    memory_encryption=NOT PROVEN when the harness declared
//                    `memory_encryption=PROVEN` (or left it bare) -> mismatch,
//                    fail. (The old `v!=='FAILED'` rule let this through.)
// A PENDING row fails unless expected is PENDING or --allow-pending (the
// static-paint pass). An absent row chip always fails.
//
// PERMISSIVE OPT-IN: --permissive restores the OLD rule (pass iff the row
// is not FAILED) for every declared row. It is opt-in and never the default,
// because a permissive-by-default driver green-lights a verifier that
// overclaims -- exactly what must never gate a live box. Prefer naming the
// exact expected verdict; reserve --permissive for exploratory runs only.
// The exit code is 0 iff painted AND every --expect-row matches its expectation.
//
// --all-pending: the STATIC-PAINT assertion (the pending-first render law).
// Every r-* row in the DOM must read exactly PENDING with the pd chip class.
// Pair with --max-subresource-requests 0: a page whose rows are all pending
// AND which fetched nothing beyond its own document IS what a JS-disabled
// browser reads (the ?static=1 mode proves it even with JS on: nothing runs).
//
// --max-subresource-requests N: cap on Network.requestWillBeSent events
// EXCLUDING the main document (and favicon). The document request itself is
// not counted (the page cannot be gated on not loading itself).
//
// Output: one JSON object on stdout:
//   { painted, match, rows{}, ms, mode, requests[], subresourceRequests,
//     allPending, certErrors[], netFailures[],
//     consoleErrors[], title, url }
// Exit 0 iff painted and rows pass and the request cap holds.

'use strict';
const { spawn, execFileSync } = require('child_process');
const http = require('http');
const net = require('net');
const crypto = require('crypto');
const os = require('os');
const fs = require('fs');
const path = require('path');

// ---------------- args ----------------
const argv = process.argv.slice(2);
const url = argv[0];
if (!url || url.startsWith('--')) {
  console.error('usage: cdp-paint-poll.js <url> [--marker X] [--bypass-cert] [--timeout S] [--port N]');
  process.exit(2);
}
function flag(name) { return argv.includes(name); }
function opt(name, dflt) {
  const i = argv.indexOf(name);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : dflt;
}
function optAll(name) {
  const out = [];
  for (let i = 0; i < argv.length; i++) if (argv[i] === name && argv[i + 1]) out.push(argv[i + 1]);
  return out;
}
// Parse each --expect-row entry into {label, expected}. A bare label
// expects PROVEN (fail-closed default); `LABEL=VERDICT` declares an exact
// expectation (e.g. `identity_link=NOT PROVEN`). Split on the FIRST '=' so a
// verdict containing no '=' is safe; "NOT PROVEN" (a space) arrives as one
// shell argument, so the whole `label=NOT PROVEN` token is one entry.
const EXPECT_ROWS = optAll('--expect-row').map(function (e) {
  const eq = e.indexOf('=');
  if (eq < 0) return { label: e, expected: 'PROVEN' };
  return { label: e.slice(0, eq), expected: e.slice(eq + 1).trim() };
});
const ALL_PENDING = flag('--all-pending');
const ALLOW_PENDING = flag('--allow-pending');
const PERMISSIVE = flag('--permissive');
const MAX_SUBREQ = opt('--max-subresource-requests', null);
const marker = opt('--marker', 'bootproof-verdict');
const markerRe = marker.startsWith('re:')
  ? new RegExp(marker.slice(3))
  : { test: (s) => s && s.includes(marker) };
const BYPASS = flag('--bypass-cert');
const TIMEOUT_MS = parseInt(opt('--timeout', '60'), 10) * 1000;
const PORT = parseInt(opt('--port', '0'), 10);
// T-F: the browser is part of the witness. Default is the historical hardcoded
// path (unchanged behavior); --chrome <path> pins a specific binary so a live
// acceptance run is reproducible and the emitted JSON records WHICH renderer
// produced the verdict. The version string is captured at startup and emitted.
const CHROME_PATH = opt('--chrome', '/usr/bin/google-chrome');

// ---------------- minimal CDP-over-WebSocket client ----------------
// RFC6455 client, text frames only (CDP is JSON text). No deps because
// node 20 still has no global WebSocket and this repo adds none.

function wsConnect(host, portNo, resource, onMessage, onClose) {
  const key = crypto.randomBytes(16).toString('base64');
  // READY GATE (a witnessed race, fixed): writes issued before the HTTP
  // upgrade completes can flush on socket-connect in an ordering node
  // does not define relative to the connect callback below, so chrome can
  // receive raw CDP JSON BEFORE the upgrade request and kill the socket
  // (witnessed: 4 reconnects, every one 'socket closed', zero events).
  // Frames sent before the 101 response are QUEUED here and flushed in
  // order the moment the handshake completes. No send ever precedes the
  // upgrade, deterministically.
  let ready = false;
  const queue = [];
  const sock = net.connect(portNo, host, () => {
    sock.write(
      `GET ${resource} HTTP/1.1\r\n` +
      `Host: ${host}:${portNo}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n` +
      `Sec-WebSocket-Key: ${key}\r\nSec-WebSocket-Version: 13\r\n\r\n`
    );
  });
  let handoff = false;
  let buf = Buffer.alloc(0);
  sock.on('data', (d) => {
    buf = Buffer.concat([buf, d]);
    if (!handoff) {
      const end = buf.indexOf('\r\n\r\n');
      if (end < 0) return;
      const head = buf.slice(0, end).toString();
      if (!/ 101 /.test(head)) {
        onClose(new Error('ws handshake failed: ' + head.split('\r\n')[0]));
        sock.destroy();
        return;
      }
      handoff = true;
      buf = buf.slice(end + 4);
      ready = true;
      for (const q of queue) rawSend(q);
      queue.length = 0;
    }
    // Frame decode (server->client: unmasked). Handles 7/16/64-bit lengths;
    // CDP never fragments text at these sizes in practice, but we re-arm on
    // buffer starvation instead of assuming whole messages arrive together.
    for (;;) {
      if (buf.length < 2) return;
      const op = buf[0] & 0x0f;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      if (buf.length < off + len) return;
      const payload = buf.slice(off, off + len);
      buf = buf.slice(off + len);
      if (op === 0x1) onMessage(payload.toString());
      else if (op === 0x8) { onClose(new Error('ws closed by peer')); return; }
    }
  });
  sock.on('error', onClose);
  sock.on('close', () => onClose(new Error('socket closed')));

  function rawSend(obj) {
    const data = Buffer.from(JSON.stringify(obj));
    const mask = crypto.randomBytes(4);
    let head;
    if (data.length < 126) head = Buffer.from([0x81, 0x80 | data.length]);
    else if (data.length < 65536) {
      head = Buffer.alloc(4); head[0] = 0x81; head[1] = 0xfe; head.writeUInt16BE(data.length, 2);
    } else {
      head = Buffer.alloc(10); head[0] = 0x81; head[1] = 0xff; head.writeBigUInt64BE(BigInt(data.length), 2);
    }
    const masked = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) masked[i] = data[i] ^ mask[i & 3];
    sock.write(Buffer.concat([head, mask, masked]));
  }
  function send(obj) {
    if (ready) rawSend(obj); else queue.push(obj);
  }
  return { send, sock };
}

// ---------------- HTTP GET helper (the /json/* DevTools endpoints) ----------------
function getJson(host, portNo, p) {
  return new Promise((resolve, reject) => {
    const req = http.get({ host, port: portNo, path: p }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { reject(e); } });
    });
    req.on('error', reject);
  });
}

// ---------------- main ----------------
(async () => {
  const chrome = CHROME_PATH;
  // T-F: record the renderer identity. A failure to read --version is NOT
  // fatal (an absent/odd binary still fails later at launch); we emit null
  // rather than crash, so the gate's exit contract is unchanged by T-F.
  let chromeVersion = null;
  try {
    chromeVersion = execFileSync(chrome, ['--version'], { encoding: 'utf8', timeout: 5000 }).trim();
  } catch (e) { chromeVersion = null; }
  const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'crow-cdp-'));
  const args = [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage',
    `--user-data-dir=${profile}`, `--remote-debugging-port=${PORT}`,
    // Self-signed pre-cert must not abort the TLS handshake path we are
    // witness-testing; on cert-night we OMIT this and let trust be real.
    ...(BYPASS ? ['--ignore-certificate-errors'] : []),
    // Launch straight at the target: chrome 152 restricts /json/new to PUT
    // and the open-a-target dance is unnecessary when the first tab IS the
    // test page. We then find it via /json/list by URL match.
    url,
  ];
  const proc = spawn(chrome, args, { stdio: ['ignore', 'ignore', 'pipe'] });
  let wsErr = '';
  proc.stderr.on('data', (d) => { wsErr += d; });

  // The DevToolsActivePort file is the rendezvous (port 0 = ephemeral).
  const portFile = path.join(profile, 'DevToolsActivePort');
  const deadline = Date.now() + 20000;
  while (!fs.existsSync(portFile)) {
    if (Date.now() > deadline) { proc.kill('SIGKILL'); throw new Error('chrome did not start: ' + wsErr.slice(0, 400)); }
    await new Promise((r) => setTimeout(r, 100));
  }
  const portNo = parseInt(fs.readFileSync(portFile, 'utf8').split('\n')[0], 10);

  // Find the page target for our URL (it was the launch argument).
  let t = null;
  const listDeadline = Date.now() + 15000;
  while (!t && Date.now() < listDeadline) {
    try {
      const list = await getJson('127.0.0.1', portNo, '/json/list');
      t = list.find((x) => x.type === 'page' && x.url === url) ||
          list.find((x) => x.type === 'page' && x.webSocketDebuggerUrl);
    } catch { /* chrome still booting */ }
    if (!t) await new Promise((r) => setTimeout(r, 200));
  }
  if (!t) { proc.kill('SIGKILL'); throw new Error('no page target found'); }

  // The live websocket, swappable: chrome can recreate the page target
  // mid-load (the target we grabbed from /json/list can be destroyed and
  // replaced with a fresh id; witnessed live when a run closed its socket
  // with zero paint events). The poll loop re-checks /json/list and
  // reconnects to whatever page target currently serves our URL.
  let ws = null;
  let wsDead = true;
  let cur = t;
  const wsErrs = [];

  // Declared BEFORE attach: attach() calls cmd() synchronously, and
  // cmd() touches id/pending (a let/const below the call site would be a
  // TDZ ReferenceError).
  let id = 0;
  const pending = new Map();
  const certErrors = [];
  const netFailures = [];
  const consoleErrors = [];
  const requests = []; // every Network.requestWillBeSent after attach: {url, type}

  function attach(target) {
    const p = new URL(target.webSocketDebuggerUrl).pathname;
    ws = wsConnect('127.0.0.1', portNo, p, onMsg, (e) => { wsErrs.push(String(e)); wsDead = true; });
    wsDead = false;
    cur = target;
    // Domains must be re-enabled on the fresh session (the old target's
    // event stream died with it).
    cmd('Page.enable'); cmd('Runtime.enable'); cmd('Network.enable');
    cmd('Security.enable'); cmd('Log.enable');
  }
  attach(cur);

  function cmd(method, params) {
    return new Promise((resolve) => {
      const mid = ++id;
      pending.set(mid, resolve);
      try { ws.send({ id: mid, method, params: params || {} }); }
      catch { pending.delete(mid); resolve({ __wsdead: true }); }
      // CDP errors resolve too (we log, never hang).
      setTimeout(() => { if (pending.has(mid)) { pending.delete(mid); resolve({ __timeout: true }); } }, 15000);
    });
  }
  function onMsg(txt) {
    let m; try { m = JSON.parse(txt); } catch { return; }
    if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result || m); pending.delete(m.id); return; }
    const P = m.params || {};
    if (m.method === 'Log.entryAdded') {
      const e = P.entry || {};
      const line = `${e.level}: ${e.text} ${e.url || ''}`;
      if (/certificate|ssl|tls/i.test(line)) certErrors.push(line);
      else if (e.level === 'error') consoleErrors.push(line);
    } else if (m.method === 'Network.loadingFailed') {
      netFailures.push(`${P.errorText || 'failed'}${P.certificateError ? ' cert:' + P.certificateError : ''}`);
    } else if (m.method === 'Network.requestWillBeSent') {
      requests.push({ url: P.request ? P.request.url : '?', type: P.type || 'Other' });
    } else if (m.method === 'Security.securityStateAdded' || m.method === 'Security.certificateErrorAdded') {
      if (P.state === 'insecure' || m.method.endsWith('certificateErrorAdded')) {
        certErrors.push(JSON.stringify(P).slice(0, 300));
      }
    } else if (m.method === 'Runtime.consoleAPICalled' && P.type === 'error') {
      consoleErrors.push((P.args || []).map((a) => a.value ?? a.description ?? '').join(' ').slice(0, 300));
    }
  }

  await cmd('Page.enable');
  await cmd('Runtime.enable');
  await cmd('Network.enable');
  await cmd('Security.enable');
  await cmd('Log.enable');

  const t0 = Date.now();
  let painted = false, matchSnippet = '', title = '', paintedText = '';
  // The row probe runs in-page and is ID-BASED: a dotted label can never be
  // confused with its parent rollup. Returns {id:{verdict,cls,rowCls}}.
  const ROW_PROBE =
    'JSON.stringify((function(){' +
    'var o={};var trs=document.querySelectorAll("tr[id^=\\"r-\\"]");' +
    'for(var i=0;i<trs.length;i++){' +
    'var id=trs[i].id.slice(2);var v=document.getElementById("v-"+id);' +
    'o[id]={verdict:v?v.textContent:null,cls:v?v.className:null,rowCls:trs[i].className||"",' +
    'why:(function(){var w=document.getElementById("w-"+id);return w?w.textContent:null;})()};}' +
    'return o;})())';
  // The page href probe: chrome can hand us a target whose /json/list url is
  // the launch URL while the live document is still about:blank (witnessed on
  // the static pass: every evaluate ran on about:blank for the full timeout).
  // When that happens we Page.navigate the attached target ourselves; the
  // launch-url-at-boot assumption is not something CDP guarantees.
  const HREF_PROBE = 'location.href';
  let navigated = false;
  let lastList = 0;
  while (Date.now() - t0 < TIMEOUT_MS) {
    // Re-attach if the socket died or the target id vanished (chrome
    // recreated the page). /json/list is cheap; poll it at 1 Hz.
    if (wsDead || Date.now() - lastList > 1000) {
      lastList = Date.now();
      try {
        const list = await getJson('127.0.0.1', portNo, '/json/list');
        const fresh = list.find((x) => x.type === 'page' && x.url === url) ||
                      list.find((x) => x.type === 'page' && x.webSocketDebuggerUrl && x.url !== 'about:blank') ||
                      list.find((x) => x.type === 'page' && x.webSocketDebuggerUrl);
        if (fresh && (wsDead || fresh.id !== cur.id)) { attach(fresh); navigated = false; }
      } catch { /* chrome mid-restart; retry next tick */ }
    }
    if (wsDead) { await new Promise((r2) => setTimeout(r2, 250)); continue; }
    // Self-heal the about:blank target: one forced navigation per attach
    // generation, only if the live document is not our URL.
    if (!navigated) {
      const h = await cmd('Runtime.evaluate', { expression: HREF_PROBE, returnByValue: true });
      const href = (h && h.result && h.result.value) || '';
      if (typeof href === 'string' && href !== url && !href.startsWith(url.split('?')[0])) {
        await cmd('Page.navigate', { url });
        navigated = true; // navigate once per generation; the reconnect below re-arms
      } else {
        navigated = true; // already on the right document, nothing to fix
      }
    }
    const r = await cmd('Runtime.evaluate', {
      expression: 'JSON.stringify({p: document.body ? document.body.innerText : "", t: document.title})',
      returnByValue: true,
    });
    let doc = { p: '', t: '' };
    try { doc = JSON.parse(r && r.result && r.result.value || '{}'); } catch {}
    title = doc.t || title;
    paintedText = doc.p || paintedText;
    // Readiness: the marker paints, OR (static mode) the pending rows are in
    // the DOM — they exist the moment the document parses, and the static
    // pass must not wait for anything that never runs.
    let rowsNow = null;
    if (ALL_PENDING) {
      const rr = await cmd('Runtime.evaluate', { expression: ROW_PROBE, returnByValue: true });
      try { rowsNow = JSON.parse(rr && rr.result && rr.result.value || 'null'); } catch {}
    }
    const pendingHit = ALL_PENDING && rowsNow && Object.keys(rowsNow).length > 10;
    if (markerRe.test(doc.p) || pendingHit) {
      painted = true;
      const i = doc.p.indexOf(marker.startsWith('re:') ? '' : marker);
      matchSnippet = doc.p.slice(Math.max(0, i), i + 200).replace(/\s+/g, ' ');
      // Give the SW one extra beat to paint the remaining rows: the shell
      // fills innerHTML with ALL rows in one message, but a partial paint
      // followed by the full one is possible across SW posts, and an
      // expect-row that missed by 200 ms would be a false fail.
      if (EXPECT_ROWS.length) {
        await new Promise((r2) => setTimeout(r2, 1000));
        const rr = await cmd('Runtime.evaluate', {
          expression: 'JSON.stringify({p: document.body ? document.body.innerText : ""})',
          returnByValue: true,
        });
        try { const d2 = JSON.parse(rr && rr.result && rr.result.value || '{}'); if (d2.p) paintedText = d2.p; } catch {}
      }
      break;
    }
    await new Promise((r2) => setTimeout(r2, 250));
  }

  // -- Per-row doctrine checks (ruling iii: NOT PROVEN pin claim = PASS).
  // Rows are read by DOM id (v-<label>), never by a text window.
  let liveRows = {};
  {
    const rr = await cmd('Runtime.evaluate', { expression: ROW_PROBE, returnByValue: true });
    try { liveRows = JSON.parse(rr && rr.result && rr.result.value || '{}'); } catch {}
  }
  const rows = {};
  let rowsOk = true;
  for (const spec of EXPECT_ROWS) {
    const label = spec.label, expected = spec.expected;
    const ent = liveRows[label];
    const v = ent && ent.verdict ? String(ent.verdict).trim() : null;
    if (!v) { rows[label] = { verdict: null, expected, pass: false, why: 'row chip v-' + label + ' not painted' }; rowsOk = false; continue; }
    let pass;
    if (PERMISSIVE) pass = v !== 'FAILED';                       // opt-in legacy rule
    else if (v === 'PENDING') pass = !!ALLOW_PENDING;            // static-paint escape
    else pass = (v === expected);                                // FAIL-CLOSED default
    let why;
    if (PERMISSIVE) why = 'permissive (opt-in): non-FAILED passes';
    else if (v === 'PENDING') why = ALLOW_PENDING ? 'pending pass allowed (static paint)' : 'row never flipped';
    else if (v === expected) why = 'matches declared expectation';
    else why = 'MISMATCH: painted ' + v + ' but harness declared ' + expected;
    rows[label] = { verdict: v, expected: expected, cls: ent.cls == null ? null : String(ent.cls), why_text: ent.why == null ? null : String(ent.why).slice(0, 300), pass: pass, why: why };
    if (!pass) rowsOk = false;
  }

  // -- The static-paint check: EVERY row PENDING with the pd chip class.
  let allPending = null;
  if (ALL_PENDING) {
    const bad = [];
    for (const id of Object.keys(liveRows)) {
      const e = liveRows[id];
      const v = e.verdict ? String(e.verdict).trim() : null;
      if (v !== 'PENDING') bad.push(id + '=' + v);
      else if (!/pd/.test(e.cls || '')) bad.push(id + '=chip-cls');
      else if (e.rowCls && !/pd/.test(e.rowCls)) bad.push(id + '=row-cls');
    }
    allPending = { count: Object.keys(liveRows).length, bad };
    if (!allPending.count) allPending.bad.push('(no rows found)');
    if (allPending.bad.length) rowsOk = false;
  }

  // -- Subresource accounting: everything but the main document + favicon.
  const subreq = requests.filter((q) => q.type !== 'Document' && !/favicon\.ico/.test(q.url));
  let reqOk = true;
  if (MAX_SUBREQ !== null && subreq.length > parseInt(MAX_SUBREQ, 10)) reqOk = false;

  const out = {
    painted,
    match: matchSnippet,
    rows,
    ms: Date.now() - t0,
    mode: BYPASS ? 'bypass-cert(precert)' : 'strict-cert',
    requests,
    subresourceRequests: subreq.length,
    allPending,
    certErrors, netFailures, consoleErrors,
    title, url,
    error: wsErrs.length ? wsErrs[wsErrs.length - 1] : null,
    reconnects: wsErrs.length,
    // T-F: pin/record the renderer so an acceptance run is reproducible and the
    // G2 witness says which Chrome produced these verdicts.
    chromePath: chrome,
    chromeVersion: chromeVersion,
  };
  console.log(JSON.stringify(out, null, 2));
  try { await cmd('Target.closeTarget', { targetId: cur.id }); } catch {}
  proc.kill('SIGKILL');
  process.exit(painted && rowsOk && reqOk ? 0 : 1);
})().catch((e) => { console.error('driver failed:', e.message); process.exit(3); });
