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
// Defaults: marker "bootproof-verdict" (the shell's verdict container id;
// override to match the shipped client), timeout 60, port 0 = ephemeral.
//
// Output: one JSON object on stdout:
//   { painted, match, ms, certErrors[], netFailures[], consoleErrors[],
//     title, url }
// Exit 0 iff painted.

'use strict';
const { spawn } = require('child_process');
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
const marker = opt('--marker', 'bootproof-verdict');
const markerRe = marker.startsWith('re:')
  ? new RegExp(marker.slice(3))
  : { test: (s) => s && s.includes(marker) };
const BYPASS = flag('--bypass-cert');
const TIMEOUT_MS = parseInt(opt('--timeout', '60'), 10) * 1000;
const PORT = parseInt(opt('--port', '0'), 10);

// ---------------- minimal CDP-over-WebSocket client ----------------
// RFC6455 client, text frames only (CDP is JSON text). No deps because
// node 20 still has no global WebSocket and this repo adds none.

function wsConnect(host, portNo, resource, onMessage, onClose) {
  const key = crypto.randomBytes(16).toString('base64');
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

  function send(obj) {
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
  const chrome = '/usr/bin/google-chrome';
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
  const wsPath = new URL(t.webSocketDebuggerUrl).pathname;

  const ws = wsConnect('127.0.0.1', portNo, wsPath, onMsg, (e) => { resultError = String(e); });

  let id = 0;
  const pending = new Map();
  const certErrors = [];
  const netFailures = [];
  const consoleErrors = [];
  let resultError = '';

  function cmd(method, params) {
    return new Promise((resolve) => {
      const mid = ++id;
      pending.set(mid, resolve);
      ws.send({ id: mid, method, params: params || {} });
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
  let painted = false, matchSnippet = '', title = '';
  while (Date.now() - t0 < TIMEOUT_MS) {
    const r = await cmd('Runtime.evaluate', {
      expression: 'JSON.stringify({p: document.body ? document.body.innerText : "", t: document.title})',
      returnByValue: true,
    });
    let doc = { p: '', t: '' };
    try { doc = JSON.parse(r && r.result && r.result.value || '{}'); } catch {}
    title = doc.t || title;
    if (markerRe.test(doc.p)) {
      painted = true;
      const i = doc.p.indexOf(marker.startsWith('re:') ? '' : marker);
      matchSnippet = doc.p.slice(Math.max(0, i), i + 200).replace(/\s+/g, ' ');
      break;
    }
    await new Promise((r2) => setTimeout(r2, 250));
  }

  const out = {
    painted,
    match: matchSnippet,
    ms: Date.now() - t0,
    mode: BYPASS ? 'bypass-cert(precert)' : 'strict-cert',
    certErrors, netFailures, consoleErrors,
    title, url,
    error: resultError || null,
  };
  console.log(JSON.stringify(out, null, 2));
  try { await cmd('Target.closeTarget', { targetId: t.id }); } catch {}
  proc.kill('SIGKILL');
  process.exit(painted ? 0 : 1);
})().catch((e) => { console.error('driver failed:', e.message); process.exit(3); });
