#!/usr/bin/env node
// broadcast_contract.js — the message-contract gate for the page/SW handoff.
//
// Regression witness (2026-11-08): verify.js broadcast() posted the rendered
// html as a TOP-LEVEL SIBLING of result (postMessage({type,result,html})),
// while shell.html reads d.result.html — always undefined — so the live page
// hung at "Verifying…" forever even though the verdict was computed. The fix
// puts html ON result (the single contract field) and that also fixes the
// sh-ping reply, which posts lastResult with no sibling channel at all.
//
// What this drives (the REAL broadcast(), no reimplementation):
//   1. load verify.js byte-for-byte into a vm with the minimal SW surface,
//   2. drive the REAL 'activate' listener -> loop() -> runVerification (fetch
//      stubbed to reject: the honest FAILED verdict path, no fabricated green),
//   3. capture the REAL 'message'/'fetch'... no — capture the 'message'
//      listener and post an sh-ping at it, recording every postMessage,
//   4. assert the broadcast posts {type:'system-health'} with result.html a
//      NON-EMPTY string (contract), and
//   5. run shell.html's handler LOGIC (mirrored from the shell source below;
//      the shell is static HTML so it cannot be required() — the mirror is
//      asserted to match by the cargo test that greps both) and assert the
//      fake #app element's innerHTML becomes the html string (painted), and
//   6. assert the sh-ping reply carries result.html too (the ping fix).
//
// Exit 0 = all assertions pass. Exit 1 = a witnessed failure (prints the
// observed shape, so a pre-fix run is an attributable red).
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const SW_PATH = path.join(__dirname, '..', '..', 'crates', 'bootproof',
  'src', 'assets', 'system_health', 'verify.js');

// ---------------------------------------------------------------------------
// The shell handler contract, MIRRORED from shell.html (which is a static
// include_str! asset, not a module). The cargo gate test greps that the real
// shell still contains the same two load-bearing reads: r.html -> innerHTML
// and the type/result guards.
// ---------------------------------------------------------------------------
function shellHandler(d, el) {
  if (!d || d.type !== 'system-health' || !d.result) return false;
  var r = d.result;
  if (el && r.html !== undefined) { el.innerHTML = r.html; return true; }
  return false;
}

function fail(msg, detail) {
  console.error('FAIL: ' + msg);
  if (detail !== undefined) console.error('  observed: ' + JSON.stringify(detail));
  process.exit(1);
}

async function main() {
  const listeners = {}; // type -> [fn]
  const swAdd = function (type, fn) { (listeners[type] = listeners[type] || []).push(fn); };

  const fakeClients = [];
  function makeFakeClient() {
    const c = { posted: [], postMessage: function (m) { c.posted.push(m); } };
    fakeClients.push(c);
    return c;
  }

  const sandbox = {
    self: {
      addEventListener: swAdd,
      location: { origin: 'https://verify.contract.invalid' },
      clients: {
        matchAll: async function () { return fakeClients.filter(function (c) { return !c.retired; }); },
      },
      // the activate handler awaits clients.claim()
      skipWaiting: function () {},
    },
    navigator: { serviceWorker: {} },
    crypto: crypto.webcrypto,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder,
    atob: function (s) { return Buffer.from(String(s), 'base64').toString('binary'); },
    btoa: function (s) { return Buffer.from(String(s), 'binary').toString('base64'); },
    URL: URL,
    setTimeout: function () { return 0; },   // kill the refresh loop's tail
    clearTimeout: function () {},
    // The honest-failure path: the envelope fetch fails, verify.js must
    // build a FAILED verdict and STILL broadcast it (that is the bug's
    // surface: the message shape, not the verdict).
    fetch: async function () { throw new Error('contract harness: no network'); },
    console: console,
  };
  sandbox.self.clients.claim = async function () {};
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  const src = fs.readFileSync(SW_PATH, 'utf8');
  vm.runInContext(src, sandbox, { filename: 'verify.js' });

  const client = makeFakeClient();

  // (1)+(2): drive the REAL activate listener (claims clients, starts the
  // loop: runVerification -> (fetch fails) -> FAILED result -> broadcast).
  const activates = listeners['activate'] || [];
  if (!activates.length) fail('no activate listener registered by verify.js');
  let waited = null;
  const activateEvent = { waitUntil: function (p) { waited = p; } };
  activates[0](activateEvent);
  if (waited) { await waited.catch(function () {}); }
  // loop() is async and its first broadcast lands a microtask or two later.
  for (let i = 0; i < 50 && client.posted.length === 0; i++) {
    await new Promise(function (r) { setImmediate(r); });
  }

  if (client.posted.length === 0) fail('the activate->loop->broadcast path posted nothing');
  const msg = client.posted[0];

  // (4): the message contract: type + result, and result.html non-empty.
  if (!msg || msg.type !== 'system-health') fail('post type is not system-health', msg && msg.type);
  const r = msg.result;
  if (!r || typeof r !== 'object') fail('message has no result object', msg);
  const sibling = Object.prototype.hasOwnProperty.call(msg, 'html');
  const onResult = Object.prototype.hasOwnProperty.call(r, 'html');
  if (typeof r.html !== 'string' || r.html.length === 0) {
    fail('result.html is not a non-empty string (the shell reads d.result.html)', {
      'result.html': r.html, 'sibling html present': sibling,
      'note': 'pre-fix shape: html posted as a top-level SIBLING, never on result',
    });
  }

  // (5): shell LOGIC paints it: the fake #app element gains innerHTML.
  const el = { id: 'app', innerHTML: 'Verifying\u2026' };
  const painted = shellHandler(msg, el);
  if (!painted) fail('the shell handler did not paint (r.html undefined?)');
  if (el.innerHTML !== r.html) fail('the shell painted the wrong bytes');
  if (!/^</.test(el.innerHTML)) fail('painted html does not look like markup', el.innerHTML.slice(0, 40));

  // (6): the sh-ping reply: post an sh-ping at the REAL message listener;
  // the reply posts lastResult, which must carry .html post-fix.
  const messages = listeners['message'] || [];
  if (!messages.length) fail('no message listener registered by verify.js');
  const source = { posted: [], postMessage: function (m) { source.posted.push(m); } };
  messages[0]({ data: { type: 'sh-ping' }, source: source });
  if (!source.posted.length) fail('sh-ping produced no reply');
  const reply = source.posted[0];
  if (!reply || reply.type !== 'system-health' || !reply.result) fail('sh-ping reply malformed', reply);
  if (typeof reply.result.html !== 'string' || reply.result.html.length === 0) {
    fail('the sh-ping reply result.html is not a non-empty string (ping cannot paint)', {
      'reply.result.html': reply.result.html,
    });
  }

  // esc() invariant spot-check: the painted html must be the render() output
  // shape (starts with the markup render() produces) and the envelope never
  // lands raw. With fetch failing there is no untrusted envelope, so assert
  // the html came from render(): it carries the FAILED verdict class markup.
  if (el.innerHTML.indexOf('<table') === -1) fail('painted html is not render() table markup', el.innerHTML.slice(0, 80));

  console.log('PASS: broadcast posts result.html (non-empty string); shell logic paints it (' +
    el.innerHTML.length + ' bytes); sh-ping reply carries result.html');
  process.exit(0);
}

main().catch(function (e) { fail('harness crashed', String(e && e.stack || e)); });
