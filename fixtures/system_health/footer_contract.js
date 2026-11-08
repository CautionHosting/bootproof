#!/usr/bin/env node
// footer_contract.js: the local-verification-claim gate (AMI-2).
//
// The page must TELL the user, in its own words, that every fact was verified
// IN THEIR BROWSER by the service worker that rendered the page, with a
// same-origin link to the verifier source. This drives the REAL render() (no
// reimplementation: load verify.js byte-for-byte into a vm and grab render,
// which uses the real esc/cls), then asserts:
//
//   1. The painted footer states the local-verification claim plainly AND
//      carries the relative /verify.js.src link (same-origin, already served).
//   2. HONESTY: the claim is about WHERE verification ran, NOT the verdicts,
//      so it must STILL appear on a result whose rows are FAILED/NOT PROVEN
//      (a red verdict from a local verifier is still a local verifier). This
//      is the security-doctrine load-bearing case: a footer that only promised
//      "verified locally" on green rows would be a green-only reassurance.
//   3. NO SELF-HASH, NO CLAIM: render() the fetch-failure shape (swLen unset:
//      the SW could not read its own bytes), and the footer must be ABSENT.
//      The local claim only ships alongside the exact bytes+hash it identifies.
//   4. No over-claim wording ("you are secure" and friends) anywhere.
//
// A pre-AMI-2 verify.js (footer = "verifier: N bytes...") FAILS assertions 1
// and 2: that is the witnessed-red falsification, run separately.
// Exit 0 = all pass; exit 1 = an attributed failure.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const SW_PATH = path.join(__dirname, '..', '..', 'crates', 'bootproof',
  'src', 'assets', 'system_health', 'verify.js');

function fail(msg, detail) {
  console.error('FAIL: ' + msg);
  if (detail !== undefined) console.error('  observed: ' + detail);
  process.exit(1);
}

function loadRender() {
  const listeners = {};
  const sandbox = {
    self: {
      addEventListener: function (t, fn) { (listeners[t] = listeners[t] || []).push(fn); },
      location: { origin: 'https://verify.contract.invalid' },
      clients: { matchAll: async function () { return []; }, claim: async function () {} },
      skipWaiting: function () {},
    },
    navigator: { serviceWorker: {} },
    crypto: crypto.webcrypto,
    TextEncoder: TextEncoder,
    TextDecoder: TextDecoder,
    atob: function (s) { return Buffer.from(String(s), 'base64').toString('binary'); },
    btoa: function (s) { return Buffer.from(String(s), 'binary').toString('base64'); },
    URL: URL,
    setTimeout: function () { return 0; },
    clearTimeout: function () {},
    fetch: async function () { throw new Error('footer harness: no network'); },
    console: console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(SW_PATH, 'utf8'), sandbox, { filename: 'verify.js' });
  if (typeof sandbox.render !== 'function') fail('verify.js did not expose a global render()');
  return sandbox.render;
}

function main() {
  const render = loadRender();

  // (2) HONESTY WITNESS: a FAILED result (a red row) must STILL carry the
  //     local-verification claim, because the claim is about the verifier's
  //     location, not its verdict. swLen is set: the SW knows its own bytes.
  const red = {
    ok: false, overall: 'FAILED', nonce: 'aa'.repeat(32),
    checks: [
      { name: 'memory_encryption', status: 'FAILED', why: 'report shows no memory encryption' },
      { name: 'wardend_state_chain', status: 'NOT PROVEN', why: 'doc signature absent' },
    ],
    serverFacts: [], sections: [],
    swLen: 75394, swSha: 'ab'.repeat(32), t: 1700000000000,
  };
  const redHtml = render(red);
  if (typeof redHtml !== 'string' || redHtml.length === 0) fail('render() returned no html for a FAILED result');
  if (redHtml.indexOf('browser-verified proofs') === -1) fail('gate capture anchor "browser-verified proofs" vanished from render()');
  if (!/verified in your browser/i.test(redHtml)) {
    fail('FAILED row: the local-verification claim is MISSING (the AMI-2 footer must be verdict-independent)', redHtml);
  }
  if (!/rendered locally, not by the server/i.test(redHtml)) {
    fail('FAILED row: the "rendered locally, not by the server" claim is missing', redHtml);
  }
  if (redHtml.indexOf('href="/verify.js.src"') === -1) {
    fail('the relative /verify.js.src link is missing from the footer', redHtml);
  }
  // (4) no over-claim wording, even though this is a security page.
  if (/you are secure|you'?re secure|fully secure|totally safe/i.test(redHtml)) {
    fail('the footer over-claims security; the claim must be about WHERE verification ran', redHtml);
  }
  // The claim rides ALONGSIDE the bytes it identifies (the self-hash is the
  // evidence for "the service worker shown below"), on the same footer.
  if (redHtml.indexOf('75394 bytes') === -1 || redHtml.indexOf('ab'.repeat(32)) === -1) {
    fail('the footer claim is not accompanied by the exact bytes+hash it identifies', redHtml);
  }

  // (3) NO SELF-HASH, NO CLAIM: the fetch-failure shape has swLen unset (the
  //     SW could not read its own bytes), so the footer must NOT make a local
  //     claim it cannot back with an identifiable verifier.
  const noSw = {
    ok: false, overall: 'FAILED', nonce: 'bb'.repeat(32),
    error: 'fetch /health/api failed: Error: no network',
    checks: [], serverFacts: [], t: 1700000000000,
  };
  const noSwHtml = render(noSw);
  if (/verified in your browser/i.test(noSwHtml)) {
    fail('the local-verification claim appeared WITHOUT swLen bytes to back it (no self-hash, no claim)', noSwHtml);
  }
  if (noSwHtml.indexOf('href="/verify.js.src"') !== -1) {
    fail('the /verify.js.src footer link appeared without swLen (footer must stay gated on the self-hash)', noSwHtml);
  }

  console.log('PASS: footer states the local-verification claim + relative source link on a FAILED row ' +
    '(verdict-independent, honest), ships with the exact bytes+hash, and is absent when swLen is unset (no self-hash, no claim).');
  process.exit(0);
}

main();
