#!/usr/bin/env node
// harness.js — run the REAL service worker verifier (verify.js) headless on
// a golden fixture, and print its fact verdicts as JSON on stdout.
//
// This is the node harness the cross-verifier agreement tests use:
//   node fixtures/system_health/harness.js <fixture.json>
// prints:
//   { "facts": [ {name,status,why}, ... ],        // the three REQUIRED facts
//     "subs":  [ {name,status,why}, ... ] }       // every sub-check, flat
//
// verify.js is loaded byte-for-byte from crates/bootproof/src/assets/
// system_health/verify.js into a vm context with the minimal service-worker
// surface it needs at load time (crypto.subtle, TextEncoder/Decoder, a
// no-op addEventListener on `self`). Nothing is monkey-patched inside the
// verifier: the same code that runs in the browser runs here, which is the
// entire point of the two-verifiers-agree gate.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const fixturePath = process.argv[2];
if (!fixturePath) {
  console.error('usage: harness.js <fixture.json>');
  process.exit(2);
}
const env = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
const meta = JSON.parse(fs.readFileSync(path.join(__dirname, 'golden.meta.json'), 'utf8'));
const nonceHex = meta.nonce_hex;

// The service-worker environment: exactly what verify.js touches at load
// and in the three channel checks. No fetch, no caches, no DOM.
const sandbox = {
  self: {
    addEventListener: function () {},
    location: { origin: 'https://golden.invalid' },
    clients: { matchAll: async function () { return []; } },
  },
  crypto: crypto.webcrypto,
  TextEncoder: TextEncoder,
  TextDecoder: TextDecoder,
  // The service worker has atob/btoa; the vm context does not, and
  // verify.js's b64ToBuf (used by wireBytes for EVERY bundle field decode)
  // needs it. Byte-identical semantics to the browser's:
  atob: function (s) { return Buffer.from(String(s), 'base64').toString('binary'); },
  btoa: function (s) { return Buffer.from(String(s), 'binary').toString('base64'); },
  setTimeout: setTimeout,
  clearTimeout: clearTimeout,
  console: console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
const src = fs.readFileSync(
  path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets', 'system_health', 'verify.js'),
  'utf8');
vm.runInContext(src, sandbox, { filename: 'verify.js' });
const V = sandbox.self.__bootproof_verifier__;
if (!V) throw new Error('verify.js did not expose __bootproof_verifier__');

// The evidence decode (mirrors verify.js's own decodeEvidence through the
// exposed seam: same base64 -> bytes path the page uses).
function decodeEvidence(ev) {
  if (!ev) return null;
  const dec = new TextDecoder();
  void dec;
  const b64ToBuf = function (s) {
    return new Uint8Array(Buffer.from(s, 'base64'));
  };
  const anchors = {};
  for (const k of Object.keys(ev.anchors || {})) anchors[k] = b64ToBuf(ev.anchors[k]);
  return { channel: ev.channel, doc: b64ToBuf(ev.doc), anchors: anchors };
}

(async function () {
  const bundle = env.bundle || {};
  const evs = bundle.evidence || [];
  const find = (c) => evs.find(function (e) { return e.channel === c; });
  const snpEv = decodeEvidence(find('snp'));
  const tpmEv = decodeEvidence(find('tpm2'));

  const facts = [];
  const subs = [];
  const push = function (r) {
    facts.push({ name: r.name, status: r.status, why: r.why });
    for (const s of r.subs || []) subs.push({ name: s.name, status: s.status, why: s.why });
  };
  push(await V.checkSnp(snpEv, nonceHex));
  push(await V.checkTpm2(tpmEv, nonceHex, bundle));
  push(await V.checkStateLog(env));

  process.stdout.write(JSON.stringify({ facts: facts, subs: subs }, null, 1) + '\n');
})().catch(function (e) {
  console.error('harness error: ' + (e && e.stack || e));
  process.exit(1);
});
