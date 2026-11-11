#!/usr/bin/env node
// docsig_parity.js — the I-2b browser-side witness that verify.js reproduces
// the HSM's whole-doc signature digest, and that the naive Number path does
// NOT (the false-red class).
//
// It loads the REAL service worker verifier (crates/bootproof/src/assets/
// system_health/verify.js) into the same minimal vm surface harness.js uses,
// then calls the doc-digest seam on the committed golden fixture's doc bytes
// through TWO parses of the SAME bytes:
//
//   * docDigestTokenSafe: the shipped path. The six u64 object members are
//     captured as digit TOKENS before coercion, so a handle > 2^53 keeps its
//     low bits. This must equal the committed pin in golden.meta.json
//     (wardend_doc_digest_hex), which is the SAME value the Rust
//     canonical_doc_digest recomputes (pinned in the plugin agreement test).
//     That is the cross-implementation parity: JS == Rust, byte for byte.
//
//   * docDigestNaive: the SAME canonicalizer fed a plain JSON.parse, where a
//     >2^53 handle round-trips through Number and LOSES the low bits. It must
//     DIVERGE from the pin. That divergence is the negative twin: it proves
//     the hazard is real (the browser would verify the wrong digest and
//     false-red an honest doc) and that the token path is what closes it.
//
// Emits { pin, token_safe, naive, token_safe_matches_pin, naive_matches_pin }
// on stdout; the Rust gate launcher asserts the two booleans are true/false.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const FIX = path.join(__dirname, 'golden.json');
const META = path.join(__dirname, 'golden.meta.json');

const sandbox = {
  self: { addEventListener: function () {}, location: { origin: 'https://golden.invalid' },
          clients: { matchAll: async function () { return []; } } },
  crypto: crypto.webcrypto,
  TextEncoder: TextEncoder,
  TextDecoder: TextDecoder,
  atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
  btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
  setTimeout: setTimeout, clearTimeout: clearTimeout, console: console,
};
sandbox.globalThis = sandbox;
vm.createContext(sandbox);
const src = fs.readFileSync(
  path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets', 'system_health', 'verify.js'),
  'utf8');
vm.runInContext(src, sandbox, { filename: 'verify.js' });
const V = sandbox.self.__bootproof_verifier__;
if (!V || !V.docDigestTokenSafe || !V.docDigestNaive) {
  throw new Error('verify.js did not expose the doc-digest seam');
}

(async function () {
  const env = JSON.parse(fs.readFileSync(FIX, 'utf8'));
  const meta = JSON.parse(fs.readFileSync(META, 'utf8'));
  const ev = (env.bundle.evidence || []).find((e) => e.channel === 'wardend');
  if (!ev) throw new Error('golden.json carries no wardend channel');
  // The doc is the raw JSON text the HSM signed; the seam takes that text and
  // runs the shipped canonicalizer over it (token-safe vs naive parse).
  const docText = Buffer.from(ev.doc, 'base64').toString('utf8');

  const pin = String(meta.wardend_doc_digest_hex).toLowerCase();
  const tokenSafe = (await V.docDigestTokenSafe(docText)).toLowerCase();
  const naive = (await V.docDigestNaive(docText)).toLowerCase();

  // D4: the digest v2 twin. The fixture's doc plus the fixture's OWN
  // bundle nonce must reproduce wardend_doc_digest_v2_hex through the
  // SHIPPED v2 canonicalizer — the same value the fixture's signature
  // closes under and the Rust canonical_doc_digest_v2 recomputes. If the
  // JS v2 canonicalizer drifts, this diverges and the gate fails.
  const pinV2 = String(meta.wardend_doc_digest_v2_hex).toLowerCase();
  const fixtureNonce = String(env.bundle.nonce);
  const tokenSafeV2 = (await V.docDigestV2TokenSafe(docText, fixtureNonce)).toLowerCase();
  // The v2 fail-closed property, computed here rather than asserted
  // blind: the SAME doc under the v1 canonicalizer and under v2 must be
  // two different digests (marker + nonce inputs), which is exactly why
  // a v1 signature cannot close under v2 and vice versa.
  if (tokenSafeV2 === tokenSafe) throw new Error('digest v2 equals v1: the marker/nonce inputs are not in the byte stream');

  process.stdout.write(JSON.stringify({
    pin: pin,
    token_safe: tokenSafe,
    naive: naive,
    token_safe_matches_pin: tokenSafe === pin,
    naive_matches_pin: naive === pin,
    pin_v2: pinV2,
    token_safe_v2: tokenSafeV2,
    token_safe_v2_matches_pin: tokenSafeV2 === pinV2,
  }, null, 1) + '\n');
})().catch(function (e) {
  console.error('docsig_parity harness error: ' + (e && e.stack || e));
  process.exit(1);
});
