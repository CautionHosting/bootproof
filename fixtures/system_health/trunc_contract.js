#!/usr/bin/env node
'use strict';
// trunc_contract.js — the RENDER-MUST-NEVER-DIE gate (T-E3, chipmunk ruling
// 2026-11-10). A sibling of tier_contract.js under the SAME R3 conformance
// seed (tier_expectations.json -> trunc_crashsafe).
//
// WHY: trunc(undefined) -> j(undefined) -> JSON.stringify(undefined) returns
// the VALUE undefined (not a string) -> s.length THROWS. Because the whole
// metadata table renders in ONE synchronous pass, that throw is a DEAD PAGE,
// not a blank cell: an absent envelope field (user_data, seal_state.state_hash,
// leaf.subject/issuer) killed the entire System Health page. AGENTS.md: a
// missing source is an honest NOT PROVEN, never a crash.
//
// R3: every expectation is LANGUAGE-NEUTRAL DATA in tier_expectations.json
// (the marker word, the trunc cases, the metadata that must render without
// throwing). This file is a THIN DRIVER, run against BOTH surfaces (the
// single-file bootproof.js AND the service-worker verify.js) so the crash-safe
// property is PROVEN BYTE-FOR-BYTE-CONSISTENT across the twins - the exact
// parity the unified library's drift-gate (R2) will inherit. A future driver
// for the unified library consumes the SAME trunc_crashsafe block unmodified.
//
// We drive trunc + renderSections DIRECTLY (the vm loader pattern), not the
// browser: this is a synchronous pure-function property, the browser adds a
// ~30s leg without testing anything the direct drive does not. Exit 0 = both
// surfaces crash-safe; exit 1 = an attributed failure on a named surface.

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const SRC_DIR = path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets');
const EXPECT_PATH = path.join(__dirname, 'tier_expectations.json');

function fail(msg, detail) {
  console.error('FAIL: ' + msg);
  if (detail !== undefined) console.error('  observed: ' + detail);
  process.exit(1);
}

// Load a surface source into a vm sandbox and return {trunc, renderSections}.
// Each surface carries its own boot stubs (verify.js = SW scope, bootproof.js =
// DOM scope); the ASSERTIONS below are shared and data-driven.
function loadSurface(name, srcFile, extraStub) {
  const src = fs.readFileSync(path.join(SRC_DIR, srcFile), 'utf8');
  const sandbox = {
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, URLSearchParams,
    atob: function (s) { return Buffer.from(String(s), 'base64').toString('binary'); },
    btoa: function (s) { return Buffer.from(String(s), 'binary').toString('base64'); },
    URL: URL, setTimeout: function () { return 0; }, clearTimeout: function () {},
    setInterval: function () { return 0; }, clearInterval: function () {},
    fetch: async function () { throw new Error('trunc harness: no network'); },
    console: console,
  };
  sandbox.globalThis = sandbox;
  extraStub(sandbox);
  try {
    vm.createContext(sandbox);
    vm.runInContext(src, sandbox, { filename: srcFile });
  } catch (e) {
    fail('surface ' + name + ' failed to LOAD in the vm', e.message);
  }
  for (const fn of ['trunc', 'renderSections']) {
    if (typeof sandbox[fn] !== 'function') fail('surface ' + name + ' did not expose a global ' + fn + '()');
  }
  return { trunc: sandbox.trunc, renderSections: sandbox.renderSections };
}

function stubSW(sb) {
  sb.self = { addEventListener: function () {}, location: { origin: 'https://trunc.contract.invalid' },
    clients: { matchAll: async function () { return []; }, claim: async function () {} }, skipWaiting: function () {} };
  sb.navigator = { serviceWorker: {} };
}
function stubDOM(sb) {
  const el = function () { return { setAttribute: function () {}, style: {}, appendChild: function () {}, addEventListener: function () {}, textContent: '', innerHTML: '' }; };
  sb.document = { getElementById: function () { return null; }, addEventListener: function () {}, querySelector: function () { return null; },
    querySelectorAll: function () { return []; }, documentElement: { setAttribute: function () {} },
    createElement: el, body: { appendChild: function () {} }, head: { appendChild: function () {} } };
  sb.window = sb; sb.location = { origin: 'https://trunc.contract.invalid', href: 'https://trunc.contract.invalid/', search: '' };
  sb.self = { addEventListener: function () {} };
}

function checkSurface(name, surf, E) {
  const T = E.trunc_crashsafe;
  // 1. trunc() itself fails closed on absent input (omitted + null).
  for (const c of T.trunc_cases) {
    let got;
    try {
      got = c.how === 'omitted' ? surf.trunc() : surf.trunc(null, 24);
    } catch (e) {
      fail('surface ' + name + ': trunc() THREW on absent input (' + c.how + ') - this is a DEAD PAGE', e.message);
    }
    if (got !== c.expected) {
      fail('surface ' + name + ': trunc() absent (' + c.how + ') is not ' + JSON.stringify(c.expected), JSON.stringify(got));
    }
  }
  // 2. The RENDER SURVIVES: renderSections over the reachable-absent metadata
  //    must RETURN rows (never throw) and PAINT the fail-closed marker on the
  //    rows whose backing field is absent.
  let rows;
  try {
    rows = surf.renderSections(T.render_sections_must_survive.metadata);
  } catch (e) {
    fail('surface ' + name + ': renderSections THREW on absent fields - the whole page is dead', e.message);
  }
  if (!Array.isArray(rows) || !rows.length) fail('surface ' + name + ': renderSections returned no rows');
  for (const label of T.render_sections_must_survive.must_paint_marker_rows) {
    const row = rows.find(function (r) { return r.label === label; });
    if (!row) fail('surface ' + name + ': renderSections lost the row ' + label);
    if (String(row.value).indexOf(T.marker) === -1) {
      fail('surface ' + name + ': row ' + label + ' does not carry the fail-closed marker ' + JSON.stringify(T.marker), row.value);
    }
  }
}

function main() {
  const E = JSON.parse(fs.readFileSync(EXPECT_PATH, 'utf8'));
  if (!E.trunc_crashsafe) fail('tier_expectations.json has no trunc_crashsafe block (R3 seed missing)');
  const surfaces = [
    ['single-file bootproof.js', 'single_file/bootproof.js', stubDOM],
    ['service-worker verify.js', 'system_health/verify.js', stubSW],
  ];
  for (const [name, file, stub] of surfaces) checkSurface(name, loadSurface(name, file, stub), E);
  console.log('PASS: trunc_crashsafe (marker "' + E.trunc_crashsafe.marker + '", ' +
    E.trunc_crashsafe.trunc_cases.length + ' trunc cases + crash-safe renderSections) holds on BOTH surfaces - no absent field can kill the page');
}
main();
