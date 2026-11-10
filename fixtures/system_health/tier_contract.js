#!/usr/bin/env node
'use strict';
// tier_contract.js — the verify.js TRUST-TIER gate (T-E2 option A, chipmunk
// rulings R1 + R3, 2026-11-10).
//
// WHY: the agreement gates crosswalk channel VERDICTS; footer_contract.js
// guards the footer CLAIM. Nothing proved that the SW page renders the
// UNSIGNED envelope (env.facts, env.metadata) at the server tier. Pre-T-E2,
// verify.js painted a server-declared "proven" fact and every present
// metadata section with the PROVEN GREEN chip under a footer claiming every
// fact was browser-verified: the exact overclaim stack T-B/T-E killed on the
// single-file surface, alive on the live SW surface (the drift class the
// two-twin architecture guaranteed; R2's unification retires the twins).
//
// R3 CONFORMANCE SEED: every expectation lives in tier_expectations.json as
// LANGUAGE-NEUTRAL DATA (verdict words + chip vocab, no JS-embedded truth).
// This file is a THIN DRIVER for the verify.js surface: it loads verify.js
// byte-for-byte into a vm (the footer_contract loader pattern, no
// reimplementation), feeds each data case through the surface's OWN mapping
// pipeline (mapStatus + renderSections run BEFORE render(), so they are
// driven directly - feeding render() pre-mapped rows would bypass the tier
// law and pass for the WRONG reason), then asserts the PAINTED HTML. A future
// driver for the unified JS library (or any language implementation) consumes
// the same JSON unmodified.
// Exit 0 = all pass; exit 1 = an attributed failure.

const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

const SW_PATH = path.join(__dirname, '..', '..', 'crates', 'bootproof',
  'src', 'assets', 'system_health', 'verify.js');
const EXPECT_PATH = path.join(__dirname, 'tier_expectations.json');

function fail(msg, detail) {
  console.error('FAIL: ' + msg);
  if (detail !== undefined) console.error('  observed: ' + detail);
  process.exit(1);
}

function loadSurface() {
  const sandbox = {
    self: {
      addEventListener: function () {},
      location: { origin: 'https://tier.contract.invalid' },
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
    fetch: async function () { throw new Error('tier harness: no network'); },
    console: console,
  };
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(fs.readFileSync(SW_PATH, 'utf8'), sandbox, { filename: 'verify.js' });
  for (const fn of ['render', 'mapStatus', 'renderSections']) {
    if (typeof sandbox[fn] !== 'function') fail('verify.js did not expose a global ' + fn + '()');
  }
  return { render: sandbox.render, mapStatus: sandbox.mapStatus, renderSections: sandbox.renderSections };
}

// Pull the chip painted for a row label out of rendered html: find the
// <td class=k>NAME</td> cell, then the FIRST verdict span after it.
function chipFor(html, name) {
  const needle = '<td class=k>' + name + '</td>';
  const i = html.indexOf(needle);
  if (i < 0) fail('row "' + name + '" never painted', html.slice(0, 2000));
  const m = /<span class="verdict ([^"]+)">([^<]*)<\/span>/.exec(html.slice(i));
  if (!m) fail('no verdict chip after row "' + name + '"', html.slice(i, i + 400));
  return { cls: m[1], verdict: m[2] };
}
function hasCls(cls, want) {
  return new RegExp('(^|\\s)' + want + '(\\s|$)').test(cls);
}
function assertChip(where, chip, exp) {
  if (chip.verdict !== exp.expected_verdict) {
    fail(where + ': verdict is not ' + exp.expected_verdict, chip.verdict);
  }
  if (!hasCls(chip.cls, exp.expected_chip)) {
    fail(where + ': chip class is not ' + exp.expected_chip, chip.cls);
  }
}

function main() {
  const E = JSON.parse(fs.readFileSync(EXPECT_PATH, 'utf8'));
  const { render, mapStatus, renderSections } = loadSurface();

  // 0. The flipped MAPPING layer itself (data-driven, the pre-render tier law).
  for (const c of E.map_status) {
    const got = mapStatus(c.raw);
    if (got !== c.expected_verdict) {
      fail('mapStatus("' + c.raw + '") is not ' + c.expected_verdict, got);
    }
  }

  // 1. The PRESENT pass: sections + facts ride the surface's own pipeline,
  //    and the PAINTED html must show the server tier, never the green tier.
  const sectionsPresent = renderSections(E.metadata_present);
  const resPresent = {
    ok: false, overall: E.pass_present.checks[0].expected_verdict === 'PROVEN' ? 'NOT PROVEN' : 'NOT PROVEN',
    nonce: E.render_fixture.nonce,
    checks: E.pass_present.checks.map(function (c) { return { name: c.name, status: c.status, why: 'data-driven witness row' }; }),
    serverFacts: E.pass_present.server_facts.map(function (f) {
      return { name: f.name, value: 'v', status: mapStatus(f.raw_status), anchors: [] };
    }),
    sections: sectionsPresent,
    swLen: E.render_fixture.sw_len, swSha: E.render_fixture.sw_sha, t: E.render_fixture.t,
  };
  const htmlP = render(resPresent);
  if (typeof htmlP !== 'string' || !htmlP.length) fail('render() returned nothing for the present pass');
  for (const c of E.pass_present.checks) assertChip('checks row ' + c.name, chipFor(htmlP, c.name), c);
  for (const f of E.pass_present.server_facts) assertChip('fact row ' + f.name, chipFor(htmlP, f.name), f);
  for (const s of E.pass_present.section_expectations) assertChip('section row ' + s.label, chipFor(htmlP, s.label), s);

  // 2. The ABSENT pass (mapping layer): absence maps to NOT PROVEN, never to
  //    the server tier and never to PROVEN - asserted vs absent are different
  //    honest states ("make everything blue" is not honesty).
  const sectionsAbsent = renderSections(E.pass_absent.metadata);
  for (const s of E.pass_absent.section_expectations) {
    const row = sectionsAbsent.find(function (r) { return r.label === s.label; });
    if (!row) fail('renderSections({}) lost the row ' + s.label);
    if (row.status !== s.expected_verdict) {
      fail('absent section ' + s.label + ' is not ' + s.expected_verdict, row.status);
    }
  }

  // 3. Footer doctrine, from the PAINTED present-pass html.
  for (const s of E.footer.must_include) {
    if (htmlP.indexOf(s) === -1) fail('footer is missing ' + JSON.stringify(s));
  }
  for (const s of E.footer.must_not_include_ci) {
    if (htmlP.toLowerCase().indexOf(s.toLowerCase()) !== -1) {
      fail('footer carries the banned claim/wording ' + JSON.stringify(s));
    }
  }

  console.log('PASS: tier_expectations.json (' + E.map_status.length + ' mapStatus cases, present/absent sections, ' +
    E.pass_present.server_facts.length + ' fact rows, footer doctrine) all hold against the real verify.js pipeline + painted html');
}
main();
