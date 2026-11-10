// harness.js — the ONLY shared code in the conformance tree (ratified layout,
// chipmunk 2026-11-10). Evaluator over the closed 4-kind
// vocabulary + zero-truth loader shims. NO expected values live here: every
// expectation is read from the property's expectations.json (TRUTH-ZERO law).
//
// Class dispatch (the neutrality law): VALUE-kinds consume impl.value_fns and
// are FREE for any impl. OUTPUT-SHAPE kinds consume impl.render; an impl with
// no render entry gets that kind SKIPPED-with-reason, NEVER faked green — and
// the driver EXITS 1 on any skip unless --allow-skip is passed, because
// silently passing a render-dependent property is exactly the "fake green" the
// law bans. So a renderless impl cannot green-light a rows_contain property.
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const crypto = require('crypto');

// The repo asset root, overridable (BP_ASSETS) for cross-tree experiments.
// In-repo default resolves from fixtures/conformance/ to the shipped assets.
const ASSETS = process.env.BP_ASSETS
  || path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets');

function baseSandbox() {
  const sb = {
    crypto: crypto.webcrypto, TextEncoder, TextDecoder, URLSearchParams,
    atob: (s) => Buffer.from(String(s), 'base64').toString('binary'),
    btoa: (s) => Buffer.from(String(s), 'binary').toString('base64'),
    URL, setTimeout: () => 0, clearTimeout: () => {}, setInterval: () => 0, clearInterval: () => {},
    fetch: async () => { throw new Error('harness: no network'); }, console,
  };
  sb.globalThis = sb;
  return sb;
}
function stubDOM(sb) {
  const el = () => ({ setAttribute() {}, style: {}, appendChild() {}, addEventListener() {}, textContent: '', innerHTML: '' });
  sb.document = { getElementById: () => null, addEventListener() {}, querySelector: () => null, querySelectorAll: () => [],
    documentElement: { setAttribute() {} }, createElement: el, body: { appendChild() {} }, head: { appendChild() {} } };
  sb.window = sb; sb.location = { origin: 'https://c.invalid', href: 'https://c.invalid/', search: '' };
  sb.self = { addEventListener() {} };
}
function stubSW(sb) {
  sb.self = { addEventListener() {}, location: { origin: 'https://c.invalid' },
    clients: { matchAll: async () => [], claim: async () => {} }, skipWaiting() {} };
  sb.navigator = { serviceWorker: {} };
}
function loadSurface(rel, stub) {
  const src = fs.readFileSync(path.join(ASSETS, rel), 'utf8');
  const sb = baseSandbox(); stub(sb);
  vm.createContext(sb);
  vm.runInContext(src, sb, { filename: rel });
  return sb;
}

// IMPL HANDLES: name -> { value_fns:[...], render?:fnName, load:()=>sandbox }.
// Loaders are the ONLY env-specific code, and they carry ZERO truth: they just
// hand back the surface's own functions. lib-node is the Q4 proof entry, not
// yet built — it errors honestly rather than pretending.
const IMPLS = {
  'bootproof-js': { value_fns: ['mapStatus', 'trunc', 'renderSections'], render: 'renderSections',
    load: () => loadSurface('single_file/bootproof.js', stubDOM) },
  'verify-js': { value_fns: ['mapStatus', 'trunc', 'renderSections'], render: 'renderSections',
    load: () => loadSurface('system_health/verify.js', stubSW) },
  'lib-node': { value_fns: [], load: () => { throw new Error('impl lib-node not built yet (post-pin-cut R2 artifact)'); } },
  // Test-only handle proving the neutrality law: exposes value_fns but NO render.
  'renderless-js': { value_fns: ['mapStatus', 'trunc'], load: () => loadSurface('single_file/bootproof.js', stubDOM) },
};

function call(sb, fn, args) {
  if (typeof sb[fn] !== 'function') throw new Error('impl missing fn: ' + fn);
  return sb[fn].apply(null, args || []);
}

function run(expectPath, implName, opts) {
  opts = opts || {};
  const spec = JSON.parse(fs.readFileSync(expectPath, 'utf8'));
  const impl = IMPLS[implName];
  if (!impl) { console.error('FAIL unknown impl ' + implName); return 1; }
  let sb;
  try { sb = impl.load(); } catch (e) { console.error('FAIL impl ' + implName + ' load: ' + e.message); return 1; }
  const skipable = (kind) => kind === 'rows_contain' && !impl.render;

  let pass = 0, fails = 0, skipped = 0;
  for (const c of spec.checks) {
    if (skipable(c.kind)) {
      skipped++;
      console.log('SKIP ' + c.id + ' :: impl ' + implName + ' declares no render entry (output-shape kind, never faked green)');
      continue;
    }
    try {
      if (c.kind === 'call_equals') {
        const got = call(sb, c.fn, c.args);
        if (got === c.expect) { pass++; console.log('PASS ' + c.id); }
        else { fails++; console.log('FAIL ' + c.id + ' :: observed ' + JSON.stringify(got)); }
      } else if (c.kind === 'survives') {
        const got = call(sb, c.fn, c.args);   // must RETURN, never throw
        if (Array.isArray(got)) { pass++; console.log('PASS ' + c.id); }
        else { fails++; console.log('FAIL ' + c.id + ' :: did not return a row array'); }
      } else if (c.kind === 'map_rows') {
        const rows = call(sb, c.fn, c.args);
        let bad = null;
        for (const r of c.rows) {
          const row = rows.find((x) => x.label === r.label);
          if (!row) { bad = r.label + ' ABSENT'; break; }
          if (row.status !== r.status) { bad = r.label + '=' + row.status + ' expected ' + r.status; break; }
        }
        if (!bad) { pass++; console.log('PASS ' + c.id); }
        else { fails++; console.log('FAIL ' + c.id + ' :: ' + bad); }
      } else if (c.kind === 'rows_contain') {
        const rows = call(sb, impl.render, c.args);
        let bad = null;
        for (const r of c.rows) {
          const row = rows.find((x) => x.label === r.label);
          if (!row) { bad = r.label + ' ABSENT'; break; }
          if (r.status && row.status !== r.status) { bad = r.label + ' status ' + row.status; break; }
          if (r.value_contains && String(row.value).indexOf(r.value_contains) === -1) {
            bad = r.label + ' value lacks ' + JSON.stringify(r.value_contains); break;
          }
        }
        if (!bad) { pass++; console.log('PASS ' + c.id); }
        else { fails++; console.log('FAIL ' + c.id + ' :: ' + bad); }
      } else {
        fails++; console.log('FAIL ' + c.id + ' :: unknown kind ' + c.kind);
      }
    } catch (e) {
      fails++; console.log('FAIL ' + c.id + ' :: threw ' + e.message);
    }
  }
  console.log('SUMMARY ' + spec.schema + ' [' + implName + '] pass=' + pass + ' fail=' + fails + ' skip=' + skipped);
  if (fails) return 1;
  if (skipped && !opts.allowSkip) return 1; // a skip is NOT a green without an explicit operator opt-in
  return 0;
}

module.exports = { run };
