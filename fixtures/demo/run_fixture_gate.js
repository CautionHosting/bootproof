#!/usr/bin/env node
// run_fixture_gate.js — one command: the DEMO page's hermetic browser gate.
//
//   node fixtures/demo/run_fixture_gate.js [fixture.json]
//
// Same doctrine as the pivot's gate (fixtures/single_file/run_fixture_gate.js),
// against the DEMO artifact. Two paint passes in real Chrome (google-chrome,
// headless, CDP):
//   PASS A  marker "measured its own served bytes": required rows paint
//     PROVEN; identity_link paints NOT PROVEN (ruling iii — the golden
//     fixture publishes no leaf); the painted self-measurement equals
//     DEMO_SHA256 as pinned in crates/bootproof/src/system_health/demo.rs
//     (the pin is READ from the Rust source, never copied here) and equals
//     the on-disk artifact size.
//   PASS B  marker "this page is STAGING": the loud staging banner actually
//     paints in the browser (a CSS-hidden or markup-dropped banner would pass
//     the Rust text gate but fail here), and the document title carries the
//     manifest env label (proves the manifest -> combiner -> DOM chain end to
//     end, not just to bytes-on-disk).
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const fixture = process.argv[2] || path.join(ROOT, 'fixtures', 'system_health', 'golden.json');

function fail(msg) { console.error('DEMO GATE FAIL: ' + msg); process.exit(1); }

// The pin comes from the Rust source it is defined in (single source of truth).
const rs = fs.readFileSync(path.join(ROOT, 'crates/bootproof/src/system_health/demo.rs'), 'utf8');
const pinM = rs.match(/pub const DEMO_SHA256: &str = "([0-9a-f]{64})"/);
if (!pinM) fail('DEMO_SHA256 not found in demo.rs');
const PIN = pinM[1];

// The env label likewise comes from its sole home: the manifest.
const manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'crates/bootproof/src/assets/demo/manifest.json'), 'utf8'));
if (!manifest.env) fail('manifest.env missing');

const srv = spawn('node', [path.join(__dirname, 'fixture-server.js'), '--fixture', fixture],
  { stdio: ['ignore', 'pipe', 'inherit'] });
let port = null;
srv.stdout.on('data', (d) => { const m = /LISTENING (\d+)/.exec(d.toString()); if (m) port = m[1]; });

const cleanup = () => { try { srv.kill('SIGTERM'); } catch (e) { /* gone */ } };
process.on('exit', cleanup);

const waitPort = async () => { for (let i = 0; i < 50 && !port; i++) await new Promise((r) => setTimeout(r, 100)); };

function drive(url, marker) {
  return execFileSync('node', [
    path.join(ROOT, 'crates/bootproof/tests/cdp-paint-poll.js'), url,
    '--marker', marker,
    '--timeout', '45',
  ], { encoding: 'utf8', timeout: 90000 });
}

(async () => {
  await waitPort();
  if (!port) fail('fixture-server never reported a port');
  const url = `http://127.0.0.1:${port}/index.html?fixture=1`;

  // ---- PASS A: the verifier painted real verdicts + self-measurement binds.
  let out;
  try {
    out = drive(url, 'measured its own served bytes');
  } catch (e) {
    console.error((e.stdout || '') + '');
    fail('pass A: cdp driver exited nonzero: ' + (e.message || e));
  }
  let j; try { j = JSON.parse(out); } catch (e) { fail('pass A: driver output not JSON: ' + out.slice(0, 400)); }
  if (!j.painted) fail('pass A: footer never painted. rows: ' + JSON.stringify(j.rows));
  // (The REQUIRED row set is asserted in pass A2 with the driver's
  // --expect-row doctrine; pass A exists for the self-measurement binding.)
  const meas = /measured its own served bytes as (\d+) bytes, sha256 ([0-9a-f]{64})/.exec(j.match);
  if (!meas) fail('pass A: painted text lost the measurement sentence');
  if (meas[2] !== PIN) fail(`pass A: self-measurement ${meas[2]} != DEMO_SHA256 ${PIN}`);
  const htmlBytes = fs.statSync(path.join(ROOT, 'crates/bootproof/src/assets/demo/index.html')).size;
  if (parseInt(meas[1], 10) !== htmlBytes) fail(`pass A: self-measured ${meas[1]}B != artifact ${htmlBytes}B`);

  // ---- PASS A2: strict required-row set with the driver's --expect-row.
  let out2;
  try {
    out2 = execFileSync('node', [
      path.join(ROOT, 'crates/bootproof/tests/cdp-paint-poll.js'), url,
      '--marker', 'measured its own served bytes',
      '--timeout', '45',
      '--expect-row', 'memory_encryption',
      '--expect-row', 'tpm_quote',
      '--expect-row', 'wardend_state_chain',
      '--expect-row', 'nonce_freshness',
      '--expect-row', 'identity_link',
    ], { encoding: 'utf8', timeout: 90000 });
  } catch (e) {
    console.error((e.stdout || '') + '');
    fail('pass A2: cdp driver exited nonzero: ' + (e.message || e));
  }
  let j2; try { j2 = JSON.parse(out2); } catch (e) { fail('pass A2: driver output not JSON'); }
  for (const req of ['memory_encryption', 'tpm_quote', 'wardend_state_chain', 'nonce_freshness']) {
    const v = j2.rows[req] && j2.rows[req].verdict;
    if (v !== 'PROVEN') fail(`pass A2: required row ${req} verdict ${v} != PROVEN`);
  }
  const idv = j2.rows.identity_link && j2.rows.identity_link.verdict;
  if (idv !== 'NOT PROVEN') fail(`pass A2: identity_link verdict ${idv} != NOT PROVEN (fixture has no leaf; ruling iii)`);

  // ---- PASS B: the staging banner paints, and the title carries the label.
  let out3;
  try {
    out3 = drive(url, 'this page is STAGING');
  } catch (e) {
    console.error((e.stdout || '') + '');
    fail('pass B: banner marker never painted — the staging banner is not visible to a real browser');
  }
  let j3; try { j3 = JSON.parse(out3); } catch (e) { fail('pass B: driver output not JSON'); }
  if (!j3.painted) fail('pass B: banner marker not painted');
  if (!(j3.title || '').includes(manifest.env)) {
    fail(`pass B: document title "${j3.title}" lacks the manifest env label "${manifest.env}"`);
  }

  const errs = [].concat(j.consoleErrors || [], j2.consoleErrors || [], j3.consoleErrors || [])
    .filter((e) => !/favicon\.ico/.test(e));
  if (errs.length) fail('unexpected console errors: ' + errs.join('; '));

  console.log('DEMO GATE PASS: painted in ' + j.ms + 'ms; required rows PROVEN; identity_link NOT PROVEN (ruling iii); self-measure ' + meas[1] + 'B == pin ' + PIN.slice(0, 16) + '...; staging banner painted; title carries env label');
  cleanup();
  process.exit(0);
})().catch((e) => { cleanup(); fail(String(e && e.stack || e)); });
