#!/usr/bin/env node
// run_fixture_gate.js — one command: the single-file pivot's browser gate.
//
//   node fixtures/single_file/run_fixture_gate.js [fixture.json]
//
// Starts fixture-server.js, runs the CDP paint-poll driver against
//   /bootproof.html?fixture=1
// with the ruling-iii rows, tears the server down, and exits 0 iff:
//   * the footer painted (the self-measurement sentence, non-transformed text),
//   * memory_encryption / tpm_quote / wardend_state_chain / nonce_freshness all
//     paint PROVEN (they are required rows: NOT PROVEN or FAILED = gate fail),
//   * identity_link paints NOT PROVEN (ruling iii: the golden fixture publishes
//     no leaf PEM; NOT PROVEN is the honest pass; FAILED fails, PROVEN is a
//     surprise we surface as a failure of THIS gate because the fixture can
//     only get there by shipping a leaf that matches the signer key, which the
//     fixture does not contain),
//   * the painted self-measurement hash equals BOOTPROOF_SHA256 as pinned in
//     system_health/single_file.rs (grep the source: the gate never trusts a
//     copied constant, it reads the pin where it lives).
// Chrome requirement: /usr/bin/google-chrome (same as the cert-night driver).
'use strict';
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..', '..');
const fixture = process.argv[2] || path.join(ROOT, 'fixtures', 'system_health', 'golden.json');

function fail(msg) { console.error('FIXTURE GATE FAIL: ' + msg); process.exit(1); }

// The pin comes from the Rust source it is defined in (single source of truth).
const rs = fs.readFileSync(path.join(ROOT, 'crates/bootproof/src/system_health/single_file.rs'), 'utf8');
const pinM = rs.match(/pub const BOOTPROOF_SHA256: &str = "([0-9a-f]{64})"/);
if (!pinM) fail('BOOTPROOF_SHA256 not found in single_file.rs');
const PIN = pinM[1];

const srv = spawn('node', [path.join(__dirname, 'fixture-server.js'), '--fixture', fixture],
  { stdio: ['ignore', 'pipe', 'inherit'] });
let port = null;
srv.stdout.on('data', (d) => { const m = /LISTENING (\d+)/.exec(d.toString()); if (m) port = m[1]; });

const cleanup = () => { try { srv.kill('SIGTERM'); } catch (e) { /* gone */ } };
process.on('exit', cleanup);

const waitPort = async () => { for (let i = 0; i < 50 && !port; i++) await new Promise((r) => setTimeout(r, 100)); };

(async () => {
  await waitPort();
  if (!port) fail('fixture-server never reported a port');
  const url = `http://127.0.0.1:${port}/bootproof.html?fixture=1`;
  let out;
  try {
    out = execFileSync('node', [
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
    out = (e.stdout || '') + '';
    console.error(out);
    fail('cdp driver exited nonzero: ' + (e.message || e));
  }
  let j; try { j = JSON.parse(out); } catch (e) { fail('driver output not JSON: ' + out.slice(0, 400)); }

  if (!j.painted) fail('footer marker never painted. rows: ' + JSON.stringify(j.rows));
  // Required rows must be PROVEN (the driver only fails on FAILED, the gate
  // is stricter for the REQUIRED set: this is the golden fixture, everything
  // required is PROVEN there or the fixture/verifier drifted).
  for (const req of ['memory_encryption', 'tpm_quote', 'wardend_state_chain', 'nonce_freshness']) {
    const v = j.rows[req] && j.rows[req].verdict;
    if (v !== 'PROVEN') fail(`required row ${req} verdict ${v} != PROVEN`);
  }
  const idv = j.rows.identity_link && j.rows.identity_link.verdict;
  if (idv !== 'NOT PROVEN') fail(`identity_link verdict ${idv} != NOT PROVEN (fixture has no leaf; ruling iii)`);
  // The painted self-measurement must equal the Rust-side pin: what the
  // browser measured IS what the build pinned. The two-sentence footer
  // doctrine in action: the page prints its measurement, THIS gate is where
  // the external binding is checked.
  const meas = /measured its own served bytes as (\d+) bytes, sha256 ([0-9a-f]{64})/.exec(j.match);
  if (!meas) fail('painted text lost the measurement sentence');
  if (meas[2] !== PIN) fail(`self-measurement ${meas[2]} != BOOTPROOF_SHA256 ${PIN}`);
  const htmlBytes = fs.statSync(path.join(ROOT, 'crates/bootproof/src/assets/single_file/bootproof.html')).size;
  if (parseInt(meas[1], 10) !== htmlBytes) fail(`self-measured ${meas[1]}B != artifact ${htmlBytes}B`);
  if ((j.consoleErrors || []).some((e) => !/favicon\.ico/.test(e))) fail('unexpected console errors: ' + j.consoleErrors.join('; '));

  console.log('FIXTURE GATE PASS: painted in ' + j.ms + 'ms; required rows PROVEN; identity_link NOT PROVEN (ruling iii); self-measure ' + meas[1] + 'B == pin ' + PIN.slice(0, 16) + '...');
  cleanup();
  process.exit(0);
})().catch((e) => { cleanup(); fail(String(e && e.stack || e)); });
