#!/usr/bin/env node
// run_fixture_gate.js — one command: the single-file pivot's browser gate.
//
//   node fixtures/single_file/run_fixture_gate.js [fixture.json]
//
// Starts fixture-server.js, runs TWO CDP passes against the served artifact,
// tears the server down, and exits 0 iff both hold:
//
// PASS A — the STATIC PAINT (the pending-first render law, browser-side):
//   loads /bootproof.html?static=1 (the mode that runs NOTHING: no fetch, no
//   timer, no flip) and asserts EVERY r-* row paints exactly PENDING with
//   the pd chip class, and the page touched ZERO subresources (the document
//   request itself aside). All-pending + zero network IS the JS-disabled
//   read: what this pass paints is what a script-less browser reads.
//
// PASS B — the FIXTURE RUN:
//   loads /bootproof.html?fixture=1 over the golden envelope + frozen nonce.
//   The driver runs FAIL-CLOSED per row (T-D): each --expect-row declares the
//   verdict the golden fixture MUST paint, and a mismatch (either direction:
//   an overclaim to PROVEN, or a required row underclaiming to NOT PROVEN)
//   fails the driver. The declarations below are the fixture's ground truth:
//   * memory_encryption / tpm_quote / wardend_state_chain / nonce_freshness
//     declare PROVEN (bare) — a required row that is NOT PROVEN or FAILED now
//     fails at the DRIVER, not just the wrapper below.
//   * identity_link declares NOT PROVEN (ruling iii: the golden fixture
//     publishes no leaf PEM; NOT PROVEN is the honest pass; the driver now
//     fails a PROVEN there as an overclaim, and FAILED as a mismatch).
//   * seal_state declares PROVEN (byte-attested by the wardend doc signature).
//   * cert_chain declares NOT PROVEN (no leaf PEM published; the honest render).
//   * user_data declares PROVEN (the golden envelope publishes user-data).
//   The wrapper below re-asserts each independently (belt and suspenders): the
//   driver being green is necessary, never sufficient, for THIS gate to pass.
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

// The envelope this gate drives (the gate reads the fixture directly so the
// user_data witness check compares painted bytes against the SAME envelope
// the server answers with).
const envelope = JSON.parse(fs.readFileSync(fixture, 'utf8'));
const UD = ((envelope.metadata || {}).user_data) || '';

const srv = spawn('node', [path.join(__dirname, 'fixture-server.js'), '--fixture', fixture],
  { stdio: ['ignore', 'pipe', 'inherit'] });
let port = null;
srv.stdout.on('data', (d) => { const m = /LISTENING (\d+)/.exec(d.toString()); if (m) port = m[1]; });

const cleanup = () => { try { srv.kill('SIGTERM'); } catch (e) { /* gone */ } };
process.on('exit', cleanup);

const waitPort = async () => { for (let i = 0; i < 50 && !port; i++) await new Promise((r) => setTimeout(r, 100)); };

function drive(args, timeout) {
  let out;
  try {
    out = execFileSync('node', [path.join(ROOT, 'crates/bootproof/tests/cdp-paint-poll.js'), ...args],
      { encoding: 'utf8', timeout });
  } catch (e) {
    out = (e.stdout || '') + '';
    console.error(out);
    fail('cdp driver exited nonzero: ' + (e.message || e));
  }
  try { return JSON.parse(out); } catch (e) { fail('driver output not JSON: ' + out.slice(0, 400)); }
}

(async () => {
  await waitPort();
  if (!port) fail('fixture-server never reported a port');

  // ---- PASS A: the static paint (pending-first law, zero network) ----------
  const staticUrl = `http://127.0.0.1:${port}/bootproof.html?static=1`;
  const sa = drive([staticUrl, '--all-pending', '--max-subresource-requests', '0', '--timeout', '20'], 60000);
  if (!sa.painted) fail('static pass: rows never painted');
  if (!sa.allPending || sa.allPending.count < 50) fail('static pass: only ' + (sa.allPending && sa.allPending.count) + ' rows found (expected the full pending set)');
  if (sa.allPending.bad.length) fail('static pass: rows not pending at first paint: ' + sa.allPending.bad.join(', '));
  if (sa.subresourceRequests !== 0) fail('static pass: the page touched the network: ' + JSON.stringify(sa.requests));
  if ((sa.consoleErrors || []).some((e) => !/favicon\.ico/.test(e))) fail('static pass console errors: ' + sa.consoleErrors.join('; '));

  // ---- PASS B: the fixture run ---------------------------------------------
  const url = `http://127.0.0.1:${port}/bootproof.html?fixture=1`;
  const j = drive([url,
    '--marker', 'measured its own served bytes',
    '--timeout', '45',
    // Fail-closed declarations (T-D): a bare label requires PROVEN; a
    // `label=NOT PROVEN` label requires that exact honest verdict. These are
    // the golden fixture's ground truth (captured by a raw driver run, not
    // guessed). Any drift — a required row dropping to NOT PROVEN, or an
    // honest pin claim climbing to PROVEN — now fails the driver itself.
    '--expect-row', 'memory_encryption',
    '--expect-row', 'tpm_quote',
    '--expect-row', 'wardend_state_chain',
    '--expect-row', 'nonce_freshness',
    '--expect-row', 'identity_link=NOT PROVEN',
    '--expect-row', 'user_data',
    '--expect-row', 'seal_state',
    '--expect-row', 'cert_chain=NOT PROVEN',
  ], 90000);

  if (!j.painted) fail('footer marker never painted. rows: ' + JSON.stringify(j.rows));
  // Required rows must be PROVEN. The fail-closed driver already enforced this
  // (a bare --expect-row requires PROVEN); the wrapper re-asserts it so the
  // driver being green is necessary, never sufficient, for THIS gate to pass.
  for (const req of ['memory_encryption', 'tpm_quote', 'wardend_state_chain', 'nonce_freshness']) {
    const v = j.rows[req] && j.rows[req].verdict;
    if (v !== 'PROVEN') fail(`required row ${req} verdict ${v} != PROVEN`);
  }
  const idv = j.rows.identity_link && j.rows.identity_link.verdict;
  if (idv !== 'NOT PROVEN') fail(`identity_link verdict ${idv} != NOT PROVEN (fixture has no leaf; ruling iii)`);
  // The lifecycle rows: flipped out of PENDING by the pass (the demo's
  // witness set — a row still PENDING after a finished pass is the silent
  // blank the pending-first pivot must never ship).
  for (const lc of ['user_data', 'seal_state', 'cert_chain']) {
    const v = j.rows[lc] && j.rows[lc].verdict;
    if (!v || v === 'PENDING') fail(`lifecycle row ${lc} never flipped (verdict ${v})`);
  }
  // The user_data row witnesses the envelope's CURRENT user-data text (the
  // hot-add witness): the flip wrote the envelope value into the row's why
  // span, and the driver dumped the painted text. The value must be THERE
  // (trunc() cuts at 120 chars + an ellipsis; the golden value is shorter
  // than that, so the full string must appear).
  const udRow = j.rows.user_data;
  if (udRow.verdict !== 'PROVEN') fail(`user_data verdict ${udRow.verdict} != PROVEN (the golden envelope publishes user-data)`);
  if (!UD) fail('the golden envelope lost its user_data (the witness check needs it)');
  if (!udRow.why_text || udRow.why_text.indexOf(UD) < 0) {
    fail(`user_data row does not carry the envelope value. painted: ${JSON.stringify(udRow.why_text)} envelope: ${JSON.stringify(UD.slice(0, 80))}`);
  }
  // The self-measurement must equal the Rust-side pin: what the
  // browser measured IS what the build pinned. The two-sentence footer
  // doctrine in action: the page prints its measurement, THIS gate is where
  // the external binding is checked.
  const meas = /measured its own served bytes as (\d+) bytes, sha256 ([0-9a-f]{64})/.exec(j.match);
  if (!meas) fail('painted text lost the measurement sentence');
  if (meas[2] !== PIN) fail(`self-measurement ${meas[2]} != BOOTPROOF_SHA256 ${PIN}`);
  const htmlBytes = fs.statSync(path.join(ROOT, 'crates/bootproof/src/assets/dist/bootproof.html')).size;
  if (parseInt(meas[1], 10) !== htmlBytes) fail(`self-measured ${meas[1]}B != artifact ${htmlBytes}B`);
  if ((j.consoleErrors || []).some((e) => !/favicon\.ico/.test(e))) fail('unexpected console errors: ' + j.consoleErrors.join('; '));

  console.log('FIXTURE GATE PASS: static pass all-pending + zero network; fixture pass ' + j.ms + 'ms; required rows PROVEN; identity_link NOT PROVEN (ruling iii); lifecycle rows flipped; self-measure ' + meas[1] + 'B == pin ' + PIN.slice(0, 16) + '...');
  cleanup();
  process.exit(0);
})().catch((e) => { cleanup(); fail(String(e && e.stack || e)); });
