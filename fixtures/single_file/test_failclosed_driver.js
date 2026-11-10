#!/usr/bin/env node
'use strict';
// test_failclosed_driver.js — the T-D fail-closed regression witness.
//
// WHY: cdp-paint-poll.js used to be permissive by default (`pass = v!=='FAILED'`),
// which let a tampered verifier that OVERCLAIMS (paints a declared pin-claim row
// PROVEN when the harness declared NOT PROVEN) still exit 0. T-D made the driver
// fail-closed: a bare --expect-row requires PROVEN, a `label=VERDICT` requires
// that exact verdict, and any mismatch fails. This test PROVES the security
// property with real headless-Chrome runs over tiny synthetic pages, so the
// fail-closed contract cannot silently regress into the permissive gate that
// would green-light an overclaiming verifier on a live box.
//
// Six assertions, each a real driver exit code against a controlled page:
//   1. OVERCLAIM caught: identity_link paints PROVEN, harness declares
//      `identity_link=NOT PROVEN`  -> driver MUST exit nonzero (mismatch).
//   2. Correct declaration passes: same page, `identity_link=PROVEN` declared
//      -> driver exits 0 (proves the rule is not "always fail").
//   3. UNDERCLAIM caught: a required row paints NOT PROVEN, harness declares it
//      bare (expected PROVEN)  -> driver MUST exit nonzero (mismatch).
//   4. Permissive opt-in: the overclaim page again, but with --permissive
//      -> driver exits 0 (proves the lenient rule is still reachable, only
//      never the default).
//   5. T-E FACTS TIER (chipmunk ruling 2026-11-10): the REAL artifact against
//      the golden envelope with a --facts-overlay [{status:"proven"}] fact ->
//      the painted fact chip MUST read SERVER-ASSERTED with the 's' class, and
//      the driver exits 0 when that is what the harness declares. (Every
//      fixture carries facts:[] — golden is blind to mapStatus — so this is
//      the ONLY witness that the server's "proven" no longer renders PROVEN.)
//   6. The tier flip is load-bearing: the SAME page, harness declares the fact
//      row bare (expected PROVEN, the pre-T-E tier) -> driver MUST exit
//      nonzero. A harness that still expects PROVEN for a server-proven fact
//      fails: the overclaim direction of the facts tier is caught.
//
// EACH assertion ALSO asserts the driver actually PAINTED the expected verdict
// (parsed from its JSON stdout), so an assertion can never pass merely because
// the page failed to render (painted:false forces a nonzero exit, which would
// make a "should-fail" case pass for the WRONG reason — the bug this witness
// must not have). Exits 0 only if all four hold with the right painted verdict.
//
// The HTTP server MUST live in the same process but the driver runs via async
// spawn (NOT spawnSync): spawnSync would freeze the event loop, the in-process
// server could not answer Chrome's page request, and every run would abort
// (net::ERR_ABORTED, painted:false). Async spawn keeps the loop free to serve.
const { spawn } = require('child_process');
const http = require('http');
const path = require('path');
const fs = require('fs');

const ROOT = path.join(__dirname, '..', '..');
const DRIVER = path.join(ROOT, 'crates/bootproof/tests/cdp-paint-poll.js');
const FSERVER = path.join(__dirname, 'fixture-server.js');
const MARKER = 'failclosed-marker';
function fail(msg) { console.error('FAIL-CLOSED WITNESS FAIL: ' + msg); process.exit(1); }
if (!fs.existsSync(DRIVER)) fail('driver not found: ' + DRIVER);

// A row painted with a given verdict word, following the driver's ID contract:
// tr id r-<label>, verdict chip id v-<label>, why span id w-<label>. Rows MUST
// live inside a <table> — a bare <tr> is invalid HTML and the parser strips it
// (a stripped row reads "not painted", which would fail for the wrong reason).
function row(label, verdict) {
  return '<tr id="r-' + label + '"><td>' + label + '</td>' +
    '<td><span class="verdict" id="v-' + label + '">' + verdict + '</span>' +
    '<span id="w-' + label + '">witness text</span></td></tr>';
}
function table(rows) { return '<table><tbody>' + rows + '</tbody></table>'; }
// Two synthetic pages: one OVERCLAIMS identity_link (PROVEN where the honest
// pin claim is NOT PROVEN); the other drops a required row to NOT PROVEN.
const overclaim = '<html><body>' + MARKER +
  table(row('identity_link', 'PROVEN') + row('memory_encryption', 'PROVEN')) +
  '</body></html>';
const underclaim = '<html><body>' + MARKER +
  table(row('identity_link', 'NOT PROVEN') + row('memory_encryption', 'NOT PROVEN')) +
  '</body></html>';

const pages = { '/overclaim': overclaim, '/underclaim': underclaim };
const srv = http.createServer(function (req, res) {
  const p = req.url.split('?')[0];
  const body = pages[p];
  if (!body) { res.writeHead(404); res.end('nope'); return; }   // favicon etc.
  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end(body);
});

// Drive the real driver against one page via ASYNC spawn (event loop stays free
// to serve the in-process server). Resolves {code, json} where json is the
// parsed driver output (null if it never produced JSON).
function drive(port, urlPath, expectArgs, extraFlags) {
  return new Promise(function (resolve) {
    const args = [DRIVER, 'http://127.0.0.1:' + port + urlPath,
      '--marker', MARKER, '--timeout', '25'];
    for (const e of expectArgs) args.push('--expect-row', e);
    if (extraFlags) args.push.apply(args, extraFlags);
    const proc = spawn('node', args);
    let out = '';
    proc.stdout.on('data', function (d) { out += d; });
    proc.on('error', function () { resolve({ code: -1, json: null, out: out }); });
    proc.on('close', function (code) {
      let json = null;
      try { json = JSON.parse(out); } catch (e) { /* not JSON */ }
      resolve({ code: code, json: json, out: out });
    });
  });
}

srv.listen(0, '127.0.0.1', async function () {
  const port = srv.address().port;
  let ok = true;
  function check(name, cond, detail) {
    if (cond) console.log('PASS  ' + name);
    else { console.error('FAIL  ' + name + ' :: ' + detail); ok = false; }
  }
  function paintedVerdict(json, label) {
    return json && json.rows && json.rows[label] && json.rows[label].verdict;
  }

  // 1. Overclaim caught: identity_link paints PROVEN, declared NOT PROVEN.
  //    Assert the row DID paint PROVEN (so the nonzero exit is a real verdict
  //    mismatch, not a blank-page false pass).
  let r = await drive(port, '/overclaim', ['identity_link=NOT PROVEN', 'memory_encryption']);
  check('overclaim identity_link=NOT PROVEN is a MISMATCH (nonzero)',
    r.code !== 0 && paintedVerdict(r.json, 'identity_link') === 'PROVEN',
    'exit ' + r.code + ', painted identity_link=' + paintedVerdict(r.json, 'identity_link') + '\n' + r.out);

  // 2. Correct declaration passes: identity_link PROVEN declared PROVEN.
  r = await drive(port, '/overclaim', ['identity_link=PROVEN', 'memory_encryption']);
  check('identity_link=PROVEN declared PROVEN exits 0 (rule is not always-fail)',
    r.code === 0 && paintedVerdict(r.json, 'identity_link') === 'PROVEN',
    'exit ' + r.code + ', painted identity_link=' + paintedVerdict(r.json, 'identity_link') + '\n' + r.out);

  // 3. Underclaim caught: required row paints NOT PROVEN, declared bare=PROVEN.
  r = await drive(port, '/underclaim', ['memory_encryption']);
  check('required memory_encryption=NOT PROVEN vs bare PROVEN is a MISMATCH (nonzero)',
    r.code !== 0 && paintedVerdict(r.json, 'memory_encryption') === 'NOT PROVEN',
    'exit ' + r.code + ', painted memory_encryption=' + paintedVerdict(r.json, 'memory_encryption') + '\n' + r.out);

  // 4. Permissive opt-in restores the old lenient rule on the overclaim page.
  r = await drive(port, '/overclaim', ['identity_link=NOT PROVEN'], ['--permissive']);
  check('--permissive restores lenient pass on the overclaim page (exit 0)',
    r.code === 0 && paintedVerdict(r.json, 'identity_link') === 'PROVEN',
    'exit ' + r.code + ', painted identity_link=' + paintedVerdict(r.json, 'identity_link') + '\n' + r.out);

  // 5 + 6. T-E facts tier, over the REAL artifact: fixture-server with a
  // facts-overlay (envelope.facts is unsigned display, so the overlay breaks
  // no signature; golden itself carries facts:[] and cannot exercise
  // mapStatus). The fact row renders under the driver's id contract as
  // fact.witness-proven.
  const factsOverlay = JSON.stringify([{ name: 'witness-proven', value: 'the server says so', status: 'proven', anchors: ['snp'] }]);
  const fsrv = spawn('node', [FSERVER, '--facts-overlay', factsOverlay],
    { stdio: ['ignore', 'pipe', 'inherit'] });
  let fport = null;
  fsrv.stdout.on('data', function (d) { const m = /LISTENING (\d+)/.exec(d.toString()); if (m) fport = m[1]; });
  for (let i = 0; i < 50 && !fport; i++) await new Promise(function (res) { setTimeout(res, 100); });
  if (!fport) { fsrv.kill('SIGTERM'); fail('facts-overlay fixture-server never reported a port'); }
  const factUrl = 'http://127.0.0.1:' + fport + '/bootproof.html?fixture=1';
  function driveUrl(url, expectArgs, cb) {
    const args = [DRIVER, url, '--marker', 'measured its own served bytes', '--timeout', '30'];
    for (const e of expectArgs) args.push('--expect-row', e);
    const proc = spawn('node', args);
    let out = '';
    proc.stdout.on('data', function (d) { out += d; });
    proc.on('close', function (code) {
      let json = null; try { json = JSON.parse(out); } catch (e) { /* */ }
      cb({ code: code, json: json, out: out });
    });
  }
  // 5. Correct tier declaration passes, AND the chip is the server tier:
  //    verdict SERVER-ASSERTED with class 's' (NOT the PROVEN green 'p').
  r = await new Promise(function (cb) { driveUrl(factUrl, ['fact.witness-proven=SERVER-ASSERTED'], cb); });
  const f5 = r.json && r.json.rows && r.json.rows['fact.witness-proven'];
  check('T-E: server-proven fact paints SERVER-ASSERTED with the s chip (exit 0)',
    r.code === 0 && f5 && f5.verdict === 'SERVER-ASSERTED' && /(^|\s)s(\s|$)/.test(f5.cls || ''),
    'exit ' + r.code + ', painted fact=' + (f5 ? f5.verdict + ' cls=' + f5.cls : 'null') + '\n' + r.out);
  // 6. The pre-T-E expectation (bare => PROVEN) MUST now fail: the flip is
  //    load-bearing, and asserting the old tier against a server fact is
  //    an overclaim the fail-closed driver catches.
  r = await new Promise(function (cb) { driveUrl(factUrl, ['fact.witness-proven'], cb); });
  const f6 = r.json && r.json.rows && r.json.rows['fact.witness-proven'];
  check('T-E: declaring the server-proven fact bare (expected PROVEN) is a MISMATCH (nonzero)',
    r.code !== 0 && f6 && f6.verdict === 'SERVER-ASSERTED',
    'exit ' + r.code + ', painted fact=' + (f6 ? f6.verdict : 'null') + '\n' + r.out);
  fsrv.kill('SIGTERM');

  srv.close();
  if (!ok) fail('one or more fail-closed assertions failed');
  console.log('FAIL-CLOSED WITNESS PASS: overclaim caught, underclaim caught, correct declaration passes, --permissive opt-in works, T-E facts tier paints SERVER-ASSERTED (s chip) and a PROVEN expectation fails it (all with real painted verdicts)');
  process.exit(0);
});
srv.on('error', function (e) { fail('server error: ' + e); });
