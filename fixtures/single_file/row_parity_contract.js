#!/usr/bin/env node
// row_parity_contract.js — the pending-first row set pinned from BOTH sides.
//
// THE LAW: every row the verifier can emit must exist as a static PENDING row
// in the shell, and every static row must be a row the flip engine knows (by
// name, or as the one dynamic table placeholder). A verifier that learns a
// new check without a static row would silently render nothing for it (the
// flip returns false); a static row the verifier can never reach would sit
// PENDING forever. Both are lies by omission, so both fail this contract.
//
// WHY A SCAN AND NOT ONLY A RUN: the golden fixture walks ONE path through
// the checks. Names that only appear on untaken branches (tpm.ak on the
// non-P-256 AK path, snp.vlek_sig on the bad-signature path, the failTpm
// shapes, ...) never surface in a fixture run. This contract therefore
// derives the emitted-name set from the SOURCE TEXT: every string literal
// passed to sub(), every finishFact first argument, every renderSections
// label. That is an over-approximation on purpose (a literal in a comment
// or test string only ADDS a required static row, which is the safe
// direction: an honest extra pending row beats a silently missing one).
//
// Directions checked:
//   1. emitted(source)  ⊆  static ids        (no orphan verdicts)
//   2. static ids       ⊆  emitted ∪ KNOWN_FLIPPABLE ∪ {server-facts}
//                                            (no unreachable pendings)
//   3. every static row ships PENDING with class pd (the render law)
//   4. the artifact (dist/) and the shell carry the same static row ids
//      (the splice changed nothing about the row set)
//
// Exit 0 iff all four hold. Zero deps.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const SRC = path.join(ROOT, 'crates', 'bootproof', 'src', 'assets', 'single_file');
const ART = path.join(ROOT, 'crates', 'bootproof', 'src', 'assets', 'dist', 'bootproof.html');

function fail(msg) { console.error('ROW PARITY FAIL: ' + msg); process.exit(1); }

const shell = fs.readFileSync(path.join(SRC, 'bootproof.html'), 'utf8');
const js = fs.readFileSync(path.join(SRC, 'bootproof.js'), 'utf8');
let art = null;
try { art = fs.readFileSync(ART, 'utf8'); } catch (e) { /* gate 4 reports */ }

// --- static rows from the shell: id -> whole line -----------------------------
function staticRows(text) {
  const rows = {};
  for (const line of text.split('\n')) {
    const m = /^\s*<tr id="r-([A-Za-z0-9_.-]+)"([^>]*)>/.exec(line);
    if (m) rows[m[1]] = { line: line.trim(), attrs: m[2] };
  }
  return rows;
}
const shellRows = staticRows(shell);
const shellIds = Object.keys(shellRows);
if (shellIds.length < 50) fail('shell has only ' + shellIds.length + ' static rows (expected the full set)');

// --- 3: the render law on every static row ------------------------------------
for (const id of shellIds) {
  const { line, attrs } = shellRows[id];
  if (!/class="pd"/.test(attrs)) fail('static row ' + id + ' lacks class="pd": ' + line.slice(0, 120));
  const chip = new RegExp('<span class="verdict pd" id="v-' + id.replace(/[.]/g, '\\.') + '">PENDING</span>');
  if (!chip.test(line)) fail('static row ' + id + ' does not ship a PENDING chip: ' + line.slice(0, 160));
}

// --- emitted names from the verifier source ------------------------------------
// sub("name", ...), sub('name', ...), finishFact("name", ...), and the
// renderSections label: "name" positions. Quoted first args to sub/finishFact
// plus every label: "<name>" literal.
function emittedNames(src) {
  const names = new Set();
  let m;
  const subRe = /\bsub\(\s*"([A-Za-z0-9_.]+)"/g;
  while ((m = subRe.exec(src))) names.add(m[1]);
  const factRe = /\bfinishFact\(\s*"([A-Za-z0-9_.]+)"/g;
  while ((m = factRe.exec(src))) names.add(m[1]);
  const labelRe = /label:\s*"([A-Za-z0-9_.]+)"/g;
  while ((m = labelRe.exec(src))) names.add(m[1]);
  // Object-literal subs: subs.push({ name: "identity_link.pin", ... }). The
  // identity subs are the ONLY row names passed as object literals, so the
  // scan is scoped to the checkIdentity region — scanning the whole file
  // witnesses false positives (WebCrypto algorithm records like
  // { name: "ECDSA", namedCurve: ... } are algorithm names, not row names;
  // the contract found exactly that on first run, which is the kind of
  // over-approximation this scan must not make).
  const ciStart = src.indexOf('async function checkIdentity');
  const ciEnd = src.indexOf('async function checkSnp');
  if (ciStart < 0 || ciEnd < 0 || ciEnd < ciStart) fail('cannot locate the checkIdentity region to scan');
  for (const line of src.slice(ciStart, ciEnd).split('\n')) {
    const nm = /\bname:\s*"([A-Za-z0-9_.]+)"/.exec(line);
    if (nm) names.add(nm[1]);
  }
  return names;
}
const emitted = emittedNames(js);

// Names the check functions attach via { name: ... } object literals inside
// the check assembly (identity_link itself and the three rollups flow through
// checks.push({ name: r.name ... }) — r.name comes from finishFact, already
// captured; identity_link is the one hand-written object literal):
for (const n of ["identity_link"]) if (!emitted.has(n)) emitted.add(n);

// --- 1: emitted ⊆ static --------------------------------------------------------
const missingStatic = [...emitted].filter((n) => !(n in shellRows));
if (missingStatic.length) {
  fail('verifier can emit rows with NO static pending row: ' + missingStatic.join(', '));
}

// --- 2: static ⊆ emitted ∪ flippable --------------------------------------------
// The flip engine flips: every emitted name (checks + sections), the facts
// placeholder (fillServerFacts), and nothing else. The overall banner and the
// footer are flipped by id but are not rows (ids overall / foot: not r-* rows,
// so they never appear in staticRows). server-facts IS an r-* row and is in
// KNOWN.
const KNOWN_FLIPPABLE = new Set(['server-facts']);
const unreachable = shellIds.filter((id) => !emitted.has(id) && !KNOWN_FLIPPABLE.has(id));
if (unreachable.length) {
  fail('static rows no flip path can ever reach (they would sit PENDING forever): ' + unreachable.join(', '));
}

// --- 4: shell vs artifact row-id parity -----------------------------------------
if (art === null) fail('dist/bootproof.html absent (run the combiner)');
const artIds = Object.keys(staticRows(art)).sort();
const shellSorted = shellIds.slice().sort();
if (artIds.join(',') !== shellSorted.join(',')) {
  const onlyArt = artIds.filter((x) => shellSorted.indexOf(x) < 0);
  const onlyShell = shellSorted.filter((x) => artIds.indexOf(x) < 0);
  fail('shell vs artifact static row drift. only-artifact: [' + onlyArt.join(',') + '] only-shell: [' + onlyShell.join(',') + ']');
}

console.log('ROW PARITY PASS: ' + shellIds.length + ' static rows, ' + emitted.size +
  ' verifier row names, both directions closed, artifact ids match shell');
