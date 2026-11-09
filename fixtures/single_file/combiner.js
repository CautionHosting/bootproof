#!/usr/bin/env node
// combiner.js — the single-file pivot build step. Deterministic.
//
// It produces ONE artifact, bootproof.html, from THREE reviewable sources:
//   shell.html   (markup, with {{BOOTPROOF_CSS}} / {{BOOTPROOF_JS}} sentinels)
//   style.css    (the System Health stylesheet, spliced verbatim in <style>)
//   verify.js    (the verifier + page runner, spliced verbatim in <script>)
//
// THE ONE RULE: this is a PURE TEXTUAL SPLICE. The combiner replaces the two
// sentinel tokens with the exact bytes of style.css and verify.js. It never
// mutates, minifies, reorders, or transpiles the verifier bytes. That is what
// makes the crypto region of verify.js byte-for-byte the service worker's
// crypto region: the artifact carries those bytes untouched, and the
// footer_contract gate asserts it. If a future change needs to touch the
// verifier to make it inline, that is a design smell: fix the source, not the
// splice.
//
// Determinism: no Date, no random, no path leakage, stable byte order, LF only.
// Run it and it prints the sha256 of the exact bytes it wrote; the Rust
// regenerate==committed test runs this and byte-compares against the committed
// bootproof.html, so the artifact can never drift from its sources.
//
//   node fixtures/single_file/combiner.js            # write the artifact
//   node fixtures/single_file/combiner.js --check     # exit 1 if it would change
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// Paths are all relative to THIS file so the output never depends on cwd
// (a path-independent, deterministic build).
const SRC = path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets', 'single_file');
const OUT = path.join(SRC, 'bootproof.html');

const shell = fs.readFileSync(path.join(SRC, 'shell.html'), 'utf8');
const css = fs.readFileSync(path.join(SRC, 'style.css'), 'utf8');
const js = fs.readFileSync(path.join(SRC, 'verify.js'), 'utf8');

// The splices. Each sentinel must appear EXACTLY once; a missing or doubled
// sentinel is a source bug, not something to paper over.
function splice(text, token, body, what) {
  const n = text.split(token).length - 1;
  if (n !== 1) {
    console.error('combiner: sentinel ' + token + ' found ' + n + ' times (expected 1) in ' + what);
    process.exit(2);
  }
  return text.replace(token, body);
}

let out = splice(shell, '{{BOOTPROOF_CSS}}', css, 'shell.html');
out = splice(out, '{{BOOTPROOF_JS}}', js, 'shell.html');

// Guard the raw-embedding invariant: a literal </script or <!-- inside the
// inlined JS (or </style inside the CSS) would break out of its block and let
// the verifier bytes reach the HTML parser. These must be ZERO or we refuse to
// emit. (esc() escapes all ENVELOPE bytes at render time; this checks the
// verifier SOURCE itself, which is trusted but must still be well-formed.)
if (/<\/script/i.test(js)) { console.error('combiner: literal </script in verify.js'); process.exit(2); }
if (/<!--/.test(js)) { console.error('combiner: literal <!-- in verify.js'); process.exit(2); }
if (/<\/style/i.test(css)) { console.error('combiner: literal </style in style.css'); process.exit(2); }

const buf = Buffer.from(out, 'utf8');
const sha = crypto.createHash('sha256').update(buf).digest('hex');

if (process.argv.indexOf('--check') >= 0) {
  let cur = null;
  try { cur = fs.readFileSync(OUT); } catch (e) { /* absent */ }
  if (!cur || !cur.equals(buf)) {
    console.error('combiner: bootproof.html is STALE (regenerate: node fixtures/single_file/combiner.js)');
    console.error('  committed sha: ' + (cur ? crypto.createHash('sha256').update(cur).digest('hex') : '(none)'));
    console.error('  recomputed sha: ' + sha);
    process.exit(1);
  }
  console.log('combiner: bootproof.html is up to date (' + buf.length + ' bytes, sha256 ' + sha + ')');
  process.exit(0);
}

fs.writeFileSync(OUT, buf);
console.log('combiner: wrote ' + path.relative(path.join(__dirname, '..', '..'), OUT));
console.log('combiner: ' + buf.length + ' bytes, sha256 ' + sha);
