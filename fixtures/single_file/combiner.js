#!/usr/bin/env node
// combiner.js — the single-file pivot build step. Deterministic.
//
// It produces ONE artifact, assets/dist/bootproof.html, from THREE
// reviewable, operator-named sources in assets/single_file/:
//   bootproof.html  (the pending-first markup, with {{BOOTPROOF_CSS}} /
//                   {{BOOTPROOF_JS}} sentinels)
//   bootproof.css   (the System Health stylesheet, spliced verbatim in <style>)
//   bootproof.js    (the verifier + flip engine + page runner, spliced
//                    verbatim in <script>)
//
// THE ONE RULE: this is a PURE TEXTUAL SPLICE. The combiner replaces the two
// sentinel tokens with the exact bytes of bootproof.css and bootproof.js. It
// never mutates, minifies, reorders, or transpiles the verifier bytes. That
// is what makes the crypto region of the single-file verifier byte-for-byte
// the service worker's crypto region: the artifact carries those bytes
// untouched, and the Rust gates assert it. If a future change needs to touch
// the verifier to make it inline, that is a design smell: fix the source,
// not the splice.
//
// Sources vs artifact: the three sources are the review surface (what a
// human reads and diffs); assets/dist/bootproof.html is the DELIVERED form
// (what bastiond embeds with include_str! and serves). The dist/ directory
// exists precisely so the artifact can never be confused with a source.
//
// Determinism: no Date, no random, no path leakage, stable byte order, LF only.
// Run it and it prints the sha256 of the exact bytes it wrote; the Rust
// regenerate==committed test runs this and byte-compares against the
// committed artifact, so the artifact can never drift from its sources.
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
const OUT = path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets', 'dist', 'bootproof.html');

const shell = fs.readFileSync(path.join(SRC, 'bootproof.html'), 'utf8');
const css = fs.readFileSync(path.join(SRC, 'bootproof.css'), 'utf8');
const js = fs.readFileSync(path.join(SRC, 'bootproof.js'), 'utf8');

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

let out = splice(shell, '{{BOOTPROOF_CSS}}', css, 'bootproof.html');
out = splice(out, '{{BOOTPROOF_JS}}', js, 'bootproof.html');

// Guard the raw-embedding invariant: a literal </script or <!-- inside the
// inlined JS (or </style inside the CSS) would break out of its block and let
// the verifier bytes reach the HTML parser. These must be ZERO or we refuse
// to emit. (esc() escapes all ENVELOPE bytes at flip time; this checks the
// verifier SOURCE itself, which is trusted but must still be well-formed.)
if (/<\/script/i.test(js)) { console.error('combiner: literal </script in bootproof.js'); process.exit(2); }
if (/<!--/.test(js)) { console.error('combiner: literal <!-- in bootproof.js'); process.exit(2); }
if (/<\/style/i.test(css)) { console.error('combiner: literal </style in bootproof.css'); process.exit(2); }

// The pending-first guard on the SHELL: every static row must ship PENDING.
// A row whose static status word is anything else (a pre-baked verdict in
// the delivered bytes) violates the render law at the source level, so the
// splice refuses to emit it. (The flip engine owns verdicts; the shell
// owns pending.)
const staticRows = out.match(/<tr id="r-[A-Za-z0-9_.-]+" class="pd">/g) || [];
if (staticRows.length === 0) { console.error('combiner: no pending static rows in the shell'); process.exit(2); }
{
  const noPending = out.split('\n').filter(function (l) {
    return /^<tr id="r-/.test(l) && !/<span class="verdict pd" id="v-[A-Za-z0-9_.-]+">PENDING<\/span>/.test(l);
  });
  if (noPending.length) {
    console.error('combiner: static rows without a PENDING verdict chip (' + noPending.length + '):');
    console.error(noPending.slice(0, 5).join('\n'));
    process.exit(2);
  }
}

const buf = Buffer.from(out, 'utf8');
const sha = crypto.createHash('sha256').update(buf).digest('hex');

if (process.argv.indexOf('--check') >= 0) {
  let cur = null;
  try { cur = fs.readFileSync(OUT); } catch (e) { /* absent */ }
  if (!cur || !cur.equals(buf)) {
    console.error('combiner: dist/bootproof.html is STALE (regenerate: node fixtures/single_file/combiner.js)');
    console.error('  committed sha: ' + (cur ? crypto.createHash('sha256').update(cur).digest('hex') : '(none)'));
    console.error('  recomputed sha: ' + sha);
    process.exit(1);
  }
  console.log('combiner: dist/bootproof.html is up to date (' + buf.length + ' bytes, sha256 ' + sha + ')');
  process.exit(0);
}

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, buf);
console.log('combiner: wrote ' + path.relative(path.join(__dirname, '..', '..'), OUT));
console.log('combiner: ' + buf.length + ' bytes, sha256 ' + sha);
