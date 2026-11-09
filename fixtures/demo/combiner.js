#!/usr/bin/env node
// combiner.js — the demo quickstart build step. Deterministic. Four inputs:
//   shell.html     markup with {{ENV_LABEL}} {{AMI_ID}} {{INSTANCE_TYPE}}
//                  {{REGION}} {{USER_DATA}} {{RUN_CMD}} {{BOOTPROOF_CSS}}
//                  {{BOOTPROOF_JS}} sentinels
//   style.css      demo stylesheet (spliced VERBATIM into <style>)
//   ../single_file/verify.js   the verifier core (spliced VERBATIM into
//                  <script>) — the demo REUSES the single-file pivot's
//                  verify.js byte-for-byte: one verifier, two envelopes. The
//                  crypto-region parity gate lives in the pivot lane and
//                  covers it; here the regenerate gate pins the artifact.
//   manifest.json  AMI id / type / region / user-data / run-cmd / env label —
//                  the replicate inputs. Strings are HTML-escaped BEFORE
//                  splicing (they land in HTML text positions); this is the
//                  ONLY transformation anywhere in this combiner, and it
//                  touches the SHELL region, never verifier or CSS bytes.
//
// The manifest is the SOLE home of the AMI/user-data strings: the page is
// DOWNLOADABLE and must carry its replicate inputs with zero fetch, so they
// are baked (design ruling chipmunk 2026-11-09). They render as displayed
// claims in the labeled replicate block — never tier-elevated.
//
//   node fixtures/demo/combiner.js          # write index.html
//   node fixtures/demo/combiner.js --check  # exit 1 if it would change
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SRC = path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'assets');
const DEMO = path.join(SRC, 'demo');
const OUT = path.join(DEMO, 'index.html');

const shell = fs.readFileSync(path.join(DEMO, 'shell.html'), 'utf8');
const css = fs.readFileSync(path.join(DEMO, 'style.css'), 'utf8');
const js = fs.readFileSync(path.join(SRC, 'single_file', 'verify.js'), 'utf8');
const manifest = JSON.parse(fs.readFileSync(path.join(DEMO, 'manifest.json'), 'utf8'));

for (const k of ['env', 'ami_id', 'instance_type', 'region', 'user_data', 'command_template']) {
  if (typeof manifest[k] !== 'string') { console.error('combiner: manifest.' + k + ' missing/not a string'); process.exit(2); }
}
const runCmd = manifest.command_template
  .split('{REGION}').join(manifest.region)
  .split('{AMI_ID}').join(manifest.ami_id)
  .split('{INSTANCE_TYPE}').join(manifest.instance_type);

function esc(s) {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function splice(text, token, body, what, expected) {
  const n = text.split(token).length - 1;
  const want = expected || 1;
  if (n !== want) { console.error('combiner: sentinel ' + token + ' found ' + n + ' times (expected ' + want + ') in ' + what); process.exit(2); }
  return text.split(token).join(body);
}

let out = splice(shell, '{{BOOTPROOF_CSS}}', css, 'shell.html');
out = splice(out, '{{BOOTPROOF_JS}}', js, 'shell.html');
out = splice(out, '{{ENV_LABEL}}', esc(manifest.env), 'shell.html', 2);
out = splice(out, '{{AMI_ID}}', esc(manifest.ami_id), 'shell.html');
out = splice(out, '{{INSTANCE_TYPE}}', esc(manifest.instance_type), 'shell.html');
out = splice(out, '{{REGION}}', esc(manifest.region), 'shell.html');
out = splice(out, '{{USER_DATA}}', esc(manifest.user_data), 'shell.html');
out = splice(out, '{{RUN_CMD}}', esc(runCmd), 'shell.html');

// Raw-embedding guards (same as the pivot combiner): the inlined verifier/css
// bytes must never contain a sequence that breaks out of its block.
if (/<\/script/i.test(js)) { console.error('combiner: literal </script in verify.js'); process.exit(2); }
if (/<!--/.test(js)) { console.error('combiner: literal <!-- in verify.js'); process.exit(2); }
if (/<\/style/i.test(css)) { console.error('combiner: literal </style in style.css'); process.exit(2); }
// And the shell itself must have no leftover sentinels (a typo'd token would
// ship as literal text on the demo page).
if (/\{\{[A-Z_]+\}\}/.test(out)) { console.error('combiner: unconsumed sentinel in output'); process.exit(2); }

const buf = Buffer.from(out, 'utf8');
const sha = crypto.createHash('sha256').update(buf).digest('hex');

if (process.argv.indexOf('--check') >= 0) {
  let cur = null;
  try { cur = fs.readFileSync(OUT); } catch (e) { /* absent */ }
  if (!cur || !cur.equals(buf)) {
    console.error('combiner: index.html is STALE (regenerate: node fixtures/demo/combiner.js)');
    console.error('  committed sha: ' + (cur ? crypto.createHash('sha256').update(cur).digest('hex') : '(none)'));
    console.error('  recomputed sha: ' + sha);
    process.exit(1);
  }
  console.log('combiner: index.html is up to date (' + buf.length + ' bytes, sha256 ' + sha + ')');
  process.exit(0);
}

fs.writeFileSync(OUT, buf);
console.log('combiner: wrote ' + path.relative(path.join(__dirname, '..', '..'), OUT));
console.log('combiner: ' + buf.length + ' bytes, sha256 ' + sha);
