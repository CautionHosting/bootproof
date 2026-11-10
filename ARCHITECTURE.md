# ARCHITECTURE.md (DRAFT — R2 unified verifier library)

Status: **decision-completed proposal, pre-code, pre-branch.** Committed to the
repo 2026-11-10 at chipmunk's dispatch (docs-only, zero shipped bytes) so the
R2 rulings are reviewable where the code lives. The rulings recorded in §0 and
§7 are chipmunk's and BINDING; the design they constrain (§3-§6) is still a
proposal, finally reviewed when the unification leg opens (chipmunk's R2
sequence: ship T-E2/T-E3 first for the honest bake-8 bytes, then open the leg
with this proposal before code). No library code exists yet and nothing under
src/ follows from this file until that leg lands.

## 0. DECISION (chipmunk ruling (c), 2026-11-10)

**ONE canonical row set on every consumer.** A "unified" library that still
renders a different row set per surface merely relocates the twins and the drift
returns on the next leg (the measured renderSections divergence in §2b is that
drift already biting on product capability, not just on honesty fixes). So the
library owns ONE canonical display; the per-surface adapters vary ONLY how the
same rows are DELIVERED (DOM-flip vs render-to-string), never WHICH rows.

Consequence the rest of this doc must honor: the migration is a **DELIBERATE
DISPLAY CHANGE** for the SW surface (verify.js gains `fleet_domains` and the
rich `cert_chain`: error-branch + issuer + not_after), NOT a byte-identity
refactor. It therefore gets a fresh SW re-key and its own witnesses, gated by
row_parity_contract (both directions) + tier_contract + trunc_contract. The
single-file surface keeps byte-identity (it already renders the canonical set),
so its re-key must come back identical IF the extraction is faithful — that
byte-equality is the PROOF the extraction was pure. The SW surface's byte change
is EXPECTED and reviewed, not a surprise.

## 1. The problem this retires

chipmunk's R2 directive: the verifier JS converges to ONE canonical standalone
library — an importable module, node-usable, the JS implementation of
bootproof-crate functionality. Both current surfaces become CONSUMERS; verify.js
as a hand-maintained twin is ELIMINATED. Rust crate + JS library = dual
reference implementations that must ALWAYS pass the same tests, verdict-for-
verdict.

The drift class is now PROVEN, not theoretical. In Nov 2026 the SERVER-ASSERTED
tier fix (T-B/T-E) and the trunc crash fix (T-E3) each had to be applied TWICE —
once in `bootproof.js` (single-file surface), once in `verify.js` (service
worker) — because the two files maintain the same logic by hand. The agreement
gates missed the class entirely: they crosswalk channel VERDICTS, not display
TIERS or render-crash safety. Two hand-maintained renderers guarantee the drift.

## 2. Where the seam actually is (structural survey, 2026-11-10)

Measured against tip 9f6c96c8:

- The **crypto region** (everything BEFORE `runVerification`) is ALREADY
  byte-identical across the two files. This is proven by the cargo test
  `crypto_region_byte_parity_with_service_worker`, which slices
  `crypto_region(sw_asset()) == crypto_region(asset("bootproof.js"))` and
  asserts byte equality. This region is NOT the drift source; it is the
  template for what single-sourcing looks like when it is done.
- The **drift lives in the display layer AFTER `runVerification`**, where both
  files maintain SAME-NAMED pure functions by hand:
  `mapStatus, wireBytes, decodeEvidence, renderSections, trunc, j, esc, cls`.
  This is exactly the set that drifted (mapStatus/renderSections on the tier;
  trunc on the crash).
- They diverge ONLY on DELIVERY, after the pure layer:
  - `bootproof.js` = DOM flip engine (pending-first): `setRow`,
    `fillServerFacts`, `applyResult`, `setFooter`, `finishPass`, `setOverall`,
    `setMeta`. Mutates DOM nodes by id (`r-<label>`/`v-<label>`/`w-<label>`).
  - `verify.js` = `render(res)` building one full HTML string inside SW scope,
    posted to clients as `result.html`.

### 2b. MEASURED divergence (comment-stripped, code-level, tip 9f6c96c8)

This CHANGES the migration estimate from "a pure concat refactor". Diffed
comment-stripped, each function sliced by its own `function NAME(...)` header to
the closing brace:

- **THE CLEAN-EXTRACTION SET (code-byte-equal, single-source with ZERO behavior
  change):** `mapStatus, wireBytes, decodeEvidence, trunc, j, esc, cls`. The
  mapStatus/trunc comment TEXT differs (T-E vs T-E2 wording) but the CODE is
  identical, so these lift into the library verbatim and both surfaces' rekeys
  come back byte-identical. This is the mechanical part of the refactor.
- **ONE genuine feature divergence: `renderSections`.** It is NOT a delivery
  difference — the single-file surface actually SHOWS MORE than the SW surface:
  1. `fleet_domains` row (counts `host ... backend=` vhost lines out of
     user-data): present in `bootproof.js`, **completely absent from
     `verify.js`**.
  2. `cert_chain`: `bootproof.js` branches on `leaf.error`, and renders issuer +
     `not_after` + a "server decode failed; the browser decodes the PEM itself"
     fallback; `verify.js` renders a weaker cert_chain (no error branch, no
     issuer, no expiry).

So today the two surfaces DO NOT show the same rows. The SW page silently omits
`fleet_domains` and under-renders `cert_chain`. This is the drift class already
biting on PRODUCT CAPABILITY, not just on honesty fixes, and it is the strongest
argument for the unification. DECIDED (§0, ruling (c)): the library renders the
SAME canonical row set on every surface, so verify.js GAINS `fleet_domains` and
the rich `cert_chain`. That is a deliberate, reviewed display change to the
shipped SW bytes with its own re-key + witnesses, NOT a silent concat. The
canonical row set is the single-file set (it is the superset); verify.js catches
UP to it.

Therefore the unification boundary is clean and principled:

```
  ┌───────────────────────────────────────────────┐
  │  CANONICAL LIBRARY  (the JS ref impl)           │
  │   crypto: report verify, SPKI pin, doc-sig, ... │  ← today's byte-identical
  │   display PURE: mapStatus, renderSections,       │     crypto region + the
  │             trunc, j, esc, cls, wireBytes,       │     drifted pure display
  │             decodeEvidence                        │     functions
  └───────────────────────────────────────────────┘
        ▲ consumer A            ▲ consumer B        ▲ node/CLI consumer
   DOM-flip adapter         render-to-string     (future: the PGP
   (single-file shell)      (SW result.html)      verifier + Go parity)
```

Each consumer keeps ONLY an adapter. No verifier or display logic in a
consumer.

## 3. Module boundary + exports (proposed)

One new source of truth, e.g. `crates/bootproof/src/assets/lib/verifier.js`:

- **Core (pure, environment-agnostic):** the crypto region + the pure display
  functions. No DOM, no `fetch`, no `self`, no `document`. Every input is a
  parameter; every output is a value. This is the byte-exact successor to
  today's `crypto_region(...) ++ {the pure display fns}`.
- **Adapters (thin, consumer-owned):**
  - `adapters/dom.js` — `applyResult`/`setRow`/`fillServerFacts`/`setFooter`.
  - `adapters/sw.js` — `render()` (render-to-string) + the `install/activate/
    fetch/message` SW lifecycle.
  - `adapters/node.js` — the node-test entry point (already the shape the
    vm-driven contracts use).

The library is authored ONCE and imported/concatenated; consumers never copy a
function.

**Node entry (Q4 ruling, operator directive "module in any node project"):**
minimal mechanism, zero build step, zero deps — plain-script core + namespace
attach (`globalThis.BootproofVerifier`), plus a thin tail guard
`if (typeof module !== 'undefined') module.exports = BootproofVerifier;`. The
SAME bytes serve both concat and `require()`. The proof is a requirement, not a
promise: one conformance driver will literally `require()` the lib file — that
IS the demonstration (see the conformance layout proposal, §5a).

VALIDATED 2026-11-10 (scratch experiment, core.js + appended tail guard =
lib.js): (1) `require('./lib.js')` returns the namespace, trunc()/trunc(null)
fail closed to "not published", mapStatus('proven') === SERVER-ASSERTED;
(2) the SAME lib.js bytes in a vm with NO module defined (the concat/SW world)
attach globalThis.BootproofVerifier and the tail guard skips cleanly — inert
there, live under node; (3) cmp proves the tail guard is a pure byte-prefix
append (core.js is a byte-exact prefix of lib.js), so the combiner appends the
node entry and NEVER mutates a core byte — the one-bytes law holds. Ship lib.js
to both surfaces by concat (guard inert) and require() the same file in node:
one artifact, three consumers, zero build.

## 4. Bundling constraint (chipmunk's R2 note)

SW scope has no fs-ESM: it must be `importScripts` or concat. The combiner
pattern already exists (`fixtures/single_file/combiner.js` splices
`{{BOOTPROOF_CSS}}`/`{{BOOTPROOF_JS}}` sentinels, pure textual, deterministic,
no minify/transpile — "the artifact carries those bytes untouched"). Two
delivery paths, both deterministic concat:

- **single-file:** shell `{{BOOTPROOF_JS}}` ← concat(lib core + dom adapter).
  The combiner gains a second JS part or a single concatenated `lib.js`; the
  "pure textual splice, exact bytes" rule is unchanged.
- **service worker:** `verify.js` becomes a thin SW entry that
  `importScripts('/lib.js')` (or is itself the concat of lib core + sw adapter),
  keeping SW_SHA256 as the pin over the exact bytes bastiond embeds with
  include_str!.

Decision to settle at implementation time: importScripts (one shared lib.js
route, both surfaces fetch it) vs concat-per-surface (zero runtime fetch, two
pinned artifacts). chipmunk leaned concat ("the combiner pattern already
exists"); concat keeps the two existing pins byte-measured per surface and adds
no new network route. Recommend concat-per-surface, single logical source.

## 5. Drift-gate design (the R3 seed, extended)

Today the R3 conformance seed already exists and ALREADY drives BOTH surfaces
from one language-neutral data file — this is the drift gate's prototype:

- `fixtures/system_health/tier_expectations.json` — language-neutral DATA:
  the tier mapping, present/absent section verdicts, fact-row verdicts + chip
  vocab, footer doctrine, and `trunc_crashsafe` (the crash-safety property).
- `fixtures/system_health/tier_contract.js` — thin driver, both surfaces'
  mapStatus+renderSections → PAINTED html.
- `fixtures/system_health/trunc_contract.js` — thin driver, both surfaces'
  trunc+renderSections crash-safety.

For the unification leg the drift gate becomes:

1. **Shared conformance tree, per-implementation driver.** Same JSON
   expectations, one thin driver per implementation (JS-library, Rust crate,
   future Go). A consumer that DROPS a fix fails the shared tree even if its
   own unit tests pass. (chipmunk R3: the E2E tree is consumable by
   cargo/JS/Go side by side.)
2. **The crypto-region parity test generalizes.** Today
   `crypto_region_byte_parity_with_service_worker` proves the two JS files'
   crypto regions match. Post-unification there is ONE crypto source, so the
   test flips to: every built surface CONTAINS the canonical lib bytes byte-
   for-byte (the concat is provably non-lossy), same style as
   `artifact_carries_verifier_crypto_bytes`.
3. **Verdict-for-verdict agreement is already gated** by the golden fixtures
   (`golden_two_verifiers_agree` core + `golden_wardend_agreement` wardend).
   These stay and gain a third driver when the library becomes importable in
   node directly.
4. **PGP verifier lands inside the library only** (chipmunk R2), so it inherits
   the gate by construction; its Rust oracle (rPGP `verify_sig_full()`) becomes
   the agreement partner, never re-implemented in a consumer.

## 6. Migration sequence (draft, per-chunk byte-measured)

Two kinds of step, and they carry DIFFERENT evidence expectations:

- A PURE-EXTRACTION step must come back BYTE-IDENTICAL (byte-equality is the
  proof the extraction changed nothing).
- A DELIBERATE-DISPLAY-CHANGE step is EXPECTED to change bytes, so byte-
  identity is NOT the gate; the row_parity_contract (both directions) +
  tier_contract + trunc_contract over the NEW rows are the gate, plus a fresh
  re-key and a reviewed diff.

Steps (each keeps the tree green; the fresh-archive witness protocol runs on
every step: fixture gate + row parity + tier/trunc contracts + cargo
system-health + wardend agreement + agreement gates):

1. **Extract lib core, PURE.** Lift the crypto region + the CLEAN-EXTRACTION
   SET (mapStatus/wireBytes/decodeEvidence/trunc/j/esc/cls) + renderSections
   verbatim into the library. No behavior change.
2. **Single-file consumer -> concat(lib core + dom adapter), PURE.** Re-measure
   BOOTPROOF_SHA256; it MUST come back 88630e3b (the single-file set is already
   the canonical set). If it does not, the extraction was not faithful — stop.
   This byte-identity is the proof step 1 was pure.
3. **renderSections canonicalization, DISPLAY CHANGE.** The library's ONE
   renderSections is the single-file (superset) set. verify.js now renders the
   same rows it does not render today: fleet_domains + rich cert_chain.
   Gated by row_parity_contract both directions (every canonical row exists on
   BOTH surfaces) + the tier/trunc contracts extended to the new SW rows.
4. **SW consumer -> concat(lib core + sw adapter + the new canonical rows),
   DELIBERATE DISPLAY CHANGE.** Re-measure SW_SHA256; it is EXPECTED to differ
   from f25a581c. The diff is reviewed, the new rows witnessed, a fresh re-key
   lands. This is the step the whole R2 decision pays for: after it, the SW page
   shows exactly what the single-file page shows, from one source.
5. **Shared-conformance driver + per-implementation wiring** (the §5 tree).
6. **Then, and only then, PGP verifier into the lib** (inherits the gate).

The point: step 2's byte-identity proves the extraction was pure; step 3/4's
reviewed byte-change proves the parity was deliberate. Both together are the end
of the "apply the fix twice" AND the end of "the two pages disagree about what
they show."

## 7. Open questions — ALL ANSWERED (chipmunk rulings, 2026-11-10)

- **Q1 BUNDLING — RULED: concat-per-surface.** Zero new routes on the attested
  surface (every route on that box is attack/audit surface); both pins stay
  byte-measured exactly as today's SW_SHA256/include_str! pattern; combiner
  doctrine unchanged. One logical source, two concatenated artifacts.
- **Q2 DOM-id contract — RULED: stays.** r-/v-/w- + the sanitizer convention IS
  the G2 acceptance contract (T-D driver + the runbook invoke by those ids);
  acceptance contracts don't get re-homed for architectural tidiness. Layering:
  the LIBRARY owns row LABELS (the canonical set), the DOM ADAPTER owns
  label→id mapping, row_parity_contract keeps arbitrating both directions.
- **Q3 CONFORMANCE TREE — RULED: fixtures/conformance/<property>/**
  {expectations.json, driver.js, future driver.go}, one dir per property. Two
  hard rules: (a) expectations.json is the ONLY place truth lives — drivers
  stay thin (trunc_contract's ~127 lines is the size ceiling; a driver that
  grows truth moves it into JSON); (b) migrate tier_expectations.json +
  trunc_crashsafe in as the first two properties, so seed and tree are one
  convention, not two. (Layout proposal drafted separately — see
  conformance-layout-draft.md.)
- **Q4 NODE ENTRY — RULED: yes, minimal mechanism.** Plain-script core +
  namespace attach (globalThis.BootproofVerifier) + tail guard
  (if (typeof module !== 'undefined') module.exports = ...); zero build step,
  zero deps; the SAME bytes concat and require(). Proof requirement: one
  conformance driver literally require()s the lib file — that IS the
  demonstration.

## 8. Timeline note (chipmunk addition)

Between migration steps 4 and 5, once a capstone box exists, re-run the FULL
G2 live acceptance ONCE: the six-commit stack was proven offline; the capstone
proves it live. Sequence note, not a gate change. (The gate artifact now also
carries chromePath/chromeVersion per T-F, so the live acceptance names its
renderer.)

