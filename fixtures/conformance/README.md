# fixtures/conformance — the two-surface conformance tree

The ratified layout (chipmunk, 2026-11-10): one property per directory, one
shared evaluator, zero truth outside data. This tree replaces the scratch
build that witnessed R2; it runs against the SHIPPED assets in this repo.

## Layout

    harness.js                 the ONLY shared code (evaluator + loaders)
    trust_tier/                property: the trust-tier law
        expectations.json      ALL expected values live here (data)
        driver.js              thin driver (see driver law)
    trunc_crashsafe/           property: absent fields never kill the render
        expectations.json
        driver.js

Run a property against an impl (default impl `bootproof-js`):

    node fixtures/conformance/trust_tier/driver.js bootproof-js
    node fixtures/conformance/trunc_crashsafe/driver.js verify-js

Exit 0 iff every check passes (and no skip, unless `--allow-skip`).

## The two laws

### 1. TRUTH-ZERO (the harness carries no verdicts)

`harness.js` contains NO expected values, NO verdict/status literals used as
expectations: every `expect`/`status`/`value_contains` is read from the
property's `expectations.json`. The harness only DISPATCHES (reads `kind`,
calls the impl's own functions, compares against the data). Loaders carry
zero truth: they hand back the surface's own exported functions.

Witness recipe (prints nothing on success):

    grep -nE "'(PROVEN|NOT PROVEN|SERVER-ASSERTED|FAILED)'|\"(PROVEN|NOT PROVEN|SERVER-ASSERTED|FAILED)\"" fixtures/conformance/harness.js \
      && echo "TRUTH-ZERO VIOLATED" || echo "TRUTH-ZERO OK"

(`status` comparisons in the evaluator read `row.status` against `r.status`
from the JSON — identifiers, never literals.)

### 2. CLASS DISPATCH (the neutrality law: value-kinds free, output-shape gated)

Every check carries a `class` field, and the field NEVER drives dispatch.
Dispatch keys on `kind` + the impl's declared capabilities:

- VALUE-kinds (`call_equals`, `survives`, `map_rows`) consume
  `impl.value_fns` and are FREE for any impl that declares the fn.
- OUTPUT-SHAPE kinds (`rows_contain`) consume `impl.render`. An impl with no
  `render` entry gets that kind SKIPPED-with-reason, never faked green —
  and the driver EXITS 1 on any skip unless `--allow-skip` is passed
  (explicit operator opt-in). A renderless impl therefore cannot green-light
  a `rows_contain` property by any path.

Witness recipe for the class-field neutrality (prints nothing on success):

    grep -n 'c.class' fixtures/conformance/harness.js \
      && echo "class field drives dispatch — VIOLATION" || echo "class field inert — NEUTRAL OK"

Capability proof (committed, honest): the `renderless-js` impl handle exposes
`mapStatus`/`trunc` but NO render —

    node fixtures/conformance/trunc_crashsafe/driver.js renderless-js            # exit 1 (skip, no opt-in)
    node fixtures/conformance/trunc_crashsafe/driver.js renderless-js --allow-skip  # exit 0
    node fixtures/conformance/trust_tier/driver.js renderless-js                 # exit 0 (all value-kinds)

`lib-node` (the R2 unified-library entry) is declared but unbuilt: loading it
fails LOUD ("not built yet"), never silently skips.

## Driver law (ratified)

Thin driver: `<5` executable lines (excluding the shebang), zero truth, zero
logic — it resolves the impl argv, the skip opt-in, and hands
`expectations.json` to the harness. The line count is a SMELL TEST, not the
law; the law is zero truth, zero logic (run both, they must print `4` and
nothing respectively):

    grep -vE '^\s*(#!|//|/\*|\*)' fixtures/conformance/trust_tier/driver.js | grep -vE '^\s*$' | wc -l   # 4 (smell test, shebang excluded)
    grep -nE '"[A-Z ]+"' fixtures/conformance/trust_tier/driver.js   # truth-shaped strings: none

## Properties

- `trunc_crashsafe@v1` — the T-E3 law: `trunc()` of absent/omitted ==
  "not published"; `renderSections` on an envelope with absent fields
  RETURNS (never throws) and paints the marker. Migrated from
  fixtures/system_health/trunc_contract.js's property (the contract stays;
  this is the cross-surface seed).
- `trust_tier@v1` — the T-E law: a server-PUBLISHED value maps
  SERVER-ASSERTED (never browser-VERIFIED), absent maps NOT PROVEN, and only
  local verification may mint PROVEN. Migrated from
  fixtures/system_health/tier_expectations.json#map_status + the
  present/absent section verdicts.

Impl handles: `bootproof-js` (single_file/bootproof.js, DOM stubs),
`verify-js` (system_health/verify.js, SW stubs), `lib-node` (unbuilt, loud),
`renderless-js` (test-only capability proof). `BP_ASSETS` overrides the asset
root for cross-tree experiments.
