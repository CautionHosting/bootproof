# SPKI tail fold + latch fold — the identity binding design note (bake-11 #2)

STATUS: design, zero code. Read at bootproof `536f9d2d` + wardend `df992cf5`
(drift law: commit plane, tagged). For chipmunk's adjudication; D1 is DEAD,
see §0.

## 0. What changed vs the first sketch (the truncation phantom)

The original D1 question ("truncate the pin to 16 bytes vs fold
H(pin) into the tail") was a PHANTOM constraint: it conflated the 64-hex
RENDERING of the pin with its 32-byte digest. The tail is `rd[32..64]`,
32 BYTES; `spki_pin` is SHA-256(SPKI), 32 BYTES. **The full pin fits the tail
exactly.** No truncation, no hash-of-hash, no prefix rule: the in-report
binding is full-equality against the same 32-byte value the TLS identity
check already uses. `snp.rs` already knew this: the `nonce_binding_ok` doc
comment names "a truncated signer-key hash ride the tail for an in-report
key-binding WITHOUT a second report" as the tail's designed purpose — this
fold is the feature that doc was waiting for.

## 1. The design in one line per plane

- `produce`/`assemble`/`wire`/`tpm2`: **zero changes.** The 64-byte challenge
  is ALREADY a composition seam: `challenge_from_nonce` fills rd[..32] and
  zeroes rd[32..64] (engine `collect_channels` → `collect_all` →
  `Channel::collect(challenge: &[u8; 64], ..)`).
- The `Snp` channel gains a configured identity:
  `Snp::with_signer_pin(pin: [u8; 32])` alongside `Snp::at(path)`.
  `collect()` builds `report_data = challenge[..32] ‖ pin` — the channel
  composes what it writes. This is the SAME seam pattern as `sev_path`
  (gate 2b): the platform hands the key knowledge to the channel at
  construction; **no core concept of "signer" is created.**
- `verify/snp.rs` gains the equality fact (G5, §3).
- The golden regenerates once (byte change, same procedure as the
  absence-reason re-pin: freeze, record supersession, agreement gates
  unchanged in logic).

## 2. Digest visibility (PROVEN by reading, not assumed)

The report blob (which contains report_data verbatim) enters THREE surfaces:
1. The VLEK signature (firmware MEASUREMENT data) — tail flips ⇒ signature
   breaks. Load-bearing, automatic.
2. The tpm2 slot-link fold `PCR22 = H(0 ‖ H(snp_doc) ‖ H(wardend_doc))` —
   the snp doc is hashed IN, so the tail is transitively bound into the TPM
   quote (attest/tpm2.rs slot-link: `other_docs` hash chain).
3. The wardend v2 digest (channel rows fold the snp row's doc).
⇒ No new digest plumbing. The fold rides existing binds; a transport that
alters the tail breaks all three.

## 3. The three-state render (G5) — verifier-side, both verifiers, in lock-step

> **AMENDED 2026-11-11 (the fold adjudication, chipmunk CLOSED).** The
> table below is the ORIGINAL design and is SUPERSEDED. The amended
> classify law: tail content NEVER FAILS — FAILED belongs to the
> signature, never to the content. The three states: all-zero ⇒
> NotEnabled (honest pre-fold); non-zero + named-candidate match ⇒
> Matched; non-zero + no match ⇒ Unattributed (NOT PROVEN with the
> auditor-law reason NAMING the measured tail hex and the candidates
> tried — honest, never a lie). A mis-folded tail is most often a bug or
> a stale key, not an attacker, and a FAILED on content would train
> operators to ignore red. Also superseded below: the `expected ==
> identity.pin` framing — the SPKI pin is an ENVELOPE value (the TLS
> leaf's identity), NOT a bundle value, so at core scope the candidate
> set is EMPTY BY LAW and only NotEnabled/Unattributed are reachable.
> The Matched arm lives where a real candidate exists: the browser
> (publishedPin, but always NOT PROVEN until #19 — browser equality is
> theater without the out-of-band manifest) and wardenctl
> (`verify_bundle_pinned`: the operator's `WARDENCTL_SEALD_PUB` pin + the
> bundle's hsm anchor, both derived through the fold law
> `SHA-256(SPKI-DER(point))` — the same `spki_der_from_point` the
> producer folds with). Implementations: bootproof `verify/snp.rs`
> `facts()` (commit 3a08e602), `verify.js` + `bootproof.js`
> `snpIdentityTailSub` (7b6cc530), wardend `wardenctl::verify_bundle_pinned`
> (wardend 3bd3ab60).

Given `expected = identity.pin` (32 bytes, already carried in the envelope
identity section):

| tail bytes | status | meaning |
|---|---|---|
| `== expected` | PROVEN | the VLEK-signed report names the signer key: hardware-anchored identity |
| all-zero | NOT PROVEN | pre-fold node — honest pre-fold era, not an attack |
| anything else | FAILED | a tail that is neither the expected pin nor honest zero is a LIE (loud, never degraded) |

The JS already half-does this: `snp.nonce_binding` renders
"(+zero tail)" vs "(nonzero tail: cross-channel data)" — cosmetic text. The
fold upgrades it from narration to verdict. G1 satisfied: placement is
`rd[32..64]`, `rd[..32] == nonce` checks are untouched everywhere
(Rust `nonce_binding_ok`, JS `reportData.subarray(0, 32)`); the tail is
guest-composed and firmware-copied verbatim (the snp.rs doc comment states
this as fact, correcting the older "firmware-chosen" claim).

## 4. The threat (restated, sharper)

Today `attest_signer_spki_sha256` is self-declared text: an attacker who
controls the serving path serves a bundle with THEIR key in `bundle.keys.sign`
and a matching identity section, and `spki_pin(leaf) == identity.pin` passes
because BOTH sides are attacker-supplied. Only the AMD cert chain is
hardware-anchored, and it attests the report bytes, not the bundle's key
fields. The tail fold moves the identity claim from tier 2 (daemon-asserted)
to tier 1: the VLEK signature covers `rd[32..64]`, so the report itself
names the key. Interposer with someone else's genuine bundle: tail mismatch
⇒ loud FAILED [SUPERSEDED 2026-11-11: ⇒ Unattributed, NOT PROVEN with the
auditor-law reason — see the §3 amendment]. Stale pre-fold bundle: zero
tail ⇒ NOT PROVEN, G4 below.

## 5. The pre-fold world (G4) — the one real design tension

A golden-era bundle (zero tail) is honest but does NOT bind identity at
tier 1. Options considered:

- **Grace (NOT PROVEN):** pre-fold bundles verify but the identity row is
  explicitly unproven. Honest, but leaves a world where the strongest
  identity claim quietly never appears.
- **Hard-cut (FAILED):** [REJECTED by the 2026-11-11 amendment — tail
  content never FAILS; the shipped law is the third option: honest
  Unattributed] every pre-fold bundle goes red on deploy day,
  including the frozen goldens and every live node until re-imaged.

RULING-NEEDED: NOT PROVEN + the deployment sequence below makes the grace
self-extinguishing (no policy carries a grace period: the ROW goes NOT
PROVEN → PROVEN the moment a node re-images; nothing ever "learns" to accept
zero tails beyond this one fact). The goldens gain a `zero_tail` variant,
asserting exactly NOT PROVEN on the identity row — the two-verifiers-agree
gate then PROVES the G4 semantics instead of debating them.

## 6. D2 — what the pin binds (chipmunk's sharpening: SPKI vs leaf)

`spki_pin(leaf_der)` is SHA-256 of the SubjectPublicKeyInfo, ACME leaf
rotation-proof (that is the whole design of it). The tail must hold the same
value: `sha256(SPKI)`, not a leaf fingerprint. One value, three consumers:
TLS identity check, wardenctl pin comparison, the in-report equality.

## 7. D4 — which key's pin (the boot-key question)

`bundle.keys.sign` is the ECDSA P-256 signer key (seald's). The pin the
browser already knows comes from the ACME leaf — and `keys.rs` proves
`spki_pin(acme_leaf) == pin(P-256 signer)`: same key pair, two certificates
(TPM-gated signer key ⇔ ACME leaf). The tail value is therefore the value
the identity section ALREADY carries (`attest_signer_spki_sha256`): the
fold closes the loop between the hardware report and the published pin.
If the boot signer ever differs from the serving key, the fold makes it
visible (tail ≠ identity.pin ⇒ FAILED) [SUPERSEDED 2026-11-11: visible as
Unattributed with the measured hex named — see the §3 amendment] rather
than assumed away.

## 8. The latch fold (item 2), design shape

`user_data` (the vmm-injected guest-request request field, 8 bytes —
`serve` already accepts `user_data` on POST /attest) becomes the latch
provenance witness: rd becomes nonce(32) ‖ pin(32) … but the tail is FULL
(pin owns it). Two shapes, one decision ahead:

- **Shape A (compose):** rd = nonce(32) ‖ H(pin ‖ latch)(32) — keeps ONE
  64-byte field; costs: the identity check becomes an equality against a
  DERIVED value (the verifier must know the latch to check identity —
  couples the two binds, weakens D6's "same value three consumers").
- **Shape B (second field, chipmunk's preferred):** `sev-6.1.0` DOES model
  the request user_data field: `sev_launch.rs:15-17` builds an
  SNpReportRequest with a 64-byte `user_data` array (the vmm-latched
  GUEST_USER_DATA lands verbatim in the report). `sev-8.0.0` (vendored)
  has `build_request` WITHOUT the user_data param — the field is upstream,
  the vendored bump is a dependency action, not a blocker (decide at the
  gate: 8.0.0 patch-back vs upgrade). rd[32] carries the pin UNTOUCHED;
  latch proves via a THIRD report field with its own three-state row:
  `latch: PROVEN (digest matches) | NOT PROVEN (zero / pre-bump) | FAILED
  (mismatch)`.

Shape B keeps every §3 property intact and matches the v2 discipline
(chipmunk: "user_data binds the doc, the tail binds the key, one field one
claim"). The fold design in §1–7 is UNBLOCKED by D3/latch: the tail fold
ships first, the latch fold lands as the sibling field.

## 9. D5 — provenance of the tail value

GUEST-COMPOSED, firmware-signed — and that is exactly the property we need.
The composition is the guest's own code path (seald's `Snp` channel), under
measurements; the VLEK signature covers it. No firmware cooperation, no new
protocol, no second report. The anti-phantom check that made §0 necessary
also made this claim evidence-based (the doc comment + the firmware-copies-
verbatim law) rather than hoped.

## 10. Gates (the contract of this design)

- G1 placement `rd[32..64]`; `rd[..32] == nonce` untouched everywhere.
  Evidence: §3, probe of all four consumers.
- G2 digest visibility: PROVEN by reading (§2), no new fold.
- G3 the node-split field check: UNREACHABLE for G3 (terminated) — recorded
  in wardend's design note (`df992cf5`.. this note's read-at), rides to the
  first bake-11-deployed box as a post-deploy `ls -l /proc/$(pidof
  seald)/fd` line. Per chipmunk: outcome lands where the check lives =
  wardend docs.
- G4 pre-fold world: §5 (NOT PROVEN + zero-tail golden variant).
- G5 the three-state identity row, both verifiers, golden + zero-tail
  golden + tampered-tail tamper fixture (the flip-a-byte case MUST be
  FAILED on both sides — agreement on REJECTION is the security property,
  same law as the fold tampers).

## 11. Open items for chipmunk (no fake forks)

1. §5 grace mechanism: NOT PROVEN (proposed) vs hard-cut. If a third shape
   exists (epoch-gated hard-cut keyed to the manifest), name it; do not
   invent forks.
2. §8 latch: shape B with the vendored `sev` bump vs patch-back —
   dependency action to adjudicate at the latch gate (the fold does NOT
   block on it).
3. G4's zero-tail golden: new fixture file vs golden-variant field —
   gen_golden.js owns the procedure either way.
4. Sequencing confirmation: tail fold (this note) → zero-tail + tamper
   goldens + re-pin → agreement gates → THEN render modules (wire before
   render, standing order).
