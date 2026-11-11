# D4 rows ruling: hw evidence rows fold INTO digest v2 (pre-first-signature window)

Status: RULING. Author: croc (bootproof repo owner, operator directive
2026-11-11T06:26Z; the rows contract was routed to this lane by the
coordinator 06:01Z). Cites: docs/design-d4-d3-digest-v2.md (the approved
v2 spec, §1 digest, §8 D5) and docs/bug-8-public-envelope-evidence-2026-11-11.md
(wardend repo, the skipped-channels root cause). Implements the discriminator
the coordinator posed and this lane answered at source.

## The question

digest_v2 (`canonical_doc_digest_v2`, landed @ ebf20293) signs the wardend
DOC: marker || nonce32 || canonical_fields(doc) || user_data presence-tagged
section (LAST). The hardware evidence rows (snp report, tpm2 quote) ride the
BUNDLE as separate `evidence` entries. Does a network attacker dropping or
swapping an hw row break any signature the verifier checks?

## The witness (source, 2026-11-11)

No. The only cross-row integrity today is the slot-link fold (PCR22 ==
H(0 || H(other docs)), bootproof `channel.rs:119-135`), and it is an explicit
3-state whose absence arm is **NotProven, not FAILED**: drop the snp row and
the fold "simply cannot run" (the code's own words). `doc_signature` covers
only the wardend doc; each hw row is self-contained (its own vendor/TPM
chain); nothing binds the SET of rows. Row absence-by-omission is a
downgrade path that breaks no checked signature — the same defect family the
coordinator named `absence-that-presents-as-honesty` (BUG-8's skipped
channels; the dp-probe EOF story is the third cousin).

## The ruling: FOLD

digest v2 gains a ROWS SECTION: per-row SHA-256 over each bundled evidence
row's canonical byte form, presence-tagged, channel-name-sorted, folded LAST
(after `user_data`) in the same walk discipline (fixed order, len-prefixing,
BE widths). The signing box commits, under its HSM key, to the exact row SET
it shipped. A post-signature row drop/swap by anything between box and
auditor breaks the doc signature: FAILED, loud, never a degrade.

Production order inside produce-assembly (seald side): collect hw rows (both
nonce-bound by construction) -> compute rows section (per-row hashes) ->
fill doc -> digest_v2(doc, nonce) -> ONE HSM signature per response. No new
signing round: still one signature covering state + nonce + user_data + rows.

What folding closes: transport-level row-drop/swap (the auditor's actual
adversary: aMitM on the wire, a lying relay, a cached/partial response).
What it does NOT close: a malicious box that SIGNS an empty rows section.
That half is policy, already promised in the design: engine VerifyPolicy
REQUIRED channels absent => FAIL (engine.rs:20's own commitment), and the
frozen-set line (disk-bound, discriminated 06:06Z) tells the verifier which
rows MUST be enumerated. This ruling ships the transport half; the BUG-8 fix
ships the presence half; the required-policy selection read-half is named in
the BUG-8 ticket and lands with the batch.

## Why NOW (the decisive timing argument)

digest_v2 has never produced a live signature. The wardend call site still
signs v1 (admin.rs `canonical_doc_digest(&doc)`, one production caller), and
bake-10 ships that v1. The v2 vectors pinned at ebf20293
(89b90855.../afb1ff54...) are fixture-internal. The cost of extending the v2
walk before its first production signature is: regenerate both fixtures +
mirror the walk in `canonicalDocDigestV2` (JS) in the SAME commit (the
byte-law already gates this) — one commit. The cost of deferring is the
coordinator's own bake-12 migration pricing: v2 ships with a documented row
gap, every box signs gap-v2, and the migration later breaks the
fail-closed-marker discipline mid-fleet. Bake-11 one-shot. This is the
cheapest the fold will ever be.

## Rejected alternatives

1. Bundle hash-chain suffices: REJECTED on the witness — there is no bundle
   chain root inside any signature; the slot-link degrades to NotProven
   exactly when a row is dropped (the degrade IS the attack surface).
2. Whole rows embedded INTO the doc: rejected on cost — the snp report is
   1184B + certs; a 32B per-row hash binds the bytes identically (the rows
   themselves are still delivered in the bundle; the hash binds their
   exactness).
3. Scope-and-name (v2 guarantees the doc only; rows documented as separate
   integrity story): viable, but ships a known gap that a later bake must
   close anyway; the asymmetry is priced in the coordinator's 06:01Z note.

## Landing set (one bootproof/wardend batch, per the 06:28Z slotting)

- bootproof: rows section in `canonical_doc_digest_v2` + both verifiers +
  `canonicalDocDigestV2` JS mirror + golden/tamper fixtures regenerated
  (v2-with-rows vectors replace 89b90855/afb1ff54 — SAME commit, drift-killer
  test updated) + endorsement amd/aws present-from-signed-rows.
- wardend: seald per-response v2 signing at the admin.rs:1176 call site
  (nonce already in scope; user_data bytes already in scope) + rows section
  filled post-collection + v1 call site deleted whole (fail-closed).
- Tests: two-nonces-different-signatures face test (A7 witness); the BUG-8
  regression gate (device present ONLY at configured path => row present =>
  endorsement true); rows-dropped-after-signature => FAILED (the new
  security property, first test of the fold).
- Gate law: Rust/JS parity fixtures green, zero unwrap, honest degrade only
  where the degrade is REAL (genuinely absent hardware, box-self-asserted).
