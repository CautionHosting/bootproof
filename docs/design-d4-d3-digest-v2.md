# D4+D3 design: nonce-bound, user-data-bearing wardend doc (digest v2)

Status: DESIGN for approval (chipmunk APPROVED-as-unit 2026-11-11T03:02Z; this
doc is the pre-code spec the ruling requires). Author: provenance lane.
Implements: A7 closure (doc freshness/replay), B1 closure (user-data attested),
operator items 2 and 4. One digest-spec change serving both: ONE HSM signature
per response covers state + nonce + user-data bytes.
Addendum (lane consolidation, chipmunk 2026-11-11T03:18Z): section 8 adds
D5, the disk-claim closure (quote-set PCR11 + pinned UKI section digests),
and section 4 gains the D4 entropy/cache threat-model bullets. The D2
track's doc base stays squid's docs/d1-firmware-measurement.md (stagex
repo); this section is the citation's bootproof-side counterpart.

## 0. The problem, measured

- `WardendVerifier::verify(ev, _nonce, _bundle)` (bootproof-platform-wardend)
  never consumes the nonce. `canonical_doc_digest(doc)` has no nonce or
  timestamp input. A captured response is replayable forever: every wardend
  row reads PROVEN against yesterday's state. On the capstone bundle today
  (evidence = [wardend] ONLY, snp platform-absent) this is the only
  signature-bearing surface.
- user-data today is metadata display only: in NO signed channel
  (`WardendDoc` has no user_data field; the SNP report carries the launch
  measurement, not user-data; the nitro doc path is not in the bundle).

## 1. Digest spec v2 (the single change)

New canonical digest:

```
digest_v2 = SHA-256(
    "wardend/platform-doc-digest/v2"      // domain AND version marker
 || nonce32                                // the challenge being answered
 || canonical_fields(doc_v2)               // same discipline as v1: fixed
                                           // field order, presence tags, BE
                                           // widths, len-prefixing - PLUS
                                           // the new user_data field
)
```

- The v1->v2 marker IS the prefix string change: `.../v1` -> `.../v2`.
  Fail-closed in both directions: a v1-signed doc recomputed under v2 breaks
  the signature; a v2-signed doc under an old verifier's v1 digest breaks the
  signature. No ambiguity window, no dual-accept mode. Old docs serve, verify
  against v1, and FAIL the v2 verifier honestly (FAILED, never silently red
  page).
- `WardendDoc` gains ONE field:

```rust
pub struct UserDataSection {
    /// SHA-256 of the RAW user-data bytes the platform read at boot.
    pub sha256: [u8; 32],
    /// The full raw bytes (UTF-8 where decodable, else the exact bytes).
    /// Present IFF the box runs the public-asserted posture (see §3).
    pub text: Option<String>,   // canonicalized in the digest as bytes
}
pub struct WardendDoc {
    // ... existing fields unchanged ...
    pub user_data: Option<UserDataSection>,
}
```

- Digest input for the new field (fixed position: LAST, after `retry`; one
  presence tag; inner: sha256 raw 32 bytes always if Some; text as
  len-prefixed UTF-8 bytes with its own presence tag).
- The nonce input: `verify()` passes its existing `_nonce: &[u8; 32]` through.
  The SIGN side (seald admin face) must sign per-response:
  `canonical_doc_digest_v2(doc, nonce)` — the HSM signs once per `/health/api`
  request (one P-256 sign per page refresh; 20 s cadence worst case:
  negligible against the HSM path, no caching of signatures across
  responses).
- Cross-channel binding (chipmunk's ask): the SAME 32-byte nonce already
  echoes in the SNP report's `report_data[..32]` and the TPM quote's
  `extraData`. v2 completes the pattern: one challenge, every signature-bearing
  channel bound. When snp returns to the bundle composition (G2 launches with
  SNP enabled), no design change is needed: both halves already key on the
  client's nonce.

## 2. Client rules (both faces, same commit)

Rust (`WardendVerifier::verify`):
1. Decode doc. Require `user_data` presence per policy (absent on a v2 doc =
   honest NOT PROVEN fact, channel itself still verifies if signed correctly).
2. Recompute digest_v2 with the bundle nonce; verify the doc signature under
   the HSM anchor FIRST (unchanged order: signature before any field).
3. If `user_data.text` present: assert `sha256(text bytes) == user_data.sha256`
   (self-consistency inside the signed bytes). Mismatch = channel FAILED.

Browser (`checkStateLog` in the verifier JS):
- Same digest walk extended with nonce + user_data (byte-law: both
  implementations change in the SAME commit; conformance vectors gate).
- New/updated rows:
  - `wardend.doc_nonce` (PROVEN/FAILED): the doc only verifies under OUR
    nonce — this row IS freshness (operator item 4): every PROVEN wardend row
    now transitively means "this pass, this challenge".
  - `user_data` flips metadata-SERVER-ASSERTED -> PROVEN-ATTESTED when:
    doc signature valid AND text present AND hash matches AND nonce bound;
    the value renders the full bytes (escaped). Honest tiers otherwise:
    commitment-only => the row reads ATTESTED-COMMITMENT, plaintext not
    published (sha shown); absent => NOT PROVEN.
  - Derived rows `fleet_domains` + `stagex_commit` re-derive their content
    FROM the attested bytes (client-side parse of verified text), wording
    keeps the doctrine: the commit remains a claim about the build until D1;
    what is PROVEN now is "these are the launch-time bytes, freshly attested".
- Divergence row: `metadata.user_data` (display) vs attested text must match
  byte-for-byte; a mismatch flips an honest `user_data_consistency` FAILED.

## 3. The private-line rule (SEEDLESS interface)

- Default posture (public AMI / seedless fleet class): `text` INCLUDED.
  Our user-data is public-by-construction (authorized ssh pubkey + fleet
  vhost lines + acme dir): nothing machine-private may be committed to the
  launch input anyway; the SEEDLESS law already forces this class.
- Exception path: one seald config flag (`user_data_publish = false`):
  presence-hash only. The page then states it explicitly:
  "commitment attested; plaintext withheld by configuration". Never a silent
  truncation, never a fabricated empty string.
- Nothing machine-specific is ever committed to the repo: this is runtime
  data inside a runtime signature; the repo carries only the digest spec and
  the fixtures' synthetic (test-key) instances.

## 4. Replay/freshness analysis (auditor-facing)

- Captured response replayed to a fresh challenge: doc signature fails
  (nonce mismatch inside the digest). Same-nonce replay requires guessing the
  client's fresh 32 random bytes: forge-class.
- The state_log chain continues to prove history continuity; v2 proves
  currency. Together: "current state, at this instant, under this HSM key"
  = operator item 4 satisfied with one signature.
- Known residual (documented, not closed here): HSM key authority is A6
  (identity-link indirection); time-of-response beyond the nonce itself
  inherits the client's own freshness (the page view), which is the honest
  outer bound for any TVC.
- **Nonce entropy (D4, binding):** the browser nonce MUST come from
  `crypto.getRandomValues(new Uint8Array(32))` -- the WebCrypto CSPRNG.
  `Math.random` is banned: it is a predictable per-tab stream, and a
  guessable nonce collapses D4 back to v1's replay property.
- **Response freshness (D4, binding):** every `/health/api` response MUST
  carry `Cache-Control: no-store` and every client MUST fetch it with
  `{cache: "no-store"}`. Both hold today (the page's fetch sites; the
  website server header) but they are now REQUIRED properties, not
  accidents: a cacheable response answering a fresh nonce is a replay
  delivered by the cache layer, and D4's whole row set would lie.

## 5. Test law (production byte protocol, every face)

- Conformance vectors JSON (new fixture, one file drives Rust+JS+node):
  v2 doc matrix — fresh-nonce PASS, stale-nonce FAIL, v1-signed-under-v2 FAIL
  (fail-closed marker), text/hash mismatch FAIL, commitment-only PASS-with-tier,
  absent NOT-PROVEN, tampered-user-data-byte FAIL, u64 token-safety cases
  preserved. Fixtures sign with the documented test key; the harness feeds
  PRODUCTION envelope bytes, not internal structs.
- Golden agreement fixture updated: the two-verifiers-agree test now walks
  the v2 doc; a v1 golden fixture is kept AND asserted to fail the v2 path.
- Real-byte witness: the fixture user-data MUST be a production-shaped
  document (ssh pubkey line + host lines), byte-protocol law, not lorem.
- CDP fixture gate + fixture gate + cargo -p bootproof + wardend agreement
  green; wardend's own seald-side digest call sites updated to the v2
  signature path in the SAME change (cross-repo coordination: seald sign side
  is wardend's; bootproof owns the digest + both verifiers).

## 6. Offsets and semantics notes landed during design (reconciliation trio)

1. LAUNCH_MEASUREMENT offset RESOLVED against sev-8.0.0 (the parser in this
   build) + both captured reports: measurement is at 0x90..0xC0, NOT 0x030 and
   NOT 0x40. Walk: report_data 0x50..0x90 (64B) then measurement 48B. The
   0x40 read was plat_info (0x27 at 0x40 in both captures); 0x030 is vmpl.
   Both fixtures: measurement = 7a89cceaaba0bbdd...d7fb8eae113d... identical
   across two separate EC2 captures (snp-report-fixture.bin VMPL1 +
   snp-report-live-v0.bin VMPL0): launch-measurement determinism corroborated
   across boots/instances of the same AMI class. doc note: the 0x030..0x060
   claim in stagex d1 doc §6 and the 0x40 claim are BOTH superseded by the
   ABI walk + fixture bytes.
2. SNP fixture provenance: both fixture reports are genuine EC2 captures
   (commit bf967901, 2026-09-06, "captured from a live EC2 SEV-SNP guest" —
   sev-guest exists on NO other platform per tonight's fleet fact). Label:
   legitimate EC2-era capture; NOT synthetic. One caveat to carry in the
   bake-11 ledger: they predate the G2 AMI; their measurement pins the OLD
   image's firmware-class digest. G2 real report (croc W4) replaces for D1.
3. LAUNCH DIGEST SEMANTICS: consistent with squid's firmware-level claim —
   EC2 UEFI boot LAUNCH_UPDATEs initial memory (OVMF + state); the UKI loads
   later via OVMF from the ESP, so the launch measurement closes a FIRMWARE
   claim. The DISK claim is measured ELSEWHERE: unikernel mode packs erofs
   root INSIDE the UKI .initrd and the EFI stub measures .linux/.initrd/
   .cmdline/.osrel into PCR11 — today's quote set stops at PCR00-07. Revise
   D2 accordingly: extend quote set to PCR11 + pin the per-UKI section digest
   = disk closure with NO pipeline change (TOFU until UKI signing, per squid:
   nothing is signed anywhere in the build path).

## 7. Sequencing inside bake-11

This doc covers step 1 (D4+D3). Implementation order per ruling:
1. D4+D3 v2 digest (bootproof: digest + both verifiers + fixtures + rows;
   wardend seald sign-side v2 — coordinated, one landing set)
2. D5 disk-claim closure (section 8; verifier-side quote-set + TOFU pins)
3. D2 measurement pins when G2's W4 value lands
4. D6+BUG-1 file:// cold verifier mode (pending-first, no self-fetch crash)
5. B2 census widening (units[] -> full user+first-party set, health +
   generation, in-doc; rows refuse "current" until this + D4 both land)
6. B7 page-sha pin row
7. A2 in-page RSA-PSS with real ASVK->VLEK fixture
8. D1 when the G2 report lands (firmware-class pin; PCR11 pin is the D2 track)

## 8. D5 -- disk-claim closure (quote-set PCR11 + pinned section digests)

**Ledger entries it closes:** the DISK half of A1 ("the disk running is the
disk that was built"). The reconciliation findings this builds on:

- The launch measurement at report_data **0x90..0xC0** (R3: byte-identical
  across both EC2 capture fixtures while 0x030 differs = vmpl; the 0x40
  read was plat_info) is a FIRMWARE/OVMF-class measurement. It says
  nothing about the disk. D1's firmware row must never borrow it for the
  disk, and vice versa.
- The DISK identity is measured by the EFI linux stub into **PCR11**: the
  stub extends `.linux`, `.initrd`, `.cmdline` and the `.osrel` section;
  the erofs root filesystem rides INSIDE `.initrd` in the unique-mode
  (unikernel) image, so PCR11 covers the complete disk contents. The
  current quote set (PCR00-07 + 13/14/15) never quotes it.

**Mechanism (verifier-side only; no signing-pipeline change):**

1. `SnpQuoteVerifier::parse_quote` parameterizes the quoted-PCR set;
   extend it to include index 11 (the bake-11 face:
   {0..7, 11, 13, 14, 15}). The quote binds digests for every listed
   index; existing TPM-side digests are unchanged.
2. `VerifyPolicy` gains the quoted-PCR set as a typed field with the
   current seven-index default; the bundle face runs the extended set so
   a quote that omits PCR11 fails the fold instead of silently skipping
   the disk row.
3. New sub row `snp.disk_verification`: the quote's PCR11 digest must
   equal the pinned expected value. Separate row and separate verdict
   from the firmware row: two claims, no cross-borrowing.
4. Expected values are **TOFU pins**: the PCR11 value and the per-UKI
   section digests come from G2's captured UKI (croc W4), recorded in
   the registry like D2's measurement pins -- not from a build pipeline
   the verifier can replay. The page labels them as pins with the capture
   source named.
5. **sbsign prerequisite:** signing must not perturb the measured
   sections. sbsign appends to `.siglineage`/`.sbsig` and leaves
   .linux/.initrd/.cmdline/.osrel bytes intact, but any change to signing
   flags, certificate, or section order is a PCR11 break by definition.
   Pins are therefore **provisional until G2 captures the FINAL signed
   UKI** the AMI boots; every re-sign is a pin rotation event with a
   recorded reason (D2's change-control discipline).

**Semantics:**

| row | verdict | evidence |
|---|---|---|
| snp.firmware_verification (launch measurement) | pinned-proven iff quote report_data[0x90..0xC0] == registry pin; no pin => NOT PROVEN | the R3-offset bytes from the live quote |
| snp.disk_verification | pinned-proven iff quote PCR11 digest == pinned PCR11; no pin => NOT PROVEN | the quote's PCR11 digest; sections listed with digests as detail |

The comparison needs only the quote's PCR11 digest, so D5 lands while the
eventlog remains absent from the bundle (ledger E1/E2): when the eventlog
is added later, the section digests upgrade from pinned to replayed and
the structural-PROVEN path (a replayable builder reproducing identical
sections) stays gated on D2's unresolved pipeline claims.

**D5 explicitly does NOT claim:** the builder is reproducible; the section
digests were produced by the public pipeline; or any implication between
the firmware row and the disk row -- a correct firmware measurement with
a wrong disk passes the firmware row and fails the disk row, which is
precisely why they are split.
