# The NOT-PROVEN Ledger (bootproof provenance lane)

Status: Phase 1 inventory, delivered to the coordinator 2026-11-11. Code read at
lance-dev 8e959a1c (file lineage: the live box serves 2db3ce4b bytes, page sha
88630e3b/110277; the repo page sha is now 4210f8a6/110282). Every "proven"
claim below is keyed on NAMED CODE PATHS, not on docs, chat logs, or witness
prose.

Four-state column set per the field amendment (croc's live measurement +
chipmunk's root cause):

- **PROVEN-in-code**   the client can cryptographically verify it from the bundle
- **PARTIAL-in-code**  verification happens with a named trust hole
- **NOT PROVEN**       asserted-but-unverifiable today
- **FIELD**            PRESENT / ABSENT-platform / ABSENT on the live capstone
                       bundle (evidence channels observed = [wardend] ONLY;
                       snp absent because the EC2 launch does not expose
                       /dev/sev-guest: seald says "sev=absent" at boot, freezes
                       the channel set, serves memory_encryption=NOT PROVEN
                       (degraded) on every gate line. Fail-closed-by-design and
                       loud, not a silent drop.)

## A. Bundle-internal proofs (who must trust what: client-of-the-page)

| # | Claim | Class | Trust hole / primitive that would close it | Field |
|---|---|---|---|---|
| A1 | SNP report signature, VLEK->ASVK->ARK to pinned AMD roots | PROVEN (verify/snp.rs, snp.rs::check; in-page snp.report_sig/snp.asvk_pin/snp.ark_pin) | — | ABSENT-platform |
| A2 | ASVK->VLEK cert edge signature (RSA-PSS/SHA-384) | PARTIAL | WebCrypto has no RSA-PSS; in-page chain stops at SPKI pin; CLI-side check is NOT the same trust (the CLI binary itself is unpinned, D5). Close: in-page EMSA-PSS via WebCrypto SHA-384 + ~200 LoC bignum + PKCS#1 v1.5 ASN.1 DigestInfo; fixture MUST carry a real captured ASVK->VLEK edge (byte-protocol law) | ABSENT-platform |
| A3 | SNP nonce binding / VMPL0 / policy bits | PROVEN (report_data echo, signed fields) | — | ABSENT-platform |
| A4 | SNP LAUNCH MEASUREMENT -> disk/UKI lineage | NOT PROVEN | The 48-byte measurement is VLEK-signed but NO verifier anywhere compares it to a pin (zero `measurement` refs in snp.rs; both verifiers ignore it). Close: D1 baked expected-measurement + client compare | ABSENT-platform |
| A5 | TPM quote: AK ECDSA sig, Name recompute, pcrDigest self-consistency, PCR22 slot fold | PARTIAL | (i) AK hardware identity: NO EK/NitroTPM vendor chain verified in either verifier (tpm.ek_cert=DEGRADED, honest in-code comment "not verified in this build"); a self-generated AK quotes anything. (ii) pcr_state displayed, NEVER compared to a pinned set; pcr_policy_covers checks SELECTION coverage, not VALUES. Close: bake vendor roots + golden-PCR pin (D2) | PRESENT (seald serves the wardend channel; tpm2 channel composition per seald channel set) |
| A6 | Wardend doc: whole-doc HSM signature + state-log chain | PARTIAL | Sig+chain verify genuinely; the HSM key's AUTHORITY is only the identity_link indirection (HSM SPKI == TLS leaf SPKI == ACME/ISRG) + server honesty at key-gen. Close: bind HSM SPKI to measured state or seal-time pin | PRESENT |
| A7 | Wardend doc FRESHNESS ("current state at any time") | NOT PROVEN — HEADLINE | WardendVerifier::verify takes `_nonce` and NEVER uses it; canonical_doc_digest has no nonce/timestamp input. Yesterday's signed doc replays forever with every wardend row PROVEN. Close: D4 (nonce inside the digest, v1->v2 fail-closed) | PRESENT-and-replayable |
| A8 | identity_link: leaf SPKI == signer SPKI, ISRG anchor, validity, SAN | PROVEN with stated assumptions (browser validates chain sigs; ISRG SPKI pins baked into the page; clock = browser) | — | PRESENT |
| A9 | TLS endpoint key == attested signer key | PROVEN in-browser via A8 | — | PRESENT |

## B. Displayed-as-data rows (renderSections tier law: metadata = SERVER-ASSERTED; none is attested in-page)

| # | Claim | Class | Trust hole / closer | Field |
|---|---|---|---|---|
| B1 | user_data / fleet_domains / stagex_commit | NOT PROVEN | user-data rides NO signed channel; wardend-commit is a parsed claim from launch input. Close: D3 (hash-commit inside the nonce-bound doc signature; plaintext included when public-by-construction) | PRESENT-as-assertion |
| B2 | units / daemon census | PARTIAL | units[] IS inside the doc signature (digest covers units) => byte-attested under the HSM key, but authority inherits A6; heartbeat is unanchored time until D4 lands. No census row may say "current" pre-D4 | PRESENT (wardend subset only; full census is a doc widening) |
| B3 | instance_identity (IMDS pkcs7 in metadata) | PARTIAL-present | the DSA/SHA-1 AWS signature is never verified by the page path (only the local trust tree carries that code). Close: in-bundle + CLI-face closure | unknown |
| B4 | spdx_inventory | NOT PROVEN | honest null; /provenance.spdx lineage is prose-adjacent. Close: SPDX digest bound to A4/A5 | null |
| B5 | disk_encryption / disk lineage metadata | NOT PROVEN | server assertion; the disk sha -> UKI -> measurement chain reaches NO verifier. See D1/D2 | unknown |
| B6 | endorsement {aws,amd} presence | NOT PROVEN | presence-claim only; chain verification is the client's job and the client cannot (A2/A5i) | assertion |
| B7 | self-measured page bytes (footer) | NOT PROVEN | the footer number IS the self-fetch; no pinned page-sha is compared anywhere at runtime; "matches the build-time pin / UKI measurement" is checked OUTSIDE this page = nowhere today. Close: B7 pin (self-measure vs baked constant = honest PROVEN-at-build-pin); the disk-binding half needs D1 | assertion |
| B8 | env.facts server verdicts | correctly SERVER-ASSERTED by the T-E tier law | — | PRESENT |

## C. Prose witnesses — classified OUT

distro.md sections, launch records, bake logs, commit-message claims, chat-log
shas: NEVER bundle evidence. "Requires trusting the operator's word" = NOT
PROVEN regardless of witness count. The entire git-pin -> tarball -> disk sha ->
AMI chain exists today ONLY as prose + chat logs: zero bytes of it are in the
bundle. docs/trust-tree.md describes the LOCAL trust tree path (IIDD verify,
NitroTPM chain), NOT the capstone bundle verify path: doc drift, do not read it
as bundle capability.

## D. The lineage spine

git pin -> tarball sha -> disk sha -> UKI -> measured boot events -> bundle:
today ZERO of that reaches the bundle as verifiable evidence. The strongest
UNUSED primitive in the codebase is the VLEK-signed launch measurement: read by
nobody, pinned by nobody. "eventlog" does not appear in the codebase: no
replay, no PCR correlation, no UKI/disk sha included anywhere.

Closers (rulings 2026-11-11, chipmunk):
- D1 measurement pin — APPROVED-CONDITIONAL (coverage fact pending: what AWS
  measures on the StageX boot path; QEMU-VLEK legs + croc's off-box raw-report
  bank are the report sources of record).
- D2 eventlog + golden-PCR pin — DEFERRED behind the eventlog format fact and
  the size budget; v1 = compact pinned expected-PCR set vs the quote's
  per-PCR digests (already transported), full replay is v2.
- D3 user-data hash-commit inside the nonce-bound signature — APPROVED.
- D4 nonce inside canonical_doc_digest, v1->v2 fail-closed — APPROVED.
- D5 CLI face — the trust asymmetry is documented: the page's roots live in
  pinned bytes; a downloaded CLI's roots live in a download. Reproducible-build
  is the prerequisite; post-capstone. D4/D3/A2 land BEFORE the CLI face.
- D6 standalone file:// face — APPROVED: cold verifier, pending-first
  degradation, honest trust note (bytes == build pin is ALL a disk page proves;
  a page on disk says nothing about any box). Folds BUG-1.

Implementation order (bake-11 set): D4+D3 (one digest change, both faces,
fixtures) -> D6+BUG-1 -> B2 census -> B7 pin -> A2 -> D1 when the fact lands.
