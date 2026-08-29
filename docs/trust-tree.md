# `bootproof verify` — local trust tree (handoff)

## Status: DONE + verified on instance (2026-08-27)

`bootproof verify` (no target) renders the local trust tree; `--json` emits
the same tree as JSON. Wired into the existing `Verify` subcommand: `target`
is now optional — absent → local tree, present → the remote TLS client.
Deployed to the instance (musl) and rendered live.

Final rendered verdicts on the c6a.large / StageX / us-east-2 instance:

| Branch | Fact | Verdict |
| --- | --- | --- |
| Cryptography | Ephemeral / System / User / Provider Key | unknown (N/A) |
| Cryptography | Cross-Attestation Binding (TPM + SEV-SNP shared nonce) | true |
| Custody | Owner / Account | true (signed IIDD) |
| Custody | Instance (i-02a44cb68978c43af) | true |
| Custody | Location (us-east-2, proven by cert chain) | true |
| Custody | Custody Chain (datacenter → Nitro → NitroTPM → SEV-SNP) | likely |
| Security | Memory Encryption | true (AMD-root-anchored) |
| Security | Filesystem Encryption | unknown |
| Security | Memory Isolation | true (AMD-root-anchored) |
| Security | Secure Boot | unknown |
| Security | Hardened Kernel | likely (self-reported) |
| Security | Hardware Backed Entropy | likely (self-reported) |
| Security | Hardware Backed Ring Isolation (SVSM) | true (AMD-root-anchored) |
| Security | Hardware Network Isolation | likely |
| Access | Administrative Access (local root + serial console) | likely |
| Hardware | CPU | true (AMD-root-anchored) |
| Hardware | TPM (NitroTPM, pinned root + nonce + endorsement chain) | true |
| Hardware | Memory | likely |
| Hardware | Storage | likely |
| Software | OS (Stageˣ) | likely |
| Software | Kernel (7.2.0) | likely |
| Software | Measured Boot (24 PCRs in signed doc) | true |
| Provenance | Source / Provenance (`/provenance.spdx`) | unknown (unsigned dev build) |

Implementation notes beyond the design above:
- OS detection falls back to NAME/ID when PRETTY_NAME is absent (StageX ships
  `NAME="[Stageˣ]"`, `ID=stagex`, no PRETTY_NAME) — done in `facts/mod.rs`.
- `lsblk` is broken on StageX (missing libncursesw); Storage falls back to
  /proc/partitions and the tree filters out ram*/loop* devices.
- IMDS v2 is FULLY working on this instance (token + all
  `latest/meta-data/*` paths, including `placement/*`, `instance-type`,
  `iam/info` — which answers JSON, not a bare ARN). Earlier "restricted
  IMDS" notes were stale.
- Run requires tpm-bridge up + `serve` stopped (single-connection bridge).
- 31 unit tests across `trust/mod.rs` + `provenance.rs` (verdict display,
  region CN parsing, snpguest text parsing, branch order, JSON roundtrip,
  unknown degradation, 80-column wrapping, cross-attestation binding, IIDD
  DSA verification against the pinned cert, IIDD custody upgrade,
  NSM user_data echo, provenance SPDX parse + sig coverage).

## What this is

`bootproof verify` (no target) renders the trust state of the system it runs
on. Two views over the same gathered evidence:

- **Default: succinct summary** — the most important facts (instance,
  account, region, cpu, memory, isolation, tpm, boot, os, secure boot), each
  with a verdict mark (✓/~/?/✗) and the **vendor root(s)** whose
  cryptographic attestation proves it: `AWS` (NitroTPM chain + signed IIDD),
  `AMD` (SEV-SNP report anchored to the pinned AMD root), or both
  (`AWS AMD` for boot: PCRs in the AWS-signed doc + the AMD-PSP launch
  measurement in the SNP report). Self-reported facts show `(self)`. A
  footer shows the cross-attestation binding (fresh nonce shared by the
  AWS-signed TPM doc and the AMD-signed SNP report) when it is `true`.
- **`--expert`** — the full human-friendly tree: vendor-agnostic top-level
  facts, each with a 4-state verdict; vendor/platform-specific detail
  (SEV-SNP, NitroTPM, IMDS, sysfs) in evidence sub-branches. Branches, in
  order: **Cryptography, Custody, Security, Access, Hardware, Software**.
- `--json` emits whichever view is selected (summary JSON by default —
  facts carry a `vendors` array — full tree JSON with `--expert`).
- Running `bootproof verify <target>` (with a target) still does the existing
  remote TLS client flow; the local views are the **default** (no target).

## Cryptography branch

Four key types as entries. Where the key is not yet identified/wired, the
value is **`N/A`** (per operator direction). Real key-wrapping comes later:
1. **Ephemeral Key** — encrypt a secret, short-lived.
2. **System Key** — encrypt a secret to a persistent key locked to THIS system.
3. **User Key** — encrypt to the active User Key; recoverable by
   m-of-n user shares.
4. **Provider Key** — encrypt to the active Provider Key;
   recoverable by m-of-n provider shares.
5. **Cross-Attestation Binding** — `true` when BOTH attestations are fresh
   and share a nonce: the SEV-SNP report's random `report_data` (64 bytes,
   covered by the report signature) is derived FIRST, its first 32 bytes
   become the nonce embedded in the NitroTPM attestation document (nonce
   echo verified against the pinned AWS root). The same 32 bytes therefore
   appear in two independently signed artifacts — the TPM document (pinned
   AWS root) and the SNP report (pinned AMD root) — both signed on this
   system, in this run, after the nonce existed. Artifacts from different
   machines or times cannot be spliced. `unknown` when a fresh report with
   report_data wasn't obtained or the TPM attestation didn't verify.

## Custody branch (who owns it)

- **Owner / Account** — `true` when the signed Instance Identity Document
  (IIDD) verifies: PKCS#7 from IMDS `latest/dynamic/instance-identity/pkcs7`,
  DSA/SHA-1 signature verified against the **pinned per-region AWS DSA
  certificate** (all 39 regional certs embedded at build time in
  `src/trust/data/iidd/`). Only the SIGNED embedded content is trusted — the
  plaintext document endpoint is never read. A MISMATCH `false` evidence
  line appears if IMDS `iam/info` shows a different account.
- **Instance** — `true` when the signed NitroTPM module id embeds the
  instance id (cross-checked against IMDS `instance-id` and the hostname);
  the signed IIDD instanceType is a `True` evidence line and drives the
  value.
- **Location** — `true`; region proven by the NitroTPM cert-chain CNs, with
  the signed IIDD region + IMDS `placement/*` as further evidence.
- **Custody Chain** — `likely`; the hardware chain "AWS datacenter → Nitro →
  NitroTPM → SEV-SNP (AMD)", with a note that physical facility custody is
  not verifiable from the guest.

## Access branch (is admin available)

- **Administrative Access** — `likely` when any admin path is found; evidence
  lines for IAM role (IMDS), local root uid 0 (`/proc/self/status`), SSH
  (`/etc/ssh/sshd_config` or running `sshd`), serial console
  (`console=ttyS*` in `/proc/cmdline`). `unknown` when nothing is found.

## Security branch (8 facts) + draft verdicts

1. Memory Encryption — `true` (SEV-SNP per-VM key + TSME).
2. Filesystem Encryption — `unknown` on this instance (no guest block-layer
   LUKS; EBS/KMS not verifiable from guest). When dm-crypt IS bound to a
   TPM (`luks_tpm_bound`), it renders `true` — "Hardware locked (TPM)" with a
   `tpm-pcr` evidence line explaining the PCR bindings (PCR0=UEFI firmware,
   PCR2=Secure-Boot DB, PCR4=kernel image, PCR11=kernel cmdline).
3. Memory Isolation — `true` (SEV-SNP ASID + mem-enc; Debug off; Page-Swap-Disable).
4. Secure Boot — `unknown` (UEFI active, `/sys/firmware/efi/sb` not exposed).
5. Hardened Kernel — `likely`/`true` (SMAP/SMEP/IBPB/STIBP + `/proc/config.gz`).
6. Hardware Backed Entropy — `true` (TPM GetRandom + RDRAND/RDSEED + `/dev/hwrng`).
7. Hardware Backed Ring Isolation (SVSM) — `true` (SEV-SNP VMPL rings, CPU-enforced).
8. Hardware Network Isolation — `likely` (Nitro ENA per-VM vNIC; "dedicated VM"
   not cryptographically provable from guest).

## Hardware branch

CPU (SEV-SNP CPUID + /proc/cpuinfo), TPM (NitroTPM), Memory, Storage.
(Location lives in Custody.)

## Software branch

OS (Stageˣ), Kernel (7.2.0), measured-boot — now a **dual-vendor fact**: the
boot artifacts are measured into TWO independent vendor roots, the 24 PCRs
in the AWS-signed NitroTPM document and the AMD-PSP **launch measurement**
(guest image hash) inside the AMD-signed SEV-SNP report.

- **Root Integrity (measured)** — "the root filesystem cannot be altered
  between boots without detection". `true` only when a **pinned expected-PCR
  policy** (`--pcr-policy`, established with `verify-nitro --emit-pcrs`)
  matches the AWS-signed attested doc (vendors: AWS, + AMD when the SNP
  launch measurement is anchored). Without a pin the fact is `unknown` —
  attested PCRs with no expected values detect nothing. The UKI/rootfs
  image-hash (PCR17) measurement and dm-verity on the root are later
  phases; until then the pin covers the PCRs the platform/guest currently
  measure (firmware, boot manager, kernel, cmdline).

## Provenance branch (image-baked build provenance)

StageX bakes a full **SPDX 2.3** build-provenance document into the image
root at build time (`/provenance.spdx`): source origin (repo + commit +
branch + dirty flag via the `stagex` package's `ExternalRef git-of-origin`),
per-package **SHA256 digests** (215 on the dev image), and the complete
DEPENDS_ON graph (1651 edges). `collect_provenance()` parses it when present
(server-side: the file lives on the machine being attested) and renders a
`Provenance` branch — `unknown` by construction, because the build wrote the
document (self-reported) and the tree does not fetch signatures.

Closing the gap is `bootproof provenance` (subcommand, same binary):

- `--sigs <signatures-repo checkout>` — checks each digest against the
  published container signatures, layout
  `stagex/<name>@sha256=<digest>/signature-N` (one file per independent
  rebuild; quorum >= 2). Tries the exact package name, then with the
  `core-`/`user-`/`pallet-`/`bootstrap-`/`service-` prefix stripped (older
  sig dirs drop it).
- `--lookaside https://sigs.stagex.tools` — same check against the remote
  lookaside endpoint.
- `--keyring <pgp>` — verifies found signatures with gpg against the
  StageX maintainer keyring (sig files are complete PGP signed messages,
  Container Signature Format payload embedded).

Verdicts: `?` unsigned build; `~` partially signed; `✓` all signed at
quorum. The dev image built from `lance/distros` is **unsigned**: 0/215
digests overlap the 4789 published sig digests, while the repo's
`digests/*.txt` manifests match the published set 100% — the release builds
are fully signed and this local build simply predates any co-signing.

**Digest semantics** (from `src/provenance.py`): per-package
`PackageChecksum` = `sha256(out/rootfs/<pkg>/manifest.txt)`; the image
package digest = `sha256(disk.img)`. The document is a deterministic
function of (commit, branch, origin, dependency digests) — that is what
makes local rebuild confirmation possible.

**Local rebuild confirmation** (`--compare`): rebuild at the pinned commit,
regenerate the document with `python3 src/provenance.py <target> --raw`,
then `bootproof provenance --path <baked> --compare <regenerated>` prints a
per-package match/mismatch/added/removed table and exits 3 on any drift
(0 when identical). This is the full-confirmation path for an unsigned
build: no published signature exists, so only a reproducing rebuild at the
pinned source commit proves the digests.

## Location / code layout

- New module: `crates/bootproof/src/trust/mod.rs` (data model + gatherers +
  renderer + `run(Opts)`).
- Register `pub mod trust;` in `crates/bootproof/src/lib.rs`.
- `crates/bootproof/src/main.rs`: make `Verify`'s `target` **optional**; when
  absent, call `trust::run`. Keep existing remote flow for `Some(target)`.
- Reuse: `crate::facts::Facts` (guest base facts),
  `bootproof_tpm::attest::parse_attestation_document`,
  `bootproof_sdk::format::nitro::Nitro::with_pcr_policy` + `.verify`.

## Gatherers (each returns a small struct)

- `collect_nitro(device, tcp, nv_index, binding_nonce, policy, user_data)`:
  open TPM -> nonce (SEV-SNP report_data or `get_random(32)`) ->
  `attestation_document(user_data, Some(nonce), None, nv_index)` (the NSM
  echoes caller `user_data` into the signed document; 8 KiB request limit) ->
  `parse_attestation_document` (module_id, pcrs, cert, cabundle, user_data) ->
  `Nitro::with_pcr_policy(doc, policy).verify(now, &nonce)` -> region from cert CNs.
- `collect_snp()`: `snpguest report /tmp/snp_report.bin /tmp/snp_req.bin -r`
  (if absent) then `snpguest display report /tmp/snp_report.bin`; parse the
  display TEXT (not the binary) for CPUID/policy/TSME/VMPL/measurement/TCB.
- `collect_imds()`: raw-socket HTTP (IMDSv2). PUT
  `http://169.254.169.254/latest/api/token` (ttl 60) -> token; then GET
  `latest/meta-data/placement/region`,
  `latest/meta-data/placement/availability-zone`,
  `latest/meta-data/instance-id`, `latest/meta-data/instance-type`,
  `latest/meta-data/iam/info` (JSON `AccountId`, or bare ARN on old v1),
  `latest/meta-data/iam/security-credentials`. All with the
  `X-aws-ec2-metadata-token` header.
- `collect_iidd(preferred_region)`: GET
  `latest/dynamic/instance-identity/pkcs7` (base64) and verify the embedded
  DSA/SHA-1 signature in pure Rust (num-bigint; no pkcs7/openssl dep).
  The signature covers the **canonical signed attributes** (the `a0`
  SET re-encoded with the `0x31` tag), NOT the content; the content is
  bound via the (signed) messageDigest attribute, which must equal
  SHA-1(content). AWS wraps the r/s pair in an OCTET STRING (not the
  standard BIT STRING) and the certs are X.509 v1 — x509-parser exposes
  only `y` for them, so p/q/g are parsed from the raw DER (the
  dsaEncryption OID's following SEQUENCE, then the BIT STRING for y).
  Region-agnostic: tries the NitroTPM-proven region's cert first, then all
  39 pinned certs (19 regions share one cert; 20 distinct keys).
- `collect_guest()`: `crate::facts::Facts` + secure-boot (efi/sb), LUKS
  (/sys/fs/cryptsetup, dm-0 target type), hardening flags (smap/smep/ibpb/stibp/
  rdrand/rdseed from cpuinfo), `/dev/hwrng`, NIC driver/vendor
  (/sys/class/net/eth0/device/{driver,vendor}), IOMMU (/sys/kernel/iommu/),
  MemTotal (/proc/meminfo), /proc/config.gz hardening options.

## Verdict rules (2026-08-27 audit: nothing `true` that a lying system could forge)

`true` requires an anchor to a **pinned trusted root** that the guest cannot
control, with signature + freshness:
- **NitroTPM chain** — attestation doc ES384-signed, chain verified to the
  **embedded (pinned) AWS Nitro Enclaves root CA** (`aws.nitro-enclaves`,
  SHA-256 `64:1a:03:21:a3:e2:…`, embedded in the binary via
  `bootproof_sdk::format::nitro::aws_nitro_root_ca_der()`), plus a
  TPM2_GetRandom **nonce echo** (freshness, replay-proof). A malicious guest
  or platform cannot forge this without breaking the signature or the pin.
- **user_data channel** — `bootproof verify --user-data <text>` places the
  text in the NSM attestation request; the NitroTPM signer echoes it into
  the attestation document, so it sits inside the SAME ES384 signature that
  chains to the pinned AWS root, in the same signed blob as the PCRs, nonce,
  and module id. With a matching `--pcr-policy` pin, the metadata is thus
  AWS-authenticated AND bound to a known-good boot state. (This is signature
  coverage, not a TPM2 NV-auth-policy PCR lock: a compromised runtime can
  put anything in a NEW document, but that document carries the compromised
  PCRs, which the policy-enforcing verifier rejects.)
- **IIDD (signed instance identity document)** — the PKCS#7 from IMDS is
  DSA/SHA-1-signed by AWS's per-region IIDD key; all 39 regional certs are
  pinned in the binary at build time, so the signature verifies against a
  root the guest cannot control. The signed attributes bind the content
  (messageDigest), so accountId / instanceType / region / instanceId in the
  embedded JSON are proven.
- Facts that stay `true`: **TPM**, **Measured Boot** (PCRs inside the signed
  doc), **Instance** (module id in the signed doc + signed IIDD type),
  **Location** (region in the signed cert chain CNs + signed IIDD),
  **Owner / Account** (signed IIDD), **Cross-Attestation Binding** (one
  fresh random nonce inside TWO independently pinned-root-signed artifacts,
  so neither artifact can be replayed or spliced from another machine/run).

`likely` covers everything a malicious system could lie about that is not
anchored to a pinned root:
- **Kernel self-reports** (/proc/cpuinfo, /dev/hwrng, RDRAND/RDSEED,
  /sys/firmware/efi/sb, LUKS/dm-crypt via sysfs, /etc/os-release,
  /proc/meminfo, /proc/partitions) — a malicious kernel can claim or hide
  these.
- **Custody Chain / Network Isolation** — architectural
  claims not independently provable from the guest. (Owner/Account moved to
  `true` via the signed IIDD.)

## Proof anchors available in this environment

1. **NitroTPM endorsement chain (pinned root + nonce)** — rendered under the
   TPM fact: full CN chain leaf→…→pinned root + root SHA-256.
2. **AMD SEV-SNP full chain to the AMD root** — the missing piece that
   turned the four SNP facts from `likely` to `true`:
   - `snpguest certificates pem <dir>` requests the **extended report** from
     the AMD PSP, which on this platform returns the **VLEK X.509
     certificate** (CN=SEV-VLEK, ECDSA P-384, per-TCB, ~1-year validity) —
     named `vlek.pem` (it's a cert, not just a key).
   - The KDS **does NOT serve per-TCB VLEK leaf certs** (`/vlek/v1/{prod}/cert`
     404s for Milan and Genoa; only VCEK has a `/cert` endpoint). The VLEK
     leaf comes from the platform; the **root of trust** comes from KDS:
     `GET https://kdsintf.amd.com/vlek/v1/Milan/cert_chain` (note: host is
     `kdsintf.amd.com`, no hyphen) → ASVK (CN=SEV-VLEK-Milan) + ARK
     (CN=ARK-Milan, self-signed). These are pinned in the binary at build
     time (`src/trust/data/`, provenance in data/README.md).
   - Runtime verification (shells out to snpguest, which does the crypto):
     `snpguest verify certs <dir>` → "ARK self-signed / ASVK signed by ARK /
     VLEK signed by ASVK"; `snpguest verify attestation <dir> <report>` →
     "VEK signed the Attestation Report" + TCB field matches (bl/tee/snp/
     ucode).
   - KDS is unreachable from the guest (no outbound DNS); that's fine — only
     the per-build pin fetch needs it.
3. **NOT available here:** VCEK (chip ID fully masked in the report by
   platform policy; KDS `/vcek/v1/.../cert` needs the unmasked HWID —
   dedicated-host path only). TCG EK-list/EKCA for the NitroTPM — the
   pinned AWS Nitro root is the equivalent.
4. **Cross-attestation binding nonce** — snpguest does not randomize
   report_data on its own; `snpguest report <rep> <req> -r` generates random
   report_data AND writes it back into the request file (a stale
   all-zero request file yields an all-zero report_data, which the
   collector detects and treats as not-fresh). The collector removes both
   files first, runs `-r`, reads report_data from the report (1184-byte
   firmware report; report_data at file offset 0x50) and cross-checks it
   against the request file; first 32 bytes → TPM document nonce.
5. **Signed IIDD (per-region AWS DSA certs pinned)** — proves AWS account,
   instance type, region, instance id:
   - IMDS `latest/dynamic/instance-identity/pkcs7` is a PKCS#7 (BER,
     indefinite length) whose signed content is the identity JSON embedded
     in the pkcs7 itself (the plaintext document endpoint is deliberately
     unused).
   - Signature scheme DSAWithSHA1 (p 1024 / q 160); the signature covers the
     canonical signed attributes (SET tag `0x31`), not the content; the
     content is bound by the (signed) messageDigest attribute.
   - AWS non-conformances handled: the r/s pair is wrapped in an OCTET
     STRING instead of a BIT STRING; the certs are X.509 v1 and x509-parser
     exposes only `y`, so p/q/g are parsed from the raw DER.
   - 39 regional certs pinned at `src/trust/data/iidd/<region>.pem`
     (provenance + SHA-256-of-DER fingerprints in data/iidd/README.md;
     fetched 2026-08-27 from docs.aws.amazon.com regions-certs; 19 regions
     share one cert, 20 distinct keys). Verification is cross-checked
     against openssl smime and Python's `cryptography` DSA verify.
   - A unit test embeds a captured 866-byte pkcs7 fixture and asserts:
     verifies against the pinned us-east-2 cert, tampered attributes fail,
     a different region's key (af-south-1) fails.
6. **Follow-up to reach `true` on software:** pin golden PCR0/2/4 values for
   the known-good StageX boot chain; a signed doc matching them upgrades
   Measured Boot from "24 PCRs present" to "measurements match known-good
   boot", and OS/Kernel from `likely` to `true`.

## Build / test / deploy (verified working)

- glibc build: `CARGO_TARGET_DIR=/home/lrvick/.bp-release cargo build --release -p bootproof`
- Tests: `cargo test -p bootproof-sdk --features nitro`;
  `cargo test -p bootproof-tpm --features attest`; `cargo test -p bootproof`
- musl build:
  `docker run --rm --entrypoint /bin/sh -v /home/lrvick/Sources/bootproof:/src -w /src bptpm-dev:latest -c 'cargo build --release -p bootproof --target-dir /src/.target-musl'`
- Deploy:
  `ssh -i ~/.ssh/tpm-exploration.pem -o StrictHostKeyChecking=no root@3.19.141.73 'pgrep -x bootproof | xargs -r /bin/kill -9; sleep 1; cat > /root/bootproof; sync; chmod 755 /root/bootproof; sha256sum /root/bootproof' < /home/lrvick/Sources/bootproof/.target-musl/release/bootproof`
- Run on instance: start `tpm-bridge --listen 127.0.0.1:51000 --control 127.0.0.1:51001`,
  then `/root/bootproof verify --tcp 127.0.0.1:51000 --nv-index 0`
  (no target -> trust tree). `--json` for machine output.
- **Pitfall:** tpm-bridge is single-connection and `serve` holds it for its
  lifetime. Do NOT run `serve` concurrently with the trust tree; stop it first
  so the trust tree's TPM connection succeeds.
- **Pitfall (Text file busy):** you cannot overwrite `/root/bootproof` while
  any bootproof process is executing it. Kill the bridge FIRST in a SEPARATE
  ssh call (`pkill -f "bootproof tpm-bridge"`) — do not combine pkill + `cat >`/
  in one shell, because `pkill -f` also matches the remote shell's own command
  line and kills it (ssh exits 255).
- **Pitfall:** StageX has no `ss`/`python3`; check the bridge with
  `pgrep -af tpm-bridge` and its log.

## Instance facts (c6a.large, us-east-2c, AMD EPYC Milan)

- OS = StageX (NixOS-based immutable). Kernel 7.2.0. Hostname
  `ip-172-31-47-16.us-east-2.compute.internal` (cross-anchors region).
- IMDS v2 fully works: token + all `latest/meta-data/*` paths.
  `iam/info` answers JSON (AccountId 412541033472, instance-profile
  `tpm-attest-profile`). IIDD pkcs7 = 866-byte BER, DSAWithSHA1, signer
  serial `96:BA:48:D9:E5:5E:1A:67` (the us-east-2 IIDD key).
- NitroTPM: module `i-02a44cb68978c43af-tpm...`, region in cert CNs, pinned
  root fp `64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B`.
- SEV-SNP: CPUID Family 25/Model 1/Step 1, policy 0x2030000 (SMT on, Debug off,
  Page-Swap-Disable on), TSME on, ECC on, VMPL=1, vlek, version 1.58.1.
  TCB: bl=4 tee=0 snp=29 ucode=222. Chip ID fully masked (all zeros).
  Platform serves the VLEK X.509 cert via `snpguest certificates pem` (CN=
  SEV-VLEK, issuer SEV-VLEK-Milan, ECDSA P-384, valid to 2027-03-09).
- NIC: eth0 ena, vendor 0x1d0f (Amazon), device 0xec20. No IOMMU to guest.
- MemTotal ~3.5GB. CPU flags: smep,smap,ibpb,stibp,pdpe1gb,rdrand,rdseed.
- UEFI active; `/sys/firmware/efi/sb` ABSENT. `/proc/config.gz` present.
- No LUKS/dm-crypt. dm-0 name="home" (target type: recheck via
  /sys/block/dm-0/dm/table).
- No python3 on the instance (parse locally).
