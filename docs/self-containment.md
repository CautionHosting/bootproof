# bootproof self-containment: killing the external-binary dependencies

Status: in progress — items 1–4 done (gzip, pgrep, lsblk, gpg), items 5–6 pending
Date: 2026-09-06
Branch: `lance/tpm2-qname` (this doc is at `534bd6c`)

## 1. Goal

The shipped `bootproof` binary is already a single static musl ELF (the
`package` stage is `FROM scratch` + `COPY` of the binary only), but it is
**not** self-contained: at runtime it shells out to host OS binaries that are
neither in the image nor under our control. A guest image missing any of them
silently degrades the attestation tree (fields drop out, `None` everywhere)
instead of failing loudly -- exactly the failure mode an attestation tool must
not have, because the absence of evidence then reads as absence of a problem.

Target state: **zero OS process execs** from the bootproof binary. Every
external-binary dependency below is replaced by an in-process pure-Rust (or
static-linked) library. The two load-bearing migrations -- SEV-SNP (`snpguest`)
and OpenPGP (`gpg`) -- are already **proven live** against real firmware
output and real published signatures (Sections 4 and 5).

## 2. The inventory (ground truth, re-verified 2026-09-06)

`grep -rn "std::process::Command::new" crates/` finds exactly **8 OS-exec
sites in 3 files**. (A raw `Command::new` search finds 36; the other 28 are
`conn::Command` TPM wire-message builders -- false positives -- plus
`bootproof-tpm/build.rs` clang invocations and example probes, which are
build-time, not runtime.)

| # | Binary | Site | What it does today |
|---|--------|------|--------------------|
| 1 | `snpguest` | `trust/mod.rs:630` | `snpguest report <rep> <req> -r` -- fetch a fresh SNP report with random `report_data` (the cross-attestation binding nonce) |
| 2 | `snpguest` | `trust/mod.rs:642` | `snpguest display report <file>` -- pretty-print the 1184-byte report; bootproof then **regexes the human-readable text** (`field_value`/`field_bool`/`policy_hex`/`hex_block`) |
| 3 | `snpguest` | `trust/mod.rs:689` | `snpguest certificates pem <dir>` -- fetch the platform-provisioned VLEK cert via the extended-report cert table |
| 4 | `snpguest` | `trust/mod.rs:1335` (`snpguest_exit_ok`, callers at 705/707) | `snpguest verify certs` / `snpguest verify attestation` -- **the actual crypto verification** (VLEK→ASVK→ARK chain, report signature, TCB check) is delegated to the host binary |
| 5 | `gpg` | `provenance.rs:292` | `gpg --batch --quiet --no-default-keyring --keyring K --verify sig` -- verify StageX published package signatures |
| 6 | `lsblk` | `facts/mod.rs:139` | `lsblk -bno NAME,SIZE,TYPE,FSTYPE,MOUNTPOINT` -- disk summary (has a `/proc/partitions` fallback) |
| 7 | `pgrep` | `trust/mod.rs:1175` | `pgrep -x sshd` -- sshd-running signal (OR'd with a config-file check) |
| 8 | `gzip` | `trust/mod.rs:1242` | `gzip -dc /proc/config.gz` -- kernel hardening options |

What the **shipped image** actually contains (live read from a StageX
SEV-SNP guest, `c6a.large` Milan): `snpguest` 13,029,744-byte musl static
ELF; `lsblk` 557,696 bytes (and **broken** -- missing `libncursesw`, which is
why `facts/mod.rs` already carries the `/proc/partitions` fallback);
`gzip` and `pgrep` are 16-byte symlinks (busybox applets); `gpg` is
**not installed at all** -- so the gpg path is a latent no-op on the exact
platform this tool targets. `openssl` (1.2 MB) is present but only as a
dynamic dep of `snpguest`/`lsblk`, which we are removing.

**Not in scope (and not a problem):** the `bootproofd` daemon is a separate
crate with separate design goals; the TPM2 channel is **already** direct
hardware (Section 7). No `dbus`, `abrmd`, `tcsd`, or socket-daemon references
exist anywhere in `crates/bootproof/src`.

## 3. The failure-mode argument

Today, "the guest lacks `snpguest`" and "the guest has no SNP" produce the
same tree output: `SnpFacts { present, ..Default }`. The `present` flag is
`/dev/sev-guest` existence, which is correct -- but every downstream field
then reads `None`, indistinguishable from "firmware returned nothing". The
sev-crate migration makes each failure mode **named**: `io::Error` from
`Firmware::open()`, `UserApiError` from the ioctl, `Result` errors from
decode/verify. That is the real payoff beyond fewer dependencies.

## 4. SEV-SNP: replace `snpguest` (sites 1–4) with the `sev` crate

**Library:** `sev` 8.0.0, `default-features = false, features = ["snp", "crypto_nossl"]`.
MSRV 1.85.0. `crypto_nossl` pulls `p384` + `sha2` (both already in bootproof's
lock) plus `rsa` + `x509-cert` (new, pure-Rust, no OpenSSL). It talks to
`/dev/sev-guest` via the same `SNP_GET_REPORT` / `SNP_GET_EXT_REPORT` ioctls
`snpguest` uses -- but in-process, returning raw bytes and typed structs.

### 4.1 API (ground truth from `sev-8.0.0` source, vendored)

```rust
use std::io::Cursor;
use sev::parser::Decoder;
use sev::firmware::guest::{Firmware, AttestationReport};
use sev::certs::snp::{Chain, Certificate, Verifiable};

let mut fw = Firmware::open()?;                       // opens /dev/sev-guest
let nonce: [u8; 64] = rand::random();                 // WE generate the binding nonce
let (report_bytes, cert_table) = fw
    .get_ext_report(Some(1), Some(nonce), Some(1))?;  // (Vec<u8>, Option<Vec<CertTableEntry>>)
let ar = AttestationReport::decode(&mut Cursor::new(&report_bytes), ())?;

// VLEK from the platform cert table (replaces `snpguest certificates pem`):
let vlek_der = cert_table.as_ref()
    .and_then(|t| t.iter().find(|c| c.cert_type == sev::firmware::host::CertType::VLEK))
    .map(|c| c.data.clone());

let vlek = Certificate::from_der(&vlek_der)?;
let chain = Chain {
    ca: sev::certs::snp::ca::Chain {
        ark:  Certificate::from_pem(AMD_ARK_MILAN_PEM)?,    // bootproof's pinned PEMs
        ask:  Certificate::from_pem(AMD_ASVK_MILAN_PEM)?,   // (asvk-sev-vlek-milan.pem)
    },
    vek: vlek,
};
(&chain).verify()?;                // AMD anchor: ARK self-signs → ARK signs ASVK → ASVK signs VLEK
(&chain, &ar).verify()?;           // report signature: VLEK ECDSA-P384/SHA-384 over report[..0x2a0]
let tcb_ok = ar.reported_tcb == ar.current_tcb; // (bootloader/tee/snp/microcode + fmc Option)
```

`CertTableEntry { cert_type: CertType, data: Vec<u8> }`, `CertType::{ARK, ASK,
VCEK, VLEK}` at `sev::firmware::host::types::snp`. The report-verify impl
(`sev/src/firmware/guest/types/snp.rs:718`) hashes `raw_report_bytes[..0x2a0]`
with SHA-384 and checks the `Signature{r,s:[u8;72]}` against the VLEK's
P-384 public key.

### 4.2 Live proof (ground truth, not a plan)

Two independent proofs, both re-run clean on 2026-09-06:

1. **In-guest** (`/home/lrvick/.jcode/scratch/sevproof`): fresh nonce →
   `get_ext_report` directly from `/dev/sev-guest` on live EC2 SEV-SNP
   hardware → VLEK from the cert table → full chain + report verify, all pure
   Rust. (Live SSH/ioctl links on the AWS instances were flaky and repeatedly
   dropped mid-run, so the durable evidence is #2.)
2. **Fixture-based** (`/home/lrvick/.jcode/scratch/sevproofverify`): verifies
   a **real** firmware report (1184 bytes, md5 `4eb57eef…`) and a **real** VLEK
   cert (md5 `1d61b637…`) captured from live hardware, fully offline and
   reproducible:

```
$ cargo run --release
report bytes: 1184  (want 1184)
[1] decoded: version 5  vmpl 1  signing_key 1  policy 0x2030000
[2] nonce binding OK: report_data == the 64 random bytes we sent (md5 dd7aca1a8979c2622257fc9354dab562)
[3] AMD anchor OK: ARK-Milan self-signs; ARK signs SEV-VLEK-Milan ASVK; ASVK signed the live VLEK
[4] report signature OK: VLEK (P-384/SHA-384) signed this exact firmware report
[5] TCB reported==current: true  (boot 4 tee 0 snp 29 microcode 222 fmc None)
[6] facts from typed fields:
    cpu fam/mod/st = Some(25) / Some(1) / Some(1)
    firmware 1 .58 .1   measurement[16]=7a89cceaaba0bbdddc4f775acca3ef15
    report_id=222ecc677aa2827eaa04eeb9f4ffbf2ade714cc22a0719575fbd5ec74c95afc4
    chip_id[8]=0000000000000000 (masked)

ALL CHECKS PASSED: sev crate (pure Rust) verifies real firmware report + VLEK chain.
```

### 4.3 Two nuances the migration must get right (both empirically confirmed)

**A. Build the `Chain` from bootproof's *pinned* PEMs, not
`sev::certs::snp::builtin`.** The sev crate's builtin Milan ASK is the
*generic* ASK (CN=`SEV-Milan`, SHA-256 `67:D3:03:BD…`), but the live VLEK
cert chains to the *VLEK-specific* ASVK (CN=`SEV-VLEK-Milan`, SHA-256
`C5:E0:81:F5…`) that bootproof already pins at
`trust/data/asvk-sev-vlek-milan.pem`. The builtin ARK does match bootproof's
pinned ARK-Milan (CN=`ARK-Milan`, SHA-256 `69:D0:63:B4…`), but using the
builtin ASK would make the anchor check fail against real Milan VLEKs. Keep
the pinned pair; delete nothing from `trust/data/`.

**B. Use the typed fields, not raw offsets.** Today `collect_snp` reads
`report_data` at raw file offset `0x50` (`trust/mod.rs:660`) and regexes the
`snpguest display report` text. For the v5 report layout, offset `0x50` is
correct (verified against the real fixture: the 64-byte nonce lands exactly
there and equals the request), but that is an implementation detail of one
firmware layout. `AttestationReport::decode` gives the same bytes as
`ar.report_data` plus every field bootproof currently scrapes as text:

| `SnpFacts` field | today (text regex) | after (`AttestationReport` typed) |
|---|---|---|
| `cpuid_family/model/stepping` | `field_value("CPUID … ID")` | `ar.cpuid_fam_id / cpuid_mod_id / cpuid_step` (`Option<u8>`) |
| `policy` | `policy_hex` | `format!("{:x}", ar.policy.0)` (`GuestPolicy`) |
| `smt_allowed` | `field_bool("SMT Allowed")` | `ar.policy.smt_allowed()` |
| `debug_allowed` | `field_bool("Debug Allowed")` | `ar.policy.debug_allowed()` |
| `page_swap_disable` | `field_bool("Page Swap Disable")` | `ar.policy.page_swap_disabled()` |
| `tsme` | `field_bool("TSME Enabled")` | `ar.plat_info.tsme_enabled()` |
| `ecc` | `field_bool("ECC Enabled")` | `ar.plat_info.ecc_enabled()` |
| `vmpl` | `field_value("VMPL")` | `ar.vmpl` |
| `signing_key` | `field_value("signing key")` | `ar.key_info.signing_key()` (0→`"vcek"`, 1→`"vlek"`, per sev's own `fmt`) |
| `measurement` | `hex_block("Measurement")[..32]` | `hex(&ar.measurement[..16])` (`[u8;48]` field) |
| `version` | `field_value("Current Version")` | `ar.current.{major,minor,build}` (`Version`) |
| `tcb_microcode` | `field_value("Microcode")` | `ar.reported_tcb.microcode` |
| `vlek_cert_cn` / `_not_after` | `pem_to_der` + `cert_cn` / `cert_not_after` | keep the existing x509-parser helpers (they stay for the Nitro path too) |
| `vlek_verified` | `snpguest verify attestation` exit code | `(&chain, &ar).verify().is_ok()` |
| `amd_chain_ok` | `snpguest verify certs` exit code | `(&chain).verify().is_ok()` |
| `report_data` | raw `raw[0x50..0x110]` | `ar.report_data` (`[u8;64]`) |

**Deletion scope** (all in `trust/mod.rs`, section header at `:1376`):
`field_value` (13 call sites, 667–680 + tests 3403–3406), `field_bool` (5 +
tests 3408–3410), `policy_hex` (1 + test 3407), `hex_block` (1 + test 3412),
`snpguest_exit_ok` (2), the whole `snpguest display text parsing` section, and
the `SNP_DISPLAY` test fixture + `snpguest_field_parsing` test (replaced by
decode-based tests). `pem_to_der` and `cert_cn` **survive** -- used by the
Nitro path (`:543,548`) and `dsa_params` (`:980`). `cert_not_after` survives
for `vlek_cert_not_after`.

**Nonce change:** today the *firmware request* randomness comes from
`snpguest -r`; after migration we generate the nonce in-process
(`rand::random::<[u8;64]>`) and pass it to `get_ext_report`. The all-zero
check in `collect_snp` (`rd.iter().any(|&b| b != 0)`) stays as a defense
against a firmware that ignores the request -- with an in-process nonce the
binding is structurally unforgeable, but keep the check.

**Edge case:** on some configurations the extended-report cert table comes
back empty (the platform returns no VLEK). `snpguest certificates pem` fails
the same way. The code must treat `cert_table: None`/no-VLEK as
"VLEK path unavailable" (current behavior: `amd_chain_ok`/`vlek_verified`
stay `None`), not as a hard error. sev exposes no separate guest cert-fetch
ioctl -- `get_ext_report` is the only path.

### 4.4 Implementation (done) — findings that diverged from the recipe above

- **`tcb_microcode` mapping correction:** the table above said
  `ar.reported_tcb.microcode`. The sev crate's `Display` prints the *Current*
  TCB before the *Reported* TCB, so the old text parser's first `Microcode:`
  line was `ar.current_tcb.microcode`. On live Milan firmware both are 222
  (verified against the fixture), so either choice is byte-identical — but
  `current_tcb` is the correct match for the old behavior, and that is what is
  implemented.
- **Error types are Debug-only:** `sev::error::UserApiError` and
  `AttestationReportError` derive only `Debug` (no `Display`), so the
  `tracing::warn!` sites use `{e:?}`.
- **No more temp files:** the old path round-tripped through
  `/tmp/snp_report_fresh.bin`, `/tmp/snp_req_fresh.bin`, and `/tmp/snp_certs/`.
  The in-process path holds everything in memory — `get_ext_report` returns the
  report bytes and cert table directly.
- **Nonce generation:** `rand::RngCore::fill_bytes(&mut rand::rng(), &mut
  nonce)` (rand 0.9), matching the crate's existing nonce idiom. The firmware
  echoes the 64 bytes into `ar.report_data`; the code asserts the echo matches
  and is non-zero before publishing `report_data`.
- **Verification (live, ground truth):** on the SEV-SNP Milan instance the
  expert tree output is **byte-identical** (md5 `62bb5c46…`) to the pre-migration
  (item-4) state: `SEV-SNP per-VM key + TSME (AMD-root-anchored)` verdict
  `true`, guest policy `0x2030000`, `report signed with vlek; ECC on`,
  `SNP firmware 1.58.1 (TCB microcode 222)`, report signature + TCB verified,
  and the full `VLEK (CN=SEV-VLEK, valid to Mar  9 19:30:05 2027) ← ASVK
  (SEV-VLEK-Milan) ← ARK (ARK-Milan, SHA-256 69d063b4…)` anchor.
- **Offline fixture proof:** `data/snp-report-fixture.bin` (1184 B real
  firmware report) + `snp-request-fixture.bin` (the 64-byte nonce) +
  `snp-vlek-fixture.pem` (the live VLEK cert) are now shipped in the crate and
  asserted by two tests: `snp_report_fields_match_baseline` (every typed field
  equals the live values above, including the nonce echo) and
  `snp_report_anchors_to_amd_root` (report signature + VLEK→ASVK→ARK chain
  verify offline, no `/dev/sev-guest`).
- **Deletions (as scoped):** `field_value`, `field_bool`, `policy_hex`,
  `hex_block`, `snpguest_exit_ok`, the `SNP_DISPLAY` fixture, and
  `snpguest_field_parsing`. `pem_to_der`/`cert_cn`/`cert_not_after` survive
  (Nitro path + the VLEK CN/notAfter now read from the DER in the cert table).
- **Binary size:** +0.26 MB (14.4 → 14.66 MB release musl static) for the sev
  `crypto_nossl` stack (p384/p256/p521/cx448/rsa/dsa + x509-cert). With this
  item, the bootproof crate has **zero** `Command::new` sites left.

## 5. OpenPGP: replace `gpg` (site 5) with the `pgp` crate (rPGP)

**Library:** `pgp` (the rPGP project) 0.16–0.20. MSRV 1.85 (≤0.17) / 1.88
(≥0.18). Pure Rust, no OpenSSL. The crate is **not** named `rpgp` -- that is
the project name, not the crate name (a common mistake).

**Critical finding (empirically verified):** the "GnuPG keyring"
`stagex-keyring.pgp` shipped in the StageX repo is **not** a kbx database.
It is a plain OpenPGP public-key packet stream -- first byte `0x99` =
binary tag 6 (public key packet), 7 key blocks. rPGP reads this directly;
no keyring import/export step needed. (gpg's kbx format is a separate
SQLite-ish store; we were storing raw packets inside a `.pgp`-suffixed file
all along.)

### 5.1 API (ground truth from a working proof)

```rust
use pgp::composed::{Message, SignedPublicKey, SignedPublicSubKey};
use pgp::types::{Fingerprint, KeyDetails, KeyId};

let keyring: Vec<u8> = fs::read(keyring_path)?;          // binary packet stream
let sig: Vec<u8>     = fs::read(sig_path)?;              // .asc is fine too (auto-detected)
let payload: Vec<u8> = fs::read(target_file)?;           // what the sig covers

let mut verified = false;
for key in PublicOrSecret::from_reader_many(&keyring)    // 7 key blocks
    .filter_map(Result::ok)
{
    let key = match key {
        PublicOrSecret::Key(k) => k,                       // SignedPublicKey
        _ => continue,
    };
    let mut msg = Message::from_bytes(&sig).ok()?;
    if matches!(msg, Message::Compressed(_)) {
        msg = msg.decompress().ok()?;                      // published sig is zlib-compressed (first byte 0xa3, tag 8)
    }
    let mut buf = Vec::new();
    msg.read_to_end(&mut buf)?;                            // MUST: computes the literal-data hash
    if buf != payload { continue; }                        // signed content must match target
    for vkey in key.verify_keys() {                        // primary + signing subkeys
        if msg.verify(vkey).is_ok() { verified = true; break; }
    }
    if verified { break; }
}
```

### 5.2 Live proof (ground truth, re-run clean 2026-09-06)

`/home/lrvick/.jcode/scratch/pgpprove`, verifying the **real** published
StageX signature (`signature-1`, 814 bytes, md5 `d9a30c41…`) against the
**real** keyring (`stagex-keyring.pgp`, 114,534 bytes, md5 `2d14eafe…`):

```
[1] keyring loaded: 114534 bytes, first packet tag byte = 0x99 (binary tag 6 public key)
[2] parsed 7 key blocks from binary stream (armored: false)
[3] signature loaded: 814 bytes, first packet tag byte = 0xa3 (binary tag 8 compressed)
[4] decompressed + read signed message; payload 231 bytes
[5] VERIFIED against a SIGNING SUBKEY (subkey #1 of 6)
ALL CHECKS PASSED
```

Cross-check: `gpg --batch --verify signature-1 target` reports "Good
signature from "Lance R. Vick <lrvick@...>"", RSA key
`67553FBDA46BB71ABD2E0B0B8E47A1EC35A1551D`. Same key, same result, no
process spawn.

### 5.3 Two nuances

**A. The published signature is a *compressed* OpenPGP message.**
`Message::from_bytes` returns `Message::Compressed` (zlib); `verify` on the
compressed wrapper fails. Must call `decompress()` first, then
`read_to_end` (which drives the literal-data hash), **then** `verify`.

**B. The signing key is a *subkey*, not the primary.** The primary key in
the keyring is a certification-only key; the signature is made by one of six
signing subkeys. Verification must iterate `key.verify_keys()` (or
explicitly `primary_key` + each `public_subkeys` entry). A naive
`msg.verify(&primary_key)` fails. `fingerprint()` lives on the `KeyDetails`
trait, not the struct -- import it to surface the verified key fingerprint
in the fact tree (useful for the tree: show *which* key verified).

**Scope of `verify_sig_gpg` today** (`provenance.rs:292`): it checks the
gpg exit code and greps `Good signature`. After migration, the replacement
returns `(verified: bool, key_fingerprint: Option<Fingerprint>, error:
Option<String>)` -- strictly more information for the trust tree. The
`--no-default-keyring` isolation gpg got is automatic: rPGP reads only the
bytes we hand it.

**Cargo feature note:** with default features `pgp` pulls ~155 transitive
crates (4.2 MB in the proof binary vs 940 KB for the sev proof). If binary
size matters, `pgp = { version = "0.16", default-features = false,
features = ["decompress", "armor"] }` plus the `std`/`rand`/`crypto-...`
feature set used by the proof -- to be trimmed during implementation.

### 5.4 Implementation (done) — findings that diverged from the recipe above

- **API drift (0.20):** `PublicOrSecret::from_reader_many` returns
  `Result<(Box<dyn Iterator<Item=Result<PublicOrSecret>>>, Option<headers>)>`,
  and `SignedPublicKey` has **no** `verify_keys()` method. The working shape:
  destructure the tuple, `filter_map(Result::ok)`, then check the primary with
  `msg.verify(&k)` and iterate `k.public_subkeys` explicitly. `verify` takes
  `&self` and is safe to call repeatedly on one parsed `Message` (the literal
  data is already hashed by the preceding `read_to_end`).
- **The old gpg exec was silently broken on GnuPG 2.x.** gpg 2.4.7 **cannot
  read the shipped keyring file at all**: `--list-keys` shows 0 keys and
  `--verify` exits 2 ("No public key"), because the file is a raw OpenPGP
  packet stream and modern GnuPG wants kbx. After `gpg --import` into a real
  kbx, the same file yields "Good signature". So the pre-migration
  `verify_sig_gpg` returned `false` for a valid signature on any GnuPG 2.x
  host. The rPGP migration removes the exec **and fixes a latent
  provenance false-negative**.
- **Cross-validation (ground truth, both directions):** for the pinned
  `core-bash@sha256=5b598c14…` entry, rPGP reported `pgp=YYYNY` (5 sigs);
  gpg (via imported kbx) reported GOOD/GOOD/GOOD/FAIL(no public key)/GOOD —
  exact match, and the single N is a true negative (that signing key is
  genuinely absent from the keyring). RSA and EdDSA keys both verified.
  The verifying fingerprint for signature-1 is the pinned
  `67553fbda46bb71abd2e0b0b8e47a1ec35a1551d`, asserted in the test.
- **Quorum design note:** there are 8 `core-bash@sha256=…` rebuild entries,
  each signed by a different maintainer key; the integration test must pin the
  exact entry (readdir order is arbitrary) or it will verify against whichever
  key happened to be first.
- **Log noise:** pgp emits `WARN` ("ignoring unexpected signature
  CertGeneric after Subkey packet") while parsing the keyring — benign
  (non-critical subkey self-signatures GnuPG tolerates). The default
  subscriber filter is now `warn,pgp=off`; a `RUST_LOG` in the environment
  still overrides it, as intended.
- **Binary size:** +3.4 MB (11.0 → 14.4 MB release musl static) for
  in-process OpenPGP. Accepted: this is the price of not shipping a `gpg`
  dependency, and the binary is already `FROM scratch`.

## 6. The trivial replacements (sites 6–8)

### 6.1 `lsblk` → `/sys/block` (+ existing `/proc/partitions` fallback)

`disk_summary` (`facts/mod.rs:139`) needs NAME/SIZE/TYPE/FSTYPE/MOUNTPOINT.
In-process equivalent, no exec:

- `/sys/block/<dev>/size` (512-byte sectors → bytes) and
  `/sys/block/<dev>/queue/rotational` cover NAME/SIZE/TYPE for block devices.
- Partitions: `/sys/block/<dev>/<dev>NN/size`, or the fallback already in
  the code (`/proc/partitions`).
- FSTYPE: `blkid -p` is the real answer, but `blkid` is also an external
  binary. Options, in order of preference: (a) parse the
  `/etc/fstab`+`/proc/self/mounts` pair (mounts give FSTYPE directly for
  anything actually mounted -- fstab covers the rest for unmounted); (b)
  read superblocks ourselves (vfat/ext4/xfs/erofs headers are trivial;
  this is what `blkid` does for the common cases). **Recommend (a)**: the
  fact is "what is this disk for", and `/proc/self/mounts` answers that for
  everything mounted, which is everything that matters on a StageX guest.
  The `lsblk`-broken-on-Milan (missing `libncursesw`) note in
  `docs/trust-tree.md:40–44` goes away entirely.

Implementation (done): two findings diverged from the plan above.
- **SIZE**: `/sys/block/<name>/size` does not exist for partitions on the
  Milan guest (only under the parent, `/sys/block/nvme0n1/nvme0n1p1/size`).
  The uniform source is `/proc/partitions` (1024-byte block counts), which
  matches `lsblk -b` byte-for-byte for every device, disk and partition.
- **FSTYPE/MOUNTPOINT**: the mount source in `/proc/self/mounts` is a *path*
  (e.g. `/dev/mapper/home` for the LUKS home volume), not a device number.
  It is canonicalized (symlinks resolved) to a canonical block name before
  matching, which restores the `/home` mountpoint + its `ext4` fstype.
- **Intentional diff**: the baseline carried `vfat` (nvme0n1p1) and
  `crypto_LUKS` (nvme1n1) tokens from libblkid superblock-probing *unmounted*
  devices. This replacement reports fstype only for devices actually mounted,
  so those two tokens are dropped. That is the honest, grounded behavior
  recommended above, not a regression.

### 6.2 `pgrep` → `/proc` scan

`pgrep -x sshd` becomes: iterate `/proc/[0-9]+/comm` (or `stat` field 2),
match `comm == "sshd"` (and `sshd: *` session variants if we want to catch
session threads -- today's `pgrep -x` does not, so plain `comm == "sshd"`
is the faithful replacement). ~15 lines, no exec, strictly faster. Keep the
existing OR with the `/etc/ssh/sshd_config` existence check.

### 6.3 `gzip` → `flate2` (promote to direct dep)

`kernel_hardening_options` (`trust/mod.rs:1242`) does `gzip -dc
/proc/config.gz`. In-process: `flate2::read::GzDecoder` over
`File::open("/proc/config.gz")`, `read_to_end`, parse as before.
`flate2` 1.1.9 is **already** in `Cargo.lock` as a transitive dep of `ureq`;
the change is one line in `crates/bootproof/Cargo.toml` (promote to direct,
no feature needed -- pure-Rust `miniz_oxide` backend is the default, no
`libz`). No new transitive deps.

## 7. TPM2: already self-contained (no work)

The TPM2 channel (`crates/bootproof-tpm`) speaks the raw 10-byte TPM header
framing directly to `/dev/tpm0` or a TCP endpoint (swtpm) -- no tpm2-tools,
no tpm2-abrmd, no tcsd, no dbus. The `esys` feature is **static C-FFI**:
`build.rs` compiles/links `libtss2-esys.a`, `libtss2-tcti-device.a`,
`libtss2-mu.a`, `libtss2-rcsp.a` in-tree (checked-in vendored C, clang at
build time, static archive linked into the musl ELF). No `dlopen`, no
plugin directory, no runtime library search. Confirmed by full-grep: zero
`abrmd`/`tcsd`/`dbus`/`tpm2-` binary references in `crates/`.

## 8. Daemon-scope note

`bootproofd` (the attestation daemon) is a separate crate with a separate
runtime profile; this doc does not touch it. Nothing in
`crates/bootproof/src` references a daemon, socket, or D-Bus name -- the
single-binary tool is the only runtime surface this migration concerns.

## 9. Image / Containerfile impact

The `package` stage is already `FROM scratch` + `COPY` of the static ELF, so
no new packages go *in*. What this removes from the *guest OS* dependency
list (the things the guest image must provide for bootproof to work fully):

| Guest package | Binary | After |
|---|---|---|
| `snpguest` (13 MB musl ELF + openssl 1.2 MB dynamic dep) | sites 1–4 | gone |
| `gnupg` (gpg -- currently **not installed** on the StageX SEV-SNP images) | site 5 | gone |
| `util-linux` (lsblk 557 KB, broken on Milan) | site 6 | gone |
| busybox applets (gzip, pgrep) | sites 7–8 | gone |

Net: the guest image no longer needs *any* package for bootproof's
SEV-SNP/OpenPGP/disk/host facts to work. The tool degrades from "silently
`None`" to "loudly `Err` with a named cause".

## 10. Risk assessment

| Change | Risk | Mitigation |
|---|---|---|
| sev: report fetch | Low | Same ioctl as snpguest; live-proven. `Firmware::open` error = no SNP (matches current `present` semantics) |
| sev: verify replaces snpguest's | **Medium** -- we now *are* the verifier | Live-proven chain + report verify on real firmware output (Section 4.2). Pinned AMD anchors stay authoritative; sev only does the crypto. Pin `sev = "=8.0.0"` |
| sev: ASVK nuance (4.3-A) | **High if missed** -- anchor verify would silently fail against real Milan VLEKs | Chain built from bootproof's pinned PEMs; a regression test asserts the pinned ASVK CN is `SEV-VLEK-Milan` (not the builtin `SEV-Milan`) |
| pgp: compressed/subkey nuances | **High if missed** -- signature verify silently fails | Both nuances live-proven (5.2); regression test verifies the real `signature-1` fixture offline |
| pgp: keyring format | Low | Empirically a plain packet stream (5.1); rPGP handles armored input too, so a future kbx-format keyring is the only break, detectable at parse |
| lsblk → sysfs/mounts | Low | Fallback chain already exists; fstab+mounts covers mounted facts; fact semantics documented |
| pgrep → /proc | Negligible | ~15 lines, identical semantics |
| gzip → flate2 | Negligible | flate2 already in the lock; pure-Rust backend |
| binary size | Low | +`rsa`, +`x509-cert`, +`pgp` (trim features) vs −nothing in-image. Est. +1–2 MB static. Acceptable for a tool whose whole point is verification |
| firmware layout drift | Low | Typed `AttestationReport` per AMD spec supersedes raw-offset reading; version field is decoded and checkable |

## 11. Implementation plan (per-item, each independently shippable)

1. **flate2** (1 line + 1 function) → drop `gzip` exec.
2. **pgrep → /proc** (1 function) → drop `pgrep` exec.
3. **lsblk → sysfs + mounts** (1 function + fallbacks) → drop `lsblk` exec.
4. **rPGP** in `provenance.rs` (replace `verify_sig_gpg` internals; keep the function signature, gain the fingerprint return) → drop `gpg` exec.
5. **sev** in `trust/mod.rs`: `Firmware::open` + `get_ext_report` for fetch + VLEK; `AttestationReport::decode` for facts; `Chain` from pinned PEMs for `amd_chain_ok`/`vlek_verified`; delete the text-parser section (4.3 deletion scope). → drop all four `snpguest` execs.
6. Update `README.md:115`, `main.rs:299` ("needs gpg" help text),
   `docs/agent-design.md:186,192`, `docs/trust-tree.md:40–44`.
7. Offline regression fixtures in-tree: the real SNP report + VLEK + request
   (Section 12 hashes) and the real StageX signature + keyring, so CI proves
   both migrations without AWS or gpg.

Order 1–3 first (zero-risk, immediate), then 4, then 5 (the load-bearing one,
last, behind the fixture tests from 7).

## 12. Evidence appendix (fixture hashes)

Proof crates on disk, all re-verified clean 2026-09-06:

| Path | Purpose |
|---|---|
| `/home/lrvick/.jcode/scratch/sevproof` | live in-guest fetch+verify (real `/dev/sev-guest`) + `fixtures/` |
| `/home/lrvick/.jcode/scratch/sevproofverify` | offline fixture verify (durable evidence) |
| `/home/lrvick/.jcode/scratch/pgpprove` | offline rPGP verify of the real published sig |

| Fixture | Size | md5 (prefix) |
|---|---|---|
| SNP `report.bin` (real firmware report, v5) | 1184 B | `4eb57eef…` |
| SNP `request.bin` (64-byte nonce) | 64 B | `dd7aca1a…` |
| SNP `vlek.pem` (real platform VLEK) | 1842 B | `1d61b637…` |
| `stagex-keyring.pgp` (OpenPGP packet stream) | 114,534 B | `2d14eafe…` |
| `signature-1` (real published sig, zlib-compressed) | 814 B | `d9a30c41…` |
| Pinned ARK-Milan | — | CN `ARK-Milan`, SHA-256 `69:D0:63:B4…` |
| Pinned ASVK (VLEK-specific) | — | CN `SEV-VLEK-Milan`, SHA-256 `C5:E0:81:F5…` |

Live proof binaries (size evidence): bootproof 11,157,000 B (current, with
all execs); sevproofverify 940,552 B; pgpprove 4,238,352 B (default pgp
features -- see 5.3 trim note).
