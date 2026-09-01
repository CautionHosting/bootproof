# Bootproof Project Memory

## AI Assistant Notes

### Current Task (handoff, Aug 28 2026)
Make bootproof's `pcr-extend` / `seal` / `unseal` work end-to-end against in-tree swtpm (libtpms 0.10.2) and live EC2 TPM2 (libtpms-derived NitroTPM firmware), then finish the `lance/cvm-support` branch (repo at `/home/lrvick/Sources/bootproof`, branch `lance/cvm-support`, HEAD `db75c6f` + uncommitted working-tree changes).

**MAJOR PIVOT (user-directed)**: After hours of wire-protocol debugging of the hand-rolled raw TPM client, the user decided: *replicate what rust-keylime does* — abandon the raw client for the seal/unseal/pcr-extend flows and use the standard TSS2/ESAPI stack (`tss-esapi-sys`), the same approach keylime uses. The user also said: *"make sure you clean up any code you are abandoning."*

**Why the pivot is viable**: `crates/bootproof-tpm` already has `tss-esapi-sys = { version = "0.6.0", optional = true }` behind the `esys` feature (`crates/bootproof-tpm/Cargo.toml:12,21`), and `crates/bootproof-tpm/src/esys.rs` is a ~900-line working `EsysTpm` (raw FFI style, not the tss-esapi wrapper crate) with: `open` (device TCTI + `Esys_Initialize`), `install_command_logger` (TCTI tx/rx trampoline; zeroes the SAS sessionAttributes byte — "dialect shim"; logs under `BP_LOG_TCTI=1`), `detect_dialect` (probes SYM_MODE_CFB_DIALECT 0x43), `ensure_started`, `get_random`, `flush_all`, `create_primary`, `create_primary_with_public`, `read_public`, `pcr_read`, `quote`, `hash`, `sign`, plus `build_ecc_sign_public` / `build_rsa_decrypt_public` / `marshal_public_bytes`.

**Repo state (bootproof working tree)**:
```
 M crates/bootproof-tpm/src/commands.rs        (raw client; parse_pcr_read unit tests ~:431-475)
 M crates/bootproof-tpm/src/commands_key.rs
 M crates/bootproof-tpm/src/commands_policy.rs
 M crates/bootproof-tpm/src/conn.rs
 M crates/bootproof-tpm/src/constants.rs       (alg table corrected to libtpms truth)
 M crates/bootproof-tpm/src/lib.rs
 M crates/bootproof-tpm/src/session.rs
 M crates/bootproof/src/main.rs                (CLI; PcrExtend ~:371/~:509, Seal ~:324/~:464, Unseal ~:347/~:487)
?? crates/bootproof-tpm/src/commands_seal.rs   (NEW, untracked — raw seal/unseal impl; ABANDONMENT candidate)
```
CLI subcommands today route pcr-extend/seal/unseal through the raw `Tpm` client. `crates/bootproof/Cargo.toml` has `default = ["platform-aws"]` — `esys` is NOT in CLI defaults.

## Exact Next Steps (ordered)

1. **Verify distro tss2 is stock upstream** (first gate): `ls /home/lrvick/Sources/stagex/packages/user/tpm2-tss/fetch/`; extract `tpm2-tss-*.tar.gz`; check `src/tss2-mu` marshaling of `TPM2B_DATA`/Load param order and TPMU_HA handling. The stagex Containerfile (`/home/lrvick/Sources/stagex/packages/user/tpm2-tss/Containerfile`) claims stock: `./configure --prefix=/usr --sysconfdir=/etc --localstatedir=/var --with-tctidefaultmodule=device --with-tctidefaultconfig=/dev/tpmrm0 --with-crypto=ossl`. If stock → "standard tss2 speaks to libtpms fine" and the raw-client spec memory was the bug (see Wire Format below — paramSize and raw TPMU_HA are standard TCG for session-tagged messages).
2. **Empirically confirm interop** (real gate): distro tpm2-tools 5.7 full seal flow vs swtpm. Restart swtpm fresh first (command below). Correct syntax (prior attempts failed only on surface): `tpm2_pcrextend` takes `--data` (NOT `--file`); TCTI via `TSS2_TCTI` — `TSS2_TCTI="swtpm:path=..."` once failed with `ERROR: Could not load tcti, got: "(null)"` (tctildr module search dir mismatch, modules are flat in `/usr/lib/`) — retry with `TSS2_TCTI="file:$R/usr/lib/libtss2-tcti-swtpm.so"`. Flow: `tpm2_pcrextend 16 --data /tmp/sealtest.txt` → `tpm2_policypcr -f /tmp/pol.ctx 16` → `tpm2_createprimary -C o -G sha256 -c /tmp/prim.ctx` → `tpm2_create -C /tmp/prim.ctx -g sha256 -G sha256 -t data -p none -u /tmp/obj.pub -r /tmp/obj.priv -L /tmp/obj.pol /tmp/sealtest.txt` → `tpm2_load` → `tpm2_evictcontrol` → `tpm2_unseal -p "session:/tmp/pol.ctx"`. Distro root: `R=/home/lrvick/Sources/stagex/out/rootfs/distro-enclave-dev/linux_amd64`; run via `$R/lib/ld-musl-x86_64.so.1 --library-path $R/usr/lib`. Note: distro tpm2-tools multiplexer (`/usr/bin/tpm2` + 103 symlinks) is missing the `tpm2_pcread` symlink; `pcrextend/policypcr/createprimary/create/load/evictcontrol/unseal` are present.
3. **Locate rust-keylime's esapi usage** for reference: `grep -rl esapi ~/Sources/keylime --include=Cargo.toml` (agent crate is the relevant one; a prior `find ... | xargs grep` returned nothing — retry).
4. **Implement in esys.rs** (existing FFI style): `pcr_extend`, `seal`, `unseal` on `EsysTpm`. ESAPI flow: `Esys_StartAuthSession` (policy, bind=NULL) → `Esys_PolicyPCR` → `Esys_CreatePrimary` (AES-CFB storage key) → `Esys_Create` sealed KEYEDHASH (authPolicy = policy digest) → `Esys_Load` → `Esys_EvictControl` persist; unseal = policy session + `Esys_Unseal`. Also add a swtpm-socket open path (`Tss2_Tcti_Swtpm_Init` or tcti-ldr conf string) so round-trip testing works — `EsysTpm::open` today uses the device TCTI (character device), which fits EC2 `/dev/tpm0`/`/dev/tpmrm0` but not the swtpm unix socket. KEEP the SAS-attrs trampoline shim (it exists because the StageX esys stack/firmware rejected non-zero SAS sessionAttributes).
5. **Wire CLI**: route `PcrExtend`/`Seal`/`Unseal` in `crates/bootproof/src/main.rs` through `EsysTpm` gated on the `esys` feature; add `esys` to `crates/bootproof/Cargo.toml` default features (propagating `bootproof-tpm/features=["esys"]`).
6. **Clean up abandoned raw-client code** (user explicit): delete raw seal/policy/pcr-extend machinery the ESAPI path replaces. Audit `main.rs` + attest first — keep what quote/certify/attest still need raw (esys.rs already has quote/sign/create_primary/read_public/pcr_read, so most raw paths are replaceable). Candidates: raw flows in `commands_seal.rs` (untracked, likely delete wholesale), `commands_policy.rs` policy-session start, `session.rs` raw session plumbing, `detect_dialect` callers.
7. **Round-trip test** (fresh swtpm): `bootproof pcr-extend 16 /tmp/sealtest.txt` → `bootproof seal --pcrs 16 --handle 0x81010200 /tmp/sealtest.txt` → `bootproof unseal --pcrs 16 --handle 0x81010200` → `cmp` outputs. (`/tmp/sealtest.txt` = "sealed-secret-1788282477".)
8. `cargo test` in bootproof (build is ~7s `cargo build --release`), commit all working-tree changes, push `lance/cvm-support`.

### Older pending todos (after the above)
- Direct SNP via the `sev` crate (not tpm-only paths)
- stagex `user-bootproof` + `user-dhcpcd` packages
- execd unit rewrites; distro Containerfile; `distro-enclave-dev-img` + QEMU boot verify
- nit push + AGENTS.md/docs update in stagex

## swtpm Test Harness (canonical, verified working)

`/tmp/swtpm-test/` is the canonical test dir. Exact fresh restart (swtpm binaries from the stagex distro VM rootfs, musl-wrapped):
```sh
cd /tmp/swtpm-test && pkill -f "swtpm-test/data.sock"; sleep 1
rm -f data.sock ctrl.sock dbg.log; rm -rf state && mkdir state
R=/home/lrvick/Sources/stagex/out/rootfs/distro-enclave-vm/linux_amd64
nohup $R/lib/ld-musl-x86_64.so.1 --library-path $R/usr/lib/swtpm:$R/lib $R/usr/bin/swtpm socket --tpm2 \
  --tpmstate dir=/tmp/swtpm-test/state \
  --server type=unixio,path=/tmp/swtpm-test/data.sock \
  --ctrl type=unixio,path=/tmp/swtpm-test/ctrl.sock \
  --log level=5,file=/tmp/swtpm-test/dbg.log > /dev/null 2>&1 & sleep 2
```
Restart fresh before re-testing (state dir carries PCR/session history from failed attempts). Diagnostic artifacts in `/tmp`: `seal_err{2..6}.txt` (raw client stderr dumps), `sealtest.txt` (seal input).

## Wire-Format Ground Truth (from libtpms 0.10.2 source, `/tmp/libtpms-0.10.2/src/tpm2/`)

Useful for verifying the ESAPI path interops correctly. All facts below were read from the source this session.

- **RC decode** (libtpms: RC_FMT1=0x080, RC_VER1=0x100, RC_WARN=0x900, RC_P=0x040, RC_1=0x100, RC_2=0x200, RC_S=0x800): `0x02CA` = RC_TYPE(0x08A)+param2 (missing `type` field / bad type); `0x0982` = RC_S+RC_1+RCS_ATTRIBUTES(0x082) (policy session attrs); `0x0184` = HIERARCHY; `0x0907` = PCR locality (PCRs 17-22 need locality ≥1/2; swtpm socket runs at locality 0 → use PCRs 0-16 or 23); `0x09A2` = RC_S+RC_1+BAD_AUTH.
- **Wire layout (session-tagged commands)**: command = header ‖ handles ‖ **paramSize u32** ‖ session area (per session: sessionHandle u32 ‖ nonceCaller TPM2B ‖ attrs u8 ‖ authValue/HMAC TPM2B) ‖ RAW params. Response = header ‖ output handles ‖ **paramSize u32** ‖ params ‖ session area (observed 69B = nonceTPM(34)‖attrs(1)‖authValue(34), no sessionHandle echo). This paramSize + raw TPMU_HA is STANDARD TCG — the raw client's initial spec misread caused much of the pain.
- **CommandDispatchData.h descriptors** (genuine libtpms deviations from TCG docs, or at least what libtpms implements): `CreatePrimary_Out = {objectHandle, objectPublic, creationData, creationHash, creationTicket, name}`; `Create_Out = {privateKey, objectPublic, creationData, creationHash, creationTicket}` (no name); `Load_In = {parentHandle, inPrivate, inPublic}` (inPrivate BEFORE objectPublic, no outsideInfo); `Load_Out = {objectHandle, name}`; `PolicyPCR` attrs = IS_IMPLEMENTED+DECRYPT_2+ALLOW_TRIAL, NO HANDLE_1_USER → a policy session in the session area must carry a decrypt/encrypt/audit bit.
- **TPMA_SESSION bits**: bit0 continueSession, bit5 decrypt (0x20), bit6 encrypt (0x40), bit7 audit (0x80).
- **ALG values (libtpms truth)**: AES 0x0006, KEYEDHASH 0x0008, SHA256 0x000B, NULL 0x0010, SYMCIPHER 0x0025, CFB 0x0043, CTR 0x0040, ECC 0x0023, ECDH 0x0019, HMAC 0x0005, XOR 0x000A, KDF1_SP800_56A 0x0020; curves P256=0x0003 / P384=0x0004.
- **Unmarshal.c**: TPMI_ALG_PUBLIC validates {KEYEDHASH,RSA,ECC,SYMCIPHER} else RC_TYPE(0x08A); TPMT_PUBLIC reads `type` FIRST; TPMT_SYM_DEF_OBJECT = alg‖keyBits‖mode; TPMS_KEYEDHASH_PARMS = scheme only; TPMA_LOCALITY marshal = 1 byte.
- **Marshal.c TPMS_CREATION_DATA order**: pcrSelect, pcrDigest, locality(1B), parentNameAlg, parentName, parentQualifiedName, outsideInfo. TPMT_TK_CREATION = tag(0x8021)‖hierarchy u32‖digest TPM2B.
- **SessionProcess.c**: session-area attrs with decrypt bit requires DecryptSize(cc)≠0 AND non-NULL session symmetric alg (else RCS_SYMMETRIC); non-authorization session must carry audit/encrypt/decrypt bit (else RCS_ATTRIBUTES). `CryptParameterDecryption`: buffer = u16 cipherSize ‖ ciphertext, cipherSize = ciphertext len excl. size field, key = sessionKey‖extraKey. SAS sessionType: HMAC=0x00, policy=0x01, trial=0x03.
- **Parameter encryption semantics for PolicyPCR** (has DECRYPT_2, no auth handle → policy session must be a decrypt session): client generates random 16B session key, sends it raw in SAS encryptedSalt (unsalted), symmetric=AES/128/CFB (`00 06 00 80 00 43`); command area attrs = 0x20 (decrypt); after session area: u16 cipherSize ‖ AES-CFB-encrypted params; HMAC key = sessionKey (no authValue), message = cpHash‖nonceCaller‖nonceTPM‖attrs. cpHash = SHA256(cc ‖ name(handle) ‖ RAW params); hierarchy/PCR/session handle name = raw 4-byte handle; transient name = object Name. Empty-key+empty-input HMAC → size-0 HMAC.

## Environment & Gotchas

- cwd of this memory: `/home/lrvick/Sources/stagex` (stagex repo, branch `lance/distros`). Bootproof repo: `/home/lrvick/Sources/bootproof`.
- Host glibc/gcc 14; distro musl binaries run via `$R/lib/ld-musl-x86_64.so.1 --library-path ...` (use the `-dev` rootfs for tss2 tools, the `-vm` rootfs for swtpm itself).
- `cargo build --release` in bootproof ~7s.
- Host `/usr/bin/tpm2*` multiplexer is BROKEN in this sandbox (symlink stat fails: `strace: Cannot stat '/usr/bin/tpm2_pcread'` even though `ls` shows it; direct `/usr/bin/tpm2` works) — always use distro tools via the ld-musl wrapper.
- mvdan/sh sandbox quirks: `$((16#…))` hex arithmetic silently yields 0/-1 — use `python3 -c "print(int('0x…',16))"`.
- `tpm2_pcrextend` takes `--data`, not `--file`.
- tctildr `TSS2_TCTI="swtpm:path=..."` failed once (module path); `TSS2_TCTI="file:<abs .so path>"` is the fallback.
- The esys.rs "dialect" shims (zeroing SAS sessionAttributes; SYM_MODE_CFB_DIALECT 0x43 vs standard CFB) exist because the StageX esys stack/firmware rejected a SAS-attrs variant — KEEP them when extending esys.rs.
- libtpms source at `/tmp/libtpms-0.10.2` (instrumentation reverted, build clean) — reusable reference.

## Distro Facts (stagex, for the interop test)

- The enclave distro ships the FULL standard tss2 stack under `/usr/lib/` (flat): `libtss2-{esys,fapi,mu,policy,rc,sys}` + tcti modules `{device,swtpm,socket,cmd,tabrmd,pcap,spidev,i2c-helper,mssim}` + `tctildr`. tpm2-tools 5.7 multiplexer at `/usr/bin/tpm2` with 103 symlinks (missing: `tpm2_pcread`).
- `packages/user/tpm2-tss/Containerfile` (stagex) = stock upstream configure (see Next Steps #1). Source tarball in `packages/user/tpm2-tss/fetch/`.

## Background (why this task exists)

Stagex enclave distro (lance/distros) does TPM2+SEV-SNP byte-level attestation: rust-keylime agent (replaced Python keylime, v0.2.10) uses the standard TSS2/ESAPI stack and works against both in-tree swtpm and live EC2 NitroTPM — that is the proof standard tss2 interops with the libtpms-derived firmware. Bootproof is a new attestation tool whose pcr-extend/seal/unseal were hand-rolled against a from-memory wire spec; every libtpms quirk became a multi-step debugging expedition (0x02CA type field → Load order → PolicyPCR attrs → parameter encryption). The user's decision: use the same libraries and approach keylime uses, and clean up the abandoned code.
