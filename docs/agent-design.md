# bootproof: Unified Attestation Framework — Research & Implementation Plan

Status: draft v4 (supersedes v1–v3)
Date: 2026-08-17

## 1. Goal

> **Build target:** `docs/mvp-spec.md` is the precise MVP functional spec —
> one `bootproof` binary with `attest` (server) / `verify` (client) /
> `decrypt` / `sign`, the lean extensible channel core, DNS discovery, and
> state-bound TPM keys. This document is the broad research + platform map;
> the spec is what gets built first.

A framework for **combined, cross-platform remote attestation** expressed as
one unified protocol, with a keylime-compatible wire interface. Two
user-facing binaries:

- **`bootproofd` (the daemon)** — runs on **every node that can attest**
  (guest, enclave, bare metal, laptop, phone). One binary, three combinable
  roles:
  - **node attester (default)** — presents one unified attestation interface
    that **behaves like keylime's agent API** (JSON over HTTP — the "TPM2
    over HTTP" interface) and, at the TPM layer, **behaves exactly like
    coconut-svsm's vTPM** (TCG simulator protocol; same engine and crypto
    libraries — TCG TPM 2.0 reference C code + OpenSSL — where a TPM is
    emulated). Combines **all attestation mechanisms available on the
    platform**: SEV-SNP + TPM2, TDX + TPM2, Nitro (NSM), IMA, UEFI/coreboot/
    Heads/Dasharo/TrenchBoot/safeboot measured boot, OP-TEE, NVIDIA CC,
    Android key attestation, Apple App Attest, WebAuthn, ...
  - **hub (`bootproofd --hub`)** — the publicly reachable HTTPS verification
    API server: registry, challenge orchestration over a **pubsub queue**
    (nodes and verifiers connect **outbound only** — works for enclaves and
    NATted phones), fleet health, verdicts, registrar-compatible identity
    API. The only inbound service in the deployment (§7).
  - **remote verifier coordinator** — `bootproofd` can **request and verify
    proofs from any number of other registered nodes**, not just the local
    system: it submits verify requests to the hub, which routes them to the
    targets, and it verifies the pushed-back proofs with the SDK.
- **`bootproof` (the client CLI)** — the requester/verifier. Registers the
  local device with a **local or remote** `bootproofd`, and can **verify any
  other registered device** over the pubsub protocol: it submits a request
  (optionally **locally signed and attested** with its own channels), the hub
  routes it to the destination, the destination signs it and pushes the
  result back, and the requester pulls it. A device that **only verifies**
  and cannot prove anything about local hardware runs **only** `bootproof`
  — no `bootproofd`.

### 1.1 Canonical use case #1 (server)

> I build a **deterministic application + operating system as a disk image**,
> and publish bit-for-bit reproducible build steps. Someone runs it on, e.g.,
> an Amazon `c6a.large` with **SEV-SNP enabled and NitroTPM**. The client wants
> a single attestation that means:
>
> *"This system is booting this kernel and root filesystem according to BOTH
> the NitroTPM (firmware measurements) AND AMD SEV-SNP (memory isolation), in
> a way that the attestation is only valid and possible if both components
> agree on it, without trusting each other."*
>
> The attestation must trace back to the exact deterministic disk image, and
> the image to the public source that built it.

### 1.2 Canonical use case #2 (phone / consumer device)

> The same protocol must work as an **alternative to attestation.app**
> (GrapheneOS Auditor: hardware-based remote attestation of Android devices —
> persistent hardware-backed key, verified boot state, TOFU baseline, scheduled
> remote verification with alerts). A phone behind NAT, a laptop, a server, or
> a browser-based verifier connects **outbound** to the hub, challenges a
> remote device, and gets a verdict about **its security state and ownership**
> — best effort over whatever hardware channels the device exposes.

### 1.3 Design goals

1. **One nonce, all channels.** The challenge nonce is signed by every
   available attestation channel (SNP, TPM2, NSM, TDX, key attest, ...) —
   "slot linking" (§3).
2. **No mutual trust between components.** No channel verifies another. The
   verifier does all cross-verification. Hardware components never see each
   other's evidence. An untrusted daemon can **withhold** attestation but can
   never **forge** it: every signature is produced inside hardware the daemon
   cannot key.
3. **Unified TPM2 proof.** The combined result is expressed as standard TPM2
   objects (Quote + PCRs + NV evidence + AK/EK) when a TPM exists, and as the
   same **Bundle** shape (quote optional) when it doesn't. Coconut-svsm- and
   keylime-compatible by construction.
4. **Provenance where possible.** The proof can be traced to the **provider's
   root** — AWS Nitro root + control plane, Azure CA/MAA, Google CA/EAT, AMD
   ARK, Intel PCS, NVIDIA PKI, Apple OSA, Google Key Attestation CA, a
   datacenter **Fleet CA** (DC-CA), or an owner key — establishing who
   owns/operates the system.
5. **Best effort across platforms.** One protocol, per-platform channel
   backends. Missing channels degrade the verdict; they never break the
   interface.
6. **Keylime-compatible superset.** `bootproofd` speaks the **exact keylime
   agent API** (v2.4 pull + v3 push). A stock keylime cloudserver can verify a
   bootproof node (partial: the TPM2 + IMA + measured-boot projection).
   `bootproofd --hub` is a drop-in superset of keylime's cloudserver +
   registrar. Nothing in the keylime protocol is weakened (§10).
7. **Most-compatible interface first.** The canonical node interface is
   **keylime-style JSON over HTTP** ("TPM2 over HTTP"), because it is the
   widest existing ecosystem; beneath it, the raw TPM2 surface is exposed via
   the TCG simulator protocol (unix/vsock/TCP) and a raw command relay, so
   tpm2-tools, swtpm-protocol clients, and coconut-svsm clients all work
   unmodified (§4.5).
8. **Outbound-only fleet topology.** Nodes **and** verifiers reach the hub by
   outbound connections over a pubsub queue — no inbound ports on enclaves,
   phones, or laptops (§7).

## 2. Research findings

### 2.1 coconut-svsm vTPM (the reference we mirror at the TPM layer)

`coconut-cloud/coconut-vtpm` is not publicly indexed; the public artifact of
the same lineage is the vTPM module in **coconut-svsm**
(`github.com/coconut-svsm/svsm`). Cross-check against the private repo if
access exists.

1. **Full TCG TPM 2.0 reference implementation wrapped in Rust** (`libtcgtpm`:
   bindgen over `Tpm_CoreLib`/`Tpm_PlatformLib`/`Tpm_CryptoLib_Math_Ossl`,
   OpenSSL backend).
2. **Transport = TCG TPM simulator protocol**: `TPM_SEND_COMMAND = 8`,
   `{u32 command, u8 locality, u32 inbuf_size, inbuf[4091]}` →
   `{u32 outbuf_size, outbuf[4092]}` — raw TPM2 buffers inside
   (`kernel/src/protocols/vtpm.rs`).
3. **Attestation model**: two-phase (negotiation → attestation); TEE evidence
   (SNP report) to a remote service; on success an encrypted secret (only
   decryptable by the SVSM's attestation key) **unlocks persistent vTPM state**
   — the TPM's state slot is gated by successful hardware attestation.

### 2.2 TCG simulator protocol (exact framing)

From `microsoft/ms-tpm-20-ref` `TPMCmd/Simulator/include/TpmTcpProtocol.h`:
`POWER_ON=1, POWER_OFF=2, PHYS_PRES=3/4, HASH_START/DATA/END=5/6/7,
SEND_COMMAND=8, CANCEL=9/10, NV_ON/OFF=11/12, KEY_CACHE=13/14,
REMOTE_HANDSHAKE=15, RESET=17, RESTART=18, SESSION_END=20, STOP=21`.
`SEND_COMMAND`: `{u8 locality, u32 inBytes, inbuf} → {u32 outBytes, outbuf}`.
This is the protocol of the TCG reference `tpm_server` **and swtpm**;
tpm2-tss ships `tcti-swtpm` (unix socket) and `tcti-tcp`. Speaking it =
drop-in compatibility with tpm2-tools and anything written against a
coconut-svsm vTPM. `REMOTE_HANDSHAKE (15)` available for optional peer auth.

### 2.3 TPM2 engine options

| Option | Notes |
|---|---|
| **`ms-tpm-20-ref-rs`** (Microsoft, MIT) | Official Rust bindings to the C reference engine (rev 1.38, the Hyper-V vTPM engine; OpenSSL 3.x; compiles the C or links via `TPM_LIB_DIR`). **Same engine + same crypto libraries as coconut-svsm's `libtcgtpm`**, official and maintained. |
| `tpm-rs` (community, pure Rust) | No C; future option / test oracle. |
| Real hardware TPM (passthrough) | When present (NitroTPM, evtpm, dTPM) the "engine" is the real TPM — strictly stronger. |

### 2.4 Nitro Enclave vsock

vsock is the only enclave↔host channel; host = CID 3, enclave CID 16 by
default (`--enclave-cid`). Enclaves can also get their own ENI (outbound
networking) — so both "vsock relay" and "direct outbound" fleet paths exist.
`vsock` crate (rust-vsock) gives tokio-friendly `VsockListener`/`VsockStream`.

### 2.5 AWS NitroTPM (the canonical TPM channel)

From AWS docs:

- Virtual TPM 2.0 from the Nitro System; "derives its root-of-trust from the
  Nitro Security Chip"; immutable EK set by AWS at instance creation.
- Supported families include **C6a, C7i, C7a, M6a, M8a, ...** (all modern
  Nitro instances except Outposts/Local Zones/Wavelength).
- Guest exposure: **`/dev/tpmrm0`** (TPM resource manager device, raw TPM2).
- **No EK certificate.** `aws ec2 get-instance-tpm-ek-pub`
  (`GetInstanceTpmEkPub`) returns the EK public key out-of-band from the EC2
  control plane (DER/TPMT; `rsa-2048` or `ecc-sec-p384`). Trust anchors to a
  **control-plane-vouched public key**, not a cert chain. Binding a quoting AK
  to that EK = standard TCG `TPM2_ActivateCredential`.
- **NSM attestation document**: requested via vendor command
  **`TPM2_VENDOR_AWS_NSM_REQUEST`** through `/dev/tpmrm0` (raw layer). AWS NSM
  signs a CBOR/COSE (ECDSA-384) document: `{module_id, timestamp, digest,
  nitrotpm_pcrs, certificate, cabundle, ? public_key, ? user_data, ? nonce}` —
  the **nonce slot** for the TPM channel; chain → public **AWS Nitro
  Attestation Root** (same root family as Nitro Enclaves attestation; "CRL
  must be disabled when validating").
- PCR semantics on EC2: PCR0/1 = AWS core system firmware (**constant by
  design**), PCR4 = boot manager (Attestable AMIs), PCR7 = Secure Boot policy,
  PCR12 = UEFI cmdline.
- SNP coexists (M6a/C6a/R6a+); different layers, they compose.

### 2.6 SEV-SNP attestation report (the TEE channel)

From the SEV-SNP ABI + kernel docs + `virtee/snpguest` / `google/go-sev-guest`:

- **`REPORT_DATA`**: 64 bytes of **requester-chosen arbitrary data** (offsets
  0x050–0x090), **covered by the AMD ECDSA P-384 signature** (covers 0x0–0x29F).
  The SNP **nonce slot**.
- Guest request: `/dev/sev-guest` → `SNP_GET_REPORT` ioctl → firmware
  `MSG_REPORT_REQ` (VMPCK-protected). Tooling: `snpguest report <out> <64B>`.
- Report: `MEASUREMENT` (SHA-384 launch digest: kernel, cmdline, initrd,
  OVMF), `GUEST_SVN`, `POLICY`, `FAMILY_ID`, `IMAGE_ID`, `PLATFORM_INFO`,
  `HOST_DATA`, `REPORT_DATA`, `ID_KEY_DIGEST`, `LAUNCH/CURRENT/REPORTED_TCB`,
  `CHIP_ID`, `VMPL`, `SIGNATURE`.
- Chain: **AMD ARK → ASK → VCEK** (per chip + TCB; AMD KDS `kdsintf.amd.com`)
  → report. VLEK for CSP shared tenancy. Verifier libs embed ARK/ASK.
- **Azure caveat**: on Azure CVMs the **paravisor (HCL) controls REPORT_DATA**
  — binding there goes through PCR-linking of the document + cloud tokens.

### 2.7 Cloud provenance roots (who owns the instance)

| Cloud | TEE | TPM | AK/EK trust anchor | Provenance proof |
|---|---|---|---|---|
| **AWS** (EC2) | SNP (M6a/C6a/R6a+) | NitroTPM `/dev/tpmrm0` | EK pubkey via `get-instance-tpm-ek-pub` (no EK cert); AK bound via ActivateCredential | NSM doc → **AWS Nitro Attestation Root**; control-plane EK fetch |
| **AWS** (enclaves) | NSM enclave | none (emulate) | EK/AK anchored by EIF | NSM COSE → **AWS Nitro root** |
| **Azure** CVM (SNP GA, TDX preview) | SNP/TDX | HCL (paravisor) vTPM, EK generated at runtime | **AK cert issued by Azure CA** (in hardware report); AMD ARK→ASK→VCEK / Intel PCS PCK | VCEK via IMDS THIM; **Azure Attestation (MAA) token** (`x-ms-compliance-status`, `vmUniqueId`) |
| **GCP** CVM (SEV/SNP N2D/C2D/C3D, TDX C3/C4/A3H) | SEV/SNP/TDX | Shielded VM vTPM (TPM 2.0, FIPS 140-2 L1) | **Google-issued AK cert auto-provisioned into vTPM NV**; VCEK (AMD KDS, GCP cache) / PCK (Intel PCS, GCP cache) | **Google Cloud Attestation** RATS **EAT** token (OIDC/PKI) |
| **Bare metal / self-hosted** | SNP/TDX | discrete dTPM | vendor EK chains (Infineon/ST/Nuvoton AIA) **or DC-CA fleet certs (§9.2)** | vendor roots + operator-pinned EK, **or DC-CA root** |
| **DigitalOcean** | none (2026-08) | none | — | unsupported today; provider-agnostic framework |

Pattern: **provenance = cloud-anchored certificate or cloud-issued attestation
token**; the Bundle carries a `provenance` slot per channel, resolved per
platform by the SDK.

### 2.8 Keylime (the compatibility target)

From keylime docs/source (`keylime.readthedocs.io`, `github.com/keylime`):

- **Components**: `keylime-agent` (node; Rust; REST API or push),
  `keylime_registrar` (identity: EK/AK enrollment, MakeCredential/
  ActivateCredential binding; hosts vendor EK certs), `keylime_cloudserver`
  (**the "verifier"** — central verification, policy, continuous polling or
  push intake, revocation), `keylime-tenant` (CLI). **Keylime calls our "router"
  the cloudserver** (the verifier service inside it).
- **Pull model (default)**: verifier polls
  `GET /v2.4/quotes/integrity?nonce=<20char>&mask=0x..&partial=0` on the agent
  (port 9002). Response JSON: `results.quote =
  b64(TPMS_ATTEST):b64(TPMT_SIGNATURE):b64(tpm2_pcrs)`, `hash_alg`, `enc_alg`,
  `sign_alg`, `pubkey`, `boottime`, `ima_measurement_list`,
  `ima_measurement_list_entry`, `mb_measurement_list` (b64 UEFI event log).
  Quote = `TPM2_Quote(AK, qualifyingData=nonce, pcrSelection incl. PCR10)`.
- **Push model (v3.0)**: agent→verifier; PoP session
  (`POST /v3/sessions` → challenge → `TPM2_Certify` over it → bearer token);
  attestation lifecycle (capabilities → challenge → evidence submission →
  async evaluation); evidence classes: `tpm_quote` (certification), `ima_log`,
  `uefi_log`.
- **Identity binding**: AK created per boot (not persisted — a known
  limitation); bound to EK via MakeCredential/ActivateCredential at the
  registrar. EK certs carry **no device identity** (TCG design).
- **IMA**: PCR10 rolling hash of executed/mmap'd files; verifier replays the
  log against PCR10, then checks an allowlist policy (digests, excludes,
  keyrings, optional ima-sig). Known weakness: log can be appended to;
  detection relies on ima-sig / strict allowlists.
- **Security**: **CVE-2026-6420** (7.14.0–7.14.1): hardcoded nonce in push
  attestation → quote stockpiling/replay (~8–33 min undetected); fixed in
  7.14.2. Design limits: vTPMs have no independent hardware root; policy
  quality is on the operator; pull model needs inbound reachability to agents.
- References RATS (RFC 9334).

### 2.9 TrenchBoot (D-RTM secure launch)

From `trenchboot.com` / `github.com/trenchboot`:

- **DRTM** on x86 via **Intel TXT (SENTER)** or **AMD Secure Startup
  (SKINIT)**: a TrenchBoot Linux kernel (with embedded u-root initramfs) is
  late-launched; the CPU hardware-measures the landing zone (CRTM) — a
  hardware root of trust independent of the original bootloader.
- Measurements (Secure Launch Spec): **kernel → PCR 17**, **public key →
  PCR 18** (plus policy entries for cmdline, ramdisk, boot params, SLRT),
  each recorded in the TPM event log, measured **in order**. SLRT is registered
  in the UEFI SystemTable (GUID `877a9b2a-0385-45d1-a034-9dac9c9e565f`).
- The **u-root initramfs runs the Security Engine**: consumes a launch policy,
  enforces it — "full, partial, or failed boot" (policy failure = boot
  halts). Key release: "double chain wrap" (drive key ← token wrap key ←
  TPM-sealed wrap key, e.g. YubiKey), or **Shamir with a TrenchBoot ACA**
  (Attestation Certificate Authority / key service): the system attests to the
  ACA to receive a key fragment that unlocks the disk — **boot is gated on
  remote attestation**.
- Remote verification: expected measurements (published with the build) +
  TPM2 Quote over PCR17/18 + event log + **proof-by-liveness** (the system
  booted and is answering ⇒ the policy passed at launch).

### 2.10 Safeboot (osresearch)

From `safeboot.dev` / `github.com/osresearch/safeboot` (GPL-2.0; same
community as Heads):

- x86-64 laptops with commodity UEFI + TPM2 (no firmware replacement). Goals:
  boot only owner-authorized code; streamlined encrypted-disk boot; reduced
  attack surface; runtime integrity; **remote attestation**.
- **Owner-key Secure Boot**: owner PK/db keys (optionally on a YubiKey,
  offline), OEM/MS keys removed; kernel+initrd+cmdline merged into a single
  **signed unified EFI kernel image**.
- **TPM sealing**: disk keys sealed to PCR values + **monotonic counters**
  (rollback protection); unseal only if firmware/config unmodified.
- **Runtime**: dmverity read-only root (signed root hash), kernel lockdown,
  module restrictions, IOMMU lockdown.
- **Attestation protocol (prior art for our hub flow)**: one round trip —
  client generates AK, quotes all PCRs with current time, sends `EKpub +
  AKpub + quote + eventlog` (quote.tar, "essentially public"); server validates
  signature/eventlog/timestamp, then `TPM2_MakeCredential`-encrypts a
  transport key + payload; client `TPM2_ActivateCredential`-decrypts with
  EK/AK — reply is "only unsealable by that specific TPM", and the whole
  exchange can be in the clear. `attest-enroll` does device enrollment by
  EKpub with secret escrow ("WK" MakeCredential / "TK" Duplicate methods).

### 2.11 Dasharo TrustRoot (coreboot + Intel Boot Guard)

From `docs.dasharo.com` / `github.com/Dasharo`:

- **TrustRoot = Intel Boot Guard** with owner-fused vendor keys (one-time
  e-fuses in the CPU; HSI Level 3): hardware validates firmware signature at
  the earliest stage; boot refuses if it fails. Owner-controlled (NovaCustom
  laptops) — "root of trust in the hands of the platform owner."
- Dasharo is a **coreboot downstream** (forks: coreboot, edk2) with upstreamed
  TPM driver refactors + **TCG-compliant event logging** (TPM2.0 format
  default) and a complete event log across coreboot → EDKII.
- PCR allocation: **PCR0** = Boot Guard/IBB measurements (reconstructable —
  fwupd HSI "PCR0 reconstruction: Valid"), **PCR2** = stages/constant data/
  blobs/payload (SRTM chain), **PCR3** = runtime data, **PCR7** = authority
  (pre-MeteorLake).
- Verification: `fwupdtool security` (HSI), `tpm2_eventlog`, `tpm2_pcrread`,
  `cbmem -L`; reproducible builds + "Openness Score". Remote verification =
  our model: expected PCRs (from the reproducible firmware build) + TPM
  quote + event log replay.

### 2.12 coreboot / Heads measured boot

From coreboot docs (`Documentation/security/vboot/measured_boot.md`) and the
Heads project (`github.com/osresearch/heads`):

- coreboot SRTM: IBB acts as S-CRTM; extends **PCR2** (stages, data, blobs:
  bootblock, verstage, romstage, fspm, postcar, ramstage, payload, microcode),
  **PCR3** (runtime data: hwinfo, MRC cache), PCR0/1 (vboot GBB where
  applicable); event log in coreboot format or **TCG TPM1.2/TPM2.0 ("CBT2")
  format**, exportable via `cbmem -L` / Linux.
- **Heads**: coreboot + Debian, fully measured boot (romstage → vbios →
  payload → initrd → OS), TPM2 integration, reproducible firmware builds.
- Remote verification: reproducible firmware build → expected PCR values +
  event log; live TPM2 Quote over the firmware PCRs binds them.

### 2.13 NVIDIA Confidential Computing (GPU channel)

From `docs.nvidia.com/attestation` + `github.com/NVIDIA/attestation-sdk`,
`NVIDIA/nvtrust`:

- **CC-On** GPU mode on H100/H200/Blackwell, GPU attached to a CVM (TDX or
  SNP). Evidence via **NVML-based collection** in `libnvat` (C SDK) /
  `nvattest` CLI: `nvat_gpu_evidence_collect()`; `nvidia-smi conf-compute -srs`
  sets ready state.
- Report (claims v3.0, per GPU): driver version, VBIOS version,
  **RIM signature verification** (driver + VBIOS Reference Integrity
  Manifests), attestation report signature status, **nonce match
  (`eat_nonce`)**, `measres`, `hwmodel`, `ueid` (unique GPU ID), `secboot`,
  `dbgstat`, plus **three cert chains** (attestation report, driver RIM,
  VBIOS RIM). Signature: **ECDSA ES384**.
- Verification root: **NVIDIA Root PKI** (chains must "belong to NVIDIA
  PKI"); roots ship in the SDK; cloud services: **NRAS**
  (`nras.attestation.nvidia.com`), **RIM Service** (reference values), **OCSP**
  (revocation).
- CPU/TEE integration: GPU attestation is generated **inside the CVM** (the
  CPU TEE protects the collection process); chains are separate — our Slot
  Link (PCR link of the GPU report document) is what unifies them. PPCIE mode
  for multi-GPU.

### 2.14 Phone / consumer-device attestation (attestation.app alternative)

- **attestation.app** (GrapheneOS **Auditor**, `github.com/GrapheneOS/Auditor`):
  hardware-based remote attestation for **Android** devices. Model: persistent
  key in the **hardware-backed keystore** (StrongBox/HSM e.g. Titan M where
  available), **verified boot** state protecting the key, **TOFU** pairing
  (first verification establishes the baseline), **scheduled remote
  verification** with email alerts, **downgrade detection** (OS/patch/app
  version regression), local P2P mode via QR challenge exchange. Android 8+
  hardware, Android 13+ verifier app. **This is exactly use case #1.2, and
  exactly our pubsub health model applied to phones** — our protocol generalizes
  it to any device class + any verifier device + full ownership provenance.
- **Android key attestation** (the channel): KeyMint/Keymaster/StrongBox key
  blob carries an X.509 **attestation certificate** signed by the **Android
  Key Attestation CA** (per-Android-release roots, published by Google).
  Extensions include: key public key, **`uniqueID` (challenge = nonce slot)**,
  Android version, device **AID**, OS patch level, **`verifiedBootState`**
  (Verified/Self/Warning/Unverified — the secure-boot state), lock state,
  keymaster version, **StrongBox vs TEE** flag. Third-party verifiable with
  the public Google roots → "genuine Android device, locked bootloader, this
  OS version, key in TEE/StrongBox, signed this nonce."
- **Apple App Attest** (iOS/iPadOS/macOS): Secure Enclave attestation key;
  `attestDevice(clientNonce:)` returns an **OSA attestation** (CMS) signed by
  the **Apple OSA root CA** (published): app bundle ID, device attestation key
  pubkey, **`clientNonce` (nonce slot)**, device class. Third-party
  verifiable → "genuine Apple device running this app signed this nonce."
  (DeviceCheck is Apple-only; App Attest is the third-party path.)
- **WebAuthn / FIDO2** (universal fallback, any browser/OS): challenge-bound
  authenticator response from a **platform authenticator** (TPM/Secure
  Enclave) with attestation statement; biometric/PIN proves **user ownership**
  of the device. Works on phones, laptops, servers, browsers — the
  cross-platform identity channel.

### 2.15 IETF RATS (standards anchor)

RFC 9334 (RATS architecture: attester/verifier/trust anchor), RFC 9711
(**EAT** — Entity Atttestation Tokens, JWT/COSE), RATS protocol over CBOR
(attestation request `{nonce, exts}`; attestation statement `{attester_id,
list, targets, nonce}`). Our design maps 1:1: daemon = attester, hub/client =
verifier, vendor/cloud roots = trust anchors, attestation manifest =
reference values. GCP/Azure already issue EAT-ish tokens → the hub can
**optionally issue EAT tokens** wrapping a verified bundle for interop, while
native verification stays offline-capable and hub-independent.

## 3. Core mechanism: the Slot Link Protocol

### 3.1 Nonce slots

Each attestation channel has a hardware-signed **nonce slot**. The daemon fills
every available slot with the same client nonce `N`:

| Channel | Slot | Signed by | Notes |
|---|---|---|---|
| SEV-SNP report | `REPORT_DATA` (64 B) | AMD VCEK → ASK → ARK | guest-set via sev-guest (Azure: paravisor-controlled) |
| TDX quote | `report_data` (64 B) | Intel QE (PCK chain) | tdx-guest |
| AWS NitroTPM | NSM doc `nonce` | AWS NSM → Nitro root | vendor cmd; `user_data` also available |
| AWS Nitro Enclave | COSE doc `nonce` | AWS NSM → Nitro root | NSM driver |
| TPM2 (any real/emulated TPM) | `TPM2_Quote.qualifyingData` | AK inside the TPM | daemon builds the quote |
| Android key attest | cert `uniqueID` | Google Key Attestation CA | key in TEE/StrongBox signs challenge |
| Apple App Attest | OSA `clientNonce` | Apple OSA CA | Secure Enclave key |
| WebAuthn | authenticator `challenge` | platform authenticator (TPM/SE) | attestation statement |
| OP-TEE / CCA (future) | cert challenge / RTM | ROTPK / RMM | per-vendor |

### 3.2 The link (PCR binding)

When a TPM is present, it is the **envelope**. At attestation time the daemon:

1. Collects evidence documents `E_i` (all channels), each with slot = `N`.
2. Extends the **evidence PCR** (default **PCR 22**):
   `PCR22 ← SHA384(PCR22 ‖ H(E_1 ‖ E_2 ‖ ...))`.
3. Stores each `E_i` in daemon-owned NV indices (`0x01500001..n`).
4. Issues `TPM2_Quote(AK, qualifyingData=N, pcrSelection=[0,1,4,7,10,12,17,22])`
   (real TPM in Mode A; reference engine in Mode B).

The verifier then `NV_Read`s the evidence, verifies each `E_i` against its own
root, and checks: every slot == N; `H(E_1‖...) == PCR22(quote)` (**the link**:
the TPM attests to the exact documents just verified against independent
roots); boot/runtime PCRs == published expectations; cross-channel PCR
agreement (NSM doc `nitrotpm_pcrs` == quote PCRs).

**Generalization (envelope optional):** when every available channel has its
own nonce slot (phones: key attest + webauthn), the Bundle is valid
**without** a TPM quote — the invariant is "every available channel signed
N," and the link PCR is simply absent. The TPM envelope is what *combines*
channels that don't sign N directly (IMA, measured-boot logs, GPU reports);
devices without a TPM carry those as plain evidence with their own
integrity mechanisms (IMA rolling hash, event-log replay).

### 3.3 "Only valid if both agree, without trusting each other"

- **Independence**: AMD never sees the TPM's PCRs; the NitroTPM never sees the
  SNP report; Google's CA never sees Apple's. No channel verifies another.
- **Agreement enforced syntactically by the verifier**: the PCR link requires
  the TPM's signed PCR22 to equal the hash of the *exact* documents whose
  signatures were just verified against independent roots. Swapping,
  mutating, or replaying any one document breaks its own signature or the
  link.
- **Freshness**: N appears inside every signature simultaneously → replayed
  bundles fail every channel at once.
- **Daemon untrustworthiness**: every signature is produced inside hardware
  the daemon cannot key. It can relay, extend PCRs / write NV (observable:
  must match published expectations or the verifier's recomputed link), or
  refuse. **It cannot forge; it can only withhold.**

### 3.4 coconut-svsm compatibility (TPM layer)

The daemon implements coconut-svsm's vTPM design in user space: same protocol
(§2.2), same engine & crypto libraries in emulation mode (`ms-tpm-20-ref-rs`
is the same TCG C engine + OpenSSL as `libtcgtpm`), same combining semantics
(hardware attestation + TPM measurements bound into one TPM2 proof). A client
written against a coconut-svsm vTPM works unmodified. Difference by design:
ours proxies a real cloud-anchored TPM when present (Mode A), so the quote key
lives in hardware the provider vouches for, not in emulated state.

## 4. Unified abstraction

### 4.1 Roles (two binaries, four roles)

| Binary / mode | Role | Runs on | Keylime equivalent |
|---|---|---|---|
| **`bootproofd`** (default) | node attester | every node that can attest (server, enclave, laptop, phone) | keylime-agent |
| **`bootproofd --hub`** | hub | a dedicated server, or combined with a node | keylime **cloudserver** (verifier) + registrar |
| **`bootproofd`** (any) | remote verifier coordinator | any bootproofd: requests + verifies other nodes' proofs | keylime-tenant (server side) |
| **`bootproof`** (CLI) | client: register + verify any registered node | server, workstation, **phone**, browser | keylime-tenant (CLI) |

Every role connects to the hub **outbound only** (HTTPS); pure verifier
devices run only `bootproof`.

### 4.2 The Bundle (one schema, all device classes)

```json
{
  "v": 3,
  "nonce": "N",
  "round_id": "r-2026-08-17-000123",
  "node": {
    "id": "i-0123456789abcdef0",
    "class": "server | enclave | laptop | phone | embedded | accelerator",
    "provenance": { "aws": {...}, "dc-fleet": {...}, "owner": {...} }
  },
  "quote": {                       // optional: absent when no TPM channel
    "tpms_attest": "b64", "signature": "b64", "pcrs": "b64",
    "ak_pub": "b64", "ak_anchor": "activate-credential | cert-chain | if-anchored",
    "counter": 12345
  },
  "evidence": [
    { "channel": "snp",        "doc": "b64", "slot": "report_data" },
    { "channel": "nsm-aws",    "doc": "b64", "slot": "nonce" },
    { "channel": "ima",        "log": "...", "pcr": 10, "m_hash": "..." },
    { "channel": "uefi-ml",    "log": "b64" },
    { "channel": "coreboot",   "pcrs": {...}, "eventlog": "b64" },
    { "channel": "trenchboot", "pcrs": {17: "...", 18: "..."}, "policy_ref": "..." },
    { "channel": "nvidia-cc",  "claims": {...}, "chains": [...], "nonce": "N" },
    { "channel": "android-ka", "cert": "b64", "unique_id": "N", "verified_boot": "Verified" },
    { "channel": "apple-osa",  "attestation": "b64", "client_nonce": "N" },
    { "channel": "webauthn",   "authenticator_data": "b64", "signature": "b64", "attestation": "..." }
  ],
  "link": { "evidence_pcr": 22, "hash": "SHA384(E_1‖E_2‖...)" },  // optional
  "manifest_ref": { "disk_image_sha384": "...", "expected_pcrs": {...} }
}
```

- `quote` optional ⇒ phones/embedded work with the same schema.
- `evidence` = open array; each channel has a pluggable verifier in the SDK:
  `trait EvidenceVerifier { fn verify(doc, nonce, policy) -> Verdict; fn root(&self); }`.
- RATS-aligned: maps to attestation statement `{attester_id, list, targets,
  nonce}`; the hub may wrap a verified bundle in an **EAT token** (RFC 9711)
  for interop; native verification never requires the hub.

### 4.3 Channel registry (all platforms, planned)

Status: **v1** = canonical server case + keylime interop; **v2** = cloud
matrix + phones; **v3** = firmware/embedded/accelerator long tail.

| # | Channel | Device class | Nonce slot | Root of trust | Status |
|---|---|---|---|---|---|
| 1 | `tpm2` (real/emulated quote) | all with TPM | qualifyingData | AK anchor (per §9) / EIF | v1 |
| 2 | `snp` | cloud VM, bare metal | report_data | AMD ARK→ASK→VCEK (KDS) | v1/v2 |
| 3 | `tdx` | cloud VM, bare metal | report_data | Intel PCS PCK chain | v2 |
| 4 | `nsm-aws` (NitroTPM doc) | AWS EC2 | doc nonce + user_data | AWS Nitro Attestation Root | v1 |
| 5 | `nsm-aws-enclave` (COSE) | AWS enclaves | doc nonce | AWS Nitro root | v1 (Mode B) |
| 6 | `ima` (PCR10 + log) | Linux | via quote link | PCR10 rolling hash + ima-sig | v1 (keylime) |
| 7 | `uefi-ml` (PCRs 0–12 + event log) | UEFI systems | via quote link | expected values (reproducible build) | v1 |
| 8 | `coreboot` (PCR0/2/3 + CBT2 log) | coreboot/Heads/Dasharo | via quote link | reproducible firmware build | v3 |
| 9 | `trenchboot` (PCR17/18, D-RTM) | TXT/SS systems | via quote link | published policy + proof-by-liveness | v3 |
| 10 | `safeboot` (owner-key SB, sealing, unified image) | owner-locked laptops | via quote link | owner key (published/offline) | v3 |
| 11 | `dasharo-trustroot` (Boot Guard + PCR0/2/3/7) | Dasharo/NovaCustom | via quote link | fused Boot Guard keys + reproducible build | v3 |
| 12 | `nvidia-cc` (H100/H200/B/GB) | GPU in CVM | eat_nonce | NVIDIA Root PKI + RIM (+NRAS/OCSP) | v3 |
| 13 | `optee` (ROTPK cert) | ARM TrustZone | cert challenge | per-device ROTPK / vendor CA | v3 |
| 14 | `arm-cca` (realm attestation) | ARM CCA | RTM | ROTPK / RAS | v3 (protocol-only) |
| 15 | `android-ka` (key attest + verified boot) | Android phones/tablets | uniqueID | Google Key Attestation CA (per-release) | v2 |
| 16 | `apple-osa` (App Attest) | iOS/iPadOS/macOS | clientNonce | Apple OSA root | v2 |
| 17 | `webauthn` (platform authenticator) | **any** (universal) | challenge | attestation CA / self-attested + credential binding | v2 |
| 18 | `aws-cp` (IID + EK, §9.1) | AWS EC2 | via NSM user_data | Amazon IID sig + control plane | v1 |
| 19 | `azure-maa` / `gcp-eat` (cloud tokens) | Azure / GCP CVM | token-bound | Azure CA / Google CA | v2 |
| 20 | `dc-fleet` (fleet binding cert, §9.2) | self-hosted | — (identity binding) | DC-CA (operator-pinned) | v2 |

Not supported: RISC-V (no standard TEE), DigitalOcean (no TEE/TPM as of
2026-08), macOS hardware (no public remote-attestation API — degrades to
`webauthn`; documented honestly).

### 4.4 Capability discovery & best-effort verdicts

Every device advertises `capabilities {channels: [...], quote: bool,
evidence_pcr, transports: [...]}` at enrollment (keylime v3
`evidence_supported` is the same idea). The hub and verifier then:
request only advertised channels; verdict = `{status: verified | degraded |
failed, channels: {name: {ok, root, detail}}, freshness: {nonce, issued,
deadline, elapsed}, provenance: {...}}`. "Best effort verify as much as
possible" = verify all advertised channels; a missing channel lowers the
status, never errors the protocol.

### 4.5 The most-compatible interface (layered)

1. **Keylime agent API (exact) — canonical HTTP interface** ("TPM2 over
   HTTP"): `bootproofd` serves v2.4 pull (`/v2.4/agent/info`,
   `/v2.4/quotes/integrity?nonce&mask&partial` → `quote =
   b64: b64: b64` + `ima_measurement_list` + `mb_measurement_list`) and v3
   push (`/v3/sessions` PoP, `/v3/agents/{id}/attestations`). Superset:
   responses carry extra fields (our multi-channel `evidence`, `provenance`,
   `manifest_ref`) that keylime ignores and our tenant/cloudserver consumes.
2. **Raw TPM2 relay** (`POST /tpm/v1/raw {command: b64} → {response: b64}`)
   for tpm2-tools via a custom TCTI and general tooling.
3. **TCG simulator protocol** over unix socket / vsock / TCP (swtpm/
   tpm_server framing) for local tools and coconut-svsm clients.
4. **Pubsub** hosted inside `bootproofd --hub`, delivered to devices over
   HTTPS (long-poll / SSE / WebSocket) for fleet fanout (§7) — the same
   messages, pushed instead of pulled.

All four are projections of one daemon; the wire choice is the client's.

## 5. Daemon modes

| Mode | When | Engine | Quote key |
|---|---|---|---|
| **A — binder/proxy (canonical)** | real TPM present (NitroTPM `/dev/tpmrm0`, evtpm, dTPM) | passthrough to the real TPM (raw TPM2 over the TPM RM device) | real AK (cloud/vendor-anchored) |
| **B — full emulation (fallback)** | no TPM (Nitro Enclaves; some TEEs) | `ms-tpm-20-ref-rs` reference engine (coconut-svsm-equivalent) | emulated AK/EK, cert anchored by the EIF; optionally deterministic EK from an EIF-embedded seed (reproducible EK; solves NV persistence) |
| **C — pure passthrough** | debugging / direct tpm2-tools | passthrough, no interception | real AK |
| **D — device adapter (no TPM)** | phones, laptops without TPM | no engine | device-SE keys (Android KMA / Apple OSA / WebAuthn platform authenticator); Bundle without envelope (§3.2) |

Mode A is what makes use case #1.1 work: the quote is signed by a key whose
trust is anchored to **AWS** (control-plane-vouched EK; TPM root = Nitro
Security Chip) while the SNP report is anchored to **AMD** — two independent
roots, one proof.

## 6. Provenance & fleet identity (best effort)

### 6.1 Cloud control-plane evidence via the instance's own credentials (AWS)

Assume the instance has an IAM role (via IMDS) scoped to the read-only APIs
needed. At attestation time the **daemon** (never the client) fetches and the
node API / hub proxies these as **additional evidence in the Bundle**:

1. **Instance Identity Document (IID)** + Amazon signature from IMDS
   (`latest/dynamic/instance-identity/{document,signature}`, IMDSv2).
   Verifiable against Amazon's published signing certificate; carries
   `account-id`, `instance-id`, `region`, `availability-zone`, `image-id`.
2. **EK public key**: `aws ec2 get-instance-tpm-ek-pub` (SigV4 under the role).
3. Optionally instance tags / `DescribeInstances` (best effort).

**Binding**: `E_nsm.user_data = { iid_sha384, ek_pub_sha384, nonce: N }` —
signed by the AWS NSM under the same fresh nonce (verify the vendor command's
user_data surface in spike S1; fallback = hash-link via the evidence PCR).
The **AK anchoring transcript** (`TPM2_ActivateCredential` against the fetched
EK_pub at attestation time) rides in the Bundle: `{secret, ak_sig, ek_pub}` —
the client verifies the AK↔EK binding **offline, credential-free**.

Result: NSM doc (AWS-signed, nonce N) binds H(IID) + H(EK_pub) ⇒ the
Amazon-signed IID and the control-plane-vouched EK belong to *this*
attestation's instance ⇒ ** "this attestation came from AWS account X, AZ Y,
instance Z."** A stale/stolen IID cannot attach to a fresh attestation.
Role scoped to `ec2:GetInstanceTpmEkPub` (+ optional `ec2:DescribeInstances`);
IMDSv2 required.

### 6.2 Datacenter CA fleet model (bare metal, optional enrollment)

The datacenter operator stands up a **Fleet CA (DC-CA)** and enrolls machines.
It cannot re-sign AMD/Intel hardware signatures; it signs a **fleet binding
certificate** binding hardware *identity* to fleet facts:

```
fleet binding cert  (X.509 v3, custom extension under a private OID; COSE alt)
{
  machine:  { id, datacenter, az, account/tenant },
  bindings: {
    snp:   { chip_id <64 B, as signed in the SNP report>, product },
    tdx:   { pck_cert_serial / platform_id, as signed in the Intel PCK chain },
    tpm:   { ek_pub <DER>, ek_nv_index }
  }
}
```

- **TPM**: the DC-CA may also provision a standard **EK cert** into the dTPM's
  NV (TCG EK cert index) → AK anchoring becomes the ordinary cert-chain path
  (AK ← EK ← DC-CA), no ActivateCredential needed.
- **CPU**: the cert records the chip identity AMD/Intel *already signed*
  (CHIP_ID / PCK platform ID); the hardware signature proves the report is
  genuine, the DC-CA cert states **where that chip sits**.

Verifier: SNP report → CHIP_ID (AMD root); fleet cert → DC-CA chain (pinned
root, serial + CRL/OCSP) → bindings; quote → EK; `fleet.tpm.ek_pub == quote
EK` and `fleet.snp.chip_id == report CHIP_ID` ⇒ **both channels from the same
enrolled machine** ⇒ "genuine SNP chip + genuine TPM, same machine, DC-1
AZ-2, tenant-42."

Trust boundary (stated plainly): the cryptographic half is hardware-verified;
the chip→rack/AZ/account **mapping is a witness claim by the fleet operator**.
Mitigations: per-machine certs, short validity, CRL/OCSP, multiple DC-CAs or
a public fleet ledger where the operator is only partially trusted.
Unenrolled machines attest with vendor-root provenance — degrades, never
fails. This mirrors what clouds do internally (Azure CA AK cert; Google CA AK
cert; AWS control-plane EK) — the DC-CA is the self-hosted "provider root."

### 6.3 Device ownership (phones / laptops)

- **Android**: key attest cert binds the key to the device AID + verified
  boot state; ownership = the account holding the device + the hub's TOFU
  enrollment (first valid attestation registers the device identity; the
  verifier's own identity — App Attest / key attest / WebAuthn — ties the
  request to the owner).
- **iOS**: App Attest binds the app bundle + device; ownership = Apple ID /
  app account + TOFU enrollment.
- **Workstations/servers**: fleet cert (§6.2) or cloud provenance (§6.1);
  WebAuthn credential adds user-level ownership.

## 7. Fleet architecture: `bootproofd --hub` + egress-only pubsub

The hub is a **mode of the daemon** (`bootproofd --hub`), not a separate
binary. It is the **only publicly reachable, inbound** service in the whole
deployment. Every node and every verifier reaches it **outbound only** over
HTTPS.

```
 pure verifier (phone/laptop: `bootproof` only, OUTBOUND only)     attesters (`bootproofd`, OUTBOUND only)
 ┌────────────────────────────────────────────┐         ┌──────────────────────────────────────────────────┐
 │ bootproof (client CLI)                      │         │ bootproofd (Mode A/B/C/D)                        │
 │  - registers the local device with a local  │         │  - vTPM engine + channel backends                │
 │    or remote bootproofd                     │         │  - keylime agent API (HTTP)                      │
 │  - verify <node>: submits a request, opt.   │         │  - Slot Link engine                              │
 │    signed + attested with its own channels  │         │  - requests + verifies REMOTE nodes' proofs      │
 │    (proves WHO is asking)                   │         │    (coordinator role, any registered node)       │
 └──────────────────────┬─────────────────────┘         └──────────────────────┬───────────────────────────┘
                        │ HTTPS (egress only; PoP)                             │ HTTPS (egress only; PoP)
 ┌──────────────────────▼──────────────────────────────────────────────────────▼───────────────────────────┐
 │ bootproofd --hub — publicly reachable HTTPS; the ONLY inbound service                                   │
 │  - node registry + TOFU baselines + registrar-compatible API (/v3.0/agents/...)                        │
 │  - pubsub broker over HTTPS (long-poll / SSE / WebSocket; backend swappable)                           │
 │  - on-demand verify router: request → target polls it up → target signs, pushes back → requester pulls │
 │  - health-round engine: hub generates a fresh nonce at set intervals; all nodes sign + push back       │
 │  - verdict store + fleet health + webhooks + (optional) EAT token issuance                             │
 └─────────────────────────────────────────────────────────────────────────────────────────────────────────┘
```

**Two flows, both strictly egress-only:**

1. *On-demand verification (requester-driven)* — `bootproof verify <node>`:
   the requester submits a verify request to the hub over egress HTTPS,
   **optionally locally signed and attested** with the requester's own
   channels (proving *who is asking*). The hub routes it to the target node,
   which polls it up via its egress-only subscription (long-poll / SSE /
   WebSocket), runs the Slot Link with a fresh nonce, and **pushes the signed
   proof back** to the hub. The requester then **pulls** the result (egress
   HTTPS) and re-verifies it offline with the SDK — the hub's verdict is
   advisory; the bundle's signatures are hardware's.
2. *Continuous health (hub-driven)*: at a set interval (default 10 s,
   keylime-parity; configurable) the **hub generates a fresh nonce** and
   broadcasts the health round; every registered node signs it with all
   available channels and pushes back within the deadline. The hub marks each
   node `verified(round)` / `stale` / `failed` after M missed rounds; webhooks
   fire on transitions. This is keylime's continuous polling, inverted to
   push (no inbound on nodes) and generalized to multi-channel.

**Why egress-only works for every topology:**

- *NATed phones / laptops*: one outbound HTTPS connection; the hub delivers
  challenges over the same connection (long-poll / SSE / WebSocket). No
  inbound port, no STUN, no UPnP.
- *Enclaves* (no public IP): the hub's challenge is relayed over vsock to the
  enclave daemon (host CID 3), or the enclave daemon dials the hub through
  the host's egress. The enclave opens nothing inbound.
- *Fully offline LAN*: run `bootproofd --hub` on the LAN; nodes and verifiers
  on that LAN talk only to the LAN hub. No internet at all.
- *Any registered device can verify any other*: the registry + router make
  node→node verification a hub-routed request; the requester never touches
  the target directly.

**Hub wire (device ⇄ hub is HTTPS; the broker underneath is swappable —
in-memory, NATS, MQTT, Redis):**

| Operation | Request | Response |
|---|---|---|
| register / enroll | `POST /v1/nodes` (PoP proof attached) | `201` + node id |
| health round (hub → all nodes) | — (SSE/WS event) | `{round_id, nonce, deadline}` |
| on-demand request (requester → target) | `POST /v1/verify {target, request?, ttl}` | `202` + `req_id` |
| challenge to target (hub → target) | — (SSE/WS event to target) | `{req_id, nonce, deadline, request?}` |
| push proof (target → hub) | `POST /v1/attestations {req_id \| round_id, nonce, bundle}` | `202` |
| pull result (requester) | `GET /v1/verify/{req_id}` | `200 {bundle, verdict}` / `202` pending |
| fleet status | `GET /v1/nodes/{id}/health`, `GET /v1/fleet/health` | `200` |

**attestation.app alternative (phones)**: phone runs `bootproofd` (Mode D) as
an app/service (or `bootproof` + a foreground service when it only
verifies); the hub schedules rounds; TOFU baseline at enrollment; checks: key
still in TEE/StrongBox (cert chain valid), `verifiedBootState == Verified`,
OS/patch version ≥ baseline (**downgrade detection**), no unexpected
key/channel changes; alerts (email/webhook) on failure — the GrapheneOS
Auditor model, generalized to any device class and any verifier device, with
full ownership provenance.

**Verifier identity**: the hub challenges the **verifier's** own channels
(key attest / App Attest / WebAuthn / TPM2) before it may request challenges
or read verdicts ⇒ "the owner's phone asked about the owner's server" is
cryptographically established, not claimed. `bootproof verify` attaches the
requester's own attestation to the request when the requester can produce
one.

**Security**: mTLS + **PoP** (proof-of-possession: node/verifier signs the
hub's nonce with its TPM AK or device SE key — keylime v3 does exactly this
with `TPM2_Certify`) for auth. Bundles are hardware-signed → interception
can't forge; nonces are **fresh, hub-generated, with hard expiry** (the
CVE-2026-6420 lesson: never reuse, never hardcode); the hub keeps a short
nonce/round registry for replay detection. A compromised hub can replay *old*
bundles (clients check freshness: round age, quote counter, per-request nonce
binding) but cannot mint fresh ones.

**No-ingress guarantee**: enclaves (vsock relay or own ENI), phones (NAT),
laptops (NAT) all open one outbound connection; everything else flows over
it. The hub is the only inbound service in the deployment — the only box
that needs a public TLS endpoint.

## 8. Canonical end-to-end #1 (server: c6a + SNP + NitroTPM)

### 8.1 Build side (public repo)

1. Reproducible build: OS + app + **UEFI/GRUB config (incl. Secure Boot db) +
   initramfs + daemon** → bit-for-bit disk image; published with recipe,
   pinned toolchain, hash.
2. In-image early-boot hook (part of the image, hence part of the hash):
   `tpm2_pcrextend 17:sha384:<H(disk image)>` — binds the **entire** image
   bit-for-bit into a user PCR.
3. `bootproof-image` emits the **attestation manifest**:
   ```json
   {
     "disk_image_sha384": "...",
     "expected_pcrs": { "0": "...", "1": "...", "4": "...", "7": "...",
                        "12": "...", "17": "<H(disk image)>" },
     "snp": { "product": "Genoa", "policy": "0x...", "launch_digest": "...",
               "min_tcb": {...} },
     "platform": "aws-nitrotpm",
     "ek_pub_pin": "<optional: pre-fetched control-plane EK pubkey>"
   }
   ```
   (Expected PCRs computed by the same tooling that builds the image — the
   analogue of `neof`'s measurement file for EIFs.)

### 8.2 Attestation time

1. Verifier → hub: `POST /nodes/{id}/attest {nonce: N}` (or hub-generated N).
2. Hub → `bp.challenge.{id}`; daemon (Mode A):
   - `E_snp ← /dev/sev-guest SNP_GET_REPORT(report_data=N)`
   - `E_nsm ← /dev/tpmrm0 TPM2_VENDOR_AWS_NSM_REQUEST(nonce=N,
     user_data={H(IID), H(EK_pub), N})`
   - `TPM2_Extend(PCR22, SHA384(E_snp ‖ E_nsm))`; NV-store both
   - `TPM2_Quote(AK, qualifyingData=N, sel=[0,1,4,7,12,17,22])`
   - keylime-format response (quote + pcrs + IMA + UEFI event log + our extra
     evidence fields) → `bp.attest.{id}` / HTTP
3. Hub verifies (SDK + manifest) → verdict → `bp.verdict.{round}`.

### 8.3 Verifier checks (bootproof-sdk)

1. `E_snp`: VCEK (AMD KDS, product) → ASK → embedded ARK; `report_data == N`;
   `MEASUREMENT == manifest.snp.launch_digest`; POLICY/TCB ok.
2. `E_nsm`: chain → embedded AWS Nitro root (CRL disabled); `nonce == N`;
   `nitrotpm_pcrs` vs quote PCRs; **provenance: AWS-operated instance**.
3. Quote: AK signature; `qualifyingData == N`; counter sanity; AK anchoring
   (AWS: `{secret, ak_sig, ek_pub}` transcript from §6.1 — client verifies
   offline; Azure: AK cert ← Azure CA; GCP: AK cert ← Google CA in NV; bare
   metal: vendor EK chain or DC-CA EK cert).
4. PCRs: `0,1,4,7,12,17 == manifest.expected_pcrs` ⇒ exact kernel, UEFI,
   Secure Boot policy, cmdline, and bit-for-bit disk image.
5. Link: `SHA384(E_snp ‖ E_nsm) == quote.PCR22` ⇒ the TPM attests to exactly
   the documents verified in 1–2.
6. Provenance (§6.1): IID (Amazon-signed; account/AZ/instance) with
   `H(IID) == NSM user_data.iid_sha384`, `H(EK_pub) ==
   NSM user_data.ek_pub_sha384`.

Verdict: *"exactly this public image, running now, in a genuine SNP VM, on an
AWS-operated instance in account X / AZ Y; all channels signed one fresh
nonce; no channel trusted another."*

## 9. Canonical end-to-end #2 (phone: attestation.app alternative)

1. **Enrollment (TOFU)**: owner's phone (verifier) + target phone (attester,
   Mode D app): hub issues a challenge; target attests with `android-ka`
   (persistent StrongBox/TEE key; `uniqueID = N`; `verifiedBootState`, AID,
   OS version, patch level, keymaster version) + `webauthn` (owner's
   biometric/PIN). Hub stores the baseline: key pubkey + attestation cert +
   boot state + versions + owner binding (verifier's own attested identity).
2. **Rounds**: hub pushes nonces on a schedule; target re-attests; hub checks:
   cert chain still valid (key still in TEE/StrongBox), boot state still
   `Verified`, OS/patch **≥ baseline (downgrade detection)**, channel set
   unchanged; alerts on failure (email/webhook) — Auditor parity.
3. **On-demand**: any attested verifier (owner's other phone, workstation,
   CI server) requests a fresh challenge; receives the bundle + verdict;
   **re-verifies offline** with the SDK (Google Key Attestation CA roots
   embedded per Android release).
4. **iOS variant**: `apple-osa` channel (App Attest; Apple OSA root;
   `clientNonce = N`) + `webauthn`; same flows.
5. **Ownership**: the bundle's key is bound to the device (AID/Apple device
   class); the owner binding is the TOFU enrollment done by an *attested*
   verifier — "the owner's device enrolled this device."

## 10. Keylime compatibility (superset, not a fork)

**Role naming (keylime → bootproof)**:

| Keylime | Bootproof | Notes |
|---|---|---|
| keylime-agent | **`bootproofd`** (node, default mode) | speaks the exact keylime agent API (v2.4 pull + v3 push) |
| keylime **cloudserver** (verifier) | **`bootproofd --hub`** (hub mode) | superset: multi-channel verify, pubsub router, on-demand verify, fleet health, EAT |
| keylime-registrar | registrar-compatible API **inside** `bootproofd --hub` | `/v3.0/agents/...` enrollment, MakeCredential/ActivateCredential |
| keylime-tenant | **`bootproof`** (client CLI) | superset: register, verify any registered node, fleet status, custom challenges, policy, enroll |

(When this plan previously said "bootproof-router" or
"bootproof-cloudserver," that is the hub mode `bootproofd --hub`; when it
said "bootproof-tenant," that is the `bootproof` client CLI.)

**What a stock keylime cloudserver can verify** (partial by design): the
TPM2 quote (AK + EK chain), PCR policy (incl. PCR10 IMA replay + allowlist),
and measured-boot log — i.e., everything in keylime's `tpm_policy` /
`runtime_policy`. It cannot see (and does not need to see) the extra
multi-channel evidence; the `bootproof` client / `bootproofd --hub` consumes
the superset fields.
This is the intended "use their keylime server to partially verify bootproof
nodes" path — and the reverse (our hub ingesting keylime agents' quotes as a
`tpm2`+`ima`+`uefi-ml` bundle) is a supported interop mode for mixed fleets.

**Security goals preserved**:

- One-nonce/all-channels, no-mutual-trust, daemon-can't-forge: unchanged —
  the keylime projection is a *view* of the same Slot Link bundle; the keylime
  verifier just checks fewer channels.
- **Nonce freshness (CVE-2026-6420)**: our daemon/hub always generate fresh
  CSPRNG nonces per round with hard expiry; keylime v2.4's 20-char nonce is
  accepted as-is for the TPM slot and padded (deterministically documented)
  for 64-byte slots; the hub never reuses a nonce (round registry).
- **IMA log append weakness**: known keylime limit; our SDK treats IMA as
  best-effort runtime evidence, enforces `ima-sig` + strict allowlists in
  policy, and never lets IMA alone carry a verdict.
- **Non-persistent keylime AK** (per-boot AK): our daemon persists the AK in
  TPM NV (or re-derives deterministically in Mode B), and v3 PoP sessions use
  the persistent AK — strictly stronger, keylime-compatible.
- **Pull-model inbound requirement**: our default is push (outbound-only
  nodes); the v2.4 pull endpoints still exist for keylime verifiers that poll.

## 11. Crate layout

```
crates/
  bootproof/            generation-side lib (Format trait) + the `bootproof`
                        CLI binary (register + verify any registered node;
                        links bootproof-sdk + hub client)
      main.rs            (new) `bootproof` CLI entry point
      format/mod.rs      Format trait (unchanged)
      format/nitro.rs    (existing) enclave NSM attestation
      format/nitrotpm.rs (new) NSM doc via TPM2_VENDOR_AWS_NSM_REQUEST (raw TPM)
      format/snp.rs      (new) sev-guest report (report_data slot)
      format/tdx.rs      (new) tdx-guest quote (report_data slot)
  bootproof-sdk/        verification side
      format/nitro.rs    (existing) enclave COSE verify (reused for NSM docs)
      format/snp.rs      (new) VCEK→ASK→ARK verify (embedded ARK/ASK, KDS fetch)
      format/tdx.rs      (new) PCK chain verify
      format/tpm2.rs     (new) Quote + per-platform AK anchoring (ActivateCredential, cert chains)
      format/bundle.rs   (new) composite: all channels + link + provenance + verdict
      format/keylime.rs  (new) keylime projection: quote/IMA/eventlog verification
                          (reuses tpm2.rs; enforces ima-sig policy)
  bootproof-channels/   (new) channel backends (daemon side):
      ima.rs, uefi_eventlog.rs, coreboot.rs, heads.rs, dasharo.rs,
      trenchboot.rs, safeboot.rs, nvidia_cc.rs, optee.rs, arm_cca.rs,
      android_ka.rs, apple_osa.rs, webauthn.rs,
      provenance/{aws_cp.rs, azure_maa.rs, gcp_eat.rs, dc_fleet.rs}
  bootproof-tcti/       TCG simulator protocol + transports (vsock/unix/tcp/
                        http-raw) + client
  bootproof-tpm/        raw TPM2 over the TPM RM device (commands, PCR extend,
                        NV define/write/read, vendor commands)
  bootproof-vtpm/       TpmBackend trait; backends: passthru (real),
      backend/passthru   ref (ms-tpm-20-ref-rs, coconut-svsm-equivalent)
      slotlink.rs        evidence collect → PCR22 extend → NV store → quote
      identity.rs        EK/AK (persistent) + per-platform AK anchoring
  bootproof-hub/        (new, LIBRARY) hub logic, linked by bootproofd for
                        `--hub` mode: node registry + TOFU baselines +
                        registrar-compatible API + pubsub broker + on-demand
                        verify router + health-round engine + verdict store +
                        webhooks + policy/manifests + (optional) EAT issuance
  bootproofd/           (existing → daemon) node attester (default) + hub mode
                        (`--hub`, links bootproof-hub) + remote verifier
                        coordinator. vTPM engine + channels + keylime agent
                        API (v2.4 pull + v3 push, exact) + raw TPM2 relay +
                        egress-only hub client (HTTPS)
  bootproof-image/      attestation manifest tooling (expected PCRs, disk
                        hash, policy) for reproducible builds
```

## 12. Phased implementation plan

### Phase 0 — foundations + spikes (~1-2 wks)
- `bootproof-tcti`: simulator protocol + vsock/unix/tcp/http-raw transports.
- `bootproof-tpm`: raw TPM2 over `/dev/tpmrm0` (command send, PCR extend, NV,
  vendor commands).
- Spikes: S1 (NitroTPM userspace PCR extend + NV + `TPM2_VENDOR_AWS_NSM_REQUEST`
  incl. nonce/user_data surface; compare `aws/nitrotpm-attestation-samples`);
  S2 (`SNP_GET_REPORT` from Rust with caller-chosen `report_data`); S3 (parse
  NSM doc with the SDK's existing COSE code; confirm `nitrotpm_pcrs`/`nonce`).

### Phase 1 — Mode A daemon, canonical server case (~3 wks)
- **Start from `docs/mvp-spec.md`**: the lean `bootproof attest` +
  `bootproof verify` (tpm2 + snp, one node) is the entry point; the full
  daemon + transports below extend it.
- `bootproof-vtpm` passthrough backend + `slotlink.rs` (Quote intercept,
  evidence collect snp+nitrotpm, PCR22 extend, NV store).
- `bootproofd` rewrite: transports, mode auto-detect (`/dev/tpmrm0` +
  `/dev/sev-guest` → A; NSM device → B; none → D), limits, optional
  `REMOTE_HANDSHAKE`.
- `bootproof-image` manifest tooling + in-image PCR17 hook.
- Deliverable: **c6a E2E** per §8 (hub can be the in-process verifier for
  this phase). Negatives: mutated report, wrong nonce, PCR tamper, swapped
  docs (link fail), stale replay.

### Phase 2 — SDK composite verifier + keylime agent API (~2-3 wks)
- `format/snp.rs`, `format/tdx.rs` (stub), `format/tpm2.rs` (quote + AK
  anchoring incl. AWS ActivateCredential transcript), `format/bundle.rs`,
  `format/keylime.rs`; IMA channel (`ima-sig` enforcement); UEFI event log
  channel.
- **AWS control-plane evidence (§6.1)**: IID + EK fetch under instance role;
  NSM user_data binding; offline AK-anchoring transcript.
- **Keylime agent API surface on bootproofd (exact v2.4 pull + v3 push)**;
  tpm2-tools check via raw relay; **milestone: a stock keylime cloudserver
  verifies a live bootproof node** (partial, as designed).

### Phase 3 — hub mode in bootproofd + bootproof client (~2-3 wks)
- `bootproof-hub` library: node registry + TOFU baselines + registrar-
  compatible API + pubsub broker (HTTPS long-poll/SSE/WebSocket; internal
  backend swappable) + on-demand verify router (submit → route → target polls
  up → signed proof pushed back → requester pulls) + health-round engine
  (hub-generated fresh CSPRNG nonces, expiry, replay registry) + verdict
  store + PoP auth (TPM AK / device SE) + webhooks.
- `bootproofd --hub` wires the library in.
- `bootproof` client CLI: register (local/remote daemon), verify any
  registered node, fleet status, custom challenges, policy, enroll.
- Deliverable: fleet health + on-demand verify E2E (server attester +
  `bootproof` CLI verifier + phone-simulated verifier), strictly egress-only.

### Phase 4 — Mode B + cloud matrix + fleet CA (~2-3 wks)
- Mode B: `ms-tpm-20-ref-rs` backend (OpenSSL 3.x in enclave image),
  deterministic-EK option, EIF-anchored EK cert.
- TDX backend + GCP CVM (TDX) + Azure CVM (SNP/TDX) incl.
  paravisor-controlled-report_data variant (PCR-link + MAA/EAT provenance).
- Bare-metal dTPM (vendor EK chains) + **DC-CA fleet model (§6.2)**: fleet
  binding cert tooling (issue/renew/revoke), DC-CA EK cert provisioning,
  CHIP_ID/EK binding + client verification.

### Phase 5 — phones / consumer devices (~2-3 wks)
- `android_ka.rs` (Key Attestation verify: per-release Google roots,
  uniqueID, verifiedBootState, StrongBox flag, downgrade detection) +
  `bootproofd` Mode D on Android (app/service; persistent keystore key;
  outbound HTTPS to the hub).
- `apple_osa.rs` (App Attest; Apple OSA root) + iOS Mode D.
- `webauthn.rs` (universal channel; attestation + self-attested handling).
- Verifier-side attestation (hub challenges the verifier device's channels).
- **attestation.app-alternative E2E**: TOFU enrollment + scheduled rounds +
  alerts for Pixel-class devices (Auditor parity) (§9).

### Phase 6 — firmware / secure-boot / accelerator channels (~3-4 wks)
- `coreboot.rs` / `heads.rs` / `dasharo.rs` (PCR0/2/3/7 + CBT2/TCG event log
  replay; reproducible-firmware expected values; fwupd HSI cross-check).
- `trenchboot.rs` (PCR17/18, D-RTM, policy ref, proof-by-liveness) +
  `safeboot.rs` (owner-key SB, sealing/monotonic counters, 1-round-trip
  protocol interop, attest-enroll compatibility).
- `nvidia_cc.rs` (libnvat evidence, ES384 + RIM chains, NRAS/OCSP optional,
  PCR-link into the quote).
- `optee.rs` (ROTPK cert verify); `arm_cca.rs` (protocol-only stub).

### Phase 7 — hardening, interop, docs (~1-2 wks)
- Fuzzing (protocol + COSE/SNP/NVAT parsers), latency budgets, threat-model
  write-up per platform, operator runbook, EAT token issuance (optional),
  mixed-fleet interop tests (keylime agents ↔ bootproof hub; bootproof nodes
  ↔ keylime cloudserver).

## 13. Risks & open questions

| # | Item | Position |
|---|---|---|
| 1 | Userspace PCR extend + vendor commands on NitroTPM | spike S1 first; daemon owns the device node regardless |
| 2 | AWS: no EK cert | ActivateCredential against control-plane EK (safeboot's 1-round-trip protocol is prior art); optional EK pin in manifest; fetch via instance role (client credential-free) |
| 3 | Azure/GCP: paravisor controls TEE nonce slot | PCR-link still binds the exact document; freshness via quote `qualifyingData`; provenance via MAA/EAT tokens |
| 4 | Disk image measurement coverage | PCR17 = H(whole image) via in-image hook; boot PCRs pin firmware/kernel/cmdline; build pins UEFI/GRUB + SB db; AWS PCR0/1 constant by design |
| 5 | Daemon compromise | cannot forge (signatures in hardware); can withhold or corrupt evidence (client detects via link/expectations); vsock/queue peer-auth via `REMOTE_HANDSHAKE` / PoP |
| 6 | `ms-tpm-20-ref-rs` constraints (Mode B) | OpenSSL 3.x; rev 1.38 pin; no saved-state stability (deterministic-EK re-derivation) |
| 7 | coconut-cloud/coconut-vtpm is private | design mirrors public coconut-svsm vTPM; cross-check if access exists |
| 8 | Keylime interop fidelity | v2.4 20-char nonce → documented deterministic padding for 64-B slots; extra JSON fields ignored by keylime (verified in Phase 2); stock-cloudserver milestone gates release |
| 9 | Nonce freshness / replay (CVE-2026-6420 lesson) | hub-generated CSPRNG per round, hard expiry, round registry, never reused; daemon-side validation of challenge age |
| 10 | IMA log append weakness | `ima-sig` + strict allowlists in policy; IMA never sole basis for a verdict |
| 11 | Hub compromise | verdicts advisory; client re-verifies offline; replay window bounded by freshness tolerance; queue mTLS + PoP |
| 12 | TOFU baseline poisoning | enrollment requires an attested verifier (+ optional out-of-band confirm); baseline re-pinning is an explicit, logged operation |
| 13 | IAM role for control-plane evidence | scope `ec2:GetInstanceTpmEkPub` (+ optional `DescribeInstances`); IMDSv2 required; read-only, public-ish data |
| 14 | DC-CA witness claims | chip→AZ/account mapping is operator-attested; per-machine certs, short validity, CRL, optional multiple DC-CAs/ledger; unenrolled → vendor roots |
| 15 | NSM vendor command user_data surface | verify in spike S1; fallback = hash-link via evidence PCR |
| 16 | Phone attestation roots | Google Key Attestation roots are per-Android-release (pin + update policy); Apple OSA root is public (embed, refresh policy); WebAuthn self-attested = weaker (label in verdict) |
| 17 | TrenchBoot requires TXT/SS | not all CPUs support SENTER/SKINIT — channel is best-effort per hardware |
| 18 | safeboot tested on Intel BootGuard | AMD path unreviewed upstream — label platform support in verdict |
| 19 | macOS has no remote-attestation API | honest degradation to `webauthn`; document as weak |
| 20 | NVIDIA CC service dependency | NRAS/RIM/OCSP optional; offline root + RIM verification in SDK |
| 21 | Bundle format | JSON now (keylime interop requires it); CBOR/EAT migration tracked with EAT issuance (Phase 7) |
| 22 | DigitalOcean | no TEE/TPM (2026-08); framework provider-agnostic |
| 23 | Hub availability (SPOF for cross-node verify) | local attestation + direct keylime-pull verifiers still work; bundles are self-contained (re-run a round to refresh); the hub is just `bootproofd --hub`, so a LAN hub can be stood up offline on any node |

## 14. Trust chain summary

**Server (canonical)**:

```
public repo: source + recipe + toolchain + pinned disk image
   + attestation manifest (expected PCRs, SNP policy, disk hash)
        │ reproducible build (auditor: source == image bytes)
        ▼
disk image ──(in-image hook)──▶ PCR17 = H(image)
        │ UEFI/GRUB/SecureBoot (pinned in build)
        ▼
boot PCRs 0/1/4/7/12 = expected (AWS OVMF constant, boot mgr, SB policy, cmdline)
        │
        │ AWS NSM signs at request time
        ▼
E_nsm: { nitrotpm_pcrs, nonce=N, user_data={H(IID),H(EK),N}, chain → AWS Nitro Root }
        │
        │ AMD ASP signs at request time
        ▼
E_snp: { MEASUREMENT(kernel/initrd/cmdline/OVMF), POLICY, TCB, CHIP_ID,
         report_data=N, sig ← VCEK ← ASK ← AMD ARK }
        │
        │ same guest, same moment, untrusted daemon
        ▼
PCR22 = H(E_snp ‖ E_nsm) ; NV[E_i]
        ▼
TPM2_Quote(AK in NitroTPM, qualifyingData=N, PCRs{0,1,4,7,12,17,22})
   AK anchored: ActivateCredential ↔ control-plane EK (AWS-vouched)
        ▼
verifier (bootproof-sdk): verify E_snp (AMD root) · E_nsm (AWS root) · quote (AK)
   + report_data==N + nonce==N + qualifyingData==N
   + H(E_snp‖E_nsm)==PCR22 + PCRs==manifest
   + provenance: IID (Amazon-signed; account/AZ) via NSM user_data hashes
   ⇒ "exactly this public image, running now, genuine SNP VM, AWS account X /
      AZ Y; all channels signed one fresh nonce; no channel trusted another."
```

**Phone (attestation.app alternative)**:

```
enrollment (TOFU, by an attested verifier): baseline {key pubkey, KA cert,
   verifiedBootState, AID, OS/patch versions, owner binding}
        │
        │ each round: hub nonce N
        ▼
E_ka:  key-attest cert (uniqueID=N, verifiedBootState, AID, versions)
       sig-chain ← Google Key Attestation CA (per-release root)
E_wa:  WebAuthn authenticatorData (challenge=N) + sig ← platform authenticator
        ▼
hub: chain valid? boot state still Verified? versions ≥ baseline (downgrade)?
   channels unchanged?  → verdict + alert on failure
        ▼
any attested verifier re-verifies offline (embedded roots) + reads verdict
   ⇒ "genuine Android device, locked bootloader, this exact OS, owner's
      device, alive now, signed a fresh nonce."
```
