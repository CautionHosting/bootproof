# bootproof MVP — functional spec: `bootproof attest` + `bootproof verify`

Status: draft v1
Companion to `agent-design.md` (the broad research + platform plan). This file
is the precise functional contract for the MVP.

## Scope

One binary, `bootproof`, four subcommands:

- **`bootproof attest`** — the node server. Serves a REST remote-attestation
  API for the local system. (This is the old `bootproofd`.)
- **`bootproof verify <host-or-domain>`** — the client. Discovers the endpoint
  (direct, or via the `bootproof` DNS TXT record), challenges the server,
  verifies the proof **offline**, prints the facts table.
- **`bootproof decrypt <blob>`** — server-side. Uses the local TPM (gated by
  the attested PCR state) to decrypt a blob sent to the machine out-of-band.
- **`bootproof sign <data>`** — server-side. Uses the local TPM (gated by the
  attested PCR state) to sign data; verifies against the `sign` key published
  in the attestation.

Two cross-cutting capabilities beyond the bare facts table:

- **Discovery**: `bootproof verify caution.co` finds the real endpoint
  (`attest.caution.co`) via a `bootproof` DNS TXT record (§Discovery).
- **State-bound keys**: the attestation publishes TPM keys for encryption and
  signing that only work while the system is in the attested PCR state
  (§State-bound TPM keys). This turns the attestation into a capability:
  secrets can be sent to the machine out-of-band and only decrypted while it's
  in the good state.

MVP platforms:

- **Bare metal**: TPM2 (required) + SEV-SNP (optional, if present).
- **AWS EC2**: TPM2 (the NitroTPM, required) + SEV-SNP (optional, if the
  instance is SNP-enabled).

**Later (extension, no core changes):** TDX, GCP, Azure, DC-CA fleet, IMA /
measured-boot log, phones.

**Not in MVP:** hub / pubsub, keylime protocol, multi-node routing, policy
engine, server-side verdicts. The server returns *evidence*; the **client**
computes the verdict.

## Discovery: the `bootproof` DNS TXT record

So a user can type just a domain — `bootproof verify caution.co` — the client
locates the real attest endpoint via a DNS TXT record:

- **Record:** `_bootproof.<domain>` TXT.
- **Value** (single string, `key=val;key=val`):
  ```
  endpoint=attest.caution.co:443;key=sha256:<hex>;image=sha384:<hex>
  ```
  - `endpoint` (required): the host[:port] serving the attest API.
  - `key` (optional): SHA-256 of the daemon's TLS pubkey — a **pin hint** so
    discovery carries initial trust (still confirmable, not blind).
  - `image` (optional): SHA-384 of the expected image hash — a pre-check hint.

**Resolution order** for `bootproof verify <arg>`:
1. If `<arg>` has a port / is an IP / `--direct` → use it as the endpoint.
2. Else look up `_bootproof.<arg>` TXT → `endpoint`. If `key` present, seed the
   pin from it (then confirm / `--trust`).
3. Else fall back to `<arg>` as the endpoint (the apex serves the API).

The TXT record is a **pointer + hint**, not a trust anchor: trust still comes
from pinning the daemon key and verifying the signed evidence offline. It is
publicly auditable (`dig TXT _bootproof.caution.co` shows where the attestation
lives and what key/image is expected).

## The lean core (what makes it extensible)

The entire system is **three small traits + a fact catalog**. Every
attestation type is a **channel** = one module implementing two traits.

```rust
// — attest side (server) —
trait Channel {
    fn name(&self) -> &'static str;                  // "tpm2" | "snp" | "tdx" | ...
    fn detect(&self) -> bool;                        // available on this host?
    fn collect(&self, nonce: &[u8; 32]) -> Evidence; // signed evidence for N
}

// — verify side (client) —
trait Verifier {
    fn name(&self) -> &'static str;
    fn verify(&self, e: &Evidence, nonce: &[u8; 32], roots: &Roots) -> Result<Verified>;
    fn facts(&self, v: &Verified) -> Vec<Fact>;      // derive the facts
}

// — shared wire types —
struct Evidence {
    channel: String,
    doc: Vec<u8>,                            // channel-specific signed evidence (opaque)
    anchors: BTreeMap<String, Vec<u8>>,      // bundled certs/keys: ek_cert, ca, vcek, ...
}
struct Fact {
    name: &'static str,                      // "image_hash" | "aws_account" | "cpu" | ...
    value: String,
    anchors: Vec<&'static str>,              // ["tpm2"] or ["snp","tpm2"]
    status: Status,
}
enum Status { Proven, Reproducible, Degraded, NotProven }
```

**Adding TDX / GCP / Azure later = one new module** with a `Channel` + a
`Verifier` + its `facts()`. The Bundle schema, the HTTP surface, the table
renderer, and pinning are all **unchanged**. That one module is the entire
extension surface.

## `bootproof attest` (server) — exact functionality

**Startup**
1. Load or generate an ECDSA P-384 keypair (the TLS identity). Persist under a
   state dir (`--state`, default `/var/lib/bootproof`); first run generates,
   later runs load. `--key <pem>` loads a static key (for reproducible images,
   where the key is compiled in and thus pinned by the image hash).
2. Detect channels: `tpm2` (`/dev/tpm0` or `/dev/tpmrm0`), `snp`
   (`/dev/sev-guest`), `aws-cp` (IMDS reachable + an instance role). Active set
   = those present.
3. Load optional metadata (`--metadata m.json`):
   `{ "image_name": "...", "image_source_url": "..." }`.
4. Serve HTTPS on `--listen` (default `:443`; `:8443` for dev).

**`POST /attestation`** (the only substantive endpoint)
- Body: `{ "nonce": <b64 32 B> }` — optional; if absent the server generates
  one (CSPRNG).
- For each active channel: `evidence_i = channel.collect(N)`.
- **Slot link** (done by the `tpm2` channel before its Quote):
  `TPM2_Extend(PCR22, SHA384(doc_1 ‖ doc_2 ‖ ...))`, with PCR22 added to the
  Quote's PCR selection. This is what binds every channel to one TPM at one
  moment — the "both agree, no mutual trust" property.
- **State-bound keys** (done by the `tpm2` channel): ensure the persistent
  `enc` (ECDH P-384, decrypt) and `sign` (ECDSA P-384) TPM keys exist (created
  from an image seed on first boot, `TPM2_PolicyPCR`-gated to the current PCR
  set); include their pubkeys + EK certs + `pcr_policy` in the Bundle.
- Return the Bundle (below).

**`GET /info`** — `{ node_id, platform, channels: [active], metadata?, daemon_pubkey }`.
**`GET /health`** — liveness.

**The Bundle (MVP wire)**
```jsonc
{
  "v": 1,
  "nonce": "b64(32 B)",
  "node": { "id": "...", "platform": "baremetal | aws | baremetal-snp | aws-snp" },
  "evidence": [
    { "channel": "tpm2",
      "doc": "b64( Quote{attest,sig,pcrs,pcr_sel} + AK + ak_cert_by_EK + EK + EK_cert + CA_chain [+ NSM doc if AWS] )",
      "anchors": { "ek_cert": "b64", "ca": "b64" } },
    { "channel": "snp",
      "doc": "b64( SNP report )",
      "anchors": { "vcek": "b64" } }
  ],
  "keys": {                                        // state-bound TPM keys (§below)
    "enc":  { "pub": "b64", "curve": "P-384", "pcr_policy": [0,1,4,7,12,17,22], "cert_by_ek": "b64" },
    "sign": { "pub": "b64", "curve": "P-384", "pcr_policy": [0,1,4,7,12,17,22], "cert_by_ek": "b64" }
  },
  "metadata": { "image_name": "...", "image_source_url": "..." }   // optional
}
```

**What `attest` never does:** no verdict, no policy, no fetching of remote
roots at request time (all roots are embedded; all anchors are local/bundled),
no multi-node, no keylime. It is stateless per request: nonce in → Bundle out.
The only persistent state is the TLS key (and the AK in TPM NV).

## `bootproof verify <host>` (client) — exact functionality

1. **Resolve + connect**: resolve the endpoint (direct / `_bootproof` TXT /
   apex, §Discovery), then TLS to it. Pin the daemon's pubkey:
   - pin exists (`~/.config/bootproof/pins.json`) → check it matches (drift).
   - no pin but the TXT `key` hint is present → seed the pin from it, confirm.
   - no pin, no hint → first contact, TOFU: print the pubkey, `--trust`.
2. **Challenge**: generate `N` locally (CSPRNG, 32 B). `POST /attestation
   {nonce: N}`.
3. **Receive Bundle**. Sanity: `bundle.nonce == N` (reject otherwise —
   replay guard).
4. **Verify each channel offline** — `verifier.verify(evidence, N, roots)`:
   - `tpm2`: verify the Quote (AK sig); AK→EK via `ak_cert_by_EK` (EK-signed,
     `TPM2_Certify`); EK via `EK_cert` → `ca` (bundled, against embedded roots);
     `qualifyingData == N`; PCRs vs expected (image-hash PCR, measured-boot
     PCRs); if AWS, verify the NSM doc (chain → embedded AWS Nitro root,
     `nonce == N`, PCRs match).
   - `snp`: verify the report (VCEK → ASK → embedded AMD ARK); `report_data
     == N`; `MEASUREMENT` vs expected (kernel/cmdline/initrd/OVMF); `POLICY`
     (debug off, no migrate); `TCB`.
   - `aws-cp`: verify the IID (Amazon sig, embedded root); extract
     account / role / instance / region / AZ / AMI.
   - **Slot link**: `PCR22 == SHA384(all evidence docs)`.
   - Roots: embedded (AMD ARK, AWS Nitro root, Amazon IID root) + the bundled
     anchors from the Bundle. `--roots <dir>` overrides.
5. **Derive facts**: `facts = concat(verifier.facts(verified))` over channels;
   merge dual-anchored facts (image hash from tpm2+snp → anchors
   `["tpm2","snp"]`).
6. **Render** the facts table (`FACT / VALUE / ANCHOR / STATUS`) + the ANCHORS
   legend + `NOT PROVEN` + next-actions (the UX mock).
7. **Pin**: `--pin` (or first-run TOFU) stores
   `{ host, daemon_pubkey, image_hash, account }`; future `verify` flags
   drift (hash changed / account changed / key changed).

**Flags**: `--port`, `--trust`, `--pin`, `--rebuild` (fetch `image_source_url`,
build, confirm the hash → `Reproducible` upgrades to `Proven(local)`),
`--bundle` (dump raw), `--json`, `--roots <dir>`, `--timeout`.

## State-bound TPM keys (encrypt + sign)

The attestation publishes two TPM keys — `enc` (ECDH P-384, for encryption) and
`sign` (ECDSA P-384, for signing) — that are **PCR-policy-bound to the current
system state**. The private keys never leave the TPM; the public keys ride in
the Bundle.

**Why "bound to the current state":** each key is created with a
`TPM2_PolicyPCR` policy asserting the current PCR set (the attested state —
image hash, measured boot, etc.). The TPM only lets the key decrypt/sign while
the live PCRs still match. If the image changes or the system drifts, the PCRs
change and the key **stops working**. So possession of a working key *is*
proof the machine is in the attested state.

**What the verifier can confirm** (all offline, from the Bundle):
- `cert_by_ek`: the EK (TPM2_Certify) attests the key lives in this TPM.
- `pcr_policy` == the Quote's PCRs == the expected (attested) state.
- The Quote proves the state is currently satisfied, so the keys are live.

**Encryption flow (send a secret to the machine, out-of-band):**
1. The sender reads `enc.pub` from the attestation.
2. Encrypts a secret with ECDH-ES hybrid encryption to `enc.pub` (ephemeral
   ECDH → KDF → AES-GCM). No TPM needed on the sender side.
3. Delivers the ciphertext **out-of-band** (email, file, paste — whatever
   reaches the machine; not the attestation API).
4. On the machine: `bootproof decrypt secret.enc` → the TPM does the inverse
   ECDH **gated by the PCR policy** → plaintext, *only if the machine is still
   in the attested state*; otherwise the TPM refuses and decrypt fails.

**Signing flow (machine signs, only in the good state):**
- `bootproof sign <data>` → the TPM signs with `sign` (PCR-gated) → a signature
  that verifies against `sign.pub`. The attestation proves `sign.pub` was
  state-bound, so the signature is only credible if the machine was in the
  attested state when it signed.

**SDK surface** (`bootproof-sdk`, used by `bootproof decrypt`/`sign` and by any
embedded caller with TPM access):
- `decrypt(blob, enc_pub, tpm) -> Result<Vec<u8>>` — PCR-gated TPM decryption.
- `sign(data, tpm) -> Result<Signature>` — PCR-gated TPM signing.
- `verify(sig, data, sign_pub, attestation) -> Result<()>` — check a signature
  against the state-bound key + attestation.

**Degradation:** channels without a TPM (phones, Mode D) have no state-bound
keys; encrypt-to-machine degrades to the platform's secure channel (e.g. push
to a device key). Documented, not a silent gap.

## The fact catalog (MVP)

| Fact | Value | Anchor(s) | Source |
|---|---|---|---|
| `image_hash` (sha384) | the UKI / disk hash | tpm2 + snp | tpm2 PCR17 + snp `MEASUREMENT` |
| `image_source` | source URL | meta | metadata (`Reproducible`) |
| `measured_boot` | UEFI SB policy / UKI signed | tpm2 (+ snp) | tpm2 PCRs 0,1,4,7,12 |
| `memory_encryption` | SEV-SNP per-VM key, debug off | snp | snp `POLICY` |
| `full_disk_encryption` | LUKS2, key sealed to PCRs | tpm2 | tpm2 sealed-key policy |
| `cpu` | model | snp | snp `CHIP_ID` / product |
| `firmware_tcb` | fw / microcode supported | snp | snp TCB |
| `aws_account` / `iam_role` / `instance` / `az` / `ami` | identity | aws-cp | aws-cp IID |
| `liveness` | nonce + anchors + elapsed | all | all |
| `enc_key` / `sign_key` | state-bound TPM key pubkeys | tpm2 | tpm2 (PCR-policy-bound) |

A fact a channel can't produce renders as `NOT PROVEN` (e.g.
`memory_encryption` on a non-SNP host; `aws_*` on bare metal). Honest
degradation, always visible.

## Extension (later, no core changes)

| Add | New module | Notes |
|---|---|---|
| TDX | `tdx` channel | `/dev/tdx-guest`, `report_data=nonce`; facts: `memory_encryption`, `cpu` |
| GCP | `gcp` channel | Shielded VM / CVM, EAT token; facts: account, cpu, memory_enc |
| Azure | `azure` channel | CVM, MAA token; facts: account, cpu, memory_enc |
| DC-CA fleet | `dc-fleet` channel | fleet binding cert; facts: datacenter, az, tenant |
| IMA / measured-boot log | `ima`, `uefi-ml` | runtime facts; PCR10 + log |
| phones | `android-ka`, `apple-osa`, `webauthn` | no TPM; Bundle has no `quote` |

Each is a `Channel` + `Verifier` + `facts()`. The Bundle, HTTP, table, pinning,
and the tpm2 / snp core are untouched.

## Lean boundaries (what keeps it small)

- One binary, four subcommands, three traits, one wire type.
- All verification offline; roots embedded; anchors bundled in the Bundle.
- No daemon-to-daemon comms in MVP (hub / pubsub is a later layer on top).
- `attest` is stateless per request; `verify` is stateless except the pin file.
- The two commands together are a small, auditable surface — the whole trust
  model is "challenge → signed evidence → offline verify → facts".
