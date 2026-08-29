# Bootproof

<https://git.distrust.co/public/bootproof>

CLI + daemon for TPM 2.0 / NitroTPM / SEV-SNP remote attestation. The core
artifact is a **trust tree** where every fact carries a verdict and a vendor
root: a fact renders `true` only when the evidence is signed by a root of
trust **pinned in the binary** (signature + freshness) — a malicious system
can never render `true` by lying, because `true` never rests on
self-reported data.

Vendor roots in play: **AWS** (NitroTPM endorsement chain, signed IIDD),
**AMD** (SEV-SNP report), **StageX** (image-baked SPDX provenance + published
container signatures).

## Workspace

| crate | what |
| --- | --- |
| `crates/bootproof` | the unified `bootproof` binary (client + node + local tree) |
| `crates/bootproofd` | standalone attestation daemon |
| `crates/bootproof-tpm` | raw TPM2 / NSM layer (StageX/NitroTPM dialect, attestation docs) |
| `crates/bootproof-sdk` | evidence formats (Nitro attestation + pinned AWS roots) |

## Build

```
make                 # musl static binary via docker (bptpm-dev:latest) -> out/bootproof
cargo build -p bootproof
cargo test           # 59 unit tests across the workspace
```

## Commands

| command | purpose |
| --- | --- |
| `bootproof verify` | local trust tree for this machine (default: succinct summary; `--expert` full evidence tree; `--json` machine output) |
| `bootproof verify <target>` | challenge a remote node, verify the proof offline, print the facts table |
| `bootproof attest` | node server: REST remote-attestation API (challenge/nonce + channels) |
| `bootproof serve` | self-contained plain-HTTP NitroTPM attestation API (`POST /attest`) |
| `bootproof verify-nitro` | verify a NitroTPM attestation doc against the pinned AWS roots (+ optional pinned-PCR policy; `--emit-pcrs` establishes a baseline) |
| `bootproof provenance` | parse `/provenance.spdx` (StageX build provenance), check digests against published signatures, diff against a locally regenerated doc |
| `bootproof nsi` | request the nonce-bound NitroTPM attestation document (NSM vendor command) |
| `bootproof tpm-bridge` | bridge a TCP port to the local TPM (raw TPM2 framing, for remote tooling) |
| `bootproof decrypt` / `sign` | use the local PCR-gated TPM key (state-bound to the attested PCR state) |
| `bootproof tpm-probe` / `nv-test` | debug: PCRs/properties, NV layout discovery |

### Local trust tree

```
bootproof verify                                  # succinct summary, per-fact vendor roots
bootproof verify --expert                         # full evidence tree
bootproof verify --json [--expert]                # machine output
bootproof verify --tcp host:port                  # via tpm-bridge (no local /dev/tpm0)
bootproof verify --pcr-policy policy.json         # pin expected PCRs (v1 hex/b64 or v2 {"source": ..., "pcrs": ...})
bootproof verify --user-data "release=sha256:..." # metadata into the AWS-signed attestation doc
```

Summary on the reference c6a.large / StageX / us-east-2 instance (a
`? provenance` line appears when the image bakes `/provenance.spdx`):

```
TRUST SUMMARY
 ✓ instance     i-02a44cb68978c43af (c6a.large)           AWS
 ✓ account      412541033472                              AWS
 ✓ region       us-east-2 (us-east-2c)                    AWS
 ✓ cpu          AMD EPYC 7R13 Processor                   AMD
 ✓ memory       SEV-SNP per-VM key + TSME                 AMD
 ✓ isolation    SEV-SNP ASID + debug off                  AMD
 ✓ tpm          NitroTPM                                  AWS
 ✓ boot         24 PCRs in signed doc + SNP launch        AWS AMD
                measurement
 ? rootfs       no pinned PCR policy                      (self)
 ~ os           Stageˣ                                    (self)
 ? secure boot  not exposed to guest                      (self)
```

Cross-attestation binding: one fresh 32-byte nonce is embedded in TWO
independently pinned-root-signed artifacts (the AWS-signed NitroTPM doc and
the AMD-signed SEV-SNP report), so neither can be replayed or spliced.

### StageX provenance

Images built from StageX bake a full SPDX 2.3 build-provenance document at
`/provenance.spdx` (source commit/branch, per-package SHA256 digests,
dependency graph). `bootproof verify` parses it when present (server-side)
and renders a Provenance branch; the deep check is:

```
bootproof provenance --path /provenance.spdx \
    --sigs /root/stagex-signatures \        # local checkout of codeberg.org/stagex/signatures
    --keyring /root/stagex-signatures/stagex-keyring.pgp   # gpg-verify found signatures

# unsigned dev build? rebuild at the pinned commit and confirm:
git checkout <commit> && make <target>
python3 src/provenance.py <target> --raw > /tmp/regen.spdx
bootproof provenance --path /provenance.spdx --compare /tmp/regen.spdx   # exit 3 on any digest drift
```

Signatures are Container Signature Format PGP signed messages, one file per
independent rebuild (`stagex/<name>@sha256=<digest>/signature-N`), quorum
>= 2; published at `https://sigs.stagex.tools` (also `--lookaside`).

### Remote attestation

```
# node
bootproof attest --listen 0.0.0.0:8443

# client
bootproof verify https://node:8443
```

## Develop

```
make shell       # docker dev shell with toolchain; `bootproof ...` inside
```

## Docs

* `docs/trust-tree.md` — the current tree in full: verdict rules, every
  branch, proof anchors, and the audit log (what is `true` and why it can't
  be forged).
* `docs/mvp-spec.md`, `docs/agent-design.md` — design specs.
* `crates/bootproof/src/trust/data/iidd/README.md` — pinned AWS IIDD certs
  (39 regions, provenance + fingerprints).
