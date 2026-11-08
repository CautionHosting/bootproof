# AGENTS.md — the bootproof attestation contract

Guidance for coding agents working in this repo. This file is the **canonical
home of the attestation contract**: bundle generation, bundle verification,
the nonce→bundle socket protocol, the fact schemas, and the browser verifier
bundle ALL live here. Platform repos (wardend, stagex, future platforms) are
*consumers*: they hold keys, collect hardware/platform evidence, and serve
bytes. They must not re-implement attestation logic.

## The governing principle

> All attestation knowledge lives in this repo. A platform is a *plugin*.

A platform supplies three things and nothing else:
1. **Hardware channels** — the in-process `snp` / `tpm2` collectors, or its
   own evidence collector, registered as `bootproof::channel::Channel`s.
2. **Platform evidence + a verifier** — a `bootproof-platform-<name>` crate
   exporting the platform's fact schema (`WardendDoc`-style), a `Verifier`
   impl, a `ChainVerifier`, and a `build_<name>_evidence()` constructor.
3. **A key + an evidence source** — the signing key (HSM/TPM) and the device
   facts to fold into the bundle.

Generation (`engine::produce`), verification (`engine::verify_bundle`), the
hash-chained signed log (`engine::verify_chained_log`), the wire contract
(`wire::Bundle`, `protocol` frames), the trust roots (`trust`, `snp`), and the
identity pin (`spki::spki_pin`) are ALL owned here and are platform-agnostic.
A new platform must add ZERO new attestation logic to this core — it only
registers a new channel/verifier. If a change to `engine`/`wire`/`protocol` is
ever required to support a new platform, that is a design smell: rework the
platform plugin instead.

## The current module map (what each piece owns)

- `engine` — `produce(nonce, node_id, platform, channels, extra_evidence)`,
  `verify_bundle(bundle, VerifyPolicy, VerifierRegistry)`,
  `verify_chained_log(entries, genesis, ChainVerifier, LogSigner)`,
  `VerifierRegistry`, `VerifyPolicy`. The generic, synchronous, platform-agnostic
  entry points. Evidence *presence* selects the verifier; a required channel
  that is absent is an honest `NOT PROVEN`, never a silent drop.
- `wire` — `Bundle`, `Evidence`, `Fact`, `Node`, `B64`, `BUNDLE_V`. The frozen
  byte/JSON contract for a bundle. The *only* bundle schema.
- `protocol` — the framed socket: `[tag, u32-BE len, payload]`, `OP_COLLECT`,
  `OP_READ_PCRS`, `RESP_OK`/`RESP_ERR`, `encode`/`decode`/`read_frame`/
  `write_frame`. This is the nonce→bundle wire contract a daemon exposes and a
  client (wardenctl, posternd proxy) speaks. ONE codec owns both frame orders
  (`FrameOrder::TagFirst` = this socket; `FrameOrder::LenFirst` = the admin
  face's historical `[len, tag, payload]` shape): a consumer never carries a
  private second framing.
- `serve` — the reference HTTP face: `POST /attest {nonce?, user_data?,
  public_key?}` → the bundle+facts. The template for any HTTP attestation proxy.
- `proxy` — the client side of the attestation ADMIN FACE (a daemon's
  nonce→envelope listener): `ProxyPolicy`, `parse_hex_nonce`,
  `attest_roundtrip`, `ProxyError` (+ `status`/`json`), `json_error`. The
  len-first round-trip a wire owner (bastiond's `/health/api`, the generic
  CLI) calls instead of hand-rolling the codec. Stops BELOW HTTP (frames +
  nonce + errors + status-as-data; the wire owner renders HTTP bytes). A
  deliberate byte pipe: it never verifies the envelope. Sync, std-only, no
  tokio.
- `bridge` — the gVisor file-transport (challenge/response files) for a
  sandboxed collector that cannot reach the host UDS.
- `spki` — `spki_der`, `spki_raw_key`, `spki_pin`, `pin_of_cert`: the bounded
  DER walk that turns a cert into the SPKI-SHA256 identity pin. Verifiers use
  `spki_pin(leaf_der)` to prove the TLS leaf key == the attestation signer key.
- `trust` / `snp` — the baked AMD ARK/ASVK + AWS IIDD region roots + the SNP
  report verifier. THE source of truth for the fingerprints the browser bundle
  must match.
- `bootproof-platform-wardend` — the wardend plugin: `WARDEND_CHANNEL`,
  `WardendDoc` (the fact schema: `units`, `LuksStatus`, `SealState`,
  `PcrPolicy`, `KeyAcl`, `StateLogEntry`), `WardendVerifier`, `P256Signer`,
  `WardendChainVerifier`, `build_wardend_evidence()`.
- `system_health` (feature `system-health`) — the browser verifier bundle:
  the System Health HTML shell + the service-worker verifier, embedded with
  `include_str!`, plus `SW_SHA256` and the drift-killer test asserting the JS
  baked roots equal the Rust `trust`/`snp` constants. One crate ships BOTH
  verifiers so JS and Rust cannot drift.

## Ownership boundary (wardend ↔ bootproof)

- **bootproof owns:** bundle schema, generation, verification, the log
  mechanism, the socket framing, trust roots, the identity pin, the fact
  schemas, the System Health envelope *presentation* schema (the metadata +
  identity section shapes), and the browser verifier.
- **wardend owns:** the daemons. `seald` holds the HSM key and supplies the
  evidence + calls `engine::produce`. `bastiond` owns the wire (:443) and
  serves the bytes bootproof hands it. `posternd` is the :22 SSH back door +
  the wardenctl/admin proxy. `wardenctl` is a CLI consumer of `verify_bundle` +
  `spki::spki_pin`. NONE of them define attestation semantics.
- A browser can only reach `bastiond` (:443); `posternd` is SSH-only. When the
  contract says "posternd proxies the attestation socket over HTTP", the HTTP
  path physically terminates at `bastiond` (the only wire owner) and is bridged
  to posternd; the *bytes and their meaning* are bootproof's either way.

## Status vs the end goal (verified 2026-11-07)

Already true (committed):
- `seald` produces bundles via `engine::produce` + the wardend plugin, and
  verifies them with `verify_bundle` on the seald side.
- `seald` binds a framed `attest.sock` (nonce→bundle) and the `admin.sock`
  wardenctl face.
- `wardenctl` embeds bootproof (`verify_bundle`) for the CLI verifier.
- The engine is registry-driven and platform-agnostic (the "future platforms"
  requirement is the design, not a TODO).
- The `system-health` feature seam is in (`Cargo.toml` + gated `pub mod`),
  commit `cf576e9`.
- The golden-fixture two-verifiers-agree gate is in:
  `fixtures/system_health/` (`gen_golden.js` regenerates
  `golden.json` + the three tamper fixtures deterministically via RFC
  6979 signing, byte-stable; `harness.js` drives the REAL `verify.js`
  headless through node's vm + WebCrypto). The gate lives in two tests:
  `crates/bootproof/tests/system_health_agreement.rs` (core snp + tpm2
  registry) and `crates/bootproof-platform-wardend/tests/system_health_agreement.rs`
  (the wardend channel; the core must never depend on a platform crate).
  The SNP half is the REAL live report under the REAL live VLEK with the
  nonce FROZEN to the live report's own binding; the TPM2 half is a
  synthetic wire-v1 quote over PCRs 0-9 + 22 so the cross-channel fold
  (PCR22 == H(0 || H(snp doc || wardend doc))) is PROVEN in both. The
  frozen verdict crosswalk: the golden asserts EXACT status equality
  (PROVEN/DEGRADED both sides); a rejected snp channel maps Rust's
  `memory_encryption` NOT PROVEN failed-fact to JS's FAILED; a rejected
  tpm2 channel (fold mismatch) emits NO tpm facts + a loud Rust error
  (Tpm2Verifier is all-or-nothing) and maps to JS's rolled FAILED
  `tpm_quote`. A tamper must never verify: agreement on the REJECTION is
  the security property; agreement on the fact placement is only
  asserted where both verifiers place the fact identically.

Remaining deltas (the actual work):
1. **Move the System Health envelope *presentation* schema** (the
   `metadata`/`identity` section shapes now built in
   `wardend/seal/src/attest_envelope.rs`) INTO bootproof so the browser, the
   CLI, and any future client render one schema from one owner. Keep it
   platform-agnostic: sections are keyed slots that a platform fills, so a
   non-wardend platform reuses the same envelope shape. seald keeps only the
   *file/device reads* (the platform's evidence source) and hands values to the
   bootproof schema builder.
2. **The browser verifier bundle** (`system_health.rs` +
   `assets/system_health/*`): shell + service worker + `SW_SHA256` + the
   drift-killer test + the golden fixture + the `verify_bundle`-agreement test.
3. **The HTTP attest proxy: design resolved, bootproof seam landed, the
   wardend swap is the open increment.** The AGENTS.md either/or
   (bastiond-bridged-to-posternd vs posternd-HTTP-bridged-by-bastiond) was a
   false dichotomy: posternd owns :22 only (`proxy_wardenctl` is a frame pipe
   INSIDE an authenticated SSH session; there is no TCP listener), so a
   browser cannot reach it and an unauthenticated posternd HTTP face would
   duplicate the SSH-gated admin path. RESOLVED: HTTP terminates at `bastiond`
   (the only wire owner) as today, and the proxy LOGIC (frame codec, nonce
   parser, timeouts, error/status mapping) moves INTO bootproof. `bootproof::proxy`
   now owns the round-trip: `ProxyPolicy` + `parse_hex_nonce` +
   `attest_roundtrip` + `ProxyError` (+ `error_json`/`status`), failure
   semantics MOVED from wardend's `bastion/src/health.rs` (equivalence tests
   re-run the original code shapes side by side, same inputs -> same reason
   strings). It stops BELOW HTTP: bootproof owns frames/nonce/errors/status-AS-DATA,
   the wire owner owns the HTTP bytes. `protocol` was generalized with an
   explicit `FrameOrder` (`TagFirst` daemon socket, `LenFirst` admin face) so
   ONE codec owns both orders (no private second framing in a consumer). The
   proxy is a deliberate byte pipe: it never verifies the envelope (a checking
   proxy is an unpinned third verifier). OPEN: wardend's `health.rs` deletes its
   hand-rolled codec and calls the seam (byte-identical HTTP responses pinned
   by the QEMU gate), dispatched as wardend's increment.

## Build + test

- `export PATH="$HOME/.cargo/bin:$PATH"` before any cargo command.
- Build/test the core: `cargo build -p bootproof` / `cargo test -p bootproof`
  (must be green, no hang). The `system-health` feature adds no deps (statics
  only), so it is cheap to build: `cargo test -p bootproof --features
  system-health`.
- If `target/` is root-owned (an old root cargo build left root-owned dirs
  under `target/debug/.fingerprint`), do NOT chmod them; build into an isolated
  dir instead: `export CARGO_TARGET_DIR="$HOME/.crow/scratch/bootproof-target"`.
- Platform plugin tests: `cargo test -p bootproof-platform-wardend`.
- Do NOT run `cargo fmt`; format by hand to match the surrounding style.
- Default feature is `platform-aws`; keep the core free of platform-specific
  code so `-p bootproof` builds without a platform.

## Style contract

- No panics in library/daemon code paths (fail closed to a reported fact), no
  `unwrap`/`expect` in non-test code. A missing source is an honest `NOT
  PROVEN`, never a fabricated healthy state and never a hang.
- The bundle byte contract (challenge expansion, slot-link fold, SNP report
  layout) is frozen; a change to it is a protocol change that must keep the
  browser verifier, the Rust verifier, wardenctl, and any posternd proxy in
  lock-step in the SAME commit.
- Focused commits, `component: summary`. Commit with the operator's git
  identity only (`Lance R. Vick <lance@distrust.co>`); never an agent identity.
  Do not `git push` without explicit operator authorization.

## The CLI layering + neutrality principle (the client side)

There is a strict, one-directional CLI layering, and it encodes the product
goal: **verify anything we can, about our own ecosystem AND other people's.**

```
future operator CLI  ->  wardenctl (wardend superset)  ->  bootproof (library)
                                                       ->  bootproof CLI
                                                          (the generic
                                                           remote attester)
```

- **bootproof CLI = the generic, neutral, UNAUTHENTICATED remote attester.**
  It must be able to point at ANY server and verify whatever the bundle proves,
  with NO credentials and NO assumption the server is a wardend/stagex node. It
  is the reference client for the whole ecosystem and every third party's:
  - our own `seald` / `bootproofd` attestation faces (the wardend + stagex
    platforms),
  - turnkey TEE-as-a-Service / TVC servers,
  - `caution.co`, `tinfoil`, and other verifiable-compute vendors,
  - any future platform that emits a `bootproof::wire::Bundle`.
  The CLI runs the generic `engine::verify_bundle` against whatever channels
  the fetched bundle actually carries (the registry is evidence-driven, so a
  bundle from ANY platform verifies its own channels + honest `NOT PROVEN` for
  what it lacks). Fetching a bundle over the network is the delta to add: a
  client that takes a URL/socket, speaks the `protocol` frame (or the
  `attest`/`serve` HTTP face), pulls the bundle, and verifies it. It must never
  hard-require a wardend/stagex channel — a turnkey TVC bundle with only SNP is
  a VALID bundle to verify, just a smaller one.
- **wardenctl = the wardend superset.** It wraps bootproof-as-a-library
  (`engine::verify_bundle` + the `bootproof-platform-wardend` verifier — already
  true in `wardenctl/src/verify.rs`) and ADDS wardend-specific behavior: the
  admin-frame/OP_ATTEST round-trip, the HSM/seal-state/unit/LUKS/PCR sections,
  the ACME-leaf identity link, the posternd proxy path. Everything generic
  lives in bootproof; wardenctl only adds wardend meaning. A future operator CLI
  wraps wardenctl-as-a-library the same way, so it inherits bootproof's generic
  reach *and* wardend's depth.
- **Directionality is enforced by the layering, not just convention:** the CLI
  depends on wardenctl depends on bootproof. bootproof must never depend on
  wardend (the wardend platform code lives in the separate
  `bootproof-platform-wardend` plugin crate, which *is* allowed to know about
  wardend). This keeps bootproof shippable to a client that only ever attests
  third-party vendors.
- **Net effect on design choices:** any feature that only makes sense for our
  own daemons (seal state, unit health, the posternd proxy) belongs in the
  wardend plugin or wardenctl, NOT in the bootproof core or the generic CLI. If
  adding it to the core would require a wardend concept, it is in the wrong
  layer.

## Validation strategy (the acceptance gate)

The contract is validated by agreement, not by assertion of a single verifier:
1. **Unit level (bootproof):** the drift-killer test asserts the JS baked
   ISRG/ARK fingerprints equal the Rust `trust`/`snp` constants; the
   `SW_SHA256` test pins the browser bundle bytes.
2. **Cross-verifier agreement (bootproof):** the golden fixture bundle is
   verified by BOTH `engine::verify_bundle` and the service worker (node or a
   documented browser harness); identical fact verdicts on every channel, or CI
   fails. One bundle, two verifiers, one verdict.
3. **Integration (QEMU gate, wardend):** a fresh boot serves `/` (the shell),
   `/verify.js` + `/verify.js.src` byte-identical, `/health/api?nonce=` = the
   envelope that is a byte-exact proxy of the `[len][OP_ATTEST][nonce32]`
   admin-frame round-trip; the dead-backend/unrouted-SNI fallback still returns
   the page (never a reset).
4. **Live acceptance (AWS):** the browser service worker and `wardenctl status
   <ip>` verify the SAME host and report identical facts/verdicts, including the
   identity link `spki_pin(leaf_pem) == identity.attest_signer_spki_sha256` and
   the fresh-nonce binding.
