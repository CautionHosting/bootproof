# Bootproof

Bootproof is a Rust toolkit and daemon for collecting and verifying remote-attestation evidence across confidential-computing platforms.

The project is intended to provide common evidence formats, challenge/response bindings, platform evidence providers, verification policy, and HTTP services without tying the overall architecture to one hardware technology. This includes environments based on AWS Nitro Enclaves, AMD SEV-SNP, Intel TDX, TPM 2.0, and confidential accelerators such as NVIDIA GPUs.

<https://codeberg.org/caution/bootproof>

## Project status

Bootproof is under active development. The current production implementation generates AWS Nitro Enclaves attestation documents and verifies their certificate chain, signature, and nonce. Other platform integrations are being developed behind platform-specific interfaces and feature flags.

Platform names in an evidence format or policy type do not by themselves imply complete hardware collection and verification support. Consult the relevant crate features and tests before relying on a platform in production.

## Workspace

- `bootproof`: attestation data types and platform evidence generation.
- `bootproof-sdk`: attestation verification for clients and relying parties.
- `bootproofd`: an HTTP daemon that serves challenge-bound attestation evidence.

The separation between evidence generation and verification is intentional: verifiers should authenticate evidence, freshness, and expected measurements independently of the attested workload.

## Intended platform scope

- AWS Nitro Enclaves
- AMD SEV-SNP
- Intel TDX
- TPM 2.0
- Composite CPU and accelerator attestation, including NVIDIA Confidential Computing

Support is added per platform rather than through a claim that all evidence formats are interchangeable. Each integration must bind the caller's challenge into hardware-authenticated evidence and enforce platform-specific certificate, signature, revocation, TCB, debug-mode, and measurement policy as applicable.

## Build

Build the complete workspace:

```sh
cargo build --workspace
```

Run the workspace tests:

```sh
cargo test --workspace
```

Build only the daemon:

```sh
cargo build --release -p bootproofd
```

## Daemon

Run `bootproofd` in an environment that provides the evidence source required by the selected platform feature. The default build enables AWS Nitro Enclaves support.

```sh
cargo run -p bootproofd
```

The daemon listens on `127.0.0.1:7080` by default. Its attestation endpoint accepts a caller-provided nonce and returns evidence bound to that challenge.

## Security

Remote attestation is useful only when verification covers the complete trust decision. A relying party should verify at least:

- evidence authenticity and its hardware/vendor trust chain;
- freshness through a caller-generated nonce;
- expected workload or platform measurements;
- security-relevant platform state, including debug and TCB policy; and
- any application, channel, or accelerator binding required by the protocol.

Development fixtures and synthetic evidence must not be accepted as production trust material.

### Persisted Nitro proofs

`Nitro::verify_at_attestation_time(expected_user_data, expected_nonce)` verifies
the AWS certificate chain at the attestation's signed generation timestamp,
without clock-skew adjustment. It still verifies the COSE signature, expected
PCRs, and an exact `user_data` match (e.g. the expected artifact hash) before
returning the payload. Certificate expiry at a later wall-clock time does not
invalidate that historical proof.

Use `Some(&nonce)` to require an exact nonce match (at least 12 bytes), or `None`
to require an absent/null nonce, as used by stored public-certificate proofs.
Callers must apply their policy to the authenticated timestamp. This API establishes
historical provenance, not freshness or current user authorization. A
content-derived deterministic nonce also does not establish freshness.

Live attestation continues to use `verify(time, &fresh_nonce)` with its existing
caller-time and nonce checks. Recryption authorization still needs its own
fresh challenges and replay protection. The local test certificates are
synthetic fixtures; neither public verification API accepts their test root.
