# Pinned vendor roots and live fixtures (Nitro side)

## nitro-root.der — the AWS Nitro Enclaves attestation root CA

The single pinned root that `Nitro::verify` chains attestation-document
certificate chains to (`AWS_NITRO_ROOT_CA_DER` in `../nitro.rs`). Baked
into every verifier binary with `include_bytes!`; no runtime fetch, ever.

SHA-256 (DER): `641a0321a3e244efe456463195d606317ed7cdcc3c1756e09893f3c68f79bb5b`
(533 bytes)

Cert facts (measured from the file with `openssl x509 -inform DER`):

- subject = issuer = `C=US, O=Amazon, OU=AWS, CN=aws.nitro-enclaves`
  (self-signed: it is the root, nothing above it)
- signature algorithm: ecdsa-with-SHA384 (P-384 root)
- `CA:TRUE`
- validity: 2019-10-28 .. 2049-10-28

Provenance, byte-traced (not remembered):

1. The DER appears BYTE-IDENTICAL inside the certificate chain of BOTH
   committed live attestation documents below: at offset 1584 of
   `aws-test.cbor` and offset 1990 of `nsm-live.cbor` (both `30 82` DER
   certs, 533 bytes, SHA-256 `641a03…`, equal to this file byte-for-byte).
   The docs' chains therefore terminate at THIS key: every signature
   check the fixtures perform walks to it.
2. `nsm-live.cbor` is a live capture from AWS hardware (instance
   `i-02a44cb68978c43af`, NitroTPM PCR8 doc via NSM vendor command; see
   the capture comment in `../nitro.rs`). A root key that terminates a
   chain produced by AWS's own NSM on AWS hardware is AWS's published key:
   the chain only verifies under it.

Honest limits (2026-11-09): the AWS docs/endpoint URLs for the root
(`aws.nitro-enclaves.s3.amazonaws.com/…`) did not serve a copy from the
dev box this provenance was traced on (DNS resolves, object fetches
404/refused from outside the enclave ecosystem), so this README does NOT
claim a same-day external re-fetch. The byte-identity trace against live
AWS-captured documents is the load-bearing evidence. Re-fetch and re-pin
if AWS ever rotates the root (a rotated root breaks the fixture chains
above loudly, in CI, so drift cannot pass silently).

## aws-test.cbor — legacy Nitro ENCLAVE attestation document

COSE_Sign1 enclave doc (PCR0/1/2 + nonce `d041b23b…52b10636`), used by
`it_works()`/expiry tests in `../nitro.rs`. Generated ~2025-12 against a
real enclave (pinned `VALID_DURATION` in the test). Chain contains the
root above.

## nsm-live.cbor — live NitroTPM attestation document (NSM vendor command)

Captured from instance `i-02a44cb68978c43af` (see the test comment in
`../nitro.rs`): a real `NSM_REQUEST` response, NitroTPM-style (keys its
PCRs as `nitrotpm_pcrs`), carrying the full certificate chain including
the root above. Used to prove the ECDSA P-384/SHA-384 COSE_Sign1
signature path against AWS-hardware-produced bytes.
