# Historical verification test certificates

These synthetic P-384 certificates and the **public test private key** exercise
signed nonce-less attestations and certificate-validity boundaries. They are not
Nitro evidence and must never be used by a production verifier.

The root is valid from 2020-01-01 through 2040-01-01. The leaf is valid from
2025-12-23 17:06:00 through 20:06:03 UTC, has digital-signature key usage and
TLS-server extended key usage, and was signed with ECDSA/SHA-384. The PKCS#8 key
belongs only to this leaf. The root private key is not retained.

The unit tests sign COSE documents locally with this leaf key. Only the private
verification helper accepts the test root; both public APIs always use AWS's
Nitro root. No runtime trust-root override or synthetic-proof switch is added.
