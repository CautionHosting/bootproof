# AMD KDS certificates (pinned at build time)

Fetched 2026-08-26 from https://kdsintf.amd.com (no auth):
- ark-milan.pem: CN=ARK-Milan (self-signed AMD root),
  GET /vlek/v1/Milan/cert_chain (2nd cert)
- asvk-sev-vlek-milan.pem: CN=SEV-VLEK-Milan (VLEK intermediate CA),
  GET /vlek/v1/Milan/cert_chain (1st cert)

SHA-256 (PEM files):
  6c0c38ecb76c9f2b2d054f7d806fd5ccfec970599149ce0ed37b1f77fa409ab7  asvk-sev-vlek-milan.pem
  8c109952166431ffad8cb9a3d54f3d20ffbbb58164f0d54be3457bf0ece9e0d8  ark-milan.pem
SHA-256 (ARK DER): 69:d0:63:b4:53:44:d2:6a:2e:94:e1:f4:21:0d:e4:9e:f5:55:30:82:87:d4:c1:74:44:5c:95:63:9a:54:0b:cd

Used by the trust tree to verify the platform-provisioned VLEK certificate
(chain: VLEK cert -> ASVK -> ARK) so SEV-SNP report facts anchor to AMD's
root of trust.
