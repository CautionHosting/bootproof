# Pinned AWS instance-identity-document (IIDD) DSA certificates

One DSA signing certificate per AWS region, pinned at build time.

- Source: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/regions-certs.html
  ("AWS public certificates for instance identity document signatures")
- Fetched: 2026-08-27
- Used for: verifying the PKCS#7 (DSA/SHA-1) signature of the EC2 instance
  identity document served at IMDS `latest/dynamic/instance-identity/pkcs7`
  (verification flow per
  https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/verify-iid.html).
- The signer's issuer is `C=US, ST=Washington State, L=Seattle,
  O=Amazon Web Services LLC`. The DSA signature covers the canonical
  signed attributes (the `a0` SET re-encoded with the `0x31` tag), NOT the
  document directly; the JSON document embedded in the PKCS#7 (contentInfo
  pkcs7-data) is bound through the (signed) messageDigest attribute, which
  must equal SHA-1 of the embedded JSON. AWS wraps the r/s pair in an OCTET
  STRING instead of the standard BIT STRING, and these are X.509 v1 certs
  (no extensions). 19 regions share one certificate (20 distinct keys).

These certificates are long-lived (notBefore 2012-2024, notAfter ~2038).
If AWS rotates them, re-fetch from the docs page and replace the files.

- `af-south-1`: `2f163f0a86b825447e09de87cfe343adce5e404756708f7078261d68f8362860`
- `ap-east-1`: `c74dd1a04ed0c91037c4222b1a7ac925122d5d75717e9067930d8b914687ae4f`
- `ap-east-2`: `6da153a6ca7c10556a2c71ec3c1d1e5b2f050aab243834d16e0af104a49419f9`
- `ap-northeast-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ap-northeast-2`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ap-northeast-3`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ap-south-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ap-south-2`: `9a97506405f8a753d824dd2d6b5e0e3df430e31a43f58b8ae7a263cfa15237f8`
- `ap-southeast-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ap-southeast-2`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ap-southeast-3`: `c9a6b5570637e9041b37bc411059fc6ae2ccc5f37e941dd4405e50cb057f58eb`
- `ap-southeast-4`: `f3e98b5016647217ffed5fbece6514630e8f18b6478ef718d52dc844407eaf16`
- `ap-southeast-5`: `3ac2d5507f002e718a432af10cd90d8d40e0d68e446edf40f7fa7605b10e010d`
- `ap-southeast-6`: `3ffaac6009c18e99910e8a7c682112cc61b5d84e0fd0b7526ca5b4e0bbeaaf97`
- `ap-southeast-7`: `3f6475464faf19c175901646b1c1c14270aefc653d4e86fe42a8a236a513da45`
- `ca-central-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `ca-west-1`: `290b12dd71a37cbc1448a808aacd4b9cf334b296e2f9bdf60454b2593a10ab2d`
- `cn-north-1`: `b2f2d587a769713c73f1c1f116d5fd24ba21a883ad00d2af1276f2ebf2724fa2`
- `cn-northwest-1`: `b2f2d587a769713c73f1c1f116d5fd24ba21a883ad00d2af1276f2ebf2724fa2`
- `eu-central-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `eu-central-2`: `c05c4c06be73376ed0b0476ed773db47d28000ede4afaaa616341ad4fd22ad3d`
- `eu-north-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `eusc-de-east-1`: `0c6deaf6071793a0cb906ac91a44fba579b4169de57523b64d3377c307028761`
- `eu-south-1`: `be1d873285529502af17bdf089cb018ea3f3319a97a580f10237aeae1228a099`
- `eu-south-2`: `145f57a770510169a75399b40bf0087ce128dceaa30483a2b7e597f5a28ec8d3`
- `eu-west-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `eu-west-2`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `eu-west-3`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `il-central-1`: `917f8d2417976c7a72ec310331cf8009b8cb2aa6b92aece04a75bea850926585`
- `me-central-1`: `5c8c690d92df123ef97bdf3ab7d91f9609c65c964fff0969ef5a2b429872a4e4`
- `me-south-1`: `5b67a15a070ff98637ae2b2779b51385349e6d0ebcf7d089efe1f553052c4a67`
- `mx-central-1`: `b028258510b8fa09bb5e74bf95dad7bf487505ad0963109d56d7b415e45d8a7d`
- `sa-east-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `us-east-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `us-east-2`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `us-gov-east-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `us-gov-west-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `us-west-1`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
- `us-west-2`: `e3aab1950fcca420843f1477b701eee16d5700dedaf512cabb1c46016131159d`
