#!/usr/bin/env node
// gen_golden.js — the golden-fixture generator for the two-verifiers-agree
// gate (the System Health contract's cross-verifier acceptance test).
//
// One deterministic envelope, verified by BOTH verifiers:
//   * Rust: bootproof::engine::verify_bundle (core snp + tpm2 verifiers; the
//     wardend channel verifies in the bootproof-platform-wardend plugin's
//     own agreement test, since the core must never depend on a platform
//     crate).
//   * JS:   the service worker verify.js driven headless from node
//     (fixtures/system_health/harness.js loads it through vm + WebCrypto).
//
// The constraints that shaped the fixture:
//   * The SNP half is the REAL live report (snp-report-live-v0.bin) under
//     the REAL live VLEK: the only VLEK whose chain reaches the pinned
//     ARK-Milan. The firmware signed report_data inside the signed prefix,
//     so the challenge nonce is FROZEN to the live report's own binding
//     (snp-request-live-v0.bin[..32]). The fixture is a point-in-time
//     snapshot; fresh-nonce behavior is covered per-check in verify.js's
//     own failure paths (the tamper fixtures exercise exactly that).
//   * The TPM2 half is synthetic: a wire v1 quote doc (hand-built
//     TPMS_ATTEST + TPMT_PUBLIC, ECDSA-P256/SHA-256 over the attestation)
//     under fixed fixture keys. The quoted selection is PCRs 0-9 + 22: the
//     NitroTPM-visible range PLUS the slot PCR, so the cross-channel fold
//     (PCR22 == H(0x00*32 || H(snp doc || wardend doc))) is genuinely
//     PROVEN in both verifiers, not skipped at a hardware boundary.
//   * The sign key's authPolicy is the TCG reference PolicyPCR formula
//     (zero-seeded digest) over THE SAME selection + per-PCR digests the
//     quote carries, byte-identical to Rust's policy_pcr_auth_policy, so
//     the Rust sign_key fact PROVENs and the JS tpm.sign_key sub PROVENs
//     from one and the same byte string.
//   * The wardend channel doc is serde-shaped JSON (every [u8;32] / Vec<u8>
//     is a JSON ARRAY OF NUMBERS, exactly what serde emits through the
//     seald admin face), with a 2-entry HSM-signed state log. The wardend
//     hash policy IS SHA-256(entry bytes), so a plain Node
//     sign('sha256', msg) IS the prehashed signature both verifiers check
//     (Rust verify_prehashed over the entry hash; JS WebCrypto hash-mode
//     over the same bytes: one digest, one signature, two verifiers).
//   * pcr_policy.values omits PCR22 ON PURPOSE: the wardend doc is folded
//     INTO PCR22, so publishing the fold inside the doc would be a fixed-
//     point with no solution. The plugin verifier does not read `values`;
//     the honest shape is "measured values for the ordinary PCRs".
//   * ek_cert is an opaque anchor blob: NEITHER verifier checks the EK
//     chain in this build. Rust: ek_cert fact = DEGRADED; JS: tpm.ek_cert
//     sub = DEGRADED, which by the shared verdict algebra does NOT
//     downgrade tpm_quote. Agreement on DEGRADED is itself the tested
//     verdict (a MISSING EK would diverge: JS rolls NOT PROVEN, Rust stays
//     PROVEN), so the fixture carries the anchor deliberately.
//
// Tamper fixtures (both verifiers must reject; the contract's honest-
// rejection cases; the exact-status-match assertion applies ONLY to the
// golden, per the divergence note in the Rust tests):
//   * snp-tamper:   one report_data byte flipped. Rust: memory_encryption
//                   NOT PROVEN (failed_fact, reason echoes the engine
//                   error); JS: FAILED (nonce binding + report sig sub).
//                   Both reject; both name the binding break.
//   * log-tamper:   one wardend log entry's operation byte flipped. Rust
//                   (plugin): the wardend channel errors, the chain fact
//                   never PROVENs; JS: wardend_state_chain FAILED.
//   * missing-snp:  the snp channel dropped. EXACT status agreement on
//                   memory_encryption = NOT PROVEN (Rust's required-absent
//                   fact vs JS's honest NOT_PROVEN). The tpm fold also
//                   breaks (other docs changed): BOTH verifiers reject
//                   tpm_quote, loudly, for the same reason.
//   * chip-tamper:  (AMI-2) one CHIP_ID byte flipped @0x1A0 -- inside the
//                   VLEK-SIGNED prefix but OUTSIDE report_data, so the
//                   nonce binding stays green and ONLY the report
//                   signature dies. This is the identity-rows failure
//                   leg: Rust's failed_facts() must emit THREE NOT
//                   PROVEN facts (memory_encryption + both identity
//                   rows); the JS gate must say NOT PROVEN on both rows
//                   for the same reason (the signature the rows ride
//                   failed). An attacker rewriting the chip serial is
//                   rejected by both verifiers through the SAME gate the
//                   rows are eligible under.
//
// No dependencies. Deterministic: fixed keys, fixed nonce source, RFC 6979
// ECDSA inside Node's sign. Outputs (same directory):
//   golden.json, golden.snp-tamper.json, golden.log-tamper.json,
//   golden.missing-snp.json, golden.meta.json (nonce hex + HSM SPKI pin +
//   the expected shared verdicts the Rust tests read).
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const OUT = __dirname;
const DATA = path.join(__dirname, '..', '..', 'crates', 'bootproof', 'src', 'trust', 'data');

// ---------------------------------------------------------------------------
// Byte helpers + the deterministic fixture keys (synthetic; NEVER anything
// that guards real material).
// ---------------------------------------------------------------------------
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const hexOf = (b) => Buffer.from(b).toString('hex');
const u8arr = (b) => Array.from(Buffer.from(b));
const b64 = (b) => Buffer.from(b).toString('base64');
const u16 = (v) => Buffer.from([v >> 8, v & 0xff]);
const u32 = (v) => Buffer.from([(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff]);
// u64: the token-safe 8-byte BE writer. v is a BigInt, a decimal string, or
// a Number that is a SAFE integer (<= 2^53). The >2^53 parity rule: a bare
// numeric literal > 2^53 corrupts AT AUTHORING (1653858798848288593 becomes
// ...500 the moment it is a Number), and every u64 in the fixture's digest
// path must flow through here as a token (BigInt/string), never a coerced
// Number. A Number argument outside Number.MAX_SAFE_INTEGER is a LOUD
// generation failure, never a silent bit loss (this is the fixture-side
// drift detector for the JS coercion class; the I-2b browser leg carries
// the parsing-side obligation).
const u64 = (v) => {
  const b = Buffer.alloc(8);
  if (typeof v === 'bigint') b.writeBigUInt64BE(v);
  else if (typeof v === 'string') b.writeBigUInt64BE(BigInt(v));
  else if (Number.isSafeInteger(v)) b.writeBigUInt64BE(BigInt(v));
  else throw new Error('u64: coerced Number beyond 2^53 (' + v + ') — author u64 values as BigInt or string tokens');
  return b;
};
function derLen(n) {
  if (n < 128) return Buffer.from([n]);
  if (n < 256) return Buffer.from([0x81, n]);
  return Buffer.from([0x82, (n >> 8) & 0xff, n & 0xff]);
}
const tlv = (tag, content) => Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
const tpm2b = (b) => Buffer.concat([u16(b.length), b]);
// The 65-byte P-256 SPKI prefix (both verifiers build the SPKI identically:
// verify.js spkiFromPoint, Rust spki::spki_der).
const P256_SPKI_PREFIX = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');

// ---------------------------------------------------------------------------
// RFC 6979 deterministic ECDSA (P-256/SHA-256, pure BigInt, no deps).
// Node's crypto.sign picks a RANDOM k per call, so the fixture bytes would
// change on every regeneration. Deterministic k (RFC 6979 with
// HMAC-SHA-256) makes the whole envelope byte-stable across regenerations
// (a fixture whose bytes drift cannot pin SW_SHA256-adjacent expectations
// or git-diff review). Signatures stay ordinary low-s ECDSA-P256/SHA-256:
// both the Rust ecdsa crate and WebCrypto verify them (checked against
// Node's own verifier below at build time).
// ---------------------------------------------------------------------------
const ECC_P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn;
const ECC_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;
const ECC_GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const ECC_GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;
const ECC_B = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn;
const bmod = (a, m) => ((a % m) + m) % m;
// The constants carry the whole implementation: assert the generator is
// actually on the curve before anything signs (a typo must fail loudly at
// generation time, not silently produce unverifiable fixtures).
if (bmod(ECC_GY * ECC_GY, ECC_P) !== bmod(ECC_GX ** 3n - 3n * ECC_GX + ECC_B, ECC_P)) {
  throw new Error('ECC generator constants are corrupt');
}
function invMod(a, m) {
  let [oldR, r] = [bmod(a, m), m];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new Error('invMod: no inverse');
  return bmod(oldS, m);
}
function ptDouble(P) {
  if (!P) return null;
  const [x, y] = P;
  if (y === 0n) return null;
  // P-256 is y^2 = x^3 - 3x + b: the doubling slope carries a = -3.
  const l = bmod((3n * x * x - 3n) * invMod(2n * y, ECC_P), ECC_P);
  const xr = bmod(l * l - 2n * x, ECC_P);
  return [xr, bmod(l * (x - xr) - y, ECC_P)];
}
function ptAdd(P, Q) {
  if (!P) return Q;
  if (!Q) return P;
  const [x1, y1] = P, [x2, y2] = Q;
  if (x1 === x2) return y1 === y2 ? ptDouble(P) : null;
  const l = bmod((y2 - y1) * invMod(x2 - x1, ECC_P), ECC_P);
  const xr = bmod(l * l - x1 - x2, ECC_P);
  return [xr, bmod(l * (x1 - xr) - y1, ECC_P)];
}
function ptMul(k, P) {
  let R = null, A = P, kk = k;
  while (kk > 0n) {
    if (kk & 1n) R = ptAdd(R, A);
    A = ptDouble(A);
    kk >>= 1n;
  }
  return R;
}
const hmacSha256 = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
function rfc6979Sign(dBuf, zDigest) {
  // RFC 6979 section 3.2 (HMAC-SHA-256 DRBG, qlen == rlen == 256 for
  // P-256, so bits2int is the plain integer read):
  const x = BigInt('0x' + dBuf.toString('hex'));
  const z = BigInt('0x' + zDigest.toString('hex'));
  const int2oct = (i) => Buffer.from(i.toString(16).padStart(64, '0'), 'hex');
  const seed = Buffer.concat([int2oct(x), int2oct(z)]);
  let v = Buffer.alloc(32, 0x01);
  let k = Buffer.alloc(32, 0x00);
  k = hmacSha256(k, Buffer.concat([v, Buffer.from([0x00]), seed])); // K = H(V||0||x||z)
  v = hmacSha256(k, v);                                             // V = H(V)
  k = hmacSha256(k, Buffer.concat([v, Buffer.from([0x01]), seed])); // K = H(V||1||x||z)
  v = hmacSha256(k, v);                                             // V = H(V)
  for (;;) {
    v = hmacSha256(k, v);                    // T = V (one block: qlen/8 == 32)
    const kInt = BigInt('0x' + v.toString('hex'));
    if (kInt === 0n || kInt >= ECC_N) {      // k invalid: retry
      k = hmacSha256(k, Buffer.concat([v, Buffer.from([0x00])]));
      v = hmacSha256(k, v);
      continue;
    }
    const R = ptMul(kInt, [ECC_GX, ECC_GY]);
    if (!R) {
      k = hmacSha256(k, Buffer.concat([v, Buffer.from([0x00])]));
      v = hmacSha256(k, v);
      continue;
    }
    const r = bmod(R[0], ECC_N);
    if (r === 0n) {
      k = hmacSha256(k, Buffer.concat([v, Buffer.from([0x00])]));
      v = hmacSha256(k, v);
      continue;
    }
    let sig = bmod(invMod(kInt, ECC_N) * bmod(z + r * x, ECC_N), ECC_N);
    if (sig === 0n) {
      k = hmacSha256(k, Buffer.concat([v, Buffer.from([0x00])]));
      v = hmacSha256(k, v);
      continue;
    }
    if (sig > ECC_N >> 1n) sig = ECC_N - sig; // low-s
    return Buffer.from(r.toString(16).padStart(64, '0') + sig.toString(16).padStart(64, '0'), 'hex');
  }
}
// Deterministic sign('sha256', msg) equivalent; self-checked against
// Node's independent verifier implementation on every use (DER form:
// crypto.verify's 4-arg one-shot accepts DER ECDSA signatures).
function intToDerInt(v) {
  let hexs = v.toString(16);
  if (hexs.length % 2) hexs = '0' + hexs;
  let b = Buffer.from(hexs, 'hex');
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0x00]), b]);
  return tlv(0x02, b);
}
function signDet(pubKey, dBuf, msg) {
  const sig = rfc6979Sign(dBuf, sha256(msg));
  const r = BigInt('0x' + sig.subarray(0, 32).toString('hex'));
  const s = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
  const der = tlv(0x30, Buffer.concat([intToDerInt(r), intToDerInt(s)]));
  const ok = crypto.createVerify('sha256').update(msg).end().verify(pubKey, der);
  if (!ok) {
    throw new Error("RFC 6979 signature failed Node's own verification");
  }
  return sig;
}

// signDetPrehashed: the PREHASHED form of signDet (sign an already-
// computed 32-byte digest, do NOT hash again). The whole-doc digest is
// already SHA-256 output, so the doc signature is signDetPrehashed of the
// digest (the Rust P256Signer verifies it with verify_prehashed over the
// same digest). Self-checked with a pure-BigInt ECDSA verify (Node's
// crypto.verify re-hashes for EC and cannot check a prehash signature),
// so a corrupt prehash signature fails at generation time, never ships.
function signDetPrehashed(pubKey, dBuf, digest) {
  const sig = rfc6979Sign(dBuf, digest);
  const r = BigInt('0x' + sig.subarray(0, 32).toString('hex'));
  const s = BigInt('0x' + sig.subarray(32, 64).toString('hex'));
  // Node's crypto.verify re-hashes its input for EC (it is NOT a prehash
  // API), so it cannot self-check a prehash signature. Verify in pure
  // BigInt instead, over the public point + the digest directly: the SAME
  // ECDSA equation the Rust P256Signer runs in verify_prehashed (R =
  // u1*G + u2*Q, accept iff R.x mod n == r). A corrupt prehash signature
  // fails here at generation time, never ships.
  const z = BigInt('0x' + digest.toString('hex'));
  if (r <= 0n || r >= ECC_N || s <= 0n || s >= ECC_N) {
    throw new Error('prehash signature: r/s out of range');
  }
  const sInv = invMod(s, ECC_N);
  const u1 = bmod(z * sInv, ECC_N);
  const u2 = bmod(r * sInv, ECC_N);
  const G = [ECC_GX, ECC_GY];
  // The public point from the SEC1 uncompressed encoding (0x04 || x || y).
  const pub = pubKey; // the KeyObject; use its raw public bytes.
  const raw = pub.export({ type: 'spki', format: 'der' });
  // The trailing 65 bytes of the P-256 SPKI are the uncompressed point.
  const point = raw.subarray(raw.length - 65);
  if (point[0] !== 0x04) throw new Error('prehash self-check: public point not uncompressed');
  const qx = BigInt('0x' + point.subarray(1, 33).toString('hex'));
  const qy = BigInt('0x' + point.subarray(33, 65).toString('hex'));
  const R = ptAdd(ptMul(u1, G), ptMul(u2, [qx, qy]));
  if (!R) throw new Error('prehash self-check: R is the point at infinity');
  if (bmod(R[0], ECC_N) !== r) {
    throw new Error("RFC 6979 prehashed signature failed the BigInt ECDSA self-check");
  }
  return sig;
}

// A P-256 keypair from a fixed scalar: SEC1 ECPrivateKey -> PKCS8 -> Node
// KeyObject. Fixed digits of e/pi/sqrt2 as scalars: clearly synthetic.
function keyFromScalar(hexStr) {
  const d = Buffer.from(hexStr, 'hex');
  const ecdh = crypto.createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const point = ecdh.getPublicKey(); // 0x04 || X || Y
  const curveOid = Buffer.from('06082a8648ce3d030107', 'hex');
  const sec1 = tlv(0x30, Buffer.concat([
    Buffer.from('020101', 'hex'),
    tlv(0x04, d),
    tlv(0xa0, curveOid),
    tlv(0xa1, tlv(0x03, Buffer.concat([Buffer.from([0x00]), point]))),
  ]));
  const algId = tlv(0x30, Buffer.concat([
    Buffer.from('06072a8648ce3d0201', 'hex'), curveOid,
  ]));
  const pkcs8 = tlv(0x30, Buffer.concat([
    Buffer.from('020101', 'hex'), algId, tlv(0x04, sec1),
  ]));
  const key = crypto.createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  // Round-trip proof: Node parsed the same point ECDH derived.
  const pub = crypto.createPublicKey(key);
  const spki = pub.export({ format: 'der', type: 'spki' });
  const spkiFromPoint = Buffer.concat([P256_SPKI_PREFIX, point]);
  if (Buffer.compare(spki, spkiFromPoint) !== 0) throw new Error('SPKI prefix disagrees with Node');
  return { key, pub, d, point, x: point.subarray(1, 33), y: point.subarray(33, 65) };
}
const AK = keyFromScalar('3141592653589793238462643383279502884197169399375105820974944592');
const SIGN = keyFromScalar('2718281828459045235360287471352662497757247093699959574966967627');
const HSM = keyFromScalar('1414213562373095048801688729037262730136678747355356627749234488');

// ---------------------------------------------------------------------------
// The frozen nonce: the live report's own binding (firmware-signed). All
// premises on the live bytes are asserted up front (fail loud at build).
// ---------------------------------------------------------------------------
const REPORT = fs.readFileSync(path.join(DATA, 'snp-report-live-v0.bin'));
const REQ = fs.readFileSync(path.join(DATA, 'snp-request-live-v0.bin'));
const NONCE = REQ.subarray(0, 32);
if (REPORT.length !== 1184) throw new Error('live report must be 1184 bytes');
if (hexOf(REPORT.subarray(0x50, 0x70)) !== hexOf(NONCE)) throw new Error('report_data must echo the request nonce');
if (REPORT.readUInt32LE(0x00) !== 5) throw new Error('report must be v5');
if (REPORT.readUInt32LE(0x30) !== 0) throw new Error('report must be VMPL 0');
if (REPORT.readUInt32LE(0x34) !== 1) throw new Error('sig_algo must be 1 (ECDSA P-384/SHA-384): the JS path gates on it');
const policyLo = REPORT.readUInt32LE(0x08);
if ((policyLo & 0x80000) !== 0) throw new Error('policy must disallow debug');
if ((policyLo & 0x2000000) === 0) throw new Error('policy must disable page-swap');
// The report_data tail (back 32) is the live host's own cross-channel fold;
// NEITHER verifier binds on it (front-32 only), and JS labels it
// informationally ("nonzero tail: cross-channel data"). No premise needed.

// ---------------------------------------------------------------------------
// The wardend channel doc (serde-shaped JSON). Built BEFORE the fold so the
// exact bytes are what PCR22 measures.
// ---------------------------------------------------------------------------
const GENESIS = sha256(Buffer.from('bootproof golden fixture genesis v1'));
const entryBytes = (prev, st, op, ts) => Buffer.concat([prev, st, op, u64(ts)]);
const entryHash = (prev, st, op, ts) => sha256(entryBytes(prev, st, op, ts));
// The wardend HSM signs the entry hash; the entry hash IS SHA-256 of these
// bytes, so sign('sha256', bytes) == sign(hash) for BOTH verifiers (see the
// header note).
const signEntry = (prev, st, op, ts) =>
  signDet(HSM.pub, HSM.d, entryBytes(prev, st, op, ts));

const op0 = Buffer.from('genesis'), op1 = Buffer.from('seal');
const st0 = sha256(Buffer.from('golden state 0')), st1 = sha256(Buffer.from('golden state 1'));
const TS0 = 1762483200, TS1 = 1762486800;
const log0 = { prev_hash: u8arr(GENESIS), new_state_hash: u8arr(st0), operation: u8arr(op0), timestamp: TS0, signature: u8arr(signEntry(GENESIS, st0, op0, TS0)) };
const h0 = entryHash(GENESIS, st0, op0, TS0);
const log1 = { prev_hash: u8arr(h0), new_state_hash: u8arr(st1), operation: u8arr(op1), timestamp: TS1, signature: u8arr(signEntry(h0, st1, op1, TS1)) };

// THE selection: PCRs 0-9 + 22 (quote, sign-key policy, wardend policy).
const SEL_BYTES = Buffer.from([0xff, 0x03, 0x40]);
const PCR_INDICES = [];
for (let b = 0; b < 3; b++) for (let i = 0; i < 8; i++) if (SEL_BYTES[b] & (1 << i)) PCR_INDICES.push(b * 8 + i);
const pcrValues = {};
for (const i of PCR_INDICES) pcrValues[i] = sha256(Buffer.from('bootproof golden pcr ' + i));

// ---------------------------------------------------------------------------
// The canonical whole-doc digest (I-2 byte-attestation): the JS mirror of
// the Rust bootproof_platform_wardend::canonical_doc_digest. ONE wire
// shape, two implementations pinned against each other by the
// GOLDEN_DOC_DIGEST_HEX assertion below (the Rust side pins the SAME hex
// in the plugin crate's tests). If this drifts, generation fails loudly.
// The discipline mirrors the Rust: domain prefix; fixed field order
// (seal_state, state_log, pcr_policy, units, luks, key_acls, retry); a
// 1-byte presence tag per Optional (None = 0x00 + nothing, so None !=
// Some(empty)); 4-byte BE lengths for bytes/strings/lists; fixed-width BE
// integers; bools as single bytes.
// ---------------------------------------------------------------------------
const DOC_DIGEST_PREFIX = Buffer.from('wardend/platform-doc-digest/v1');
const dBytes = (b) => Buffer.concat([u32(b.length), Buffer.from(b)]);
const dU64 = (v) => u64(v);
const dBool = (b) => Buffer.from([b ? 1 : 0]);
const dOpt = (v, f) => (v === undefined || v === null ? Buffer.from([0]) : Buffer.concat([Buffer.from([1]), f(v)]));
const dU32s = (arr) => Buffer.concat([u32(arr.length), ...arr.map((x) => u32(x))])
const canonicalDocDigest = (doc) => sha256(Buffer.concat([
  DOC_DIGEST_PREFIX,
  dOpt(doc.seal_state, (s) => Buffer.concat([
    Buffer.from([s.posture === 'sealed' ? 1 : 0]),
    dBytes(s.state),
  ])),
  Buffer.concat([
    u32(doc.state_log.length),
    ...doc.state_log.map((e) => Buffer.concat([
      Buffer.from(e.prev_hash),
      Buffer.from(e.new_state_hash),
      dBytes(e.operation),
      dU64(e.timestamp),
      dBytes(e.signature),
    ])),
  ]),
  dOpt(doc.pcr_policy, (p) => Buffer.concat([
    dU32s(p.expected),
    dBytes(p.pcr_select),
    // JSON object key order: Rust canonicalizes the BTreeMap by ascending
    // numeric key; sort numerically here to match (a generator with string
    // insertion order would drift).
    Buffer.concat([
      u32(Object.keys(p.values).length),
      ...Object.keys(p.values)
        .map(Number)
        .sort((a, b) => a - b)
        .flatMap((k) => [u32(k), dBytes(p.values[k])]),
    ]),
  ])),
  Buffer.concat([
    u32(doc.units.length),
    ...doc.units.map((u) => Buffer.concat([
      dBytes(Buffer.from(u.name, 'utf8')),
      dBool(u.up),
      dOpt(u.heartbeat, dU64),
    ])),
  ]),
  dOpt(doc.luks, (l) => Buffer.concat([
    dBytes(Buffer.from(l.device, 'utf8')),
    dBool(l.open),
    dU32s(l.pcr_policy),
    dOpt(l.marker_counter, dU64),
  ])),
  Buffer.concat([
    u32(doc.key_acls.length),
    ...doc.key_acls.map((k) => Buffer.concat([
      dU64(k.handle),
      Buffer.concat([
        u32(k.operations.length),
        ...k.operations.map((op) => dBytes(Buffer.from(op, 'utf8'))),
      ]),
      dU32s(k.pcr_policy),
    ])),
  ]),
  dOpt(doc.retry, (r) => Buffer.concat([dU64(r.warden_respawn), dU64(r.watchdog_reboot_guard)])),
]));

// The doc's JSON: the serde shape. A BigInt handle must serialize as a
// BARE NUMBER TOKEN (serde_json writes u64 as a bare integer; a quoted
// string would fail the Rust decode). JSON.stringify has no BigInt
// support, so the token route: quote it through the replacer, then strip
// the quotes. Deterministic; the exact decimal digits of the BigInt are
// what lands in the bytes (no Number ever sees the value).
const jSerde = (o) => Buffer.from(JSON.stringify(o, (k, v) =>
  typeof v === 'bigint' ? `@@bigint-token:${v.toString()}@@` : v
).replace(/"@@bigint-token:(\d+)@@"/g, '$1'));

const wardendDocObj = {
  seal_state: { posture: 'sealed', state: u8arr(st1) },
  state_log: [log0, log1],
  pcr_policy: {
    expected: PCR_INDICES.slice(),
    pcr_select: u8arr(Buffer.concat([u16(0x000b), Buffer.from([0x03]), SEL_BYTES])),
    values: Object.fromEntries(PCR_INDICES.filter((i) => i !== 22).map((i) => [i, u8arr(pcrValues[i])])),
  },
  units: [{ name: 'seald', up: true, heartbeat: TS1 }],
  luks: { device: '/dev/nvme1n1', open: true, pcr_policy: [0, 22], marker_counter: 7 },
  // The D12 real handle (key_acl_handle('bastiond-tls') style: SHA-256-
  // derived u64s routinely exceed 2^53): authored as a BigInt TOKEN so the
  // generator itself never coerces it. In the fixture's doc JSON it is
  // serialized as a bare number (the serde shape), so every consumer that
  // parses the doc with JSON.parse loses the low bits — the >2^53 parity
  // landmine the I-2b browser leg must survive (BigInt/decimal-string
  // token path), witnessed by the fixture digest moving to a value that
  // ONLY the token-safe canonicalization reproduces.
  key_acls: [{ handle: 1653858798848288593n, operations: ['sign', 'unseal'], pcr_policy: [22] }],
  retry: { warden_respawn: 2, watchdog_reboot_guard: 0 },
};
// The canonical wardend doc bytes: what BOTH verifiers decode, what the
// fold measures, what a byte-level tamper must break.
const WARDEND_DOC = jSerde(wardendDocObj);

// I-2: the whole-doc signature. The HSM signs the canonical digest of
// THIS doc (every field; never the signature itself: the signature rides
// the evidence ANCHORS map, so the doc bytes below are byte-pure under
// the digest and the PCR22 fold input is untouched by construction).
// The RFC6979 nonce keeps the fixture byte-stable across regenerations.
const WARDEND_DOC_DIGEST = canonicalDocDigest(wardendDocObj);
const WARDEND_DOC_SIG = signDetPrehashed(HSM.pub, HSM.d, WARDEND_DOC_DIGEST);
// The parity pin. This is the digest of THE FIXTURE's wardend doc (not
// the plugin crate's internal golden-doc vector, which is a different
// document). Two independent witnesses pin this one value: (1) the JS
// mirror here (drift fails at generation time), (2) the Rust plugin
// integration test recomputes canonical_doc_digest over the fixture's
// DECODED doc and asserts this hex (drift fails at cargo test time). The
// JS side computing this hex over the fixture doc bytes and the Rust side
// asserting the same hex IS the cross-implementation parity witness:
// same bytes, two canonicalizations, one vector.
const FIXTURE_DOC_DIGEST_HEX = "c957cec67aebdcd839b66d7a58d462c4513e85a23596d8564f689338651aa62d";
if (hexOf(WARDEND_DOC_DIGEST) !== FIXTURE_DOC_DIGEST_HEX) {
  throw new Error(
    'doc-digest parity FAILED: the JS canonicalDocDigest drifted from the pinned vector\n' +
    '  js:    ' + hexOf(WARDEND_DOC_DIGEST) + '\n  pinned: ' + FIXTURE_DOC_DIGEST_HEX,
  );
}

// PCR22 is the fold of the OTHER channels' docs (evidence order snp,
// wardend): reset to zero, then extended with H(concat).
{
  const hDocs = sha256(Buffer.concat([REPORT, WARDEND_DOC]));
  pcrValues[22] = sha256(Buffer.concat([Buffer.alloc(32), hDocs]));
}

// ---------------------------------------------------------------------------
// The synthetic TPM2 quote doc (wire v1), over THE final PCR values.
// ---------------------------------------------------------------------------
const AK_PUBLIC = Buffer.concat([
  u16(0x0023),                                  // TPM_ALG_ECC
  u16(0x000b),                                  // nameAlg: SHA-256
  Buffer.from([0x00, 0x00, 0x00, 0x64]),        // attributes (sign|fixedTPM|fixedParent; uninterpreted offline)
  u16(0),                                       // authPolicy: empty
  u16(0x0010),                                  // symmetric: TPM_ALG_NULL (2 bytes)
  Buffer.from([0x00, 0x18, 0x00, 0x0b]),        // scheme: ECDSA/SHA-256 (4 bytes)
  u16(0x0003),                                  // curve: P-256
  u16(0x0010),                                  // kdf: TPM_ALG_NULL (2 bytes)
  tpm2b(AK.x), tpm2b(AK.y),
]);
const AK_NAME = Buffer.concat([u16(0x000b), sha256(AK_PUBLIC)]);
const QUALIFIED_NAME = Buffer.concat([u16(0x000b), sha256(Buffer.concat([u32(0x40000001), AK_NAME]))]);
const perPcr = Buffer.concat(PCR_INDICES.map((i) => pcrValues[i]));
const pcrDigest = sha256(perPcr);
const selMarshalled = Buffer.concat([u32(1), u16(0x000b), Buffer.from([0x03]), SEL_BYTES]);
const attestBody = Buffer.concat([
  Buffer.from('ff544347', 'hex'),               // TCG magic
  u16(0x8018),                                  // TPM_ST_ATTEST_QUOTE
  tpm2b(QUALIFIED_NAME),                        // OWNER-qualified Name(AK)
  tpm2b(NONCE),                                 // extraData == THE challenge
  u64(0), u32(0), u32(0), Buffer.from([0]),     // clockInfo (17 bytes)
  u64(0x00010002),                              // firmwareVersion (8 bytes)
  selMarshalled,                                // TPML_PCR_SELECTION
  tpm2b(pcrDigest),
]);
const attestSig = signDet(AK.pub, AK.d, attestBody);
const TPM_DOC = Buffer.concat([
  Buffer.from([1]),                             // wire v1
  tpm2b(attestBody), tpm2b(AK_PUBLIC),
  tpm2b(attestSig.subarray(0, 32)), tpm2b(attestSig.subarray(32, 64)),
  tpm2b(perPcr),
]);

// The state-bound sign key: authPolicy = the TCG PolicyPCR formula over THE
// same selection + per-PCR digests (zero-seeded digest: the ref-model
// dialect, byte-identical to Rust policy_pcr_auth_policy).
const signPolicy = sha256(Buffer.concat([
  Buffer.alloc(32), u32(0x017f), selMarshalled, pcrDigest,
]));
const signPublic = Buffer.concat([
  u16(0x0023), u16(0x000b),
  Buffer.from([0x00, 0x00, 0x00, 0x44]),
  tpm2b(signPolicy),
  u16(0x0010),
  Buffer.from([0x00, 0x18, 0x00, 0x0b]),
  u16(0x0003), u16(0x0010),
  tpm2b(SIGN.x), tpm2b(SIGN.y),
]);

// ---------------------------------------------------------------------------
// The bundle + envelope (the frozen wire contract; B64 = standard base64).
// ---------------------------------------------------------------------------
const pemDer = (pem) => Buffer.from(pem.toString().replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''), 'base64');
const VLEK_DER = pemDer(fs.readFileSync(path.join(DATA, 'snp-vlek-live-v0.pem')));
const ASVK_DER = pemDer(fs.readFileSync(path.join(DATA, 'asvk-sev-vlek-milan.pem')));
const ARK_DER = pemDer(fs.readFileSync(path.join(DATA, 'ark-milan.pem')));
const EK_BLOB = Buffer.from('bootproof golden fixture EK-cert blob (presence only: neither verifier checks the NitroTPM EK chain in this build; the shared verdict is DEGRADED)');

const bundle = {
  v: 1,
  nonce: b64(NONCE),
  node: { id: 'i-0golden0000000000', platform: 'aws-snp' },
  evidence: [
    { channel: 'snp', doc: b64(REPORT), anchors: { vlek: b64(VLEK_DER), asvk: b64(ASVK_DER), ark: b64(ARK_DER) } },
    { channel: 'tpm2', doc: b64(TPM_DOC), anchors: { ek_cert: b64(EK_BLOB) } },
    { channel: 'wardend', doc: b64(WARDEND_DOC), anchors: { hsm_public: b64(HSM.point), doc_signature: b64(WARDEND_DOC_SIG) } },
  ],
  keys: { sign: { pub_: b64(signPublic), curve: 'P-256', scheme: 'ecdsa-sha256', pcr_policy: Array.from(PCR_INDICES) } },
};
const HSM_PIN = hexOf(sha256(Buffer.concat([P256_SPKI_PREFIX, HSM.point])));

const envelope = {
  bundle,
  // The server's self-report is NOT part of the agreement (the test
  // re-derives the engine facts live); the empty array is the envelope
  // schema's shape for "published, and re-checkable".
  facts: [],
  nonce: hexOf(NONCE),
  // Both identity keys, explicit, in schema declaration order (declaration
  // order IS the contract): the golden publishes no TLS leaf PEM (see
  // metadata.cert_chain.leaf_pem: null), so the honest claim is false.
  // The typed-schema gate in the agreement tests decodes every fixture
  // through system_health::schema::Envelope: the fixture must stay an
  // explicit typed-valid instance, never a lenient-parse survivor.
  identity: { attest_signer_spki_sha256: HSM_PIN, leaf_pem_present: false },
  metadata: {
    instance_id: 'i-0golden0000000000',
    user_data: 'bootproof golden fixture user-data (no wardend-commit line)',
    stagex_commit: null,
    instance_identity: null,
    disk_encryption: null,
    units: [{ name: 'seald', state: 'active', health: 'healthy', detail: null }],
    hsm_keys: [{ name: 'state-signer', pcr_gated: true, pcrs: [22], sealed: true, key_id: 'persist', key_type: null }],
    seal_state: { posture: 'sealed', state_hash: hexOf(st1), state_log: 2, pcrs: [0, 22] },
    cert_chain: { tls_verified: false, leaf_pem: null, leaf: null, chain: [], spki_anchors: [] },
    endorsement: {
      aws: { present: true, detail: 'tpm2 channel present (1 quote); the EK-cert chain is not verified in either verifier' },
      amd: { present: true, detail: "snp channel present (1 report); VLEK bundled, ASVK/ARK anchors bundled; verification is the client's job" },
    },
    spdx_inventory: null,
  },
};

// ---------------------------------------------------------------------------
// The tamper fixtures (single byte flips: honest-rejection cases).
// ---------------------------------------------------------------------------
const clone = (o) => JSON.parse(JSON.stringify(o));

const tSnap = clone(envelope);   // snp-tamper: flip one report_data byte.
{
  const doc = Buffer.from(tSnap.bundle.evidence[0].doc, 'base64');
  doc[0x50] ^= 0x01;             // the nonce echo: binding + signature die
  tSnap.bundle.evidence[0].doc = doc.toString('base64');
}

const tChip = clone(envelope);   // chip-tamper (AMI-2): flip one CHIP_ID byte.
{
  const doc = Buffer.from(tChip.bundle.evidence[0].doc, 'base64');
  doc[0x1a0] ^= 0x01;            // inside the signed prefix, OUTSIDE
                                 // report_data: the signature dies alone
  tChip.bundle.evidence[0].doc = doc.toString('base64');
}

const tLog = clone(envelope);    // log-tamper: flip a byte in entry 1's op.
{
  const docStr = Buffer.from(tLog.bundle.evidence[2].doc, 'base64').toString();
  const flipped = docStr.replace('"operation":[115,101,97,108]', '"operation":[115,101,97,109]'); // "seal" -> "seam"
  if (flipped === docStr) throw new Error('log-tamper: the seal operation bytes were not found');
  tLog.bundle.evidence[2].doc = Buffer.from(flipped).toString('base64');
}

const tNoSnp = clone(envelope);  // missing-snp: the channel dropped.
tNoSnp.bundle.evidence = tNoSnp.bundle.evidence.filter((e) => e.channel !== 'snp');

const tNoSig = clone(envelope);  // unsigned-doc: the doc signature dropped
{
  // from the wardend anchors (the doc bytes are the golden's: this is
  // exactly the pre-I-2 shape — a valid doc with no byte-attestation —
  // and the Rust verifier must reject it fail-closed).
  const ev = tNoSig.bundle.evidence.find((e) => e.channel === 'wardend');
  delete ev.anchors.doc_signature;
}

// ---------------------------------------------------------------------------
// Write.
// ---------------------------------------------------------------------------
const write = (name, obj) => fs.writeFileSync(path.join(OUT, name), JSON.stringify(obj, null, 1) + '\n');
write('golden.json', envelope);
write('golden.snp-tamper.json', tSnap);
write('golden.chip-tamper.json', tChip);
write('golden.log-tamper.json', tLog);
write('golden.missing-snp.json', tNoSnp);
write('golden.unsigned-doc.json', tNoSig);
write('golden.meta.json', {
  // The harness + tests read the frozen nonce from here. The expected
  // VERDICTS deliberately do NOT live here: they are hardcoded in the
  // Rust agreement tests (crates/bootproof/tests/system_health_agreement
  // .rs + the wardend plugin's), so regenerating this generator can
  // never quietly move the goalposts: a verdict change is a test edit.
  nonce_hex: hexOf(NONCE),
  hsm_spki_pin: HSM_PIN,
  // I-2: the fixture's wardend doc canonical digest (the JS mirror of
  // the Rust canonical_doc_digest, pinned twice: here at generation, and
  // in the plugin's fixture agreement test against the Rust computation
  // over the decoded fixture doc — the cross-implementation parity pin).
  wardend_doc_digest_hex: hexOf(WARDEND_DOC_DIGEST),
});
console.log('golden fixtures written to', OUT);
console.log('nonce:', hexOf(NONCE));
console.log('hsm pin:', HSM_PIN);
console.log('doc digest:', hexOf(WARDEND_DOC_DIGEST));
console.log('doc sig:', hexOf(WARDEND_DOC_SIG));
