// =============================================================================
// bootproof System Health: the browser-side remote-attestation verifier.
//
// This file IS the verifier. It runs as a service worker (scope '/'), is
// baked into the bastiond binary at compile time via include_str! (its
// SHA-256 is bootproof::system_health::SW_SHA256 and the page prints it),
// and re-verifies the server on EVERY navigation. There are no
// dependencies: WebCrypto + fetch + the DOM, nothing else. No minification,
// ever: a human must be able to read all of it in one sitting.
//
// It is the browser twin of bootproof::engine::verify_bundle (Rust). The
// contract (docs/system-health.md v4): one bundle, two verifiers, one
// verdict. Every check below has a named Rust counterpart, cited in
// comments. A bootproof test feeds one golden fixture through both and
// asserts identical verdicts, so drift fails CI instead of shipping.
//
// Trust comes from exactly three things:
//   1. WebCrypto (the platform's crypto, not ours).
//   2. The baked SPKI pins below (a compromised server cannot swap them:
//      they live inside these bytes, and these bytes are hash-pinned in
//      the binary that serves them).
//   3. The fresh nonce you generated moments ago in step 1 of
//      runVerification (nothing older than this page view can be replayed
//      at you).
//
// Failure mode philosophy: honest NOT PROVEN, never a fabricated green,
// never a hang. Every source that can be absent IS handled as absent.
// =============================================================================

// === baked trust anchors (SPKI-SHA256 hex) ===
// These MUST equal the Rust trust anchors in bootproof::snp. The drift-killer
// test in crates/bootproof/src/system_health.rs recompiles the pins from
// AMD_ARK_MILAN_PEM / AMD_ASVK_MILAN_PEM and asserts they equal the two strings
// below, so a change to either side fails the build. The browser verifies the
// SNP report's VLEK against ARK (and the KDS ASVK) using THESE pins, baked in
// at compile time so they cannot be swapped by a compromised server.
const ARK_MILAN_SPKI_SHA256 = "9f056bee44377e29308cb5ffa895bdfb62d18881fa6bed8d6f075b0204089cb9";
const ASVK_MILAN_SPKI_SHA256 = "66450a123ea5876206df67f2514a4fea224c0f63b18313423078b0edc4535e33";

// The Let's Encrypt / ISRG root keys (SPKI-SHA256). The TLS identity link
// check accepts a chain only when one of its certificates' SPKI pins one of
// these. These are the SAME fingerprints the server renders in
// metadata.cert_chain.spki_anchors (wardend's attest_envelope::match_anchor
// and bastion::chain::TRUST_ANCHORS carry identical constants; the browser
// re-derives them from the served PEM bytes and compares HERE, so a server
// that lies about its anchor list is caught by this equality instead).
const ISRG_ROOT_X1_SPKI_SHA256 = "0b9fa5a59eed715c26c1020c711b4f6ec42d58b0015e14337a39dad301c5afc3";
const ISRG_ROOT_X2_SPKI_SHA256 = "762195c225586ee6c0237456e2107dc54f1efc21f61a792ebd515913cce68332";
const TLS_ANCHORS = [ISRG_ROOT_X1_SPKI_SHA256, ISRG_ROOT_X2_SPKI_SHA256];

// The re-verify cadence. The SW never stops verifying while the tab lives.
const REFRESH_MS = 20000;

// DER object-identifier bodies (the value bytes after tag 0x06).
const OID = {
  EC_PUBLIC_KEY: "2a8648ce3d0201",           // 1.2.840.10045.2.1
  CURVE_P256:    "2a8648ce3d030107",         // 1.2.840.10045.3.1.7
  CURVE_P384:    "2b81040022",               // 1.3.132.0.34
  ECDSA_SHA256:  "2a8648ce3d040302",         // 1.2.840.10045.4.3.2
  ECDSA_SHA384:  "2a8648ce3d040303",         // 1.2.840.10045.4.3.3
  RSA_ENCRYPTION:"2a864886f70d010101",       // 1.2.840.113549.1.1.1 (ARK/ASVK)
  RSA_PSS:       "2a864886f70d01010a",       // 1.2.840.113549.1.1.10
  SAN:           "551d11",                   // 2.5.29.17 subjectAltName
};

// The SEV-SNP report field offsets (AMD SNP ABI, rev 5 report; the same
// layout bootproof::snp::decode_report walks via the `sev` crate, and
// verify/snp.rs requires: doc.len() == 1184, version == 5).
const SNP = {
  LEN: 1184,
  VERSION: 0x00,        // u32 LE, must be 5
  POLICY: 0x08,         // u64 LE (bit19 debug, bit25 page-swap-disable)
  VMPL: 0x30,           // u32 LE, must be 0
  SIG_ALGO: 0x34,       // u32 LE, 1 == ECDSA P-384 / SHA-384
  REPORT_DATA: 0x50,    // 64 bytes: front 32 echo the challenge nonce
  SIG: 0x2a0,           // the signature field: 144 bytes, r LE (72) || s LE
                        // (72), 48 significant bytes each, then 368 reserved
                        // zero bytes to the end of the 1184-byte report.
  MEASURABLE: 0x2a0,    // the firmware signs bytes [0, 0x2a0) with the VLEK
};
const SNP_POLICY_DEBUG_BIT = 19;        // must be 0 (policy & 0x80000 == 0)
const SNP_POLICY_PAGESWAP_BIT = 25;     // must be 1 (bit 25 set)

// The TPM2 evidence doc layout (wire v1), exactly as verify/tpm2.rs reads
// it: [u8 version==1] [u16 len] TPMS_ATTEST [u16 len] TPMT_PUBLIC(AK)
// [u16 len] sig.r [u16 len] sig.s [u16 len] per-PCR digests. Every length
// is a TPM2B (u16 big-endian). All TPM numbers in the structures are
// big-endian.
const TPM = {
  ATTEST_MAGIC: 0xff544347,  // "TCG"
  ATTEST_QUOTE: 0x8018,
  ALG_SHA256: 0x000b,
  ALG_ECC: 0x0023,
  ALG_EC_P256: 0x0003,
  ALG_NULL: 0x0010,
  OWNER_HIERARCHY: 0x40000001,  // the AK's parent (primary in OWNER)
  SLOT_PCR: 22,
};

// Status vocabulary, mirroring bootproof::wire::Status plus the browser
// only FAILED level the contract's render step requires ("PROVEN /
// NOT PROVEN / FAILED with the failing reason").
const PROVEN = "PROVEN";
const NOT_PROVEN = "NOT PROVEN";
const FAILED = "FAILED";
const SERVER_ASSERTED = "SERVER-ASSERTED"; // the server published it, the
                                           // browser cannot check it alone

// -----------------------------------------------------------------------------
// Byte + text helpers (no dependencies)
// -----------------------------------------------------------------------------

function bufToHex(buf) {
  const b = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, "0");
  return s;
}

function hexToBuf(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function b64ToBuf(s) {
  const BIN = atob(String(s).replace(/\s+/g, ""));
  const out = new Uint8Array(BIN.length);
  for (let i = 0; i < BIN.length; i++) out[i] = BIN.charCodeAt(i);
  return out;
}

// The base64 alphabet is only needed for the reverse direction; see
// wireBytes/b64ToBuf. Nothing here encodes: the verifier only reads.

// PEM -> DER: take the base64 body between the -----BEGIN/END CERTIFICATE-----
// armor lines and decode. The server's builder does the identical walk
// (attest_envelope::pem_to_der_chain); a malformed block is skipped, never a
// throw, so a truncated file degrades to "no certs" -> NOT PROVEN.
function pemToDer(pem) {
  const out = [];
  const BEGIN = "-----BEGIN CERTIFICATE-----";
  const END = "-----END CERTIFICATE-----";
  let rest = String(pem || "");
  for (;;) {
    const start = rest.indexOf(BEGIN);
    if (start < 0) break;
    const after = rest.slice(start + BEGIN.length);
    const end = after.indexOf(END);
    if (end < 0) break;
    const body = after.slice(0, end).replace(/[^A-Za-z0-9+/=]/g, "");
    rest = after.slice(end + END.length);
    try {
      const der = b64ToBuf(body);
      if (der.length > 0) out.push(der);
    } catch (e) { /* malformed block: skip (fail closed to fewer certs) */ }
  }
  return out;
}

function sha256Hex(buf) {
  return crypto.subtle.digest("SHA-256", buf).then(bufToHex);
}

// Little-endian u32/u64 (as LE pair, value stays < 2^53 for real policies).
function leU32(b, o) { return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] * 16777216); }
function leU64Lo(b, o) { return b[o] + b[o+1]*256 + b[o+2]*65536 + b[o+3]*16777216; }
function leU64Hi(b, o) { return b[o+4] + b[o+5]*256 + b[o+6]*65536 + b[o+7]*16777216; }
function beU16(b, o) { return (b[o] << 8) | b[o+1]; }
function beU32(b, o) { return ((b[o] << 24) | (b[o+1] << 16) | (b[o+2] << 8) | b[o+3]) >>> 0; }

// -----------------------------------------------------------------------------
// DER: the minimal, bounded TLV walk (mirrors bootproof::spki exactly: the
// outer SEQUENCE -> tbsCertificate SEQUENCE -> optional [0] version -> serial
// -> sigalg -> issuer -> validity -> subject -> SPKI SEQUENCE, returning the
// SPKI's RAW bytes so SHA-256(SPKI) is the same pin spki_pin computes).
// -----------------------------------------------------------------------------

// Read one TLV at `off`: returns {tag, content, start, end} or null. `start`
// is the tag position, so the element's RAW bytes are buf.subarray(start,
// end) - that is what a SPKI pin hashes (tag + length + content), matching
// bootproof::spki::spki_der exactly.
function derTlv(buf, off) {
  if (off == null || off < 0 || buf.length < off + 2) return null;
  const tag = buf[off];
  const first = buf[off + 1];
  let len, body;
  if (first < 0x80) { len = first; body = off + 2; }
  else if (first === 0x81) {
    if (buf.length < off + 3) return null;
    len = buf[off + 2]; body = off + 3;
  } else if (first === 0x82) {
    if (buf.length < off + 4) return null;
    len = (buf[off + 2] << 8) | buf[off + 3]; body = off + 4;
  } else {
    return null; // long forms > 64 KiB or indeterminate: refuse
  }
  const end = body + len;
  if (len < 0 || end > buf.length || end <= body) return null;
  return { tag: tag, content: buf.subarray(body, end), raw: buf.subarray(off, end), start: off, end: end };
}

// The certificate's elements, RAW, via the spki_der walk: outer SEQUENCE ->
// tbsCertificate SEQUENCE -> optional [0] version -> serial -> sigalg ->
// issuer -> validity -> subject -> SPKI, then (in the OUTER sequence) the
// signatureAlgorithm + the signatureValue BIT STRING.
function derCertsParts(der) {
  const outer = derTlv(der, 0);
  if (!outer || outer.tag !== 0x30) return null;
  const tbs = derTlv(outer.content, 0);            // the signed bytes
  if (!tbs || tbs.tag !== 0x30) return null;
  let off = 0;
  const first = derTlv(tbs.content, off);
  if (!first) return null;
  if (first.tag === 0xa0) off = first.end;         // [0] EXPLICIT version
  const order = ["serial", "sigalg", "issuer", "validity", "subject"];
  const els = {};
  for (const k of order) {
    const e = derTlv(tbs.content, off);
    if (!e) return null;
    els[k] = e;
    off = e.end;
  }
  const spki = derTlv(tbs.content, off);
  if (!spki || spki.tag !== 0x30) return null;
  // The outer sequence's tail: signatureAlgorithm then signatureValue.
  const outerSigAlg = derTlv(outer.content, tbs.end);
  if (!outerSigAlg || outerSigAlg.tag !== 0x30) return null;
  const outerSigVal = derTlv(outer.content, outerSigAlg.end);
  if (!outerSigVal || outerSigVal.tag !== 0x03 || outerSigVal.content.length === 0) return null;
  return {
    tbs: tbs.content,          // what the ISSUER of this cert signed
    spki: spki.raw,            // tag+len+content: the SPKI PIN input
    spkiInner: spki.content,
    afterSpki: tbs.content.subarray(spki.end), // extensions live here
    sigalg: els.sigalg.content,
    issuer: els.issuer.content,
    subject: els.subject.content,
    validity: els.validity.content,
    outerSigAlg: outerSigAlg.content,
    outerSigBits: outerSigVal.content.subarray(1),  // drop the unused-bits byte
  };
}

// The OID hex at the start of a TLV content, or "".
function derOid(content) {
  const t = derTlv(content, 0);
  return t && t.tag === 0x06 ? bufToHex(t.content) : "";
}

// Time: UTCTime / GeneralizedTime -> ms epoch (compare against Date.now()).
function derTime(tlv) {
  let s = "";
  for (let i = 0; i < tlv.content.length; i++) s += String.fromCharCode(tlv.content[i]);
  let y, mo, d, h, mi, se;
  if (tlv.tag === 0x17) {                       // UTCTime YYMMDDHHMMZ
    if (tlv.content.length !== 13 || tlv.content[12] !== 0x5a) return null;
    y = parseInt(s.slice(0, 2), 10);
    y = y >= 50 ? 1900 + y : 2000 + y;
    mo = +s.slice(2, 4); d = +s.slice(4, 6); h = +s.slice(6, 8);
    mi = +s.slice(8, 10); se = +s.slice(10, 12);
  } else if (tlv.tag === 0x18) {                // GeneralizedTime YYYY..Z
    if (tlv.content.length !== 15 || tlv.content[14] !== 0x5a) return null;
    y = +s.slice(0, 4); mo = +s.slice(4, 6); d = +s.slice(6, 8);
    h = +s.slice(8, 10); mi = +s.slice(10, 12); se = +s.slice(12, 14);
  } else return null;
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || se > 60) return null;
  return Date.UTC(y, mo - 1, d, h, mi, se);
}

// The validity window from the tbs, as ms epochs (compare Date.now()).
// NOTE: derCertsParts hands us the validity element's CONTENT: the inner
// SEQUENCE has already been unwrapped, so the two time TLVs sit at the top
// level here. Do not expect another 0x30 wrapper.
function certValidity(validityContent) {
  const nbEl = derTlv(validityContent, 0);
  if (!nbEl) return null;
  const naEl = derTlv(validityContent, nbEl.end);
  if (!naEl) return null;
  const nb = derTime(nbEl), na = derTime(naEl);
  if (nb == null || na == null) return null;
  return { notBefore: nb, notAfter: na };
}

// The dNSName list from the [3] EXPLICIT extensions' subjectAltName, walking
// whatever optional elements sit between the SPKI and the extensions.
function certDnsNames(afterSpki) {
  let off = 0;
  for (;;) {
    const e = derTlv(afterSpki, off);
    if (!e) return [];                        // no [3]: no SANs (honest)
    off = e.end;
    if (e.tag !== 0xa3) continue;
    const exts = derTlv(e.content, 0);
    if (!exts || exts.tag !== 0x30) return [];
    const names = [];
    let eo = 0;
    for (;;) {
      const ext = derTlv(exts.content, eo);
      if (!ext) return names;
      eo = ext.end;
      if (derOid(ext.content) !== OID.SAN) continue;
      // Extension ::= SEQUENCE { OID, critical BOOLEAN DEFAULT FALSE,
      //                          value OCTET STRING } - step over the OID
      // first; the bool is OPTIONAL (a non-critical SAN has none, and real
      // ACME leaves publish SAN non-critical), then the value must be 0x04.
      let p = 0;
      let t = derTlv(ext.content, p);
      if (t && t.tag === 0x06) { p = t.end; t = derTlv(ext.content, p); }  // oid
      if (t && t.tag === 0x01) { p = t.end; t = derTlv(ext.content, p); }  // critical bool
      if (!t || t.tag !== 0x04) continue;
      // The OCTET STRING's content is a SEQUENCE of GeneralName; unwrap it
      // before walking, or every dNSName hides one level deeper than we look.
      const seq = derTlv(t.content, 0);
      if (!seq || seq.tag !== 0x30) continue;
      let q = 0;
      for (;;) {
        const g = derTlv(seq.content, q);
        if (!g) break;
        q = g.end;
        if (g.tag === 0x82) {                 // dNSName (IA5String)
          let s = "";
          for (let i = 0; i < g.content.length; i++) s += String.fromCharCode(g.content[i]);
          names.push(s.toLowerCase());
        }
      }
    }
  }
}

// The extensions' signatureAlgorithm OID (the TBS's claim) and the outer
// one: a certificate's issuer signs the TBS with the ALGORITHM THE CERT
// DECLARES, so the TBS's sigalg is what selects the verify path (and the
// two MUST agree: a mismatch is a DER self-contradiction, rejected).

// Build the P-256 SPKI DER for a 65-byte uncompressed point. This is byte-
// for-byte attest_envelope::spki_der_from_point, so
// SHA-256(this) == identity.attest_signer_spki_sha256 by construction.
function spkiFromPoint(point) {
  if (!point || point.length !== 65 || point[0] !== 0x04) return null;
  const oidEc = hexToBuf(OID.EC_PUBLIC_KEY);
  const oidC = hexToBuf(OID.CURVE_P256);
  const algInner = concat(derWrap(0x06, oidEc), derWrap(0x06, oidC));
  const alg = derWrap(0x30, algInner);
  const bits = new Uint8Array(point.length + 1);
  bits[0] = 0x00;
  bits.set(point, 1);
  return derWrap(0x30, concat(alg, derWrap(0x03, bits)));
}

function derLenBytes(len) {
  return len < 0x80 ? new Uint8Array([len]) : new Uint8Array([0x81, len]);
}
function derWrap(tag, content) {
  const l = derLenBytes(content.length);
  const out = new Uint8Array(1 + l.length + content.length);
  out[0] = tag;
  out.set(l, 1);
  out.set(content, 1 + l.length);
  return out;
}
function concat() {
  let n = 0;
  for (const a of arguments) n += a.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const a of arguments) { out.set(a, o); o += a.length; }
  return out;
}

// The EC PUBLIC key for WebCrypto from raw coordinates: hand-built SPKI
// DER -> importKey('spki'). WebCrypto only imports structured keys, so the
// structure IS the auditable part.
function importEcKey(pubDer, namedCurve, hashName) {
  return crypto.subtle.importKey(
    "spki", pubDer, { name: "ECDSA", namedCurve: namedCurve }, false,
    hashName ? ["verify"] : ["verify", "sign"]);
}
function ecSpkiDer(curve, x, y) {
  const oidEc = hexToBuf(OID.EC_PUBLIC_KEY);
  const oidC = hexToBuf(curve === "P-384" ? OID.CURVE_P384 : OID.CURVE_P256);
  const alg = derWrap(0x30, concat(derWrap(0x06, oidEc), derWrap(0x06, oidC)));
  // The BIT STRING content: the unused-bits byte (0x00) then the point
  // (0x04 || x || y). Getting this one byte wrong is the classic hand-
  // rolled-SPKI bug: WebCrypto rejects the key, which the verifier would
  // report as a failed signature. spkiFromPoint follows the same layout.
  const bits = new Uint8Array(x.length + y.length + 2);
  bits[0] = 0x00;
  bits[1] = 0x04;
  bits.set(x, 2);
  bits.set(y, 2 + x.length);
  return derWrap(0x30, concat(alg, derWrap(0x03, bits)));
}
async function verifyEcdsa(curve, hashAlg, pubDer, sig, msg) {
  if (!pubDer || !sig || sig.length !== (curve === "P-384" ? 96 : 64)) return false;
  let key;
  try { key = await importEcKey(pubDer, curve, hashAlg); } catch (e) { return false; }
  try {
    return await crypto.subtle.verify(
      { name: "ECDSA", hash: { name: hashAlg } }, key, sig, msg);
  } catch (e) { return false; }
}
// WHY hash-mode WebCrypto IS the prehashed path the Rust verifier uses.
// WebCrypto's ECDSA verify computes H(message) and then checks the
// signature against that digest. The Rust side checks the signature
// against a digest it computed itself (ecdsa::hazmat::verify_prehashed):
//   * the SNP report: sev verifies prehashed SHA-384(report[0:0x2a0]); the
//     browser hands WebCrypto those exact bytes with hash SHA-384.
//   * the wardend state log: the wardend hash policy IS
//     SHA-256(prev_hash || new_state_hash || operation || timestamp_be),
//     i.e. the Rust prehash is SHA-256 of exactly the bytes the browser
//     concatenates here, so hash-mode over those bytes is the SAME check.
// A signature one verifier accepts is therefore accepted by the other -
// the contract's "identical verdicts" requirement, by construction rather
// than by convention.

// -----------------------------------------------------------------------------
// X.509: the TLS identity link (contract step 3). Rust side:
// bootproof::spki::spki_pin + wardenctl's identity-link check.
// -----------------------------------------------------------------------------

async function decodeCert(der) {
  const parts = derCertsParts(der);
  if (!parts) return null;
  const c = {};
  c.der = der;
  c.tbs = parts.tbs;               // the bytes an issuer signs
  c.spkiDer = parts.spki;          // the bytes this cert's key pins
  c.spkiPin = await sha256Hex(parts.spki);
  c.fingerprint = await sha256Hex(der);
  // issuer/subject DER compared byte-for-byte for the self-signed test,
  // same as the Rust builder's issuer_raw == subject_raw.
  c.selfSigned = bufToHex(parts.issuer) === bufToHex(parts.subject);
  c.sigOid = derOid(parts.sigalg);      // the TBS's declared signature alg
  c.outerSigOid = derOid(parts.outerSigAlg);
  c.sigBits = parts.outerSigBits;       // the certificate's own signature
  const v = certValidity(parts.validity);
  if (v) { c.notBefore = v.notBefore; c.notAfter = v.notAfter; }
  c.dnsNames = certDnsNames(parts.afterSpki);
  return c;
}

// The identity-link verdict: the leaf's SPKI pin MUST equal the signer pin
// the server published, the chain must terminate at a baked ISRG anchor by
// SPKI, the leaf must cover the host we are reading, and be currently
// valid. Proves: the key terminating this TLS session is the key the
// attestation binds (LE issued the cert for that key after domain-control
// validation).
async function checkIdentity(env, host) {
  const published = env.identity && env.identity.attest_signer_spki_sha256;
  const pem = env.metadata && env.metadata.cert_chain && env.metadata.cert_chain.leaf_pem;
  const why = [];
  const subs = [];
  if (!pem || !published) {
    why.push(pem ? "identity.attest_signer_spki_sha256 is null (no HSM key published)"
                 : "no leaf PEM in metadata.cert_chain (ACME not issued / not published)");
    return { status: NOT_PROVEN, why: why.join("; "), subs: subs };
  }
  const ders = pemToDer(pem);
  if (ders.length === 0) return { status: FAILED, why: "leaf_pem holds no parsable certificate", subs: subs };
  const certs = [];
  for (const d of ders) { const c = await decodeCert(d); if (c) certs.push(c); }
  if (certs.length === 0) return { status: FAILED, why: "certificate DER walk failed", subs: subs };
  const leaf = certs[0];
  // (a) THE LINK: leaf SPKI == the bundle signer's SPKI.
  const linkOk = leaf.spkiPin === String(published).toLowerCase();
  subs.push({ name: "identity_link.pin", status: linkOk ? PROVEN : FAILED,
    why: "leaf SPKI-SHA256 " + leaf.spkiPin.slice(0, 16) + "… " +
         (linkOk ? "==" : "!=") + " identity.attest_signer_spki_sha256 " +
         String(published).slice(0, 16) + "…" });
  // (b) anchor: some certificate in the served chain pins a baked ISRG root.
  let anchored = null;
  for (const c of certs) {
    for (const a of TLS_ANCHORS) {
      if (c.spkiPin === a) anchored = a === ISRG_ROOT_X1_SPKI_SHA256 ? "ISRG Root X1" : "ISRG Root X2";
    }
  }
  subs.push({ name: "identity_link.anchor",
    status: anchored ? PROVEN : FAILED,
    why: anchored ? "chain terminates at baked " + anchored
                  : "no certificate in the served chain matches a baked ISRG SPKI anchor" });
  // (c) validity window vs this browser's clock (honest: browser time).
  const now = Date.now();
  const validOk = leaf.notBefore != null && now >= leaf.notBefore && now <= leaf.notAfter;
  subs.push({ name: "identity_link.validity", status: validOk ? PROVEN : FAILED,
    why: validOk ? "within the leaf validity window" : "outside the leaf validity window (browser clock)" });
  // (d) SAN covers the host you are reading (wildcard prefix match).
  const h = String(host || "").toLowerCase();
  const sanOk = leaf.dnsNames.some(function (n) {
    if (n.startsWith("*.")) return h.endsWith(n.slice(1)) && h.split(".").length === n.split(".").length;
    return n === h;
  });
  subs.push({ name: "identity_link.san", status: sanOk ? PROVEN : FAILED,
    why: sanOk ? "leaf covers " + h : "leaf SANs [" + leaf.dnsNames.join(" ") + "] do not cover " + h });
  const ok = linkOk && anchored && validOk && sanOk;
  if (!ok && linkOk) why.push("link proven but chain/validity/SAN failed");
  if (!linkOk) why.push("TLS key != attestation signer key: a different server or a stripped re-issue");
  return { status: ok ? PROVEN : FAILED, why: why.length ? why.join("; ") : "leaf key == signer key, ISRG-anchored, valid, covers host", subs: subs, certs: certs };
}

// -----------------------------------------------------------------------------
// SEV-SNP: the report + the VLEK chain (contract step 4). Rust side:
// verify/snp.rs (SnpVerifier) + snp.rs::check against the pinned roots.
// -----------------------------------------------------------------------------

function snpParse(doc) {
  if (!doc || doc.length !== SNP.LEN) return null;
  return {
    doc: doc,
    version: leU32(doc, SNP.VERSION),
    policyLo: leU64Lo(doc, SNP.POLICY),
    policyHi: leU64Hi(doc, SNP.POLICY),
    vmpl: leU32(doc, SNP.VMPL),
    sigAlgo: leU32(doc, SNP.SIG_ALGO),
    reportData: doc.subarray(SNP.REPORT_DATA, SNP.REPORT_DATA + 64),
    // r/s: 72-byte little-endian fields, 48 significant bytes each.
    sig: doc.subarray(SNP.SIG, SNP.SIG + 144),
  };
}
function leToBe(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
  return out;
}
// The report signature (P-384/SHA-384 over the first 0x2a0 bytes), the
// crypto_nossl-equivalent walk: r/s LE -> BE, then plain ECDSA verify.
async function snpReportSigOk(r, vlekPubSpki) {
  if (r.sigAlgo !== 1) return false;
  const rr = leToBe(r.sig.subarray(0, 48));
  const ss = leToBe(r.sig.subarray(72, 120));
  return verifyEcdsa("P-384", "SHA-384", vlekPubSpki, concat(rr, ss),
                     r.doc.subarray(0, SNP.MEASURABLE));
}
// The cert edges: signer's public key signs signee's TBS. ECDSA edges are
// checked with WebCrypto; RSA-PSS edges (ARK/ASVK are 4096-bit RSA-PSS/
// SHA-384, and WebCrypto has no RSA-PSS) are checked by SPKI PIN EQUALITY
// against the baked constants, which is the strictly stronger anchor for
// those two specific keys: the pinned key is trusted by pin, so its
// signature under it is redundant, exactly the argument the Rust side's
// "pinned roots" argument makes in snp.rs::check.
async function certEdgeOk(signerCert, signeeCert) {
  const alg = signeeCert.sigOid;
  if (alg !== signeeCert.outerSigOid) return false;   // DER self-contradiction
  if (alg === OID.ECDSA_SHA384 || alg === OID.ECDSA_SHA256) {
    const curve = alg === OID.ECDSA_SHA384 ? "P-384" : "P-256";
    const hash = alg === OID.ECDSA_SHA384 ? "SHA-384" : "SHA-256";
    return verifyEcdsa(curve, hash, signerCert.spkiDer, signeeCert.sigBits, signeeCert.tbs);
  }
  return null; // not an ECDSA edge: the pin-equality path decides
}

async function checkSnp(ev, nonceHex) {
  const subs = [];
  if (!ev) {
    return finishFact("memory_encryption",
      [sub("snp.evidence", NOT_PROVEN, "no snp evidence in the bundle (non-SNP host, or /dev/sev-guest was absent at produce time)")], "");
  }
  const r = snpParse(ev.doc);
  if (!r) {
    return finishFact("memory_encryption",
      [sub("snp.evidence", FAILED, "snp doc is " + (ev.doc ? ev.doc.length : 0) + " bytes, expected the full 1184-byte v5 report")], "");
  }
  if (r.version !== 5) {
    return finishFact("memory_encryption", [sub("snp.evidence", FAILED, "snp report version " + r.version + ", expected 5")], "");
  }
  // 1. Nonce binding: report_data[0..32] echoes OUR fresh nonce.
  const nonceOk = bufToHex(r.reportData.subarray(0, 32)) === nonceHex;
  const zerosOk = r.reportData.subarray(32).every(function (b) { return b === 0; });
  subs.push(sub("snp.nonce_binding", nonceOk ? PROVEN : FAILED,
    nonceOk ? ("report_data binds this page's nonce" + (zerosOk ? " (+zero tail)" : " (nonzero tail: cross-channel data)"))
            : "report_data does NOT echo the fresh nonce: replay or a bundle for another challenge"));
  // 2. VMPL 0 (the hypervisor cannot observe or control the guest).
  const vmplOk = r.vmpl === 0;
  subs.push(sub("snp.vmpl_zero", vmplOk ? PROVEN : FAILED, vmplOk ? "VMPL 0" : "VMPL " + r.vmpl));
  // 3. Policy: debug bit clear + page-swap bit set (the Rust gate).
  const debugClear = (r.policyLo & 0x80000) === 0;
  const pswSet = (r.policyLo & 0x2000000) !== 0;
  const policyStr = "0x" + ((r.policyHi * 4294967296) + r.policyLo).toString(16);
  subs.push(sub("snp.policy", debugClear && pswSet ? PROVEN : FAILED,
    "policy " + policyStr + (debugClear ? "" : " ALLOWS DEBUG") + (pswSet ? "" : " page-swap NOT disabled")));
  // 4. The VLEK: present, EC P-384, and its issuer pins the baked ASVK.
  const vlekDer = ev.anchors && ev.anchors.vlek ? ev.anchors.vlek : null;
  if (!vlekDer || vlekDer.length === 0) {
    subs.push(sub("snp.vlek", NOT_PROVEN, "no VLEK anchor bundled (firmware did not provision one)"));
    subs.push(sub("snp.report_sig", NOT_PROVEN, "cannot check without the VLEK"));
    return finishFact("memory_encryption", subs, "");
  }
  const vlek = await decodeCert(vlekDer);
  if (!vlek) return finishFact("memory_encryption", [sub("snp.vlek", FAILED, "VLEK DER walk failed")], "");
  const vlekCurve = spkiCurveIs(vlek.spkiDer, OID.CURVE_P384);
  subs.push(sub("snp.vlek", vlekCurve ? PROVEN : FAILED,
    vlekCurve ? "VLEK is an EC P-384 key" : "VLEK SPKI is not id-ecPublicKey/P-384"));
  // 5. VLEK signed the report (the report signature under the VLEK key).
  const sigOk = vlekCurve ? await snpReportSigOk(r, vlek.spkiDer) : false;
  subs.push(sub("snp.report_sig", sigOk ? PROVEN : FAILED,
    sigOk ? "VLEK ECDSA-P384 signature over the first 0x2a0 bytes verifies"
          : "the VLEK did NOT sign this report (forged, or a wrong VLEK was bundled)"));
  // 6. The chain to the baked roots. Hardware truth: the ASVK -> VLEK edge
  //    is RSA-PSS/SHA-384 (AMD's Milan KDS signs even the EC P-384 VLEK
  //    with the RSA ASVK key), and WebCrypto has NO RSA-PSS. So in-page:
  //    (a) the ASVK/ARK SPKI pins against the baked constants are REAL
  //    browser verification (the keys that sign VLEKs ARE the pinned keys
  //    - a swapped CA key fails here loudly), and (b) an ECDSA edge (a
  //    future VLEK family) is checked when present. The RSA-PSS signature
  //    bytes cannot be checked in-page: that half stays the CLI's check
  //    (wardenctl runs the pure-Rust verifier with the baked PEMs) and is
  //    labeled server-asserted, so the fact-level verdict tracks what the
  //    browser proved while the boundary stays visible on the page.
  const asvkDer = ev.anchors && ev.anchors.asvk ? ev.anchors.asvk : null;
  if (!asvkDer) {
    subs.push(sub("snp.vlek_chain", SERVER_ASSERTED,
      "no ASVK bytes in the bundle: the VLEK -> ASVK -> pinned ARK-Milan anchoring is the CLI's check (wardenctl verifies it against the baked PEMs)"));
  } else {
    const asvk = await decodeCert(asvkDer);
    const asvkPinned = !!(asvk && asvk.spkiPin === ASVK_MILAN_SPKI_SHA256);
    subs.push(sub("snp.asvk_pin", asvkPinned ? PROVEN : FAILED,
      asvkPinned ? "the bundled ASVK IS the baked SEV-VLEK-Milan key (SPKI pin match): the VLEK issuer key is trusted by pin"
                 : "the bundled ASVK's SPKI pin DOES NOT match the baked ASVK-Milan constant (a swapped CA key)"));
    const arkDer = ev.anchors && ev.anchors.ark ? ev.anchors.ark : null;
    if (arkDer) {
      const ark = await decodeCert(arkDer);
      subs.push(sub("snp.ark_pin", ark && ark.spkiPin === ARK_MILAN_SPKI_SHA256 ? PROVEN : FAILED,
        ark && ark.spkiPin === ARK_MILAN_SPKI_SHA256 ? "the bundled ARK is the baked ARK-Milan root (SPKI pin match)"
                       : "the bundled ARK's SPKI pin DOES NOT match the baked ARK-Milan constant"));
    }
    const vlekJudge = asvk ? await certEdgeOk(asvk, vlek) : null;
    if (vlekJudge === true) {
      subs.push(sub("snp.vlek_sig", PROVEN, "the VLEK certificate's ECDSA signature under the bundled ASVK verifies"));
    } else if (vlekJudge === false) {
      subs.push(sub("snp.vlek_sig", FAILED, "the VLEK certificate's ECDSA signature under the ASVK does NOT verify"));
    } else {
      subs.push(sub("snp.vlek_sig", SERVER_ASSERTED,
        "the ASVK -> VLEK edge is RSA-PSS/SHA-384 (WebCrypto has no RSA-PSS): wardenctl verifies it under the pinned ASVK key"));
    }
  }
  return finishFact("memory_encryption", subs, "");
}
function spkiCurveIs(spkiDer, curveOidHex) {
  const spki = derTlv(spkiDer, 0);
  if (!spki || spki.tag !== 0x30) return false;
  const alg = derTlv(spki.content, 0);
  if (!alg || alg.tag !== 0x30) return false;
  const inner = derTlv(alg.content, 0);
  if (!inner || bufToHex(inner.content) !== OID.EC_PUBLIC_KEY) return false;
  const c = derTlv(alg.content, inner.end);
  return !!(c && bufToHex(c.content) === curveOidHex);
}
function sub(name, status, why) { return { name: name, status: status, why: why }; }
// The fact-level verdict is the WORST of its sub-checks, where a
// SERVER-ASSERTED sub (something only the CLI can check) does NOT
// downgrade: that is what keeps the browser and the Rust verifier at the
// same verdict for the same bundle, which is the whole contract.
function finishFact(name, subs, why) {
  let s = PROVEN;
  for (const x of subs) {
    if (x.status === FAILED) { s = FAILED; break; }
    if (x.status === NOT_PROVEN) s = NOT_PROVEN;
  }
  return { name: name, status: s, why: why || subs.map(function (x) { return x.name + ": " + x.why; }).join("; "), subs: subs };
}

// -----------------------------------------------------------------------------
// TPM2: the quote under the AK (contract step 4). Rust side: verify/tpm2.rs.
// -----------------------------------------------------------------------------

function tpm2b(b, o) {
  if (!b || b.length < o + 2) return null;
  const n = beU16(b, o);
  if (b.length < o + 2 + n) return null;
  return { data: b.subarray(o + 2, o + 2 + n), end: o + 2 + n };
}

// The TPMT_PUBLIC walk (bootproof-tpm::parse_public_area): type u16, nameAlg
// u16, attributes u32, authPolicy TPM2B, symmetric, scheme, curve, kdf,
// unique {x TPM2B, y TPM2B}.
function tpmPublicArea(b) {
  if (!b || b.length < 12) return null;
  if (beU16(b, 0) !== TPM.ALG_ECC) return null;
  let off = 8;
  const ap = tpm2b(b, off); if (!ap) return null; off = ap.end;
  const sym = beU16(b, off);
  off += sym === TPM.ALG_NULL ? 2 : 6;
  const sch = beU16(b, off);
  off += sch === TPM.ALG_NULL ? 2 : 4;
  const curve = beU16(b, off); off += 2;
  const kdf = beU16(b, off);
  off += kdf === TPM.ALG_NULL ? 2 : 4;
  const x = tpm2b(b, off); if (!x) return null; off = x.end;
  const y = tpm2b(b, off); if (!y) return null;
  return { nameAlg: beU16(b, 2), authPolicy: ap.data, curve: curve, x: x.data, y: y.data };
}

function selectionIndices(sel) {
  if (!sel || sel.length < 3) return null;
  const size = sel[2];
  if (sel.length < 3 + size) return null;
  const out = [];
  for (let byte = 0; byte < size; byte++) {
    for (let bit = 0; bit < 8; bit++) {
      if (sel[3 + byte] & (1 << bit)) out.push(byte * 8 + bit);
    }
  }
  return out;
}
function hashSelectDigest(digests) {
  const cat = concat.apply(null, digests);
  return crypto.subtle.digest("SHA-256", cat);
}

async function checkTpm2(ev, nonceHex, bundle) {
  const subs = [];
  if (!ev) {
    return finishFact("tpm_quote", [sub("tpm.evidence", NOT_PROVEN, "no tpm2 evidence in the bundle (no TPM served)")], "");
  }
  const doc = ev.doc;
  if (!doc || doc.length === 0 || doc[0] !== 1) {
    return finishFact("tpm_quote", [sub("tpm.evidence", FAILED, "unsupported tpm2 doc version")], "");
  }
  let off = 1;
  const attest = tpm2b(doc, off); if (!attest) return failTpm("truncated TPMS_ATTEST"); off = attest.end;
  const akPublic = tpm2b(doc, off); if (!akPublic) return failTpm("truncated AK public"); off = akPublic.end;
  const sigR = tpm2b(doc, off); if (!sigR) return failTpm("truncated sig r"); off = sigR.end;
  const sigS = tpm2b(doc, off); if (!sigS) return failTpm("truncated sig s"); off = sigS.end;
  const perPcr = tpm2b(doc, off); if (!perPcr) return failTpm("truncated per-PCR digests");

  const a = attest.data;
  if (a.length < 8 || beU32(a, 0) !== TPM.ATTEST_MAGIC) return failTpm("bad attestation magic");
  if (beU16(a, 4) !== TPM.ATTEST_QUOTE) return failTpm("attestation type is not QUOTE");
  let q = 6;
  const qs = tpm2b(a, q); if (!qs) return failTpm("truncated qualifiedSigner"); q = qs.end;
  const ed = tpm2b(a, q); if (!ed) return failTpm("truncated extraData"); q = ed.end;
  q += 8 + 4 + 4 + 1 + 8; // clockInfo + firmwareVersion
  if (a.length < q + 4) return failTpm("truncated pcrSelect count");
  const selCount = beU32(a, q); q += 4;
  const sels = [];
  for (let i = 0; i < selCount; i++) {
    if (a.length < q + 3) return failTpm("truncated pcrSelect");
    const size = a[q + 2];
    if (a.length < q + 3 + size) return failTpm("truncated pcrSelect bytes");
    sels.push(a.subarray(q, q + 3 + size));
    q += 3 + size;
  }
  const pcrDigest = tpm2b(a, q); if (!pcrDigest) return failTpm("truncated pcrDigest");

  // 1. Nonce binding: extraData (qualifiedData) == OUR fresh nonce.
  const nonceOk = bufToHex(ed.data.subarray(0, 32)) === nonceHex;
  subs.push(sub("tpm.nonce_binding", nonceOk ? PROVEN : FAILED,
    nonceOk ? "quote extraData binds this page's nonce"
            : "quote extraData != the fresh nonce (replay or wrong challenge)"));

  // 2. The AK: P-256 ECC, Name / qualified Name recomputation.
  const ak = tpmPublicArea(akPublic.data);
  if (!ak || ak.curve !== TPM.ALG_EC_P256 || ak.nameAlg !== TPM.ALG_SHA256) {
    return finishFact("tpm_quote", [sub("tpm.ak", FAILED, "AK is not P-256 with SHA-256 nameAlg")], "");
  }
  const nameHash = await sha256Hex(akPublic.data);
  const akName = hexToBuf(TPM_HEX(TPM.ALG_SHA256) + nameHash);
  const qualified = hexToBuf(TPM_HEX(TPM.ALG_SHA256) +
    await sha256Hex(concat(u32be(TPM.OWNER_HIERARCHY), akName)));
  const signerOk = bufToHex(qs.data) === bufToHex(akName) || bufToHex(qs.data) === bufToHex(qualified);
  subs.push(sub("tpm.ak_name", signerOk ? PROVEN : FAILED,
    signerOk ? "qualifiedSigner matches the AK's (qualified) Name"
             : "qualifiedSigner matches neither Name(AK) nor the OWNER-qualified Name"));

  // 3. The quote signature: AK ECDSA-P256/SHA-256 over the raw attestation.
  const akPubDer = ecSpkiDer("P-256", ak.x, ak.y);
  const sig = concat(zeroPad(sigR.data, 32), zeroPad(sigS.data, 32));
  const quoteSigOk = await verifyEcdsa("P-256", "SHA-256", akPubDer, sig, a);
  subs.push(sub("tpm.quote_sig", quoteSigOk ? PROVEN : FAILED,
    quoteSigOk ? "AK ECDSA-P256 signature over TPMS_ATTEST verifies"
               : "the AK did NOT sign this quote (forged quote or wrong AK bytes)"));

  // 4. PCR self-consistency: the quoted selection + per-PCR digests hash
  //    to the signed pcrDigest.
  const indices = sels.length === 1 ? selectionIndices(sels[0]) : null;
  if (!indices || indices.length === 0) {
    subs.push(sub("tpm.pcr_digest", FAILED, "the quote selection is malformed or empty"));
    return finishFact("tpm_quote", subs, "");
  }
  if (perPcr.data.length !== indices.length * 32) {
    subs.push(sub("tpm.pcr_digest", FAILED, "per-PCR blob length disagrees with the selection"));
    return finishFact("tpm_quote", subs, "");
  }
  const pcrs = {};
  const digests = [];
  for (let i = 0; i < indices.length; i++) {
    const d = perPcr.data.subarray(i * 32, (i + 1) * 32);
    pcrs[indices[i]] = d;
    digests.push(d);
  }
  const digestOk = bufToHex(new Uint8Array(await hashSelectDigest(digests))) === bufToHex(pcrDigest.data);
  subs.push(sub("tpm.pcr_digest", digestOk ? PROVEN : FAILED,
    digestOk ? "SHA-256 of the " + indices.length + " per-PCR digests equals the signed pcrDigest"
             : "per-PCR digests do NOT hash to the signed pcrDigest"));
  // pcr_state: the values themselves (mirrors the Rust pcr_state fact).
  const pcrStr = indices.map(function (i) { return "PCR" + pad2(i) + "=" + bufToHex(pcrs[i]); }).join(" ");
  subs.push(sub("tpm.pcr_state", PROVEN, pcrStr));
  // 5. Slot link (PCR22): the node folds the other channels' docs after
  //    resetting PCR22, so the expected value is H(0^32 || H(concat docs)).
  const otherDocs = (bundle.evidence || []).filter(function (e) {
    return e.channel !== "tpm2";
  }).map(function (e) { return wireBytes(e.doc) || new Uint8Array(0); });
  const slot = pcrs[TPM.SLOT_PCR];
  if (!slot) {
    subs.push(sub("tpm.slot_link", NOT_PROVEN,
      "PCR" + TPM.SLOT_PCR + " is not on this TPM (NitroTPM exposes 0-9): the cross-channel fold is a hardware boundary, not a failure"));
  } else {
    const hDocs = otherDocs.length === 0
      ? await sha256Hex(new Uint8Array(0))
      : await sha256Hex(concat.apply(null, otherDocs));
    const expected = await sha256Hex(concat(hexToBuf("00".repeat(32)), hexToBuf(hDocs)));
    const foldOk = bufToHex(slot) === expected;
    subs.push(sub("tpm.slot_link", foldOk ? PROVEN : FAILED,
      foldOk ? "PCR" + TPM.SLOT_PCR + " == H(0 || H(other docs)): the other channels are bound into the quote"
             : "PCR" + TPM.SLOT_PCR + " is neither the fold nor a measured state (INTEGRITY FAILURE)"));
  }
  // 6. The sign key: published in bundle.keys.sign; the browser renders it
  //    and checks its curve shape. The authPolicy recomputation (PolicyPCR)
  //    is the one Rust check the browser delegates: it depends on the TPM's
  //    selection dialect and stays the CLI's job. Labeled server-asserted.
  const sign = bundle.keys && bundle.keys.sign;
  if (!sign || !sign.pub_) {
    subs.push(sub("tpm.sign_key", NOT_PROVEN, "no state-bound sign key published in bundle.keys"));
  } else {
    const sk = tpmPublicArea(wireBytes(sign.pub_));
    subs.push(sub("tpm.sign_key", sk && sk.curve === TPM.ALG_EC_P256 ? PROVEN : FAILED,
      sk ? "P-256 state-bound sign key published (PCR-gated; authPolicy recomputation is server-asserted: the CLI re-verifies it)"
         : "the published sign key public area does not parse"));
  }
  // 7. The EK cert: presence only (the Rust fact itself says the chain is
  //    not verified in this build: same verdict, both verifiers).
  const ek = ev.anchors && ev.anchors.ek_cert;
  subs.push(sub("tpm.ek_cert", ek ? "DEGRADED" : NOT_PROVEN,
    ek ? "present (" + ek.length + " bytes); the AWS/NitroTPM EK-cert chain is not verified in either verifier (honest informational)"
       : "absent from the node"));
  return finishFact("tpm_quote", subs, "");
}
function failTpm(why) { return finishFact("tpm_quote", [sub("tpm.evidence", FAILED, why)], ""); }
function zeroPad(b, n) {
  if (b.length >= n) return b.subarray(b.length - n);
  const o = new Uint8Array(n); o.set(b, n - b.length); return o;
}
function u32be(v) { return new Uint8Array([(v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255]); }
function TPM_HEX(v) { return ("0000" + v.toString(16)).slice(-4); }
function pad2(n) { return n < 10 ? "0" + n : "" + n; }

// -----------------------------------------------------------------------------
// The wardend state-log signatures (contract step 3's wardend channel).
// Rust side: verify_chained_log + P256Signer (prehashed ECDSA over the
// wardend entry hash SHA-256(prev||new||op||timestamp_be)).
// -----------------------------------------------------------------------------

async function checkStateLog(env) {
  const bundle = env.bundle || {};
  const evs = bundle.evidence || [];
  const ev = evs.find(function (e) { return e.channel === "wardend"; });
  if (!ev) {
    return finishFact("wardend_state_chain",
      [sub("wardend.evidence", NOT_PROVEN, "the bundle carries no wardend channel (no seald admin face)")], "");
  }
  let doc;
  try {
    const raw = wireBytes(ev.doc);
    if (!raw) return finishFact("wardend_state_chain", [sub("wardend.evidence", FAILED, "the wardend doc is not a base64 string")], "");
    doc = JSON.parse(new TextDecoder().decode(raw));
  } catch (e) {
    return finishFact("wardend_state_chain", [sub("wardend.evidence", FAILED, "the wardend evidence doc is not decodable JSON: " + e)], "");
  }
  const log = doc.state_log || [];
  const subs = [];
  if (log.length === 0) {
    subs.push(sub("wardend.seal_state", doc.seal_state ? PROVEN : NOT_PROVEN,
      doc.seal_state ? "seal state published: " + j(doc.seal_state) : "the doc carries no seal state"));
    subs.push(sub("wardend.state_chain", NOT_PROVEN, "the state log is empty: no signature to verify"));
    return finishFact("wardend_state_chain", subs, "");
  }
  const anchorKey = ev.anchors && (ev.anchors.hsm_public || ev.anchors.seald_public);
  if (!anchorKey) {
    return finishFact("wardend_state_chain",
      [sub("wardend.state_chain", NOT_PROVEN, "no seald HSM public key anchor in the bundle: the state log cannot be verified")], "");
  }
  const point = wireBytes(anchorKey);
  const spki = spkiFromPoint(point);
  if (!spki) {
    return finishFact("wardend_state_chain",
      [sub("wardend.state_chain", FAILED, "the HSM anchor is not the 65-byte uncompressed P-256 point")], "");
  }
  // The identity cross-check: the HSM SPKI we are about to trust must pin
  // to the same key the identity section publishes (both sides of the
  // contract's identity link, browser-side).
  let anchorConsistent = true;
  if (env.identity && env.identity.attest_signer_spki_sha256) {
    anchorConsistent = (await sha256Hex(spki)) === String(env.identity.attest_signer_spki_sha256).toLowerCase();
  }
  let prev = log[0].prev_hash ? hexOrBytes(log[0].prev_hash) : new Uint8Array(32);
  // NOTE (agreement): the Rust verifier seeds the chain with the FIRST
  // entry's own prev_hash (WardendVerifier: no independent genesis
  // constant), and the browser mirrors that exactly, so both verifiers
  // judge links [1..n] and every signature and NEITHER judges entry 0's
  // parent. Same blind spot, same verdict, documented in both.
  for (let i = 0; i < log.length; i++) {
    const e = log[i];
    const prevH = hexOrBytes(e.prev_hash), newH = hexOrBytes(e.new_state_hash);
    if (i > 0 && bufToHex(prevH) !== bufToHex(prev)) {
      subs.push(sub("wardend.state_chain", FAILED, "the prev_hash link is broken at entry " + i + " (tampered log)"));
      return finishFact("wardend_state_chain", subs, "");
    }
    const msg = concat(prevH, newH, bytesOf(e.operation), u64be(e.timestamp));
    const sig = bytesOf(e.signature);
    // The signature check: ECDSA-P256/SHA-256 over the entry's field bytes.
    // The wardend hash policy IS SHA-256 of exactly those bytes, so this is
    // byte-for-byte the Rust verify_prehashed check (see the note above
    // verifyEcdsa).
    const sigOk = sig.length === 64 ? await verifyEcdsa("P-256", "SHA-256", spki, sig, msg) : false;
    if (!sigOk) {
      subs.push(sub("wardend.state_chain", sig.length === 0 ? NOT_PROVEN : FAILED,
        sig.length === 0 ? "entry " + i + " carries no signature bytes"
                         : "entry " + i + ": the HSM signature over the entry hash does NOT verify"));
      return finishFact("wardend_state_chain", subs, "");
    }
    prev = new Uint8Array(await crypto.subtle.digest("SHA-256", msg));
  }
  subs.push(sub("wardend.state_chain", anchorConsistent ? PROVEN : FAILED,
    (anchorConsistent ? "all " + log.length + " entries: links intact, ECDSA over each entry hash valid under the pinned HSM key"
                      : "the chain verifies but the HSM anchor SPKI != identity.attest_signer_spki_sha256")));
  return finishFact("wardend_state_chain", subs, "");
}
// serde serializes [u8; 32] and Vec<u8> as a JSON ARRAY of numbers (the
// wardend StateLogEntry goes through serde_json, not the B64 newtype), so
// the arrays below are numbers. A hex string is accepted too (a hand-built
// fixture), anything else is zero-length and fails honestly.
function hexOrBytes(v) {
  if (Array.isArray(v)) return new Uint8Array(v);
  if (typeof v === "string") {
    const h = v.replace(/[^0-9a-fA-F]/g, "");
    return h.length === v.length * 2 || h.length % 2 === 0 ? hexToBuf(h) : new Uint8Array(0);
  }
  return new Uint8Array(0);
}
function bytesOf(v) {
  if (Array.isArray(v)) return new Uint8Array(v);
  if (typeof v === "string") return new Uint8Array(new TextEncoder().encode(v));
  return new Uint8Array(0);
}
function u64be(n) {
  const hi = Math.floor(n / 4294967296), lo = n % 4294967296;
  return concat(u32be(hi), u32be(lo));
}

// -----------------------------------------------------------------------------
// runVerification: THE verifier (the contract's order, one page view).
// The pure decision list it builds is the same one the Rust verifier
// produces: see the name-for-name table in
// crates/bootproof/tests/system_health_agreement.rs (golden fixture).
// -----------------------------------------------------------------------------

async function runVerification(origin) {
  const t0 = Date.now();
  // 1. A FRESH 32-byte nonce: nothing older than this page view is worth
  //    forging, and every channel below must bind it.
  const nonce = crypto.getRandomValues(new Uint8Array(32));
  const nonceHex = bufToHex(nonce);
  // 2. Fetch the envelope fresh (no-store: the server echoes OUR nonce).
  let env;
  try {
    const res = await fetch(origin + "/health/api?nonce=" + nonceHex, { cache: "no-store" });
    env = await res.json();
  } catch (e) {
    return { ok: false, overall: FAILED, error: "fetch /health/api failed: " + e,
             nonce: nonceHex, checks: [], serverFacts: [], t: t0 };
  }
  const checks = [];
  const host = (origin || "").replace(/^https?:\/\//, "").replace(/:.*$/, "").split("/")[0];

  // 3a. The TLS identity link.
  const id = await checkIdentity(env, host);
  checks.push({ name: "identity_link", status: id.status, why: id.why });
  for (const s of id.subs || []) checks.push(s);

  // 3b. Envelope nonce freshness: the echo must be OUR nonce (the channel
  //     signatures bind it in the bundle; the echo is the envelope-level
  //     freshness marker, the same one wardenctl checks).
  const echoed = String(env.nonce || "").toLowerCase();
  const fresh = echoed.length === 64 && echoed === nonceHex;
  checks.push(sub("nonce_freshness", echoed === "" ? NOT_PROVEN : (fresh ? PROVEN : FAILED),
    echoed === "" ? "the envelope carries no nonce echo"
                  : (fresh ? "the envelope echoes this page's fresh nonce"
                           : "the envelope nonce is NOT the nonce we sent")));
  // And the bundle's own nonce field must match too (verify_bundle takes
  // the bundle nonce as its challenge: the same binding, one level down).
  if (env.bundle && env.bundle.nonce != null) {
    const nb = wireBytes(env.bundle.nonce);
    const bn = nb && nb.length === 32 ? bufToHex(nb) : "";
    checks.push(sub("bundle_nonce", bn === nonceHex ? PROVEN : (bn.length === 64 ? FAILED : NOT_PROVEN),
      bn === nonceHex ? "bundle.nonce == our challenge (verify_bundle's nonce)"
                      : "bundle.nonce does not match our 32-byte challenge"));
  }

  // 4. The bundle's channels: what the browser verifies itself.
  const bundle = env.bundle || {};
  const evs = bundle.evidence || [];
  const snpEv = decodeEvidence(evs.find(function (e) { return e.channel === "snp"; }));
  const tpmEv = decodeEvidence(evs.find(function (e) { return e.channel === "tpm2"; }));
  checks.push(await checkSnp(snpEv, nonceHex));
  checks.push(await checkTpm2(tpmEv, nonceHex, bundle));
  checks.push(await checkStateLog(env));

  // 5. The server's own verdicts, rendered VERBATIM as published (the
  //    server-asserted layer: the seald-side verify_bundle output). Every
  //    fact the browser could not independently check lives here honestly.
  const serverFacts = (env.facts || []).map(function (f) {
    return { name: f.name, value: f.value, status: mapStatus(f.status), anchors: f.anchors || [] };
  });

  // 6. The metadata sections: rendered from the envelope; null is an
  //    honest NOT PROVEN, never a fake row (the render step below).
  const sections = renderSections(env.metadata || {});

  // Overall: PROVEN only if every REQUIRED check is PROVEN. Required =
  // the signature-bearing proofs (identity, freshness, the channels'
  // signatures, the state chain). NOT PROVEN/FAILED anywhere else keeps
  // the banner honest (a missing hardware channel is NOT PROVEN, not a
  // lie, but it still blocks a full PROVEN, exactly like the Rust pass()).
  const required = ["identity_link", "nonce_freshness", "memory_encryption",
                    "tpm_quote", "wardend_state_chain"];
  let overall = PROVEN;
  for (const c of checks) {
    if (required.indexOf(c.name) >= 0 && c.status !== PROVEN) overall = c.status;
  }

  // 7. Self-report: our own bytes so the page can prove WHICH verifier ran.
  let swLen = null, swSha = null;
  try {
    const sw = await (await fetch(origin + "/verify.js", { cache: "no-store" })).arrayBuffer();
    swLen = sw.byteLength;
    swSha = await sha256Hex(new Uint8Array(sw));
  } catch (e) { /* the page already prints SW_SHA256 from the server side */ }

  return { ok: overall === PROVEN, overall: overall, nonce: nonceHex,
           checks: checks, serverFacts: serverFacts, sections: sections,
           swLen: swLen, swSha: swSha, t: t0 };
}

function mapStatus(s) {
  return s === "proven" ? PROVEN : s === "degraded" ? "DEGRADED" :
         s === "reproducible" ? "REPRODUCIBLE" : NOT_PROVEN;
}
// The wire's B64 newtype serializes as a PLAIN base64 string (see
// bootproof::src/b64.rs: Serialize -> serialize_str), so every binary field
// in the bundle is a base64 string, never an object. Anything else is an
// honest null (fail closed).
function wireBytes(v) {
  if (typeof v === "string") { try { return b64ToBuf(v); } catch (e) { return null; } }
  if (v && v instanceof Uint8Array) return v;
  return null;
}
function decodeEvidence(ev) {
  if (!ev) return null;
  const anchors = {};
  const a = ev.anchors || {};
  for (const k of Object.keys(a)) anchors[k] = wireBytes(a[k]);
  return { channel: ev.channel, doc: wireBytes(ev.doc), anchors: anchors };
}

// The metadata render: section -> structured rows. A null section is an
// honest NOT PROVEN row. Everything is escaped at render time.
function renderSections(m) {
  const rows = [];
  rows.push({ label: "instance_id", status: m.instance_id ? PROVEN : NOT_PROVEN, value: m.instance_id || "not set" });
  rows.push({ label: "user_data", status: m.user_data ? PROVEN : NOT_PROVEN, value: trunc(m.user_data, 120) });
  rows.push({ label: "stagex_commit", status: m.stagex_commit ? PROVEN : NOT_PROVEN,
    value: (m.stagex_commit || "no wardend-commit line in user-data") + (m.stagex_commit ? "  (a parsed CLAIM from user-data: pair it with the measured-boot facts)" : "") });
  rows.push({ label: "instance_identity", status: m.instance_identity ? PROVEN : NOT_PROVEN,
    value: m.instance_identity ? "signed IMDS document present (verifiable only against AWS's signing key)" : "absent (not an AWS instance, or IMDS was unreachable)" });
  rows.push({ label: "disk_encryption", status: m.disk_encryption ? PROVEN : NOT_PROVEN, value: j(m.disk_encryption) });
  rows.push({ label: "units", status: Array.isArray(m.units) && m.units.length ? PROVEN : NOT_PROVEN,
    value: Array.isArray(m.units) && m.units.length
      ? m.units.map(function (u) { return u.name + ": " + (u.state || u.health || "?"); }).join(", ")
      : "the node published no unit table" });
  rows.push({ label: "hsm_keys", status: Array.isArray(m.hsm_keys) && m.hsm_keys.length ? PROVEN : NOT_PROVEN,
    value: Array.isArray(m.hsm_keys) && m.hsm_keys.length
      ? m.hsm_keys.map(function (k) { return k.name + (k.pcr_gated ? " [PCR-gated " + (k.pcrs || []).join(",") + "]" : " [not PCR-gated]"); }).join(", ")
      : "no named secrets registered" });
  if (m.seal_state) {
    rows.push({ label: "seal_state", status: PROVEN,
      value: "posture " + (m.seal_state.posture || "?") + ", state_hash " + trunc(m.seal_state.state_hash, 24) +
             ", log entries " + (m.seal_state.state_log != null ? m.seal_state.state_log : "?") +
             ", pcrs [" + ((m.seal_state.pcrs || []).join(",")) + "]" });
  } else {
    rows.push({ label: "seal_state", status: NOT_PROVEN, value: "no seal state published" });
  }
  const cc = m.cert_chain;
  rows.push({ label: "cert_chain", status: cc && cc.leaf ? PROVEN : NOT_PROVEN,
    value: cc && cc.leaf ? ("leaf " + trunc(cc.leaf.subject, 60) + ", anchors: " + ((cc.spki_anchors || []).join(", ") || "none")) : "no ACME leaf published" });
  const en = m.endorsement || {};
  rows.push({ label: "endorsement", status: (en.aws && en.aws.present) || (en.amd && en.amd.present) ? PROVEN : NOT_PROVEN,
    value: "aws: " + j(en.aws) + " amd: " + j(en.amd) });
  rows.push({ label: "spdx_inventory", status: m.spdx_inventory ? PROVEN : NOT_PROVEN, value: m.spdx_inventory ? j(m.spdx_inventory) : "no SBOM shipped with this image (honest null until one exists)" });
  return rows;
}
function trunc(v, n) { const s = typeof v === "string" ? v : j(v); return s.length > n ? s.slice(0, n) + "…" : s; }
function j(v) { try { return JSON.stringify(v); } catch (e) { return String(v); } }

// -----------------------------------------------------------------------------
// RENDER (the page). All text goes through esc(); the envelope is
// UNTRUSTED input and this file must never hand it to the parser.
// -----------------------------------------------------------------------------

// The page carries the CSS (the shell's <style>); this file only produces
// verdict markup, so the styling can never fight the verifier's bytes.

function esc(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}
function cls(status) {
  return status === PROVEN ? "p" : status === FAILED ? "f" : status === SERVER_ASSERTED || status === "DEGRADED" || status === "REPRODUCIBLE" ? "s" : "n";
}
function render(res) {
  const parts = [];
  parts.push('<h1>System Health<span class="verdict ' + cls(res.overall) + '">' + esc(res.overall) + "</span></h1>");
  parts.push('<p class="why">nonce ' + esc((res.nonce || "").slice(0, 16)) + "… · verified " +
    new Date(res.t).toISOString() + " · this page view only</p>");
  if (res.error) parts.push('<p class="verdict f">' + esc(res.error) + "</p>");
  parts.push('<div class="sec">browser-verified proofs</div><table>');
  for (const c of res.checks || []) {
    parts.push("<tr><td class=k>" + esc(c.name) + '</td><td><span class="verdict ' + cls(c.status) + '">' +
      esc(c.status) + "</span> <span class=why>" + esc(c.why) + "</span></td></tr>");
  }
  parts.push("</table>");
  parts.push('<div class="sec">server-published facts (verbatim, the seald-side verify)</div><table>');
  for (const f of res.serverFacts || []) {
    parts.push("<tr><td class=k>" + esc(f.name) + '</td><td><span class="verdict ' + cls(f.status) + '">' +
      esc(f.status) + '</span> <span class=why>"' + esc(f.value) + '" [' + esc((f.anchors || []).join("+")) + "]</span></td></tr>");
  }
  parts.push("</table>");
  parts.push('<div class="sec">envelope sections</div><table>');
  for (const r of res.sections || []) {
    parts.push("<tr><td class=k>" + esc(r.label) + '</td><td><span class="verdict ' + cls(r.status) + '">' +
      esc(r.status) + "</span> <span class=why>" + esc(r.value) + "</span></td></tr>");
  }
  parts.push("</table>");
  if (res.swLen) {
    parts.push('<p class=foot>verifier: ' + esc(res.swLen) + " bytes, sha256 " + esc(res.swSha) +
      ' · <a href="/verify.js.src">read it</a> · re-verifies every ' + (REFRESH_MS / 1000) + "s</p>");
  }
  return parts.join("");
}

async function broadcast(result) {
  lastResult = result;
  // The page is a dumb renderer: it receives the SW's own escaped HTML (all
  // envelope bytes already went through esc()), never raw data. One
  // renderer for the browser twin - the markup and the verdicts cannot
  // diverge because the SAME function produced both.
  const html = render(result);
  const list = await self.clients.matchAll({ includeUncontrolled: true, type: "window" });
  for (const c of list) c.postMessage({ type: "system-health", result: result, html: html });
}

let lastResult = null;
let loopHandle = null;

async function loop(origin) {
  let result;
  try {
    result = await runVerification(origin);
  } catch (e) {
    // The verifier itself crashed: the HONEST verdict is FAILED with the
    // reason. A bug never renders as a green check.
    result = { ok: false, overall: FAILED, error: "verifier error: " + e, checks: [], serverFacts: [], t: Date.now() };
  }
  try { await broadcast(result); } catch (e) { /* client vanished */ }
  loopHandle = setTimeout(function () { loop(origin); }, REFRESH_MS);
}

// -----------------------------------------------------------------------------
// The service worker lifecycle.
// -----------------------------------------------------------------------------

self.addEventListener("install", function (e) {
  // Skip waiting: the newest verified bytes are always the ones running.
  self.skipWaiting();
});

self.addEventListener("activate", function (e) {
  e.waitUntil((async function () {
    await self.clients.claim();
    if (loopHandle) clearTimeout(loopHandle);
    loop(self.location.origin);   // verify immediately, then every REFRESH_MS
  })());
});

self.addEventListener("message", function (e) {
  // A page can ask for the current verdict without waiting for the tick.
  if (e.data && e.data.type === "sh-ping") {
    if (e.source) e.source.postMessage({ type: "system-health", result: lastResult });
    else if (e.ports && e.ports[0] && lastResult) e.ports[0].postMessage(lastResult);
  }
});

self.addEventListener("fetch", function (e) {
  const req = e.request;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;           // never touch cross-origin
  if (req.method !== "GET") { e.respondWith(fetch(req)); return; }
  // /health/api passes through UNTOUCHED: the page (or anyone) may fetch
  // it directly and the bytes must stay a byte-exact proxy of the
  // admin-frame round-trip.
  if (url.pathname === "/health/api") return;
  // Everything else is static: cache-first with network fallforward, so a
  // navigation re-verifies against the cached shell even when the origin
  // is unreachable (the verdict then honestly reflects the fetch failure).
  e.respondWith(
    caches.open("sh-static-v1").then(function (cache) {
      return cache.match(req).then(function (hit) {
        const net = fetch(req).then(function (res) {
          if (res && res.ok && res.status === 200) cache.put(req, res.clone());
          return res;
        }).catch(function () {
          return hit || Response.error();
        });
        return hit || net;
      });
    })
  );
});

// Test seam: the node harness (the golden-fixture agreement test) loads
// this file and drives these functions directly. self-based so a browser
// gets nothing extra; the service worker itself ignores this.
try {
  self.__bootproof_verifier__ = {
    runVerification: runVerification,
    checkIdentity: checkIdentity,
    checkSnp: checkSnp,
    checkTpm2: checkTpm2,
    checkStateLog: checkStateLog,
    pemToDer: pemToDer,
    spkiFromPoint: spkiFromPoint,
    spkiOfLeaf: function (pem) {
      const ders = pemToDer(pem);
      return ders.length ? sha256Hex(derCertsParts(ders[0]).spki) : Promise.resolve(null);
    },
  };
} catch (e) { /* non-browser context without self: fine */ }
