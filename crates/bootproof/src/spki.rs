//! SPKI pinning: the pin is `SHA-256(SubjectPublicKeyInfo DER)`, the standard
//! TLS public-key pin. Extracted with a bounded DER walk so we don't pull in a
//! full X.509 parser just to pin a self-signed identity we control.

use sha2::{Digest, Sha256};

/// Return an error.
fn err<T>(msg: &str) -> Result<T, String> {
    Err(msg.to_string())
}

/// Read a DER length at `o` (the position of the length octets, i.e. right
/// after the tag). Returns `(length, new_o)` where `new_o` is the position of
/// the element's contents.
fn read_len(b: &[u8], o: usize) -> Result<(usize, usize), String> {
    let first = *b.get(o).ok_or("truncated: no len byte")?;
    if first < 0x80 {
        return Ok((first as usize, o + 1));
    }
    let n = (first & 0x7F) as usize;
    if n == 0 || n > 4 {
        return err("bad DER length");
    }
    if b.len() < o + 1 + n {
        return err("truncated: long len");
    }
    let mut v = 0usize;
    for i in 1..=n {
        v = (v << 8) | b[o + i] as usize;
    }
    if v > (b.len() - o - 1 - n) {
        return err("DER length overruns buffer");
    }
    Ok((v, o + 1 + n))
}

/// Skip one full DER element starting at `o` (the tag). Returns the position
/// just past it.
fn skip_elem(b: &[u8], o: usize) -> Result<usize, String> {
    let _tag = *b.get(o).ok_or("truncated: no tag")?;
    let (len, c) = read_len(b, o + 1)?;
    if b.len() < c + len {
        return err("truncated element");
    }
    Ok(c + len)
}

/// Walk the end-entity cert DER and return the raw DER bytes of the
/// `subjectPublicKeyInfo` element (tag + length + contents).
///
/// Layout walked:
/// ```text
/// Certificate ::= SEQUENCE {
///   tbsCertificate ::= SEQUENCE {
///     [0] version            (v3 only, context-specific)
///     serialNumber  INTEGER
///     signature     ALGORITHM (SEQUENCE)
///     issuer        NAME      (SEQUENCE)
///     validity      SEQUENCE
///     subject       NAME      (SEQUENCE)
///     subjectPublicKeyInfo SEQUENCE   <-- returned
///     ...
/// ```
pub fn spki_der(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    // Certificate outer SEQUENCE.
    let cert_start = 0usize;
    if *cert_der.get(0).ok_or("empty cert")? != 0x30 {
        return err("not a SEQUENCE");
    }
    let (cert_len, tbs_pos) = read_len(cert_der, 1)?;
    if cert_der.len() < tbs_pos + cert_len {
        return err("cert length overrun");
    }

    // tbsCertificate SEQUENCE.
    let tbs_start = tbs_pos;
    if *cert_der.get(tbs_pos).ok_or("truncated tbs")? != 0x30 {
        return err("tbs not a SEQUENCE");
    }
    let (_tbs_len, o) = read_len(cert_der, tbs_pos + 1)?;

    // [0] version (context-specific, class 0, constructed 0xA0) — present in
    // v3 certs, which is all we generate.
    let o = if cert_der.get(o) == Some(&0xA0) {
        skip_elem(cert_der, o)?
    } else {
        o
    };

    // serialNumber INTEGER, signature ALGORITHM, issuer NAME, validity,
    // subject NAME.
    let o = skip_elem(cert_der, o)?; // serialNumber
    let o = skip_elem(cert_der, o)?; // signature alg
    let o = skip_elem(cert_der, o)?; // issuer
    let o = skip_elem(cert_der, o)?; // validity
    let o = skip_elem(cert_der, o)?; // subject

    // subjectPublicKeyInfo SEQUENCE — capture its raw DER.
    let spki_start = o;
    if cert_der.get(o) != Some(&0x30) {
        return err("SPKI not a SEQUENCE");
    }
    let (spki_len, spki_c) = read_len(cert_der, o + 1)?;
    if cert_der.len() < spki_c + spki_len {
        return err("SPKI length overrun");
    }
    let spki_end = spki_c + spki_len;
    let _ = (tbs_start, cert_start, cert_len);
    Ok(cert_der[spki_start..spki_end].to_vec())
}

/// The raw subject public key bytes (the SEC1 point) from the cert's SPKI.
///
/// SPKI layout: `SEQUENCE { SEQUENCE { algid }, BIT STRING { 00, key } }`.
pub fn spki_raw_key(cert_der: &[u8]) -> Result<Vec<u8>, String> {
    let spki = spki_der(cert_der)?;
    // Skip the SPKI outer tag+len, enter contents.
    let (spki_len, o) = read_len(&spki, 1)?;
    if spki.len() < o + spki_len {
        return err("SPKI contents overrun");
    }
    // AlgorithmIdentifier SEQUENCE.
    if spki.get(o) != Some(&0x30) {
        return err("algid not a SEQUENCE");
    }
    let o = skip_elem(&spki, o)?;
    // subjectPublicKey BIT STRING.
    if spki.get(o) != Some(&0x03) {
        return err("subjectPublicKey not a BIT STRING");
    }
    let (len, c) = read_len(&spki, o + 1)?;
    if spki.len() < c + len || len < 1 {
        return err("BIT STRING truncated");
    }
    if spki[c] != 0 {
        return err("non-zero unused bits in BIT STRING");
    }
    Ok(spki[c + 1..c + len].to_vec())
}

/// The pin for a cert: hex `SHA-256(SPKI DER)`.
pub fn spki_pin(cert_der: &[u8]) -> Result<String, String> {
    let spki = spki_der(cert_der)?;
    Ok(hex(&Sha256::digest(&spki)))
}

/// The SPKI pin for a self-signed cert we hold (server side).
pub fn pin_of_cert(cert_der: &[u8]) -> Result<String, String> {
    spki_pin(cert_der)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
