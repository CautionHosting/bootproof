//! The tpm2 verifier: check the AK quote, the slot link, and the state-bound
//! sign key -- all offline, from the Bundle.
//!
//! Checks (in order):
//! 1. Doc parses (v1 layout).
//! 2. `TPMS_ATTEST` magic + type QUOTE; `qualifiedData == nonce`.
//! 3. `qualifiedSigner` matches the AK's qualified Name:
//!    `nameAlg || H(0x40000001 || Name)` where Name = `nameAlg || H(public)`
//!    and 0x40000001 is the OWNER hierarchy the primary was created in
//!    (verified against a live TPM; the raw Name is also accepted, e.g.
//!    for keys with the null parent).
//! 4. AK public area parses; ECDSA-SHA256 quote signature verifies over the
//!    raw attestation bytes.
//! 5. `SHA256(concat(per_pcr)) == quote pcrDigest` (per-PCR values are the
//!    ones that determine the signed digest).
//! 6. Slot link: `PCR22 == SHA256(concat of the other channels' docs)`.
//! 7. Sign key: `authPolicy == H(TPM_CC_PolicyPCR || selection || pcrDigest)`
//!    with the quote's selection and digest (the TCG reference formula).

use digest::Digest;
use group::prime::PrimeCurveAffine;
use sha2::Sha256;

use bootproof_tpm::commands_policy::{policy_pcr_auth_policy, parse_public_area};
use bootproof_tpm::{PcrSelection, constants::alg};

use crate::channel::{SlotLink, Tpm2Verified, Verified, Verifier};
use crate::wire::{Bundle, Evidence, Fact, Status};

const ATTEST_MAGIC: u32 = 0xFF54_4347;
const ATTEST_QUOTE: u16 = 0x8018;

struct Attest {
    qualified_signer: Vec<u8>,
    qualified_data: Vec<u8>,
    pcr_selections: Vec<Vec<u8>>, // each TPMS_PCR_SELECTION (hash u16 | size u8 | bytes)
    pcr_digest: Vec<u8>,
}

fn read_tpm2b(b: &[u8], o: usize) -> Option<(usize, &[u8], usize)> {
    let size = u16::from_be_bytes([b[o], b[o + 1]]) as usize;
    if b.len() < o + 2 + size {
        return None;
    }
    Some((size, &b[o + 2..o + 2 + size], o + 2 + size))
}

/// Parse a full `TPMS_ATTEST` of type QUOTE.
fn parse_attest(att: &[u8]) -> Result<Attest, String> {
    if att.len() < 4 {
        return Err("attestation too short".into());
    }
    let magic = u32::from_be_bytes([att[0], att[1], att[2], att[3]]);
    if magic != ATTEST_MAGIC {
        return Err(format!("bad attestation magic 0x{magic:08X}"));
    }
    let typ = u16::from_be_bytes([att[4], att[5]]);
    if typ != ATTEST_QUOTE {
        return Err(format!("unexpected attestation type 0x{typ:04X}"));
    }
    let (_qs_size, qualified_signer, mut off) =
        read_tpm2b(att, 6).ok_or_else(|| "truncated qualifiedSigner".to_string())?;
    let (_ed_size, qualified_data, off2) =
        read_tpm2b(att, off).ok_or_else(|| "truncated extraData".to_string())?;
    off = off2;
    // clockInfo (u64 u32 u32 u8) + firmwareVersion (u64)
    off += 8 + 4 + 4 + 1 + 8;
    if att.len() < off + 4 {
        return Err("truncated pcrSelect count".into());
    }
    let sel_count = u32::from_be_bytes([att[off], att[off + 1], att[off + 2], att[off + 3]]) as usize;
    off += 4;
    let mut pcr_selections = Vec::new();
    for _ in 0..sel_count {
        if att.len() < off + 3 {
            return Err("truncated pcrSelect".into());
        }
        let sel_size = att[off + 2] as usize;
        if att.len() < off + 3 + sel_size {
            return Err("truncated pcrSelect bytes".into());
        }
        pcr_selections.push(att[off..off + 3 + sel_size].to_vec());
        off += 3 + sel_size;
    }
    let (_d_size, pcr_digest, _off2) =
        read_tpm2b(att, off).ok_or_else(|| "truncated pcrDigest".to_string())?;
    Ok(Attest {
        qualified_signer: qualified_signer.to_vec(),
        qualified_data: qualified_data.to_vec(),
        pcr_selections,
        pcr_digest: pcr_digest.to_vec(),
    })
}

/// `Name(TPMT_PUBLIC)` = `nameAlg || H(public)` (TPM 2.0 Part 1, 16.8).
fn public_name(name_alg: u16, public: &[u8]) -> Result<Vec<u8>, String> {
    if name_alg != alg::SHA256 {
        return Err(format!("AK nameAlg is 0x{name_alg:04X}, expected SHA256"));
    }
    let mut out = name_alg.to_be_bytes().to_vec();
    out.extend_from_slice(&Sha256::digest(public));
    Ok(out)
}

/// The hierarchy `create_primary_ecc_sign` creates the AK in: the standard
/// OWNER handle (matches `bootproof_tpm::commands_key::create_primary_ecc_sign`).
const AK_PARENT: u32 = 0x4000_0001;

/// The qualified Name of a primary object: `nameAlg || H(parent || name)`,
/// where parent is the 4-byte big-endian parent hierarchy handle. This is
/// what the TPM reports as `qualifiedSigner` in a QUOTE attestation
/// (verified against a live AWS NitroTPM).
fn qualified_name(name: &[u8], parent: u32) -> Vec<u8> {
    let mut out = name[..2].to_vec();
    let mut h = Sha256::new();
    h.update(parent.to_be_bytes());
    h.update(name);
    out.extend_from_slice(&h.finalize());
    out
}

/// The slot-link decision, factored out as a pure function of the
/// attested PCR22 (if any) and the other channels' docs, so it can be
/// unit-tested against synthetic values without a TPM.
///
/// The node folds only when it actually can (other docs exist, and
/// PCR_Reset + PCR_Extend both succeed), and it includes the slot PCR in
/// the quote only after a successful fold. So the expected value is
/// deterministic: the node reset PCR22 to zero, then extended it with
/// H(concat other docs), i.e. PCR22 == H(0^32 || H(docs)).
///
/// - `slot_actual == None`            -> `NoSlotPcr` (fold not available)
/// - `slot_actual == H(0^32 || H(d))` -> `Proven`
/// - anything else                    -> `Mismatched`
pub fn slot_link_decision(slot_actual: Option<&[u8]>, other_docs: &[Vec<u8>]) -> SlotLink {
    let slot = match slot_actual {
        None => return SlotLink::NoSlotPcr,
        Some(d) => d,
    };
    let mut concat = Vec::new();
    for d in other_docs {
        concat.extend_from_slice(d);
    }
    let h_docs = Sha256::digest(&concat);
    let mut m = Sha256::new();
    m.update([0u8; 32]); // the PCR pre-state after TPM2_PCR_Reset
    m.update(h_docs);
    let expected = m.finalize();
    if slot == expected.as_slice() {
        SlotLink::Proven
    } else {
        SlotLink::Mismatched
    }
}

pub struct Tpm2Verifier;

impl Verifier for Tpm2Verifier {
    fn name(&self) -> &'static str {
        "tpm2"
    }

    fn verify(
        &self,
        ev: &Evidence,
        nonce: &[u8; 32],
        bundle: &Bundle,
    ) -> Result<Verified, String> {
        let doc = &ev.doc.0;
        if doc.is_empty() || doc[0] != 1 {
            return Err("tpm2 doc: unsupported version".into());
        }
        let mut off = 1usize;
        let (_a_size, quote_attest, o) =
            read_tpm2b(doc, off).ok_or_else(|| "tpm2 doc: truncated attest".to_string())?;
        off = o;
        let (_k_size, ak_public, o) =
            read_tpm2b(doc, off).ok_or_else(|| "tpm2 doc: truncated ak_public".to_string())?;
        off = o;
        let (_r_size, sig_r, o) =
            read_tpm2b(doc, off).ok_or_else(|| "tpm2 doc: truncated sig_r".to_string())?;
        off = o;
        let (_s_size, sig_s, o) =
            read_tpm2b(doc, off).ok_or_else(|| "tpm2 doc: truncated sig_s".to_string())?;
        off = o;
        let (_p_size, per_pcr, _o2) =
            read_tpm2b(doc, off).ok_or_else(|| "tpm2 doc: truncated per_pcr".to_string())?;

        // 1-2. Attestation structure + nonce binding.
        let attest = parse_attest(quote_attest)?;
        if attest.qualified_data != nonce {
            return Err("nonce mismatch: qualifiedData != challenge nonce (replay?)".into());
        }

        // 3. AK public area + Name check.
        let ak = parse_public_area(ak_public).map_err(|e| format!("AK public: {e}"))?;
        if ak.curve != alg::EC_P256 {
            return Err(format!("AK curve is 0x{:04X}, expected P-256", ak.curve));
        }
        let ak_name = public_name(ak.name_alg, ak_public)?;
        // The AK is a primary object in the OWNER hierarchy, so the TPM
        // reports its qualified Name: nameAlg || H(0x40000001 || name).
        let qualified = qualified_name(&ak_name, AK_PARENT);
        if attest.qualified_signer != qualified && attest.qualified_signer != ak_name {
            return Err("qualifiedSigner != qualified Name(AK public)".into());
        }

        // 4. ECDSA-SHA256 signature over the attestation bytes.
        let mut sec1 = vec![0x04u8];
        sec1.extend_from_slice(&ak.unique_x);
        sec1.extend_from_slice(&ak.unique_y);
        let pk = p256::PublicKey::from_sec1_bytes(&sec1)
            .map_err(|e| format!("AK public key: {e}"))?;
        let point = pk.as_affine().to_curve();
        let mut sig_bytes = sig_r.to_vec();
        sig_bytes.extend_from_slice(sig_s);
        let sig = ecdsa::Signature::<p256::NistP256>::from_slice(&sig_bytes)
            .map_err(|e| format!("quote signature: {e}"))?;
        let digest = Sha256::digest(quote_attest);
        ecdsa::hazmat::verify_prehashed(&point, &digest, &sig)
            .map_err(|e| format!("quote signature invalid: {e}"))?;

        // 5. Derive the attested PCR set from the (AK-signed) quote selection.
        //    The set is discovered per-TPM at attestation time, so the
        //    verifier must not assume a fixed canonical set -- it reads the
        //    indices the quote actually bound.
        let quote_sels: Vec<PcrSelection> = attest
            .pcr_selections
            .iter()
            .map(|s| PcrSelection::from_raw(s))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| "quote selection malformed".to_string())?;
        if quote_sels.len() != 1 {
            return Err("expected exactly one PCR selection in the quote".into());
        }
        let indices = quote_sels[0].indices();
        if indices.is_empty() {
            return Err("quote selected no PCRs".into());
        }

        // Per-PCR values determine the signed digest (each SHA256 digest is
        // 32 bytes, in ascending index order).
        if per_pcr.len() != indices.len() * 32 {
            return Err(format!(
                "per_pcr length {}: expected {} digests",
                per_pcr.len(),
                indices.len()
            ));
        }
        let per_pcr: Vec<(u8, Vec<u8>)> = indices
            .iter()
            .enumerate()
            .map(|(i, idx)| {
                let d = &per_pcr[i * 32..i * 32 + 32];
                (*idx, d.to_vec())
            })
            .collect();
        let mut h = Sha256::new();
        for (_, d) in &per_pcr {
            h.update(d);
        }
        if h.finalize().to_vec() != attest.pcr_digest {
            return Err("per-PCR digests do not hash to the quote pcrDigest".into());
        }

        // 6. Slot link: the node resets PCR22 to zero and (when other
        //    channels exist) extends it with H(other docs), so the expected
        //    value is deterministic: H(0^32 || H(docs)), or all-zero when
        //    there was nothing to fold. A PCR22 that is not in the quote
        //    means the node's TPM has no usable slot PCR (AWS NitroTPM
        //    exposes only PCRs 0-9; a virtual TPM may lock PCR22 behind
        //    locality 3) -- an honest hardware boundary, not an integrity
        //    failure.
        let other_docs: Vec<Vec<u8>> = bundle
            .evidence
            .iter()
            .filter(|e| e.channel != "tpm2")
            .map(|e| e.doc.0.clone())
            .collect();
        let slot_actual = per_pcr
            .iter()
            .find(|(i, _)| *i == crate::attest::tpm2::SLOT_PCR)
            .map(|(_, d)| d.as_slice());
        let slot_link = slot_link_decision(slot_actual, &other_docs);
        // A mismatch is a real integrity failure: the quote bound a PCR22
        // that is neither the node's fold nor a measured boot state. Fail the
        // channel loudly (this is also the documented tpm2 contract: every
        // fact it emits comes from a fully verified quote).
        if matches!(slot_link, SlotLink::Mismatched) {
            return Err(format!(
                "PCR{} in the quote does not match the cross-channel fold \
                 (H(0 || H(other docs))); integrity failure",
                crate::attest::tpm2::SLOT_PCR
            ));
        }

        // 7. Sign key policy == the attested state. The quote echoes the
        // selection the TPM used; recompute the expected authPolicy from
        // the selection + per-PCR digests and compare.

        let (sign_public, sign_policy, sign_pcrs) = match &bundle.keys {
            Some(k) => match &k.sign {
                Some(sk) => {
                    let expected = policy_pcr_auth_policy(&quote_sels, &per_pcr);
                    let pa = parse_public_area(&sk.pub_.0)
                        .map_err(|e| format!("sign key public: {e}"))?;
                    if pa.auth_policy != expected {
                        return Err(
                            "sign key authPolicy != PolicyPCR(quote selection, per-PCR digests)"
                                .into(),
                        );
                    }
                    (
                        Some(sk.pub_.0.clone()),
                        Some(pa.auth_policy),
                        Some(indices.clone()),
                    )
                }
                None => (None, None, None),
            },
            None => (None, None, None),
        };

        let ek_cert = ev.anchors.get("ek_cert").map(|b| b.0.clone());

        Ok(Verified::Tpm2(Tpm2Verified {
            per_pcr,
            ak_public: ak_public.to_vec(),
            sign_public,
            sign_policy,
            sign_pcrs,
            slot_link,
            ek_cert,
        }))
    }

    fn facts(&self, v: &Verified) -> Vec<Fact> {
        let Verified::Tpm2(v) = v else {
            unreachable!("tpm2 facts called with a non-tpm2 Verified")
        };
        let mut facts = Vec::new();

        facts.push(Fact {
            name: "tpm_quote".into(),
            value: format!(
                "nonce-bound quote over {} PCRs; AK ECDSA-SHA256 signature valid",
                v.per_pcr.len()
            ),
            anchors: vec!["tpm2".into()],
            status: Status::Proven,
        });

        let pcr_hex: Vec<String> = v
            .per_pcr
            .iter()
            .map(|(i, d)| format!("PCR{i:02}={}", hex(d)))
            .collect();
        facts.push(Fact {
            name: "pcr_state".into(),
            value: pcr_hex.join(" "),
            anchors: vec!["tpm2".into()],
            status: Status::Proven,
        });

        facts.push(Fact {
            name: "slot_link".into(),
            value: match v.slot_link {
                SlotLink::Proven => format!(
                    "PCR{} binds the other channels' docs",
                    crate::attest::tpm2::SLOT_PCR
                ),
                SlotLink::Mismatched => format!(
                    "PCR{} does not match the other channels' docs",
                    crate::attest::tpm2::SLOT_PCR
                ),
                SlotLink::NoSlotPcr => format!(
                    "PCR{} not present on this TPM; cross-channel fold not available",
                    crate::attest::tpm2::SLOT_PCR
                ),
            },
            anchors: vec!["tpm2".into()],
            status: match v.slot_link {
                SlotLink::Proven => Status::Proven,
                _ => Status::NotProven,
            },
        });

        if let (Some(pub_), Some(pcrs)) = (&v.sign_public, v.sign_pcrs.as_ref()) {
            let _ = pub_;
            facts.push(Fact {
                name: "sign_key".into(),
                value: format!(
                    "P-256 ecdsa-sha256, PCR policy bound to [{}]",
                    pcrs.iter()
                        .map(|i| i.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                anchors: vec!["tpm2".into()],
                status: Status::Proven,
            });
        } else {
            facts.push(Fact {
                name: "sign_key".into(),
                value: "no state-bound sign key published".into(),
                anchors: vec!["tpm2".into()],
                status: Status::NotProven,
            });
        }

        facts.push(match &v.ek_cert {
            Some(c) => Fact {
                name: "ek_cert".into(),
                value: format!("present ({} bytes); chain not verified in this build", c.len()),
                anchors: vec!["tpm2".into()],
                status: Status::Degraded,
            },
            None => Fact {
                name: "ek_cert".into(),
                value: "absent from the node".into(),
                anchors: vec!["tpm2".into()],
                status: Status::NotProven,
            },
        });

        facts.push(Fact {
            name: "image_hash".into(),
            value: "SHA-384 PCR17 (later phase)".into(),
            anchors: vec!["tpm2".into()],
            status: Status::NotProven,
        });
        // NOTE: the `memory_encryption` fact is owned by the snp channel
        // (verify::snp::SnpVerifier): proven from a verified SEV-SNP report,
        // NOT PROVEN with a reason when the channel is present but failing,
        // or NOT PROVEN "absent" when the node does not serve snp at all.
        // The tpm2 channel never claims it.
        facts.push(Fact {
            name: "enc_key".into(),
            value: "ECDH encrypt-to-machine (later phase)".into(),
            anchors: vec!["tpm2".into()],
            status: Status::NotProven,
        });
        facts
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::channel::SlotLink;
    use sha2::Sha256;

    /// The node's expected PCR22 value: reset to zero, then extend with
    /// H(concat other docs) -> H(0^32 || H(docs)).
    fn expected_fold(other_docs: &[Vec<u8>]) -> Vec<u8> {
        let mut concat = Vec::new();
        for d in other_docs {
            concat.extend_from_slice(d);
        }
        let h_docs = Sha256::digest(&concat);
        let mut m = Sha256::new();
        m.update([0u8; 32]);
        m.update(h_docs);
        m.finalize().to_vec()
    }

    #[test]
    fn slot_link_proven_when_fold_matches() {
        let docs = vec![vec![0x01, 0x02, 0x03], vec![0xAA, 0xBB]];
        let expected = expected_fold(&docs);
        assert_eq!(slot_link_decision(Some(&expected), &docs), SlotLink::Proven);
    }

    #[test]
    fn slot_link_proven_with_empty_docs() {
        // No other docs: the node folded H(empty) from a zeroed PCR.
        let expected = expected_fold(&[]);
        assert_eq!(slot_link_decision(Some(&expected), &[]), SlotLink::Proven);
    }

    #[test]
    fn slot_link_mismatched_on_wrong_value() {
        let docs = vec![vec![0x01, 0x02, 0x03]];
        let wrong = vec![0xDE; 32];
        assert_ne!(wrong, expected_fold(&docs));
        assert_eq!(slot_link_decision(Some(&wrong), &docs), SlotLink::Mismatched);
    }

    #[test]
    fn slot_link_absent_when_pcr22_not_in_quote() {
        let docs = vec![vec![0x01, 0x02, 0x03]];
        assert_eq!(slot_link_decision(None, &docs), SlotLink::NoSlotPcr);
        assert_eq!(slot_link_decision(None, &[]), SlotLink::NoSlotPcr);
    }
}
