//! The tpm2 verifier: check the AK quote, the slot link, and the state-bound
//! sign key -- all offline, from the Bundle.
//!
//! Checks (in order):
//! 1. Doc parses (v1 layout).
//! 2. `TPMS_ATTEST` magic + type QUOTE; `qualifiedData == nonce`.
//! 3. `qualifiedSigner == Name(AK public)` (Name = nameAlg || H(0x0013 || public)).
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

use crate::channel::{Tpm2Verified, Verified, Verifier};
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

/// `Name(TPMT_PUBLIC)` = `nameAlg || H(0x0013 || public)`.
fn public_name(name_alg: u16, public: &[u8]) -> Result<Vec<u8>, String> {
    if name_alg != alg::SHA256 {
        return Err(format!("AK nameAlg is 0x{name_alg:04X}, expected SHA256"));
    }
    let mut h = Sha256::new();
    h.update([0x00u8, 0x13]);
    h.update(public);
    let d = h.finalize();
    let mut out = name_alg.to_be_bytes().to_vec();
    out.extend_from_slice(&d);
    Ok(out)
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
        if attest.qualified_signer != ak_name {
            return Err("qualifiedSigner != Name(AK public)".into());
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

        // 6. Slot link: PCR22 == SHA256(concat of other channels' docs), but
        //    only when other channels exist and this TPM has a slot PCR.
        let has_other = bundle.evidence.iter().any(|e| e.channel != "tpm2");
        let slot_expected = {
            let mut other = Vec::new();
            for e in &bundle.evidence {
                if e.channel != "tpm2" {
                    other.extend_from_slice(&e.doc.0);
                }
            }
            Sha256::digest(&other).to_vec()
        };
        let slot_actual = per_pcr
            .iter()
            .find(|(i, _)| *i == crate::attest::tpm2::SLOT_PCR)
            .map(|(_, d)| d.clone());
        let slot_link = match slot_actual {
            Some(actual) if has_other => actual == slot_expected,
            _ => false, // no other channels to bind, or no slot PCR on this TPM
        };

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
        let Verified::Tpm2(v) = v;
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
            value: if v.slot_link {
                format!("PCR{} binds the other channels' docs", crate::attest::tpm2::SLOT_PCR)
            } else {
                "PCR22 does not match the other channels' docs".into()
            },
            anchors: vec!["tpm2".into()],
            status: if v.slot_link {
                Status::Proven
            } else {
                Status::NotProven
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
        facts.push(Fact {
            name: "memory_encryption".into(),
            value: "no SEV-SNP channel on this node".into(),
            anchors: vec![],
            status: Status::NotProven,
        });
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
