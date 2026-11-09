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

/// The NSM identity-doc check legs that need the AWS Nitro PKI path: the
/// COSE_Sign1 signature + cert chain to the baked root + nonce echo.
/// `bootproof_sdk::format::nitro::Nitro::verify` owns that machinery (it
/// already gates the sdk's own attestation flow); the bootproof core
/// reuses it rather than re-implementing COSE/webpki here -- the
/// governing principle in reverse: ONE implementation of each vendor
/// verifier, consumed through the registry, never forked.
fn nsm_sig_chain_nonce_ok(doc_bytes: &[u8], nonce: &[u8], at_secs: u64) -> Result<(), String> {
    use bootproof_sdk::format::nitro::{Nitro, NitroPcrs};
    use bootproof_sdk::format::VerifiableSignedAttestationFormat;
    use std::collections::HashMap;
    use std::time::Duration;
    // Empty PCR policy: the sdk verifies signature + chain + nonce with no
    // PCR pin. PCR agreement between the NSM doc and the TPM quote is NOT
    // checked here on purpose -- the two are different PCRs (NSM reports
    // SHA-384 enclave/NitroTPM PCRs; the quote is SHA-256 over the
    // platform set) and pinning their correspondence is a separate,
    // explicitly-scoped contract extension. The AK public-area equality
    // is the binding.
    let pcrs: NitroPcrs = HashMap::new();
    Nitro::with_pcr_policy(doc_bytes.to_vec(), pcrs)
        // `&&[u8]`: the sealed AsNonce blanket impl covers sized types, so
        // the slice reference itself is the nonce value.
        .verify(Duration::from_secs(at_secs), &nonce)
        .map(|_| ())
        .map_err(|e| format!("nsm doc: {e}"))
}

/// Pure NSM binding decision (factored out so the arms are testable with
/// an explicit `now`; `verify()` calls it with the wall clock).
///
/// `ak_public` is the RAW TPMT_PUBLIC bytes the quote was signed by
/// (already signature-verified by the caller). Freshness design:
///   * REPLAY is bound by the nonce: the doc signs `nonce == this
///     challenge`, so an old doc cannot answer a new challenge.
///   * STALENESS is bound by the AWS cert validity window: the chain
///     check runs at the wall clock, and the NSM signing cert is valid
///     for ~3 hours around issuance, so a doc older than that window
///     fails closed through webpki (`CertExpired`). A live capture proves
///     the window (measured: notBefore/notAfter 2h57m apart on the
///     fixture leaf). No separate max-age constant exists to get wrong.
/// `now_secs` is therefore ONLY an injectable test seam for the wall
/// clock; production always passes the real clock.
fn nsm_binding_decision(
    anchor: Option<&[u8]>,
    nonce: &[u8],
    ak_public: &[u8],
    now_secs: u64,
) -> crate::channel::NsmBinding {
    use crate::channel::NsmBinding;
    let Some(doc_bytes) = anchor else {
        return NsmBinding::Absent;
    };
    // Parse first: the public_key + module_id echo what AWS signed.
    let facts = match bootproof_tpm::attest::parse_attestation_document(doc_bytes) {
        Ok(f) => f,
        Err(e) => return NsmBinding::Failed(format!("nsm doc: {e}")),
    };
    // Leg (a): COSE signature + chain to the baked Nitro root + the nonce
    // echo. Runs at `now` in production: an expired doc (a replay older
    // than the ~3h cert window) fails here, loudly.
    if let Err(e) = nsm_sig_chain_nonce_ok(doc_bytes, nonce, now_secs) {
        return NsmBinding::Failed(e);
    }
    // Leg (b): THE decisive assertion. The doc's `public_key` is the
    // AWS-signed statement of "the attestation key on this module". It
    // must equal the TPMT_PUBLIC that signed the quote, byte for byte.
    // Anything else is forged-identity territory: fail closed, loudly.
    nsm_ak_match_arm(facts.public_key.as_deref(), ak_public, &facts.module_id)
}

/// The AK-equality arm, factored out so the decisive byte comparison is
/// unit-witnessed on all three sub-arms (match / mismatch / absent) even
/// though no committed fixture carries a non-null signed public_key
/// (measured: nsm-live.cbor and aws-test.cbor both captured
/// public_key == CBOR null 0xf6 -- the captures predate the public_key
/// request). The PROVEN end-to-end arm rides the live NitroTPM gate
/// (CAST-3): a genuine doc with a signed AK exists only on NitroTPM
/// hardware with the scratch index defined, exactly like the ek-cert live
/// witness. What is witnessed here: the equality gate passes ONLY on
/// byte-exact equality, and every other arm fails closed with a loud
/// reason.
fn nsm_ak_match_arm(
    signed_pk: Option<&[u8]>,
    ak_public: &[u8],
    module_id: &str,
) -> crate::channel::NsmBinding {
    use crate::channel::NsmBinding;
    match signed_pk {
        Some(pk) if pk == ak_public => NsmBinding::Proven { module_id: module_id.into() },
        Some(pk) => NsmBinding::Failed(format!(
            "nsm doc public_key ({} bytes) != AK public area ({} bytes) that signed the quote: \
             the vendor-signed identity is NOT the key producing these quotes",
            pk.len(),
            ak_public.len()
        )),
        None => NsmBinding::Failed(
            "nsm doc carries no public_key: the node requested no AK binding".into(),
        ),
    }
}

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

        // 8. The NitroNSM identity binding (NitroTPM's answer to the NV EK
        //    cert): an AWS-signed doc naming THIS AK for THIS nonce. The
        //    wall clock is the freshness leg (cert window); the nonce is
        //    the replay leg. Both inside the pure decision fn so the
        //    stale-doc and decoy arms are testable without hardware.
        let nsm_binding = nsm_binding_decision(
            ev.anchors.get("nsm_doc").map(|b| b.0.as_slice()),
            nonce,
            ak_public,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0), // clock before 1970: every doc fails the chain check, fail closed
        );

        Ok(Verified::Tpm2(Tpm2Verified {
            per_pcr,
            ak_public: ak_public.to_vec(),
            sign_public,
            sign_policy,
            sign_pcrs,
            slot_link,
            ek_cert,
            nsm_binding,
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

        // The AK identity binding. Three states, kept structurally
        // distinct (honest absence != present-but-failed):
        //   PROVEN      -- AWS signed "this AK, this nonce", chain + echo
        //                  verify: the quote-signing key is vendor-attested.
        //   NOT PROVEN  -- two spellings, both honest, one in the value:
        //                  absent (non-Nitro or the node could not produce
        //                  a doc) vs a FAILED binding (never promoted to
        //                  Proven, never silently dropped).
        facts.push(match &v.nsm_binding {
            crate::channel::NsmBinding::Proven { module_id } => Fact {
                name: "nsm_ak_binding".into(),
                value: format!(
                    "AWS Nitro-signed identity doc chains to the baked root, echoes the nonce, \
                     and names this quote's AK (module {module_id})"
                ),
                anchors: vec!["tpm2".into()],
                status: Status::Proven,
            },
            crate::channel::NsmBinding::Absent => Fact {
                name: "nsm_ak_binding".into(),
                value: "absent: node served no NSM identity doc (non-Nitro platform, or the \
                     NitroTPM NSM leg was unavailable)".into(),
                anchors: vec!["tpm2".into()],
                status: Status::NotProven,
            },
            crate::channel::NsmBinding::Failed(reason) => Fact {
                name: "nsm_ak_binding".into(),
                value: format!("identity doc present but FAILED: {reason}"),
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

    // ---- NSM AK binding: the three belt arms, all hardware-free --------
    //
    // Two witness layers, no hardware:
    //
    // A. THE DECISIVE GATE (unit, exhaustive): nsm_ak_match_arm is the
    //    byte-equality check itself. All three sub-arms witness here:
    //    byte-exact match -> Proven; same-length decoy -> Failed, loud,
    //    distinct reason; absent key -> Failed. This is the check the
    //    belt demands be decisive, and it is fully witnessed.
    //
    // B. THE PIPELINE (fixture): the live NitroTPM document (nsm-live
    //    .cbor, AWS-signed, chain to the baked root) drives the full
    //    decision: nonce echo, chain validity window (measured: the leaf
    //    cert is valid ~3h around issuance 2026-08-26 07:41..10:41 UTC,
    //    so the fixture is EXPIRED at any real "now" today -> the stale
    //    arm is the natural fixture behavior), and fail-closed-on-null-
    //    public_key (measured: both committed fixtures captured
    //    public_key == null 0xf6, so a GENUINE fixture doc at its own
    //    valid time must still FAIL the binding, never pass it silently).
    //    The end-to-end PROVEN leg (genuine doc + signed AK) requires
    //    live NitroTPM hardware with the scratch NV index defined and is
    //    the CAST-3 live gate, exactly like the ek-cert live witness.

    /// The live NitroTPM document captured by the sdk (the same bytes the
    /// sdk's `nsm_live_doc_full_verify` gates: one fixture, two crates).
    const NSM_LIVE: &[u8] =
        include_bytes!("../../../bootproof-sdk/src/format/data/nsm-live.cbor");

    fn fixture_parts() -> (Vec<u8>, u64) {
        let f = bootproof_tpm::attest::parse_attestation_document(NSM_LIVE)
            .expect("the live fixture parses");
        let nonce = f.nonce.expect("the live fixture echoes a nonce");
        (nonce, f.timestamp_ms / 1000)
    }

    // -- A. the decisive gate, witnessed exhaustively ------------------

    #[test]
    fn ak_gate_byte_exact_match_proves() {
        let ak = vec![0x00, 0x21, 0x00, 0x44, 0xAA, 0xBB];
        let b = nsm_ak_match_arm(Some(&ak), &ak, "i-0abc-tpm0000000000000000");
        match b {
            crate::channel::NsmBinding::Proven { module_id } => {
                assert_eq!(module_id, "i-0abc-tpm0000000000000000");
            }
            other => panic!("byte-exact equality must PROVEN, got {other:?}"),
        }
    }

    #[test]
    fn ak_gate_same_length_decoy_fails_closed_loudly() {
        // The attack the belt names: a genuine AWS-signed doc bound to a
        // DIFFERENT key than the quote's AK. One byte differs, so only a
        // byte-exact check can catch it. Must be Failed with the AK
        // mismatch named in the reason -- never a silent pass, never the
        // Absent spelling.
        let ak = vec![0x00, 0x21, 0x00, 0x44, 0xAA, 0xBB];
        let mut decoy = ak.clone();
        decoy[4] ^= 0xFF;
        let b = nsm_ak_match_arm(Some(&decoy), &ak, "i-0abc-tpm0000000000000000");
        match b {
            crate::channel::NsmBinding::Failed(reason) => {
                assert!(
                    reason.contains("public_key") && reason.contains("!= AK public area"),
                    "decoy must name the AK mismatch loudly: {reason}"
                );
            }
            other => panic!("decoy AK must FAIL, got {other:?}"),
        }
        // And the reverse roles (decoy signed, genuine claimed): same
        // failure, different lengths must also fail (size equality is
        // never the check).
        let b2 = nsm_ak_match_arm(Some(&decoy[..5]), &ak, "m");
        assert!(matches!(b2, crate::channel::NsmBinding::Failed(_)));
    }

    #[test]
    fn ak_gate_absent_key_fails_closed() {
        let ak = vec![0x00, 0x21];
        let b = nsm_ak_match_arm(None, &ak, "m");
        match b {
            crate::channel::NsmBinding::Failed(reason) => {
                assert!(reason.contains("no public_key"), "reason: {reason}");
            }
            other => panic!("absent signed key must FAIL, got {other:?}"),
        }
    }

    // -- B. the pipeline over the real AWS-signed fixture ---------------

    #[test]
    fn fixture_genuine_doc_at_issue_time_still_fails_closed_on_null_ak() {
        // The fixtures captured public_key == null (measured 0xf6), so
        // even with a VALID chain (verified at the doc's own timestamp,
        // the sdk test's technique) and the right nonce, the binding
        // must fail closed on the AK leg. Fail-closed beats pass-by-
        // omission: a node that requests no AK binding gets NOT PROVEN
        // with a reason, never a free Proven.
        let (nonce, ts) = fixture_parts();
        let b = nsm_binding_decision(Some(NSM_LIVE), &nonce, b"whatever-ak", ts);
        match b {
            crate::channel::NsmBinding::Failed(reason) => {
                assert!(
                    reason.contains("no public_key"),
                    "pipeline must reach the AK leg and fail there: {reason}"
                );
            }
            other => panic!("null-key fixture must FAIL, got {other:?}"),
        }
    }

    #[test]
    fn nsm_binding_wrong_nonce_fails_closed() {
        let (mut nonce, ts) = fixture_parts();
        nonce[0] ^= 0xFF;
        let b = nsm_binding_decision(Some(NSM_LIVE), &nonce, b"whatever-ak", ts);
        assert!(
            matches!(b, crate::channel::NsmBinding::Failed(_)),
            "a replayed doc against a fresh challenge must FAIL, got {b:?}"
        );
    }

    #[test]
    fn nsm_binding_stale_at_wall_clock_fails_closed() {
        // The replay bound: the fixture's signing cert expired hours after
        // issuance (measured window 2026-08-26 07:41..10:41 UTC). At the
        // real wall clock the chain check must reject it -- a captured doc
        // cannot be replayed forever even if someone reused its nonce.
        let (nonce, _ts) = fixture_parts();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now > 1_756_200_000, "test clock sanity (post 2025-08-26)");
        let b = nsm_binding_decision(Some(NSM_LIVE), &nonce, b"whatever-ak", now);
        match b {
            crate::channel::NsmBinding::Failed(reason) => {
                // webpki's expired verdict surfaces through the sdk error.
                assert!(!reason.is_empty(), "stale doc must fail with a reason");
            }
            other => panic!("stale doc at wall clock must FAIL, got {other:?}"),
        }
    }

    #[test]
    fn nsm_binding_absent_is_distinct_from_failed() {
        use crate::channel::NsmBinding;
        // Arm 3's structural-distinctness half: honest absence and a
        // present-but-failed doc are different states (the ek_cert split
        // pattern) and must stay distinct at BOTH the decision and the
        // fact layer.
        let absent = nsm_binding_decision(None, &[7u8; 32], &[0u8; 8], 0);
        assert_eq!(absent, NsmBinding::Absent);

        let v_absent = Verified::Tpm2(Tpm2Verified {
            per_pcr: Vec::new(),
            ak_public: Vec::new(),
            sign_public: None,
            sign_policy: None,
            sign_pcrs: None,
            slot_link: SlotLink::NoSlotPcr,
            ek_cert: None,
            nsm_binding: NsmBinding::Absent,
        });
        let mut v_failed = match v_absent {
            Verified::Tpm2(v) => v,
            _ => unreachable!(),
        };
        v_failed.nsm_binding = NsmBinding::Failed("decoy".into());

        let f = Tpm2Verifier;
        let facts_absent = f.facts(&Verified::Tpm2(Tpm2Verified {
            nsm_binding: NsmBinding::Absent,
            ..clone_tpm2(&v_failed)
        }));
        let fact_absent = facts_absent.iter().find(|x| x.name == "nsm_ak_binding").unwrap();
        let facts_failed = f.facts(&Verified::Tpm2(v_failed));
        let fact_failed = facts_failed.iter().find(|x| x.name == "nsm_ak_binding").unwrap();

        // Same name, same status vocabulary (NotProven -- no red status
        // exists in the wire contract), but structurally distinct VALUES:
        // "absent:" vs "identity doc present but FAILED:". Neither is
        // silently dropped; neither is ever Proven by construction.
        assert_eq!(fact_absent.status, Status::NotProven);
        assert_eq!(fact_failed.status, Status::NotProven);
        assert!(fact_absent.value.starts_with("absent:"), "absent spelling: {}", fact_absent.value);
        assert!(
            fact_failed.value.contains("present but FAILED"),
            "failed spelling: {}",
            fact_failed.value
        );
        assert_ne!(fact_absent.value, fact_failed.value);
    }

    // Helper: Tpm2Verified is not Clone (holds Vecs only, but no derive);
    // the distinctness test needs two copies differing in one field.
    fn clone_tpm2(v: &Tpm2Verified) -> Tpm2Verified {
        Tpm2Verified {
            per_pcr: v.per_pcr.clone(),
            ak_public: v.ak_public.clone(),
            sign_public: v.sign_public.clone(),
            sign_policy: v.sign_policy.clone(),
            sign_pcrs: v.sign_pcrs.clone(),
            slot_link: v.slot_link,
            ek_cert: v.ek_cert.clone(),
            nsm_binding: v.nsm_binding.clone(),
        }
    }
}
