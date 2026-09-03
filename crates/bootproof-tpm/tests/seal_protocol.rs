//! Live, incremental tests for the tpm2-protocol-based seal flow.
//!
//! Each test is self-contained: it builds its own commands with the
//! `tpm2-protocol` crate, sends them over bootproof's transport, and asserts
//! the round-trip. Run against the in-tree swtpm (libtpms 0.10.2):
//!
//! ```sh
//! BOOTPROOF_SWPTM=/tmp/swptpm2/tpm.sock cargo test -p bootproof-tpm --test seal_protocol
//! ```

use tpm2_protocol::basic::TpmHandle;
use tpm2_protocol::data::TpmSt;
use tpm2_protocol::frame::tpm_marshal_command;
use tpm2_protocol::TpmWriter;

use bootproof_tpm::Tpm;

fn tpm() -> Tpm {
    use tpm2_protocol::frame::TpmFlushContextCommand;
    let sock = std::env::var("BOOTPROOF_SWPTM").unwrap_or_else(|_| "/tmp/swptpm2/tpm.sock".into());
    let mut tpm: Tpm = Tpm::connect_swtpm_unix(std::path::Path::new(&sock)).unwrap();
    tpm.ensure_started().unwrap();
    // Free transient slots leaked by earlier runs (the swtpm's pool is small;
    // a full pool makes the next CreatePrimary fail 0x0902 OBJECT_MEMORY).
    for h in 0x8000_0000u32..=0x8000_001F {
        let cmd = TpmFlushContextCommand {
            handles: [],
            flush_handle: TpmHandle::new(h),
        };
        let _ = tpm.transfer(&marshal_cmd(&cmd, TpmSt::NoSessions, &[]));
    }
    // ...and leaked auth sessions (a full pool is 0x090B SESSION_MEMORY).
    // libtpms assigns HMAC sessions at 0x11000000+i, policy at 0x12000000+i,
    // MAX_ACTIVE_SESSIONS = 64 each.
    for h in 0x1100_0000u32..=0x1100_003F {
        let cmd = TpmFlushContextCommand {
            handles: [],
            flush_handle: TpmHandle::new(h),
        };
        let _ = tpm.transfer(&marshal_cmd(&cmd, TpmSt::NoSessions, &[]));
    }
    for h in 0x1200_0000u32..=0x1200_003F {
        let cmd = TpmFlushContextCommand {
            handles: [],
            flush_handle: TpmHandle::new(h),
        };
        let _ = tpm.transfer(&marshal_cmd(&cmd, TpmSt::NoSessions, &[]));
    }
    tpm
}

/// Marshal a command with `tpm_marshal_command` into a wire-ready Vec.
fn marshal_cmd<C>(cmd: &C, tag: TpmSt, sessions: &[tpm2_protocol::data::TpmsAuthCommand]) -> Vec<u8>
where
    C: tpm2_protocol::frame::TpmFrame,
{
    let mut buf = vec![0u8; 4096];
    let len = {
        let mut w = TpmWriter::new(&mut buf);
        tpm_marshal_command(cmd, tag, sessions, &mut w).unwrap();
        w.len()
    };
    buf.truncate(len);
    buf
}

/// Test 1: CreatePrimary (AES-128-CFB storage parent, empty-auth HMAC
/// session) round-trips with rc=0 and unmarshals into the typed response.
#[test]
fn t01_create_primary_storage_parent() {
    use digest::Digest;
    use hmac::{Hmac, Mac};
    use tpm2_protocol::data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bPublic,
        Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId, TpmSe, TpmaObject,
        TpmaSession, TpmsAuthCommand, TpmsSensitiveCreate, TpmsSymcipherParms, TpmtPublic,
        TpmtSymDef, TpmlPcrSelection, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    };
    use tpm2_protocol::frame::{
        TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, TpmResponse,
        TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
    };
    use tpm2_protocol::{TpmMarshal, TpmSized};
    type Hmac256 = Hmac<sha2::Sha256>;

    let mut tpm = tpm();

    // --- StartAuthSession (HMAC, unsalted, unbound, SHA256) ---
    let nonce_caller = tpm.get_random(32).unwrap();
    let sas = TpmStartAuthSessionCommand {
        handles: [TpmHandle::new(0x4000_0007); 2],
        nonce_caller: Tpm2bNonce::try_from(nonce_caller.as_slice()).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::try_from(&[][..]).unwrap(),
        session_type: TpmSe::Hmac,
        symmetric: TpmtSymDef {
            algorithm: TpmAlgId::Null,
            key_bits: TpmuSymKeyBits::Null,
            mode: TpmuSymMode::Null,
        },
        auth_hash: TpmAlgId::Sha256,
    };
    let resp = tpm.transfer(&marshal_cmd(&sas, TpmSt::NoSessions, &[])).unwrap();
    let r = TpmResponse::cast(&resp).expect("SAS cast");
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "SAS rc={:?}", r.rc());
    let sr = r.unmarshal::<TpmStartAuthSessionResponse>().expect("SAS unmarshal");
    let sess_handle = TpmHandle::new(sr.handles[0].value());
    let nonce_tpm = sr.nonce_tpm.to_vec();
    println!("SAS handle=0x{:08x} nonce_tpm={}B", sr.handles[0].value(), nonce_tpm.len());

    // --- CreatePrimary command, NoSessions marshal for the parameter area ---
    let hier = TpmHandle::new(0x4000_0001);
    let cp = TpmCreatePrimaryCommand {
        handles: [hier],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(&[][..]).unwrap(),
            },
        },
        in_public: Tpm2bPublic {
            inner: TpmtPublic {
                object_type: TpmAlgId::SymCipher,
                name_alg: TpmAlgId::Sha256,
                object_attributes: TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT
                    | TpmaObject::SENSITIVE_DATA_ORIGIN
                    | TpmaObject::USER_WITH_AUTH
                    | TpmaObject::RESTRICTED
                    | TpmaObject::DECRYPT,
                auth_policy: Tpm2bDigest::try_from(&[][..]).unwrap(),
                parameters: TpmuPublicParms::SymCipher(TpmsSymcipherParms {
                    sym: TpmtSymDef {
                        algorithm: TpmAlgId::Aes,
                        key_bits: TpmuSymKeyBits::Aes(128.into()),
                        mode: TpmuSymMode::Aes(TpmAlgId::Cfb),
                    },
                }),
                unique: TpmuPublicId::SymCipher(Tpm2bSymKey::try_from(&[][..]).unwrap()),
            },
        },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    // Parameter area: from a NoSessions marshal, [10 header + 4 handles..].
    let cp_nos = marshal_cmd(&cp, TpmSt::NoSessions, &[]);
    let param_area = &cp_nos[14..];

    // --- cpHash + request HMAC (unbound empty-auth: key is empty) ---
    let cc: u32 = 0x0000_0131;
    let mut cp_input = Vec::new();
    cp_input.extend_from_slice(&cc.to_be_bytes());
    cp_input.extend_from_slice(&hier.value().to_be_bytes());
    cp_input.extend_from_slice(param_area);
    let cp_hash = sha2::Sha256::digest(&cp_input);

    let mut hmsg = Vec::new();
    hmsg.extend_from_slice(&cp_hash);
    hmsg.extend_from_slice(&nonce_caller);
    hmsg.extend_from_slice(&nonce_tpm);
    hmsg.push(0u8); // sessionAttributes: none
    let req_hmac = {
        let mut m = Hmac256::new_from_slice(&[]).unwrap();
        m.update(&hmsg);
        m.finalize().into_bytes().to_vec()
    };

    // --- Sessions-tagged wire: header + handles + authSize + session + params
    let sess = TpmsAuthCommand {
        session_handle: sess_handle,
        nonce: Tpm2bNonce::try_from(nonce_caller.as_slice()).unwrap(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::try_from(req_hmac.as_slice()).unwrap(),
    };
    let sess_area = {
        let mut b = vec![0u8; 128];
        let len = {
            let mut w = TpmWriter::new(&mut b);
            sess.marshal(&mut w).unwrap();
            w.len()
        };
        b.truncate(len);
        b
    };

    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TpmSt::Sessions.value().to_be_bytes());
    let total = 10 + 4 + 4 + sess_area.len() + param_area.len();
    cmd.extend_from_slice(&(total as u32).to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&hier.value().to_be_bytes());
    cmd.extend_from_slice(&(sess_area.len() as u32).to_be_bytes());
    cmd.extend_from_slice(&sess_area);
    cmd.extend_from_slice(param_area);

    let resp = tpm.transfer(&cmd).unwrap();
    let r = TpmResponse::cast(&resp).expect("CP cast");
    let rc = r.rc().map(|c| c.value()).unwrap_or(u32::MAX);
    assert_eq!(rc, 0, "CreatePrimary rc=0x{rc:08x} ({:?})", r.rc());
    let cr = r.unmarshal::<TpmCreatePrimaryResponse>().expect("CP unmarshal");
    println!(
        "CreatePrimary OK new_entity=0x{:08x} out_public={}B name={}B",
        cr.handles[0].value(),
        cr.out_public.len(),
        cr.name.len()
    );
}

/// Start a fresh unbound empty-auth HMAC session; returns (handle, nonceTpm).
/// Used by the setup commands (CreatePrimary/Create/Load/PcrExtend), where the
/// empty-auth HMAC's session key is the empty string.
fn start_session(t: &mut Tpm) -> (TpmHandle, Vec<u8>) {
    use tpm2_protocol::data::{
        Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmSe, TpmuSymKeyBits, TpmuSymMode,
    };
    use tpm2_protocol::frame::{TpmStartAuthSessionCommand, TpmStartAuthSessionResponse};
    let nc = t.get_random(32).unwrap();
    let sas = TpmStartAuthSessionCommand {
        handles: [TpmHandle::new(0x4000_0007); 2],
        nonce_caller: Tpm2bNonce::try_from(nc.as_slice()).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::try_from(&[][..]).unwrap(),
        session_type: TpmSe::Hmac,
        symmetric: tpm2_protocol::data::TpmtSymDef {
            algorithm: TpmAlgId::Null,
            key_bits: TpmuSymKeyBits::Null,
            mode: TpmuSymMode::Null,
        },
        auth_hash: TpmAlgId::Sha256,
    };
    let resp = t.transfer(&marshal_cmd(&sas, TpmSt::NoSessions, &[])).unwrap();
    let r = TpmResponse::cast(&resp).unwrap();
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "SAS rc={:?}", r.rc());
    let sr = r.unmarshal::<TpmStartAuthSessionResponse>().unwrap();
    (TpmHandle::new(sr.handles[0].value()), sr.nonce_tpm.to_vec())
}

/// Start a fresh unbound POLICY session (SHA256). Its policyDigest begins as
/// the 32-byte zero string (libtpms Session.c: "policyDigest is initialized
/// with a string of 0s" of authHashAlg digest size).
fn start_policy_session(t: &mut Tpm) -> TpmHandle {
    use tpm2_protocol::data::{
        Tpm2bEncryptedSecret, Tpm2bNonce, TpmAlgId, TpmSe, TpmuSymKeyBits, TpmuSymMode,
    };
    use tpm2_protocol::frame::{TpmStartAuthSessionCommand, TpmStartAuthSessionResponse};
    let nc = t.get_random(32).unwrap();
    let sas = TpmStartAuthSessionCommand {
        handles: [TpmHandle::new(0x4000_0007); 2],
        nonce_caller: Tpm2bNonce::try_from(nc.as_slice()).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::try_from(&[][..]).unwrap(),
        session_type: TpmSe::Policy,
        symmetric: tpm2_protocol::data::TpmtSymDef {
            algorithm: TpmAlgId::Null,
            key_bits: TpmuSymKeyBits::Null,
            mode: TpmuSymMode::Null,
        },
        auth_hash: TpmAlgId::Sha256,
    };
    let resp = t.transfer(&marshal_cmd(&sas, TpmSt::NoSessions, &[])).unwrap();
    let r = TpmResponse::cast(&resp).unwrap();
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "SAS policy rc={:?}", r.rc());
    let sr = r.unmarshal::<TpmStartAuthSessionResponse>().unwrap();
    TpmHandle::new(sr.handles[0].value())
}

/// Send `cmd` with one auth session in the session area. On TPM_RC_RETRY
/// (0x0922, libtpms' first-check-after-startup NV visibility artifact) resend
/// with a fresh caller nonce.
fn send<C>(t: &mut Tpm, cmd: &C, sess: TpmHandle) -> Vec<u8>
where
    C: tpm2_protocol::frame::TpmFrame,
{
    use tpm2_protocol::data::{Tpm2bAuth, Tpm2bNonce, TpmaSession, TpmsAuthCommand};
    for attempt in 0..4u8 {
        let nc = t.get_random(32).unwrap();
        let auth = TpmsAuthCommand {
            session_handle: sess,
            nonce: Tpm2bNonce::try_from(nc.as_slice()).unwrap(),
            session_attributes: TpmaSession::default(),
            hmac: Tpm2bAuth::try_from(&[][..]).unwrap(),
        };
        let wire = marshal_cmd(cmd, TpmSt::Sessions, &[auth]);
        let resp = t.transfer(&wire).unwrap();
        let r = TpmResponse::cast(&resp).unwrap();
        let rc = r.rc().map(|c| c.value()).unwrap_or(u32::MAX);
        if rc == 0 {
            return resp;
        }
        if rc == 0x0922 && attempt < 3 {
            continue; // RC_RETRY: daUsed NV write not yet visible
        }
        let rc_str = r.rc().map(|e| e.to_string()).unwrap_or_default();
        panic!("command {:?} rc=0x{rc:04x} ({rc_str}), attempt {attempt}", cmd.cc());
    }
    unreachable!()
}

/// NoSessions-marshal a command and slice out the parameter area.
fn params_of<C: tpm2_protocol::frame::TpmFrame>(c: &C, n_handles: usize) -> Vec<u8> {
    let w = marshal_cmd(c, TpmSt::NoSessions, &[]);
    w[10 + n_handles * 4..].to_vec()
}

/// Test 2: TPM2_Create (KEYEDHASH sealed object under the storage parent),
/// parent authorized by an empty-auth HMAC session; rc=0 and the Name is
/// nameAlg || SHA256(marshaled in_public).
#[test]
fn t02_create_sealed_under_parent() {
    use digest::Digest;
    use hmac::{Hmac, Mac};
    use tpm2_protocol::data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bPublic, Tpm2bSensitiveCreate,
        Tpm2bSensitiveData, TpmAlgId, TpmaObject, TpmaSession, TpmsAuthCommand,
        TpmsSensitiveCreate, TpmtPublic, TpmlPcrSelection, TpmuKeyedhashScheme,
        TpmuPublicId, TpmuPublicParms,
    };
    use tpm2_protocol::data::TpmsKeyedhashParms;
    use tpm2_protocol::data::TpmtKeyedhashScheme;
    use tpm2_protocol::frame::{
        TpmCreateCommand, TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, TpmCreateResponse,
        TpmResponse, TpmStartAuthSessionCommand, TpmStartAuthSessionResponse,
    };
    use tpm2_protocol::{TpmMarshal, TpmSized};
    type Hmac256 = Hmac<sha2::Sha256>;

    /// Start a fresh unbound empty-auth HMAC session; returns (handle, nonceTpm).
    fn start_session(t: &mut Tpm) -> (TpmHandle, Vec<u8>) {
        let nc = t.get_random(32).unwrap();
        let sas = TpmStartAuthSessionCommand {
            handles: [TpmHandle::new(0x4000_0007); 2],
            nonce_caller: Tpm2bNonce::try_from(nc.as_slice()).unwrap(),
            encrypted_salt: tpm2_protocol::data::Tpm2bEncryptedSecret::try_from(&[][..]).unwrap(),
            session_type: tpm2_protocol::data::TpmSe::Hmac,
            symmetric: tpm2_protocol::data::TpmtSymDef {
                algorithm: TpmAlgId::Null,
                key_bits: tpm2_protocol::data::TpmuSymKeyBits::Null,
                mode: tpm2_protocol::data::TpmuSymMode::Null,
            },
            auth_hash: TpmAlgId::Sha256,
        };
        let resp = t.transfer(&marshal_cmd(&sas, TpmSt::NoSessions, &[])).unwrap();
        let r = TpmResponse::cast(&resp).unwrap();
        assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "SAS rc={:?}", r.rc());
        let sr = r.unmarshal::<TpmStartAuthSessionResponse>().unwrap();
        (TpmHandle::new(sr.handles[0].value()), sr.nonce_tpm.to_vec())
    }

    let mut tpm = tpm();
    let (sess, nonce_tpm) = start_session(&mut tpm);
    println!("session 0x{:08x} nonce_tpm={}B", sess.value(), nonce_tpm.len());

    /// Build a one-HMAC-session wire command: handles + authSize + session +
    /// params, with cpHash = H(cc || entityName || params). The area (and the
    /// HMAC message) carry CONTINUE_SESSION: libtpms destroys the session
    /// after each command unless that bit is set, so a session reused across
    /// commands must keep it.
    fn wire_hmac(
        cc: u32,
        handles: &[u32],
        entity_name: &[u8],
        params: &[u8],
        sess: TpmHandle,
        nonce_caller: &[u8],
        nonce_tpm: &[u8],
    ) -> Vec<u8> {
        const ATTRS: u8 = 0x01; // TpmaSession::CONTINUE_SESSION
        let mut cp = Vec::new();
        cp.extend_from_slice(&cc.to_be_bytes());
        cp.extend_from_slice(entity_name);
        cp.extend_from_slice(params);
        let cp_hash = sha2::Sha256::digest(&cp);
        let mut hmsg = Vec::new();
        hmsg.extend_from_slice(&cp_hash);
        hmsg.extend_from_slice(nonce_caller);
        hmsg.extend_from_slice(nonce_tpm);
        hmsg.push(ATTRS);
        let mut m = Hmac256::new_from_slice(&[]).unwrap();
        m.update(&hmsg);
        let req_hmac = m.finalize().into_bytes().to_vec();
        let auth = TpmsAuthCommand {
            session_handle: sess,
            nonce: Tpm2bNonce::try_from(nonce_caller).unwrap(),
            session_attributes: TpmaSession::CONTINUE_SESSION,
            hmac: Tpm2bAuth::try_from(req_hmac.as_slice()).unwrap(),
        };
        let sess_area = {
            let mut b = vec![0u8; 128];
            let len = {
                let mut w = TpmWriter::new(&mut b);
                auth.marshal(&mut w).unwrap();
                w.len()
            };
            b.truncate(len);
            b
        };
        let mut cmd = Vec::new();
        cmd.extend_from_slice(&TpmSt::Sessions.value().to_be_bytes());
        let total = 10 + handles.len() * 4 + 4 + sess_area.len() + params.len();
        cmd.extend_from_slice(&(total as u32).to_be_bytes());
        cmd.extend_from_slice(&cc.to_be_bytes());
        for h in handles {
            cmd.extend_from_slice(&h.to_be_bytes());
        }
        cmd.extend_from_slice(&(sess_area.len() as u32).to_be_bytes());
        cmd.extend_from_slice(&sess_area);
        cmd.extend_from_slice(params);
        cmd
    }

    /// NoSessions-marshal a command and slice out the parameter area.
    fn params_of<C: tpm2_protocol::frame::TpmFrame>(c: &C, n_handles: usize) -> Vec<u8> {
        let w = marshal_cmd(c, TpmSt::NoSessions, &[]);
        w[10 + n_handles * 4..].to_vec()
    }

    /// Send a one-session HMAC command; on TPM_RC_RETRY (0x0922) resend with a
    /// fresh caller nonce. libtpms 0.9.x returns RETRY from the first
    /// authorization check after a fresh startup (the DA `daUsed` flag is
    /// written to NV asynchronously and the command must be retried once the
    /// write is visible) — tss-esapi-based stacks do exactly this retry.
    fn send_hmac(
        t: &mut Tpm,
        cc: u32,
        handles: &[u32],
        entity_name: &[u8],
        params: &[u8],
        sess: TpmHandle,
        nonce_tpm: &[u8],
    ) -> Vec<u8> {
        for attempt in 0..4u8 {
            let nc = t.get_random(32).unwrap();
            let resp = t
                .transfer(&wire_hmac(cc, handles, entity_name, params, sess, &nc, nonce_tpm))
                .unwrap();
            let r = TpmResponse::cast(&resp).unwrap();
            let rc = r.rc().map(|c| c.value()).unwrap_or(u32::MAX);
            if rc == 0 {
                return resp;
            }
            if rc == 0x0922 && attempt < 3 {
                continue; // RC_RETRY: daUsed NV write not yet visible
            }
            let rc_str = r.rc().map(|e| e.to_string()).unwrap_or_default();
            panic!(
                "command 0x{cc:04x} rc=0x{rc:04x} ({rc_str}), attempt {attempt}"
            );
        }
        unreachable!()
    }

    // --- parent: CreatePrimary (reuse test 1's template) ---
    let hier = 0x4000_0001u32;
    let cp = TpmCreatePrimaryCommand {
        handles: [TpmHandle::new(hier)],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(&[][..]).unwrap(),
            },
        },
        in_public: Tpm2bPublic {
            inner: TpmtPublic {
                object_type: TpmAlgId::SymCipher,
                name_alg: TpmAlgId::Sha256,
                object_attributes: TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT
                    | TpmaObject::SENSITIVE_DATA_ORIGIN
                    | TpmaObject::USER_WITH_AUTH
                    | TpmaObject::RESTRICTED
                    | TpmaObject::DECRYPT,
                auth_policy: Tpm2bDigest::try_from(&[][..]).unwrap(),
                parameters: tpm2_protocol::data::TpmuPublicParms::SymCipher(
                    tpm2_protocol::data::TpmsSymcipherParms {
                        sym: tpm2_protocol::data::TpmtSymDef {
                            algorithm: TpmAlgId::Aes,
                            key_bits: tpm2_protocol::data::TpmuSymKeyBits::Aes(128.into()),
                            mode: tpm2_protocol::data::TpmuSymMode::Aes(TpmAlgId::Cfb),
                        },
                    },
                ),
                unique: tpm2_protocol::data::TpmuPublicId::SymCipher(
                    tpm2_protocol::data::Tpm2bSymKey::try_from(&[][..]).unwrap(),
                ),
            },
        },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cp_params = params_of(&cp, 1);
    let resp = send_hmac(&mut tpm, 0x0000_0131, &[hier], &hier.to_be_bytes(), &cp_params, sess, &nonce_tpm);
    let r = TpmResponse::cast(&resp).unwrap();
    let cr = r.unmarshal::<TpmCreatePrimaryResponse>().unwrap();
    let parent_handle = cr.handles[0].value();
    let parent_name = cr.name.to_vec();
    println!("parent 0x{parent_handle:08x} name={}B", parent_name.len());

    // --- sealed KEYEDHASH object: authPolicy = 32 bytes of 0xab (fixed for
    //     this test; the policy-digest correctness is test 3's job) ---
    // libtpms CreateChecks + PublicAttributesValidation (KEYEDHASH data object):
    //   - sign==decrypt==clear REQUIRES sensitiveDataOrigin CLEAR (we supply data)
    //   - parent is a PRIMARY object (fixedTPM) so child must have fixedParent
    //     == fixedTPM; the canonical sealed object sets BOTH.
    let sealed_inner = TpmtPublic {
            object_type: TpmAlgId::KeyedHash,
            name_alg: TpmAlgId::Sha256,
            object_attributes: TpmaObject::NO_DA
                | TpmaObject::USER_WITH_AUTH
                | TpmaObject::ADMIN_WITH_POLICY
                | TpmaObject::FIXED_TPM
                | TpmaObject::FIXED_PARENT,
            auth_policy: Tpm2bDigest::try_from(&[0xabu8; 32][..]).unwrap(),
            parameters: tpm2_protocol::data::TpmuPublicParms::KeyedHash(
                TpmsKeyedhashParms {
                    scheme: TpmtKeyedhashScheme {
                        scheme: TpmAlgId::Null,
                        details: TpmuKeyedhashScheme::Null,
                    },
                },
            ),
            unique: TpmuPublicId::KeyedHash(Tpm2bDigest::try_from(&[][..]).unwrap()),
        };
    let sealed = Tpm2bPublic::from(sealed_inner.clone());
    // Marshaled inPublic prefix (everything up to the unique field) for the
    // post-Create sanity check: the TPM may only fill `unique`.
    let sealed_public_prefix = {
        let mut b = vec![0u8; 256];
        let len = {
            let mut w = TpmWriter::new(&mut b);
            sealed_inner.marshal(&mut w).unwrap();
            w.len()
        };
        b.truncate(len);
        b
    };
    let data: &[u8] = b"seal-test-payload";
    let create = TpmCreateCommand {
        handles: [TpmHandle::new(parent_handle)],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(data).unwrap(),
            },
        },
        in_public: sealed,
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let cr_params = params_of(&create, 1);
    let (sess2, ntpm2) = start_session(&mut tpm);
    let resp = send_hmac(
        &mut tpm,
        0x0000_0153,
        &[parent_handle],
        &parent_name, // cpHash uses the ENTITY'S NAME, not the handle bytes
        &cr_params,
        sess2,
        &ntpm2,
    );
    let r = TpmResponse::cast(&resp).unwrap();
    let cr2 = r.unmarshal::<TpmCreateResponse>().unwrap();
    println!(
        "Create OK private={}B out_public={}B",
        cr2.out_private.len(),
        cr2.out_public.len()
    );
    // The TPM fills `unique` in outPublic (for a data object: the digest of
    // the sealed data), so outPublic != inPublic BY DESIGN. The child's Name
    // is nameAlg || SHA256(marshaled OUTpublic) — computed client-side from
    // the TPM's echo, which is what Unseal/Load later authorize against.
    let public_bytes = {
        let mut b = vec![0u8; 256];
        let len = {
            let mut w = TpmWriter::new(&mut b);
            cr2.out_public.inner.marshal(&mut w).unwrap();
            w.len()
        };
        b.truncate(len);
        b
    };
/// Test 3: full PolicyPCR + Unseal round-trip. A sealed KEYEDHASH child is
/// created with `authPolicy = SHA256( zero32 || 0x0000017F ||
/// marshal(TPML_PCR_SELECTION) || pcrDigest )`, where pcrDigest is the
/// SHA256 of the current PCR 0. Loading it, running TPM2_PolicyPCR in a
/// policy session (which makes the session's policyDigest equal that same
/// value), and then TPM2_Unseal returns the sealed data. The negative half
/// (a fresh policy session, no PolicyPCR) must fail with TPM_RC_POLICY_FAIL.
///
/// libtpms 0.9.2 ground truth:
///   - Session.c: fresh policy session policyDigest = 32 zero bytes.
///   - EACommands.c TPM2_PolicyPCR: policyDigest_new = H( policyDigest_old
///     || CC_PolicyPCR(4B) || TPML_PCR_SELECTION || pcrDigest ).
///   - PCR.c PCRComputeCurrentDigest: pcrDigest = H(selected PCR values),
///     data only, ascending, no length prefix.
///   - SessionProcess.c CheckPolicyAuthSession: MemoryEqual2B(session
///     policyDigest, object authPolicy); Unseal role = USER (no
///     PolicyCommandCode needed).
#[test]
fn t03_policy_pcr_unseal() {
    use digest::Digest;
    use tpm2_protocol::basic::TpmList;
    use tpm2_protocol::data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bName, Tpm2bNonce, Tpm2bPublic,
        Tpm2bSensitiveCreate, Tpm2bSensitiveData, TpmAlgId, TpmaObject,
        TpmsKeyedhashParms, TpmsPcrSelection, TpmsSensitiveCreate, TpmtHa, TpmtKeyedhashScheme,
        TpmtPublic, TpmsPpcrSelect, TpmlPcrSelection, TpmlDigestValues, TpmuKeyedhashScheme,
        TpmuPublicId, TpmuPublicParms,
    };
    use tpm2_protocol::frame::{
        TpmCreateCommand, TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, TpmCreateResponse,
        TpmLoadCommand, TpmLoadResponse, TpmPcrExtendCommand, TpmPcrReadCommand,
        TpmPcrReadResponse, TpmPolicyPcrCommand, TpmResponse, TpmUnsealCommand, TpmUnsealResponse,
    };
    use tpm2_protocol::TpmMarshal;

    let mut tpm = tpm();

    // --- a PCR-selection list with a single { SHA256, PCR 0 } entry ---
    let sel = TpmsPcrSelection {
        hash: TpmAlgId::Sha256,
        pcr_select: TpmsPpcrSelect::try_from(&[0x01u8][..]).unwrap(), // bit 0 = PCR 0
    };
    fn one_entry(sel: TpmsPcrSelection) -> TpmlPcrSelection {
        let mut l = TpmlPcrSelection::new();
        l.try_push(sel).unwrap();
        l
    }
    let selection = one_entry(sel);

    // --- parent: CreatePrimary (empty auth, NoSessions) ---
    let cp = TpmCreatePrimaryCommand {
        handles: [TpmHandle::new(0x4000_0001)],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(&[][..]).unwrap(),
            },
        },
        in_public: Tpm2bPublic {
            inner: TpmtPublic {
                object_type: TpmAlgId::SymCipher,
                name_alg: TpmAlgId::Sha256,
                object_attributes: TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT
                    | TpmaObject::SENSITIVE_DATA_ORIGIN
                    | TpmaObject::USER_WITH_AUTH
                    | TpmaObject::RESTRICTED
                    | TpmaObject::DECRYPT,
                auth_policy: Tpm2bDigest::try_from(&[][..]).unwrap(),
                parameters: tpm2_protocol::data::TpmuPublicParms::SymCipher(
                    tpm2_protocol::data::TpmsSymcipherParms {
                        sym: tpm2_protocol::data::TpmtSymDef {
                            algorithm: TpmAlgId::Aes,
                            key_bits: tpm2_protocol::data::TpmuSymKeyBits::Aes(128.into()),
                            mode: tpm2_protocol::data::TpmuSymMode::Aes(TpmAlgId::Cfb),
                        },
                    },
                ),
                unique: tpm2_protocol::data::TpmuPublicId::SymCipher(
                    tpm2_protocol::data::Tpm2bSymKey::try_from(&[][..]).unwrap(),
                ),
            },
        },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let resp = tpm.transfer(&marshal_cmd(&cp, TpmSt::NoSessions, &[])).unwrap();
    let r = TpmResponse::cast(&resp).expect("CP cast");
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "CreatePrimary rc={:?}", r.rc());
    let cp_resp = r.unmarshal::<TpmCreatePrimaryResponse>().expect("CP unmarshal");
    let parent = cp_resp.handles[0].value();
    println!("parent 0x{parent:08x}");

    // --- read PCR 0 (NoSessions: PCR 0 has empty ownerAuth on a fresh TPM) ---
    let pr = TpmPcrReadCommand {
        handles: [],
        pcr_selection_in: selection,
    };
    let resp = tpm.transfer(&marshal_cmd(&pr, TpmSt::NoSessions, &[])).unwrap();
    let r = TpmResponse::cast(&resp).expect("PcrRead cast");
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "PcrRead rc={:?}", r.rc());
    let pr_resp = r.unmarshal::<TpmPcrReadResponse>().expect("PcrRead unmarshal");
    // pcr_values is a TPML of TPM2B_DIGEST, one entry (SHA256, PCR 0).
    let pcr0: Vec<u8> = pr_resp.pcr_values[0].inner.to_vec();
    assert_eq!(pcr0.len(), 32, "PCR 0 must be a 32-byte SHA256 digest");
    println!("pcr0 = {:064x}", u128::from_be_bytes(pcr0[16..].try_into().unwrap()), );
    println!("pcr0[..16] = {:032x}", u128::from_be_bytes(pcr0[..16].try_into().unwrap()));

    // --- pcrDigest = SHA256(current PCR 0) ; authPolicy = the PolicyPCR digest ---
    let pcr_digest = sha2::Sha256::digest(&pcr0);
    // marshaled TPML_PCR_SELECTION (count + one {hash, size, select} entry)
    let sel_bytes = {
        let mut b = vec![0u8; 64];
        let len = {
            let mut w = TpmWriter::new(&mut b);
            selection.marshal(&mut w).unwrap();
            w.len()
        };
        b.truncate(len);
        b
    };
    println!(
        "TPML_PCR_SELECTION = {:02x?} ({}B)",
        sel_bytes,
        sel_bytes.len()
    );
    let mut pol = Vec::new();
    pol.extend_from_slice(&[0u8; 32]); // policyDigest_old (fresh policy session)
    pol.extend_from_slice(&0x0000_017Fu32.to_be_bytes()); // CC_PolicyPCR
    pol.extend_from_slice(&sel_bytes);
    pol.extend_from_slice(&pcr_digest);
    let auth_policy: [u8; 32] = sha2::Sha256::digest(&pol).into();
    println!("authPolicy = {:064x}", {
        let mut s = String::new();
        for b in auth_policy { s.push_str(&format!("{:02x}", b)); }
        s
    });

    // --- child: sealed KEYEDHASH with that authPolicy ---
    let data: &[u8] = b"policy-sealed-payload-3";
    let create = TpmCreateCommand {
        handles: [TpmHandle::new(parent)],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(data).unwrap(),
            },
        },
        in_public: Tpm2bPublic {
            inner: TpmtPublic {
                object_type: TpmAlgId::KeyedHash,
                name_alg: TpmAlgId::Sha256,
                object_attributes: TpmaObject::NO_DA
                    | TpmaObject::ADMIN_WITH_POLICY
                    | TpmaObject::FIXED_TPM
                    | TpmaObject::FIXED_PARENT,
                auth_policy: Tpm2bDigest::try_from(auth_policy.as_slice()).unwrap(),
                parameters: tpm2_protocol::data::TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
                    scheme: TpmtKeyedhashScheme {
                        scheme: TpmAlgId::Null,
                        details: TpmuKeyedhashScheme::Null,
                    },
                }),
                unique: TpmuPublicId::KeyedHash(Tpm2bDigest::try_from(&[][..]).unwrap()),
            },
        },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    let (sess, _ntpm) = start_session(&mut tpm);
    let resp = send(&mut tpm, &create, sess);
    let r = TpmResponse::cast(&resp).expect("Create cast");
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "Create rc={:?}", r.rc());
    let create_resp = r.unmarshal::<TpmCreateResponse>().expect("Create unmarshal");
    println!(
        "Create OK private={}B out_public={}B",
        create_resp.out_private.len(),
        create_resp.out_public.len()
    );

    // --- Load the child (parent authorized, empty-auth session) ---
    let load = TpmLoadCommand {
        handles: [TpmHandle::new(parent)],
        in_private: create_resp.out_private,
        in_public: create_resp.out_public,
    };
    let resp = send(&mut tpm, &load, sess);
    let r = TpmResponse::cast(&resp).expect("Load cast");
    assert_eq!(r.rc().map(|c| c.value()).unwrap_or(u32::MAX), 0, "Load rc={:?}", r.rc());
    let load_resp = r.unmarshal::<TpmLoadResponse>().expect("Load unmarshal");
    let child = load_resp.handles[0].value();
    let child_name: Vec<u8> = load_resp.name.to_vec();
    println!("child 0x{child:08x} name={}B", child_name.len());

    // --- POSITIVE: policy session + PolicyPCR, then Unseal ---
    let pol_sess = start_policy_session(&mut tpm);
    let policy_pcr = TpmPolicyPcrCommand {
        handles: [pol_sess],
        pcr_digest: Tpm2bDigest::try_from(&[][..]).unwrap(), // 0 => use current PCR value
        pcrs: selection,
    };
    let resp = tpm
        .transfer(&marshal_cmd(&policy_pcr, TpmSt::NoSessions, &[]))
        .unwrap();
    let r = TpmResponse::cast(&resp).expect("PolicyPCR cast");
    assert_eq!(
        r.rc().map(|c| c.value()).unwrap_or(u32::MAX),
        0,
        "PolicyPCR rc={:?}",
        r.rc()
    );
    println!("PolicyPCR OK (session 0x{:08x})", pol_sess.value());

    // Unseal with the SAME policy session now in the session area.
    let unseal = TpmUnsealCommand {
        handles: [TpmHandle::new(child)],
    };
    let resp = send(&mut tpm, &unseal, pol_sess);
    let r = TpmResponse::cast(&resp).expect("Unseal cast");
    assert_eq!(
        r.rc().map(|c| c.value()).unwrap_or(u32::MAX),
        0,
        "Unseal rc={:?}",
        r.rc()
    );
    let unseal_resp = r.unmarshal::<TpmUnsealResponse>().expect("Unseal unmarshal");
    let out: Vec<u8> = unseal_resp.out_data.to_vec();
    assert_eq!(out, data, "unsealed data must equal the sealed payload");
    println!("Unseal OK data={:?}", String::from_utf8_lossy(&out));

    // --- NEGATIVE: a fresh policy session (no PolicyPCR) must fail Unseal ---
    let bad_sess = start_policy_session(&mut tpm);
    let unseal2 = TpmUnsealCommand {
        handles: [TpmHandle::new(child)],
    };
    let resp = send(&mut tpm, &unseal2, bad_sess);
    let r = TpmResponse::cast(&resp).expect("Unseal2 cast");
    let rc = r.rc().map(|c| c.value()).unwrap_or(u32::MAX);
    assert_eq!(rc, 0x095E, "expected TPM_RC_POLICY_FAIL 0x095E, got 0x{rc:04x} ({:?})", r.rc());
    println!("negative Unseal correctly failed with TPM_RC_POLICY_FAIL 0x{rc:04x}");
}
    // Sanity: outPublic differs from inPublic ONLY in the unique field
    // (the trailing digest), which the TPM populated.
    assert!(public_bytes.len() > 16, "outPublic too short");
    assert_eq!(&public_bytes[..42], &sealed_public_prefix[..42], "template mutated beyond unique");
    println!(
        "child Name = {}B (from TPM outPublic), private={}B",
        expected_name.len(),
        cr2.out_private.len()
    );
}
