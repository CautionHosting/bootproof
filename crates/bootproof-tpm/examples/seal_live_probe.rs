//! Live ground-truth probe: drive a real command over bootproof's transport
//! using the vendored tpm2-protocol marshaling, dump the raw response bytes.
//! Settles the response `paramSize` layout and validates the integration.
use tpm2_protocol::basic::TpmHandle;
use tpm2_protocol::data::TpmSt;
use tpm2_protocol::frame::{TpmGetRandomCommand, tpm_marshal_command};
use tpm2_protocol::TpmWriter;

use bootproof_tpm::Tpm;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn main() {
    let sock = std::env::args().nth(1).unwrap_or_else(|| "/tmp/swptpm2/tpm.sock".into());
    let mut tpm: Tpm = Tpm::connect_swtpm_unix(std::path::Path::new(&sock)).unwrap();
    tpm.ensure_started().expect("startup");

    // GetRandom(16) via canonical marshaling.
    let cmd = TpmGetRandomCommand {
        handles: [],
        bytes_requested: 16.into(),
    };
    let wire = {
        let mut buf = vec![0u8; 512];
        let len = {
            let mut w = TpmWriter::new(&mut buf);
            tpm_marshal_command(&cmd, TpmSt::NoSessions, &[], &mut w).unwrap();
            w.len()
        };
        buf.truncate(len);
        buf
    };
    println!("CMD ({}B) = {}", wire.len(), hex(&wire));
    let resp = tpm.transfer(&wire).expect("transfer");
    println!("RESP({}B) = {}", resp.len(), hex(&resp));
    println!("  tag=0x{:04x} size={} cc/rc=0x{:08x}",
        u16::from_be_bytes([resp[0], resp[1]]),
        u32::from_be_bytes([resp[2], resp[3], resp[4], resp[5]]),
        u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]));
    println!("  body[10..] = {}", hex(&resp[10..]));

    // Now try the canonical typed unmarshal of the response.
    use tpm2_protocol::frame::{TpmGetRandomResponse, TpmResponse};
    match TpmResponse::cast(&resp) {
        Ok(r) => {
            println!("  TpmResponse::cast OK, rc={:?}", r.rc());
            match r.unmarshal::<TpmGetRandomResponse>() {
                Ok(gr) => println!("  UNMARSHAL OK random_bytes={}B", gr.random_bytes.len()),
                Err(e) => println!("  UNMARSHAL ERR: {e:?}"),
            }
        }
        Err(e) => println!("  TpmResponse::cast ERR: {e:?}"),
    }

    // CreatePrimary (SYMCIPHER AES-128-CFB) with an empty-auth HMAC session.
    run_create_primary(&mut tpm);
    println!("OK");
}

fn run_create_primary(tpm: &mut Tpm) {
    use tpm2_protocol::data::{
        Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bNonce, Tpm2bPublic, Tpm2bSensitiveCreate,
        Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId, TpmSe, TpmaObject, TpmaSession,
        TpmsAuthCommand, TpmsSensitiveCreate, TpmsSymcipherParms, TpmtPublic, TpmtSymDef,
        TpmlPcrSelection, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
    };
    use tpm2_protocol::frame::{
        TpmCreatePrimaryCommand, TpmCreatePrimaryResponse, TpmResponse,
        TpmStartAuthSessionCommand, tpm_marshal_command,
    };
    use tpm2_protocol::{TpmMarshal, TpmSized, TpmWriter};
    use digest::Digest;
    use hmac::{Hmac, Mac};
    type Hmac256 = Hmac<sha2::Sha256>;

    let hier = TpmHandle::new(0x4000_0001);

    // --- StartAuthSession (HMAC, unbound, SHA256) ---
    let nonce_caller = tpm.get_random(32).unwrap();
    let sas = TpmStartAuthSessionCommand {
        handles: [TpmHandle::new(0x4000_0007), TpmHandle::new(0x4000_0007)],
        nonce_caller: Tpm2bNonce::try_from(nonce_caller.as_slice()).unwrap(),
        encrypted_salt: tpm2_protocol::data::Tpm2bEncryptedSecret::try_from(&[][..]).unwrap(),
        session_type: TpmSe::Hmac,
        symmetric: TpmtSymDef { algorithm: TpmAlgId::Null, key_bits: TpmuSymKeyBits::Null, mode: TpmuSymMode::Null },
        auth_hash: TpmAlgId::Sha256,
    };
    let sas_wire = {
        let mut buf = vec![0u8; 512];
        let len = { let mut w = TpmWriter::new(&mut buf); tpm_marshal_command(&sas, TpmSt::NoSessions, &[], &mut w).unwrap(); w.len() };
        buf.truncate(len); buf
    };
    let sas_resp = tpm.transfer(&sas_wire).unwrap();
    println!("SAS CMD  = {}", hex(&sas_wire));
    println!("SAS RESP = {} ({}B)", hex(&sas_resp), sas_resp.len());
    // canonical: rc at [6..10], body = paramSize(4) + [handle(4) + nonceTPM TPM2B]
    let sess_handle: u32; let nonce_tpm: Vec<u8>;
    {
        use tpm2_protocol::frame::{TpmResponse, TpmStartAuthSessionResponse};
        match TpmResponse::cast(&sas_resp) {
            Ok(r) => {
                if r.rc().map(|rc| rc.value()).unwrap_or(u32::MAX) != 0 {
                    println!("SAS rc={:?}", r.rc()); return;
                }
                match r.unmarshal::<TpmStartAuthSessionResponse>() {
                    Ok(sr) => {
                        sess_handle = sr.handles[0].value();
                        nonce_tpm = sr.nonce_tpm.to_vec();
                        println!("  SAS UNMARSHAL OK handle=0x{sess_handle:08x} nonceTPM={}B", nonce_tpm.len());
                    }
                    Err(e) => { println!("SAS unmarshal ERR {e:?}"); return; }
                }
            }
            Err(e) => { println!("SAS cast ERR {e:?}"); return; }
        }
    }

    // --- CreatePrimary command (canonical) ---
    let parent_public = TpmtPublic {
        object_type: TpmAlgId::SymCipher,
        name_alg: TpmAlgId::Sha256,
        object_attributes: TpmaObject::FIXED_TPM | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN | TpmaObject::USER_WITH_AUTH
            | TpmaObject::RESTRICTED | TpmaObject::DECRYPT,
        auth_policy: Tpm2bDigest::try_from(&[][..]).unwrap(),
        parameters: TpmuPublicParms::SymCipher(TpmsSymcipherParms {
            sym: TpmtSymDef { algorithm: TpmAlgId::Aes, key_bits: TpmuSymKeyBits::Aes(128.into()), mode: TpmuSymMode::Aes(TpmAlgId::Cfb) },
        }),
        unique: TpmuPublicId::SymCipher(Tpm2bSymKey::try_from(&[][..]).unwrap()),
    };
    let cp = TpmCreatePrimaryCommand {
        handles: [hier],
        in_sensitive: Tpm2bSensitiveCreate { inner: TpmsSensitiveCreate { user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(), data: Tpm2bSensitiveData::try_from(&[][..]).unwrap() } },
        in_public: Tpm2bPublic { inner: parent_public },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };

    // parameter bytes come from a NoSessions marshal (no authAreaSize in that
    // layout), so [10 header + 4 handles..] is exactly the parameters region.
    let cp_nos = {
        let mut buf = vec![0u8; 512];
        let len = { let mut w = TpmWriter::new(&mut buf); tpm_marshal_command(&cp, TpmSt::NoSessions, &[], &mut w).unwrap(); w.len() };
        buf.truncate(len); buf
    };
    let param_area = &cp_nos[14..]; // 10 header + 4 handles

    // cpHash = H(cc || hierName || params); hier name = raw 4-byte handle
    let cc = 0x0000_0131u32;
    let mut cp_input = Vec::new();
    cp_input.extend_from_slice(&cc.to_be_bytes());
    cp_input.extend_from_slice(&hier.value().to_be_bytes());
    cp_input.extend_from_slice(param_area);
    let cp_hash = sha2::Sha256::digest(&cp_input);

    // unbound empty-auth: HMAC key = empty
    let attrs: u8 = 0x00;
    let mut hmsg = Vec::new();
    hmsg.extend_from_slice(&cp_hash);
    hmsg.extend_from_slice(&nonce_caller);
    hmsg.extend_from_slice(&nonce_tpm);
    hmsg.push(attrs);
    let req_hmac = {
        let mut m = Hmac256::new_from_slice(&[]).unwrap();
        m.update(&hmsg); m.finalize().into_bytes().to_vec()
    };
    println!("cpHash = {}", hex(&cp_hash));
    println!("reqHmac= {}", hex(&req_hmac));

    // session area (canonical TpmsAuthCommand)
    let sess = TpmsAuthCommand {
        session_handle: TpmHandle::new(sess_handle),
        nonce: Tpm2bNonce::try_from(nonce_caller.as_slice()).unwrap(),
        session_attributes: TpmaSession::default(),
        hmac: Tpm2bAuth::try_from(req_hmac.as_slice()).unwrap(),
    };
    let sess_area = {
        let mut b = vec![0u8; 128];
        let len = { let mut w = TpmWriter::new(&mut b); sess.marshal(&mut w).unwrap(); w.len() };
        b.truncate(len); b
    };

    // assemble: header(8002 size cc) + handle(4) + authSize(u32) + sess_area + params
    let mut cmd = Vec::new();
    cmd.extend_from_slice(&TpmSt::Sessions.value().to_be_bytes());
    let total = 10 + 4 + 4 + sess_area.len() + param_area.len();
    cmd.extend_from_slice(&(total as u32).to_be_bytes());
    cmd.extend_from_slice(&cc.to_be_bytes());
    cmd.extend_from_slice(&hier.value().to_be_bytes());
    cmd.extend_from_slice(&((sess_area.len()) as u32).to_be_bytes());
    cmd.extend_from_slice(&sess_area);
    cmd.extend_from_slice(param_area);
    println!("CPP CMD  = {} ({}B)", hex(&cmd), cmd.len());

    let resp = tpm.transfer(&cmd).unwrap();
    println!("CPP RESP = {} ({}B)", hex(&resp), resp.len());
    let rc = u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]]);
    println!("CPP rc = 0x{rc:08x} {}", if rc == 0 { "OK" } else { "FAIL" });
    if rc == 0 {
        use tpm2_protocol::frame::TpmResponse as R;
        match R::cast(&resp) {
            Ok(r) => match r.unmarshal::<TpmCreatePrimaryResponse>() {
                Ok(cr) => { use tpm2_protocol::TpmSized; println!("  UNMARSHAL OK new_entity=0x{:08x} out_public={}B name={}B", cr.handles[0].value(), cr.out_public.len(), cr.name.len()); },
                Err(e) => println!("  UNMARSHAL ERR: {e:?}"),
            },
            Err(e) => println!("  cast ERR: {e:?}"),
        }
    }
}
