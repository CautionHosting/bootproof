//! Marshal the canonical CreatePrimary / Create / Load / Unseal through
//! tpm2-protocol and dump the exact param bytes. Ground truth for the
//! commands_seal.rs rewrite: the param bytes here are what swtpm accepts
//! (proven end-to-end via tpm2sh over the same crate).
use tpm2_protocol::basic::TpmHandle;
use tpm2_protocol::data::{
    Tpm2bAuth, Tpm2bData, Tpm2bDigest, Tpm2bEncryptedSecret, Tpm2bNonce, Tpm2bPrivate,
    Tpm2bPublic, Tpm2bSensitiveCreate, Tpm2bSensitiveData, Tpm2bSymKey, TpmAlgId, TpmSe,
    TpmSt, TpmaObject, TpmaSession, TpmsAuthCommand, TpmsKeyedhashParms, TpmsSensitiveCreate,
    TpmsSymcipherParms, TpmtKeyedhashScheme, TpmtPublic, TpmtSymDef, TpmlPcrSelection,
    TpmuKeyedhashScheme, TpmuPublicId, TpmuPublicParms, TpmuSymKeyBits, TpmuSymMode,
};
use tpm2_protocol::frame::{
    TpmCreateCommand, TpmCreatePrimaryCommand, TpmLoadCommand, TpmStartAuthSessionCommand,
    TpmUnsealCommand, tpm_marshal_command,
};
use tpm2_protocol::{TpmMarshal, TpmWriter};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn marshal<C: tpm2_protocol::frame::TpmFrame>(c: &C, tag: TpmSt) -> Vec<u8> {
    let mut buf = vec![0u8; 4096];
    let len = {
        let mut w = TpmWriter::new(&mut buf);
        tpm_marshal_command(c, tag, &[], &mut w).expect("marshal");
        w.len()
    };
    buf.truncate(len);
    buf
}

fn main() {
    // ---- StartAuthSession (HMAC, unsalted, unbound, SHA256) ----
    let sas = TpmStartAuthSessionCommand {
        handles: [TpmHandle::new(0x4000_0007), TpmHandle::new(0x4000_0007)],
        nonce_caller: Tpm2bNonce::try_from(&[0u8; 32][..]).unwrap(),
        encrypted_salt: Tpm2bEncryptedSecret::try_from(&[][..]).unwrap(),
        session_type: TpmSe::Hmac,
        symmetric: TpmtSymDef {
            algorithm: TpmAlgId::Null,
            key_bits: TpmuSymKeyBits::Null,
            mode: TpmuSymMode::Null,
        },
        auth_hash: TpmAlgId::Sha256,
    };
    println!("SAS          = {}", hex(&marshal(&sas, TpmSt::NoSessions)));

    // ---- SYMCIPHER AES-128-CFB storage key public ----
    let parent_public = TpmtPublic {
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
    };
    println!(
        "  parent attrs = 0x{:08x}",
        parent_public.object_attributes.bits()
    );

    let cp = TpmCreatePrimaryCommand {
        handles: [TpmHandle::new(0x4000_0001)],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(&[][..]).unwrap(),
            },
        },
        in_public: Tpm2bPublic {
            inner: parent_public.clone(),
        },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    println!("CreatePrim   = {}", hex(&marshal(&cp, TpmSt::NoSessions)));

    // ---- KEYEDHASH sealed object public (policy digest = 32 bytes) ----
    let policy = vec![0xabu8; 32];
    let sealed_public = TpmtPublic {
        object_type: TpmAlgId::KeyedHash,
        name_alg: TpmAlgId::Sha256,
        object_attributes: TpmaObject::FIXED_TPM
            | TpmaObject::FIXED_PARENT
            | TpmaObject::SENSITIVE_DATA_ORIGIN
            | TpmaObject::USER_WITH_AUTH
            | TpmaObject::ADMIN_WITH_POLICY
            | TpmaObject::NO_DA,
        auth_policy: Tpm2bDigest::try_from(policy.as_slice()).unwrap(),
        parameters: TpmuPublicParms::KeyedHash(TpmsKeyedhashParms {
            scheme: TpmtKeyedhashScheme {
                scheme: TpmAlgId::Null,
                details: TpmuKeyedhashScheme::Null,
            },
        }),
        unique: TpmuPublicId::KeyedHash(Tpm2bDigest::try_from(&[][..]).unwrap()),
    };
    println!(
        "  sealed attrs = 0x{:08x}",
        sealed_public.object_attributes.bits()
    );

    let data = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff,
    ];
    let cr = TpmCreateCommand {
        handles: [TpmHandle::new(0x8101_0000)],
        in_sensitive: Tpm2bSensitiveCreate {
            inner: TpmsSensitiveCreate {
                user_auth: Tpm2bAuth::try_from(&[][..]).unwrap(),
                data: Tpm2bSensitiveData::try_from(&data[..]).unwrap(),
            },
        },
        in_public: Tpm2bPublic {
            inner: sealed_public.clone(),
        },
        outside_info: Tpm2bData::try_from(&[][..]).unwrap(),
        creation_pcr: TpmlPcrSelection::default(),
    };
    println!("Create(noS)  = {}", hex(&marshal(&cr, TpmSt::NoSessions)));

    let ld = TpmLoadCommand {
        handles: [TpmHandle::new(0x8101_0000)],
        in_private: Tpm2bPrivate::try_from(&vec![0u8; 64][..]).unwrap(),
        in_public: Tpm2bPublic {
            inner: sealed_public,
        },
    };
    println!("Load(noS)    = {}", hex(&marshal(&ld, TpmSt::NoSessions)));

    let un = TpmUnsealCommand {
        handles: [TpmHandle::new(0x8000_0001)],
    };
    println!("Unseal(noS)  = {}", hex(&marshal(&un, TpmSt::NoSessions)));

    // session area layout (TpmsAuthCommand) for a 32-byte nonce + 32-byte hmac
    let sess = TpmsAuthCommand {
        session_handle: TpmHandle::new(0x0200_0000),
        nonce: Tpm2bNonce::try_from(&[0u8; 32][..]).unwrap(),
        session_attributes: TpmaSession::default(), // 1-byte attrs
        hmac: Tpm2bAuth::try_from(&[0u8; 32][..]).unwrap(),
    };
    let sess_bytes = {
        let mut b = vec![0u8; 512];
        let len = {
            let mut w = TpmWriter::new(&mut b);
            sess.marshal(&mut w).unwrap();
            w.len()
        };
        b.truncate(len);
        b
    };
    println!("sess_area    = {} ({}B)", hex(&sess_bytes), sess_bytes.len());
    println!("OK");
}
