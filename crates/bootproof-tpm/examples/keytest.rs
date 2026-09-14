//! Debug: exercise the key + attestation commands against a live (sw)TPM.
//!
//! Usage: cargo run -p bootproof-tpm --example keytest -- <tcp-addr | /dev/tpm0>
//!
//! Creates an ECC P-256 signing key (empty auth, no session), reads its
//! public area, produces a Quote over the measured PCRs, and signs a digest.
//! Used to validate the raw marshaling/parsing against a reference TPM.

use std::path::PathBuf;

use bootproof_tpm::{PcrSelection, Result, Tpm, constants::alg};

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or(0))
        .collect()
}

fn main() -> Result<()> {
    let target = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:2402".into());

    // --decode <rc...>: decode TPM/tss2 RC codes with the DIALECT's own
    // RC decoder (no device needed). e.g. keytest --decode 0x18a
    if std::env::args().any(|a| a == "--decode") {
        #[cfg(feature = "esys")]
        {
            let args: Vec<String> = std::env::args().collect();
            let i = args.iter().position(|a| a == "--decode").unwrap();
            for s in args.iter().skip(i + 1) {
                if let Ok(rc) = u32::from_str_radix(s.trim_start_matches("0x"), 16) {
                    println!("{s} = {}", bootproof_tpm::esys::decode_rc(rc));
                } else if let Ok(rc) = u32::from_str_radix(s, 16) {
                    println!("{s} = {}", bootproof_tpm::esys::decode_rc(rc));
                }
            }
            return Ok(());
        }
        #[cfg(not(feature = "esys"))]
        {
            return Err(bootproof_tpm::Error::Other(
                "bootproof-tpm was built without the `esys` feature".into(),
            ));
        }
    }

    // --rsatpl: build an RSA-2048 restricted-decrypt template, print its
    // dialect-marshalled wire bytes (via the platform tss2 Tss2_MU), then
    // CreatePrimary through the EsysTpm backend. Capture with BP_LOG_TCTI=1
    // for the exact working wire command.
    if std::env::args().any(|a| a == "--rsatpl") {
        #[cfg(feature = "esys")]
        {
            use bootproof_tpm::esys::{EsysTpm, rh_std};
            if !target.starts_with('/') {
                return Err(bootproof_tpm::Error::Other(
                    "--rsatpl needs a device path (/dev/tpm0)".into(),
                ));
            }
            let tp = bootproof_tpm::esys::build_rsa_decrypt_public();
            let mb = bootproof_tpm::esys::marshal_public_bytes(&tp)?;
            println!("[rs] marshalled RSA TPMT_PUBLIC ({}B): {}", mb.len(), hex(&mb));
            let mut tpm = EsysTpm::open(&PathBuf::from(&target))?;
            tpm.ensure_started()?;
            let flushed = tpm.flush_all();
            println!("[rs] flush_all OK: {flushed} handles flushed");
            match tpm.create_primary_with_public(rh_std::OWNER, &tp) {
                Ok(k) => println!(
                    "[rs] CreatePrimary RSA OK handle=0x{:08x} public={}B name={}",
                    k.handle,
                    k.public.len(),
                    hex(&k.name)
                ),
                Err(e) => println!("[rs] CreatePrimary RSA ERR {e}"),
            }
            return Ok(());
        }
        #[cfg(not(feature = "esys"))]
        {
            return Err(bootproof_tpm::Error::Other(
                "bootproof-tpm was built without the `esys` feature".into(),
            ));
        }
    }

    // --sepprobe: bisect the TPM2_SE wire byte for a policy session. Tries
    // 0x00 (HMAC), 0x01, 0x02 (std POLICY), 0x03 (TRIAL) through
    // StartAuthSession -> PolicyRestart -> PolicyPCR -> PolicyGetDigest.
    // keytest /dev/tpm0 --sepprobe
    if std::env::args().any(|a| a == "--sepprobe") {
        #[cfg(feature = "esys")]
        {
            use bootproof_tpm::esys::EsysTpm;
            if !target.starts_with('/') {
                return Err(bootproof_tpm::Error::Other(
                    "--sepprobe needs a device path (/dev/tpm0)".into(),
                ));
            }
            let mut tpm = EsysTpm::open(&PathBuf::from(&target))?;
            tpm.ensure_started()?;
            let _ = tpm.flush_all();
            let pcr = PcrSelection::new(alg::SHA256, &[7]);
            for st in [0x00u8, 0x01, 0x02, 0x03] {
                match tpm.start_auth_session(st) {
                    Err(e) => println!("[p] SE=0x{st:02x} START FAILED: {e}"),
                    Ok(sess) => {
                        println!("[p] SE=0x{st:02x} session=0x{sess:08x}");
                        // Fresh-session digest (is this a usable policy session?).
                        match tpm.policy_get_digest(sess) {
                            Ok(d) => println!("[p]   GetDigest(fresh) OK {}B", d.len()),
                            Err(e) => println!("[p]   GetDigest(fresh) FAIL: {e}"),
                        }
                        // Add PCR7 (the op the working raw path used).
                        match tpm.policy_pcr(sess, None, &[pcr]) {
                            Ok(()) => println!("[p]   PolicyPCR OK"),
                            Err(e) => println!("[p]   PolicyPCR FAIL: {e}"),
                        }
                        match tpm.policy_get_digest(sess) {
                            Ok(d) => println!("[p]   GetDigest(postPCR) OK {}B {}", d.len(), hex(&d)),
                            Err(e) => println!("[p]   GetDigest(postPCR) FAIL: {e}"),
                        }
                        // PolicyRestart (the op that has been failing).
                        match tpm.policy_restart(sess) {
                            Ok(()) => println!("[p]   PolicyRestart OK"),
                            Err(e) => println!("[p]   PolicyRestart FAIL: {e}"),
                        }
                        tpm.flush_session(sess);
                    }
                }
            }
            return Ok(());
        }
        #[cfg(not(feature = "esys"))]
        {
            return Err(bootproof_tpm::Error::Other(
                "bootproof-tpm was built without the `esys` feature".into(),
            ));
        }
    }

    // --rawpolicy: prove the RAW hand-rolled policy session path on a device.
    // pcr_read(7) -> start_policy_pcr_session (explicit live PCR 7) ->
    // policy_get_digest, cross-checked against the offline
    // policy_pcr_auth_policy() computation. keytest /dev/tpm0 --rawpolicy
    if std::env::args().any(|a| a == "--rawpolicy") {
        if !target.starts_with('/') {
            return Err(bootproof_tpm::Error::Other(
                "--rawpolicy needs a device path (/dev/tpm0)".into(),
            ));
        }
        let mut tpm = Tpm::open_started(&PathBuf::from(&target))?;
        let pcr = PcrSelection::new(alg::SHA256, &[7]);
        let live = tpm.pcr_read(&[pcr])?;
        let pcr7 = live
            .values
            .first()
            .map(|v| v.digest.clone())
            .ok_or_else(|| bootproof_tpm::Error::Other("no PCR 7 value".into()))?;
        if pcr7.len() != 32 {
            return Err(bootproof_tpm::Error::Other(format!(
                "PCR 7 digest is {}B (want 32)",
                pcr7.len()
            )));
        }
        println!("[rp0] PCR7 = {}", hex(&pcr7));
        let sess = tpm.start_policy_pcr_session(&[pcr], &[(7, pcr7.clone())])?;
        println!("[rp1] raw policy session OK handle=0x{:08x}", sess.handle);
        let digest = tpm.policy_get_digest(&sess)?;
        let _ = tpm.flush_context(sess.handle);
        if digest.len() != 32 {
            return Err(bootproof_tpm::Error::Other(format!(
                "live policy digest is {}B (want 32)",
                digest.len()
            )));
        }
        println!("[rp2] live PolicyGetDigest = {}", hex(&digest));
        let offline = bootproof_tpm::policy_pcr_auth_policy(&[pcr], &[(7, pcr7.clone())]);
        println!("[rp3] offline policy_pcr_auth_policy = {}", hex(&offline));
        if digest == offline {
            println!("[rp4] MATCH: live session digest == offline computation (32B)");
        } else {
            return Err(bootproof_tpm::Error::Other(
                "live policy digest != offline computation".into(),
            ));
        }
        return Ok(());
    }

    // --khprobe: bisect which keyedHash scheme the firmware accepts. Tries
    // XOR/KDF2, XOR/KDF1, HMAC/SHA256, NULL against a storage primary and
    // prints the RC for each. keytest /dev/tpm0 --khprobe
    if std::env::args().any(|a| a == "--khprobe") {
        #[cfg(feature = "esys")]
        {
            use bootproof_tpm::esys::EsysTpm;
            if !target.starts_with('/') {
                return Err(bootproof_tpm::Error::Other(
                    "--khprobe needs a device path (/dev/tpm0)".into(),
                ));
            }
            let mut tpm = EsysTpm::open(&PathBuf::from(&target))?;
            tpm.ensure_started()?;
            let _ = tpm.flush_all();
            let owner = bootproof_tpm::esys::rh_std::OWNER;
            let parent = tpm.create_storage_primary(owner)?;
            println!("[k0] storage parent 0x{:08x}", parent.handle);
            let data = b"khprobe";
            let cands: [(u16, u16, &str); 4] = [
                (0x000A, 0x0021, "XOR/KDF2"),
                (0x000A, 0x0020, "XOR/KDF1"),
                (0x0005, 0x0000, "HMAC/SHA256"),
                (0x0010, 0x0000, "NULL"),
            ];
            for (scheme, kdf, name) in cands {
                match tpm.create_data_object_with_scheme(parent.handle, data, &[], scheme, kdf) {
                    Ok(o) => println!(
                        "[k] {} OK private={}B name={}",
                        name,
                        o.private.len(),
                        hex(&o.name)
                    ),
                    Err(e) => println!("[k] {} REJECTED: {e}", name),
                }
            }
            return Ok(());
        }
        #[cfg(not(feature = "esys"))]
        {
            return Err(bootproof_tpm::Error::Other(
                "bootproof-tpm was built without the `esys` feature".into(),
            ));
        }
    }

    // --sealtest: validate the sealed-data-object path (EsysTpm). Seals a
    // keyedHash data object under the OWNER storage parent, Load + Unseal
    // round-trips it (no policy), then exercises an isolated policy session
    // (Restart -> PCR -> GetDigest) with a positive and a negative unseal.
    if std::env::args().any(|a| a == "--sealtest") {
        #[cfg(feature = "esys")]
        {
            use bootproof_tpm::esys::EsysTpm;
            if !target.starts_with('/') {
                return Err(bootproof_tpm::Error::Other(
                    "--sealtest needs a device path (/dev/tpm0)".into(),
                ));
            }
            let mut tpm = EsysTpm::open(&PathBuf::from(&target))?;
            tpm.ensure_started()?;
            let _ = tpm.flush_all();
            let owner = bootproof_tpm::esys::rh_std::OWNER;
            // The Create PARENT must be a storage (restricted+decrypt) key.
            // A signing primary here is rejected by the firmware with 0x18A
            // ("handle(1): the type of the value is not appropriate").
            let parent = tpm.create_storage_primary(owner)?;
            println!(
                "[s0] storage parent OK handle=0x{:08x} (rsa restricted+decrypt)",
                parent.handle
            );

            // Leg 1: no-policy data object, Create -> Load -> Unseal.
            let payload = b"stagex-dmext-sealtest-v1";
            let obj = tpm.create_data_object(parent.handle, payload, &[])?;
            println!(
                "[s1] Create data object OK private={}B public={}B name={}",
                obj.private.len(),
                obj.public.len(),
                hex(&obj.name)
            );
            let loaded = tpm.load_data_object(parent.handle, &obj)?;
            println!("[s2] Load OK handle=0x{:08x} (Name cross-checked)", loaded.handle);
            let got = tpm.unseal(loaded.handle)?;
            if got != payload {
                return Err(bootproof_tpm::Error::Other(
                    "unseal round-trip mismatch".into(),
                ));
            }
            println!("[s3] Unseal OK: {} bytes match", got.len());

            // Leg 2: isolated policy session — Restart -> PCR(7, current)
            // -> GetDigest. Verify the digest is non-empty and deterministic
            // (a second identical session yields the same digest).
            let pcr = PcrSelection::new(alg::SHA256, &[7]);
            let live_pcr = tpm.pcr_read(&[PcrSelection::new(alg::SHA256, &[7])])?;
            let pcr7 = live_pcr
                .values
                .first()
                .map(|v| v.digest.clone())
                .ok_or_else(|| bootproof_tpm::Error::Other("no PCR 7 value".into()))?;
            let sess = tpm.start_policy_session()?;
            tpm.policy_restart(sess)?;
            tpm.policy_pcr(sess, None, &[pcr])?;
            let digest = tpm.policy_get_digest(sess)?;
            tpm.flush_session(sess);
            if digest.len() != 32 {
                return Err(bootproof_tpm::Error::Other(format!(
                    "policy digest wrong length: {} (want 32)",
                    digest.len()
                )));
            }
            let sess_b = tpm.start_policy_session()?;
            tpm.policy_restart(sess_b)?;
            tpm.policy_pcr(sess_b, None, &[pcr])?;
            let digest_b = tpm.policy_get_digest(sess_b)?;
            tpm.flush_session(sess_b);
            if digest != digest_b {
                return Err(bootproof_tpm::Error::Other(
                    "policy digest not deterministic across sessions".into(),
                ));
            }
            println!(
                "[s4] policy session OK pcr7={} digest={} (deterministic)",
                hex(&pcr7),
                hex(&digest)
            );

            // Leg 3: negative — an explicit PCR 7 digest that does not match
            // the live value must be rejected (by PolicyPCR or Unseal).
            let wrong = pcr7.iter().map(|b| b ^ 0xFF).collect::<Vec<u8>>();
            let sess2 = tpm.start_policy_session()?;
            tpm.policy_restart(sess2)?;
            let res = tpm.policy_pcr(sess2, Some(&wrong), &[pcr]).and_then(|()| {
                tpm.unseal_policy(loaded.handle, sess2)
            });
            tpm.flush_session(sess2);
            match res {
                Err(e) => println!("[s5] negative policy correctly rejected: {e}"),
                Ok(_) => {
                    return Err(bootproof_tpm::Error::Other(
                        "negative policy unexpectedly succeeded".into(),
                    ))
                }
            }

            println!("\nALL SEALTEST COMMANDS OK");
            return Ok(());
        }
        #[cfg(not(feature = "esys"))]
        {
            return Err(bootproof_tpm::Error::Other(
                "bootproof-tpm was built without the `esys` feature".into(),
            ));
        }
    }

    // --esys: run the full flow through the EsysTpm (tss2 C stack) backend.
    // Optional 2nd arg: standard TPM_RH hierarchy hex (default 0x40000003 =
    // endorsement); the backend maps it to the platform dialect if detected.
    if std::env::args().any(|a| a == "--esys") {
        #[cfg(feature = "esys")]
        {
            use bootproof_tpm::esys::{EsysTpm, rh_std};
            let args: Vec<String> = std::env::args().collect();
            let explicit = args
                .iter()
                .position(|a| a == "--esys")
                .and_then(|i| args.get(i + 1))
                .and_then(|s| u32::from_str_radix(s.trim_start_matches("0x"), 16).ok());
            if !target.starts_with('/') {
                return Err(bootproof_tpm::Error::Other(
                    "--esys needs a device path (/dev/tpm0)".into(),
                ));
            }
            let mut tpm = EsysTpm::open(&PathBuf::from(&target))?;
            tpm.ensure_started()?;
            let hierarchy = explicit
                .unwrap_or(if tpm.dialect() {
                    // The dialect's endorsement hierarchy carries no
                    // authValue, so a NULL session cannot authenticate
                    // it (TPM RC 0x12F). OWNER works in both dialects.
                    rh_std::OWNER
                } else {
                    rh_std::OWNER
                });
            eprintln!("[e] backend=esys hierarchy=0x{hierarchy:08x}");
            println!("[e0] esys open + started: {target} dialect={}", tpm.dialect());
            let flushed = tpm.flush_all();
            println!("[0] flush_all OK: {flushed} handles flushed");
            let key = tpm.create_primary(hierarchy)?;
            println!("[1] CreatePrimary OK handle=0x{:08x}", key.handle);
            println!("    public len={} name={}", key.public.len(), hex(&key.name));
            println!("    public={}", hex(&key.public));
            let pub2 = tpm.read_public(key.handle)?;
            assert_eq!(pub2.public, key.public, "ReadPublic public != CreatePrimary");
            assert_eq!(pub2.name, key.name, "ReadPublic name != CreatePrimary");
            println!("[2] ReadPublic OK (matches CreatePrimary)");
            let pcrs = tpm.pcr_read(&[PcrSelection::all(alg::SHA256)])?;
            println!(
                "[3] PCRRead OK update_counter={} values={}",
                pcrs.update_counter,
                pcrs.values.len()
            );
            let nonce = [0x42u8; 16];
            let q = tpm.quote(&key, &nonce, &[PcrSelection::new(alg::SHA256, &[0])])?;
            println!(
                "[4] Quote OK attest={} sig_h={} sig_t={} pcr_digest={}",
                q.attestation.len(),
                hex(&q.sig_h),
                hex(&q.sig_t),
                hex(&q.pcr_digest)
            );
            println!("    pcr_select={}", hex(&q.pcr_select));
            let msg = b"bootproof";
            let (hashval, ticket) = tpm.hash(msg, alg::SHA256)?;
            println!(
                "[5a] Hash OK digest={} ticket_tag=0x{:04x} ticket_h=0x{:08x}",
                hex(&hashval),
                ticket.tag,
                ticket.hierarchy
            );
            let (h, t) = tpm.sign(&key, &hashval, Some(&ticket))?;
            println!("[5] Sign OK h={} t={}", hex(&h), hex(&t));
            println!("\nALL ESYS KEY COMMANDS OK");
            return Ok(());
        }
        #[cfg(not(feature = "esys"))]
        {
            return Err(bootproof_tpm::Error::Other(
                "bootproof-tpm was built without the `esys` feature".into(),
            ));
        }
    }

    let mut tpm = if target.starts_with('/') {
        Tpm::open_started(&PathBuf::from(&target))?
    } else {
        Tpm::connect_swtpm_tcp_started(&target)?
    };
    println!("connected: {target}");

    // 0. Diagnostic: enumerate + flush each handle type separately.
    let diag = std::env::args().any(|a| a == "--diag");
    if diag {
        for (name, htype) in [
            ("transient", bootproof_tpm::constants::ht::TRANSIENT),
            ("session", bootproof_tpm::constants::ht::SESSION),
            ("persistent", bootproof_tpm::constants::ht::PERSISTENT),
            ("nv", bootproof_tpm::constants::ht::NV_INDEX),
        ] {
            match tpm.get_handles(htype) {
                Ok(hs) => {
                    let list: Vec<String> =
                        hs.iter().map(|h| format!("0x{:08x}", h)).collect();
                    println!("  {name}: {} handles -> {}", hs.len(), list.join(", "));
                }
                Err(e) => println!("  {name}: get_handles ERROR: {e}"),
            }
        }
        return Ok(());
    }

    // --flush: enumerate + flush all loaded handles, then exit.
    if std::env::args().any(|a| a == "--flush") {
        let n = tpm.flush_all()?;
        println!("flushed {n} handles");
        return Ok(());
    }

    // --flush-sessions: directly flush the auto-allocated session handle
    // ranges (this TPM does not enumerate them via GetCapability). Recovers
    // from "out of memory for session contexts" (0x903).
    if std::env::args().any(|a| a == "--flush-sessions") {
        let n1 = tpm.flush_range(0x0200_0000, 0x0200_00FF)?;
        let n2 = tpm.flush_range(0x0300_0000, 0x0300_00FF)?;
        let n3 = tpm.flush_range(0x0100_0000, 0x0100_00FF)?;
        println!("flushed sessions: 0x02xx={n1} 0x03xx={n2} 0x01xx={n3}");
        return Ok(());
    }

    // --probe: try CreatePrimary against each hierarchy, report the raw RC.
    if std::env::args().any(|a| a == "--probe") {
        use bootproof_tpm::constants::rh;
        for (name, h) in [
            ("OWNER(0x40000002)", rh::OWNER),
            ("ENDORSEMENT(0x40000001)", rh::ENDORSEMENT),
            ("LOCKOUT(0x40000003)", rh::LOCKOUT),
            ("PLATFORM(0x40000007)", rh::PLATFORM),
            ("NULL(0x00000000)", 0x0000_0000u32),
        ] {
            match tpm.create_primary_rc(h) {
                Ok(rc) => println!("  {name}: RC=0x{:04x} {}", rc, if rc == 0 { "OK" } else { "ERR" }),
                Err(e) => println!("  {name}: transport error {e}"),
            }
        }
        return Ok(());
    }

    // --getrandom: probe TPM2_GetRandom (16 bytes).
    if std::env::args().any(|a| a == "--getrandom") {
        match tpm.get_random(16) {
            Ok(b) => println!("[r1] GetRandom OK: {}", hex(&b)),
            Err(e) => println!("[r1] GetRandom error {e}"),
        }
        return Ok(());
    }

    // --raw <hex>: send the given hex bytes as a raw command and print the
    // full response hex. For differential debugging against captured
    // tpm2-tools traffic.
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--raw") {
            if let Some(hexstr) = args.get(i + 1) {
                let clean: String = hexstr.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                let cmd = hex_to_bytes(&clean);
                eprintln!("[raw] sending {} bytes", cmd.len());
                let resp = tpm.transfer(&cmd)?;
                println!("[raw] resp ({}B): {}", resp.len(), hex(&resp));
                return Ok(());
            }
        }
    }

    // --rawtpl <primaryHex> <sensHex> <pubHex>: CreatePrimary (no session)
    // with fully caller-supplied TPMT_SENSITIVE / TPMT_PUBLIC raw bytes.
    // Template experiments to isolate firmware RC 0x2E1.
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--rawtpl") {
            let clean = |s: &str| s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>();
            let primary = args
                .get(i + 1)
                .and_then(|s| u32::from_str_radix(&clean(s), 16).ok())
                .unwrap_or(0x4000_0001);
            let sens = hex_to_bytes(&clean(args.get(i + 2).map(|s| s.as_str()).unwrap_or("")));
            let pubt = hex_to_bytes(&clean(args.get(i + 3).map(|s| s.as_str()).unwrap_or("")));
            eprintln!("[t] primary=0x{primary:08x} sens={}B pub={}B", sens.len(), pubt.len());
            let flushed = tpm.flush_all()?;
            println!("[t0] flush_all OK: {flushed} handles flushed");
            match tpm.create_primary_raw_tpl(primary, &sens, &pubt) {
                Ok(rc) => println!(
                    "[t1] CreatePrimary RC=0x{:04x} {}",
                    rc,
                    if rc == 0 { "OK" } else { "ERR" }
                ),
                Err(e) => println!("[t1] transport error {e}"),
            }
            return Ok(());
        }
    }

    // --exact: replay the platform tss2 C stack's exact pre-SAS command
    // sequence (byte-identical GetCapability + PCRRead + flush ranges), then
    // SAS + CreatePrimary-with-session. Isolates whether any pre-SAS command
    // byte (vs. connection-level state) drives the session pool allocation.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--exact") {
            let hex_send = |tpm: &mut Tpm, h: &str| {
                let b: Vec<u8> = (0..h.len()).step_by(2).map(|i| u8::from_str_radix(&h[i..i + 2], 16).unwrap()).collect();
                tpm.transfer(&b).map(|r| u32::from_be_bytes([r[6], r[7], r[8], r[9]]))
            };
            let rc1 = hex_send(&mut tpm, "8001000000160000017a000000000000004300000001");
            eprintln!("[x] GetCapability rc={rc1:?}");
            let rc2 = hex_send(&mut tpm, "8001000000140000017e00000001000b03010000");
            eprintln!("[x] PCRRead rc={rc2:?}");
            let mut f1 = 0usize;
            for h in 0x0000_0000u32..=0x0000_00FF {
                let hx = format!("80010000000e00000165{h:08x}");
                let b: Vec<u8> = (0..hx.len()).step_by(2).map(|i| u8::from_str_radix(&hx[i..i + 2], 16).unwrap()).collect();
                if tpm.transfer(&b).map(|r| r[6] == 0).unwrap_or(false) {
                    f1 += 1;
                }
            }
            let mut f2 = 0usize;
            for h in 0x0200_0000u32..=0x0200_00FF {
                let hx = format!("80010000000e00000165{h:08x}");
                let b: Vec<u8> = (0..hx.len()).step_by(2).map(|i| u8::from_str_radix(&hx[i..i + 2], 16).unwrap()).collect();
                if tpm.transfer(&b).map(|r| r[6] == 0).unwrap_or(false) {
                    f2 += 1;
                }
            }
            eprintln!("[x] flushed 0x00xx={f1} 0x02xx={f2}");
            let rc3 = hex_send(&mut tpm, "80010000000c0000017b0020");
            eprintln!("[x] GetRandom rc={rc3:?}");
            let session = tpm.start_auth_session(0x4000_0007, 0x00)?;
            let sensitive = bootproof_tpm::commands_key::build_ecc_sign_sensitive();
            let public = bootproof_tpm::commands_key::build_ecc_sign_template();
            let (rc, _body) =
                tpm.call_create_primary_with_session(0x4000_0001, &session, &sensitive, &public)?;
            let _ = tpm.flush_context(session.handle);
            println!(
                "[x1] CreatePrimary-with-session RC=0x{:04x} {}",
                rc,
                if rc == 0 { "OK" } else { "ERR" }
            );
            return Ok(());
        }
    }

    // --sascmd <hex>: send a verbatim raw SAS command (full wire bytes) and
    // print the response. Used to feed the exact captured esys SAS bytes and
    // observe the returned session-handle range from this client's connection.
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--sascmd") {
            let hx = args.get(i + 1).cloned().unwrap_or_default();
            let b: Vec<u8> = (0..hx.len())
                .step_by(2)
                .map(|j| u8::from_str_radix(&hx[j..j + 2], 16).unwrap())
                .collect();
            let resp = tpm.transfer(&b).unwrap();
            eprintln!("[sc] sent {}B, resp {}B: {}", b.len(), resp.len(), hex(&resp));
            if resp.len() >= 14 {
                let h = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
                println!("[sc] sessionHandle=0x{:08x}", h);
            }
            return Ok(());
        }
    }

    // --replay <file>: send each hex line of <file> verbatim (one full command
    // per line, no markers), in order, over this client's connection. Prints
    // the RC per command and the session handle for SAS responses. Used to
    // replay the platform C stack's captured preamble and isolate what makes
    // the firmware hand out a 0x02xxxxxx vs 0x03xxxxxx session handle.
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--replay") {
            let path = args.get(i + 1).cloned().unwrap_or_default();
            let text = std::fs::read_to_string(&path)
                .map_err(|e| bootproof_tpm::Error::Other(format!("replay file: {e}")))?;
            let mut n = 0usize;
            for line in text.lines() {
                let hx: String = line.chars().filter(|c| c.is_ascii_hexdigit()).collect();
                if hx.is_empty() {
                    continue;
                }
                let b: Vec<u8> = (0..hx.len())
                    .step_by(2)
                    .map(|j| u8::from_str_radix(&hx[j..j + 2], 16).unwrap())
                    .collect();
                let resp = tpm
                    .transfer(&b)
                    .map_err(|e| bootproof_tpm::Error::Other(format!("replay #{n}: {e}")))?;
                let rc = if resp.len() >= 10 {
                    u32::from_be_bytes([resp[6], resp[7], resp[8], resp[9]])
                } else {
                    0xDEAD_BEEF
                };
                let cc = if b.len() >= 10 {
                    u32::from_be_bytes([b[6], b[7], b[8], b[9]])
                } else {
                    0
                };
                if cc == 0x0000_0176 && resp.len() >= 14 {
                    let h = u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]);
                    println!("[rp] #{n} SAS rc=0x{rc:08x} sessionHandle=0x{h:08x}");
                } else if n < 5 || n % 100 == 0 || rc != 0 {
                    eprintln!("[rp] #{n} cc=0x{cc:08x} rc=0x{rc:08x} ({}B)", resp.len());
                }
                n += 1;
            }
            println!("[rp] done: {n} commands");
            return Ok(());
        }
    }

    // --sastest: session-pool allocation probe. Opens the device twice and
    // starts SAS sessions on each open (with random and fixed nonces) to map
    // how the firmware assigns session handle ranges per connection.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--sastest") {
            let device = target.clone();
            let p = PathBuf::from(&device);
            let mut t1 = Tpm::open(&p).unwrap();
            let mut t2 = Tpm::open(&p).unwrap();
            let s1 = t1
                .start_auth_session_nonce(0x4000_0007, 0x01, None)
                .map(|s| s.handle);
            let s2 = t2
                .start_auth_session_nonce(0x4000_0007, 0x01, None)
                .map(|s| s.handle);
            let s3 = t1
                .start_auth_session_nonce(0x4000_0007, 0x01, None)
                .map(|s| s.handle);
            let zero = [0u8; 32];
            let s4 = t2
                .start_auth_session_nonce(0x4000_0007, 0x01, Some(&zero))
                .map(|s| s.handle);
            let one = [1u8; 32];
            let s5 = t2
                .start_auth_session_nonce(0x4000_0007, 0x00, Some(&one))
                .map(|s| s.handle);
            println!(
                "open1#1={s1:?} open2#1={s2:?} open1#2={s3:?} open2#zero={s4:?} open2#explicit={s5:?}"
            );
            return Ok(());
        }
    }

    // --session [hierarchyHex] [sessionTypeHex]: CreatePrimary with our own ECC
    // signing template, inside an unbound empty-auth HMAC session authorizing
    // `hierarchy` (default 0x40000001 = this TPM's endorsement hierarchy).
    // sessionType default 00 (HMAC).
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--session") {
            let hierarchy = args
                .get(i + 1)
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .unwrap_or(0x4000_0001);
            let session_type = args
                .get(i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .unwrap_or(bootproof_tpm::session::TPM_SE_HMAC);
            eprintln!("[s] hierarchy=0x{hierarchy:08x} session_type={session_type}");
            if let Ok(s) = std::env::var("SAS_DELAY_MS") {
                let ms: u64 = s.parse().unwrap_or(0);
                eprintln!("[s] sleeping {ms}ms after open");
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
            // Preamble matching the platform tss2 C stack's startup, then
            // flush the session pools so stale sessions cannot linger.
            let prop = tpm.get_property(0x0043).unwrap_or(0);
            let _pcr = tpm.pcr_read(&[PcrSelection::new(alg::SHA256, &[0])]).is_ok();
            eprintln!("[s] preamble prop=0x{prop:08x} pcr_read={_pcr}");
            let flushed = tpm.flush_session_pools().unwrap_or(0);
            println!("[s0] session pools flushed: {flushed} handles");
            match tpm.create_primary_ecc_sign_session(hierarchy, session_type) {
                Ok(key) => println!(
                    "[s1] CreatePrimary-with-session OK handle=0x{:08x} name={}",
                    key.handle,
                    hex(&key.name)
                ),
                Err(e) => println!("[s1] CreatePrimary-with-session ERR {e}"),
            }
            return Ok(());
        }
    }

    // --rawcp <sasAuthHex> <sessionTypeHex> <primaryHex> <sensHex> <pubHex>:
    // CreatePrimary with a live session and fully caller-supplied inSensitive /
    // inPublic byte strings. Differential debugging against tpm2-tools traffic.
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(i) = args.iter().position(|a| a == "--rawcp") {
            let sas_auth = args
                .get(i + 1)
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .unwrap_or(0x4000_0007);
            let session_type = args
                .get(i + 2)
                .and_then(|s| u8::from_str_radix(s, 16).ok())
                .unwrap_or(bootproof_tpm::session::TPM_SE_HMAC);
            let primary = args
                .get(i + 3)
                .and_then(|s| u32::from_str_radix(s, 16).ok())
                .unwrap_or(0x4000_0001);
            let clean = |s: &str| s.chars().filter(|c| c.is_ascii_hexdigit()).collect::<String>();
            let sens_hex = clean(args.get(i + 4).map(|s| s.as_str()).unwrap_or(""));
            let pub_hex = clean(args.get(i + 5).map(|s| s.as_str()).unwrap_or(""));
            let sens = hex_to_bytes(&sens_hex);
            let pubb = hex_to_bytes(&pub_hex);
            eprintln!(
                "[rc] sas=0x{sas_auth:08x} type={session_type} primary=0x{primary:08x} sens={}B pub={}B",
                sens.len(),
                pubb.len()
            );
            match tpm.create_primary_raw_session(sas_auth, session_type, primary, &sens, &pubb) {
                Ok(rc) => println!(
                    "[rc] CreatePrimary RC=0x{:04x} {}",
                    rc,
                    if rc == 0 { "OK" } else { "ERR" }
                ),
                Err(e) => println!("[rc] transport error {e}"),
            }
            return Ok(());
        }
    }

    // --attestflow: replicate the attest collect() sequence to reproduce
    // the AK CreatePrimary 0x0902: flush pools, pcr_read, policy session
    // (expected to fail), then CreatePrimary-with-session.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--attestflow") {
            let _ = tpm.flush_session_pools();
            let all = PcrSelection::all(alg::SHA256);
            let disc = tpm.pcr_read(&[all]).unwrap();
            let available = disc.selection.map(|s| s.indices()).unwrap_or_default();
            let idx: Vec<u8> = (0..16u8).filter(|i| available.contains(i)).collect();
            let sel = PcrSelection::new(alg::SHA256, &idx);
            let read = tpm.pcr_read(&[sel]).unwrap();
            let per_pcr: Vec<(u8, Vec<u8>)> = idx
                .iter()
                .zip(read.values.iter())
                .map(|(i, v)| (*i, v.digest.clone()))
                .collect();
            match tpm.create_primary_sign_policy(&[sel.clone()], &per_pcr) {
                Ok(_) => println!("[af] sign_policy OK"),
                Err(e) => println!("[af] sign_policy ERR {e}"),
            }
            match tpm.create_primary_ecc_sign() {
                Ok(k) => println!("[af] AK CreatePrimary OK handle=0x{:08x}", k.handle),
                Err(e) => println!("[af] AK CreatePrimary ERR {e}"),
            }
            return Ok(());
        }
    }

    // --doublesas: two SAS on one connection, CreatePrimary with the second.
    {
        let args: Vec<String> = std::env::args().collect();
        if args.iter().any(|a| a == "--doublesas") {
            let _ = tpm.flush_session_pools();
            let ft = tpm.flush_range(0x8000_0000, 0x8000_00FF).unwrap_or(0);
            eprintln!("[ds] transient flush: {ft}");
            let s1 = tpm.start_auth_session(0x4000_0007, 0x00).unwrap();
            let _ = tpm.flush_context(s1.handle);
            match tpm.create_primary_ecc_sign() {
                Ok(k) => println!("[ds] AK CreatePrimary (2nd SAS) OK handle=0x{:08x}", k.handle),
                Err(e) => println!("[ds] AK CreatePrimary (2nd SAS) ERR {e}"),
            }
            return Ok(());
        }
    }

    // 0b. Flush any loaded contexts (recovers an exhausted context pool).
    let flushed = tpm.flush_all()?;
    println!("[0] flush_all OK: {flushed} handles flushed");

    // 1. Create a primary ECC P-256 signing key (empty auth, no session).
    let key = tpm.create_primary_ecc_sign()?;
    println!("[1] CreatePrimary OK handle=0x{:08x}", key.handle);
    println!("    public len={} name={}", key.public.len(), hex(&key.name));

    // 2. ReadPublic for the same handle.
    let pub2 = tpm.read_public(key.handle)?;
    assert_eq!(pub2.public, key.public, "ReadPublic public != CreatePrimary");
    assert_eq!(pub2.name, key.name, "ReadPublic name != CreatePrimary");
    println!("[2] ReadPublic OK (matches CreatePrimary)");

    // 3. PCR read (sha256, all) to know what the quote will cover.
    let pcrs = tpm.pcr_read(&[PcrSelection::all(alg::SHA256)])?;
    println!("[3] PCRRead OK update_counter={} values={}", pcrs.update_counter, pcrs.values.len());

    // 4. Quote over PCR 0 (sha256) with a 16-byte qualifying data (nonce).
    let nonce = [0x42u8; 16];
    let q = tpm.quote(&key, &nonce, &[PcrSelection::new(alg::SHA256, &[0])])?;
    println!(
        "[4] Quote OK attest={} sig_h={} sig_t={} pcr_digest={}",
        q.attestation.len(),
        hex(&q.sig_h),
        hex(&q.sig_t),
        hex(&q.pcr_digest)
    );
    println!("    pcr_select={}", hex(&q.pcr_select));

    // 5. Sign with the key (TPM2_Hash + ticket + session internally).
    let data = [0xABu8; 32];
    let (h, t) = tpm.sign(&key, &data)?;
    println!("[5] Sign OK h={} t={}", hex(&h), hex(&t));

    println!("\nALL KEY COMMANDS OK");
    Ok(())
}
