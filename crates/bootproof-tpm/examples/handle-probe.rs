//! Empirical probe of the ESAPI persistent-handle occupant flush (the C1 flow):
//!  - raw read_public (empty vs occupied)
//!  - ESAPI from_tpm_public + evict_control(owner, tr, 0) to flush an occupant
//! Pass the handle as arg 2.
fn main() {
    let dev = std::env::args().nth(1).unwrap_or_else(|| "/dev/tpm0".into());
    let h: u32 = match std::env::args().nth(2) {
        Some(s) => u32::from_str_radix(s.trim_start_matches("0x"), 16).expect("bad handle"),
        None => 0x8101_0200,
    };
    let owner: u32 = 0x4000_0001;

    // Occupancy check (raw read_public works on persistent handles directly).
    let occupied = {
        let mut tpm = bootproof_tpm::conn::Tpm::open_started(std::path::Path::new(&dev)).unwrap();
        match tpm.read_public(h) {
            Ok(k) => {
                println!(
                    "read_public(0x{h:08x}) = OK  public={}B name={}B",
                    k.public.len(),
                    k.name.len()
                );
                true
            }
            Err(e) => {
                println!("read_public(0x{h:08x}) = ERR {e:?}  (empty)");
                false
            }
        }
    };

    if !occupied {
        println!("handle empty -> nothing to flush");
        return;
    }

    // The C1 ESAPI flush: register the persistent handle, then EvictControl(0).
    let mut esys = bootproof_tpm::EsysTpm::open(std::path::Path::new(&dev)).unwrap();
    esys.ensure_started().unwrap();
    let tr = esys
        .from_tpm_public(h)
        .expect("from_tpm_public (Esys_TR_FromTPMPublic)");
    println!("from_tpm_public(0x{h:08x}) = OK  ESYS_TR=0x{tr:08x}");
    match esys.evict_control(owner, tr, 0) {
        Ok(()) => println!("evict_control(owner, tr, 0) = OK  (flushed)"),
        Err(e) => println!("evict_control(owner, tr, 0) = ERR {e:?}"),
    }

    // Confirm it's empty now.
    let mut tpm = bootproof_tpm::conn::Tpm::open_started(std::path::Path::new(&dev)).unwrap();
    match tpm.read_public(h) {
        Ok(k) => println!(
            "  after: read_public OK name={}B (STILL OCCUPIED)",
            k.name.len()
        ),
        Err(e) => println!("  after: read_public ERR {e:?}  (now empty)"),
    }
}
