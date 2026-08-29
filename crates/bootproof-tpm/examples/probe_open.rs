//! Probe: what connection-level behavior flips the firmware's SAS session
//! handle range (0x02xxxxxx vs 0x03xxxxxx)?
//!
//! Each test does a fresh open() of the TPM device (sequential; the device
//! is exclusive), sends a StartAuthSession, prints the returned handle, and
//! closes. Varying open flags and pre-SAS I/O patterns.

use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::thread;
use std::time::Duration;

fn sas_cmd(nonce: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(&0x8001u16.to_be_bytes());
    b.extend_from_slice(&59u32.to_be_bytes());
    b.extend_from_slice(&0x0176u32.to_be_bytes());
    b.extend_from_slice(&0x4000_0007u32.to_be_bytes()); // authHandle
    b.extend_from_slice(&0x4000_0007u32.to_be_bytes()); // bind
    b.extend_from_slice(&32u16.to_be_bytes());
    b.extend_from_slice(nonce);
    b.extend_from_slice(&0u16.to_be_bytes()); // keyBits
    b.push(0x01); // sessionType HMAC
    b.extend_from_slice(&0x0010u16.to_be_bytes()); // symmetric NULL
    b.extend_from_slice(&0x000bu16.to_be_bytes()); // authHash SHA256
    b
}

fn read_response(f: &mut impl Read, want: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    while buf.len() < want {
        let n = f.read(&mut tmp).unwrap();
        if n == 0 {
            break;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
    buf
}

fn do_sas(f: &mut std::fs::File, nonce: &[u8; 32]) -> Option<u32> {
    let cmd = sas_cmd(nonce);
    f.write_all(&cmd).ok()?;
    f.flush().ok()?;
    let resp = read_response(f, 48);
    if resp.len() >= 14 {
        Some(u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]))
    } else {
        eprintln!("short resp: {}B", resp.len());
        None
    }
}

fn open_basic(path: &Path) -> std::fs::File {
    OpenOptions::new().read(true).write(true).open(path).unwrap()
}

fn next_nonce(nonce: &mut [u8; 32], h: u32, counter: u32) {
    for (i, n) in nonce.iter_mut().enumerate() {
        *n = n
            .wrapping_add(h as u8)
            .wrapping_add(counter as u8)
            .wrapping_add(i as u8);
    }
}

fn main() {
    let arg = std::env::args().nth(1).unwrap_or_else(|| "/dev/tpm0".into());
    let path = Path::new(&arg);
    let mut nonce: [u8; 32] = [0u8; 32];
    let mut counter: u32 = 0;
    macro_rules! bump {
        ($h:expr, $label:expr) => {{
            counter = counter.wrapping_add(1);
            next_nonce(&mut nonce, $h, counter);
            println!("{}: 0x{:08x}", $label, $h);
        }};
    }

    // A: plain open
    {
        let mut f = open_basic(path);
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "A plain O_RDWR");
        }
    }
    // B: second open (fresh description)
    {
        let mut f = open_basic(path);
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "B plain again");
        }
    }
    // C: O_CLOEXEC
    {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x80000)
            .open(path)
            .unwrap();
        let mut f = f;
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "C O_CLOEXEC");
        }
    }
    // D: O_NONBLOCK
    {
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x800)
            .open(path)
            .unwrap();
        let mut f = f;
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "D O_NONBLOCK");
        }
    }
    // E: fstat before SAS
    {
        let mut f = open_basic(path);
        let _ = f.metadata();
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "E fstat first");
        }
    }
    // F: sleep 300ms after open
    {
        let mut f = open_basic(path);
        thread::sleep(Duration::from_millis(300));
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "F sleep 300ms");
        }
    }
    // G: GetRandom first, then SAS (nonce from TPM)
    {
        let mut f = open_basic(path);
        let mut gr = Vec::new();
        gr.extend_from_slice(&0x8001u16.to_be_bytes());
        gr.extend_from_slice(&12u32.to_be_bytes());
        gr.extend_from_slice(&0x017bu32.to_be_bytes());
        gr.extend_from_slice(&32u16.to_be_bytes());
        f.write_all(&gr).unwrap();
        let resp = read_response(&mut f, 40);
        if resp.len() >= 36 {
            nonce.copy_from_slice(&resp[12..44]);
        }
        if let Some(h) = do_sas(&mut f, &nonce) {
            bump!(h, "G GetRandom first");
        }
    }
    // H: split write (header, then body)
    {
        let mut f = open_basic(path);
        let cmd = sas_cmd(&nonce);
        f.write_all(&cmd[..10]).unwrap();
        f.write_all(&cmd[10..]).unwrap();
        f.flush().unwrap();
        let resp = read_response(&mut f, 48);
        if resp.len() >= 14 {
            bump!(u32::from_be_bytes([resp[10], resp[11], resp[12], resp[13]]), "H split write");
        }
    }
    // I: small read (16 bytes) then rest
    {
        let mut f = open_basic(path);
        let cmd = sas_cmd(&nonce);
        f.write_all(&cmd).unwrap();
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        let n1 = f.read(&mut tmp).unwrap();
        buf.extend_from_slice(&tmp[..n1.min(16)]);
        while buf.len() < 48 {
            let n = f.read(&mut tmp).unwrap();
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
        }
        if buf.len() >= 14 {
            bump!(u32::from_be_bytes([buf[10], buf[11], buf[12], buf[13]]), "I small read");
        }
    }
}
