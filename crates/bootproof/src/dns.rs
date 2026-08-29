//! Minimal DNS over UDP for `_bootproof.<domain>` TXT discovery.
//!
//! The TXT record is a pointer + hint:
//! ```text
//! _bootproof.caution.co. TXT "endpoint=attest.caution.co:443;key=sha256:<hex>;image=sha384:<hex>"
//! ```
//! No external DNS library: one query, one parse.

use std::hash::Hasher;
use std::net::{UdpSocket, Ipv4Addr};
use std::time::Duration;

/// Parsed `_bootproof` TXT record.
#[derive(Debug, Clone, Default)]
pub struct BootproofRecord {
    /// The host[:port] serving the attest API (required).
    pub endpoint: Option<String>,
    /// SHA-256 pin hint for the daemon pubkey (hex).
    pub key: Option<Vec<u8>>,
    /// SHA-384 expected image hash hint (hex).
    pub image: Option<Vec<u8>>,
}

fn encode_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        if label.is_empty() {
            continue;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

fn build_query(id: u16, fqdn: &str) -> Vec<u8> {
    let mut q = Vec::new();
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    q.extend_from_slice(&[1, 0, 0, 0, 0, 0]); // counts
    q.extend_from_slice(&encode_name(fqdn));
    q.extend_from_slice(&16u16.to_be_bytes()); // TXT
    q.extend_from_slice(&1u16.to_be_bytes()); // IN
    q
}

fn hex_to_bytes(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

fn parse_record(value: &str) -> BootproofRecord {
    let mut rec = BootproofRecord::default();
    for part in value.split(';') {
        let part = part.trim();
        if let Some(k) = part.strip_prefix("endpoint=") {
            rec.endpoint = Some(k.to_string());
        } else if let Some(k) = part.strip_prefix("key=sha256:") {
            rec.key = hex_to_bytes(k);
        } else if let Some(k) = part.strip_prefix("image=sha384:") {
            rec.image = hex_to_bytes(k);
        }
    }
    rec
}

/// Read DNS response names (handles compression pointers). Advances `o`
/// past the name.
fn skip_name(buf: &[u8], o: usize) -> Option<usize> {
    let mut o = o;
    loop {
        let len = *buf.get(o)? as usize;
        if len == 0 {
            return Some(o + 1);
        }
        if len & 0xC0 == 0xC0 {
            // Pointer: 2 bytes, stop (the target is elsewhere).
            return Some(o + 2);
        }
        o += 1 + len;
    }
}

/// Look up `_bootproof.<domain>` TXT. Returns `None` when the record does
/// not exist (NXDOMAIN / NOERROR-empty / no server answered).
pub fn lookup(domain: &str) -> Option<BootproofRecord> {
    let fqdn = format!("_bootproof.{domain}");
    let servers = [Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(1, 1, 1, 1)];

    let mut h = std::collections::hash_map::DefaultHasher::new();
    std::hash::Hash::hash(&fqdn, &mut h);
    let id = (h.finish() >> 8) as u16;
    let query = build_query(id, &fqdn);

    for server in servers {
        let sock = match UdpSocket::bind("0.0.0.0:0") {
            Ok(s) => s,
            Err(_) => continue,
        };
        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = sock.set_write_timeout(Some(Duration::from_secs(2)));
        let addr = std::net::SocketAddr::from((server, 53));
        if sock.send_to(&query, addr).is_err() {
            continue;
        }
        let mut buf = [0u8; 4096];
        let (n, _) = match sock.recv_from(&mut buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let resp = &buf[..n];
        if resp.len() < 12 {
            continue;
        }
        let rid = u16::from_be_bytes([resp[0], resp[1]]);
        if rid != id {
            continue;
        }
        let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

        // Skip the question section.
        let mut o = 12;
        for _ in 0..1usize {
            o = skip_name(resp, o)?;
            o += 4; // qtype + qclass
        }

        let mut strings: Vec<String> = Vec::new();
        for _ in 0..ancount {
            o = skip_name(resp, o)?;
            if resp.len() < o + 10 {
                break;
            }
            let typ = u16::from_be_bytes([resp[o], resp[o + 1]]);
            let rdlen = u16::from_be_bytes([resp[o + 8], resp[o + 9]]) as usize;
            o += 10;
            if resp.len() < o + rdlen {
                break;
            }
            if typ == 16 {
                // TXT: sequence of { len u8, bytes }
                let mut p = 0;
                while p < rdlen {
                    let slen = resp[o + p] as usize;
                    if slen == 0 || p + 1 + slen > rdlen {
                        break;
                    }
                    strings.push(
                        String::from_utf8_lossy(&resp[o + p + 1..o + p + 1 + slen]).to_string(),
                    );
                    p += 1 + slen;
                }
            }
            o += rdlen;
        }
        if !strings.is_empty() {
            return Some(parse_record(&strings.join("")));
        }
    }
    None
}
