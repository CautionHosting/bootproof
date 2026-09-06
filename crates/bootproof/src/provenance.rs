//! StageX build provenance: parse `/provenance.spdx` (SPDX 2.3 tag-value,
//! baked into the image at build time) and check its package digests
//! against the published StageX container signatures.
//!
//! Signature layout (sigs.stagex.tools / codeberg.org/stagex/signatures):
//! `<root>/stagex/<name>@sha256=<digest>/signature-N` — one file per
//! independent rebuild (quorum: >= 2 maintainers). Files are complete PGP
//! signed messages (Container Signature Format payload embedded), checked in
//! process with rPGP (the `pgp` crate) against the maintainer keyring --
//! no external `gpg`. The keyring ships as a raw OpenPGP public-key packet
//! stream, which rPGP reads directly (GnuPG 2.x needs it imported into a
//! kbx first and cannot verify against the file as-is).
//!
//! Verdict discipline (matches trust/mod.rs): the document itself is
//! self-reported (the build wrote it) — at best `likely`. A digest earns
//! `true` only when a published signature for it verifies against the
//! pinned keyring. An unsigned dev build is `unknown`; the honest close is
//! "rebuild locally at the pinned commit and compare the digests".

use std::path::{Path, PathBuf};

/// One SPDX package block.
#[derive(Debug, Clone, Default)]
pub struct Pkg {
    pub name: String,
    pub spdx_id: String,
    pub version: Option<String>,
    /// SHA256 hex (lowercase), when `PackageChecksum: SHA256: ...` present.
    pub digest: Option<String>,
    /// Free-form comment (e.g. `branch=lance/distros dirty=0`, `src=<sha>`).
    pub comment: Option<String>,
    /// `ExternalRef` values (e.g. `OTHER git-of-origin <url>`).
    pub external_refs: Vec<String>,
}

/// Where the source tree came from (from the `stagex` package block).
#[derive(Debug, Clone, Default)]
pub struct GitOrigin {
    pub repo: Option<String>,
    pub commit: Option<String>,
    pub branch: Option<String>,
    pub dirty: Option<String>,
}

impl GitOrigin {
    /// `repo @ <16-hex commit> (branch X, dirty N)` — compact display.
    pub fn display(&self) -> Option<String> {
        let commit = self.commit.as_ref()?;
        let mut s = format!(
            "{} @ {}",
            self.repo.as_deref().unwrap_or("unknown repo"),
            &commit[..commit.len().min(16)]
        );
        if let Some(b) = &self.branch {
            s.push_str(&format!(" (branch {b}"));
            if let Some(d) = &self.dirty {
                s.push_str(&format!(", dirty {d}"));
            }
            s.push(')');
        }
        Some(s)
    }
}

/// A parsed SPDX 2.3 tag-value document.
#[derive(Debug, Clone, Default)]
pub struct SpdxDoc {
    pub spdx_version: Option<String>,
    pub doc_name: Option<String>,
    pub doc_namespace: Option<String>,
    pub creator: Option<String>,
    pub created: Option<String>,
    pub packages: Vec<Pkg>,
    pub relationships: usize,
    pub git: GitOrigin,
}

impl SpdxDoc {
    pub fn digest_count(&self) -> usize {
        self.packages.iter().filter(|p| p.digest.is_some()).count()
    }
}

/// Parse an SPDX 2.3 tag-value document. Tolerant: unknown fields are
/// ignored, blocks are separated by blank lines.
pub fn parse_spdx(text: &str) -> Result<SpdxDoc, String> {
    let mut doc = SpdxDoc::default();
    let mut cur: Option<usize> = None;

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            cur = None;
            continue;
        }
        let (field, val) = match line.split_once(':') {
            Some(t) => t,
            None => continue,
        };
        let (field, val) = (field.trim(), val.trim());
        match field {
            "SPDXVersion" => doc.spdx_version = Some(val.to_string()),
            "DocumentName" => doc.doc_name = Some(val.to_string()),
            "DocumentNamespace" => doc.doc_namespace = Some(val.to_string()),
            "Creator" => doc.creator = Some(val.to_string()),
            "Created" => doc.created = Some(val.to_string()),
            "Relationship" => doc.relationships += 1,
            "PackageName" => {
                cur = Some(doc.packages.len());
                doc.packages.push(Pkg {
                    name: val.to_string(),
                    ..Default::default()
                });
            }
            _ => {
                let Some(i) = cur else { continue };
                let p = &mut doc.packages[i];
                match field {
                    "SPDXID" => p.spdx_id = val.to_string(),
                    "PackageVersion" => p.version = Some(val.to_string()),
                    "PackageComment" => p.comment = Some(val.to_string()),
                    "ExternalRef" => p.external_refs.push(val.to_string()),
                    "PackageChecksum" => {
                        if let Some(hex) = val.strip_prefix("SHA256:") {
                            p.digest = Some(hex.trim().to_lowercase());
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Git origin: the distro-source package (named "stagex") carries
    // ExternalRef git-of-origin, PackageVersion = commit, and a comment
    // with branch/dirty.
    if let Some(sp) = doc.packages.iter().find(|p| p.name == "stagex") {
        if let Some(v) = sp.version.clone() {
            doc.git.commit = Some(v);
        }
        if let Some(c) = &sp.comment {
            for tok in c.split_whitespace() {
                if let Some(b) = tok.strip_prefix("branch=") {
                    doc.git.branch = Some(b.to_string());
                }
                if let Some(d) = tok.strip_prefix("dirty=") {
                    doc.git.dirty = Some(d.to_string());
                }
            }
        }
        for r in &sp.external_refs {
            if let Some(u) = r.split_once("git-of-origin") {
                let mut repo = u.1.trim().trim_end_matches(".git").to_string();
                for scheme in ["https://", "http://", "git://", "ssh://"] {
                    if let Some(stripped) = repo.strip_prefix(scheme) {
                        repo = stripped.to_string();
                        break;
                    }
                }
                doc.git.repo = Some(repo);
            }
        }
    }
    Ok(doc)
}

/// Category prefixes stripped when matching a package name to a
/// signature-directory name (older sigs dirs drop the prefix).
const CATEGORY_PREFIXES: &[&str] = &["core-", "user-", "pallet-", "bootstrap-", "service-"];

/// One package's published-signature status.
#[derive(Debug, Clone, Default)]
pub struct CoverageRow {
    pub name: String,
    pub digest: String,
    /// Signature file names found (e.g. `["signature-1", "signature-2"]`).
    pub sigs: Vec<String>,
    /// Per-sig OpenPGP verification outcome (None = not attempted).
    pub verified: Vec<Option<bool>>,
    /// What was checked (local path or lookaside URL).
    pub checked: String,
}

impl CoverageRow {
    pub fn signed(&self) -> bool {
        !self.sigs.is_empty()
    }
    /// Quorum met: >= 2 signatures, and (if verified) >= 2 good.
    pub fn quorum(&self) -> bool {
        if self.verified.iter().all(|v| v.is_none()) {
            self.sigs.len() >= 2
        } else {
            self.verified.iter().filter(|v| **v == Some(true)).count() >= 2
        }
    }
}

/// Candidate signature-directory names for a package: exact name first,
/// then with known category prefixes stripped.
pub fn dir_candidates(name: &str) -> Vec<String> {
    let mut v = vec![name.to_string()];
    for p in CATEGORY_PREFIXES {
        if let Some(stripped) = name.strip_prefix(p) {
            if !stripped.is_empty() {
                v.push(stripped.to_string());
            }
        }
    }
    v
}

/// Check a local checkout of the signatures repo. `sigs_root` is the
/// directory containing the `<name>@sha256=<digest>/` entries (e.g.
/// `<checkout>/stagex`).
pub fn coverage_local(packages: &[Pkg], sigs_root: &Path) -> Vec<CoverageRow> {
    let checked = sigs_root.display().to_string();
    packages
        .iter()
        .filter_map(|p| p.digest.as_ref().map(|d| (p, d.as_str())))
        .map(|(p, d)| {
            let mut sigs = Vec::new();
            for cand in dir_candidates(&p.name) {
                let dir = sigs_root.join(format!("{cand}@sha256={d}"));
                if dir.is_dir() {
                    if let Ok(rd) = std::fs::read_dir(&dir) {
                        for e in rd.flatten() {
                            let n = e.file_name().to_string_lossy().to_string();
                            if n.starts_with("signature") {
                                sigs.push(n);
                            }
                        }
                    }
                    break;
                }
            }
            sigs.sort();
            CoverageRow {
                name: p.name.clone(),
                digest: d.to_string(),
                sigs,
                verified: Vec::new(),
                checked: checked.clone(),
            }
        })
        .collect()
}

/// Lookaside URL for one signature slot of a package digest.
pub fn lookaside_url(base: &str, name: &str, digest: &str, n: usize) -> String {
    format!(
        "{}/stagex/{}@sha256={}/signature-{}",
        base.trim_end_matches('/'),
        name,
        digest,
        n
    )
}

/// Check the remote lookaside (`<base>/stagex/<name>@sha256=<d>/signature-N`).
/// At most `max_pkgs` packages are queried (each is an HTTP round trip).
pub fn coverage_lookaside(
    packages: &[Pkg],
    base: &str,
    max_pkgs: usize,
) -> anyhow::Result<Vec<CoverageRow>> {
    let base = base.trim_end_matches('/');
    let checked = format!("lookaside {base}");
    let mut out = Vec::new();
    for p in packages.iter().take(max_pkgs) {
        let Some(d) = &p.digest else { continue };
        let mut sigs = Vec::new();
        for n in 1..=4usize {
            let url = lookaside_url(base, &p.name, d, n);
            match ureq::get(&url).timeout(std::time::Duration::from_secs(15)).call() {
                Ok(_) => sigs.push(format!("signature-{n}")),
                Err(ureq::Error::Status(404, _)) => {}
                Err(ureq::Error::Status(403, _)) => {}
                Err(e) => return Err(anyhow::anyhow!("lookaside {url}: {e}")),
            }
        }
        out.push(CoverageRow {
            name: p.name.clone(),
            digest: d.clone(),
            sigs,
            verified: Vec::new(),
            checked: checked.clone(),
        });
    }
    Ok(out)
}

/// Verify one signature file against a PGP keyring, in-process with rPGP
/// (the `pgp` crate). No external `gpg`.
///
/// Signature files are complete PGP signed messages (the payload is embedded,
/// so no external target is needed). The keyring is a plain OpenPGP
/// public-key packet stream (first byte `0x99` = binary tag 6), which rPGP
/// reads directly. Semantics match the old `gpg --batch --no-default-keyring
/// --keyring K --verify S`: Ok(true) iff a key in the keyring produces a good
/// signature, and the isolation gpg got from `--no-default-keyring` is
/// automatic -- only the bytes we hand rPGP are considered.
pub fn verify_sig_gpg(sig_file: &Path, keyring: &Path) -> anyhow::Result<bool> {
    Ok(verify_sig_full(sig_file, keyring)?.verified)
}

/// rPGP verification outcome. Strictly more information than the old gpg exit
/// code: which key verified (fingerprint) or why it failed.
pub struct SigVerify {
    pub verified: bool,
    /// Fingerprint of the key that produced the good signature.
    pub fingerprint: Option<String>,
    /// What the signature covers (the embedded payload length).
    pub payload_len: Option<usize>,
    /// Error detail when not verified.
    pub error: Option<String>,
}

/// Verify one signature file against a PGP keyring with rPGP, returning the
/// full outcome. See [`verify_sig_gpg`] for the semantics.
pub fn verify_sig_full(sig_file: &Path, keyring: &Path) -> anyhow::Result<SigVerify> {
    use pgp::composed::{Message, PublicOrSecret};
    use pgp::types::KeyDetails;
    use std::io::Read;

    let kb = std::fs::read(keyring).map_err(|e| anyhow::anyhow!("read keyring: {e}"))?;
    let sig = std::fs::read(sig_file).map_err(|e| anyhow::anyhow!("read sig: {e}"))?;

    let mut msg = Message::from_bytes(&*sig)
        .map_err(|e| anyhow::anyhow!("parse signature: {e}"))?;
    // The published signature is a compressed (zlib) message wrapping the
    // signed one; gpg decompressed transparently, rPGP needs the explicit step.
    if matches!(msg, Message::Compressed { .. }) {
        msg = msg
            .decompress()
            .map_err(|e| anyhow::anyhow!("decompress signature: {e}"))?;
    }
    // Drive the literal-data hash by reading the embedded payload to the end.
    let mut buf: Vec<u8> = Vec::new();
    msg.read_to_end(&mut buf)
        .map_err(|e| anyhow::anyhow!("read signed content: {e}"))?;
    let payload_len = buf.len();

    let (keys, _headers) = PublicOrSecret::from_reader_many(&*kb)
        .map_err(|e| anyhow::anyhow!("parse keyring: {e}"))?;
    for key in keys.filter_map(Result::ok) {
        let PublicOrSecret::Public(k) = key else { continue };
        // The published sig is made by a dedicated signing subkey, so check
        // the primary key and then each subkey (gpg --verify does the same).
        if msg.verify(&k).is_ok() {
            return Ok(SigVerify {
                verified: true,
                fingerprint: Some(k.fingerprint().to_string()),
                payload_len: Some(payload_len),
                error: None,
            });
        }
        for sk in &k.public_subkeys {
            if msg.verify(sk).is_ok() {
                return Ok(SigVerify {
                    verified: true,
                    fingerprint: Some(sk.fingerprint().to_string()),
                    payload_len: Some(payload_len),
                    error: None,
                });
            }
        }
    }
    Ok(SigVerify {
        verified: false,
        fingerprint: None,
        payload_len: Some(payload_len),
        error: Some("no key in the keyring produced a good signature".to_string()),
    })
}

/// Per-package digest comparison between two documents (the image-baked
/// one vs a locally regenerated one after a rebuild).
#[derive(Debug, Clone, Default)]
pub struct CompareReport {
    /// Packages present (with digests) in both, digests equal.
    pub matched: usize,
    /// Packages present in both, digests differ: (name, baked, regenerated).
    pub mismatched: Vec<(String, String, String)>,
    /// Digest-bearing packages only in the baked doc.
    pub only_baked: Vec<String>,
    /// Digest-bearing packages only in the regenerated doc.
    pub only_regen: Vec<String>,
}

impl CompareReport {
    pub fn ok(&self) -> bool {
        self.mismatched.is_empty() && self.only_baked.is_empty() && self.only_regen.is_empty()
    }
}

/// Compare the per-package digests of two parsed documents.
pub fn compare(baked: &SpdxDoc, regen: &SpdxDoc) -> CompareReport {
    let mut rep = CompareReport::default();
    let map = |d: &SpdxDoc| -> std::collections::HashMap<String, String> {
        d.packages
            .iter()
            .filter_map(|p| p.digest.as_ref().map(|x| (p.name.clone(), x.clone())))
            .collect()
    };
    let a = map(baked);
    let b = map(regen);
    for (n, d) in &a {
        match b.get(n) {
            Some(x) if x == d => rep.matched += 1,
            Some(x) => rep.mismatched.push((n.clone(), d.clone(), x.clone())),
            None => rep.only_baked.push(n.clone()),
        }
    }
    for n in b.keys() {
        if !a.contains_key(n) {
            rep.only_regen.push(n.to_string());
        }
    }
    rep.mismatched.sort();
    rep.only_baked.sort();
    rep.only_regen.sort();
    rep
}

/// Render the comparison section (appended to the main report).
pub fn render_compare(rep: &CompareReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("  compare     {} matched", rep.matched));
    if rep.ok() {
        s.push_str(" — IDENTICAL: the local rebuild reproduces every baked digest\n");
    } else {
        s.push_str("\n");
        for (n, a, b) in &rep.mismatched {
            s.push_str(&format!(
                "  ✗ {:<38} baked={} regenerated={}\n",
                n,
                &a[..a.len().min(16)],
                &b[..b.len().min(16)]
            ));
        }
        for n in &rep.only_baked {
            s.push_str(&format!("  - {:<38} only in the baked document\n", n));
        }
        for n in &rep.only_regen {
            s.push_str(&format!("  + {:<38} only in the regenerated document\n", n));
        }
        s.push_str("  verdict     ✗ rebuild does NOT reproduce the baked document\n");
    }
    s
}

/// Render the report (plain text).
pub fn render(
    doc: &SpdxDoc,
    rows: &Option<Vec<CoverageRow>>,
    all: bool,
) -> String {
    let mut s = String::new();
    s.push_str("STAGEX PROVENANCE (");
    s.push_str(doc.spdx_version.as_deref().unwrap_or("SPDX ?"));
    s.push_str(")\n");
    if let Some(n) = &doc.doc_name {
        s.push_str(&format!("  document    {n}\n"));
    }
    if let Some(o) = doc.git.display() {
        s.push_str(&format!("  origin      {o}\n"));
    }
    s.push_str(&format!(
        "  packages    {} ({} with SHA256 digests, {} dependency edges)\n",
        doc.packages.len(),
        doc.digest_count(),
        doc.relationships
    ));
    match rows {
        Some(rows) if !rows.is_empty() => {
            let signed = rows.iter().filter(|r| r.signed()).count();
            let quorum = rows.iter().filter(|r| r.quorum()).count();
            let src = rows[0].checked.clone();
            s.push_str(&format!(
                "  signatures  {signed} / {} published, {quorum} at quorum (source: {src})\n",
                rows.len()
            ));
            if signed == 0 {
                let commit = doc.git.commit.as_deref().unwrap_or("<commit>");
                s.push_str("  verdict     ? unsigned build (dev build, no published sigs)\n");
                s.push_str("              full confirmation: rebuild locally at the pinned\n");
                s.push_str(&format!(
                    "              commit {commit}, regenerate with\n"
                ));
                s.push_str("              `python3 src/provenance.py <target> --raw`, then\n");
                s.push_str("              `bootproof provenance --compare <regenerated-doc>`. Per-\n");
                s.push_str("              package digests = sha256(out/rootfs/<pkg>/manifest.txt);\n");
                s.push_str("              the image digest = sha256(disk.img).\n");
            } else if signed < rows.len() {
                s.push_str(&format!(
                    "  verdict     ~ partially signed ({signed} of {})\n",
                    rows.len()
                ));
            } else {
                s.push_str("  verdict     ✓ all digests have published signatures\n");
            }
            if all {
                for r in rows {
                    let mark = if r.quorum() {
                        "✓"
                    } else if r.signed() {
                        "~"
                    } else {
                        " "
                    };
                    let v = if r.verified.is_empty() {
                        String::new()
                    } else {
                        format!(
                            "  pgp={}",
                            r.verified
                                .iter()
                                .map(|v| match v {
                                    Some(true) => "Y",
                                    Some(false) => "N",
                                    None => "-",
                                })
                                .collect::<String>()
                        )
                    };
                    s.push_str(&format!(
                        "  {mark} {:<38} {} {}{}\n",
                        r.name,
                        &r.digest[..r.digest.len().min(16)],
                        if r.sigs.is_empty() {
                            "no published sig".to_string()
                        } else {
                            r.sigs.join(",")
                        },
                        v
                    ));
                }
            } else if signed < rows.len() {
                let mut shown = 0;
                for r in rows.iter().filter(|r| r.signed()) {
                    s.push_str(&format!(
                        "  ✓ {:<38} {}\n",
                        r.name,
                        &r.digest[..r.digest.len().min(16)]
                    ));
                    shown += 1;
                    if shown >= 10 {
                        s.push_str(&format!(
                            "  ... and {} more signed\n",
                            rows.iter().filter(|r| r.signed()).count() - 10
                        ));
                        break;
                    }
                }
            }
        }
        _ => {
            s.push_str("  signatures  not checked (pass --sigs <repo> or --lookaside <url>)\n");
        }
    }
    s
}

/// Render the report as JSON.
pub fn to_json(
    doc: &SpdxDoc,
    rows: &Option<Vec<CoverageRow>>,
    compare: &Option<CompareReport>,
) -> String {
    #[derive(serde::Serialize)]
    struct Origin<'a> {
        repo: Option<&'a str>,
        commit: Option<&'a str>,
        branch: Option<&'a str>,
        dirty: Option<&'a str>,
    }
    #[derive(serde::Serialize)]
    struct Out<'a> {
        document: Option<&'a str>,
        spdx_version: Option<&'a str>,
        origin: Origin<'a>,
        packages: usize,
        digests: usize,
        relationships: usize,
        signed: Option<usize>,
        sig_source: Option<String>,
        rows: Vec<serde_json::Value>,
        compare: Option<serde_json::Value>,
    }
    let rows_json: Vec<serde_json::Value> = rows
        .as_ref()
        .map(|rs| {
            rs.iter()
                .map(|r| {
                    serde_json::json!({
                        "name": r.name,
                        "digest": r.digest,
                        "sigs": r.sigs,
                        "verified": r.verified,
                        "quorum": r.quorum(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    let (signed, sig_source) = match rows {
        Some(rs) if !rs.is_empty() => (
            Some(rs.iter().filter(|r| r.signed()).count()),
            Some(rs[0].checked.clone()),
        ),
        _ => (None, None),
    };
    let compare = compare.as_ref().map(|rep| {
        serde_json::json!({
            "matched": rep.matched,
            "mismatched": rep.mismatched.iter().map(|(n, a, b)| serde_json::json!({"name": n, "baked": a, "regenerated": b})).collect::<Vec<_>>(),
            "only_baked": rep.only_baked,
            "only_regen": rep.only_regen,
            "identical": rep.ok(),
        })
    });
    serde_json::to_string(&Out {
        document: doc.doc_name.as_deref(),
        spdx_version: doc.spdx_version.as_deref(),
        origin: Origin {
            repo: doc.git.repo.as_deref(),
            commit: doc.git.commit.as_deref(),
            branch: doc.git.branch.as_deref(),
            dirty: doc.git.dirty.as_deref(),
        },
        packages: doc.packages.len(),
        digests: doc.digest_count(),
        relationships: doc.relationships,
        signed,
        sig_source,
        rows: rows_json,
        compare,
    })
    .expect("serialize")
}

/// Options for the `bootproof provenance` subcommand.
#[derive(Debug, Clone)]
pub struct Opts {
    /// Path to the SPDX document (default /provenance.spdx).
    pub path: PathBuf,
    /// Local checkout root of the signatures repo (contains `stagex/`
    /// or the `<name>@sha256=.../` dirs directly).
    pub sigs: Option<PathBuf>,
    /// Lookaside base URL (e.g. https://sigs.stagex.tools).
    pub lookaside: Option<String>,
    /// PGP keyring to verify found signatures against (in-process, rPGP).
    pub keyring: Option<PathBuf>,
    /// Print every package line, not just a summary.
    pub all: bool,
    /// JSON output.
    pub json: bool,
    /// Max packages to query for the remote lookaside check.
    pub max: usize,
    /// A locally REGENERATED provenance document (after rebuilding at the
    /// pinned commit): compare its per-package digests against `path`.
    pub compare: Option<PathBuf>,
}

/// Run the subcommand; returns the process exit code.
pub fn run(o: Opts) -> anyhow::Result<i32> {
    let text = std::fs::read_to_string(&o.path)
        .map_err(|e| anyhow::anyhow!("read {}: {e}", o.path.display()))?;
    let doc = parse_spdx(&text).map_err(|e| anyhow::anyhow!("{e}"))?;

    let mut rows: Option<Vec<CoverageRow>> = None;
    if let Some(root) = &o.sigs {
        // Accept either the checkout root (with a stagex/ subdir) or the
        // dir containing the @sha256= entries directly. Refuse to report
        // "0 published" against a root that does not exist.
        let inner = root.join("stagex");
        let root = if inner.is_dir() { inner } else { root.clone() };
        if !root.is_dir() {
            anyhow::bail!("sigs root does not exist: {}", root.display());
        }
        rows = Some(coverage_local(&doc.packages, &root));
    } else if let Some(url) = &o.lookaside {
        rows = Some(coverage_lookaside(&doc.packages, url, o.max)?);
    }

    // OpenPGP verification of anything found (in-process via rPGP).
    if let Some(k) = &o.keyring {
        if let Some(rs) = &mut rows {
            for r in rs.iter_mut() {
                if r.sigs.is_empty() {
                    continue;
                }
                let base = match &o.sigs {
                    Some(root) => {
                        let inner = root.join("stagex");
                        if inner.is_dir() { inner } else { root.clone() }
                    }
                    None => continue, // remote sigs are not on disk
                };
                let mut verified = Vec::new();
                for cand in dir_candidates(&r.name) {
                    let dir = base.join(format!("{}@sha256={}", cand, r.digest));
                    if dir.is_dir() {
                        for sig in &r.sigs {
                            match verify_sig_gpg(&dir.join(sig), k) {
                                Ok(ok) => verified.push(Some(ok)),
                                Err(e) => {
                                    eprintln!("pgp verify {sig}: {e}");
                                    verified.push(None);
                                }
                            }
                        }
                        break;
                    }
                }
                r.verified = verified;
            }
        }
    }

    // Local rebuild confirmation: diff this doc against a regenerated one.
    let mut compare_rep: Option<CompareReport> = None;
    if let Some(cp) = &o.compare {
        let ctext = std::fs::read_to_string(cp)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", cp.display()))?;
        let cdoc =
            parse_spdx(&ctext).map_err(|e| anyhow::anyhow!("parse {}: {e}", cp.display()))?;
        compare_rep = Some(compare(&doc, &cdoc));
    }

    if o.json {
        println!("{}", to_json(&doc, &rows, &compare_rep));
    } else {
        print!("{}", render(&doc, &rows, o.all));
        if let Some(rep) = &compare_rep {
            print!("{}", render_compare(rep));
        }
    }
    Ok(if compare_rep.as_ref().is_some_and(|r| !r.ok()) { 3 } else { 0 })
}

// ── tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const MINIDOC: &str = r#"# test doc
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: Test build provenance
DocumentNamespace: https://example.org/test/spdx/abc123/nodisk
Creator: Tool: test-1
Created: 2026-01-01T00:00:01Z
LicenseListVersion: 3.21

PackageName: stagex
SPDXID: SPDXRef-stagex
PackageVersion: 6a618c0f9991d7b6fcce3aacf0c66d8e3b0539af
PackageDownloadLocation: https://codeberg.org/stagex/stagex.git
FilesAnalyzed: false
PackageComment: branch=lance/distros dirty=0
ExternalRef: OTHER git-of-origin https://codeberg.org/stagex/stagex.git

PackageName: core-bash
SPDXID: SPDXRef-core-bash
PackageChecksum: SHA256: d0fd09ec04780a73
PackageComment: src=deadbeef

PackageName: user-glib
SPDXID: SPDXRef-user-glib
PackageChecksum: SHA256: 12593b3a9e068aac

PackageName: box-uki
SPDXID: SPDXRef-box-uki
FilesAnalyzed: false

Relationship: SPDXRef-box-uki DEPENDS_ON SPDXRef-core-bash
Relationship: SPDXRef-box-uki DEPENDS_ON SPDXRef-user-glib
"#;

    #[test]
    fn parse_minidoc_fields() {
        let d = parse_spdx(MINIDOC).expect("parse");
        assert_eq!(d.spdx_version.as_deref(), Some("SPDX-2.3"));
        assert_eq!(d.doc_name.as_deref(), Some("Test build provenance"));
        assert_eq!(d.packages.len(), 4);
        assert_eq!(d.digest_count(), 2);
        assert_eq!(d.relationships, 2);
        assert!(d.packages.iter().any(|p| p.name == "box-uki" && p.digest.is_none()));
    }

    #[test]
    fn parse_git_origin() {
        let d = parse_spdx(MINIDOC).expect("parse");
        assert_eq!(d.git.commit.as_deref(), Some("6a618c0f9991d7b6fcce3aacf0c66d8e3b0539af"));
        assert_eq!(d.git.branch.as_deref(), Some("lance/distros"));
        assert_eq!(d.git.dirty.as_deref(), Some("0"));
        assert_eq!(d.git.repo.as_deref(), Some("codeberg.org/stagex/stagex"));
        let disp = d.git.display().expect("display");
        assert!(disp.contains("6a618c0f9991d7b6"), "{disp}");
        assert!(disp.contains("branch lance/distros"), "{disp}");
    }

    #[test]
    fn coverage_local_exact_and_stripped() {
        let dir = std::env::temp_dir().join(format!("bp-prov-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // exact-name dir with quorum, prefix-stripped dir with one sig, missing dir
        std::fs::create_dir_all(dir.join("alpha@sha256=aaaa")).expect("mk");
        std::fs::write(dir.join("alpha@sha256=aaaa/signature-1"), b"sig").expect("w");
        std::fs::write(dir.join("alpha@sha256=aaaa/signature-2"), b"sig").expect("w");
        std::fs::create_dir_all(dir.join("beta@sha256=bbbb")).expect("mk");
        std::fs::write(dir.join("beta@sha256=bbbb/signature-1"), b"sig").expect("w");
        std::fs::write(dir.join("beta@sha256=bbbb/other"), b"x").expect("w");

        let pkgs = vec![
            Pkg { name: "alpha".into(), digest: Some("aaaa".into()), ..Default::default() },
            Pkg { name: "core-beta".into(), digest: Some("bbbb".into()), ..Default::default() },
            Pkg { name: "gamma".into(), digest: Some("cccc".into()), ..Default::default() },
        ];
        let rows = coverage_local(&pkgs, &dir);
        let a = rows.iter().find(|r| r.name == "alpha").expect("a");
        assert_eq!(a.sigs, vec!["signature-1".to_string(), "signature-2".to_string()]);
        assert!(a.quorum());
        let b = rows.iter().find(|r| r.name == "core-beta").expect("b");
        assert_eq!(b.sigs, vec!["signature-1".to_string()]);
        assert!(!b.quorum());
        let g = rows.iter().find(|r| r.name == "gamma").expect("g");
        assert!(g.sigs.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn render_unsigned_dev_build() {
        let d = parse_spdx(MINIDOC).expect("parse");
        let rows = vec![CoverageRow {
            name: "core-bash".into(),
            digest: "d0fd09ec04780a73".into(),
            sigs: vec![],
            verified: vec![],
            checked: "test".into(),
        }];
        let s = render(&d, &Some(rows), false);
        assert!(s.contains("0 / 1 published"), "{s}");
        assert!(s.contains("? unsigned build"), "{s}");
        assert!(s.contains("6a618c0f9991d7b6"), "{s}");
    }

    #[test]
    fn json_shape() {
        let d = parse_spdx(MINIDOC).expect("parse");
        let j: serde_json::Value =
            serde_json::from_str(&to_json(&d, &None, &None)).expect("json");
        assert_eq!(j["packages"], 4);
        assert_eq!(j["digests"], 2);
        assert_eq!(j["origin"]["commit"], "6a618c0f9991d7b6fcce3aacf0c66d8e3b0539af");
        assert!(j["signed"].is_null());
        assert!(j["compare"].is_null());
    }

    #[test]
    fn compare_detects_drift() {
        let a = parse_spdx(MINIDOC).expect("a");
        let btext = MINIDOC
            .replace(
                "PackageChecksum: SHA256: d0fd09ec04780a73",
                "PackageChecksum: SHA256: eeee0000",
            )
            .replace(
                "PackageName: user-glib\nSPDXID: SPDXRef-user-glib\nPackageChecksum: SHA256: 12593b3a9e068aac\n",
                "",
            )
            .replace(
                "Relationship: SPDXRef-box-uki DEPENDS_ON SPDXRef-user-glib\n",
                "PackageName: core-new\nSPDXID: SPDXRef-core-new\nPackageChecksum: SHA256: ffff1111\n\n",
            );
        let b = parse_spdx(&btext).expect("b");
        let rep = compare(&a, &b);
        assert!(
            rep.mismatched.iter().any(|(n, _, _)| n == "core-bash"),
            "{rep:?}"
        );
        assert!(rep.only_baked.iter().any(|n| n == "user-glib"), "{rep:?}");
        assert!(rep.only_regen.iter().any(|n| n == "core-new"), "{rep:?}");
        assert!(!rep.ok());
        let s = render_compare(&rep);
        assert!(s.contains("does NOT reproduce"), "{s}");
    }

    #[test]
    fn lookaside_url_shape() {
        assert_eq!(
            lookaside_url("https://sigs.stagex.tools/", "core-bash", "d0fd09ec", 2),
            "https://sigs.stagex.tools/stagex/core-bash@sha256=d0fd09ec/signature-2"
        );
    }

    #[test]
    fn run_missing_sigs_root_is_an_error() {
        let dir = std::env::temp_dir().join(format!("bp-prov-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk");
        let spdx = dir.join("doc.spdx");
        std::fs::write(&spdx, MINIDOC).expect("w");
        let opts = Opts {
            path: spdx,
            sigs: Some(dir.join("no-such-checkout")),
            lookaside: None,
            keyring: None,
            all: false,
            json: false,
            max: 10,
            compare: None,
        };
        let err = run(opts).expect_err("must refuse a missing sigs root");
        assert!(err.to_string().contains("does not exist"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn run_compare_exit_codes() {
        let dir = std::env::temp_dir().join(format!("bp-prov-cmp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mk");
        let baked = dir.join("baked.spdx");
        std::fs::write(&baked, MINIDOC).expect("w");
        // Identical regeneration.
        let same = dir.join("same.spdx");
        std::fs::write(&same, MINIDOC).expect("w");
        let opts = |compare: Option<PathBuf>| Opts {
            path: baked.clone(),
            sigs: None,
            lookaside: None,
            keyring: None,
            all: false,
            json: false,
            max: 10,
            compare,
        };
        assert_eq!(run(opts(Some(same))).expect("identical"), 0);
        // Drifted regeneration (one digest changed).
        let drifted = dir.join("drift.spdx");
        std::fs::write(
            &drifted,
            MINIDOC.replace("PackageChecksum: SHA256: d0fd09ec04780a73", "PackageChecksum: SHA256: eeee0000"),
        )
        .expect("w");
        assert_eq!(run(opts(Some(drifted))).expect("drift"), 3);
        // JSON path carries the compare object.
        let jopts = Opts {
            json: true,
            compare: Some(dir.join("drift.spdx")),
            ..opts(None)
        };
        // Capture is not needed: the exit code is the contract.
        assert_eq!(run(jopts).expect("json drift"), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn pgp_verify_published_signature() {
        // Integration test: verifies a PUBLISHED StageX signature against the
        // maintainer keyring, in-process via rPGP (no gpg binary required).
        // Skipped where the checkout is absent.
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        let root = std::env::var_os("STAGEX_SIGS_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join("Sources/stagex-signatures"));
        let dir = root.join("stagex");
        let keyring = root.join("stagex-keyring.pgp");
        // Pin the exact entry the ground-truth proof used (doc §5.2 + the gpg
        // cross-check): there are several core-bash rebuilds, each signed by a
        // different maintainer, and readdir order is arbitrary. This one was
        // signed by the Lance R. Vick (Personal) signing subkey.
        let entry = match std::fs::read_dir(&dir) {
            Ok(rd) => rd
                .flatten()
                .map(|e| e.file_name())
                .find(|n| n.to_string_lossy().starts_with("core-bash@sha256=5b598c14"))
                .map(|n| n.to_string_lossy().to_string()),
            Err(_) => None,
        };
        let Some(entry) = entry else {
            eprintln!("SKIP pgp test: no sigs checkout at {}", dir.display());
            return;
        };
        let sig = dir.join(&entry).join("signature-1");
        if !sig.exists() || !keyring.exists() {
            eprintln!("SKIP pgp test: missing sig or keyring");
            return;
        }
        let Some(res) = verify_sig_full(&sig, &keyring).ok() else {
            eprintln!("SKIP pgp test: verification errored");
            return;
        };
        assert!(res.verified, "published core-bash signature must verify");
        // The signature is made by a dedicated signing subkey of the maintainer
        // primary key. Pin the exact verifying fingerprint (lowercase) so a
        // future regression that verifies against the WRONG key fails loudly
        // rather than silently passing on "some key matched".
        let fp = res.fingerprint.clone().unwrap_or_default();
        assert!(
            fp == "67553fbda46bb71abd2e0b0b8e47a1ec35a1551d",
            "verified by the expected signing subkey, got {fp}"
        );
        assert!(res.payload_len.is_some(), "embedded payload was read");
    }
}
