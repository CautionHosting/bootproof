// Final-link tss2 wiring for the `bootproof` binary.
//
// Cargo applies a build script's `cargo:rustc-link-arg` only to the units the
// package that emitted them actually builds; the flags do NOT propagate to a
// downstream consumer's final binary link. bootproof-tpm's build script owns
// the tss2 link line for the crates/bootproof-tpm targets (e.g. the `keytest`
// example, which lives inside that package and therefore links against its
// own build script's args). But the production `bootproof` bin is a SEPARATE
// package that merely depends on bootproof-tpm, so once dmext pulls in an
// EsysTpm (and with it the whole tss2 C stack + the trampoline shim), that
// bin's final link is missing every tss2 archive and the trampoline.o and
// fails with undefined Tss2_MU_*/Esys_*/bp_* references.
//
// The fix is to re-emit the identical, ordered link-args from THIS package's
// build script, because `rustc-link-arg` emitted by the top-level crate being
// linked DOES reach the final link. This mirrors crates/bootproof-tpm/build.rs
// exactly (same exact-archive order, dependents before dependencies, libc
// last) plus a fresh compile of the shared trampoline.c.
//
// The tss2 archives come from the StageX tss2 image (COPY'd into / in the
// Containerfile `build` target, so they land at /usr/lib/libtss2-*.a); libc.a
// and libcrypto.a come from the pallet-rust base (/lib). clang is on PATH in
// the same base.
fn main() {
    use std::path::Path;
    use std::process::Command;

    // Presence gate: fail loudly with a clear message if the build environment
    // is missing the tss2 C stack (the primary archive; it pulls the rest in
    // the link line below).
    let esys = Path::new("/usr/lib/libtss2-esys.a");
    if !esys.is_file() {
        panic!(
            "tss2 C stack not found at /usr/lib/libtss2-esys.a; build the \
             bootproof binary through the Containerfile `build` target, which \
             COPYs the StageX tss2 image (the `esys` link line depends on it)"
        );
    }

    // Command-logging / dialect trampoline (TCTI transmit hook). The source is
    // shared with bootproof-tpm; each crate compiles its own copy into its own
    // OUT_DIR. Only THIS package's copy reaches the final bin link (the
    // bootproof-tpm copy's link-arg does not propagate here), so there is
    // exactly one trampoline.o on the link line -- no duplicate symbols.
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let obj = format!("{out_dir}/trampoline.o");
    let src = "../bootproof-tpm/trampoline.c";
    let status = Command::new("clang")
        .args(["-O2", "-fPIC", "-c"])
        .arg(src)
        .arg("-o")
        .arg(&obj)
        .status()
        .expect("failed to run clang for trampoline.c");
    assert!(status.success(), "clang failed on {src}");
    println!("cargo:rerun-if-changed={src}");

    println!("cargo:rustc-link-arg={obj}");
    println!("cargo:rustc-link-arg=-L/usr/lib");
    println!("cargo:rustc-link-arg=-L/lib");
    // Exact-archive (-l:libX.a) flags: dependents before dependencies.
    // OpenSSL (musl static from the pallet's /lib) follows libtss2-esys, which
    // calls into it for session encryption.
    println!("cargo:rustc-link-arg=-l:libtss2-esys.a");
    println!("cargo:rustc-link-arg=-l:libcrypto.a");
    println!("cargo:rustc-link-arg=-l:libtss2-rc.a");
    println!("cargo:rustc-link-arg=-l:libtss2-sys.a");
    // Device TCTI linked directly so no dlopen is needed at runtime.
    println!("cargo:rustc-link-arg=-l:libtss2-tcti-device.a");
    println!("cargo:rustc-link-arg=-l:libtss2-tctildr.a");
    // tss2-mu is referenced by most of the above, so it goes last.
    println!("cargo:rustc-link-arg=-l:libtss2-mu.a");
    // Static single-pass linking: libc (rand, dlopen stubs, unwinder) must come
    // after every archive that references it. Exact archive: /lib/libc.so is
    // the dynamic loader on musl systems.
    println!("cargo:rustc-link-arg=-l:libc.a");

    println!("cargo:rerun-if-changed=build.rs");
}
