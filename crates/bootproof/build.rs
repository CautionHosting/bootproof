// Final-link wiring for the `bootproof` binary: tss2 C stack + libdevmapper,
// linked DYNAMICALLY against the guest rootfs's shared objects.
//
// Cargo applies a build script's `cargo:rustc-link-arg` only to the units the
// package that emitted them actually builds; the flags do NOT propagate to a
// downstream consumer's final binary link. bootproof-tpm's build script owns
// the tss2 link line for the crates/bootproof-tpm targets (e.g. the `keytest`
// example, which lives inside that package and therefore links against its
// own build script's args). But the production `bootproof` bin is a SEPARATE
// package that merely depends on bootproof-tpm, so once dmext pulls in an
// EsysTpm (and with it the whole tss2 C stack + the trampoline shim), that
// bin's final link is missing every tss2 symbol and the trampoline.o and
// fails with undefined Tss2_MU_*/Esys_*/bp_* references.
//
// The fix is to re-emit the ordered link-args from THIS package's build
// script, because `rustc-link-arg` emitted by the top-level crate being linked
// DOES reach the final link, plus a fresh compile of the shared trampoline.c.
//
// Dynamic link (policy: C libs link dynamically so a shared-library update
// never forces a Rust rebuild). The Containerfile `build` target COPYs the
// StageX tss2 image (user-tpm2-tss) and lvm2 (user-lvm2) into /, so the shared
// objects land at /usr/lib/libtss2-*.so and /usr/lib/libdevmapper.so. libcrypto
// comes from the pallet-rust base (/lib). Each tss2 .so records its own
// DT_NEEDED by SONAME, so the runtime loader resolves the rest; the flags here
// only tell the linker which NEEDED entries to record. clang is on PATH in the
// same base.
fn main() {
    use std::path::Path;
    use std::process::Command;

    // Presence gate: fail loudly with a clear message if the build environment
    // is missing the tss2 C stack (the primary shared object) or libdevmapper.
    let esys = Path::new("/usr/lib/libtss2-esys.so");
    if !esys.is_file() {
        panic!(
            "tss2 C stack not found at /usr/lib/libtss2-esys.so; build the \
             bootproof binary through the Containerfile `build` target, which \
             COPYs the StageX tss2 + lvm2 images (the dynamic link line depends on them)"
        );
    }
    let devmapper = Path::new("/usr/lib/pkgconfig/devmapper.pc");
    if !devmapper.is_file() {
        panic!(
            "devmapper.pc not found at /usr/lib/pkgconfig/devmapper.pc; the \
             Containerfile `build` target must COPY the StageX lvm2 image \
             (user-lvm2) into / so devicemapper-sys can bindgen the dm_ioctl \
             structs from libdevmapper.h at BUILD time (the crate itself does raw \
             DM ioctls and links no libdevmapper)"
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
    // Dynamic link (per the "link C libs dynamically so they can be updated
    // without rebuilding the Rust binaries" policy): the guest rootfs ships
    // the tss2 shared objects (user-tpm2-tss) and libcrypto (core-openssl).
    // A shared-library update never forces a Rust rebuild. Each tss2 .so
    // records its own DT_NEEDED by SONAME, so the runtime loader resolves the
    // rest; the flags here just tell the LINKER which NEEDED entries to record
    // on the binary. Plain `-l` (not `-l:libX.a`): resolves to the .so at
    // /usr/lib. No `libc.a`: dynamic musl pulls libc through the loader.
    //
    // NOTE: libdevmapper is NOT linked here. The stratis `devicemapper` crate
    // talks to the kernel via raw DM ioctls (do_ioctl -> ioctl(DM_*)), not the
    // libdevmapper C API, so the final binary has no libdevmapper DT_NEEDED and
    // no undefined dm_ symbols. user-lvm2 is still COPY'd into the build image
    // for its headers + devmapper.pc: devicemapper-sys bindgens the dm_ioctl
    // struct + DM_* constants from them at BUILD time. (Proven: removing the
    // -ldevmapper flag still links with zero undefined references.)
    // Dependents before dependencies.
    println!("cargo:rustc-link-arg=-ltss2-esys");
    println!("cargo:rustc-link-arg=-lcrypto");
    println!("cargo:rustc-link-arg=-ltss2-rc");
    println!("cargo:rustc-link-arg=-ltss2-sys");
    // Device TCTI linked directly so no dlopen is needed at runtime.
    println!("cargo:rustc-link-arg=-ltss2-tcti-device");
    println!("cargo:rustc-link-arg=-ltss2-tctildr");
    // tss2-mu is referenced by most of the above, so it goes last.
    println!("cargo:rustc-link-arg=-ltss2-mu");

    println!("cargo:rerun-if-changed=build.rs");
}
