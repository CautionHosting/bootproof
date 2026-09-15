fn main() {
    #[cfg(feature = "esys")]
    {
        use std::process::Command;
        // Presence check only: tss-esapi-sys's build script probes the rest
        // (tss2-sys/esys/tctildr/mu). The tss2 .pc files' Libs lines are
        // emptied in the Containerfile, so no pkg-config probe emits link
        // flags; this build script owns the whole link line.
        pkg_config::Config::new()
            .probe("tss2-tcti-device")
            .expect("tss2-tcti-device not found via pkg-config");

        // Command-logging trampoline (TCTI transmit hook); enabled at
        // runtime via BP_LOG_TCTI=1.
        let out_dir = std::env::var("OUT_DIR").unwrap();
        let obj = format!("{out_dir}/trampoline.o");
        let status = Command::new("clang")
            .args(["-O2", "-fPIC", "-c"])
            .arg("trampoline.c")
            .arg("-o")
            .arg(&obj)
            .status()
            .expect("failed to run clang for trampoline.c");
        assert!(status.success(), "clang failed on trampoline.c");
        println!("cargo:rerun-if-changed=trampoline.c");
        println!("cargo:rustc-link-arg={obj}");

        println!("cargo:rustc-link-arg=-L/usr/lib");
        println!("cargo:rustc-link-arg=-L/lib");
        // Dynamic link (policy: C libs link dynamically so a shared-library
        // update never forces a Rust rebuild). The tss2 .so + libcrypto come
        // from the rootfs (user-tpm2-tss, core-openssl); each tss2 .so records
        // its own DT_NEEDED by SONAME, so the flags below only tell the linker
        // which NEEDED entries to record. Plain `-l` (not `-l:libX.a`), and no
        // `libc.a` (dynamic musl pulls libc through the loader). Dependents
        // before dependencies.
        println!("cargo:rustc-link-arg=-ltss2-esys");
        println!("cargo:rustc-link-arg=-lcrypto");
        println!("cargo:rustc-link-arg=-ltss2-rc");
        println!("cargo:rustc-link-arg=-ltss2-sys");
        // Device TCTI linked directly so no dlopen is needed at runtime.
        println!("cargo:rustc-link-arg=-ltss2-tcti-device");
        println!("cargo:rustc-link-arg=-ltss2-tctildr");
        // tss2-mu is referenced by most of the above, so it goes last.
        println!("cargo:rustc-link-arg=-ltss2-mu");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
