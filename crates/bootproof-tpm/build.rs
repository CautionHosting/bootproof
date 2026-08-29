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
        // Exact-archive (-l:libX.a) flags: dependents before dependencies.
        // OpenSSL (musl static from the Rust pallet's /lib) follows
        // libtss2-esys, which calls into it for session encryption.
        println!("cargo:rustc-link-arg=-l:libtss2-esys.a");
        println!("cargo:rustc-link-arg=-l:libcrypto.a");
        println!("cargo:rustc-link-arg=-l:libtss2-rc.a");
        println!("cargo:rustc-link-arg=-l:libtss2-sys.a");
        // Device TCTI linked directly so no dlopen is needed at runtime.
        println!("cargo:rustc-link-arg=-l:libtss2-tcti-device.a");
        println!("cargo:rustc-link-arg=-l:libtss2-tctildr.a");
        // tss2-mu is referenced by most of the above, so it goes last.
        println!("cargo:rustc-link-arg=-l:libtss2-mu.a");
        // Static single-pass linking: libc (rand, dlopen stubs, unwinder)
        // must come after every archive that references it. Exact archive:
        // /lib/libc.so is the dynamic loader on musl systems.
        println!("cargo:rustc-link-arg=-l:libc.a");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
