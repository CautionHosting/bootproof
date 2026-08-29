# Build the `bootproof` binary using the StageX Rust pallet so the result is
# a StageX-compatible (musl, static) binary that runs on StageX guests.
#
# The pallet's default/host target is x86_64-unknown-linux-musl, so a plain
# `cargo build --release` produces the right artifact.

FROM stagex/pallet-rust AS build
ADD . /src
WORKDIR /src
RUN cargo rustc --locked --release --bin bootproof -- -C target-feature=+crt-static

# TPM client: bootproof-tpm with the `esys` feature against the StageX
# tss2 stack (the platform's TPM dialect). The final link uses the
# `crt-static` target feature so the result is fully static (static-pie,
# no DT_NEEDED) and runs unmodified on StageX guests and dev hosts.
FROM stagex/pallet-rust AS tpm
COPY --from=stagex/tpm2-tss:sx2024.08.1@sha256:5e362f43a5e0c49f774605a0e3e1b7523dc6bc775f537c206a3aaa8b8b733c93 . /
ADD . /src
WORKDIR /src
# The `esys` build script emits the tss2 static archives as link-args
# (dependents before dependencies, libc last). The tss2 .pc files' Libs
# lines are emptied so the pkg-config probes (done by tss2-esapi-sys and
# our build script) emit no link flags of their own; only our build script
# controls the link line.
RUN for f in esys sys mu rc tcti-device tctildr; do \
        sed -i 's|^Libs:.*|Libs: |' /usr/lib/pkgconfig/tss2-$f.pc; \
    done && \
    cargo rustc --locked --release -p bootproof-tpm --example keytest --features esys -- \
        -C target-feature=+crt-static

# Dev shell: the Rust toolchain plus the TPM tooling (swtpm + tpm2-tools) used
# for local, software-TPM testing.
FROM stagex/pallet-rust AS dev
COPY --from=stagex/tpm2-tools:sx2024.08.1@sha256:1693d4ef7e0b7df3e9bd60088588d94b7f5bf755fde0c1be695f3c2f00ec2897 . /
COPY --from=stagex/tpm2-tss:sx2024.08.1@sha256:5e362f43a5e0c49f774605a0e3e1b7523dc6bc775f537c206a3aaa8b8b733c93 . /
COPY --from=stagex/swtpm . /
COPY --from=stagex/libtpms . /
COPY --from=stagex/libseccomp . /
# swtpm's dynamic dependencies: glib, plus OpenSSL 3 in a side directory.
# The pallet toolchain ships its own /usr/lib/libcrypto.so.3 (cargo is
# linked against it) and must not be clobbered.
COPY --from=stagex/glib . /
COPY --from=stagex/openssl /usr/lib/libcrypto.so.3 /usr/lib/libssl.so.3 /opt/swtpm-libs/

FROM scratch AS package
COPY --from=build /src/target/release/bootproof /bootproof
