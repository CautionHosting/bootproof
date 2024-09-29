FROM stagex/busybox:sx2024.08.1@sha256:8cb9360041cd17e8df33c5cbc6c223875045c0c249254367ed7e0eb445720757 AS busybox
FROM stagex/musl:sx2024.08.1@sha256:f888fcf45fabaaae3d0268bcec902ceb94edba7bf8d09ef6966ebb20e00b7127 AS musl
FROM stagex/zlib:sx2024.08.1@sha256:d0d6eef463a410191e086448c710441109ae72693cb074fe2b795ee033aa6c9d AS zlib
FROM stagex/tpm2-tools:sx2024.08.1@sha256:1693d4ef7e0b7df3e9bd60088588d94b7f5bf755fde0c1be695f3c2f00ec2897 AS tpm2-tools
FROM stagex/tpm2-tss:sx2024.08.1@sha256:5e362f43a5e0c49f774605a0e3e1b7523dc6bc775f537c206a3aaa8b8b733c93 AS tpm2-tss
FROM stagex/openssl:sx2024.08.1@sha256:9bd55ed05263a538e6a23c0262edc356c998a24674f3b8ad008a4b117a4cdf3b AS openssl
FROM stagex/libseccomp AS libseccomp
FROM stagex/glib AS glib
FROM stagex/libtpms AS libtpms
FROM stagex/swtpm AS swtpm
FROM stagex/curl AS curl
FROM stagex/rust AS rust
FROM stagex/gcc AS gcc
FROM stagex/binutils AS binutils
FROM stagex/llvm AS llvm
FROM stagex/libunwind AS libunwind
FROM stagex/ca-certificates AS ca-certificates
FROM stagex/git AS git

FROM scratch AS base
COPY --from=stagex/busybox . /
COPY --from=stagex/rust . /
COPY --from=stagex/musl . /
COPY --from=stagex/gcc . /
COPY --from=stagex/binutils . /
COPY --from=stagex/llvm . /
COPY --from=stagex/libunwind . /
COPY --from=stagex/openssl . /
COPY --from=stagex/zlib . /
COPY --from=stagex/ca-certificates . /
COPY --from=stagex/git . /

FROM base AS dev
COPY --from=glib . /
COPY --from=libseccomp . /
COPY --from=curl . /
COPY --from=swtpm . /
COPY --from=libtpms . /
COPY --from=tpm2-tss . /
COPY --from=tpm2-tools . /

FROM base AS build
ADD . /src
WORKDIR /src
ENV RUST_BACKTRACE=1
ENV RUSTFLAGS='-C codegen-units=1 -C target-feature=+crt-static'
RUN --network=none \
    cargo build \
        --frozen \
        --release \
        --target x86_64-unknown-linux-musl \
        --bin bootproof

FROM scratch AS package
COPY --from=build /src/target/x86_64-unknown-linux-musl/release/bootproof .
