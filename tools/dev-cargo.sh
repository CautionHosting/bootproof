#!/bin/sh
# Run a cargo command inside the bootproof dev container (pallet-rust + tss2 + clang).
# Usage: ./tools/dev-cargo.sh build / test / clippy ...
set -e
IMG=f933e86b5de7
DIR="$(cd "$(dirname "$0")/.." && pwd)"
docker run --rm --entrypoint sh -v "$DIR":/src -w /src "$IMG" -c "cargo $*"
