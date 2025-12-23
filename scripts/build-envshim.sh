#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/envshim"
SRC="$ROOT/internal/policy/envshim"

build_one() {
  arch="$1"
  cc="$2"
  target_dir="$OUT/linux_${arch}"
  mkdir -p "$target_dir"
  echo "[envshim] building for linux/${arch} with CC=${cc}" >&2
  if ! command -v "$cc" >/dev/null 2>&1; then
    echo "[envshim] skipping linux/${arch}: compiler $cc not found" >&2
    return 1
  fi
  make -C "$SRC" clean >/dev/null 2>&1 || true
  CC="$cc" TARGET="$target_dir/libenvshim.so" make -C "$SRC" all
}

rm -rf "$OUT"
mkdir -p "$OUT"

# amd64 using native gcc
build_one amd64 gcc || true

# arm64 using cross-compiler if available
build_one arm64 aarch64-linux-gnu-gcc || true
