#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/build/ptracer"
SRC="$ROOT/cmd/agentsh-unixwrap/ptracer"

build_one() {
  arch="$1"
  cc="$2"
  target_dir="$OUT/linux_${arch}"
  mkdir -p "$target_dir"
  echo "[ptracer] building for linux/${arch} with CC=${cc}" >&2
  if ! command -v "$cc" >/dev/null 2>&1; then
    echo "[ptracer] skipping linux/${arch}: compiler $cc not found" >&2
    # Create stub for packaging so archives always include the expected file.
    # At runtime findPtracerLib() finds this but dlopen will fail harmlessly;
    # the log message from setupPtracerPreload already warns about missing lib.
    echo '#!/bin/sh' > "$target_dir/libagentsh-ptracer.so"
    echo 'echo "ptracer: stub library - rebuild with $cc for full functionality" >&2' >> "$target_dir/libagentsh-ptracer.so"
    chmod 644 "$target_dir/libagentsh-ptracer.so"
    return 0
  fi
  make -C "$SRC" clean >/dev/null 2>&1 || true
  CC="$cc" TARGET="$target_dir/libagentsh-ptracer.so" make -C "$SRC" all
}

rm -rf "$OUT"
mkdir -p "$OUT"

# amd64 using native gcc
build_one amd64 gcc || true

# arm64 using cross-compiler if available
build_one arm64 aarch64-linux-gnu-gcc || true
