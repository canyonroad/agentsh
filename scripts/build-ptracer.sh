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
    # No stub: LD_PRELOAD requires a valid ELF shared object; a non-ELF stub
    # would cause dynamic linker errors on every exec. findPtracerLib() handles
    # the missing file gracefully with a log warning.
    return 1
  fi
  make -C "$SRC" clean >/dev/null 2>&1 || true
  CC="$cc" TARGET="$target_dir/libagentsh-ptracer.so" make -C "$SRC" all
}

rm -rf "$OUT"
mkdir -p "$OUT"

# amd64 using native gcc (mandatory — primary Linux target)
build_one amd64 gcc

# arm64 using cross-compiler if available (optional — graceful degradation)
build_one arm64 aarch64-linux-gnu-gcc || true
