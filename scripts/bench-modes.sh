#!/usr/bin/env bash
# Build and run the agentsh performance benchmark.
# Compares baseline vs full mode (seccomp+FUSE) vs seccomp-notify vs ptrace.
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "bench: building image..."
docker build -f Dockerfile.bench -t agentsh-bench:latest .

echo "bench: running benchmark..."
docker run --rm \
  --cap-add SYS_ADMIN --cap-add SYS_PTRACE \
  --device /dev/fuse \
  --security-opt seccomp=unconfined \
  agentsh-bench:latest
