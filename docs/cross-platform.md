# agentsh Cross-Platform Notes

**Last updated:** December 2025

agentsh is **Linux-first**. The current implementation relies on Linux features (notably FUSE) for full workspace visibility.

If you’re on Windows or macOS, the recommended approach is to run agentsh inside a Linux environment and connect to it over HTTP or the unix socket exposed inside that environment.

## What works today

- **Linux (native):** primary supported platform.
- **Windows:** run in **WSL2** (recommended) or a Linux container.
- **macOS:** run in a Linux VM/container (e.g. Docker Desktop’s Linux VM, Lima, etc.).

## Feature availability (current implementation)

- **FUSE workspace view:** Linux-only (requires FUSE3; in containers requires `/dev/fuse` + `SYS_ADMIN`).
- **Network visibility + policy enforcement:** works via the per-session proxy (DNS/connect/HTTP events).
- **Transparent netns interception:** optional, Linux/root-only (requires privileges; proxy mode works without it).
- **cgroups v2 limits:** optional, Linux-only; disabled by default (requires a writable cgroup base path).
- **seccomp / full namespace isolation / eBPF:** planned/future work (not implemented).

## Quick start

### Linux

```bash
agentsh server
```

### Windows (WSL2)

- Install WSL2 + a distro (e.g. Ubuntu).
- Inside WSL, install `fuse3` and run `agentsh server`.
- Keep workspaces on the Linux filesystem (e.g. `/home/...`), not `/mnt/c/...`, for performance.

### Docker (any host)

FUSE requires extra privileges inside containers:

```bash
docker run --rm -it \
  --cap-add SYS_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  -p 8080:8080 \
  -v "$(pwd)":/workspace \
  ghcr.io/agentsh/agentsh:latest
```

## Troubleshooting

- **FUSE mount fails:** ensure FUSE3 is installed (host/VM) and, in Docker, `/dev/fuse` is present and `SYS_ADMIN` is allowed.
- **Transparent network mode fails:** run as root / with NET_ADMIN capabilities; otherwise rely on proxy mode.
- **cgroups errors:** keep `sandbox.cgroups.enabled: false` unless you have a writable cgroup v2 base path configured.
