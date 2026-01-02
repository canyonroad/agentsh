# agentsh Cross-Platform Notes

**Last updated:** January 2026

agentsh supports **Linux** and **macOS** natively. Linux provides the most complete feature set. macOS supports two enforcement tiers: **ESF+NE** (90% security score, requires Apple entitlements) and **FUSE-T** (70% score, easy setup).

If you're on Windows, the recommended approach is to run agentsh inside WSL2 or a Linux container. Unix socket monitoring (seccomp user-notify) is Linux-only and currently audit-only.

## What works today

- **Linux (native):** primary supported platform with full feature set.
- **macOS ESF+NE (enterprise):** Endpoint Security Framework + Network Extension for near-Linux enforcement (requires Apple entitlements).
- **macOS FUSE-T (standard):** FUSE-T support for file policy enforcement (requires `brew install fuse-t` and CGO).
- **Windows:** run in **WSL2** (recommended) or a Linux container.
- **gRPC (optional):** if enabled, clients connect to `server.grpc.addr` (default `127.0.0.1:9090`). The CLI can prefer gRPC via `AGENTSH_TRANSPORT=grpc`.

## Feature availability (current implementation)

- **FUSE workspace view:** Linux (FUSE3) and macOS (FUSE-T). In containers requires `/dev/fuse` + `SYS_ADMIN`.
- **Network visibility + policy enforcement:** works via the per-session proxy (DNS/connect/HTTP events).
- **Transparent netns interception:** optional, Linux/root-only (requires privileges; proxy mode works without it).
- **cgroups v2 limits:** optional, Linux-only; disabled by default (requires a writable cgroup base path).
- **seccomp / full namespace isolation / eBPF:** planned/future work (not implemented).

## Quick start

### Linux

```bash
agentsh server
```

### macOS (FUSE-T - Standard)

```bash
# Install FUSE-T (required for file policy enforcement)
brew install fuse-t

# Build with CGO enabled (default on macOS)
CGO_ENABLED=1 go build -o agentsh ./cmd/agentsh

# Run the server
agentsh server
```

**Note:** Without FUSE-T or CGO, agentsh falls back to observation-only mode using FSEvents.

### macOS (ESF+NE - Enterprise)

For enterprise deployments with Apple entitlements:

```bash
# Build the enterprise bundle (requires Xcode 15+)
make build-macos-enterprise

# Sign the bundle (requires code signing identity)
SIGNING_IDENTITY="Developer ID Application" make sign-bundle

# The app bundle includes System Extension + XPC Service
# User must approve System Extension in System Settings
```

**Requirements:**
- Apple Developer Program membership
- ESF + Network Extension entitlements from Apple
- Xcode 15+ and Swift 5.9+
- Code signing identity

**Note:** ESF+NE mode automatically falls back to FUSE-T if entitlements are unavailable. See [macOS Build Guide](macos-build.md) for detailed instructions.

### Windows (Native - Mini Filter Driver)

For native Windows support with kernel-level enforcement:

```bash
# Install the driver (requires Administrator)
# Driver must be test-signed for development or production-signed for release
sc create agentsh type=filesys binPath="C:\path\to\agentsh.sys"
sc start agentsh

# Run the agentsh server
agentsh server
```

**Requirements:**
- Windows 10/11 (64-bit)
- Administrator privileges for driver installation
- Test signing enabled for development, or EV-signed driver for production

**Network Interception:**
- WinDivert for transparent TCP/DNS proxy (requires Administrator)
- Falls back to WFP for block-only mode if WinDivert unavailable

**Current Implementation Status (All 5 Phases Complete):**
- ✅ Driver skeleton and filter port communication
- ✅ Process tracking (session processes and child inheritance)
- ✅ Filesystem interception (create, write, delete, rename)
- ✅ Registry interception (create/set/delete keys, high-risk path detection)
- ✅ Network interception (WinDivert TCP/DNS proxy with WFP fallback)
- ✅ Production readiness (configurable fail modes, metrics, caching)

See [Windows Driver Deployment Guide](windows-driver-deployment.md) for installation and configuration.

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

- **FUSE mount fails (Linux):** ensure FUSE3 is installed (host/VM) and, in Docker, `/dev/fuse` is present and `SYS_ADMIN` is allowed.
- **FUSE-T mount fails (macOS):** ensure FUSE-T is installed (`brew install fuse-t`) and the binary was built with CGO enabled.
- **System Extension not loading (macOS ESF+NE):** check System Settings > General > Login Items & Extensions. User must approve the System Extension.
- **XPC connection fails (macOS ESF+NE):** verify the System Extension is approved and running. Check Console.app for XPC errors.
- **ESF client initialization fails:** ensure the app is signed with valid ESF entitlements from Apple.
- **Transparent network mode fails:** run as root / with NET_ADMIN capabilities; otherwise rely on proxy mode.
- **cgroups errors:** keep `sandbox.cgroups.enabled: false` unless you have a writable cgroup v2 base path configured.
- **gRPC connection fails:** confirm `server.grpc.enabled: true`, the address/port are reachable, and (if auth is enabled) send the API key via gRPC metadata `x-api-key`.
