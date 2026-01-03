# agentsh Cross-Platform Notes

**Last updated:** January 2026

agentsh supports **Linux** and **macOS** natively. Linux provides the most complete feature set. macOS supports two enforcement tiers: **ESF+NE** (90% security score) and **FUSE-T** (70% score, easy setup).

**Entitlement requirements for macOS ESF+NE:**
- **ESF (Endpoint Security):** Requires Apple approval - submit business justification
- **Network Extension:** Standard capability since November 2016 - enable in Xcode, no approval needed

If you're on Windows, the recommended approach is to run agentsh inside WSL2 or a Linux container. Unix socket monitoring (seccomp user-notify) is Linux-only and currently audit-only.

## What works today

- **Linux (native):** primary supported platform with full feature set.
- **macOS ESF+NE (enterprise):** Endpoint Security Framework + Network Extension for near-Linux enforcement (ESF needs Apple approval; NE is standard).
- **macOS FUSE-T (standard):** FUSE-T support for file policy enforcement (requires `brew install fuse-t` and CGO).
- **Windows:** run in **WSL2** (recommended) or a Linux container.
- **gRPC (optional):** if enabled, clients connect to `server.grpc.addr` (default `127.0.0.1:9090`). The CLI can prefer gRPC via `AGENTSH_TRANSPORT=grpc`.

## Feature availability (current implementation)

- **FUSE workspace view:** Linux (FUSE3), macOS (FUSE-T), and Windows (WinFsp). In containers requires `/dev/fuse` + `SYS_ADMIN`.
- **FUSE event emission:** File operation events (open, read, write, create, delete, rename) are emitted to the configured EventChannel for audit logging and monitoring.
- **Network visibility + policy enforcement:** works via the per-session proxy (DNS/connect/HTTP events).
- **Transparent netns interception:** optional, Linux/root-only (requires privileges; proxy mode works without it).
- **cgroups v2 limits:** optional, Linux-only; disabled by default (requires a writable cgroup base path).
- **macOS resource monitoring:** native Mach API monitoring for memory, CPU, and thread count (monitoring only, no enforcement).
- **Windows resource monitoring:** Job Objects for memory, CPU, disk I/O, process count; Toolhelp32 for thread count (both monitoring and enforcement via Job Objects).
- **Process execution stats:** CPU user/system time returned in exec results on all platforms. Peak memory available on Unix (Linux/macOS) but not Windows.
- **Registry monitoring + policy enforcement:** Windows-only, requires mini filter driver (see below).
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

For enterprise deployments:

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
- ESF entitlement from Apple (requires approval with business justification)
- Network Extension entitlement (standard capability - enable in Xcode)
- Xcode 15+ and Swift 5.9+
- Code signing identity

**Note:** ESF+NE mode automatically falls back to FUSE-T if ESF entitlement is unavailable. See [macOS Build Guide](macos-build.md) for detailed instructions.

### macOS (Lima VM - Full Isolation)

For full Linux isolation on macOS, agentsh supports Lima VM. When Lima is installed with a running VM, agentsh automatically detects and uses it:

```bash
# Install Lima
brew install lima

# Create and start a VM
limactl start default

# agentsh automatically detects Lima and uses it
agentsh server  # Will use darwin-lima mode
```

**Automatic Detection:** When `limactl` is installed and at least one VM is running, agentsh automatically uses Lima mode which provides:
- Full Linux namespace isolation (mount, network, PID, user)
- seccomp-bpf syscall filtering
- cgroups v2 resource limits
- FUSE3 filesystem interception
- iptables network interception

**Resource Limits (cgroups v2):** Lima uses cgroups v2 inside the VM for resource enforcement:
- Cgroup path: `/sys/fs/cgroup/agentsh/<session-name>`
- Supported limits: CPU (quota/period), memory, process count, disk I/O (read/write bandwidth)
- Stats available: memory usage, CPU time, process count, disk I/O bytes

**Network Interception (iptables):** Lima uses iptables DNAT rules for traffic redirection:
- Custom chain: `AGENTSH` in the nat table
- TCP traffic redirected to proxy port (localhost excluded)
- DNS (UDP port 53) redirected to DNS proxy port

**Filesystem Mounting (bindfs):** Lima uses bindfs for FUSE-based filesystem mounting inside the VM:
- Source directory mounted to mount point using bindfs (passthrough mount)
- Automatic bindfs installation if not present (`sudo apt install bindfs`)
- Unmount via `fusermount -u` with `sudo umount` fallback
- Mount tracking prevents duplicate mounts to same location

**Process Isolation (namespaces):** Lima uses Linux namespaces via `unshare` for process isolation:
- Full isolation: user, mount, UTS, IPC, network, and PID namespaces
- Partial isolation: mount, UTS, IPC, PID namespaces (when user namespace unavailable)
- Automatic detection of available isolation level
- Working directory support for sandboxed commands

**Manual Mode Selection:** You can force Lima mode in your config:

```yaml
platform:
  mode: darwin-lima  # or just "lima"
```

**Security Score:** 85% - Full Linux capabilities with slight VM overhead.

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
- ✅ WinFsp filesystem mounting (FUSE-style with soft-delete support)

**Registry Policy Configuration:**

Registry rules in your policy file control Windows registry access:

```yaml
registry_rules:
  - name: allow-app-settings
    paths: ['HKCU\SOFTWARE\MyApp\*']
    operations: ["*"]
    decision: allow

  - name: block-persistence-keys
    paths:
      - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*'
      - 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*'
    operations: [write, create, delete]
    decision: deny
    priority: 100
```

Built-in high-risk path detection automatically blocks write operations to critical registry locations (Run keys, services, Windows Defender settings, LSA) with MITRE ATT&CK technique mappings for audit logging.

**WinFsp Filesystem Mounting:**

For FUSE-style filesystem mounting with soft-delete support:

```bash
# Install WinFsp (required for FUSE-style mounting)
winget install WinFsp.WinFsp

# Build with CGO enabled
CGO_ENABLED=1 go build -o agentsh.exe ./cmd/agentsh

# Run the server (WinFsp mount is automatic)
agentsh server
```

WinFsp provides the same FUSE-style mounting as macOS FUSE-T, using a shared `internal/platform/fuse/` package. Features include:
- Policy-enforced file operations (read, write, create, delete)
- Soft-delete (files moved to trash instead of permanent deletion)
- Automatic minifilter process exclusion to prevent double-interception

**AppContainer Sandbox Isolation:**

Windows 8+ supports AppContainer for kernel-enforced process isolation. agentsh uses a two-layer security model:

| Layer | Technology | Purpose |
|-------|------------|---------|
| Primary | AppContainer | Kernel-enforced capability isolation |
| Secondary | Minifilter driver | Policy-based file/registry rules |

**AppContainer Features:**
- Full process isolation with kernel-enforced capability restrictions
- Stdout/stderr capture from sandboxed processes
- Automatic ACL cleanup on sandbox close
- Configurable network access levels (none, outbound, local, full)

**Sandbox Configuration:**

```yaml
sandbox:
  windows:
    use_app_container: true    # Default: true (Windows 8+ required)
    use_minifilter: true       # Default: true
    network_access: none       # none, outbound, local, full
    fail_on_error: true        # Default: true
```

**Network Access Levels:**

| Level | Description |
|-------|-------------|
| `none` | No network access (default, maximum isolation) |
| `outbound` | Internet client connections only |
| `local` | Private network access only |
| `full` | All network access |

**Configuration Example (Go API):**

```go
config := platform.SandboxConfig{
    Name: "my-sandbox",
    WorkspacePath: "/path/to/workspace",
    WindowsOptions: &platform.WindowsSandboxOptions{
        UseAppContainer:         true,
        UseMinifilter:           true,
        NetworkAccess:           platform.NetworkNone,
        FailOnAppContainerError: true,
    },
}
```

See [Windows Driver Deployment Guide](windows-driver-deployment.md) for installation and configuration.

### Windows (WSL2)

- Install WSL2 + a distro (e.g. Ubuntu).
- Inside WSL, install `fuse3` and run `agentsh server`.
- Keep workspaces on the Linux filesystem (e.g. `/home/...`), not `/mnt/c/...`, for performance.

**Resource Limits (cgroups v2):** WSL2 uses cgroups v2 inside the Linux VM for resource enforcement:
- Cgroup path: `/sys/fs/cgroup/agentsh/<session-name>`
- Supported limits: CPU (quota/period), memory, process count, disk I/O (read/write bandwidth)
- Stats available: memory usage, CPU time, process count, disk I/O bytes

**Network Interception (iptables):** WSL2 uses iptables DNAT rules for traffic redirection:
- Custom chain: `AGENTSH` in the nat table
- TCP traffic redirected to proxy port (localhost excluded)
- DNS (UDP port 53) redirected to DNS proxy port

**Filesystem Mounting (bindfs):** WSL2 uses bindfs for FUSE-based filesystem mounting inside the VM:
- Windows paths translated to WSL paths (e.g., `C:\Users\test` → `/mnt/c/Users/test`)
- Source directory mounted to mount point using bindfs (passthrough mount)
- Automatic bindfs installation if not present (`sudo apt install bindfs`)
- Unmount via `fusermount -u` with `sudo umount` fallback
- Mount tracking prevents duplicate mounts to same location

**Process Isolation (namespaces):** WSL2 uses Linux namespaces via `unshare` for process isolation:
- Full isolation: user, mount, UTS, IPC, network, and PID namespaces
- Partial isolation: mount, UTS, IPC, PID namespaces (when user namespace unavailable)
- Automatic detection of available isolation level
- Working directory support for sandboxed commands

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
- **bindfs mount fails (Lima/WSL2):** ensure bindfs is installed in the VM (`sudo apt install bindfs`) and `/dev/fuse` is available.
- **System Extension not loading (macOS ESF+NE):** check System Settings > General > Login Items & Extensions. User must approve the System Extension.
- **XPC connection fails (macOS ESF+NE):** verify the System Extension is approved and running. Check Console.app for XPC errors.
- **ESF client initialization fails:** ensure the app is signed with valid ESF entitlement from Apple (requires approval).
- **Transparent network mode fails:** run as root / with NET_ADMIN capabilities; otherwise rely on proxy mode.
- **cgroups errors:** keep `sandbox.cgroups.enabled: false` unless you have a writable cgroup v2 base path configured.
- **gRPC connection fails:** confirm `server.grpc.enabled: true`, the address/port are reachable, and (if auth is enabled) send the API key via gRPC metadata `x-api-key`.
