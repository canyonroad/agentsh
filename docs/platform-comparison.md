# Platform Comparison Matrix

This document provides a comprehensive comparison of agentsh capabilities across all supported platforms.

## Feature Support Matrix

| Feature | Linux | macOS ESF+NE | macOS FUSE-T | macOS Lima | Win Native | Win WSL2 |
|---------|:-----:|:------------:|:------------:|:----------:|:----------:|:--------:|
| **Filesystem Interception** |
| Implementation | FUSE3 | Endpoint Security | FUSE-T (NFS) | FUSE3 | Mini Filter + WinFsp | FUSE3 |
| File read monitoring | Block | Block | Block | Block | Block | Block |
| File write monitoring | Block | Block | Block | Block | Block | Block |
| File create/delete | Block | Block | Block | Block | Block | Block |
| File policy enforcement | Yes | Yes | Yes | Yes | Yes | Yes |
| **Network Interception** |
| Implementation | iptables | Network Extension | pf | iptables | WinDivert | iptables |
| TCP interception | Block | Block | Block | Block | Block | Block |
| UDP interception | Block | Block | Block | Block | Block | Block |
| DNS interception | Block | Block | Block | Block | Block | Block |
| TLS inspection | Yes | Yes | Yes | Yes | Yes | Yes |
| Per-app filtering | No | Yes | No | No | No | No |
| **Synchronous Interception** |
| File operations hold | Yes | Yes | Yes | Yes | Yes | Yes |
| Network operations hold | Yes | Yes | Yes | Yes | Yes | Yes |
| DNS hold | Yes | Yes | Yes | Yes | Yes | Yes |
| Env var hold | Yes | Spawn | Partial | Yes | Partial | Yes |
| Registry hold | N/A | N/A | N/A | N/A | Yes | N/A |
| File redirect | Yes | Yes | Yes | Yes | Yes | Yes |
| Network redirect | Yes | Yes | Yes | Yes | Yes | Yes |
| DNS redirect | Yes | Yes | Yes | Yes | Yes | Yes |
| Env var redirect | Yes | Spawn | Partial | Yes | Partial | Yes |
| Registry redirect | N/A | N/A | N/A | N/A | Yes | N/A |
| Manual approval | Yes | Yes | Yes | Yes | Yes | Yes |
| **Environment Variable Protection** |
| Spawn-time filtering | Yes | Yes | Yes | Yes | Yes | Yes |
| Runtime interception | LD_PRELOAD | No | DYLD* | LD_PRELOAD | Detours | LD_PRELOAD |
| env_read events | Yes | Spawn | Partial | Yes | Partial | Yes |
| env_list events | Yes | Spawn | Partial | Yes | Partial | Yes |
| env_write events | Yes | Spawn | Partial | Yes | Partial | Yes |
| environ blocking | Yes | Yes | Non-SIP | Yes | Partial | Yes |
| **Process Isolation** |
| Mount namespace | Yes | No | No | Yes | No | Yes |
| Network namespace | Yes | No | No | Yes | No | Yes |
| PID namespace | Yes | No | No | Yes | No | Yes |
| User namespace | Yes | No | No | Yes | No | Yes |
| AppContainer | N/A | N/A | N/A | N/A | Partial | N/A |
| **Syscall Filtering** |
| seccomp-bpf | Yes | No | No | Yes | No | Yes |
| Process exec blocking | Yes | Yes | No | Yes | No | Yes |
| Syscall allowlist | Yes | No | No | Yes | No | Yes |
| **Resource Limits** |
| CPU limit | Yes | No | No | Yes | Job | Yes |
| Memory limit | Yes | No | No | Yes | Job | Yes |
| Disk I/O limit | Yes | No | No | Yes | No | Yes |
| Network BW limit | Yes | No | No | Yes | No | Yes |
| Process count | Yes | No | No | Yes | Job | Yes |
| **Platform-Specific** |
| Registry monitoring | N/A | N/A | N/A | N/A | Yes | N/A |
| Registry blocking | N/A | N/A | N/A | N/A | Yes | N/A |
| Kernel events | eBPF | ESF | No | eBPF | No | eBPF |
| **Requirements** |
| Special permissions | root | ESF approval + NE entitlements | root + brew | Lima VM | Admin | WSL2 |
| Installation complexity | Low | Medium (ESF needs Apple approval) | Low | Medium | Medium | Low |

## Security Score Comparison

| Platform | Score | File Block | Net Block | Isolation | Syscall Filter | Resources |
|----------|:-----:|:----------:|:---------:|:---------:|:--------------:|:---------:|
| **Linux Native** | 100% | Yes | Yes | Full | Yes | Full |
| **Windows WSL2** | 100% | Yes | Yes | Full | Yes | Full |
| **macOS ESF+NE** | 90% | Yes | Yes | None | Exec only | None |
| **macOS + Lima** | 85% | Yes | Yes | Full | Yes | Full |
| **macOS FUSE-T** | 70% | Yes | Yes | None | No | None |
| **Windows Native** | 85% | Yes | Yes | Partial | No | Partial |

## Security Feature Coverage

```
Platform               File    Network  Isolation  Syscall  Resources  Score
────────────────────────────────────────────────────────────────────────────

Linux Native          ████████████████████████████████████████████████  100%
                      File✓   Net✓    Iso✓      Sys✓     Res✓

Windows WSL2          ████████████████████████████████████████████████  100%
                      File✓   Net✓    Iso✓      Sys✓     Res✓

macOS ESF+NE          ████████████████████████████████████████░░░░░░░░   90%
                      File✓   Net✓    Iso✗      Sys⚠     Res✗
                      (ESF requires Apple approval; NE is standard capability)

macOS + Lima          ██████████████████████████████████████░░░░░░░░░░   85%
                      File✓   Net✓    Iso✓      Sys✓     Res✓
                      (VM overhead, file I/O slightly slower)

macOS FUSE-T + pf     ██████████████████████████████░░░░░░░░░░░░░░░░░░   70%
                      File✓   Net✓    Iso✗      Sys✗     Res✗
                      (No isolation, no syscall filter, no resource limits)

Windows Native        ██████████████████████████████████████░░░░░░░░░░   85%
                      File✓   Net✓    Iso⚠      Sys✗     Res⚠
                      (Mini Filter + WinDivert + Registry blocking + AppContainer sandbox)

Legend: ✓ = Full support  ⚠ = Partial support  ✗ = Not supported
```

## Performance Impact

### File Operations

| Mechanism | Overhead | Latency Added | Throughput Impact | Notes |
|-----------|:--------:|:-------------:|:-----------------:|-------|
| FUSE3 (Linux) | Low | 5-20µs | 3-8% | Kernel-userspace context switch |
| FUSE-T (macOS) | Medium | 50-200µs | 10-25% | NFS protocol overhead |
| ESF (macOS) | Very Low | 1-5µs | <2% | In-kernel, no context switch for observe |
| Mini Filter (Windows) | Very Low | 1-5µs | <3% | In-kernel, no userspace IPC for cached |
| WinFsp (Windows) | Low | 10-50µs | 5-15% | Kernel-userspace via FUSE protocol |
| Lima VM | Medium | 20-100µs | 15-30% | VM boundary + 9p/virtiofs |

```
File I/O Overhead Comparison (relative to native)

Sequential Read (large files):
Native          ████████████████████████████████████████  100% baseline
FUSE3           ████████████████████████████████████░░░░   92%
ESF             ████████████████████████████████████████   98%
FUSE-T          ████████████████████████████████░░░░░░░░   80%
MiniFilter      ████████████████████████████████████████   98%
WinFsp          ████████████████████████████████████░░░░   90%
Lima/virtiofs   ████████████████████████████░░░░░░░░░░░░   70%

Random I/O (many small files):
Native          ████████████████████████████████████████  100% baseline
FUSE3           ████████████████████████████████░░░░░░░░   85%
ESF             ████████████████████████████████████████   99%
FUSE-T          ████████████████████████████░░░░░░░░░░░░   75%
MiniFilter      ████████████████████████████████████████   97%
WinFsp          ████████████████████████████████░░░░░░░░   85%
Lima/virtiofs   ██████████████████████████░░░░░░░░░░░░░░   65%
```

### Network Operations

| Mechanism | Overhead | Latency Added | Connection Overhead | Notes |
|-----------|:--------:|:-------------:|:-------------------:|-------|
| iptables + proxy | Low | 0.1-1ms | Per-connection | Single hop through localhost |
| Network Extension | Very Low | 0.05-0.2ms | Per-packet capable | In-kernel packet processing |
| pf + proxy | Low | 0.1-1ms | Per-connection | Similar to iptables |
| WinDivert | Low | 0.1-0.5ms | Per-packet | Kernel-mode redirection |

### Environment Variable Operations

| Mechanism | Overhead | Latency Added | Notes |
|-----------|:--------:|:-------------:|-------|
| Spawn-time filtering | None at runtime | 1-5ms at spawn | One-time cost per process |
| LD_PRELOAD sync | Medium | 50-500µs | IPC to daemon per getenv() |
| LD_PRELOAD cached | Very Low | 1-5µs | Policy cached in shim |
| Detours (Windows) | Low | 10-50µs | In-process hook |

### Synchronous Hold Impact

| Hold Type | Typical Latency | Impact |
|-----------|:---------------:|--------|
| Policy lookup (cached) | 1-10µs | Negligible |
| Policy lookup (IPC) | 50-200µs | Low, acceptable |
| Redirect (file) | Same as normal I/O | None beyond redirect target |
| Redirect (network) | +0.1-1ms | Connection setup to new target |
| Manual approval | 1s - 5min | **Process blocked** - use timeouts |

### Performance Recommendations by Workload

| Workload | Recommended Config | Expected Overhead |
|----------|-------------------|:-----------------:|
| CI/CD builds | FUSE3 + iptables, no TLS inspection | 5-10% |
| Development | FUSE-T + pf (macOS) or FUSE3 | 10-15% |
| AI agent tasks | Full interception, TLS inspection | 15-25% |
| Data processing | Lima with virtiofs batch mode | 15-30% |
| Security-critical | ESF + NE (macOS) or full Linux | 2-10% |

## Platform Selection Guide

```
                    ┌─────────────────────────────┐
                    │  What's your primary OS?    │
                    └──────────────┬──────────────┘
                                   │
         ┌─────────────────────────┼─────────────────────────┐
         │                         │                         │
         ▼                         ▼                         ▼
   ┌───────────┐             ┌───────────┐             ┌───────────┐
   │   Linux   │             │   macOS   │             │  Windows  │
   └─────┬─────┘             └─────┬─────┘             └─────┬─────┘
         │                         │                         │
         ▼                         ▼                         ▼
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│  Linux Native   │    │ Need full isolation │    │  Need registry      │
│                 │    │ & resource limits?  │    │  monitoring?        │
│  100% - Best    │    └──────────┬──────────┘    └──────────┬──────────┘
└─────────────────┘          Yes  │  No                 Yes  │  No
                                  │                          │
                                  ▼                          ▼
                    ┌─────────────────────┐    ┌─────────────────────┐
                    │    macOS + Lima     │    │   Windows Native    │
                    │    85% - Full       │    │   75% + Registry    │
                    │    isolation        │    │   + WinDivert       │
                    └─────────────────────┘    └─────────────────────┘
                                  │
                                  │ If Lima not acceptable
                                  ▼
                    ┌─────────────────────┐    ┌─────────────────────┐
                    │ Have Apple          │    │   Windows WSL2      │
                    │ entitlements?       │    │   100% - Full       │
                    └──────────┬──────────┘    │   Linux             │
                          Yes  │  No           └─────────────────────┘
                               │
              ┌────────────────┴────────────────┐
              ▼                                 ▼
┌─────────────────────┐           ┌─────────────────────┐
│   macOS ESF+NE      │           │   macOS FUSE-T      │
│   90% - Best native │           │   70% - Easy setup  │
│   (ESF needs Apple  │           │   brew install      │
│    approval; NE     │           │   fuse-t            │
│    is standard)     │           │                     │
└─────────────────────┘           └─────────────────────┘
```

## Recommended Configuration by Use Case

| Use Case | Recommended Platform | Security | Notes |
|----------|---------------------|:--------:|-------|
| Production - Maximum Security | Linux Native | 100% | Full isolation, all features |
| Production - Windows Server | Windows WSL2 | 100% | Full Linux security in VM |
| Production - macOS | macOS + Lima | 85% | Full isolation via VM |
| Enterprise Security Product | macOS ESF+NE | 90% | ESF requires Apple approval; NE is standard |
| Development - macOS | macOS FUSE-T | 70% | Easy setup, good monitoring |
| Development - Windows | Windows Native | 75% | Registry monitoring + WinDivert network |
| CI/CD Pipeline | Linux Native | 100% | Containers supported |
| Air-gapped/Offline | Linux Native | 100% | No external dependencies |

## Windows-Specific Features

| Feature | Native | WSL2 | Notes |
|---------|:------:|:----:|-------|
| **Registry Monitoring** |
| Read monitoring | Yes | N/A | Via RegNotifyChangeKeyValue |
| Write monitoring | Yes | N/A | Via RegNotifyChangeKeyValue |
| Create key monitoring | Yes | N/A | Via RegNotifyChangeKeyValue |
| Delete key monitoring | Yes | N/A | Via RegNotifyChangeKeyValue |
| Registry blocking | Yes | N/A | Via CmRegisterCallbackEx in mini filter driver |
| **High-Risk Path Alerts** |
| Run keys (persistence) | Yes | N/A | HKLM/HKCU Run, RunOnce |
| Services | Yes | N/A | HKLM\SYSTEM\Services |
| Winlogon | Yes | N/A | Shell, Userinit hijacking |
| Image File Exec Options | Yes | N/A | Debugger hijacking |
| COM objects | Yes | N/A | CLSID hijacking |
| Windows Defender | Yes | N/A | Policy modifications |
| LSA settings | Yes | N/A | Credential access |

## Windows Sandbox Configuration

| Configuration | Security | Performance | Use Case |
|--------------|----------|-------------|----------|
| AppContainer + Minifilter | Maximum | ~5-10ms startup | AI agent execution (full output capture) |
| AppContainer only | High | ~3-5ms startup | Isolated dev environment |
| Minifilter only | Medium | <1ms startup | Policy enforcement only |
| Neither | None | Baseline | Legacy/unsandboxed |

**AppContainer Features:**
- Process execution inside isolated container
- Full stdout/stderr capture from sandboxed commands
- Automatic ACL cleanup on sandbox termination
- Configurable network access (none/outbound/local/full)

### Configuration Example

```yaml
sandbox:
  windows:
    use_app_container: true   # Default: true
    use_minifilter: true      # Default: true
    network_access: none      # none, outbound, local, full
    fail_on_error: true       # Default: true
```

## macOS Configuration Options

| Configuration | File Interception | Network | Isolation | Ease of Setup | Security |
|---------------|:-----------------:|:-------:|:---------:|:-------------:|:--------:|
| ESF + NE | Endpoint Security | Network Extension | None | Medium (ESF needs approval) | 90% |
| FUSE-T + pf | FUSE-T (NFS) | pf packet filter | None | Easy (`brew install`) | 70% |
| Lima VM | FUSE3 in VM | iptables in VM | Full | Medium | 85% |
| Degraded | FSEvents (observe) | pcap (observe) | None | None required | 25% |

**When to use each:**
- **ESF + NE**: Building a commercial security product, have Apple Developer relationship
- **FUSE-T + pf**: Development, testing, personal use - best balance of features/simplicity
- **Lima VM**: Need full isolation and resource limits on macOS
- **Degraded**: Quick testing, observation-only use cases

## Known Limitations by Platform

### Linux Native
- No significant limitations
- Requires root or CAP_SYS_ADMIN for namespaces
- eBPF requires kernel 5.x+ for full features

### macOS ESF+NE
- **ESF requires Apple approval** - must apply for ESF entitlement with business justification
- **Network Extension is standard** - enable in Xcode, no approval needed (since Nov 2016)
- **No process isolation** - macOS has no namespace equivalent
- **No resource limits** - no cgroups equivalent
- **No syscall filtering** - except exec blocking via ESF
- Best option for commercial security products

### macOS FUSE-T + pf
- **No process isolation** - agents can see all processes
- **No resource limits** - cannot enforce CPU/memory limits
- **No syscall filtering** - cannot block dangerous syscalls
- **Requires root for pf** - network interception needs sudo
- Best option for development and personal use

### macOS + Lima
- Adds VM overhead (~200-500MB RAM)
- File access through virtiofs slightly slower
- Some edge cases with file permissions
- Requires maintaining Lima VM
- Best option for production on macOS

### Windows Native
- **Partial isolation** - AppContainer provides file/registry isolation but not full namespace isolation
- **No syscall filtering** - no seccomp equivalent
- **No disk I/O limits** - Job Objects don't support this
- **No network bandwidth limits** - Job Objects don't support this
- **WinDivert requires admin** - Administrator privileges needed for network interception
- **Driver requires signing** - Mini filter driver requires test signing (dev) or EV signing (production)
- Uses kernel-mode mini filter driver for filesystem and registry interception
- Configurable fail modes (fail-open/fail-closed) for production reliability
- See [Windows Driver Deployment Guide](windows-driver-deployment.md) for details

### Windows WSL2
- Slight overhead from VM layer
- Network goes through Windows NAT
- File I/O to Windows drives slower than native
- Some Windows integration edge cases
- **No registry monitoring** - WSL2 runs Linux, Windows registry not accessible

## Installation Quick Reference

| Platform | Command | Requirements |
|----------|---------|--------------|
| Linux | `curl -fsSL https://get.agentsh.dev \| bash` | root for full features |
| macOS ESF+NE | `make build-macos-enterprise` | Xcode 15+, ESF entitlement (Apple approval), code signing |
| macOS FUSE-T | `brew install fuse-t && brew install agentsh` | root for pf network |
| macOS Lima | `brew install lima && limactl start agentsh` | Lima VM |
| Windows Native | `sc create agentsh type=filesys` | Admin, test signing (dev) or EV cert (prod) |
| Windows WSL2 | `wsl --install -d Ubuntu && ...` | WSL2 enabled |

See [macOS Build Guide](macos-build.md) for detailed macOS build instructions.

## Optimization Configuration

```yaml
# agentsh.yaml - Performance-optimized configuration

performance:
  # Cache policy decisions
  policy_cache:
    enabled: true
    ttl_seconds: 300
    max_entries: 10000

  # Batch event emission
  event_batching:
    enabled: true
    batch_size: 100
    flush_interval_ms: 100

  # Async logging (don't block operations)
  async_logging:
    enabled: true
    buffer_size: 10000

  # Skip interception for known-safe paths
  bypass_paths:
    - "/usr/lib/*"
    - "/lib/*"
    - "*.so"
    - "*.pyc"

  # Skip interception for known-safe hosts
  bypass_hosts:
    - "127.0.0.1"
    - "localhost"
    - "*.internal.company.com"

  # Reduce syscall overhead
  fuse:
    kernel_cache: true
    batch_forget: true
    max_readahead_kb: 1024
```
