# Windows Minifilter Driver

This document describes how to build, install, and test the AgentSH Windows minifilter driver.

## Overview

The AgentSH minifilter is a Windows kernel driver that intercepts filesystem operations for policy enforcement. It communicates with the usermode `agentsh.exe` process via a filter communication port.

### Behavior

| Scenario | Behavior |
|----------|----------|
| agentsh not running | All filesystem operations allowed (fail-open) |
| agentsh running, session registered | Policy enforced |
| agentsh crashes mid-session | Fail-open after timeout |

The driver only monitors processes explicitly registered as sessions. Non-session processes are always allowed (fast path).

## Prerequisites

### Required Software

| Component | Purpose | Download |
|-----------|---------|----------|
| Go 1.25+ | Build agentsh.exe | https://go.dev/dl/ |
| Visual Studio 2022 Build Tools | MSBuild + C++ compiler | https://visualstudio.microsoft.com/ |
| Windows SDK | Windows headers/libs | Included with VS |
| Windows Driver Kit (WDK) | Kernel driver toolset | https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk |
| WDK VS Extension | VS integration | https://go.microsoft.com/fwlink/?linkid=2296374 |

### Installation via winget

```powershell
# Git (optional, for Windows-native git)
winget install Git.Git

# WDK (match your Windows SDK version)
winget search "windows driver kit"
winget install Microsoft.WindowsWDK.10.0.26100
```

### Verify Installation

```powershell
# Check MSBuild
& "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" -version

# Check WDK tools
Test-Path "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\stampinf.exe"

# Check WDK VS integration
Test-Path "C:\Program Files (x86)\Windows Kits\10\build\WindowsDriver.common.targets"
```

## Building

### From Windows (Native)

```cmd
cd drivers\windows\agentsh-minifilter

# Build Release
scripts\build.cmd Release x64

# Build Debug
scripts\build.cmd Debug x64

# Output: bin\x64\Release\agentsh.sys (or Debug)
```

### From WSL2

```bash
# Build Go binary for Windows
GOOS=windows GOARCH=amd64 go build -o bin/agentsh.exe ./cmd/agentsh

# Build driver via PowerShell + MSBuild
powershell.exe -Command "& 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe' '\\wsl.localhost\Ubuntu\$PWD\drivers\windows\agentsh-minifilter\agentsh.sln' /p:Configuration=Release /p:Platform=x64 /p:SignMode=Off /t:Build /v:minimal"
```

### Build Outputs

| File | Description |
|------|-------------|
| `bin\x64\Release\agentsh.sys` | Kernel driver |
| `bin\x64\Release\agentsh.pdb` | Debug symbols |

## Installing

### Enable Test Signing (One-time)

Unsigned drivers require test signing mode:

```powershell
# Run as Administrator
bcdedit /set testsigning on

# Reboot required
Restart-Computer
```

### Install Driver

```powershell
# Run as Administrator
cd drivers\windows\agentsh-minifilter

# Install (copies to System32\drivers and loads)
.\scripts\install.cmd bin\x64\Release\agentsh.sys
```

### Verify Installation

```powershell
# List loaded minifilters
fltmc filters

# Check agentsh filter instances
fltmc instances -f agentsh
```

## Uninstalling

```powershell
# Run as Administrator
cd drivers\windows\agentsh-minifilter

# Uninstall (unloads and removes)
.\scripts\uninstall.cmd
```

## Dynamic Load/Unload

For development, you can load and unload the driver without full install/uninstall:

```powershell
# Load driver (must be in System32\drivers or specify full path)
fltmc load agentsh

# Unload driver
fltmc unload agentsh

# Check status
fltmc filters
```

## Testing

### Basic Driver Test

1. Build the driver:
   ```powershell
   scripts\build.cmd Release x64
   ```

2. Install and load:
   ```powershell
   scripts\install.cmd bin\x64\Release\agentsh.sys
   fltmc filters  # Verify loaded
   ```

3. Run agentsh and create a session:
   ```powershell
   .\agentsh.exe serve --config configs\server-config.yaml
   ```

4. In another terminal, create a session and test policy enforcement.

5. Unload when done:
   ```powershell
   scripts\uninstall.cmd
   ```

### Debug Output

View driver debug messages using DebugView or WinDbg:

```powershell
# Download DebugView from Sysinternals
# Run as Administrator, enable "Capture Kernel" option

# Driver outputs messages like:
# AgentSH: Client connected (PID: 1234, Version: 0x00010000)
# AgentSH: Session registration failed: 0x80000001
```

### Driver Verifier

For development, enable Driver Verifier to catch bugs:

```powershell
# Enable verifier for agentsh driver
verifier /standard /driver agentsh.sys

# Reboot required
Restart-Computer

# Check verifier status
verifier /query

# Disable when done
verifier /reset
```

## Troubleshooting

### Build Errors

| Error | Solution |
|-------|----------|
| `MSBuild not found` | Install VS Build Tools with C++ workload |
| `WindowsKernelModeDriver10.0 not found` | Install WDK and WDK VS Extension |
| `SDK version mismatch` | Ensure WDK version matches Windows SDK |

### Installation Errors

| Error | Solution |
|-------|----------|
| `Access denied` | Run as Administrator |
| `Driver load failed` | Enable test signing mode |
| `Filter not loading` | Check `fltmc filters` for conflicts |

### Runtime Issues

| Issue | Solution |
|-------|----------|
| Driver not intercepting | Verify session is registered |
| System slowdown | Check for policy query timeouts |
| BSOD | Use Driver Verifier to diagnose |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     User Mode                                │
│  ┌─────────────┐     Filter Port      ┌──────────────────┐  │
│  │ agentsh.exe │◄────────────────────►│ Policy Engine    │  │
│  └─────────────┘                      └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                          │
                    FltCreateCommunicationPort
                          │
┌─────────────────────────────────────────────────────────────┐
│                    Kernel Mode                               │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                  agentsh.sys                         │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │    │
│  │  │ Process  │  │ Policy   │  │ File Operations  │   │    │
│  │  │ Tracking │  │ Cache    │  │ Callbacks        │   │    │
│  │  └──────────┘  └──────────┘  └──────────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
│                          │                                   │
│                    Filter Manager                            │
│                          │                                   │
│                    NTFS / ReFS                               │
└─────────────────────────────────────────────────────────────┘
```

### Components

| Component | File | Purpose |
|-----------|------|---------|
| Driver Entry | `driver.c` | Initialization, filter registration |
| Communication | `communication.c` | User-kernel message passing |
| Filesystem | `filesystem.c` | File operation interception |
| Process | `process.c` | Session process tracking |
| Cache | `cache.c` | Policy decision caching |
| Config | `config.c` | Runtime configuration |
| Metrics | `metrics.c` | Performance counters |
| Registry | `registry.c` | Registry operation filtering |

### Intercepted Operations

#### Filesystem (Filter Manager)

| IRP | Purpose |
|-----|---------|
| `IRP_MJ_CREATE` | File open/create |
| `IRP_MJ_WRITE` | File write |
| `IRP_MJ_SET_INFORMATION` | Delete, rename |

#### Registry (CmRegisterCallbackEx)

| Operation | Purpose |
|-----------|---------|
| `RegNtPreCreateKeyEx` | Key creation |
| `RegNtPreSetValueKey` | Value modification |
| `RegNtPreDeleteKey` | Key deletion |
| `RegNtPreDeleteValueKey` | Value deletion |
| `RegNtPreRenameKey` | Key rename |

The driver monitors high-risk registry paths (MITRE ATT&CK mapped):
- Persistence: Run keys (T1547.001), Services (T1543.003), Winlogon (T1547.004)
- Defense Evasion: Image File Execution Options (T1546.012), Windows Defender (T1562.001)
- Credential Access: LSA settings (T1003)
- COM Hijacking: CLSID keys (T1546.015)

#### Process Tracking (PsSetCreateProcessNotifyRoutineEx)

| Event | Purpose |
|-------|---------|
| Process creation | Inherit session from parent |
| Process termination | Remove from tracking |

### NOT Handled by Minifilter

| Component | Implementation | Notes |
|-----------|----------------|-------|
| **Networking** | Usermode (WinDivert/WFP/AppContainer) | See `internal/platform/windows/` |

## Network Enforcement

Network control is handled separately from the minifilter driver, with multiple options providing strong protection even without WinDivert.

### Option 1: WinDivert (Full Traffic Control)

Requires installing the WinDivert driver (`WinDivert.sys`).

| Capability | Status |
|------------|--------|
| Transparent proxy redirect | ✓ |
| DNS interception | ✓ |
| Block by IP/port/process | ✓ |
| Traffic inspection | ✓ |

### Option 2: WFP (Windows Filtering Platform)

Always available on Windows Vista+. **No driver installation required.**

| Capability | Status |
|------------|--------|
| Block connections by IP/port | ✓ |
| Block connections by process | ✓ |
| Allow-list specific destinations | ✓ |
| Transparent proxy redirect | ✗ |
| DNS interception | ✗ |

### Option 3: AppContainer Isolation

Process-level network isolation using Windows security. **No driver or admin required.**

| Network Level | Effect |
|---------------|--------|
| `NetworkNone` | Complete network isolation |
| `NetworkOutbound` | Internet access only (no LAN) |
| `NetworkLocal` | LAN access only (no internet) |
| `NetworkFull` | Full network access |

Processes running in an AppContainer with `NetworkNone` cannot make any network connections - this provides **strong isolation without any drivers**.

### Comparison

| Feature | WinDivert | WFP | AppContainer |
|---------|-----------|-----|--------------|
| Transparent proxy | ✓ | ✗ | ✗ |
| DNS interception | ✓ | ✗ | ✗ |
| Block by IP/port | ✓ | ✓ | ✗ |
| Block by process | ✓ | ✓ | ✓ (all or nothing) |
| Deny all network | ✓ | ✓ | ✓ |
| Requires driver | Yes | No | No |
| Requires admin | Yes | Yes | No |

### Strong Protection Without WinDivert

Even without WinDivert installed, AgentSH provides strong network protection:

1. **AppContainer with `NetworkNone`**: Sandboxed processes have zero network access - they cannot connect to any IP address, resolve DNS, or communicate externally. This is enforced by the Windows kernel.

2. **WFP blocking**: For processes that need selective network access, WFP can block specific destinations or allow only approved endpoints.

3. **Proxy via environment**: Applications that respect `HTTP_PROXY`/`HTTPS_PROXY` environment variables can be routed through a policy-enforcing proxy.

The main limitation without WinDivert is the inability to **transparently intercept and inspect traffic** - but you can still **completely block** or **selectively allow** network access.

### Architecture Without WinDivert

```
┌─────────────────────────────────────────────────────────┐
│                  Protection Layers                       │
├─────────────────────────────────────────────────────────┤
│ Filesystem     → Minifilter driver    (full control)    │
│ Registry       → Minifilter driver    (full control)    │
│ Process tree   → Minifilter driver    (full tracking)   │
│ Network deny   → AppContainer         (kernel enforced) │
│ Network filter → WFP                  (block/allow)     │
└─────────────────────────────────────────────────────────┘
```

## Security Considerations

- The driver runs in kernel mode with full system privileges
- Only attach to NTFS volumes (configurable)
- Fail-open by default to prevent system lockup
- Policy cache to reduce usermode round-trips
- Timeout protection on policy queries
