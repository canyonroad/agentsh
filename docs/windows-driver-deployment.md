# Windows Mini Filter Driver Deployment Guide

## Overview

This guide covers deploying the agentsh Windows mini filter driver in production environments, including code signing requirements, installation procedures, and monitoring.

## Requirements

### Development/Testing
- Windows 10/11 64-bit
- Test signing mode enabled (`bcdedit /set testsigning on`)
- Administrator privileges

### Production
- EV (Extended Validation) Code Signing Certificate
- Microsoft Hardware Dev Center account (for attestation signing on Windows 10 1607+)
- WHQL certification (optional, recommended for enterprise deployment)

## Code Signing

### Test Signing (Development)

1. Create a test certificate:
```cmd
makecert -r -pe -ss PrivateCertStore -n "CN=AgentSH Test" agentsh-test.cer
```

2. Sign the driver:
```cmd
signtool sign /v /s PrivateCertStore /n "AgentSH Test" /t http://timestamp.digicert.com agentsh.sys
```

3. Enable test signing on target machine:
```cmd
bcdedit /set testsigning on
```

### Production Signing

1. **Obtain an EV Code Signing Certificate** from a trusted CA (DigiCert, Sectigo, etc.)

2. **Sign the driver catalog**:
```cmd
inf2cat /driver:. /os:10_x64
signtool sign /v /ac cross-cert.cer /n "Your Company" /tr http://timestamp.digicert.com /td sha256 /fd sha256 agentsh.cat
```

3. **Submit for attestation signing** (Windows 10 1607+):
   - Create account at https://partner.microsoft.com/dashboard
   - Submit driver package for attestation signing
   - Download signed package

## Installation

### Manual Installation

```cmd
REM As Administrator
copy agentsh.sys %SystemRoot%\System32\drivers\
rundll32.exe setupapi.dll,InstallHinfSection DefaultInstall 132 agentsh.inf
fltmc load agentsh
```

### Verify Installation

```cmd
fltmc
```

Expected output:
```
Filter Name                     Num Instances    Altitude    Frame
------------------------------  -------------  ------------  -----
AgentSH                               3          385200       0
```

### Uninstallation

```cmd
fltmc unload agentsh
rundll32.exe setupapi.dll,InstallHinfSection DefaultUninstall 132 agentsh.inf
del %SystemRoot%\System32\drivers\agentsh.sys
```

## Configuration

### Fail Modes

| Mode | Behavior |
|------|----------|
| `FAIL_MODE_OPEN` (default) | Allow operations when policy service unavailable |
| `FAIL_MODE_CLOSED` | Deny operations when policy service unavailable |

Configure via Go client:
```go
client.SetConfig(&DriverConfig{
    FailMode:              FailModeClosed,
    PolicyQueryTimeoutMs:  5000,
    MaxConsecutiveFailures: 10,
})
```

### Cache Tuning

| Parameter | Default | Range | Description |
|-----------|---------|-------|-------------|
| CacheMaxEntries | 4096 | 100-100000 | Maximum cached decisions |
| CacheDefaultTTLMs | 5000 | 100-3600000 | Default cache entry TTL |

## Monitoring

### Registry Monitoring

The driver intercepts Windows registry operations via `CmRegisterCallbackEx`. This provides:

- **Operation interception:** Create, set, delete, rename keys and values
- **Policy enforcement:** Allow, deny, or require approval based on registry rules
- **High-risk path detection:** Automatic detection of persistence and security-sensitive paths
- **MITRE ATT&CK mapping:** Events include technique IDs for security monitoring

#### Registry Policy Configuration

In your policy file (`agentsh.yaml`):

```yaml
registry_rules:
  # Allow application settings
  - name: allow-app-settings
    paths: ['HKCU\SOFTWARE\MyApp\*']
    operations: ["*"]
    decision: allow

  # Block persistence locations
  - name: block-run-keys
    paths:
      - 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*'
      - 'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*'
    operations: [write, create, delete]
    decision: deny
    priority: 100
    notify: true

  # Require approval for service modifications
  - name: approve-service-changes
    paths: ['HKLM\SYSTEM\CurrentControlSet\Services\*']
    operations: [write, create, delete]
    decision: approve
    message: "Agent wants to modify service: {{.Path}}"
    timeout: 2m
```

#### Registry Operations

| Operation | Description |
|-----------|-------------|
| `read` | Query key/value (QueryValue) |
| `write` | Set key/value (SetValue) |
| `create` | Create key (CreateKey) |
| `delete` | Delete key/value (DeleteKey, DeleteValue) |
| `rename` | Rename key (RenameKey) |

#### High-Risk Registry Paths

The driver includes built-in detection for high-risk paths commonly used in attacks:

| Path | Risk | MITRE Technique |
|------|------|-----------------|
| `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*` | Critical | T1547.001 - Registry Run Keys |
| `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon*` | Critical | T1547.004 - Winlogon Helper DLL |
| `HKLM\SYSTEM\CurrentControlSet\Services\*` | High | T1543.003 - Windows Service |
| `HKLM\SOFTWARE\Policies\Microsoft\Windows Defender*` | Critical | T1562.001 - Disable Security Tools |
| `HKLM\SYSTEM\CurrentControlSet\Control\Lsa*` | Critical | T1003 - Credential Dumping |

Write operations to these paths are blocked by default even if `default_action: allow` is set.

### Metrics

Retrieve via Go client:
```go
metrics, _ := client.GetMetrics()
fmt.Printf("Cache hit rate: %.2f%%\n",
    float64(metrics.CacheHitCount) / float64(metrics.CacheHitCount + metrics.CacheMissCount) * 100)
```

Key metrics:
- `CacheHitCount` / `CacheMissCount` - Cache efficiency
- `PolicyQueryTimeouts` - Policy service responsiveness
- `FailOpenMode` - Current fail mode state
- `AllowDecisions` / `DenyDecisions` - Policy enforcement stats

### Windows Event Log

Driver events appear in:
- Event Viewer → Windows Logs → System
- Source: AgentSH

### Debug Output

In development, view DbgPrint output with DebugView (Sysinternals).

## Troubleshooting

### Driver won't load

1. Check test signing: `bcdedit | findstr testsigning`
2. Verify driver signature: `signtool verify /v /pa agentsh.sys`
3. Check Event Viewer for errors

### High latency

1. Check metrics for cache hit rate (should be >80%)
2. Verify policy service is running
3. Consider increasing cache size

### Fail-open triggered

1. Check policy service connectivity
2. Review `ConsecutiveFailures` metric
3. Increase `MaxConsecutiveFailures` or fix connectivity

## Security Considerations

1. **Production deployments must use EV-signed drivers**
2. **Never disable Secure Boot in production**
3. **Use FAIL_MODE_CLOSED for high-security environments**
4. **Monitor fail mode transitions in SIEM**
5. **Rotate session tokens regularly**

## WinFsp Coexistence

When using both the minifilter driver and WinFsp filesystem mounting, the agentsh process is automatically excluded from minifilter interception to prevent double-capture of file events.

### How It Works

1. Before mounting WinFsp, the Go client calls `ExcludeSelf()` on the driver client
2. The driver stores the agentsh process ID in `gExcludedProcessId`
3. All minifilter pre-callbacks (PreCreate, PreWrite, PreSetInfo) check for the excluded PID
4. If the current process matches, the operation is allowed without policy check

### Configuration

The exclusion is automatic when both systems are active. No additional configuration is required.

```go
// This happens automatically in Filesystem.Mount()
if fs.driverClient != nil && fs.driverClient.Connected() {
    fs.driverClient.ExcludeSelf()
}
```

### Troubleshooting

If you see duplicate file events:
1. Verify the driver client is connected before mounting WinFsp
2. Check that `ExcludeSelf()` completes without error
3. Ensure the minifilter driver is running (version with MSG_EXCLUDE_PROCESS support)

To verify exclusion is working:
```go
// Check metrics - file events should not double-count
metrics, _ := client.GetMetrics()
fmt.Printf("File queries: %d\n", metrics.FilePolicyQueries)
```

## Sandbox Integration

The Windows sandbox uses two complementary isolation layers:

### AppContainer (Primary)

- Kernel-enforced capability isolation
- Automatic registry isolation
- Configurable network access
- Requires Windows 8+

### Minifilter (Secondary)

- Policy-based file/registry rules
- Works with AppContainer for defense-in-depth
- Can operate standalone for legacy systems

### Configuration

```go
config := platform.SandboxConfig{
    Name: "my-sandbox",
    WorkspacePath: "/path/to/workspace",
    AllowedPaths: []string{"/path/to/tools"},
    WindowsOptions: &platform.WindowsSandboxOptions{
        UseAppContainer: true,
        UseMinifilter: true,
        NetworkAccess: platform.NetworkOutbound,
        FailOnAppContainerError: true,
    },
}
```
