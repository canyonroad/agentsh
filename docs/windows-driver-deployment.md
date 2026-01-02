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
