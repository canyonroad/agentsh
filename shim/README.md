# Environment Variable Interception Shims

This directory contains native code shims that intercept environment variable access
at runtime. These provide Layer 2 protection (see §7 in the spec) to prevent agents
from bypassing environment filtering by directly reading `/proc/self/environ` or
using native APIs.

## Overview

| Platform | Mechanism | File |
|----------|-----------|------|
| Linux | `LD_PRELOAD` | `linux/libenvshim.so` |
| macOS | `DYLD_INSERT_LIBRARIES` | `darwin/libenvshim.dylib` |
| Windows | Microsoft Detours | `windows/envshim.dll` |

## How It Works

The shims intercept standard library functions for environment variable access:

- **Linux/macOS**: `getenv()`, `setenv()`, `putenv()`, `unsetenv()`
- **Windows**: `GetEnvironmentVariableA/W`, `SetEnvironmentVariableA/W`, `GetEnvironmentStringsA/W`

When a blocked variable is accessed, the shim returns NULL (or empty) as if the
variable doesn't exist, and emits an event to the agentsh daemon.

## Configuration

Policy is loaded from `/etc/agentsh/env-policy.conf` (or path in `AGENTSH_ENV_POLICY_FILE`):

```conf
# Mode: allowlist (default, more secure) or blocklist
mode=blocklist

# Variables to block (glob patterns supported)
blocked=*_KEY,*_TOKEN,*_SECRET,*_PASSWORD,AWS_*,GITHUB_*

# Sensitive patterns for logging (substring match)
sensitive=KEY,TOKEN,SECRET,PASSWORD,CREDENTIAL

# Enable/disable event logging
log_access=true
```

## Building

### Linux

```bash
cd linux
make
# Test
make test
```

### macOS

```bash
cd darwin
make
# Test (note: SIP restrictions apply)
make test
```

### Windows

Requires Microsoft Detours (automatically fetched by CMake):

```powershell
cd windows
mkdir build && cd build
cmake ..
cmake --build . --config Release
```

## Usage

### Linux

```bash
LD_PRELOAD=/path/to/libenvshim.so your_command
```

### macOS

```bash
# Only works with non-system binaries due to SIP
DYLD_INSERT_LIBRARIES=/path/to/libenvshim.dylib your_command
```

### Windows

```powershell
# Using the injector helper
envshim-inject.exe your_command.exe [args]

# Or via IFEO (Image File Execution Options) for system-wide injection
```

## Event Logging

Events are sent to the agentsh daemon via Unix socket (Linux/macOS) or named pipe (Windows):

- Linux: `/run/agentsh/env.sock` (or `AGENTSH_ENV_SOCKET`)
- macOS: `/var/run/agentsh/env.sock` (or `AGENTSH_ENV_SOCKET`)
- Windows: `\\.\pipe\agentsh-env`

Event format (JSON):

```json
{
  "type": "env_read",
  "timestamp": 1703520000.123456789,
  "decision": "deny",
  "platform": "linux-ld-preload",
  "metadata": {
    "variable": "AWS_SECRET_KEY",
    "operation": "read",
    "sensitive": true,
    "pid": 12345
  }
}
```

## Limitations

### macOS (SIP)

System Integrity Protection prevents `DYLD_INSERT_LIBRARIES` from working with:
- System binaries in `/usr/bin`, `/bin`, `/sbin`
- Signed Apple applications
- Apps with restricted entitlements

Workarounds:
1. Use Lima/Docker for full Linux environment
2. Build your tools from source (unsigned)
3. Disable SIP (not recommended for production)

### Windows

- Requires administrator privileges for system-wide injection
- Some protected processes may not allow DLL injection
- Antivirus may flag Detours-based injection
