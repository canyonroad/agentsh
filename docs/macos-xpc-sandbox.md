# macOS XPC Sandbox

agentsh provides XPC/Mach IPC control on macOS through sandbox profiles that restrict which system services sandboxed processes can communicate with.

## Overview

XPC (Cross-Process Communication) is macOS's primary IPC mechanism. By default, any process can connect to any XPC service. agentsh's XPC sandbox restricts this using Apple's sandbox profile system.

## Configuration

```yaml
sandbox:
  xpc:
    enabled: true
    mode: enforce  # enforce | audit | disabled
    mach_services:
      default_action: deny  # deny (allowlist) or allow (blocklist)
      allow:
        - "com.apple.system.logger"
        - "com.apple.CoreServices.coreservicesd"
      block:
        - "com.apple.security.authhost"
      allow_prefixes:
        - "com.apple.cfprefsd."
      block_prefixes:
        - "com.apple.accessibility."
```

## How It Works

1. When `agentsh exec` runs a command on macOS with XPC enabled, it wraps the command with `agentsh-macwrap`
2. The wrapper generates an SBPL (Sandbox Profile Language) profile with mach-lookup rules
3. The sandbox is applied via `sandbox_init_with_parameters()` before exec
4. The sandboxed process can only connect to allowed XPC services

## Default Allow List

When `default_action: deny`, these services are allowed by default:
- `com.apple.system.logger` - System logging
- `com.apple.CoreServices.coreservicesd` - Core services
- `com.apple.lsd.mapdb` - Launch services
- `com.apple.SecurityServer` - Code signing
- `com.apple.cfprefsd.*` - Preferences

## Default Block List

When `default_action: allow`, these are blocked by default:
- `com.apple.accessibility.*` - Accessibility APIs (input injection)
- `com.apple.tccd.*` - TCC bypass attempts
- `com.apple.security.authhost` - Auth dialog spoofing
- `com.apple.coreservices.appleevents` - AppleScript

## Discovering Required Services

To find which XPC services your application needs:

```bash
# Trace sandbox violations
sandbox-exec -t /tmp/trace.out -p "(version 1)(deny default)(allow mach-lookup)" ./myapp

# Watch system log
log stream --predicate 'subsystem == "com.apple.sandbox"' --level debug
```

## Audit Events

XPC sandbox violations generate `xpc_sandbox_violation` events in the audit log.
