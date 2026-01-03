# agentsh Project Structure

This document describes the *current* repository layout (not an aspirational structure).

## High-level layout

```
agentsh/
├── cmd/agentsh/                 # main() for the agentsh binary
├── internal/                    # implementation (not exported)
├── pkg/types/                   # API/CLI types shared across packages
├── proto/                       # gRPC proto definitions (Struct-based)
├── configs/                     # example configs (api keys, etc.)
├── docs/                        # design docs and notes
├── macos/                       # macOS System Extension (ESF+NE) Swift code
├── config.yml                   # example server config (repo-local)
└── default-policy.yml           # example policy (repo-local)
```

## `internal/` packages (where to change what)

- `internal/server/` — Wires configuration into HTTP + unix-socket servers and session lifecycle.
- `internal/api/` — HTTP routing + handlers (`/sessions`, `/exec`, `/events`, `/metrics`), exec responses (`include_events`, `guidance`).
- `internal/cli/` — Cobra CLI commands (`agentsh exec`, `agentsh session …`, `agentsh events …`).
- `internal/client/` — HTTP + gRPC clients used by the CLI (and tests) to call the server API.
- `internal/config/` — Config structs, load/validate helpers.
- `internal/policy/` — Policy parsing + evaluation and derived limits/timeouts.
- `internal/session/` — Session manager and built-in commands (`cd`, `export`, `aenv`, `als`, `acat`, `astat`).
- `internal/fsmonitor/` — FUSE workspace view + file operation capture.
- `internal/netmonitor/` — Network proxy + DNS cache/resolver and optional netns/transparent plumbing.
- `internal/limits/` — Optional cgroups v2 enforcement (Linux-only; wired from exec hooks).
- `internal/events/` — In-memory event broker for SSE.
- `internal/store/` — Event sinks (SQLite, JSONL, webhook) and composition.
- `internal/auth/` — API key auth implementation.
- `internal/approvals/` — Approval manager (shadow/enforced modes).
- `internal/platform/` — Platform abstraction layer for cross-platform support.
- `internal/platform/fuse/` — Shared FUSE package for macOS (FUSE-T) and Windows (WinFsp) filesystem mounting.
- `internal/platform/lima/` — Lima VM platform for macOS with full Linux isolation (cgroups v2, iptables, namespaces).
- `internal/platform/wsl2/` — WSL2 platform for Windows with full Linux isolation (cgroups v2, iptables, namespaces).

## Notes

- `pkg/types/` is the “schema” layer: keep it stable and versioned when changing API responses.
- Tests live next to code (`*_test.go`) in `internal/*`.

For gRPC:
- `proto/agentsh/v1/agentsh.proto` defines the service (Struct-based, no codegen required).
- `internal/api/grpc.go` implements the gRPC server (including `ExecStream` and `EventsTail`).
- `internal/client/grpc_client.go` provides a small gRPC client used by the CLI when `AGENTSH_TRANSPORT=grpc`.

## `macos/` directory (ESF+NE enterprise mode)

The `macos/` directory contains Swift code for the macOS System Extension that provides ESF+NE enforcement:

```
macos/
├── SysExt/                      # System Extension bundle
│   ├── main.swift               # System Extension entry point
│   ├── ESFClient.swift          # Endpoint Security Framework client
│   ├── FilterDataProvider.swift # Network Extension flow filter
│   ├── DNSProxyProvider.swift   # Network Extension DNS proxy
│   ├── Info.plist               # Bundle configuration
│   └── SysExt.entitlements      # ESF + NE entitlements
├── XPCService/                  # XPC service bridging Swift ↔ Go
│   ├── main.swift               # XPC service entry point
│   ├── XPCServiceDelegate.swift # XPC connection handling
│   └── PolicyBridge.swift       # Unix socket bridge to Go policy server
├── Shared/                      # Shared Swift types
│   └── XPCProtocol.swift        # XPC protocol definition
└── AgentSH.xcodeproj/           # Xcode project (build with Xcode 15+)
```

Related Go packages:
- `internal/platform/darwin/xpc/` — XPC protocol types and Unix socket server
- `internal/platform/darwin/sysext.go` — System Extension manager

**Build:** `make build-macos-enterprise` (requires Xcode 15+, Apple entitlements)

## `drivers/` directory (Windows kernel components)

The `drivers/` directory contains Windows kernel-mode driver code:

```
drivers/
└── windows/
    └── agentsh-minifilter/       # Windows Mini Filter driver
        ├── inc/                   # Header files
        │   ├── protocol.h         # User-mode ↔ kernel protocol
        │   └── ...
        └── src/                   # Driver implementation
            ├── driver.c           # Driver entry point
            ├── filesystem.c       # File operation interception
            ├── communication.c    # Filter port communication
            ├── registry.c         # Registry operation interception
            └── ...
```

Related Go packages:
- `internal/platform/windows/driver_client.go` — Driver communication client
- `internal/platform/windows/filesystem.go` — Filesystem interceptor (WinFsp + minifilter)

**Build:** Requires Visual Studio 2022 + WDK (Windows Driver Kit)
