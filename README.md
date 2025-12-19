# agentsh

**A secure shell environment for AI agents**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.25-blue.svg)](https://golang.org/)

---

## Overview

agentsh is a purpose-built shell environment that provides AI agents with secure, monitored, and policy-controlled command execution. Unlike traditional shells designed for humans, agentsh treats every operation as an auditable event with structured, queryable logs.

### Key Features

- **🔒 Complete I/O Visibility**: Intercepts all file reads, writes, and deletes—even within scripts
- **🌐 Network Monitoring**: Captures all network connections and DNS queries
- **📋 Policy Enforcement**: Fine-grained control over what agents can do
- **📊 Dual Output Modes**: Shell-like output by default; JSON mode for tools/agents
- **⚡ Session Persistence**: Keep sandboxes alive across commands for efficiency
- **✅ Approval Workflows**: Human-in-the-loop for sensitive operations
- **🗑️ Delete Safety (FUSE audit)**: Audit, soft-block, or soft-delete destructive ops; restore/purge via `agentsh trash`

### Why agentsh?

| Traditional Shell | agentsh |
|------------------|---------|
| `rm -rf /` just runs | Policy blocks dangerous operations |
| `python script.py` is a black box | See every file and network operation inside |
| Error: "Permission denied" | Error with context, suggestions, and alternatives |
| No visibility into what happened | Complete audit trail of all operations |

## How agentsh compares (and why it protects better)

Codex CLI and Claude Code are excellent *agent developer tools*: they help an LLM plan, edit files, and run commands with varying degrees of sandboxing and user approvals. **agentsh is different**: it’s a dedicated execution gateway that sits *under* the agent and makes the *runtime* observable and enforceable at the operation level.

That matters because the risky stuff often happens **inside** “one safe-looking command” (`python script.py`, `npm install`, `make test`): subprocesses, file I/O, and network calls that are invisible at the wrapper/tool boundary. agentsh is built to surface and control those operations, then store and stream them for auditing.

In practice, you can use them together: keep your favorite coding agent UI, but route execution through agentsh so you get **consistent policies + auditability** across scripts, subprocesses, and long-running sessions.

### Protection model: tool boundary vs runtime boundary

| Dimension | Claude Code | Codex CLI | agentsh |
|----------|-------------|-----------|---------|
| Primary purpose | Interactive coding agent | Interactive coding agent | **Runtime execution gateway + audit** |
| Enforcement point | Tool / workflow boundary | Tool + OS sandbox boundary | **Per-operation policy at runtime (file + net + command)** |
| Visibility into subprocess file I/O | Limited (not per-open/write) | Limited (not per-open/write) | **Full workspace view interception via FUSE** |
| Visibility into DNS + outbound connects | Limited | Often blockable/configurable | **DNS + connect events (proxy + optional transparent mode)** |
| Approval semantics | Tool-level approvals | Tool-level approvals | **Policy decision preserved; shadow-approve or enforced approvals** |
| Audit storage | Local session logs | Local history/telemetry (varies) | **Pluggable sinks: SQLite + JSONL (default), optional webhook** |
| Query/search | Ad-hoc | Ad-hoc | **API + CLI queries over SQLite (filters by time/type/path/domain/decision)** |
| Event streaming | N/A / limited | N/A / limited | **SSE stream per session + metrics endpoint** |

> Note: The Claude Code / Codex CLI columns are a *high-level practitioner summary*. Exact behavior varies by version, platform, and configuration.

### Practitioner snapshot: Claude Code vs Codex CLI (context)

| Aspect | Claude Code | OpenAI Codex CLI |
|--------|-------------|------------------|
| Language/runtime | Node.js (bundled) | Native binary (Rust) |
| Open source | Bundled/obfuscated | Apache 2.0 open source |
| Sandbox | Process isolation | OS-level sandboxing (platform-specific) |
| File editing | String replacement (`Edit`) | Diff-like patches (`apply_patch`) |
| Project docs | `CLAUDE.md` | `AGENTS.md` |
| Observability | Session JSONL logs | Telemetry/history (varies) |

### Sandbox & security (context)

| Feature | Claude Code | Codex CLI |
|---------|-------------|----------|
| OS-level sandbox enforcement | No (process isolation) | Yes (platform-specific) |
| Network blocking | Typically not enforced | Often blockable/configurable |
| Filesystem restrictions | Approval/workflow based | Kernel-enforced sandbox (mode-dependent) |
| Audit trail focus | Session logs | Tool history/telemetry (varies) |

### File editing approach (context)

| Aspect | Claude Code `Edit` | Codex `apply_patch` |
|--------|---------------------|---------------------|
| Mechanism | Exact string replacement | Diff-like patch with context |
| Multi-file changes | Multiple edits | Single patch can touch many files |
| Rename/move | Separate steps | Supported in patch format |
| Learning curve | Lower | Higher |

## Installation

### Packages (`.deb` / `.rpm` / `.apk`)

From a GitHub Release, download the package matching your platform and install it:

```bash
# Debian/Ubuntu (amd64 example)
sudo dpkg -i ./agentsh_<VERSION>_linux_amd64.deb

# RHEL/Fedora (amd64 example)
sudo rpm -Uvh ./agentsh_<VERSION>_linux_amd64.rpm

# Alpine (amd64 example)
sudo apk add --allow-untrusted ./agentsh_<VERSION>_linux_amd64.apk
```

The packages install:
- Binaries: `/usr/bin/agentsh`, `/usr/bin/agentsh-shell-shim`
- Config: `/etc/agentsh/config.yaml`
- Default policy: `/etc/agentsh/default-policy.yml`

### Archives (`.tar.gz`)

If you prefer a portable install, download the `.tar.gz` archive from a GitHub Release and extract it:

```bash
tar -xzf agentsh_<VERSION>_linux_amd64.tar.gz
sudo install -m 0755 agentsh /usr/local/bin/agentsh
sudo install -m 0755 agentsh-shell-shim /usr/local/bin/agentsh-shell-shim

sudo install -d /etc/agentsh
sudo install -m 0644 config.yml /etc/agentsh/config.yaml
sudo install -m 0644 default-policy.yml /etc/agentsh/default-policy.yml
```

## Shell Shim activation (opt-in)

To enforce that anything invoking `/bin/sh -c ...` or `/bin/bash -lc ...` routes through agentsh, install the shim explicitly.

```bash
# Inspect current state
sudo agentsh shim status --root / --bash

# Install shim at /bin/sh and /bin/bash (if bash exists)
sudo agentsh shim install-shell \
  --root / \
  --shim /usr/bin/agentsh-shell-shim \
  --bash \
  --i-understand-this-modifies-the-host

# Revert back to the original shells
sudo agentsh shim uninstall-shell \
  --root / \
  --bash \
  --i-understand-this-modifies-the-host
```

Note: if you installed from a `.tar.gz` archive into `/usr/local/bin`, use `--shim /usr/local/bin/agentsh-shell-shim`.

Safety: the installer refuses `--root=/` unless you pass `--i-understand-this-modifies-the-host`.

## Quick Start

### Build + Run (local)

```bash
make build
./bin/agentsh server --config config.yml
```

### Basic Usage

```bash
# Auth
# - Local dev config may run with auth disabled (auth.type=none).
# - To enable API key auth, set auth.type=api_key and configure configs/api_keys.yaml.
# - IMPORTANT: approval endpoints require auth; with auth disabled, approvals can only be handled via local_tty (no self-approval via API).
API_KEY=sk-dev-local  # only needed when API key auth is enabled

# Create a session
curl -X POST http://localhost:8080/api/v1/sessions \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"workspace": "/home/user/project", "policy": "default"}'

# Execute a command
curl -X POST http://localhost:8080/api/v1/sessions/SESSION_ID/exec \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["-la"]}'
```

### Using the CLI

```bash
# Create session
agentsh session create --workspace /home/user/project

# Output formats
# - Default: shell-like output (stdout/stderr) + process exit code
# - JSON: structured response for agents/tools
agentsh exec --output json SESSION_ID -- python script.py
# Or set a default:
AGENTSH_OUTPUT=json agentsh exec SESSION_ID -- python script.py

# Control how many events are included in the ExecResponse JSON (smaller responses for agents)
agentsh exec --output json --events summary SESSION_ID -- curl -sS https://ifconfig.me
agentsh exec --output json --events all SESSION_ID -- curl -sS https://ifconfig.me

# When a command is blocked or fails, the JSON response includes `guidance` with retryability and optional substitutions.

# Execute commands
agentsh exec SESSION_ID -- npm install
agentsh exec SESSION_ID -- python script.py

# Soft-delete lifecycle (when sandbox.fuse.audit.mode=soft_delete)
agentsh trash list --session SESSION_ID
agentsh trash restore TOKEN --dest /workspace/restored.txt
agentsh trash purge --session SESSION_ID --ttl 7d --quota 5GB

# Convenience: if the server isn't running, `agentsh exec` will auto-start a local server (using `AGENTSH_CONFIG` or `config.yml`).
# If SESSION_ID doesn't exist yet, it will be created using the current working directory as the workspace.
# Set `AGENTSH_NO_AUTO=1` to disable both behaviors.

# Watch events in real-time
agentsh events tail SESSION_ID

# Interactive PTY (stdin/stdout streaming, resize, signals)
# Note: PTY mode merges stdout/stderr (like a real terminal).
agentsh exec --pty SESSION_ID -- sh

# Advanced: override argv[0] for the executed process (useful for shell shims and login-shell behavior)
agentsh exec --argv0 /bin/sh SESSION_ID -- /bin/sh -lc 'echo hi'
```

## Network monitoring & eBPF

agentsh can observe outbound connects and optionally enforce per-session network allowlists in the kernel (cgroup eBPF), alongside proxy/transparent modes.

Highlights
- Events: all TCP connects emit `net_connect`; blocked ones emit `net_connect_blocked`. Optional rDNS adds `rdns`.
-, when enabled, default-denies and allows only policy-derived destinations (domains → IPs, CIDRs, loopback). Wildcards stay non-strict (no default-deny).
- Map sizing at runtime: `map_*_entries` config overrides are applied once at startup—no rebuild needed.
- DNS refresh: domain allowlists refresh on a jittered interval capped by `dns_max_ttl_seconds`; cache is bounded and exposed via `/debug/ebpf`.

Config snippet:
```yaml
sandbox:
  network:
    ebpf:
      enabled: true
      enforce: true
      enforce_without_dns: false
      resolve_rdns: false
      dns_refresh_seconds: 60       # 0 disables refresh
      dns_max_ttl_seconds: 60       # cap for cached TTLs
      map_allow_entries: 2048       # allowlist map size (0 = embedded default)
      map_deny_entries: 2048        # denylist map size
      map_lpm_entries: 2048         # CIDR LPM map size
      map_lpm_deny_entries: 2048    # deny LPM map size
      map_default_entries: 1024     # default_deny map size
      # Map overrides are applied at startup (process-wide); restart to change.
```

Policy example (allow outbound to a host):
```yaml
network_rules:
  - name: allow-api
    domains: ["api.example.com"]
    ports: [443]
    decision: allow
```

Debugging:
- `GET /debug/ebpf` returns map overrides/defaults, last-populated map counts (not live occupancy), and DNS cache stats (read-only).
- Integration (Linux, root, cgroup v2): `go test -tags=integration ./internal/netmonitor/ebpf`.

### gRPC API (optional)

Enable `server.grpc.enabled` and use `proto/agentsh/v1/agentsh.proto`. The gRPC service uses `google.protobuf.Struct` so the payloads match the HTTP JSON shapes.

The CLI can prefer gRPC for `exec`, `exec --stream`, and `events tail`:

```bash
AGENTSH_TRANSPORT=grpc agentsh exec SESSION_ID -- ls -la
AGENTSH_TRANSPORT=grpc agentsh exec SESSION_ID --stream -- npm install
AGENTSH_TRANSPORT=grpc agentsh events tail SESSION_ID

# PTY exec also supports both transports:
AGENTSH_TRANSPORT=http agentsh exec --pty SESSION_ID -- sh
AGENTSH_TRANSPORT=grpc agentsh exec --pty SESSION_ID -- sh
```

Example with `grpcurl`:

```bash
# Create session
grpcurl -plaintext \
  -import-path proto -proto proto/agentsh/v1/agentsh.proto \
  -d '{"workspace":"/home/user/project","policy":"default"}' \
  127.0.0.1:9090 agentsh.v1.Agentsh/CreateSession

# Exec (note session_id is part of the request)
grpcurl -plaintext \
  -import-path proto -proto proto/agentsh/v1/agentsh.proto \
  -d '{"session_id":"session-...","command":"ls","args":["-la"],"include_events":"summary"}' \
  127.0.0.1:9090 agentsh.v1.Agentsh/Exec

# ExecStream (server-streaming stdout/stderr + done)
grpcurl -plaintext \
  -import-path proto -proto proto/agentsh/v1/agentsh.proto \
  -d '{"session_id":"session-...","command":"sh","args":["-c","echo hi"]}' \
  127.0.0.1:9090 agentsh.v1.Agentsh/ExecStream

# EventsTail (server-streaming session events)
grpcurl -plaintext \
  -import-path proto -proto proto/agentsh/v1/agentsh.proto \
  -d '{"session_id":"session-..."}' \
  127.0.0.1:9090 agentsh.v1.Agentsh/EventsTail
```

### Using with Claude Code / Codex CLI

Claude Code reads project instructions from `CLAUDE.md` (recommended). OpenAI Codex CLI reads `AGENTS.md`.

Example `CLAUDE.md` (or `AGENTS.md`) snippet to route execution through agentsh:

```md
## Shell access
- Do not run commands directly in bash/zsh.
- Execute commands via agentsh: `agentsh exec -- <command ...>`.
- If you need structured output for a tool decision, use: `agentsh exec --output json --events summary -- <command ...>`.
```

## Shell Shim (Container Compatibility)

When an agent/harness runs commands via `/bin/sh -c ...` or `/bin/bash -lc ...`, it can bypass higher-level “please use agentsh” instructions.
For container scenarios, agentsh provides a tiny shim binary (`agentsh-shell-shim`) intended to replace `/bin/sh` and `/bin/bash` and route execution through `agentsh exec`.

### Dockerfile integration

See `Dockerfile.example` for a Debian-based image that downloads a release `.deb` and activates the shim via `agentsh shim install-shell`.

### Rootfs installer (CLI)

For custom image build tooling, you can also install the shim into an arbitrary rootfs directory:

```bash
agentsh shim install-shell --root /path/to/rootfs --shim /path/to/agentsh-shell-shim --bash
agentsh shim uninstall-shell --root /path/to/rootfs --bash
```

Dry run / inspection:

```bash
agentsh shim install-shell --dry-run --output json --root /path/to/rootfs --shim /path/to/agentsh-shell-shim --bash
agentsh shim status --output json --root /path/to/rootfs --shim /path/to/agentsh-shell-shim --bash
```

Safety: `agentsh shim install-shell` and `agentsh shim uninstall-shell` refuse `--root=/` unless you pass `--i-understand-this-modifies-the-host`.

### Environment variables (shim + CLI)

- `AGENTSH_SERVER`: agentsh server base URL (default `http://127.0.0.1:8080`)
- `AGENTSH_BIN`: override the `agentsh` executable path used by the shim (otherwise resolved via `PATH`)
- `AGENTSH_GRPC_ADDR`: agentsh gRPC address (default `127.0.0.1:9090`)
- `AGENTSH_SESSION_ID`: explicit session id (best option; harness sets it)
- `AGENTSH_SESSION_FILE`: file path containing a 1-line session id (shim reads/creates)
- `AGENTSH_SESSION_SCOPE`: `workspace` (default) or `global` for file-backed fallback ids
- `AGENTSH_WORKSPACE`: optional workspace root override (used for workspace-scoped fallback)
- `AGENTSH_IN_SESSION`: reserved/internal recursion guard (set by server; shim will exec `*.real`)
- `AGENTSH_TRANSPORT`: `http` or `grpc` (affects `agentsh exec --pty` and other CLI calls)
- `AGENTSH_PTY_DENY_MODE`: if set to `error`, preserve raw errors for PTY policy/approval denies (default behavior exits `126` like non-PTY)
- `AGENTSH_SHIM_DEBUG`: if set to `1`, the shell shim prints extra debug info on fatal errors

### Session ID resolution (shim)

The shim needs a session id to call `agentsh exec`. Resolution order:

1) `AGENTSH_SESSION_ID` (exact id; no files)
2) `AGENTSH_SESSION_FILE` (read/create a 1-line file and reuse it)
3) File-backed fallback using `AGENTSH_SESSION_SCOPE`:
   - `workspace` (default): uses `AGENTSH_WORKSPACE` if set, otherwise walks up from `$PWD` to find a `.git` directory and uses that as the workspace root
   - `global`: one shared id for the whole machine/container

If all fallback directories are unwritable, the shim uses `session-default` as a last resort.

### PTY endpoints (server)

- HTTP WebSocket: `GET /api/v1/sessions/{id}/pty`
- gRPC: `proto/agentsh/v1/pty.proto` (`agentsh.v1.AgentshPTY/ExecPTY`)

## Smoke Test (Manual)

```bash
make build
./bin/agentsh server --config config.yml

PY=python; command -v python >/dev/null 2>&1 || PY=python3
SID=$(./bin/agentsh session create --workspace . | "$PY" -c 'import json,sys; print(json.load(sys.stdin)["id"])')
./bin/agentsh exec "$SID" -- sh -lc 'echo hi'
./bin/agentsh exec --pty "$SID" -- sh
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                         Agent                               │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      agentsh Server                         │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                    Session                          │    │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐   │    │
│  │  │    FUSE     │  │   Network   │  │   Policy   │   │    │
│  │  │  Workspace  │  │    Proxy    │  │   Engine   │   │    │
│  │  └─────────────┘  └─────────────┘  └────────────┘   │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

1. **Agent creates a session** with a workspace directory
2. **FUSE filesystem** intercepts all file operations
3. **Network proxy** captures all connections and DNS
4. **Policy engine** allows/denies operations based on rules
5. **Structured responses** tell agents exactly what happened

## Example Output

When an agent runs `python process_data.py` in JSON mode (`agentsh exec --output json ...`):

```json
{
  "command_id": "cmd-...",
  "session_id": "session-...",
  "request": {"command": "python", "args": ["process_data.py"]},
  "result": {"exit_code": 0, "stdout": "Processed 1000 records\n", "duration_ms": 2341},
  "events": {
    "file_operations": [{"type": "file_read", "path": "/workspace/input.csv"}],
    "network_operations": [{"type": "dns_query", "domain": "api.example.com"}, {"type": "net_connect", "remote": "api.example.com:443"}],
    "blocked_operations": []
  },
  "resources": {"memory_peak_kb": 12345}
}
```

## Policy Configuration

Control what agents can do with YAML policies:

```yaml
file_rules:
  - name: allow-workspace
    paths: ["/workspace/**"]
    operations: [read, write, create]
    decision: allow
    
  - name: approve-deletes
    paths: ["/workspace/**"]
    operations: [delete]
    decision: approve  # Requires human approval
    
  - name: block-sensitive
    paths: ["/etc/**", "**/.env", "**/secrets/**"]
    decision: deny

network_rules:
  - name: allow-package-registries
    domains: ["npmjs.org", "pypi.org", "github.com"]
    decision: allow
    
  - name: block-internal
    cidrs: ["10.0.0.0/8", "192.168.0.0/16"]
    decision: deny
```

## Documentation

- [`docs/spec.md`](docs/spec.md) — Full specification
- [`docs/project-structure.md`](docs/project-structure.md) — Repository structure and conventions
- [`docs/approval-auth.md`](docs/approval-auth.md) — Approval/auth model
- [`docs/cross-platform.md`](docs/cross-platform.md) — Cross-platform notes (Linux-first)
- [`docs/ebpf.md`](docs/ebpf.md) — eBPF tracing/enforcement details and configuration

## Requirements

- Linux 5.4+ (5.15+ recommended for best performance)
- FUSE3 support
- Go 1.25+ (for building from source)

## Building from Source

```bash
git clone https://github.com/agentsh/agentsh
cd agentsh
make build
```

## Performance

agentsh is designed for minimal overhead:

| Workload | Overhead |
|----------|----------|
| CPU-bound computation | ~2% |
| Network-heavy | 5-15% |
| I/O-heavy (large files) | 15-25% |
| Many small files | 25-40% |

Session persistence amortizes setup costs—creating a sandbox once instead of per-command reduces overhead by ~73%.

## Security

agentsh implements defense in depth:

- **FUSE** loopback mount for filesystem interception in the workspace view
- **Network monitoring/enforcement** via per-session proxy (unprivileged) and optional netns-based interception (Linux/root-only)
- **Policy engine** for operation-level control
- **Approvals** for `approve` decisions (optional; shadow-approve by default)

See [`docs/spec.md`](docs/spec.md) for details.

## Use Cases

- **AI Agent Sandboxing**: Run Claude, GPT, or other agents safely
- **CI/CD Security**: Monitor and control build scripts
- **Development Environments**: Audited execution for compliance
- **Education**: Show students exactly what commands do

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) first.

## License

Apache 2.0 - see [LICENSE](LICENSE) for details.

---

**Built for the age of AI agents** 🤖
