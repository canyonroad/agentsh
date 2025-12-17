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

## Notes

- `pkg/types/` is the “schema” layer: keep it stable and versioned when changing API responses.
- Tests live next to code (`*_test.go`) in `internal/*`.

For gRPC:
- `proto/agentsh/v1/agentsh.proto` defines the service (Struct-based, no codegen required).
- `internal/api/grpc.go` implements the gRPC server (including `ExecStream` and `EventsTail`).
- `internal/client/grpc_client.go` provides a small gRPC client used by the CLI when `AGENTSH_TRANSPORT=grpc`.
