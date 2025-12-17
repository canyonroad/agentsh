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
- `internal/client/` — HTTP client used by the CLI (and tests) to call the server API.
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
- Connection tracking

### internal/policy/

Policy evaluation:
- Load and parse YAML policies
- Evaluate operations against rules
- Cache decisions for performance
- Handle approval workflows

### internal/audit/

Audit logging:
- Structured event logging
- Multiple output backends
- Rotation and retention

## Build Targets

```makefile
# Makefile

.PHONY: build test lint clean

VERSION := $(shell git describe --tags --always)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o bin/agentsh ./cmd/agentsh

test:
	go test -v -race ./...

test-integration:
	go test -v -tags=integration ./test/integration/...

lint:
	golangci-lint run

proto:
	protoc --go_out=. --go-grpc_out=. api/proto/*.proto

clean:
	rm -rf bin/

install: build
	sudo cp bin/agentsh /usr/local/bin/

docker:
	docker build -t agentsh:$(VERSION) .

release:
	goreleaser release --clean
```

## Development Workflow

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/agentsh/agentsh
cd agentsh

# Install dependencies
go mod download

# Install development tools
./scripts/setup-dev.sh

# Run tests
make test

# Build
make build

# Run locally
./bin/agentsh server --config configs/config.yaml
```

### Running Tests

```bash
# Unit tests
make test

# Integration tests (requires root for namespaces)
sudo make test-integration

# Coverage
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Code Generation

```bash
# Generate gRPC code
make proto

# Generate mocks (for testing)
go generate ./...
```

## Key Implementation Notes

### FUSE Implementation

Use `github.com/hanwen/go-fuse/v2` which supports:
- io_uring for better performance (Linux 5.15+)
- Kernel-level caching
- Async operations

```go
// Example FUSE server setup
import "github.com/hanwen/go-fuse/v2/fs"
import "github.com/hanwen/go-fuse/v2/fuse"

func mountFUSE(root, mountpoint string) (*fuse.Server, error) {
    opts := &fs.Options{
        MountOptions: fuse.MountOptions{
            AllowOther:    true,
            FsName:        "agentfs",
            MaxReadAhead:  128 * 1024,
        },
        EntryTimeout: &entryTimeout,
        AttrTimeout:  &attrTimeout,
    }
    
    server, err := fs.Mount(mountpoint, &AgentFS{root: root}, opts)
    return server, err
}
```

### Namespace Setup

```go
// Example namespace creation
import "syscall"

func createNamespace() (*exec.Cmd, error) {
    cmd := exec.Command("/bin/sh")
    cmd.SysProcAttr = &syscall.SysProcAttr{
        Cloneflags: syscall.CLONE_NEWNS |
                    syscall.CLONE_NEWNET |
                    syscall.CLONE_NEWPID |
                    syscall.CLONE_NEWUTS,
    }
    return cmd, nil
}
```

### Policy Evaluation

```go
// Fast path with caching
func (p *PolicyEngine) Check(op Operation) Decision {
    key := op.CacheKey()
    
    if decision, ok := p.cache.Get(key); ok {
        return decision
    }
    
    decision := p.evaluate(op)
    p.cache.Set(key, decision, p.cacheTTL)
    return decision
}
```

## Testing Strategy

### Unit Tests
- Policy evaluation logic
- Event parsing and formatting
- Configuration validation
- API request/response handling

### Integration Tests
- FUSE operations (requires FUSE kernel module)
- Network proxy (requires network namespace)
- Full session lifecycle
- Policy enforcement

### End-to-End Tests
- Complete workflows: create session → execute commands → verify events
- Multi-session scenarios
- Approval workflows
- Error handling and recovery

### Benchmarks
- FUSE throughput (small files, large files)
- Network proxy throughput
- Policy evaluation performance
- Session creation/teardown time
