# agentsh Project Structure

This document outlines the recommended project structure for implementing agentsh.

## Directory Layout

```
agentsh/
├── cmd/
│   └── agentsh/
│       └── main.go                 # CLI entrypoint
│
├── internal/
│   ├── api/
│   │   ├── server.go               # HTTP/gRPC server setup
│   │   ├── handlers.go             # Request handlers
│   │   ├── middleware.go           # Auth, logging middleware
│   │   └── sse.go                  # Server-sent events for streaming
│   │
│   ├── session/
│   │   ├── manager.go              # Session lifecycle management
│   │   ├── session.go              # Session state and operations
│   │   └── cleanup.go              # Idle timeout, resource cleanup
│   │
│   ├── sandbox/
│   │   ├── sandbox.go              # Sandbox orchestration
│   │   ├── namespace.go            # Linux namespace setup
│   │   ├── cgroups.go              # Resource limits via cgroups v2
│   │   ├── seccomp.go              # Syscall filtering
│   │   ├── executor.go             # Command execution
│   │   └── shell.go                # Builtin commands (cd, export, etc.)
│   │
│   ├── fsmonitor/
│   │   ├── fuse.go                 # FUSE filesystem implementation
│   │   ├── dir.go                  # Directory operations
│   │   ├── file.go                 # File operations
│   │   ├── handle.go               # File handle management
│   │   └── symlink.go              # Symlink handling
│   │
│   ├── netmonitor/
│   │   ├── proxy.go                # Transparent TCP proxy
│   │   ├── dns.go                  # DNS interception
│   │   ├── iptables.go             # iptables rule management
│   │   └── tls.go                  # TLS inspection (optional)
│   │
│   ├── policy/
│   │   ├── engine.go               # Policy evaluation engine
│   │   ├── rules.go                # Rule types and matching
│   │   ├── parser.go               # YAML policy parsing
│   │   ├── cache.go                # Decision caching
│   │   └── approval.go             # Approval workflow handling
│   │
│   ├── audit/
│   │   ├── logger.go               # Audit log writer
│   │   ├── events.go               # Event formatting
│   │   └── storage.go              # Log storage backends
│   │
│   └── config/
│       ├── config.go               # Configuration loading
│       ├── defaults.go             # Default values
│       └── validate.go             # Config validation
│
├── pkg/
│   ├── types/
│   │   ├── session.go              # Session types
│   │   ├── events.go               # Event types
│   │   ├── policy.go               # Policy types
│   │   └── api.go                  # API request/response types
│   │
│   └── client/
│       ├── client.go               # Go client library
│       ├── session.go              # Session operations
│       └── exec.go                 # Command execution
│
├── api/
│   └── proto/
│       └── agentsh.proto           # gRPC service definitions
│
├── configs/
│   ├── config.yaml                 # Default server config
│   └── policies/
│       ├── default.yaml            # Default policy
│       ├── strict.yaml             # Strict security policy
│       └── permissive.yaml         # Permissive policy
│
├── scripts/
│   ├── install.sh                  # Installation script
│   ├── setup-dev.sh                # Development environment setup
│   └── benchmark.sh                # Performance benchmarking
│
├── docs/
│   ├── api.md                      # API documentation
│   ├── policies.md                 # Policy writing guide
│   ├── deployment.md               # Deployment guide
│   └── security.md                 # Security considerations
│
├── test/
│   ├── integration/                # Integration tests
│   ├── e2e/                        # End-to-end tests
│   └── fixtures/                   # Test fixtures
│
├── Makefile
├── go.mod
├── go.sum
├── README.md
├── SPEC.md                         # Full specification
├── LICENSE
└── CONTRIBUTING.md
```

## Package Dependencies

### Core Dependencies

```go
// go.mod
module github.com/agentsh/agentsh

go 1.25

require (
    // FUSE
    github.com/hanwen/go-fuse/v2 v2.4.0
    
    // gRPC
    google.golang.org/grpc v1.59.0
    google.golang.org/protobuf v1.31.0
    
    // HTTP
    github.com/go-chi/chi/v5 v5.0.10
    
    // Configuration
    gopkg.in/yaml.v3 v3.0.1
    
    // Logging
    go.uber.org/zap v1.26.0
    
    // seccomp
    github.com/seccomp/libseccomp-golang v0.10.0
    
    // Glob matching
    github.com/gobwas/glob v0.2.3
    
    // CLI
    github.com/spf13/cobra v1.8.0
    
    // Testing
    github.com/stretchr/testify v1.8.4
)
```

## Component Responsibilities

### cmd/agentsh/main.go

Entry point that sets up:
- CLI command parsing (cobra)
- Configuration loading
- Server initialization
- Signal handling for graceful shutdown

### internal/api/

HTTP and gRPC server implementation:
- RESTful endpoints for sessions, exec, events
- gRPC service for high-performance clients
- Server-sent events for real-time streaming
- Authentication middleware

### internal/session/

Session lifecycle management:
- Create/destroy sessions
- Track session state and metrics
- Handle idle timeout and cleanup
- Maintain session registry

### internal/sandbox/

Isolated execution environment:
- Linux namespace creation (mount, net, PID, UTS)
- cgroups v2 resource limits
- seccomp-bpf syscall filtering
- Command execution with I/O capture
- Shell builtin handling

### internal/fsmonitor/

FUSE filesystem implementation:
- Intercept all file operations
- Policy check on each operation
- Event emission for audit
- Passthrough to real filesystem

### internal/netmonitor/

Network interception:
- Transparent TCP proxy
- DNS query interception
- iptables rule management
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
