# agentsh

**A secure shell environment for AI agents**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/go-%3E%3D1.25-blue.svg)](https://golang.org/)

---

## Overview

agentsh is a purpose-built shell environment that provides AI agents with secure, monitored, and policy-controlled command execution. Unlike traditional shells designed for humans, agentsh treats every operation as an auditable event with structured output.

### Key Features

- **🔒 Complete I/O Visibility**: Intercepts all file reads, writes, and deletes—even within scripts
- **🌐 Network Monitoring**: Captures all network connections and DNS queries
- **📋 Policy Enforcement**: Fine-grained control over what agents can do
- **📊 Structured Output**: JSON responses that agents can actually parse
- **⚡ Session Persistence**: Keep sandboxes alive across commands for efficiency
- **✅ Approval Workflows**: Human-in-the-loop for sensitive operations

### Why agentsh?

| Traditional Shell | agentsh |
|------------------|---------|
| `rm -rf /` just runs | Policy blocks dangerous operations |
| `python script.py` is a black box | See every file and network operation inside |
| Error: "Permission denied" | Error with context, suggestions, and alternatives |
| No visibility into what happened | Complete audit trail of all operations |

## Quick Start

### Installation

```bash
# Download latest release
curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
chmod +x agentsh-linux-amd64
sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh

# Start server
agentsh server
```

### Basic Usage

```bash
# Create a session
curl -X POST http://localhost:8080/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"workspace": "/home/user/project", "policy": "default"}'

# Execute a command
curl -X POST http://localhost:8080/api/v1/sessions/SESSION_ID/exec \
  -H "Content-Type: application/json" \
  -d '{"command": "ls", "args": ["-la"]}'
```

### Using the CLI

```bash
# Create session
agentsh session create --workspace /home/user/project

# Execute commands
agentsh exec SESSION_ID -- npm install
agentsh exec SESSION_ID -- python script.py

# Watch events in real-time
agentsh events SESSION_ID
```

## How It Works

```
┌─────────────────────────────────────────────────────────────┐
│                         Agent                                │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                      agentsh Server                          │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                    Session                           │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌────────────┐  │   │
│  │  │    FUSE     │  │   Network   │  │   Policy   │  │   │
│  │  │  Workspace  │  │    Proxy    │  │   Engine   │  │   │
│  │  └─────────────┘  └─────────────┘  └────────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

1. **Agent creates a session** with a workspace directory
2. **FUSE filesystem** intercepts all file operations
3. **Network proxy** captures all connections and DNS
4. **Policy engine** allows/denies operations based on rules
5. **Structured responses** tell agents exactly what happened

## Example Output

When an agent runs `python process_data.py`:

```json
{
  "exit_code": 0,
  "stdout": "Processed 1000 records",
  "duration_ms": 2341,
  "events": {
    "file_operations": [
      {"type": "file_read", "path": "/workspace/input.csv", "bytes": 45000},
      {"type": "file_write", "path": "/workspace/output.json", "bytes": 62000}
    ],
    "network_operations": [
      {"type": "dns_query", "domain": "api.example.com"},
      {"type": "net_connect", "remote": "93.184.216.34:443", "bytes_sent": 1024}
    ],
    "blocked_operations": [
      {"type": "file_read", "path": "/etc/passwd", "decision": "deny"}
    ]
  }
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

- **[Full Specification](SPEC.md)** - Complete technical specification
- **[API Reference](docs/api.md)** - REST and gRPC API documentation
- **[Policy Guide](docs/policies.md)** - How to write policies
- **[Deployment Guide](docs/deployment.md)** - Production deployment

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

- **Linux namespaces** for process isolation
- **FUSE** for filesystem interception
- **seccomp-bpf** for syscall filtering
- **cgroups v2** for resource limits
- **Policy engine** for operation-level control

See the [Security Model](SPEC.md#13-security-model) in the specification for details.

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
