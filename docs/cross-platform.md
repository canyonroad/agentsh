# agentsh Cross-Platform Support

**Version:** 0.1.0-draft  
**Date:** December 2024

---

## Overview

agentsh provides full security features on Linux. For Windows and macOS, we support multiple deployment strategies that ultimately run agentsh inside a Linux environment.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                      Platform Support Matrix                             │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────────────────────┐ │
│  │   Linux     │    │   Windows   │    │          macOS              │ │
│  │             │    │             │    │                             │ │
│  │  ✅ Native  │    │  • WSL2     │    │  • Tier 1: FUSE only       │ │
│  │             │    │  • Docker   │    │  • Tier 2: + sandbox-exec  │ │
│  │  Full       │    │             │    │  • Tier 3: Lima VM         │ │
│  │  Support    │    │  Full Linux │    │  • Docker container        │ │
│  │             │    │  inside     │    │                             │ │
│  └─────────────┘    └─────────────┘    └─────────────────────────────┘ │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Linux (Native) — Full Support ✅

Linux is the primary platform with full feature support.

### Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Kernel | 5.4+ | 5.15+ (io_uring support) |
| FUSE | FUSE3 | FUSE3 |
| cgroups | v2 | v2 with systemd |
| Architecture | amd64, arm64 | amd64 |

### Features

| Feature | Status |
|---------|--------|
| FUSE filesystem interception | ✅ Full |
| Network proxy interception | ✅ Full |
| Linux namespaces (mount, net, PID, UTS) | ✅ Full |
| seccomp-bpf syscall filtering | ✅ Full |
| cgroups v2 resource limits | ✅ Full |
| eBPF monitoring (optional) | ✅ Full |

### Installation

```bash
# Download binary
curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
chmod +x agentsh-linux-amd64
sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh

# Install FUSE
sudo apt-get install fuse3 libfuse3-dev  # Debian/Ubuntu
sudo dnf install fuse3 fuse3-devel        # Fedora/RHEL

# Start server
agentsh server
```

---

## 2. Windows Support

Windows does not natively support the Linux kernel primitives agentsh requires. We support two deployment strategies, both running Linux:

### Strategy A: WSL2 (Recommended)

WSL2 runs a real Linux kernel and provides near-native performance.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Windows Host                                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                        WSL2                                  │   │
│  │                   (Linux Kernel VM)                          │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │              agentsh (Full Linux)                   │    │   │
│  │  │                                                     │    │   │
│  │  │   ✅ FUSE           ✅ Namespaces                  │    │   │
│  │  │   ✅ seccomp        ✅ cgroups                     │    │   │
│  │  │   ✅ iptables       ✅ Full isolation              │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                         │                                   │   │
│  │                    Port forwarding                          │   │
│  │                   localhost:8080                            │   │
│  └─────────────────────────┼───────────────────────────────────┘   │
│                            │                                        │
│              Windows apps connect to localhost:8080                │
│              (IDE, browser, agent applications)                    │
└─────────────────────────────────────────────────────────────────────┘
```

#### WSL2 Setup

```powershell
# 1. Install WSL2 (PowerShell as Administrator)
wsl --install -d Ubuntu-24.04

# 2. Configure WSL2 resources
# Create/edit %USERPROFILE%\.wslconfig
```

```ini
# %USERPROFILE%\.wslconfig
[wsl2]
memory=8GB
processors=4
swap=2GB

[boot]
systemd=true
```

```bash
# 3. Restart WSL and enter Ubuntu
wsl --shutdown
wsl

# 4. Inside WSL2 - Install agentsh
curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
chmod +x agentsh-linux-amd64
sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh

# 5. Install dependencies
sudo apt update
sudo apt install -y fuse3 libfuse3-dev

# 6. Create workspace (use Linux filesystem, NOT /mnt/c/)
mkdir -p ~/workspaces

# 7. Start agentsh
agentsh server --http-addr 0.0.0.0:8080
```

```powershell
# 8. From Windows - verify connection
curl http://localhost:8080/health
```

#### WSL2 Performance Notes

| Aspect | Performance |
|--------|-------------|
| Linux filesystem (`/home/...`) | ~95-100% of native |
| Windows filesystem (`/mnt/c/...`) | ~10-20% of native (avoid!) |
| Network | Near-native |
| Memory overhead | ~200-500MB |

**Important**: Always keep workspaces in the Linux filesystem (`/home/user/...`), not mounted Windows paths (`/mnt/c/...`).

#### WSL2 as systemd Service

```bash
# Create systemd service inside WSL2
sudo tee /etc/systemd/system/agentsh.service << 'EOF'
[Unit]
Description=agentsh secure agent shell
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/agentsh server --config /etc/agentsh/config.yaml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable agentsh
sudo systemctl start agentsh
```

### Strategy B: Docker Container

Run agentsh inside a Docker container with Linux. Works on any system with Docker.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Windows Host                                 │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Docker Desktop                            │   │
│  │                  (WSL2 or Hyper-V backend)                   │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │           agentsh Container (Linux)                 │    │   │
│  │  │                                                     │    │   │
│  │  │   ✅ FUSE           ✅ Namespaces                  │    │   │
│  │  │   ✅ seccomp        ✅ cgroups                     │    │   │
│  │  │   ✅ Full isolation                                │    │   │
│  │  │                                                     │    │   │
│  │  │   Volume: /workspaces ◀──▶ Host directory         │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                         │                                   │   │
│  │                    -p 8080:8080                             │   │
│  └─────────────────────────┼───────────────────────────────────┘   │
│                            │                                        │
│              Windows apps connect to localhost:8080                │
└─────────────────────────────────────────────────────────────────────┘
```

#### Docker Setup

```bash
# Pull agentsh image
docker pull ghcr.io/agentsh/agentsh:latest

# Run with required capabilities
docker run -d \
  --name agentsh \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  -p 8080:8080 \
  -p 9090:9090 \
  -v C:\Users\username\workspaces:/workspaces \
  ghcr.io/agentsh/agentsh:latest
```

#### Docker Compose

```yaml
# docker-compose.yml
version: '3.8'

services:
  agentsh:
    image: ghcr.io/agentsh/agentsh:latest
    container_name: agentsh
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
    devices:
      - /dev/fuse
    security_opt:
      - apparmor=unconfined
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ./workspaces:/workspaces
      - ./config:/etc/agentsh:ro
    restart: unless-stopped
```

```bash
# Start with docker-compose
docker-compose up -d

# View logs
docker-compose logs -f agentsh
```

### Windows: Recommendation

| Use Case | Recommendation |
|----------|---------------|
| Development | WSL2 (best performance, native feel) |
| CI/CD | Docker container |
| Team standardization | Docker container |
| Maximum performance | WSL2 with Linux filesystem |

---

## 3. macOS Support

macOS requires a tiered approach due to lack of Linux kernel primitives.

### Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         macOS Platform Support                           │
│                                                                         │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │                    Security Tier Selection                       │   │
│  │                                                                  │   │
│  │    Agent Request ──▶ Risk Assessment ──▶ Select Tier            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│         ┌──────────────┬───────────────┬───────────────┬────────────┐  │
│         ▼              ▼               ▼               ▼            │  │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐ ┌─────────────────┐  │  │
│  │  Tier 1    │ │  Tier 2    │ │  Tier 3    │ │    Tier 4       │  │  │
│  │  FUSE Only │ │  +Sandbox  │ │  Lima VM   │ │    Docker       │  │  │
│  │            │ │            │ │            │ │                 │  │  │
│  │ Monitoring │ │ + Basic    │ │ Full Linux │ │  Full Linux     │  │  │
│  │ only       │ │ isolation  │ │ isolation  │ │  isolation      │  │  │
│  │            │ │            │ │            │ │                 │  │  │
│  │ Fast ⚡    │ │ Medium     │ │ Secure 🔒  │ │  Secure 🔒      │  │  │
│  └────────────┘ └────────────┘ └────────────┘ └─────────────────┘  │  │
│                                                                         │
│  Overhead:  ~5%        ~10%         ~15-20%        ~15-20%            │
│  Security:  Low        Medium       High           High                │
│  Isolation: None       Partial      Full           Full                │
└─────────────────────────────────────────────────────────────────────────┘
```

### Tier 1: FUSE Only (Monitoring)

Provides file and network monitoring without process isolation.

**Use for**: Development, testing, trusted code

```
┌─────────────────────────────────────────────────────────────┐
│                  Tier 1: FUSE Only                           │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              macFUSE Workspace                       │   │
│  │                                                      │   │
│  │  ✅ File I/O monitoring                             │   │
│  │  ✅ Policy-based allow/deny                         │   │
│  │  ✅ Structured output                               │   │
│  │  ❌ No process isolation                            │   │
│  │  ❌ No resource limits                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              Network Proxy (pf)                      │   │
│  │                                                      │   │
│  │  ✅ Network monitoring                              │   │
│  │  ✅ DNS interception                                │   │
│  │  ⚠️ Basic filtering only                           │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  Requirements: macFUSE (https://osxfuse.github.io)         │
└─────────────────────────────────────────────────────────────┘
```

**Setup**:
```bash
# Install macFUSE (requires reboot, reduced security on Apple Silicon)
brew install --cask macfuse

# Install agentsh
brew install agentsh

# Start with tier 1
agentsh server --security-tier fast
```

### Tier 2: FUSE + sandbox-exec (Basic Isolation)

Adds Apple's sandbox-exec for basic process restrictions.

**Use for**: Normal agent operations, moderate trust

```
┌─────────────────────────────────────────────────────────────┐
│               Tier 2: FUSE + sandbox-exec                    │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 sandbox-exec                         │   │
│  │                                                      │   │
│  │  ✅ File path restrictions (enforced)               │   │
│  │  ✅ Network restrictions (basic)                    │   │
│  │  ⚠️ Deprecated by Apple                            │   │
│  │  ❌ No resource limits                              │   │
│  └─────────────────────────────────────────────────────┘   │
│                         +                                   │
│  ┌─────────────────────────────────────────────────────┐   │
│  │              FUSE + Network Proxy                    │   │
│  │              (same as Tier 1)                        │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Setup**:
```bash
# Start with tier 2 (default on macOS)
agentsh server --security-tier medium
```

**Sandbox Profile** (`/etc/agentsh/macos-sandbox.sb`):
```scheme
(version 1)
(deny default)

;; Allow basic process operations
(allow process-fork)
(allow process-exec)
(allow signal (target self))

;; System libraries (read-only)
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/Library/Frameworks")
    (subpath "/System/Library"))

;; Workspace only
(allow file-read* file-write*
    (subpath "/Users/*/agent-workspaces"))

;; Temp directory
(allow file-read* file-write*
    (subpath "/tmp/agentsh"))

;; Network - HTTPS/HTTP only
(allow network-outbound
    (remote tcp "*:443")
    (remote tcp "*:80"))

;; Block sensitive paths
(deny file-read* file-write*
    (subpath (string-append (param "HOME") "/.ssh"))
    (subpath (string-append (param "HOME") "/.aws"))
    (subpath (string-append (param "HOME") "/.gnupg")))
```

### Tier 3: Lima VM (Full Linux Isolation)

Run agentsh inside a lightweight Linux VM using Apple's Virtualization.framework.

**Use for**: Production, untrusted code, high security requirements

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tier 3: Lima VM                                   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │              Lima (Virtualization.framework)                 │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │              Linux VM (Ubuntu/Alpine)               │    │   │
│  │  │                                                     │    │   │
│  │  │     agentsh with FULL Linux features:              │    │   │
│  │  │                                                     │    │   │
│  │  │     ✅ FUSE filesystem                             │    │   │
│  │  │     ✅ Linux namespaces                            │    │   │
│  │  │     ✅ seccomp-bpf                                 │    │   │
│  │  │     ✅ cgroups v2                                  │    │   │
│  │  │     ✅ Full network isolation                      │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                         │                                   │   │
│  │                    virtio-fs                                │   │
│  │              (fast shared folders)                          │   │
│  │                         │                                   │   │
│  └─────────────────────────┼───────────────────────────────────┘   │
│                            │                                        │
│               ~/agent-workspaces (shared with VM)                  │
│                                                                     │
│  Overhead: ~15-20% | Startup: ~2-5 seconds                        │
└─────────────────────────────────────────────────────────────────────┘
```

**Setup**:
```bash
# Install Lima
brew install lima

# Create agentsh VM (first time)
agentsh setup-lima

# Or manually:
limactl create --name=agentsh template://ubuntu-lts
limactl start agentsh

# Start agentsh with Lima backend
agentsh server --security-tier secure
```

**Lima Configuration** (`~/.lima/agentsh/lima.yaml`):
```yaml
vmType: "vz"                    # Apple Virtualization.framework
os: "Linux"
arch: "default"

cpus: 4
memory: "4GiB"
disk: "20GiB"

images:
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64.img"
    arch: "aarch64"
  - location: "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
    arch: "x86_64"

mounts:
  - location: "~/agent-workspaces"
    mountPoint: "/workspaces"
    writable: true
    virtiofs: true

portForwards:
  - guestPort: 8080
    hostPort: 8080
  - guestPort: 9090
    hostPort: 9090

provision:
  - mode: system
    script: |
      #!/bin/bash
      apt-get update
      apt-get install -y fuse3 libfuse3-dev
      curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-$(uname -m)
      chmod +x agentsh-linux-*
      mv agentsh-linux-* /usr/local/bin/agentsh
      
      # Create systemd service
      cat > /etc/systemd/system/agentsh.service << 'EOF'
      [Unit]
      Description=agentsh
      After=network.target
      [Service]
      Type=simple
      ExecStart=/usr/local/bin/agentsh server
      Restart=always
      [Install]
      WantedBy=multi-user.target
      EOF
      
      systemctl daemon-reload
      systemctl enable --now agentsh
```

### Tier 4: Docker Container (Full Linux Isolation)

Run agentsh inside a Docker container. Works regardless of how Docker runs on macOS.

**Use for**: CI/CD, team standardization, consistent environments

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Tier 4: Docker Container                          │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │         Docker Desktop / Colima / OrbStack                   │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │           agentsh Container (Linux)                 │    │   │
│  │  │                                                     │    │   │
│  │  │     ✅ FUSE filesystem                             │    │   │
│  │  │     ✅ Linux namespaces                            │    │   │
│  │  │     ✅ seccomp-bpf                                 │    │   │
│  │  │     ✅ cgroups                                     │    │   │
│  │  │     ✅ Full network isolation                      │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                         │                                   │   │
│  │              Volume mount: /workspaces                      │   │
│  └─────────────────────────┼───────────────────────────────────┘   │
│                            │                                        │
│               ~/agent-workspaces (mounted into container)          │
└─────────────────────────────────────────────────────────────────────┘
```

**Setup**:
```bash
# Using Docker Desktop, Colima, or OrbStack
docker run -d \
  --name agentsh \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  -p 8080:8080 \
  -v ~/agent-workspaces:/workspaces \
  ghcr.io/agentsh/agentsh:latest
```

**Docker Compose**:
```yaml
# docker-compose.yml
version: '3.8'

services:
  agentsh:
    image: ghcr.io/agentsh/agentsh:latest
    cap_add:
      - SYS_ADMIN
      - NET_ADMIN
    devices:
      - /dev/fuse
    security_opt:
      - apparmor=unconfined
    ports:
      - "8080:8080"
      - "9090:9090"
    volumes:
      - ~/agent-workspaces:/workspaces
      - ./config:/etc/agentsh:ro
    restart: unless-stopped
```

### macOS Tier Selection

```yaml
# ~/.agentsh/config.yaml

platform:
  # Auto-select tier based on session requirements
  auto_tier: true
  
  # Default tier when auto-select not possible
  default_tier: "medium"
  
  # Tier escalation rules
  escalation:
    # Always use secure tier for these conditions
    force_secure:
      - untrusted_code: true
      - require_isolation: true
      - production: true
      
    # Use medium tier for these
    force_medium:
      - network_enabled: true
      - file_write_enabled: true
      
  # Tier-specific settings
  tiers:
    fast:
      description: "FUSE only - monitoring without isolation"
      requires: ["macfuse"]
      
    medium:
      description: "FUSE + sandbox-exec - basic isolation"
      requires: ["macfuse"]
      sandbox_profile: "/etc/agentsh/macos-sandbox.sb"
      
    secure:
      description: "Lima VM - full Linux isolation"
      requires: ["lima"]
      vm_name: "agentsh"
      auto_start_vm: true
      
    docker:
      description: "Docker container - full Linux isolation"
      requires: ["docker"]
      image: "ghcr.io/agentsh/agentsh:latest"
```

### macOS CLI Usage

```bash
# Install agentsh
brew install agentsh

# First-time setup (installs dependencies, creates Lima VM)
agentsh setup
  ✓ macFUSE installed
  ✓ Lima installed
  ✓ Lima VM 'agentsh' created
  ✓ Docker available
  Ready!

# Start server with auto tier selection
agentsh server

# Start with specific tier
agentsh server --security-tier fast    # Tier 1: FUSE only
agentsh server --security-tier medium  # Tier 2: + sandbox-exec
agentsh server --security-tier secure  # Tier 3: Lima VM
agentsh server --security-tier docker  # Tier 4: Docker container

# Create session with specific security
agentsh session create \
  --workspace ~/projects/my-app \
  --security-tier secure

# Auto-escalate based on flags
agentsh session create \
  --workspace ~/projects/my-app \
  --untrusted-code \
  --allow-network
  # Auto-selects: secure tier
```

### macOS: Recommendation Matrix

| Use Case | Recommended Tier | Reason |
|----------|-----------------|--------|
| Local development, trusted code | Tier 1 (FUSE) | Fast, low overhead |
| Normal agent operations | Tier 2 (sandbox) | Balance of security/speed |
| Untrusted code execution | Tier 3 (Lima) or 4 (Docker) | Full isolation |
| CI/CD pipelines | Tier 4 (Docker) | Reproducible, standard |
| Team standardization | Tier 4 (Docker) | Same environment everywhere |
| Production workloads | Tier 3 or 4 | Full security |

---

## 4. Container-Based Development (Any Platform)

When developing inside a container (VS Code Dev Containers, GitHub Codespaces, GitPod, etc.), run agentsh inside the container for full Linux support regardless of host OS.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Container-Based Development                       │
│                                                                     │
│  Host: Windows, macOS, or Linux                                    │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                Development Container                         │   │
│  │                    (Linux)                                   │   │
│  │                                                              │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │              Your Development Environment           │    │   │
│  │  │                                                     │    │   │
│  │  │   • VS Code Server / IDE                           │    │   │
│  │  │   • Your code                                      │    │   │
│  │  │   • Build tools                                    │    │   │
│  │  │                                                     │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  │                         │                                   │   │
│  │                         ▼                                   │   │
│  │  ┌────────────────────────────────────────────────────┐    │   │
│  │  │                    agentsh                          │    │   │
│  │  │                                                     │    │   │
│  │  │   ✅ Full Linux support                            │    │   │
│  │  │   ✅ All security features                         │    │   │
│  │  │   ✅ Same behavior as native Linux                 │    │   │
│  │  └────────────────────────────────────────────────────┘    │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

### VS Code Dev Container

`.devcontainer/devcontainer.json`:
```json
{
  "name": "Development with agentsh",
  "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
  
  "features": {
    "ghcr.io/agentsh/devcontainer-features/agentsh:1": {}
  },
  
  "capAdd": ["SYS_ADMIN", "NET_ADMIN"],
  "securityOpt": ["apparmor=unconfined"],
  "mounts": [
    "type=bind,source=/dev/fuse,target=/dev/fuse"
  ],
  
  "forwardPorts": [8080],
  
  "postStartCommand": "agentsh server --background"
}
```

### Docker Development Container

`Dockerfile.dev`:
```dockerfile
FROM ubuntu:24.04

# Install development tools
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    curl \
    fuse3 \
    libfuse3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install agentsh
RUN curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64 \
    && chmod +x agentsh-linux-amd64 \
    && mv agentsh-linux-amd64 /usr/local/bin/agentsh

# Your development setup...
WORKDIR /workspace

# Start agentsh on container start
CMD ["agentsh", "server"]
```

```bash
# Run development container with agentsh
docker build -f Dockerfile.dev -t mydev .
docker run -it \
  --cap-add SYS_ADMIN \
  --cap-add NET_ADMIN \
  --device /dev/fuse \
  --security-opt apparmor=unconfined \
  -p 8080:8080 \
  -v $(pwd):/workspace \
  mydev
```

### GitHub Codespaces / GitPod

For cloud development environments, include agentsh in your container definition:

`.gitpod.yml`:
```yaml
image:
  file: .gitpod.Dockerfile

tasks:
  - name: Start agentsh
    init: |
      curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
      chmod +x agentsh-linux-amd64
      sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh
    command: agentsh server --background

ports:
  - port: 8080
    onOpen: ignore
```

---

## 5. Platform Feature Matrix

| Feature | Linux | Windows WSL2 | Windows Docker | macOS Tier 1 | macOS Tier 2 | macOS Tier 3/4 |
|---------|-------|--------------|----------------|--------------|--------------|----------------|
| FUSE interception | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Network interception | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Namespace isolation | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| seccomp filtering | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| cgroups limits | ✅ | ✅ | ✅ | ❌ | ❌ | ✅ |
| File path enforcement | ✅ | ✅ | ✅ | Policy | ✅ | ✅ |
| Process isolation | ✅ | ✅ | ✅ | ❌ | ⚠️ | ✅ |
| Performance | 100% | ~95% | ~90% | ~95% | ~90% | ~80-85% |

---

## 6. Quick Start by Platform

### Linux
```bash
curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
chmod +x agentsh-linux-amd64
sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh
agentsh server
```

### Windows (WSL2)
```powershell
wsl --install -d Ubuntu-24.04
```
```bash
# Inside WSL2
curl -LO https://github.com/agentsh/agentsh/releases/latest/download/agentsh-linux-amd64
chmod +x agentsh-linux-amd64 && sudo mv agentsh-linux-amd64 /usr/local/bin/agentsh
agentsh server
```

### Windows (Docker)
```powershell
docker run -d --name agentsh --cap-add SYS_ADMIN --cap-add NET_ADMIN `
  --device /dev/fuse --security-opt apparmor=unconfined `
  -p 8080:8080 -v ${PWD}/workspaces:/workspaces `
  ghcr.io/agentsh/agentsh:latest
```

### macOS
```bash
brew install agentsh
agentsh setup    # Sets up Lima VM for secure tier
agentsh server   # Auto-selects appropriate tier
```

### macOS (Docker)
```bash
docker run -d --name agentsh --cap-add SYS_ADMIN --cap-add NET_ADMIN \
  --device /dev/fuse --security-opt apparmor=unconfined \
  -p 8080:8080 -v ~/workspaces:/workspaces \
  ghcr.io/agentsh/agentsh:latest
```

---

## 7. Troubleshooting

### Windows WSL2

| Issue | Solution |
|-------|----------|
| WSL2 not starting | `wsl --update` then `wsl --shutdown` |
| Slow file I/O | Move files to Linux FS (`/home/...`), not `/mnt/c/` |
| Port not accessible | Check Windows Firewall, try `netsh interface portproxy` |
| cgroups not working | Enable systemd in `/etc/wsl.conf` |

### macOS

| Issue | Solution |
|-------|----------|
| macFUSE not loading | Reboot, enable kernel extension in Security settings |
| Lima VM won't start | `limactl delete agentsh && limactl create agentsh` |
| Docker permission error | Add `--privileged` or specific capabilities |
| sandbox-exec failing | Check profile syntax, may need path adjustments |

### Docker (All Platforms)

| Issue | Solution |
|-------|----------|
| FUSE not working | Ensure `--device /dev/fuse` and `--cap-add SYS_ADMIN` |
| Network isolation failing | Add `--cap-add NET_ADMIN` |
| AppArmor blocking | Add `--security-opt apparmor=unconfined` |
| SELinux blocking | Add `--security-opt label=disable` |
