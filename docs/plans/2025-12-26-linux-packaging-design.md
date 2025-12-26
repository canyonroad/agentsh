# Linux Package Managers Design

## Overview

Add Linux packaging for deb (Debian/Ubuntu), rpm (Fedora/RHEL), and Arch Linux using nFPM for simplified cross-format builds. CI builds packages on release tags.

## Package Contents

**Binaries:**
- `/usr/bin/agentsh` - Main CLI
- `/usr/bin/agentsh-shell-shim` - Shell shim

**Configuration:**
- `/etc/agentsh/config.yaml` - Default config (noreplace on upgrade)

**Shell Completions:**
- `/usr/share/bash-completion/completions/agentsh`
- `/usr/share/zsh/site-functions/_agentsh`
- `/usr/share/fish/vendor_completions.d/agentsh.fish`

**Documentation:**
- `/usr/share/doc/agentsh/README.md`
- `/usr/share/doc/agentsh/LICENSE`

## Directory Structure

```
packaging/
├── nfpm.yaml              # Single config for all formats
├── config.yaml            # Default config file
└── completions/
    ├── agentsh.bash
    ├── agentsh.zsh
    └── agentsh.fish
```

## nFPM Configuration

Single `packaging/nfpm.yaml` generates deb, rpm, and archlinux packages.

Key features:
- Version from environment variable (set by CI)
- Config file marked as `config|noreplace`
- Supports amd64 and arm64 architectures

## Build Process

**Local:**
```bash
make package-deb
make package-rpm
make package-arch
make package-all
```

**CI (GitHub Actions):**
- Triggers on `v*` tags
- Matrix: amd64, arm64
- Builds all three formats
- Uploads to GitHub Releases with SHA256SUMS

## Files to Create

1. `packaging/nfpm.yaml` - nFPM config
2. `packaging/config.yaml` - Default configuration
3. `packaging/completions/agentsh.bash` - Bash completion
4. `packaging/completions/agentsh.zsh` - Zsh completion
5. `packaging/completions/agentsh.fish` - Fish completion
6. `.github/workflows/release.yml` - Release workflow
7. Update `Makefile` - Add package targets

## Decisions

- Use nFPM instead of native tools (simpler, single config)
- Config at `/etc/agentsh/` (matches existing code)
- No systemd service (shell shim auto-starts server)
- Build both via CI and locally
