# Policies

This guide covers policy configuration and management for agentsh.

## Policy Variables

Policies support variable substitution using `${VAR}` syntax. Variables are expanded at session creation time, allowing policies to be portable across different projects and environments.

### Built-in Variables

| Variable | Description | Example Value |
|----------|-------------|---------------|
| `${PROJECT_ROOT}` | Auto-detected project root (nearest go.mod, package.json, Cargo.toml, etc.) | `/home/user/myproject` |
| `${GIT_ROOT}` | Nearest .git directory (may differ from PROJECT_ROOT in monorepos) | `/home/user/monorepo` |
| `${HOME}` | User's home directory (from environment) | `/home/user` |
| `${TMPDIR}` | System temp directory (from environment) | `/tmp` |

On Windows, additional variables are available:
| Variable | Description | Example Value |
|----------|-------------|---------------|
| `${USERPROFILE}` | User's profile directory | `C:\Users\user` |
| `${APPDATA}` | Application data directory | `C:\Users\user\AppData\Roaming` |
| `${LOCALAPPDATA}` | Local application data | `C:\Users\user\AppData\Local` |
| `${TEMP}` / `${TMP}` | Temp directory | `C:\Users\user\AppData\Local\Temp` |

### How Project Root Detection Works

When a session is created, agentsh walks up from the workspace directory looking for project markers. The detection follows this logic:

1. **Language markers** (go.mod, package.json, Cargo.toml, pyproject.toml) set `PROJECT_ROOT`
2. **.git directory** sets `GIT_ROOT` (and `PROJECT_ROOT` if no language marker found)
3. If no markers found, `PROJECT_ROOT` defaults to the workspace directory

**Monorepo example:**
```
/home/user/monorepo/           <- GIT_ROOT (.git here)
  ├── services/
  │   └── api/                 <- PROJECT_ROOT (go.mod here)
  │       └── cmd/             <- workspace (session started here)
  └── frontend/
      └── package.json
```

The default project markers are:
- `.git`
- `go.mod`
- `package.json`
- `Cargo.toml`
- `pyproject.toml`

### Fallback Syntax

Use `${VAR:-fallback}` to provide a default value when a variable is undefined:

```yaml
paths:
  # Use git root if available, otherwise project root
  - "${GIT_ROOT:-${PROJECT_ROOT}}/**"

  # Use TMPDIR from environment, fall back to /tmp
  - "${TMPDIR:-/tmp}/**"

  # Empty fallback (variable becomes empty string if undefined)
  - "${OPTIONAL_PATH:-}/**"
```

### Example: Using Variables in Policies

```yaml
file_rules:
  # Allow full access to project files
  - name: allow-project
    paths:
      - "${PROJECT_ROOT}/**"
    operations: ["*"]
    decision: allow

  # Read-only access to monorepo root (for shared configs)
  - name: allow-monorepo-read
    paths:
      - "${GIT_ROOT}/**"
    operations: [read, stat, list]
    decision: allow

  # Block access to credentials
  - name: deny-credentials
    paths:
      - "${HOME}/.ssh/**"
      - "${HOME}/.aws/**"
    operations: ["*"]
    decision: deny
```

## Server Configuration

### Project Root Detection Settings

In your server configuration (`server-config.yaml`):

```yaml
policies:
  dir: "/etc/agentsh/policies"
  default: "dev-safe"

  # Enable/disable automatic project root detection (default: true)
  detect_project_root: true

  # Custom project markers (optional, overrides defaults)
  project_markers:
    - ".git"
    - "go.mod"
    - "package.json"
    - "Cargo.toml"
    - "pyproject.toml"
    - "setup.py"           # Add Python setup.py
    - "pom.xml"            # Add Maven projects
    - ".agentsh-root"      # Custom marker file
```

### Disabling Detection

**Server-wide** (in config):
```yaml
policies:
  detect_project_root: false
```

**Per-session** (CLI):
```bash
# Disable detection, use workspace as PROJECT_ROOT
agentsh exec --no-detect-root SESSION -- cmd

# Explicit project root (skips detection)
agentsh exec --project-root /path/to/project SESSION -- cmd
```

**Per-session** (API):
```json
{
  "workspace": "/home/user/project/subdir",
  "detect_project_root": false,
  "project_root": "/home/user/project"
}
```

## Platform-Specific Policies

agentsh provides separate policy files for Unix/macOS and Windows:

| Policy | Unix/macOS | Windows |
|--------|-----------|---------|
| Development | `dev-safe.yaml` | `dev-safe-windows.yaml` |
| Agent Sandbox | `agent-sandbox.yaml` | `agent-sandbox-windows.yaml` |
| CI Strict | `ci-strict.yaml` | `ci-strict-windows.yaml` |
| Default | `default.yaml` | `default-windows.yaml` |
| System Read-only | `system-readonly.yaml` | (cross-platform) |

Windows policies include:
- Windows file paths (`C:\Program Files\**`, `${APPDATA}\**`)
- Windows registry rules (`HKCU\SOFTWARE\*`, etc.)
- Windows-specific commands (`dir`, `type`, `findstr`, `msbuild`)
- NuGet package registry access

## Signal Rules

Signal rules control how signals (kill, terminate, stop, etc.) can be sent between processes within an agentsh session. This provides protection against runaway processes, accidental signal delivery to critical services, and enables graceful shutdown patterns.

### Platform Support

| Platform | Blocking | Redirect | Audit |
|----------|----------|----------|-------|
| Linux | Yes (seccomp) | Yes | Yes |
| macOS | No | No | Yes (ES) |
| Windows | Partial | No | Yes (ETW) |

### Signal Specification

Signals can be specified in three ways:

| Format | Example | Description |
|--------|---------|-------------|
| Name | `SIGKILL`, `SIGTERM`, `SIGHUP` | Standard signal name |
| Number | `9`, `15`, `1` | Numeric signal value |
| Group | `@fatal`, `@job`, `@reload` | Predefined signal group |

#### Predefined Signal Groups

| Group | Signals |
|-------|---------|
| `@fatal` | SIGKILL, SIGTERM, SIGQUIT, SIGABRT |
| `@job` | SIGSTOP, SIGCONT, SIGTSTP, SIGTTIN, SIGTTOU |
| `@reload` | SIGHUP, SIGUSR1, SIGUSR2 |
| `@ignore` | SIGCHLD, SIGURG, SIGWINCH |
| `@all` | All signals (1-31) |

### Target Types

Target types define which processes can receive signals:

| Type | Description |
|------|-------------|
| `self` | Process sending to itself |
| `children` | Direct children of sender |
| `descendants` | All descendants |
| `siblings` | Processes with same parent |
| `session` | Any process in agentsh session |
| `parent` | The agentsh supervisor |
| `external` | PIDs outside session |
| `system` | PID 1 and kernel threads |
| `user` | Other processes owned by same user |
| `process` | Match by process name pattern |
| `pid_range` | Match by PID range |

### Decision Types

| Decision | Behavior |
|----------|----------|
| `allow` | Allow signal |
| `deny` | Block signal (EPERM) |
| `audit` | Allow + log |
| `approve` | Require manual approval |
| `redirect` | Change signal (e.g., SIGKILL to SIGTERM) |
| `absorb` | Silently drop (no error to sender) |

### Example Configuration

```yaml
signal_rules:
  - name: allow-self-and-children
    signals: ["@all"]
    target:
      type: self
    decision: allow

  - name: graceful-kill
    signals: ["SIGKILL"]
    target:
      type: children
    decision: redirect
    redirect_to: SIGTERM

  - name: deny-external-fatal
    signals: ["@fatal"]
    target:
      type: external
    decision: deny
    fallback: audit
    message: "Blocking signal to external process"

  - name: protect-database
    signals: ["@fatal"]
    target:
      type: process
      pattern: "postgres*"
    decision: deny
```

## Troubleshooting

### Variable Not Expanding

If a variable like `${PROJECT_ROOT}` appears literally in logs:

1. Check that the policy file uses the correct syntax (`${VAR}`, not `$VAR`)
2. Verify the variable is defined (check session creation logs)
3. For undefined variables without fallbacks, session creation will fail with an error

### Wrong Project Root Detected

If the wrong directory is detected as PROJECT_ROOT:

1. Check which marker files exist in parent directories
2. Use `--project-root` to override detection
3. Add a custom marker file (e.g., `.agentsh-root`) and configure `project_markers`

### Checking Detected Values

The detected PROJECT_ROOT and GIT_ROOT are included in session information:

```bash
# Via API
curl http://localhost:18080/api/v1/sessions/SESSION_ID | jq '.project_root, .git_root'
```
