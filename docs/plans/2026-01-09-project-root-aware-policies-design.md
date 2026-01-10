# Project-Root Aware Policies Design

## Overview

Policies can reference dynamic paths using variable substitution. Variables are expanded when a session is created, before the policy engine compiles glob patterns. This allows generic policies that work across different projects without hardcoding paths.

## Problem Statement

Current policies use hardcoded paths like `/workspace/**` which:
- Can confuse AI agents when virtual paths differ from real paths
- Require per-project policy customization
- Don't adapt to monorepo structures

## Solution

Introduce variable substitution in policy files with automatic project root detection.

## Variables

### Built-in Variables

| Variable | Source | Description |
|----------|--------|-------------|
| `${PROJECT_ROOT}` | Detection | Nearest project marker (go.mod, package.json, etc.) or CWD |
| `${GIT_ROOT}` | Detection | Nearest `.git` directory, or undefined |
| `${*}` | Environment | Any other variable falls through to `os.Getenv()` |

### Variable Syntax (bash-like)

```yaml
# Required - fails if undefined
paths: ["${GIT_ROOT}/**"]

# With fallback - uses /workspace if GIT_ROOT undefined
paths: ["${GIT_ROOT:-/workspace}/**"]

# Empty fallback - becomes empty string if undefined
paths: ["${GIT_ROOT:-}/**"]
```

## Project Detection

### Algorithm

When a session is created with a workspace path:

1. Walk up from workspace looking for markers
2. Record first language marker found → `PROJECT_ROOT`
3. Record first `.git` found → `GIT_ROOT`
4. If no markers found, `PROJECT_ROOT` = workspace (CWD)

### Project Markers

| Marker | Type |
|--------|------|
| `.git` | Git repository (sets GIT_ROOT) |
| `go.mod` | Go module |
| `package.json` | Node.js |
| `Cargo.toml` | Rust |
| `pyproject.toml` | Python |

### Example Detection

```
/home/eran/work/monorepo/                    <- .git found -> GIT_ROOT
/home/eran/work/monorepo/services/
/home/eran/work/monorepo/services/api/       <- go.mod found -> PROJECT_ROOT
/home/eran/work/monorepo/services/api/cmd/   <- workspace (CWD)

Result:
  PROJECT_ROOT = /home/eran/work/monorepo/services/api
  GIT_ROOT     = /home/eran/work/monorepo
```

### Non-Project Directory

```
/tmp/scratch/  <- workspace, no markers above

Result:
  PROJECT_ROOT = /tmp/scratch
  GIT_ROOT     = <undefined>
```

## Configuration

### Server Config (`config.yaml`)

```yaml
policies:
  dir: "./configs/policies"
  default: "dev-safe"

  # Project detection settings
  detect_project_root: true          # Enable smart detection (default: true)
  project_markers:                   # Optional: override default markers
    - ".git"
    - "go.mod"
    - "package.json"
    - "Cargo.toml"
    - "pyproject.toml"
```

### Session Creation Request

```json
POST /api/v1/sessions
{
  "workspace": "/home/eran/work/agentsh",
  "policy": "dev-safe",
  "detect_project_root": false
}
```

### CLI Flags

```bash
# Use smart detection (default)
agentsh exec my-session -- ls

# Disable detection, use workspace as-is
agentsh exec --no-detect-root my-session -- ls

# Explicit project root (skips detection)
agentsh exec --project-root /custom/path my-session -- ls
```

### Precedence

1. Explicit `--project-root` flag -> use that path, skip detection
2. `--no-detect-root` flag -> use workspace as-is
3. Session request `detect_project_root: false` -> use workspace as-is
4. Server config `detect_project_root: false` -> use workspace as-is
5. Otherwise -> run detection algorithm

## Policy File Example

Updated `dev-safe.yaml`:

```yaml
version: 1
name: dev-safe
description: Safe policy for local development using project-root variables.

file_rules:
  # Project workspace - full read access
  - name: allow-project-read
    paths:
      - "${PROJECT_ROOT}"
      - "${PROJECT_ROOT}/**"
    operations: [read, open, stat, list, readlink]
    decision: allow

  # Project workspace - write with delete approval
  - name: allow-project-write
    paths:
      - "${PROJECT_ROOT}/**"
    operations: [write, create, mkdir, chmod, rename]
    decision: allow

  - name: approve-project-delete
    paths:
      - "${PROJECT_ROOT}/**"
    operations: [delete, rmdir]
    decision: approve
    message: "Delete {{.Path}}?"

  # Git root (for monorepos) - read-only access to sibling projects
  - name: allow-git-root-read
    paths:
      - "${GIT_ROOT:-}/**"
    operations: [read, open, stat, list]
    decision: allow

  # Home directory configs - read only
  - name: allow-home-configs
    paths:
      - "${HOME}/.gitconfig"
      - "${HOME}/.npmrc"
      - "${HOME}/.config/**"
    operations: [read, open, stat]
    decision: allow

  # Temp directories - full access
  - name: allow-tmp
    paths:
      - "/tmp/**"
      - "${TMPDIR:-/tmp}/**"
    operations: ["*"]
    decision: allow

  # Credentials - always blocked
  - name: deny-ssh-keys
    paths:
      - "${HOME}/.ssh/**"
    operations: ["*"]
    decision: deny

  # Default deny
  - name: default-deny
    paths: ["**"]
    operations: ["*"]
    decision: deny
```

## Implementation

### New Files

| File | Purpose |
|------|---------|
| `internal/policy/vars.go` | Variable expansion logic, bash-like syntax parser |
| `internal/policy/detect.go` | Project root detection, walk-up algorithm |

### Modified Files

| File | Changes |
|------|---------|
| `internal/config/config.go` | Add `DetectProjectRoot` and `ProjectMarkers` to `PoliciesConfig` |
| `internal/policy/engine.go` | Call `ExpandVariables()` before compiling globs |
| `internal/api/core.go` | Detect roots, pass to engine, store in session |
| `internal/session/manager.go` | Add `ProjectRoot`, `GitRoot` fields to `Session` struct |
| `pkg/types/sessions.go` | Add `DetectProjectRoot` to `CreateSessionRequest` |
| `internal/cli/exec.go` | Add `--no-detect-root` and `--project-root` flags |

### Data Flow

```
1. Client: POST /sessions {workspace: "/home/eran/work/agentsh/cmd"}
                              |
2. Server: detectProjectRoots(workspace)
           -> PROJECT_ROOT = /home/eran/work/agentsh (found go.mod)
           -> GIT_ROOT = /home/eran/work/agentsh (found .git)
                              |
3. Server: loadPolicy("dev-safe")
                              |
4. Server: policy.ExpandVariables(map[string]string{
               "PROJECT_ROOT": "/home/eran/work/agentsh",
               "GIT_ROOT": "/home/eran/work/agentsh",
           })
           -> "${PROJECT_ROOT}/**" becomes "/home/eran/work/agentsh/**"
                              |
5. Server: NewEngine(expandedPolicy)
           -> Compiles globs for real paths
                              |
6. Server: Store roots in session, return to client
```

## Error Handling

### Variable Expansion Errors

| Scenario | Behavior |
|----------|----------|
| `${UNDEFINED}` (no fallback) | Session creation fails with error: `undefined variable: UNDEFINED` |
| `${UNDEFINED:-}` (empty fallback) | Expands to empty string |
| `${UNDEFINED:-/fallback}` | Expands to `/fallback` |
| `${GIT_ROOT}` when not in git repo | Fails unless fallback provided |
| Malformed syntax `${FOO` | Session creation fails with parse error |

### Detection Edge Cases

| Scenario | Behavior |
|----------|----------|
| Workspace doesn't exist | Session creation fails: `workspace does not exist` |
| No read permission on parent dirs | Stop walking at permission boundary, use deepest accessible |
| Symlinked workspace | Resolve symlinks before detection |
| `.git` is a file (git worktree) | Treat as valid git marker |
| Network/mounted filesystem | Detection works normally (just `stat()` calls) |

### Logging

```
INFO  session created id=abc123 workspace=/home/eran/work/agentsh/cmd
INFO  project detection project_root=/home/eran/work/agentsh git_root=/home/eran/work/agentsh
DEBUG expanded policy variable var=PROJECT_ROOT value=/home/eran/work/agentsh
WARN  project detection found no markers, using workspace as project_root
```

## Non-Goals

- Caching detected roots or compiled engines (add later if profiling shows need)
- Nested variable expansion (`${${FOO}}`)
- Arithmetic or string manipulation in variables
