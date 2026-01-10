# Policies

This guide covers policy configuration and management for agentsh.

## Policy Variables

Policies support variable substitution using `${VAR}` syntax.

### Built-in Variables

| Variable | Description |
|----------|-------------|
| `${PROJECT_ROOT}` | Detected project root (nearest go.mod, package.json, etc.) |
| `${GIT_ROOT}` | Nearest .git directory |
| `${HOME}` | User's home directory (from environment) |
| `${TMPDIR}` | System temp directory (from environment) |

### Fallback Syntax

Use `${VAR:-fallback}` to provide a default value:

```yaml
paths:
  - "${GIT_ROOT:-${PROJECT_ROOT}}/**"  # Use git root, fall back to project root
  - "${TMPDIR:-/tmp}/**"               # Use TMPDIR, fall back to /tmp
```

### Disabling Detection

Server config:
```yaml
policies:
  detect_project_root: false
```

Per-session:
```bash
agentsh exec --no-detect-root SESSION -- cmd
```

Explicit root:
```bash
agentsh exec --project-root /path/to/project SESSION -- cmd
```
