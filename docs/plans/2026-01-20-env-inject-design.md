# Environment Variable Injection Design

**Date:** 2026-01-20
**Status:** Approved
**Problem:** Blaxel's runtime strips Docker ENV variables, so BASH_ENV isn't available to disable shell builtins that bypass seccomp policy enforcement.

## Overview

Add `env_inject` configuration that injects environment variables into command execution, regardless of the parent environment. This enables operators to set variables like `BASH_ENV` that would otherwise be blocked by policy.

## Configuration

### Global Config (`config.yaml`)

```yaml
sandbox:
  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
    # Operators can add other vars
    MY_CUSTOM_VAR: "value"
```

### Policy-Level Override (`policies/*.yaml`)

```yaml
version: 1
name: restrictive

env_inject:
  BASH_ENV: "/etc/mycompany/custom_bash_startup.sh"
  EXTRA_VAR: "policy-specific"

# ... rest of policy
```

### Merge Behavior

- Start with global `sandbox.env_inject`
- Layer policy `env_inject` on top
- Policy wins on key conflicts
- Result bypasses env policy filtering (operator-trusted)

## Bundled Startup Script

**Location:** `/usr/lib/agentsh/bash_startup.sh`

**Content:**
```bash
#!/bin/bash
# Disable builtins that bypass seccomp policy enforcement
enable -n kill      # Signal sending
enable -n enable    # Prevent re-enabling
enable -n ulimit    # Resource limits
enable -n umask     # File permission mask
enable -n builtin   # Force builtin bypass
enable -n command   # Function/alias bypass
```

## Packaging

| Package Type | Script Location | Config File |
|--------------|-----------------|-------------|
| Tarballs (linux) | `bash_startup.sh` in archive root | `.goreleaser.yml` archives |
| deb/rpm/arch | `/usr/lib/agentsh/bash_startup.sh` | `.goreleaser.yml` nfpms.contents |
| Alpine musl | In tarball root | `.github/workflows/release.yml` |
| Homebrew (macOS) | Not included | N/A (BASH_ENV is Linux-specific) |

## Implementation

### Files to Modify

1. **`internal/config/config.go`** - Add EnvInject to SandboxConfig:
   ```go
   type SandboxConfig struct {
       Fuse        FuseConfig
       Network     NetworkConfig
       UnixSockets UnixSocketsConfig
       Seccomp     SeccompConfig
       EnvInject   map[string]string `yaml:"env_inject"`
   }
   ```

2. **`internal/policy/policy.go`** - Add EnvInject to policy struct:
   ```go
   type Policy struct {
       // ... existing fields
       EnvInject map[string]string `yaml:"env_inject"`
   }
   ```

3. **`internal/api/exec.go`** (~line 142-164) - Inject vars after policy filtering

4. **New file: `bash_startup.sh`** - The builtin-disabling script

5. **`.goreleaser.yml`** - Add to archives and nfpms contents

6. **`.github/workflows/release.yml`** - Add to Alpine tarball

### Merge Logic

```go
func mergeEnvInject(cfg *config.Config, pol *policy.Engine) map[string]string {
    result := make(map[string]string)

    // 1. Start with global config
    for k, v := range cfg.Sandbox.EnvInject {
        result[k] = v
    }

    // 2. Layer policy on top (policy wins conflicts)
    if pol != nil {
        for k, v := range pol.GetEnvInject() {
            result[k] = v
        }
    }

    return result
}
```

### Application Point

In `exec.go`, after existing env building (~line 159-163):

```go
// Existing: add wrapper env (AGENTSH_* vars)
for k, v := range extra.env {
    env = append(env, k+"="+v)
}

// NEW: add env_inject (operator-trusted, bypasses policy)
for k, v := range mergeEnvInject(cfg, pol) {
    env = append(env, k+"="+v)
}

cmd.Env = env
```

## Testing

### Unit Tests

1. Config parsing - Verify `env_inject` parses from YAML correctly
2. Merge logic - Global + policy merge, policy wins conflicts
3. Empty cases - No global, no policy, neither

### Integration Test

```yaml
# Test policy
env_inject:
  BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"

command_rules:
  - name: block-kill
    commands: ["kill"]
    decision: deny
```

```bash
# Test: bash builtin kill should fail
bash -c "kill -0 $$"  # Should fail
```

### Manual Validation on Blaxel

1. Deploy with new config
2. Verify `bash -c "kill ..."` is blocked
3. Verify `/bin/kill` still blocked by policy
4. Verify other builtins (`enable`, `ulimit`) are disabled

## Security Considerations

- `env_inject` bypasses policy filtering because values are operator-configured (trusted)
- Same trust model as `AGENTSH_*` internal variables
- Defense-in-depth: config file access control is the security boundary
- The bundled script disables `enable` itself to prevent re-enabling builtins
