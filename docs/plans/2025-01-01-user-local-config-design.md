# User-Local Configuration Design

**Status:** Implemented

## Overview

Enable agentsh to search for configuration in user-local directories before falling back to system-wide locations. This allows non-root users to run agentsh with their own configuration, policies, and data storage.

## Configuration Search Order

When agentsh needs to find its config file, it searches in this order (first found wins):

1. **`AGENTSH_CONFIG` env var** - Explicit path, highest priority
2. **User-local config** - Platform-specific:
   - Linux: `$XDG_CONFIG_HOME/agentsh/config.yaml` (default: `~/.config/agentsh/config.yaml`)
   - macOS: `~/Library/Application Support/agentsh/config.yaml`
   - Windows: `%APPDATA%\agentsh\config.yaml`
3. **System-wide config** - Platform-specific:
   - Linux: `/etc/agentsh/config.yaml`
   - macOS: `/usr/local/etc/agentsh/config.yaml`
   - Windows: `%PROGRAMDATA%\agentsh\config.yaml`

The code tracks *which* config was loaded (user vs system) to determine default paths for policies and data.

## Policies Directory Resolution

The default policies directory is derived from the config location:

| Config Loaded From | Default Policies Dir |
|-------------------|---------------------|
| User-local | `~/.config/agentsh/policies/` |
| System-wide | `/etc/agentsh/policies/` |
| Explicit path (`AGENTSH_CONFIG`) | Same directory as config + `/policies/` |

The `policies.dir` setting in the config file can still override this default.

Policy file lookup within a directory stays unchanged - the existing `ResolvePolicyPath()` logic continues to work as-is.

## Data Directory Resolution

Data directories (sessions, events.db) follow the same user vs system pattern:

| Config Loaded From | Default Data Dir |
|-------------------|------------------|
| User-local | `~/.local/share/agentsh/` (Linux), `~/Library/Application Support/agentsh/` (macOS), `%APPDATA%\agentsh\` (Windows) |
| System-wide | `/var/lib/agentsh/` (Linux), `/usr/local/var/agentsh/` (macOS), `%PROGRAMDATA%\agentsh\` (Windows) |

This affects defaults for:
- `sessions.base_dir` → `<data_dir>/sessions/`
- `audit.storage.sqlite_path` → `<data_dir>/events.db`

Config file settings still override these defaults.

## Implementation Changes

**Files to modify:**

1. **`internal/cli/local_config.go`** - Update `defaultConfigPath()` to use new search order and track config source

2. **`internal/config/platform.go`** - Add `GetUserDataDir()` function (parallel to existing `GetUserConfigDir()`)

3. **`internal/config/config.go`** - Update `applyDefaults()` to use config source when setting default paths for policies and data

**New concept: ConfigSource**

```go
type ConfigSource int
const (
    ConfigSourceEnv    ConfigSource = iota  // AGENTSH_CONFIG
    ConfigSourceUser                        // ~/.config/agentsh/
    ConfigSourceSystem                      // /etc/agentsh/
)
```

The config loader returns both the `*Config` and its `ConfigSource`, which is then used to determine default paths.

## Edge Cases

1. **No config found anywhere** - Fall back to sensible defaults (current behavior), use user-local paths for data
2. **User config dir doesn't exist** - Skip it silently, continue to system config
3. **Permission errors** - If user can't read system config, report clear error
4. **Mixed scenario** - User config exists but references system policy by name → should still work (policies.dir can be absolute path)

## Testing Strategy

- Unit tests for `defaultConfigPath()` with mocked filesystem
- Unit tests for `GetUserDataDir()` across platforms
- Integration test: run as non-root user with user-local config, verify data goes to user dir
