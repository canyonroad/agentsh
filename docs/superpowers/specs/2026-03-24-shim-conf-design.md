# Shim Configuration File (`/etc/agentsh/shim.conf`)

## Problem

The shell shim (`agentsh-shell-shim`) bypasses policy enforcement when stdin is not a TTY and `AGENTSH_SHIM_FORCE=1` is not set. This is correct for general use (preserves binary stdin/stdout for piped data), but breaks enforcement on platforms where:

1. Commands are always non-interactive (no TTY)
2. The platform spawns the shell without a way to inject env vars beforehand

exe.dev is one such platform: `ssh exe.dev ssh vmname "command"` spawns a shell on the VM, but the env var is not in the shell's process environment. `/etc/environment`, `/etc/profile.d/`, and `.bashrc` do not help because the gateway's SSH does not source these for non-interactive commands.

## Solution

Add a config file that the shim reads at startup. The file is written during `agentsh shim install-shell --force` or by the operator manually. Unlike env vars or profile scripts, the shim reads the file directly — it works regardless of how the shell was spawned.

## Design

### Config file format

Simple `key=value`, one per line. Blank lines and lines where the first non-whitespace character is `#` are ignored. Whitespace around keys and values is trimmed (e.g., `force = true` is equivalent to `force=true`). Trailing inline comments are not supported (`force=true # comment` would set `force` to `true # comment`). Keys are case-sensitive. No quoting, no sections, no nested values.

```
# /etc/agentsh/shim.conf
# Written by: agentsh shim install-shell --force
force=true
```

### Config path

`/etc/agentsh/shim.conf` on both Linux and macOS. `/etc` exists on macOS, the config is system-level (not per-user), and using the same path keeps the code simple. `ShimConfPath(root)` is the single place to change this if a platform-specific path is ever needed.

### Shared package: `internal/shim/conf.go`

The config parser lives in `internal/shim/` so both the shim binary and the install command share the same logic.

```go
// ShimConfPath returns the config file path under root.
func ShimConfPath(root string) string

// ReadShimConf reads the config file at ShimConfPath(root).
// Missing file (ENOENT) returns empty conf with nil error.
// Other read errors (permission denied, I/O) return empty conf AND the error,
// so the caller can log it without crashing.
func ReadShimConf(root string) (ShimConf, error)

// WriteShimConf writes all keys from conf.Raw as key=value lines, one per line.
// Prepends a comment header: "# Written by: agentsh shim install-shell".
// Creates /etc/agentsh/ directory (mode 0o755) if needed.
// File is written atomically with mode 0o644.
func WriteShimConf(root string, conf ShimConf) error

// ShimConf is the parsed config.
type ShimConf struct {
    Force bool              // force=true|1
    Raw   map[string]string // all key=value pairs for forward compat
}
```

### Permissions

The config file is security-relevant (`force=true` enables policy enforcement). A world-writable config would let a local attacker set `force=false` to bypass enforcement.

- Directory `/etc/agentsh/`: mode `0o755`, owned by root. Standard `/etc` subdirectory convention.
- File `shim.conf`: mode `0o644` (readable by all, writable only by root). Consistent with `/etc/ssh/sshd_config` and similar system configs.

`WriteShimConf` enforces these modes in its atomic write.

### Shim bypass logic (`cmd/agentsh-shell-shim/main.go`)

Precedence: env var > config file > default (false).

```go
conf, confErr := shim.ReadShimConf("/")
if confErr != nil {
    debugLog("read shim.conf: %v", confErr)
}
forceShim := strings.TrimSpace(os.Getenv("AGENTSH_SHIM_FORCE"))
switch {
case forceShim == "1":
    debugLog("AGENTSH_SHIM_FORCE=1: enforcing policy despite non-interactive stdin")
case forceShim == "0":
    debugLog("AGENTSH_SHIM_FORCE=0: config file force overridden by env")
case conf.Force:
    forceShim = "1"
    debugLog("shim.conf force=true: enforcing policy despite non-interactive stdin")
}
if !term.IsTerminal(int(os.Stdin.Fd())) && forceShim != "1" {
    // bypass as before
}
```

`AGENTSH_SHIM_FORCE=0` explicitly overrides `force=true` in the config, giving operators per-process control.

### Install command (`internal/cli/shim_cmd.go`)

New `--force` flag on `install-shell`. When set, writes `shim.conf` with `force=true` after installing the shim binary:

```
agentsh shim install-shell --root / --shim /path/to/shim --bash --force --i-understand-this-modifies-the-host
```

Dry-run support: `--force --dry-run` includes a `write` action in the plan output for the config file, integrating with the existing `ShellShimPlan`/`ShellShimAction` system.

Uninstall does not touch the config file. The file is inert without the shim and follows the Unix convention that `/etc` configs survive package removal.

The config file is global. `force=true` applies to all shim invocations regardless of which shell is shimmed. It has no effect on shells where the shim is not installed (e.g., if `--bash-only` was used, `force=true` does not affect `/bin/sh` since the shim is not installed there).

### Performance

Reading a small file adds ~0.1ms. The shim already does `os.Getenv()`, `term.IsTerminal()` (ioctl), and `os.Stat()` for real shell detection. One more `os.ReadFile()` is negligible.

## Files to modify

1. `internal/shim/conf.go` (new) — `ShimConfPath`, `ReadShimConf`, `WriteShimConf`, `ShimConf`
2. `internal/shim/conf_test.go` (new) — unit tests for config parsing and round-trip
3. `cmd/agentsh-shell-shim/main.go` — read config, integrate into bypass logic
4. `cmd/agentsh-shell-shim/main_test.go` — integration tests for config + env + TTY precedence
5. `internal/cli/shim_cmd.go` — `--force` flag on `install-shell`, write config after install
6. `internal/cli/shim_cmd_test.go` — CLI tests for `--force` and `--force --dry-run`

## Test plan

### Unit tests (`internal/shim/conf_test.go`)

- `ReadShimConf` with missing file returns empty conf, nil error
- `ReadShimConf` with `force=true` returns `Force: true`
- `ReadShimConf` with `force=1` returns `Force: true`
- `ReadShimConf` with `force=false` returns `Force: false`
- `ReadShimConf` with malformed lines, comments, blank lines parses correctly
- `ReadShimConf` with unreadable file (permission denied) returns empty conf and non-nil error
- `WriteShimConf` creates directory (0o755) and file (0o644) atomically
- `WriteShimConf` then `ReadShimConf` round-trip preserves values
- `ShimConfPath` returns expected path for given root

### Integration tests (`cmd/agentsh-shell-shim/main_test.go`)

- No config, no env, no TTY → bypass (existing, unchanged)
- No config, `AGENTSH_SHIM_FORCE=1`, no TTY → enforce (existing, unchanged)
- Config `force=true`, no env, no TTY → enforce (new)
- Config `force=true`, `AGENTSH_SHIM_FORCE=0`, no TTY → bypass (env overrides config)
- Config `force=true`, TTY → enforce (TTY always enforces)

### CLI tests (`internal/cli/shim_cmd_test.go`)

- `install-shell --force` writes config file
- `install-shell --force --dry-run` includes config write action in plan
- `install-shell` without `--force` does not write config file
