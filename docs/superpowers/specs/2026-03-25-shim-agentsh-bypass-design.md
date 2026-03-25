# Fix: Agentsh CLI Self-Deadlock Through Shim

## Problem

When `shim.conf force=true` is set, any `agentsh` CLI command (`detect`, `debug policy-test`, `--version`, `trash list`) executed through the shell shim deadlocks. The shim routes the command to the server via `agentsh exec`, the server spawns the CLI, and the CLI connects back to the same server — which is blocked handling the shim's exec request.

This affects operators running diagnostic commands and test infrastructure in shim-enforced environments like exe.dev.

## Solution

Add an agentsh binary bypass to the shim. Before the force/config logic, check if the command being executed IS the agentsh binary. If so, exec the real shell directly (same mechanism as the `AGENTSH_IN_SESSION` recursion guard).

### Detection logic

The shim is invoked as `sh -c "agentsh detect"`. The detection:

1. Check if args contain `-c` followed by a command string
2. Extract the first word from the command string
3. Resolve it via `exec.LookPath` to get the absolute path
4. Compare against `resolveAgentshBin()` (existing function that finds the agentsh binary)
5. If they match, bypass to real shell

```go
if isAgentshCommand(os.Args[1:]) {
    debugLog("agentsh CLI bypass: command is agentsh itself, executing real shell %s", realShell)
    execOrExit(realShell, append([]string{argv0}, os.Args[1:]...), os.Environ())
    return
}
```

### Placement in main.go

The check goes AFTER the `AGENTSH_IN_SESSION` recursion guard (line 31) and AFTER `resolveRealShell` (line 48), but BEFORE the config read and force/bypass logic (line 66). This ensures agentsh CLI commands are always bypassed regardless of `force=true`.

### `isAgentshCommand` implementation

```go
func isAgentshCommand(args []string) bool {
    if len(args) < 2 || args[0] != "-c" {
        return false
    }
    cmdParts := strings.Fields(args[1])
    if len(cmdParts) == 0 {
        return false
    }
    cmdPath, err := exec.LookPath(cmdParts[0])
    if err != nil {
        return false
    }
    agentshPath, err := resolveAgentshBin()
    if err != nil {
        return false
    }
    return cmdPath == agentshPath
}
```

If either `LookPath` or `resolveAgentshBin` fails, the check returns false (no bypass — command proceeds normally through the server, where it'll fail on its own).

## Files to modify

1. `cmd/agentsh-shell-shim/main.go` — Add `isAgentshCommand` function and bypass check
2. `cmd/agentsh-shell-shim/main_test.go` — Unit tests for `isAgentshCommand` and integration test

## Test plan

**Unit tests for `isAgentshCommand`:**
- `-c "agentsh detect"` → true
- `-c "agentsh --version"` → true
- `-c "echo hello"` → false
- `-c "/usr/bin/agentsh trash list"` → true (absolute path)
- `-c "sudo agentsh detect"` → false (first word is sudo)
- No `-c` flag → false
- Empty command string → false

**Integration tests (build shim, run as subprocess):**
- Shim with `force=true` + `agentsh` command → bypasses (no server needed)
- Shim with `force=true` + non-agentsh command → enforces (tries server)
