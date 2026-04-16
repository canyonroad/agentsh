# Multi-User Wrap Socket Permissions

**Date:** 2026-04-16
**Status:** Draft
**Scope:** `internal/api/wrap.go`, `internal/api/wrap_linux.go`, `internal/cli/wrap.go`, `internal/cli/wrap_linux.go`, `pkg/types/sessions.go`

## Problem

When `agentsh server` runs as root (e.g. a systemd service) and `agentsh wrap` runs as an unprivileged user (e.g. uid=1000), the wrap process cannot connect to the notify sockets. The server creates the temp directory at `/tmp/agentsh-wrap-*/` as `root:root 0700`. The unprivileged CLI cannot traverse the directory to reach the sockets, failing with `EACCES` at `forwardNotifyFD` → `net.Dial("unix", socketPath)`.

All three socket types are affected: seccomp notify, ptrace notify, and signal filter.

## Approach: Chown + SO_PEERCRED (defense in depth)

Two independent barriers:

1. **Filesystem isolation (chown):** The server chowns the notify directory and sockets to the wrap caller's UID. Directory stays `0700` — only the specific user can traverse. Falls back to relaxed permissions (`0711`/`0666`) when the server lacks `CAP_CHOWN` (non-root mode).

2. **Runtime verification (SO_PEERCRED):** On every notify socket accept, the server extracts the connecting process's UID from kernel-provided `SO_PEERCRED` credentials and rejects mismatches. This is the always-on layer — even if chown succeeded, the server still verifies.

The combination means: a spoofed `CallerUID` in the HTTP request is self-defeating (chown grants access to the wrong user, but SO_PEERCRED then rejects the attacker's real UID), and relaxed filesystem permissions in fallback mode are backstopped by kernel credential checks.

## Protocol Change

`WrapInitRequest` gains one field:

```go
type WrapInitRequest struct {
    AgentCommand string   `json:"agent_command"`
    AgentArgs    []string `json:"agent_args,omitempty"`
    CallerUID    int      `json:"caller_uid,omitempty"` // 0 = not provided (old client)
}
```

The CLI sets `CallerUID = os.Getuid()` before the wrap-init HTTP call. `omitempty` ensures old clients that don't send it produce `caller_uid: 0`, which the server treats as "unknown caller."

No changes to `WrapInitResponse`.

## Server-Side: Directory and Socket Ownership

After `MkdirTemp` and before creating sockets, the server secures the directory and each socket. Two helpers, since the directory is created once but may contain multiple sockets (seccomp path shares a directory between notify and signal sockets):

```
// secureNotifyDir chowns the directory to callerUID. Returns true if chown
// succeeded, false if fallback permissions were applied instead.
secureNotifyDir(dir, callerUID) bool:
  if callerUID > 0:
    err := os.Chown(dir, callerUID, -1)
    if err is EPERM:
      log.Debug("chown failed, falling back to permissive mode")
      chmod(dir, 0711)       // traverse-only for others
      return false
    chmod(dir, 0700)         // only caller can traverse
    return true
  else:
    chmod(dir, 0711)         // old client, permissive fallback
    return false

// secureSocket chowns or chmods the socket after net.Listen.
secureSocket(socketPath, callerUID, chownOK):
  if chownOK:
    os.Chown(socketPath, callerUID, -1)  // caller owns socket
  else:
    chmod(socketPath, 0666)              // world-connectable fallback
```

Call pattern in `wrapInitCore`:
- **Ptrace path** (~line 76): `secureNotifyDir` once, `net.Listen`, `secureSocket` once.
- **Seccomp path** (~line 198): `secureNotifyDir` once, then for each of notify socket (~line 226) and signal socket (~line 248): `net.Listen`, `secureSocket`.

## Server-Side: SO_PEERCRED Verification

### Extend `getConnPeerPID` → `getConnPeerCreds`

```go
type peerCreds struct {
    PID int
    UID uint32
}

func getConnPeerCreds(conn *net.UnixConn) peerCreds {
    // Existing GetsockoptUcred logic, return both .Pid and .Uid
}
```

### Verify in each accept function

In `acceptNotifyFD`, `acceptSignalFD`, and `acceptPtracePID`, after `listener.Accept()`:

```
creds := getConnPeerCreds(unixConn)
if expectedUID > 0 && creds.UID != uint32(expectedUID):
    log.Warn("wrap: rejected connection from unexpected UID",
        "expected", expectedUID, "got", creds.UID, "pid", creds.PID)
    conn.Close()
    return
```

The `expectedUID` is threaded from `wrapInitCore` into the accept goroutines (passed as a parameter). When `CallerUID == 0` (old client), skip the check.

## Client-Side Change

In `internal/cli/wrap.go`, before the wrap-init call:

```go
req.CallerUID = os.Getuid()
```

One line.

## Backward Compatibility

| Server | Client | Behavior |
|--------|--------|----------|
| New | New | Full: chown + SO_PEERCRED |
| New | Old | `CallerUID=0` → fallback `0711`/`0666`, no UID check. Equivalent to user's proposed fix. |
| Old | New | Server ignores unknown field (Go JSON unmarshal lenient). Old `0700` behavior — still broken for multi-user, but was already broken. |
| Old | Old | Status quo |

No configuration required. Chown-vs-fallback is automatic based on server capabilities and client version.

## Testing

### Unit tests

1. **`getConnPeerCreds`** — verify both PID and UID are returned from a local socketpair.

2. **`secureNotifyDir` + `secureSocket` helpers** — three cases:
   - `callerUID > 0`, chown succeeds → directory owned by callerUID, mode `0700`; socket owned by callerUID.
   - `callerUID > 0`, chown returns `EPERM` → directory mode `0711`, socket mode `0666`.
   - `callerUID == 0` → same fallback as EPERM case.

3. **SO_PEERCRED rejection** — create a listener, connect from current process. Accept succeeds when `expectedUID == os.Getuid()`. Accept rejects (closes connection) when `expectedUID` is a different value.

### Integration test

4. **Multi-user wrap round-trip (root only)** — if running as root: create wrap-init with `CallerUID=1000`, verify ownership, connect from a forked uid=1000 process, confirm fd forwarding succeeds. Skip if not root.

### Not tested

Actually running as two different non-root users simultaneously — requires `setuid`, fragile in CI. The unit tests for permission logic and SO_PEERCRED cover the critical paths.
