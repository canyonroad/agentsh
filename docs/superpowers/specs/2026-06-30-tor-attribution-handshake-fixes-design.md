# Tor Attribution & Handshake Robustness — Design

**Status:** Draft (spec pending review)

**Fixes:** three Important issues found by the adversarial review of commits
`37cd3b2d..5173547e` (Tor access control Phase 4, PR #430; command-PID
attribution for interception-path `tor_control` events, PR #431).

## Summary

PR #431 threaded the session's command-process PID into the four
interception-path `tor_control` event sites (`transparent_tcp`, `dns`, `proxy`).
The review found three Important defects in that work:

1. **TOCTOU attribution** — `commandID` and `pid` are read as two separately
   locked getter calls (`CurrentCommandID()` then `CurrentProcessPID()`), so a
   `tor_control` audit event can observe a torn pair across a command
   start/release boundary (e.g. `commandID="cmd-A", pid=99` from cmd-B, or
   `commandID="cmd-A", pid=0`).
2. **Bypass events unattributed** — the sibling `db_bypass_attempt` events in
   the same handlers pass the literal `pid=0` even though the handlers now read
   the real `pid` for the adjacent `tor_control` event.
3. **Slowloris on the SOCKS gateway** — `handleTorSocks` reads the client
   handshake with no read deadline, so a client that stalls mid-handshake holds
   a gateway goroutine + fd indefinitely.

This design closes all three with a minimal, localized change confined to
`internal/session` and `internal/netmonitor`. It adds **no new data path**, **no
new event type**, and **no new config knobs**.

## Motivation

### Issue #1 — Torn (commandID, pid) pairs

`Session` stores `currentCommandID` and `currentProcPID` behind one mutex
(`s.mu`), but exposes them through two independent getters, each taking `s.mu`
separately:

```go
func (s *Session) CurrentCommandID() string { s.mu.Lock(); defer s.mu.Unlock(); return s.currentCommandID }
func (s *Session) CurrentProcessPID() int    { s.mu.Lock(); defer s.mu.Unlock(); return s.currentProcPID }
```

The setters are likewise separate, and `LockExec`'s release clears both under
one lock. PR #431 added the second read at every interception site:

```go
commandID := ""
pid := 0
if t.sess != nil {
    commandID = t.sess.CurrentCommandID()
    pid = t.sess.CurrentProcessPID()
}
```

Because `execMu` serializes commands per session, a torn *cross-command* pair
can only occur at a launch/release boundary: between the two getter calls a
command can finish (release clears both → `(cmd-A, 0)`) or a new command can
start (sets commandID, PID comes later → read `cmd-B` then `pid` still of
cmd-A, or `pid` of cmd-B with `commandID` of cmd-A). An auditor correlating
`pid` and `commandID` on a `tor_control` event could be misled about which
command performed a Tor access.

**Scope decision (chosen B):** fix the read side with a single combined getter
under one lock, and (per Issue #2 below) thread the resulting `pid` into the
bypass sites. Deliberately **do not** touch the command-launch path in
`internal/api/` to also close the launch-window `(commandID=cmd-B, pid=0)`
state: that window is between `SetCurrentCommandID` (top of launch,
`exec_stream.go:51`) and `SetCurrentProcessPID` (after `cmd.Start()`,
`:434`/`exec.go:357`/`pty_core.go:202`), during which **the PID genuinely does
not exist yet** (e.g. `CheckCommandWithExecve` runs pre-Start). `pid=0` there is
an *accurate* "process not yet started" state, not misattribution. Closing it
would require either suppressing legitimate attribution or faking a PID, with a
wide blast radius into every pre-Start `commandID` reader — a separate, larger
effort.

### Issue #2 — `db_bypass_attempt` passes `pid=0`

`emitDBBypassAttempt` accepts a `pid int` and stamps it onto the event, but
every call site passes the literal `0`:

- `internal/netmonitor/transparent_tcp.go:163`
- `internal/netmonitor/proxy.go:194, 241, 363, 414`

After PR #431 the `tor_control` event in the same handler carries the real
`pid`; the sibling bypass event for the *same decision* does not. `db_bypass`
is the most security-sensitive event in these functions — it records a process
*attempting to bypass DB protection — and leaving it unattributed while the
adjacent event is attributed is an inconsistency the PR made conspicuous.

`proxy.handleConnect` (sites 194, 241) currently reads **only** `commandID`,
not `pid`, so it must adopt the combined getter to bring `pid` into scope.

**Scope decision (chosen A):** wire the real `pid` into the 5
`emitDBBypassAttempt` sites only. Do **not** also set `PID` on the sibling
`net_connect`/`net_close` events (Minor review item #8: `netEvent`/`emitNetEvent`
leave `ev.PID` zero). That is the same `pid` read in the same functions, but it
expands the change into `netEvent`/`emitNetEvent` signatures and their other
callers; better as its own focused change.

### Issue #3 — Slowloris on the SOCKS gateway

`handleTorSocks` reads the client SOCKS5 handshake with `io.ReadFull` and **no
read deadline**:

```go
if err := readSocksGreeting(conn); err != nil { return err }   // blocks forever
if err := writeSocksMethod(conn, 0x00); err != nil { return err }
req, err := readSocksRequest(conn)                              // blocks forever
```

`net.DialTimeout` bounds only the *upstream* dial (20s); the *client*-side
handshake reads are unbounded. A sandboxed command can open many connections to
the redirected Tor SOCKS port, stall each handshake, and exhaust agentsh's
host-side goroutines/fds, DoSing monitoring for the session. The new `RESOLVE`
path inherits the exposure (a second blocking `readSocksRequest(conn)`).

The transparent interception path never reads a client handshake, so the
slowloris surface is local to the SOCKS gateway.

**Scope decision (chosen A):** `conn.SetReadDeadline` around the handshake
reads, cleared before the tunnel/relay phase. Matches in-file precedent
(`dns.go` uses a 250ms read deadline; `gatewayConnect` already uses a 20s
upstream `DialTimeout`). A flat handshake deadline is sufficient — the
handshake is at most a few hundred bytes; per-read reset (the rejected option
C) adds complexity for no practical gain.

## Design

### Component 1 — Atomic attribution read (fixes #1)

Add one combined accessor to `internal/session/manager.go` (additive — existing
`CurrentCommandID`/`CurrentProcessPID` remain for other callers):

```go
// CurrentCommandAttribution returns (commandID, pid) as a single snapshot
// under one lock, so audit events cannot observe a torn pair across a command
// start/release boundary. pid==0 during the launch window is an honest
// "process not yet started" state, not a misattribution.
func (s *Session) CurrentCommandAttribution() (commandID string, pid int) {
    s.mu.Lock()
    defer s.mu.Unlock()
    return s.currentCommandID, s.currentProcPID
}
```

Replace the two-call reads at **3 sites**:

- `internal/netmonitor/transparent_tcp.go` `handle` (~114-116)
- `internal/netmonitor/dns.go` `handle` (~99-100)
- `internal/netmonitor/proxy.go` `handleHTTP` (~331-332)

with:

```go
commandID, pid := "", 0
if t.sess != nil {
    commandID, pid = t.sess.CurrentCommandAttribution()
}
```

The resulting `pid` feeds Component 2.

### Component 2 — Thread `pid` into bypass sites (fixes #2)

Pass the real `pid` (from Component 1's snapshot) at exactly **5**
`emitDBBypassAttempt` call sites instead of the literal `0`:

- `transparent_tcp.go:163` — `pid` in scope from Component 1.
- `proxy.go:363, 414` (`handleHTTP`) — `pid` in scope from Component 1.
- `proxy.go:194, 241` (`handleConnect`) — `handleConnect` currently reads only
  `commandID` (line ~161-163); switch it to the combined getter so `pid` is in
  scope, then pass it.

No signature change to `emitDBBypassAttempt` (it already takes `pid int`).

### Component 3 — Handshake read deadline (fixes #3)

In `internal/netmonitor/socks.go`, bound the client handshake and clear before
the tunnel/relay:

```go
const socksHandshakeTimeout = 10 * time.Second

func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy,
    emit Emitter, sessionID, commandID string, pid int) error {
    defer conn.Close()

    // Bound the handshake against slow clients. Cleared before the tunnel so
    // long-lived CONNECT streams are unaffected. The error is ignored: some
    // conns (net.Pipe in tests, wrapped conns) do not honor deadlines.
    _ = conn.SetReadDeadline(time.Now().Add(socksHandshakeTimeout))
    if err := readSocksGreeting(conn); err != nil {
        return err
    }
    if err := writeSocksMethod(conn, 0x00); err != nil { // no-auth
        return err
    }
    req, err := readSocksRequest(conn)
    if err != nil {
        _ = writeSocksReply(conn, socksRepGeneralFailure)
        return err
    }
    _ = conn.SetReadDeadline(time.Time{}) // handshake done; tunnel/relay unbounded

    switch req.cmd {
    case socksCmdConnect:
        return gatewayConnect(conn, upstreamAddr, pol, emit, sessionID, commandID, pid, req)
    case socksCmdResolve:
        return gatewayResolve(conn, upstreamAddr, pol, emit, sessionID, commandID, pid, req)
    default:
        _ = writeSocksReply(conn, socksRepCmdNotSupported)
        return nil
    }
}
```

The upstream side is unchanged: it is trusted loopback Tor and already has a
20s `DialTimeout`. `gatewayResolve` has no splice (request/reply only), so the
cleared deadline is harmless there; the deadline reset before the switch covers
both branches uniformly.

## Testing

- **#1 (atomic attribution):**
  - Extend the existing PID assertions (`dns_test.go`, `proxy_test.go`,
    `socks_handler_test.go`, `transparent_tcp_test.go`) to assert **both**
    `commandID` and `pid` are set on the `tor_control` event from one snapshot.
  - Add a concurrency test in `internal/session`: a goroutine repeatedly calls
    `LockExec()`/`SetCurrentCommandID`/`SetCurrentProcessPID`/release with
    distinct values, while N readers call `CurrentCommandAttribution()`; assert
    no reader ever observes a torn pair (`commandID` and `pid` always belong to
    the same command, or both empty/zero). Run with `-race`.

- **#2 (bypass PID):**
  - Add tests asserting `db_bypass_attempt` events carry the real PID (not 0)
    on a deny, for both `handleConnect` and `handleHTTP` deny paths in
    `proxy_test.go`, and the transparent deny path in
    `transparent_tcp_test.go`.

- **#3 (slowloris):**
  - Add a test using a **real TCP listener** (not `net.Pipe`, which ignores
    deadlines): open a conn to the gateway, send only the SOCKS greeting, then
    stall. Assert `handleTorSocks` returns within ~`socksHandshakeTimeout`
    (with slack) and the goroutine/connection is released.
  - Assert a fully-sent handshake still tunnels/relays correctly (covered by
    existing `TestHandleTorSocks_*` tests; verify they still pass with the new
    deadline set/clear).

## Non-goals (explicitly out of scope)

- The launch-window `(commandID=cmd-B, pid=0)` state stays as honest state
  (the "C" option rejected for Issue #1).
- `net_connect`/`net_close` `PID=0` (Minor review item #8) — left for a
  separate change.
- All review Minor items (#4–#10): `RESOLVE_PTR` (0xF1) test, malformed-request
  → `0x01` test, reply-code enumeration oracle, unsupported-command audit
  visibility, `EvalSocksTarget` target normalization, non-IPv4 RESOLVE reply
  test coverage.

## Risk

- **Combined getter vs existing getters:** additive only; no existing caller
  changes unless it adopts the new one. The 3 netmonitor sites are the only
  adoption in this change.
- **Deadline on `net.Pipe`:** `net.Pipe` does not honor deadlines; the deadline
  set is a no-op there and the clear is harmless. Existing `net.Pipe`-based
  tests continue to pass (verify). The slowloris test uses a real TCP listener.
- **Ignored `SetReadDeadline` error:** a wrapped conn without the method would
  return an error; ignoring it is intentional and graceful (the conn simply
  remains unbounded, no worse than today).
