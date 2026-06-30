# Tor Attribution & Handshake Robustness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close three Important review findings on commits `37cd3b2d..5173547e` — torn `(commandID, pid)` audit pairs, `db_bypass_attempt` events unattributed (`pid=0`), and slowloris on the SOCKS gateway handshake.

**Architecture:** (1) Add one atomic combined getter on `Session` and adopt it at the 3 interception read sites; (2) thread the resulting `pid` into the 5 `emitDBBypassAttempt` call sites (adding the missing PID read to `proxy.handleConnect`); (3) set a client read deadline around the SOCKS handshake in `handleTorSocks`, cleared before the tunnel/relay. All changes confined to `internal/session` and `internal/netmonitor`.

**Tech Stack:** Go 1.24, `net`, `io`, `sync`, `net.Pipe` (honors `SetReadDeadline` — verified).

**Spec:** [docs/superpowers/specs/2026-06-30-tor-attribution-handshake-fixes-design.md](../specs/2026-06-30-tor-attribution-handshake-fixes-design.md)

## Global Constraints

- Cross-platform Go (Linux/macOS/Windows, per AGENTS.md). These fixes are platform-agnostic; tests use `net.Pipe` (no `SO_ORIGINAL_DST`), so they run on all platforms — do **not** add `t.Skip()` or `runtime.GOOS` guards.
- No new config knobs, no new event types, no new data paths.
- Additive only: keep the existing `CurrentCommandID()` / `CurrentProcessPID()` getters (other packages call them); add `CurrentCommandAttribution()` alongside.
- `socksHandshakeTimeout` is a package-level **`var`** (not `const`) so tests can override it; production default is `10 * time.Second`. (Testability refinement over the spec's `const`; behavior identical in production.)
- The `SetReadDeadline` error is intentionally ignored (some conns — `net.Pipe` in tests, wrapped conns — do not honor deadlines; the conn then simply stays unbounded, no worse than today).

## File Structure

- **Modify** `internal/session/manager.go` — add `CurrentCommandAttribution() (commandID string, pid int)`.
- **Create** `internal/session/manager_attribution_test.go` — atomicity race test for the combined getter.
- **Modify** `internal/netmonitor/transparent_tcp.go` — `handle`: use combined getter; pass `pid` at the `emitDBBypassAttempt` site.
- **Modify** `internal/netmonitor/dns.go` — `handle`: use combined getter.
- **Modify** `internal/netmonitor/proxy.go` — `handleHTTP`: use combined getter + pass `pid` at 2 bypass sites; `handleConnect`: switch to combined getter (brings `pid` into scope) + pass `pid` at 2 bypass sites.
- **Modify** `internal/netmonitor/socks.go` — add `socksHandshakeTimeout` var; set/clear read deadline in `handleTorSocks`.
- **Modify** `internal/netmonitor/proxy_test.go` — 2 handler-level bypass-PID tests + `newDBUnavoidabilityIPEngine` helper.
- **Modify** `internal/netmonitor/socks_handler_test.go` — slowloris handshake-deadline test.

---

### Task 1: Atomic attribution getter

**Files:**
- Create: `internal/session/manager_attribution_test.go`
- Modify: `internal/session/manager.go` (add method near `CurrentProcessPID` at ~line 379)
- Test: `internal/session/manager_attribution_test.go`

**Interfaces:**
- Consumes: `Session.LockExec() func()`, `Session.SetCurrentCommandID(string)`, `Session.SetCurrentProcessPID(int)` (all pre-existing).
- Produces: `func (s *Session) CurrentCommandAttribution() (commandID string, pid int)` — used by Task 2.

- [ ] **Step 1: Write the failing test**

Create `internal/session/manager_attribution_test.go`:

```go
package session

import (
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
)

// TestCurrentCommandAttribution_AtomicSnapshot asserts the combined getter
// never returns a torn (commandID, pid) pair from two different commands.
// A "cmd-i" snapshot is only ever observed with pid 0 (launching, before
// SetCurrentProcessPID) or pid 1000+i (running) — never with another
// command's pid. A two-call getter would (probabilistically) observe torn
// pairs across the launch/release boundary; the combined getter cannot.
func TestCurrentCommandAttribution_AtomicSnapshot(t *testing.T) {
	s := &Session{ID: "attribution-test"}

	const commands = 300
	const readers = 8

	// valid: (cid, pid) belong to the same command i, or the session is idle.
	valid := func(cid string, pid int) bool {
		if cid == "" {
			return pid == 0 // idle (after LockExec release clears both)
		}
		for i := 0; i < commands; i++ {
			if cid == "cmd-"+strconv.Itoa(i) {
				return pid == 0 || pid == 1000+i // launching or running
			}
		}
		return false
	}

	var stop atomic.Bool
	var bad atomic.Int64

	var wg sync.WaitGroup
	for r := 0; r < readers; r++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for !stop.Load() {
				cid, pid := s.CurrentCommandAttribution()
				if !valid(cid, pid) {
					bad.Add(1)
				}
			}
		}()
	}

	// Writer cycles through commands, mirroring real launch: LockExec, set
	// commandID, then (separately) set the PID once "known", then release.
	for i := 0; i < commands; i++ {
		unlock := s.LockExec()
		s.SetCurrentCommandID("cmd-" + strconv.Itoa(i))
		s.SetCurrentProcessPID(1000 + i)
		unlock()
	}
	stop.Store(true)
	wg.Wait()

	if n := bad.Load(); n != 0 {
		t.Fatalf("observed %d torn (commandID, pid) snapshots; combined getter is not atomic", n)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/session/ -run TestCurrentCommandAttribution_AtomicSnapshot -v`
Expected: FAIL — compile error: `s.CurrentCommandAttribution undefined`.

- [ ] **Step 3: Write the minimal implementation**

In `internal/session/manager.go`, add immediately after the `CurrentProcessPID` method (around line 381):

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

- [ ] **Step 4: Run the test to verify it passes (with the race detector)**

Run: `go test -race ./internal/session/ -run TestCurrentCommandAttribution_AtomicSnapshot -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/session/manager.go internal/session/manager_attribution_test.go
git commit -m "feat(session): atomic CurrentCommandAttribution getter

Reads (commandID, pid) under one lock so audit events can't observe a torn
pair across a command start/release boundary. Additive; existing getters remain."
```

---

### Task 2: Adopt the combined getter and thread `pid` into bypass events

**Files:**
- Modify: `internal/netmonitor/transparent_tcp.go` (handle ~110-116, bypass site :163)
- Modify: `internal/netmonitor/dns.go` (handle ~94-100)
- Modify: `internal/netmonitor/proxy.go` (handleHTTP ~326-332 + sites :363,:414; handleConnect ~159-163 + sites :194,:241)
- Test: `internal/netmonitor/proxy_test.go`

**Interfaces:**
- Consumes: `Session.CurrentCommandAttribution() (commandID string, pid int)` from Task 1.
- Produces: the 5 `emitDBBypassAttempt` call sites pass the real `pid` instead of `0`.

- [ ] **Step 1: Write the failing tests**

Append to `internal/netmonitor/proxy_test.go`. First the IP-based DB-unavoidability engine (literal-IP domain so `resolveAndEmitDNS`/`CheckNetworkCtx` skip DNS — non-flaky, no network):

```go
// newDBUnavoidabilityIPEngine builds a DB-unavoidability engine whose deny
// rules match a literal IP (127.0.0.1) so handler tests never perform a real
// DNS lookup. The 5432 rule is for handleConnect (CONNECT), the 80 rule for
// handleHTTP (plain HTTP).
func newDBUnavoidabilityIPEngine(t *testing.T) *policy.Engine {
	t.Helper()
	p := &policy.Policy{
		Version: 1,
		Name:    "test-db-unavoidability-ip",
		Metadata: []policy.RuleMetadata{
			{RuleName: "db-appdb-deny-direct", Source: dbservice.RuleSourceDBUnavoidability, DBService: "appdb", BypassMode: dbservice.BypassModeTCPDirect, Destination: "127.0.0.1:5432"},
			{RuleName: "db-appdb-deny-http", Source: dbservice.RuleSourceDBUnavoidability, DBService: "appdb", BypassMode: dbservice.BypassModeTCPDirect, Destination: "127.0.0.1:80"},
		},
		NetworkRules: []policy.NetworkRule{
			{Name: "db-appdb-deny-direct", Domains: []string{"127.0.0.1"}, Ports: []int{5432}, Decision: "deny", Message: "Direct database egress is blocked; use the AgentSH DB proxy"},
			{Name: "db-appdb-deny-http", Domains: []string{"127.0.0.1"}, Ports: []int{80}, Decision: "deny", Message: "Direct database egress is blocked; use the AgentSH DB proxy"},
		},
	}
	engine, err := policy.NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return engine
}

// TestProxyHandleConnect_DBBypassCarriesCommandPID drives a CONNECT to a
// DB-unavoidability-denied target through handleConnect and asserts the
// db_bypass_attempt event carries the session's command PID, not 0.
func TestProxyHandleConnect_DBBypassCarriesCommandPID(t *testing.T) {
	engine := newDBUnavoidabilityIPEngine(t)
	sess := &session.Session{ID: "sess-bypass"}
	sess.SetCurrentCommandID("cmd-bypass")
	sess.SetCurrentProcessPID(4242)

	capture := &captureDBBypassEmitter{}
	p := &Proxy{sessionID: "sess-bypass", sess: sess, policy: engine, emit: &stubEmitter{}}
	p.SetDBBypassEmitter(dbevents.NewBypassEmitter(capture))

	req := &http.Request{Method: "CONNECT", Host: "127.0.0.1:5432"}

	client, server := net.Pipe()
	go io.Copy(io.Discard, client) // drain the 403 so the handler's write never blocks
	done := make(chan struct{})
	go func() {
		_ = p.handleConnect(server, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleConnect did not return")
	}
	client.Close()

	if len(capture.events) != 1 {
		t.Fatalf("db bypass events = %d, want 1 (events: %+v)", len(capture.events), capture.events)
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" {
		t.Fatalf("event type = %q, want db_bypass_attempt", ev.Type)
	}
	if ev.PID != 4242 {
		t.Fatalf("bypass event PID = %d, want 4242", ev.PID)
	}
	if ev.Fields["rule_name"] != "db-appdb-deny-direct" {
		t.Fatalf("rule_name = %v, want db-appdb-deny-direct", ev.Fields["rule_name"])
	}
}

// TestProxyHandleHTTP_DBBypassCarriesCommandPID drives a plain-HTTP GET to a
// DB-unavoidability-denied target through handleHTTP and asserts the
// db_bypass_attempt event carries the session's command PID, not 0.
func TestProxyHandleHTTP_DBBypassCarriesCommandPID(t *testing.T) {
	engine := newDBUnavoidabilityIPEngine(t)
	sess := &session.Session{ID: "sess-bypass"}
	sess.SetCurrentCommandID("cmd-bypass")
	sess.SetCurrentProcessPID(4242)

	capture := &captureDBBypassEmitter{}
	p := &Proxy{sessionID: "sess-bypass", sess: sess, policy: engine, emit: &stubEmitter{}}
	p.SetDBBypassEmitter(dbevents.NewBypassEmitter(capture))

	req := httptest.NewRequest("GET", "http://127.0.0.1/", nil)

	client, server := net.Pipe()
	go io.Copy(io.Discard, client) // drain the 403 so the handler's write never blocks
	done := make(chan struct{})
	go func() {
		_ = p.handleHTTP(server, req)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleHTTP did not return")
	}
	client.Close()

	if len(capture.events) != 1 {
		t.Fatalf("db bypass events = %d, want 1 (events: %+v)", len(capture.events), capture.events)
	}
	ev := capture.events[0]
	if ev.Type != "db_bypass_attempt" {
		t.Fatalf("event type = %q, want db_bypass_attempt", ev.Type)
	}
	if ev.PID != 4242 {
		t.Fatalf("bypass event PID = %d, want 4242", ev.PID)
	}
	if ev.Fields["rule_name"] != "db-appdb-deny-http" {
		t.Fatalf("rule_name = %v, want db-appdb-deny-http", ev.Fields["rule_name"])
	}
}
```

Note: `proxy_test.go` already imports `context`, `io`, `net`, `net/http`, `net/http/httptest`, `testing`, `time`, `policy`, `dbevents`, `session`, `types`. Confirm during the run that `net/http/httptest` and `dservice` are imported; add any missing imports (`net/http`, `net/http/httptest`, `internal/db/events`/`dbevents`, `internal/dbservice` as the existing `newNetmonitorDBUnavoidabilityEngine` helper already uses them).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/netmonitor/ -run 'TestProxyHandleConnect_DBBypassCarriesCommandPID|TestProxyHandleHTTP_DBBypassCarriesCommandPID' -v`
Expected: FAIL — `bypass event PID = 0, want 4242` (the call sites pass literal `0`; `handleConnect` does not even read `pid` yet).

- [ ] **Step 3: Adopt the combined getter at the 3 read sites**

In `internal/netmonitor/transparent_tcp.go`, replace (handle, ~line 114-116):

```go
	commandID := ""
	pid := 0
	if t.sess != nil {
		commandID = t.sess.CurrentCommandID()
		pid = t.sess.CurrentProcessPID() // command-process PID; reused by the relay_ip/socks_port emit below
	}
```

with:

```go
	commandID, pid := "", 0
	if t.sess != nil {
		commandID, pid = t.sess.CurrentCommandAttribution() // atomic snapshot; pid reused by the relay_ip/socks_port emit below
	}
```

In `internal/netmonitor/dns.go`, replace (handle, ~line 98-100):

```go
	commandID := ""
	pid := 0
	if d.sess != nil {
		commandID = d.sess.CurrentCommandID()
		pid = d.sess.CurrentProcessPID() // command-process PID, not necessarily the leaf caller
	}
```

with:

```go
	commandID, pid := "", 0
	if d.sess != nil {
		commandID, pid = d.sess.CurrentCommandAttribution() // atomic snapshot
	}
```

In `internal/netmonitor/proxy.go` `handleHTTP`, replace (~line 328-332):

```go
	commandID := ""
	pid := 0
	if p.sess != nil {
		commandID = p.sess.CurrentCommandID()
		pid = p.sess.CurrentProcessPID() // command-process PID, not necessarily the leaf caller
	}
```

with:

```go
	commandID, pid := "", 0
	if p.sess != nil {
		commandID, pid = p.sess.CurrentCommandAttribution() // atomic snapshot
	}
```

In `internal/netmonitor/proxy.go` `handleConnect`, replace (~line 161-163):

```go
	commandID := ""
	if p.sess != nil {
		commandID = p.sess.CurrentCommandID()
	}
```

with:

```go
	commandID, pid := "", 0
	if p.sess != nil {
		commandID, pid = p.sess.CurrentCommandAttribution() // atomic snapshot; pid threads into db_bypass events
	}
```

- [ ] **Step 4: Thread `pid` into the 5 bypass call sites**

Replace the literal `0` with `pid` at each site. Each site is shown with enough surrounding context to be unique.

`internal/netmonitor/transparent_tcp.go` (handle deny, ~line 163):

```go
	if dec.EffectiveDecision == types.DecisionDeny {
		t.emitDBBypassAttempt(context.Background(), commandID, pid, dec.Rule, dec.Message)
		return nil
	}
```

`internal/netmonitor/proxy.go` `handleConnect` fail-closed http_service path (~line 194):

```go
			p.emitDBBypassAttempt(context.Background(), commandID, pid, failClosedDec.Rule, failClosedDec.Message)
			p.emitHTTPServiceDeniedDirect(context.Background(), commandID, svcName, envVar, host, "", "CONNECT")
			return nil
```

`internal/netmonitor/proxy.go` `handleConnect` deny path (~line 241):

```go
	if dec.EffectiveDecision == types.DecisionDeny {
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\n\r\n")
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		p.emitDBBypassAttempt(context.Background(), commandID, pid, dec.Rule, dec.Message)
		return nil
	}
```

`internal/netmonitor/proxy.go` `handleHTTP` fail-closed http_service path (~line 363):

```go
			p.emitDBBypassAttempt(context.Background(), commandID, pid, failClosedDec.Rule, failClosedDec.Message)
			p.emitHTTPServiceDeniedDirect(context.Background(), commandID, svcName, envVar, host, "", req.Method)
			return nil
```

`internal/netmonitor/proxy.go` `handleHTTP` deny path (~line 414):

```go
	if dec.EffectiveDecision == types.DecisionDeny {
		resp := "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\n\r\nblocked by policy\n"
		_, _ = io.WriteString(client, resp)
		_ = p.emit.AppendEvent(context.Background(), connectEv)
		p.emit.Publish(connectEv)
		p.emitDBBypassAttempt(context.Background(), commandID, pid, dec.Rule, dec.Message)
		return nil
	}
```

- [ ] **Step 5: Run the new tests to verify they pass**

Run: `go test ./internal/netmonitor/ -run 'TestProxyHandleConnect_DBBypassCarriesCommandPID|TestProxyHandleHTTP_DBBypassCarriesCommandPID' -v`
Expected: PASS.

- [ ] **Step 6: Run the full netmonitor + session suites (with race detector) and the Windows build check**

Run:
```bash
go test -race ./internal/netmonitor/ ./internal/session/ -v
GOOS=windows go build ./...
```
Expected: all PASS, Windows build succeeds. The pre-existing PID assertions (`TestProxyHandleHTTPOnionRemapsVectorToOnionHTTP` expects PID 4242, `TestDNSInterceptor_OnionEmitsTorControl`, `TestHandleTorSocks_*`, `TestTransparentTCP_TorControlCarriesCommandPID`) still pass — the combined getter returns the same values they set. The direct-call `TestProxyEmitDBBypassAttempt`/`TestTransparentTCPEmitDBBypassAttempt` still pass — they call `emitDBBypassAttempt` directly with literal `0` (unchanged).

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/transparent_tcp.go internal/netmonitor/dns.go internal/netmonitor/proxy.go internal/netmonitor/proxy_test.go
git commit -m "fix(netmonitor): attribute db_bypass_attempt to command PID via atomic getter

Adopt Session.CurrentCommandAttribution() at the 3 interception read sites
and pass the real pid (not 0) at all 5 emitDBBypassAttempt call sites.
handleConnect now reads pid too. Closes torn-pair and bypass-attribution gaps."
```

---

### Task 3: SOCKS handshake read deadline (slowloris)

**Files:**
- Modify: `internal/netmonitor/socks.go` (add `socksHandshakeTimeout` var; set/clear deadline in `handleTorSocks` ~line 140)
- Test: `internal/netmonitor/socks_handler_test.go`

**Interfaces:**
- Consumes: none new.
- Produces: `socksHandshakeTimeout` (package-level `var`, overridable in tests).

- [ ] **Step 1: Add the handshake-timeout variable**

In `internal/netmonitor/socks.go`, in the `const (...)` block, the timeout cannot be a `const` (tests must override it). Add a package-level `var` just above `readSocksGreeting`:

```go
// socksHandshakeTimeout bounds the client-side SOCKS5 handshake reads in
// handleTorSocks so a stalled client cannot hold a gateway goroutine + fd
// indefinitely (slowloris). It is a var (not const) so tests can shorten it.
var socksHandshakeTimeout = 10 * time.Second
```

- [ ] **Step 2: Write the failing test**

Append to `internal/netmonitor/socks_handler_test.go`:

```go
// TestHandleTorSocks_HandshakeDeadlineStallsSlowClient verifies a client that
// sends only the greeting then stalls causes handleTorSocks to return within
// the handshake deadline (rather than blocking forever on readSocksRequest),
// emitting no event. net.Pipe honors SetReadDeadline, so no real TCP listener
// is needed.
func TestHandleTorSocks_HandshakeDeadlineStallsSlowClient(t *testing.T) {
	orig := socksHandshakeTimeout
	socksHandshakeTimeout = 100 * time.Millisecond
	t.Cleanup(func() { socksHandshakeTimeout = orig })

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}

	go io.Copy(io.Discard, client) // drain handler writes so they never block
	done := make(chan struct{})
	go func() {
		// upstreamAddr is unreachable on purpose; a stalled handshake must never dial it.
		_ = handleTorSocks(server, "127.0.0.1:1", fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
		close(done)
	}()

	// Send only the greeting, then stall — readSocksRequest must time out.
	if _, err := client.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTorSocks did not return after stalled handshake (no read deadline on handshake)")
	}
	client.Close()

	if len(emit.events()) != 0 {
		t.Fatalf("stalled handshake emitted %d events, want 0", len(emit.events()))
	}
}
```

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/netmonitor/ -run TestHandleTorSocks_HandshakeDeadlineStallsSlowClient -v`
Expected: FAIL — `handleTorSocks did not return after stalled handshake` (without the deadline, `readSocksRequest` blocks forever; the 2s select fires).

- [ ] **Step 4: Implement the deadline set/clear in handleTorSocks**

In `internal/netmonitor/socks.go`, replace the start of `handleTorSocks` (currently):

```go
func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, pid int) error {
	defer conn.Close()

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

with:

```go
func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, pid int) error {
	defer conn.Close()

	// Bound the client handshake against slow/stalled clients (slowloris).
	// Cleared before the tunnel/relay so long-lived CONNECT streams are
	// unaffected. The error is ignored: some conns (net.Pipe in tests, wrapped
	// conns) do not honor deadlines, in which case the conn simply stays
	// unbounded — no worse than today.
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

- [ ] **Step 5: Run the slowloris test to verify it passes**

Run: `go test ./internal/netmonitor/ -run TestHandleTorSocks_HandshakeDeadlineStallsSlowClient -v`
Expected: PASS — `handleTorSocks` returns ~100ms after the greeting, with 0 events.

- [ ] **Step 6: Run the full netmonitor suite (race) and the Windows build check**

Run:
```bash
go test -race ./internal/netmonitor/ -v
GOOS=windows go build ./...
```
Expected: all PASS, Windows build succeeds. Existing `TestHandleTorSocks_*` tests still pass — they complete the handshake quickly under the 10s default deadline, and the deadline is cleared before `splice`/relay.

- [ ] **Step 7: Commit**

```bash
git add internal/netmonitor/socks.go internal/netmonitor/socks_handler_test.go
git commit -m "fix(netmonitor): bound SOCKS gateway handshake against slowloris

Set a client read deadline around the SOCKS5 handshake in handleTorSocks and
clear it before the tunnel/relay so long-lived CONNECT streams are unaffected.
Upstream (trusted loopback Tor) unchanged."
```

---

## Out of scope (do not implement)

- Launch-window `(commandID=cmd-B, pid=0)` state — stays as honest "process not yet started" state (the PID genuinely does not exist pre-`cmd.Start()`).
- `net_connect`/`net_close` `PID=0` (review Minor #8 — `netEvent`/`emitNetEvent` omit `PID`) — separate change.
- All review Minor items #4–#10 (0xF1 test, malformed→0x01 test, reply-code oracle, unsupported-command audit visibility, `EvalSocksTarget` target normalization, non-IPv4 RESOLVE reply coverage).
