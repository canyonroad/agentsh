# Onion / Connection-Vector Event PID Attribution — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hardcoded `pid: 0` in the four transparent-interception-path `tor_control` events with the session's current command-process PID.

**Architecture:** Each interception point already holds a `*session.Session` and already reads `sess.CurrentCommandID()`; it additionally reads `sess.CurrentProcessPID()` and passes it where it currently passes the literal `0` to `tor.BuildControlEvent`. The SOCKS gateway path threads a new `pid int` parameter through `handleTorSocks → gatewayConnect/gatewayResolve → emitOnionEvent`. No new event type, config knob, or data path.

**Tech Stack:** Go; `internal/netmonitor` (interceptors), `internal/session` (PID source), `internal/tor` (event builder, unchanged), `internal/policy` (`TorVerdict`).

## Global Constraints

- **No new `events.EventType`** — reuse the existing `"tor_control"` event; the OCSF registry stays untouched.
- **No new config knobs and no new data path** — behaviour derives entirely from existing session state.
- **`tor.BuildControlEvent(sessionID, commandID string, pid int, v tor.Verdict)` is unchanged** — it already accepts and stamps `pid`. Only callers change.
- **Honest semantics:** the value is the session's *current command-process PID* (root of the running command's process tree), not necessarily the exact leaf caller. Each emission site carries a short comment saying so.
- **Idle session:** when no command is running, `CurrentProcessPID()` returns `0` and `CurrentCommandID()` returns `""`; emit `pid: 0` honestly. No special-casing.
- **Cross-compile must stay clean:** `GOOS=windows go build ./...` (per AGENTS.md / CLAUDE.md).
- **PID value used in all tests:** `4242` (arbitrary non-zero sentinel), `0` for idle-case tests.

---

## File Structure

- `internal/netmonitor/socks.go` — add `pid int` to `handleTorSocks`, `gatewayConnect`, `gatewayResolve`, `emitOnionEvent`; pass it to `BuildControlEvent`. (Task 1)
- `internal/netmonitor/transparent_tcp.go` — in `handleConn`, read `pid` once next to the existing `commandID` read; pass it to `handleTorSocks` (Task 1); reuse it for the `relay_ip`/`socks_port` emission, extracted into a small `emitTorControl` method (Task 2).
- `internal/netmonitor/dns.go` — read `pid` next to `commandID` in `handle`; pass at the `onion_dns` emission. (Task 3)
- `internal/netmonitor/proxy.go` — read `pid` next to `commandID` in `handleHTTP`; pass at the `onion_http` emission. (Task 4)
- Tests: `socks_handler_test.go` (Task 1), `transparent_tcp_test.go` (Task 2), `dns_test.go` (Task 3), `proxy_test.go` (Task 4).
- `docs/superpowers/specs/2026-06-22-onion-event-pid-attribution-design.md` — status + a verification note. (Task 5)

Reference facts (verified against the tree at base `7dccbb35`):
- `internal/session/manager.go:379` — `func (s *Session) CurrentProcessPID() int`. The setter is `SetCurrentProcessPID(pid int)` (`:373`); `LockExec`'s release closure clears `currentProcPID = 0` (`:351`), so idle ⇒ `0`.
- `dec.Tor` is of type `*policy.TorVerdict` (`internal/policy/engine.go:166`), with fields `Vector, Mode, Decision, Target`.
- All test emitters live in `package netmonitor` (white-box) and are mutually visible: `captureEmitter` (`dns_test.go:15`, has `.events []types.Event`), `stubEmitter` (`proxy_test.go:24`, has `.events`), `torCaptureEmitter` (`socks_handler_test.go:29`).
- A `*session.Session` is constructible in tests as `&session.Session{ID: "s"}` (see `proxy_test.go:651`); call `sess.SetCurrentProcessPID(4242)` on it.

---

### Task 1: SOCKS onion gateway events carry the command PID

**Files:**
- Modify: `internal/netmonitor/socks.go` (`handleTorSocks` `:140`, `gatewayConnect` `:173`, `gatewayResolve` `:301`, `emitOnionEvent` `:337`)
- Modify: `internal/netmonitor/transparent_tcp.go` (`handleConn`, the `commandID` read `:112-115` and the `handleTorSocks` call `:119`)
- Test: `internal/netmonitor/socks_handler_test.go`

**Interfaces:**
- Consumes: `session.Session.CurrentProcessPID() int`; `tor.BuildControlEvent(sessionID, commandID string, pid int, v tor.Verdict)`.
- Produces: new signatures used by later tasks reading from the same `handleConn`:
  - `handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, pid int) error`
  - `emitOnionEvent(emit Emitter, sessionID, commandID string, pid int, v tor.Verdict, socksCmd string)`
  - In `transparent_tcp.go handleConn`, a local `pid int` read once next to `commandID` (Task 2 reuses it).

- [ ] **Step 1: Update the test helper and call sites to assert PID (fails to compile → drives the change)**

In `internal/netmonitor/socks_handler_test.go`, change `assertOnionEvent` to take a wanted PID and assert it:

```go
func assertOnionEvent(t *testing.T, emit *torCaptureEmitter, wantDecision, wantCmd string, wantPID int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range emit.events() {
			if ev.Type == "tor_control" && ev.Fields["vector"] == tor.VectorOnion {
				if ev.Fields["decision"] != wantDecision {
					t.Fatalf("event decision = %v, want %v", ev.Fields["decision"], wantDecision)
				}
				if ev.Fields["socks_cmd"] != wantCmd {
					t.Fatalf("event socks_cmd = %v, want %v", ev.Fields["socks_cmd"], wantCmd)
				}
				if ev.PID != wantPID {
					t.Fatalf("event PID = %d, want %d", ev.PID, wantPID)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no tor_control{vector:onion,decision:%s,socks_cmd:%s} event seen", wantDecision, wantCmd)
}
```

Update all 7 `assertOnionEvent(...)` call sites to pass `4242` as the final arg (lines ~166, 184, 220, 282, 492, 509, 536): e.g. `assertOnionEvent(t, emit, "allow", "connect", 4242)` and `assertOnionEvent(t, emit, "deny", "resolve", 4242)`.

Update all 8 `handleTorSocks(...)` call sites (lines ~147, 176, 200, 263, 295, 476, 502, 524) to pass `4242` as the final arg, e.g.:

```go
_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
```

Add an idle-session test (new PID-0 path) at the end of the file:

```go
func TestHandleTorSocks_IdleSessionPIDZero(t *testing.T) {
	upstream, stop := fakeTorUpstream(t)
	defer stop()
	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	go func() {
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "", 0)
	}()
	if rep := driveClient(t, client, "ok.onion", 443); rep != 0x00 {
		t.Fatalf("rep = 0x%02x, want 0x00", rep)
	}
	assertOnionEvent(t, emit, "allow", "connect", 0)
	client.Close()
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `go test ./internal/netmonitor/ -run TestHandleTorSocks -count=1`
Expected: FAIL — compile error, `handleTorSocks`/`emitOnionEvent` called with too many arguments.

- [ ] **Step 3: Thread `pid` through `socks.go`**

In `internal/netmonitor/socks.go`:

`handleTorSocks` signature and its two dispatch calls:

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

`gatewayConnect` signature + its `emitOnionEvent` call (leave the rest of the body unchanged):

```go
func gatewayConnect(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, pid int, req socksReq) error {
	v, ok := pol.EvalSocksTarget(req.host, req.port)
	if ok {
		emitOnionEvent(emit, sessionID, commandID, pid, v, "connect")
	}
	// ... unchanged ...
```

`gatewayResolve` signature + its `emitOnionEvent` call (leave the rest unchanged):

```go
func gatewayResolve(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, pid int, req socksReq) error {
	v, ok := pol.EvalSocksTarget(req.host, req.port)
	if ok {
		emitOnionEvent(emit, sessionID, commandID, pid, v, "resolve")
	}
	// ... unchanged ...
```

`emitOnionEvent` — accept `pid` and pass it to the builder:

```go
func emitOnionEvent(emit Emitter, sessionID, commandID string, pid int, v tor.Verdict, socksCmd string) {
	if emit == nil {
		return
	}
	// pid is the session's current command-process PID (root of the running
	// command's process tree), not necessarily the exact leaf caller.
	ev := tor.BuildControlEvent(sessionID, commandID, pid, v)
	ev.Fields["socks_cmd"] = socksCmd
	_ = emit.AppendEvent(context.Background(), ev)
	emit.Publish(ev)
}
```

- [ ] **Step 4: Update the production call site in `transparent_tcp.go`**

In `internal/netmonitor/transparent_tcp.go`, `handleConn`, replace the `commandID` read block (`:112-115`) and the `handleTorSocks` call (`:119`):

```go
	commandID := ""
	pid := 0
	if t.sess != nil {
		commandID = t.sess.CurrentCommandID()
		pid = t.sess.CurrentProcessPID() // command-process PID; reused by the relay_ip/socks_port emit below
	}
	engine := t.policyEngine()

	if cfg, ok := t.torGatewayFor(dstPort); ok {
		return handleTorSocks(conn, cfg.upstream, cfg.pol, t.emit, t.sessionID, commandID, pid)
	}
```

- [ ] **Step 5: Run the SOCKS tests to verify they pass**

Run: `go test ./internal/netmonitor/ -run 'TestHandleTorSocks|TestReadSocksRequest|TestSplice' -count=1`
Expected: PASS (all gateway tests, including `TestHandleTorSocks_IdleSessionPIDZero`).

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/socks.go internal/netmonitor/transparent_tcp.go internal/netmonitor/socks_handler_test.go
git commit -m "feat(tor): onion SOCKS gateway events carry the command-process PID"
```

---

### Task 2: relay_ip / socks_port event carries the command PID

**Files:**
- Modify: `internal/netmonitor/transparent_tcp.go` (extract `emitTorControl`; replace the inline emission `:142-148`; reuse the `pid` local from Task 1)
- Test: `internal/netmonitor/transparent_tcp_test.go`

**Interfaces:**
- Consumes: the `pid int` local introduced in `handleConn` by Task 1; `dec.Tor` of type `*policy.TorVerdict`.
- Produces: `func (t *TransparentTCP) emitTorControl(commandID string, pid int, tv *policy.TorVerdict)`.

- [ ] **Step 1: Write the failing test**

Add to `internal/netmonitor/transparent_tcp_test.go` (the package already imports `policy` and `types`; add `captureEmitter` is defined in `dns_test.go`, same package):

```go
func TestTransparentTCP_TorControlCarriesCommandPID(t *testing.T) {
	em := &captureEmitter{}
	tcp := &TransparentTCP{sessionID: "s", emit: em}
	tcp.emitTorControl("cmd-1", 4242, &policy.TorVerdict{
		Vector: "relay_ip", Mode: "deny", Decision: "deny", Target: "10.0.0.1:443",
	})
	if len(em.events) != 1 {
		t.Fatalf("want 1 event, got %d", len(em.events))
	}
	ev := em.events[0]
	if ev.Type != "tor_control" {
		t.Fatalf("type = %q, want tor_control", ev.Type)
	}
	if ev.PID != 4242 {
		t.Fatalf("PID = %d, want 4242", ev.PID)
	}
	if ev.Fields["vector"] != "relay_ip" {
		t.Fatalf("vector = %v, want relay_ip", ev.Fields["vector"])
	}
}

func TestTransparentTCP_TorControlIdlePIDZero(t *testing.T) {
	em := &captureEmitter{}
	tcp := &TransparentTCP{sessionID: "s", emit: em}
	tcp.emitTorControl("", 0, &policy.TorVerdict{
		Vector: "socks_port", Mode: "deny", Decision: "deny", Target: "127.0.0.1:9050",
	})
	if len(em.events) != 1 {
		t.Fatalf("want 1 event, got %d", len(em.events))
	}
	if em.events[0].PID != 0 {
		t.Fatalf("PID = %d, want 0", em.events[0].PID)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/netmonitor/ -run TestTransparentTCP_TorControl -count=1`
Expected: FAIL — `tcp.emitTorControl undefined`.

- [ ] **Step 3: Extract the method and call it with `pid`**

In `internal/netmonitor/transparent_tcp.go`, add the method (near `handleConn`):

```go
// emitTorControl publishes a tor_control event for a Tor verdict carried on a
// connect decision. pid is the session's current command-process PID (root of
// the running command's process tree), not necessarily the exact leaf caller.
func (t *TransparentTCP) emitTorControl(commandID string, pid int, tv *policy.TorVerdict) {
	if tv == nil || t.emit == nil {
		return
	}
	tev := tor.BuildControlEvent(t.sessionID, commandID, pid, tor.Verdict{
		Vector: tv.Vector, Mode: tv.Mode, Decision: tv.Decision, Target: tv.Target,
	})
	_ = t.emit.AppendEvent(context.Background(), tev)
	t.emit.Publish(tev)
}
```

Replace the inline emission block (`:142-148`) with a call that reuses the `pid` local from Task 1:

```go
	dec := t.checkConnectNetwork(context.Background(), commandID, domain, redirectHostPort, dstIP, dstPort, redirectResult)
	t.emitTorControl(commandID, pid, dec.Tor)
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/netmonitor/ -run TestTransparentTCP -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/transparent_tcp.go internal/netmonitor/transparent_tcp_test.go
git commit -m "feat(tor): relay_ip/socks_port event carries the command-process PID"
```

---

### Task 3: onion_dns event carries the command PID

**Files:**
- Modify: `internal/netmonitor/dns.go` (`handle`, the `commandID` read `:96-99` and the emission `:124`)
- Test: `internal/netmonitor/dns_test.go` (extend `TestDNSInterceptor_OnionEmitsTorControl`)

**Interfaces:**
- Consumes: `session.Session.CurrentProcessPID()`.
- Produces: nothing new; `onion_dns` event now carries `PID`.

- [ ] **Step 1: Extend the existing onion test to set a session PID and assert it**

In `internal/netmonitor/dns_test.go`, in `TestDNSInterceptor_OnionEmitsTorControl`, construct a session with a known PID and attach it to the interceptor, then assert the event PID. Change the `&DNSInterceptor{...}` literal (`:393-399`) to include `sess`, and add a PID assertion after the existing `vector`/`decision` checks:

```go
	sess := &session.Session{ID: "session-test"}
	sess.SetCurrentProcessPID(4242)

	em := &captureEmitter{}
	d := &DNSInterceptor{
		sessionID: "session-test",
		sess:      sess,
		pc:        serverPC,
		upstream:  up.LocalAddr().String(),
		emit:      em,
		policy:    engine,
	}
```

Add after the existing `decision` assertion (around `:417`):

```go
	if torEv.PID != 4242 {
		t.Errorf("event PID = %d, want 4242", torEv.PID)
	}
```

Ensure `dns_test.go` imports `"github.com/agentsh/agentsh/internal/session"` (add it to the import block if absent).

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/netmonitor/ -run TestDNSInterceptor_OnionEmitsTorControl -count=1`
Expected: FAIL — `event PID = 0, want 4242` (the interceptor still passes `0`).

- [ ] **Step 3: Read and pass `pid` in `dns.go`**

In `internal/netmonitor/dns.go`, `handle`, extend the `commandID` block (`:96-99`) and the emission (`:124`):

```go
	commandID := ""
	pid := 0
	if d.sess != nil {
		commandID = d.sess.CurrentCommandID()
		pid = d.sess.CurrentProcessPID() // command-process PID, not necessarily the leaf caller
	}
```

```go
	if dec.Tor != nil && d.emit != nil {
		tev := tor.BuildControlEvent(d.sessionID, commandID, pid, tor.Verdict{
			Vector: dec.Tor.Vector, Mode: dec.Tor.Mode, Decision: dec.Tor.Decision, Target: dec.Tor.Target,
		})
		_ = d.emit.AppendEvent(context.Background(), tev)
		d.emit.Publish(tev)
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/netmonitor/ -run TestDNSInterceptor -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/dns.go internal/netmonitor/dns_test.go
git commit -m "feat(tor): onion_dns event carries the command-process PID"
```

---

### Task 4: onion_http event carries the command PID

**Files:**
- Modify: `internal/netmonitor/proxy.go` (`handleHTTP`, the `commandID` read `:328-331` and the emission `:397`)
- Test: `internal/netmonitor/proxy_test.go` (extend `TestProxyHandleHTTPOnionRemapsVectorToOnionHTTP`)

**Interfaces:**
- Consumes: `session.Session.CurrentProcessPID()`.
- Produces: nothing new; `onion_http` event now carries `PID`.

- [ ] **Step 1: Extend the existing onion test to set a session PID and assert it**

In `internal/netmonitor/proxy_test.go`, in `TestProxyHandleHTTPOnionRemapsVectorToOnionHTTP`, attach a session with a known PID to the `&Proxy{...}` literal (`:845`) and assert the event PID. Change:

```go
	sess := &session.Session{ID: "tor-session"}
	sess.SetCurrentProcessPID(4242)

	em := &stubEmitter{}
	p := &Proxy{sessionID: "tor-session", sess: sess, policy: engine, emit: em}
```

Add after the existing `vector == "onion_http"` assertion (around `:893`):

```go
	if torEv.PID != 4242 {
		t.Fatalf("event PID = %d, want 4242", torEv.PID)
	}
```

`proxy_test.go` already imports `session` (it constructs `&session.Session{...}` elsewhere); no import change expected — confirm during implementation.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/netmonitor/ -run TestProxyHandleHTTPOnionRemapsVectorToOnionHTTP -count=1`
Expected: FAIL — `event PID = 0, want 4242`.

- [ ] **Step 3: Read and pass `pid` in `proxy.go`**

In `internal/netmonitor/proxy.go`, `handleHTTP`, extend the `commandID` block (`:328-331`) and the emission (`:397`):

```go
	commandID := ""
	pid := 0
	if p.sess != nil {
		commandID = p.sess.CurrentCommandID()
		pid = p.sess.CurrentProcessPID() // command-process PID, not necessarily the leaf caller
	}
```

```go
	if dec.Tor != nil && p.emit != nil {
		vector := dec.Tor.Vector
		if vector == tor.VectorOnionDNS {
			vector = tor.VectorOnionHTTP
		}
		tev := tor.BuildControlEvent(p.sessionID, commandID, pid, tor.Verdict{
			Vector: vector, Mode: dec.Tor.Mode, Decision: dec.Tor.Decision, Target: dec.Tor.Target,
		})
		_ = p.emit.AppendEvent(context.Background(), tev)
		p.emit.Publish(tev)
	}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/netmonitor/ -run TestProxyHandleHTTPOnion -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/proxy.go internal/netmonitor/proxy_test.go
git commit -m "feat(tor): onion_http event carries the command-process PID"
```

---

### Task 5: PID-namespace verification + spec status + full gates

**Files:**
- Modify: `docs/superpowers/specs/2026-06-22-onion-event-pid-attribution-design.md`

**Interfaces:**
- Consumes: nothing. Documentation + verification only.

- [ ] **Step 1: Verify the cross-reference claim (read-only)**

Confirm the command-process PID and the ptrace-path PID are in the same (host) PID namespace, so the two event families cross-reference on `pid`:
- `internal/api/exec.go:357` and `internal/api/exec_stream.go:434` — `SetCurrentProcessPID(cmd.Process.Pid)`; `cmd.Process.Pid` is the host PID of the spawned command (Go `os/exec`).
- `internal/api/pty_core.go:202` — `SetCurrentProcessPID(ps.PID())`; confirm `ps.PID()` is the host PID of the PTY process.
- The ptrace-path Tor events use `nc.PID` (`internal/.../ptrace_handlers.go`), the host PID delivered by the ptrace subsystem.

All are host-side PIDs observed by agentsh → the cross-reference holds.

- [ ] **Step 2: Record the finding and flip status in the spec**

In `docs/superpowers/specs/2026-06-22-onion-event-pid-attribution-design.md`, change `**Status:** Draft` to `**Status:** Implemented (PR pending)`, and replace the body of the "PID-namespace checkpoint (verify during implementation)" section with the confirmed result:

```markdown
## PID-namespace verification (confirmed)

`SetCurrentProcessPID` is called with `cmd.Process.Pid` (`internal/api/exec.go:357`,
`internal/api/exec_stream.go:434`) and `ps.PID()` (`internal/api/pty_core.go:202`)
— all host-side PIDs of the command process as agentsh observes it. The
ptrace-path Tor events use `nc.PID`, also a host-side PID from the ptrace
subsystem. Both event families therefore carry `pid` in the same namespace and
cross-reference cleanly.
```

- [ ] **Step 3: Run the full gates**

```bash
go build ./...
GOOS=windows go build ./...
gofmt -l internal/netmonitor internal/session
go test ./internal/netmonitor/ ./internal/session/ ./internal/tor/ -count=1
go test ./...
```

Expected: builds clean; `gofmt -l` lists none of the files this branch touched (`socks.go`, `transparent_tcp.go`, `dns.go`, `proxy.go`, and the four `*_test.go`); `internal/netmonitor`, `internal/session`, `internal/tor` green. In the full suite, the only acceptable failure is the known pre-existing `internal/fsmonitor` FUSE flake (and, when run alongside `internal/api`, the `internal/ocsf` exhaustiveness flake that passes standalone — this change adds no `events.EventType`). `internal/netmonitor` must be green.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-06-22-onion-event-pid-attribution-design.md
git commit -m "docs(tor): mark command-PID attribution implemented; record PID-namespace verification"
```

---

## Self-Review

**1. Spec coverage:**
- "All four interception-path sites" → Task 1 (socks/onion), Task 2 (relay_ip/socks_port), Task 3 (onion_dns), Task 4 (onion_http). ✅
- "thread `sess.CurrentProcessPID()`" → Tasks 1–4. ✅
- "no new event type / config / data path" → Global Constraints; `BuildControlEvent` unchanged. ✅
- "honest semantics comment at each site" → comments in Tasks 1–4. ✅
- "idle-session pid 0" → `TestHandleTorSocks_IdleSessionPIDZero` (Task 1), `TestTransparentTCP_TorControlIdlePIDZero` (Task 2). ✅
- "per-site unit tests" → Tasks 1–4 each add/extend a test. ✅
- "PID-namespace checkpoint" → Task 5. ✅
- "reject eBPF leaf attribution" → out of scope; not built. ✅

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code. ✅

**3. Type consistency:** `pid int` appended consistently to `handleTorSocks`/`gatewayConnect`/`gatewayResolve`/`emitOnionEvent`; `emitTorControl(commandID string, pid int, tv *policy.TorVerdict)` matches `dec.Tor`'s type; `CurrentProcessPID()`/`SetCurrentProcessPID(int)` match `internal/session/manager.go`; test PID sentinel `4242` used uniformly. ✅
