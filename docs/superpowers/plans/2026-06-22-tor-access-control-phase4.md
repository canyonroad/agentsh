# Tor Access Control — Phase 4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the onion gateway command-aware — filter-and-forward SOCKS `RESOLVE` (0xF0) through `onion_rules`, and reject `RESOLVE_PTR` (0xF1) and all other non-CONNECT commands with the correct SOCKS `command not supported` (0x07).

**Architecture:** Generalize the existing single-command `handleTorSocks` in `internal/netmonitor/socks.go` into a command-aware dispatcher. A generic `readSocksRequest` captures the command byte; the handler switches on it — CONNECT keeps its existing tunnel path, RESOLVE filters via the same `EvalSocksTarget` then forwards the request and relays the single reply (no splice), and everything else gets `0x07`. The shared upstream SOCKS handshake is factored into one helper. Audit events gain a `socks_cmd` field set in `emitOnionEvent`.

**Tech Stack:** Go; SOCKS5 (RFC 1928) + Tor's RESOLVE extension; existing `internal/netmonitor` SOCKS front-end and `internal/tor` policy/event packages.

## Global Constraints

- No new `events.EventType` — reuse the existing `tor_control` event (`Type: "tor_control"`); the OCSF registry stays untouched.
- No new config knobs — behavior derives from existing `onion_rules` / `socks_ports`; gateway activation (`GatewayActive()`) is unchanged.
- No new data path — CONNECT's tunnel behavior is unchanged; RESOLVE is request/reply (no `splice`).
- `RESOLVE` (0xF0): filter through `onion_rules` exactly like CONNECT; allowed → forward + relay single reply; denied/unmatched → `not allowed` (0x02), fail-closed.
- `RESOLVE_PTR` (0xF1) and every other non-CONNECT/non-RESOLVE command → `command not supported` (0x07); no upstream dial; no event.
- Fail-closed parity: any parse/dial/upstream error → `general failure` (0x01); denied target → `not allowed` (0x02).
- Audit: one `tor_control{vector: onion}` event per evaluated request, with `Fields["socks_cmd"]` = `"connect"` or `"resolve"`; RESOLVE_PTR / unsupported commands emit none.
- Cross-compile clean: `GOOS=windows go build ./...` must stay green.

---

### Task 1: Command-aware dispatch + correct unsupported-command handling

Generalize the parser/encoder, split the CONNECT body into `gatewayConnect`, add the command switch (RESOLVE still rejected with `0x07` here — it becomes a real branch in Task 2), factor the upstream handshake into `upstreamHandshake`, and add `socks_cmd: "connect"` to CONNECT events. Net behavior change: non-CONNECT commands now get the correct `0x07` instead of a misleading `general failure`, and CONNECT events carry `socks_cmd`.

**Files:**
- Modify: `internal/netmonitor/socks.go`
- Test: `internal/netmonitor/socks_handler_test.go`

**Interfaces:**
- Consumes (existing, unchanged): `readSocksGreeting`, `writeSocksMethod`, `writeSocksReply`, `readSocksReply`, `splice`, `TorGatewayPolicy.EvalSocksTarget(host string, port int) (tor.Verdict, bool)`, `tor.BuildControlEvent(sessionID, commandID string, pid int, v tor.Verdict) types.Event`, `Emitter`.
- Produces (for Task 2): `readSocksRequest(r io.Reader) (socksReq, error)` (sets `socksReq.cmd`), `encodeReq(req socksReq) []byte`, `upstreamHandshake(up net.Conn) error`, `gatewayConnect(...)`, `emitOnionEvent(emit Emitter, sessionID, commandID string, v tor.Verdict, socksCmd string)`, and the constants `socksCmdResolve = 0xF0`, `socksCmdResolvePtr = 0xF1`, `socksRepCmdNotSupported = 0x07`. `socksReq` gains a `cmd byte` field.

- [ ] **Step 1: Write the failing tests**

Add to `internal/netmonitor/socks_handler_test.go`. These replace the decision-only `assertOneOnionEvent` with a command-aware `assertOnionEvent` and add an unsupported-command test.

```go
// assertOnionEvent waits for one tor_control{vector:onion} event and asserts
// both its decision and its socks_cmd field.
func assertOnionEvent(t *testing.T, emit *torCaptureEmitter, wantDecision, wantCmd string) {
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
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no tor_control{vector:onion,decision:%s,socks_cmd:%s} event seen", wantDecision, wantCmd)
}

// driveCmd sends a SOCKS5 request with an explicit command byte and returns the
// reply's REP code (reply is the fixed 10-byte IPv4-form reply for the cases
// exercised here).
func driveCmd(t *testing.T, conn net.Conn, cmd byte, host string, port int) byte {
	t.Helper()
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // greeting
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(encodeReq(socksReq{cmd: cmd, atyp: atypDomain, addr: []byte(host), host: host, port: port}))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

// TestHandleTorSocks_UnsupportedCommand verifies a non-CONNECT/non-RESOLVE
// command (here BIND 0x02) gets command-not-supported (0x07), no upstream dial,
// and emits no event.
func TestHandleTorSocks_UnsupportedCommand(t *testing.T) {
	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		// upstreamAddr is unreachable on purpose; it must never be dialed.
		_ = handleTorSocks(server, "127.0.0.1:1", fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()
	rep := driveCmd(t, client, 0x02 /* BIND */, "ok.onion", 443)
	if rep != socksRepCmdNotSupported {
		t.Fatalf("BIND got reply 0x%02x, want command-not-supported (0x%02x)", rep, socksRepCmdNotSupported)
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTorSocks did not return for unsupported command")
	}
	if len(emit.events()) != 0 {
		t.Fatalf("unsupported command emitted %d events, want 0", len(emit.events()))
	}
}
```

Also update the existing `assertOneOnionEvent` call sites (in `TestHandleTorSocks_Allowed`, `TestHandleTorSocks_Denied`, `TestHandleTorSocks_UpstreamRefuses`, `TestHandleTorSocks_UpstreamRequiresAuth`) to the new `assertOnionEvent` with the `"connect"` command, and delete the old `assertOneOnionEvent` helper:
- `assertOneOnionEvent(t, emit, "allow")` → `assertOnionEvent(t, emit, "allow", "connect")`
- `assertOneOnionEvent(t, emit, "deny")` → `assertOnionEvent(t, emit, "deny", "connect")`

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/netmonitor/ -run 'TestHandleTorSocks' -v`
Expected: compile failure — `encodeReq`, `socksRepCmdNotSupported`, `socksReq.cmd`, and `assertOnionEvent` are undefined.

- [ ] **Step 3: Generalize the constants, request struct, parser, and encoder in `socks.go`**

Replace the constant block (lines 14-25) with:

```go
// SOCKS5 reply / command codes (RFC 1928) and Tor's RESOLVE extension.
const (
	socksVer                = 0x05
	socksCmdConnect         = 0x01
	socksCmdResolve         = 0xF0 // Tor RESOLVE extension
	socksCmdResolvePtr      = 0xF1 // Tor RESOLVE_PTR extension (deliberately unsupported)
	socksRepSuccess         = 0x00
	socksRepGeneralFailure  = 0x01
	socksRepNotAllowed      = 0x02 // connection not allowed by ruleset
	socksRepCmdNotSupported = 0x07 // command not supported

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)
```

Add the `cmd` field to `socksReq`:

```go
type socksReq struct {
	cmd  byte
	atyp byte
	addr []byte // raw address bytes (domain text, or 4/16-byte IP)
	host string
	port int
}
```

Rename `readSocksConnect` to `readSocksRequest` and capture the command byte without judging it (the handler dispatches on it):

```go
// readSocksRequest reads a SOCKS5 request: VER CMD RSV ATYP ADDR PORT. The
// command byte is captured verbatim into req.cmd; the caller dispatches on it
// (CONNECT and RESOLVE are handled, others get command-not-supported).
func readSocksRequest(r io.Reader) (socksReq, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(r, head); err != nil {
		return socksReq{}, err
	}
	if head[0] != socksVer {
		return socksReq{}, fmt.Errorf("socks: bad version 0x%02x", head[0])
	}
	var req socksReq
	req.cmd = head[1]
	req.atyp = head[3]
	switch req.atyp {
	case atypIPv4:
		req.addr = make([]byte, 4)
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = net.IP(req.addr).String()
	case atypIPv6:
		req.addr = make([]byte, 16)
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = net.IP(req.addr).String()
	case atypDomain:
		lb := make([]byte, 1)
		if _, err := io.ReadFull(r, lb); err != nil {
			return socksReq{}, err
		}
		req.addr = make([]byte, int(lb[0]))
		if _, err := io.ReadFull(r, req.addr); err != nil {
			return socksReq{}, err
		}
		req.host = string(req.addr)
	default:
		return socksReq{}, fmt.Errorf("socks: bad atyp 0x%02x", req.atyp)
	}
	portB := make([]byte, 2)
	if _, err := io.ReadFull(r, portB); err != nil {
		return socksReq{}, err
	}
	req.port = int(binary.BigEndian.Uint16(portB))
	return req, nil
}
```

Rename `encodeConnectReq` to `encodeReq` and emit the request's own command:

```go
// encodeReq re-serializes req (preserving its command byte) for the upstream
// Tor SOCKS daemon.
func encodeReq(req socksReq) []byte {
	out := []byte{socksVer, req.cmd, 0x00, req.atyp}
	if req.atyp == atypDomain {
		out = append(out, byte(len(req.addr)))
	}
	out = append(out, req.addr...)
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], uint16(req.port))
	return append(out, p[:]...)
}
```

- [ ] **Step 4: Rewrite `handleTorSocks` as a dispatcher, extract `gatewayConnect` + `upstreamHandshake`, and thread `socks_cmd` into events**

Replace `handleTorSocks` (lines 131-205) and `emitOnionEvent` (lines 271-278) with:

```go
// handleTorSocks terminates a client SOCKS5 handshake, reads the request, and
// dispatches on the command: CONNECT tunnels through the onion gateway,
// RESOLVE is filtered-and-forwarded, and every other command is rejected with
// command-not-supported. Fail-closed on any error.
func handleTorSocks(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string) error {
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
		return gatewayConnect(conn, upstreamAddr, pol, emit, sessionID, commandID, req)
	// case socksCmdResolve is added in Task 2.
	default:
		// RESOLVE_PTR (0xF1), BIND, UDP ASSOCIATE, etc. — deliberately
		// unsupported. Reply the correct SOCKS code and close; no event,
		// since no onion_rules decision was made.
		_ = writeSocksReply(conn, socksRepCmdNotSupported)
		return nil
	}
}

// gatewayConnect handles a SOCKS CONNECT: evaluate the target against the onion
// gateway policy, and either proxy the stream to the real Tor SOCKS daemon or
// reply not-allowed. Fail-closed on any error. Emits one tor_control{vector:
// onion, socks_cmd: connect} event.
func gatewayConnect(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, req socksReq) error {
	v, ok := pol.EvalSocksTarget(req.host, req.port)
	if ok {
		emitOnionEvent(emit, sessionID, commandID, v, "connect")
	}
	if !ok || v.Decision != "allow" {
		_ = writeSocksReply(conn, socksRepNotAllowed)
		return nil
	}

	up, err := net.DialTimeout("tcp", upstreamAddr, 20*time.Second)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	defer up.Close()

	if err := upstreamHandshake(up); err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	if _, err := up.Write(encodeReq(req)); err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	upReply, err := readSocksReply(up)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	// Relay the upstream's reply verbatim to the client.
	if _, err := conn.Write(upReply); err != nil {
		return err
	}
	// Only tunnel when the upstream accepted the connection.
	if len(upReply) < 2 || upReply[1] != socksRepSuccess {
		return nil
	}
	splice(conn, up)
	return nil
}

// upstreamHandshake performs the SOCKS5 no-auth client handshake with the real
// Tor daemon (greeting with one method, no-auth, then method-selection reply
// validation). Returns an error if the upstream does not accept no-auth.
func upstreamHandshake(up net.Conn) error {
	if _, err := up.Write([]byte{socksVer, 0x01, 0x00}); err != nil { // greeting: 1 method, no-auth
		return err
	}
	methodReply := make([]byte, 2)
	if _, err := io.ReadFull(up, methodReply); err != nil {
		return err
	}
	if methodReply[0] != socksVer || methodReply[1] != 0x00 {
		return fmt.Errorf("socks: upstream selected auth method 0x%02x (want no-auth)", methodReply[1])
	}
	return nil
}
```

Replace `emitOnionEvent` to set `socks_cmd`:

```go
func emitOnionEvent(emit Emitter, sessionID, commandID string, v tor.Verdict, socksCmd string) {
	if emit == nil {
		return
	}
	ev := tor.BuildControlEvent(sessionID, commandID, 0, v)
	ev.Fields["socks_cmd"] = socksCmd
	_ = emit.AppendEvent(context.Background(), ev)
	emit.Publish(ev)
}
```

- [ ] **Step 5: Update test-helper references to the renamed functions**

In `internal/netmonitor/socks_handler_test.go`, the package will not compile until the helpers use the new names:
- In `driveClient`: `encodeConnectReq(socksReq{atyp: atypDomain, ...})` → `encodeReq(socksReq{cmd: socksCmdConnect, atyp: atypDomain, addr: []byte(host), host: host, port: port})`.
- In `fakeTorUpstreamWithReply`: `if _, err := readSocksConnect(c); err != nil {` → `if _, err := readSocksRequest(c); err != nil {`.
- `fakeTorUpstreamRequiresAuth` does not call `readSocksConnect` (it closes after the method reply) — no change.

- [ ] **Step 6: Run the tests to verify they pass**

Run: `go test ./internal/netmonitor/ -run 'TestHandleTorSocks|TestSplice' -v`
Expected: PASS — including the existing CONNECT tests (now asserting `socks_cmd: "connect"`) and `TestHandleTorSocks_UnsupportedCommand`.

- [ ] **Step 7: Verify build, cross-compile, and format**

Run: `go build ./... && GOOS=windows go build ./... && gofmt -l internal/netmonitor/socks.go internal/netmonitor/socks_handler_test.go`
Expected: both builds succeed; `gofmt -l` prints nothing.

- [ ] **Step 8: Commit**

```bash
git add internal/netmonitor/socks.go internal/netmonitor/socks_handler_test.go
git commit -m "feat(tor): command-aware SOCKS gateway dispatch + correct unsupported-command reply"
```

---

### Task 2: RESOLVE (0xF0) filter-and-forward

Add the RESOLVE branch: evaluate the target via the same `EvalSocksTarget`, and when allowed forward the RESOLVE to upstream Tor and relay the single reply verbatim — no splice. Reuse `upstreamHandshake`/`encodeReq`/`readSocksReply` from Task 1.

**Files:**
- Modify: `internal/netmonitor/socks.go`
- Test: `internal/netmonitor/socks_handler_test.go`

**Interfaces:**
- Consumes (from Task 1): `readSocksRequest`, `encodeReq`, `upstreamHandshake`, `emitOnionEvent(..., socksCmd string)`, `socksCmdResolve`, `assertOnionEvent`, `driveCmd`.
- Produces: `gatewayResolve(...)` and the `case socksCmdResolve` dispatch arm.

- [ ] **Step 1: Write the failing tests**

Add to `internal/netmonitor/socks_handler_test.go`:

```go
// fakeTorResolveUpstream answers a forwarded RESOLVE (0xF0) with a fixed
// resolved IPv4 address (REP success). It asserts the forwarded command is
// RESOLVE; on any other command it closes without replying.
func fakeTorResolveUpstream(t *testing.T, resolved net.IP) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = readSocksGreeting(c)
				_ = writeSocksMethod(c, 0x00)
				req, err := readSocksRequest(c)
				if err != nil || req.cmd != socksCmdResolve {
					return
				}
				ip4 := resolved.To4()
				reply := []byte{socksVer, socksRepSuccess, 0x00, atypIPv4}
				reply = append(reply, ip4...)
				reply = append(reply, 0, 0) // port
				_, _ = c.Write(reply)
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// driveResolve sends a SOCKS5 RESOLVE for host and returns the full 10-byte
// IPv4-form reply (VER REP RSV ATYP ADDR PORT).
func driveResolve(t *testing.T, conn net.Conn, host string) []byte {
	t.Helper()
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // greeting
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(encodeReq(socksReq{cmd: socksCmdResolve, atyp: atypDomain, addr: []byte(host), host: host}))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply
}

// TestHandleTorSocks_ResolveAllowed verifies an allowed RESOLVE is forwarded to
// upstream Tor and its reply (resolved IP) relayed verbatim, with no splice.
func TestHandleTorSocks_ResolveAllowed(t *testing.T) {
	upstream, stop := fakeTorResolveUpstream(t, net.IPv4(1, 2, 3, 4))
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()

	reply := driveResolve(t, client, "ok.onion")
	if reply[1] != socksRepSuccess {
		t.Fatalf("RESOLVE reply REP = 0x%02x, want success", reply[1])
	}
	if reply[3] != atypIPv4 || !net.IP(reply[4:8]).Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("RESOLVE reply addr = %v (atyp 0x%02x), want 1.2.3.4/IPv4", net.IP(reply[4:8]), reply[3])
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTorSocks did not return after RESOLVE (possible spurious splice)")
	}
	assertOnionEvent(t, emit, "allow", "resolve")
}

// TestHandleTorSocks_ResolveDenied verifies a denied RESOLVE replies not-allowed
// with no upstream dial.
func TestHandleTorSocks_ResolveDenied(t *testing.T) {
	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	go func() {
		// upstreamAddr unreachable on purpose; a denied RESOLVE must not dial.
		_ = handleTorSocks(server, "127.0.0.1:1", fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()
	reply := driveResolve(t, client, "blocked.onion")
	if reply[1] != socksRepNotAllowed {
		t.Fatalf("denied RESOLVE reply REP = 0x%02x, want not-allowed", reply[1])
	}
	client.Close()
	assertOnionEvent(t, emit, "deny", "resolve")
}

// TestHandleTorSocks_ResolveUpstreamError verifies a non-success RESOLVE reply
// from upstream Tor is relayed verbatim (the client sees Tor's error code) and
// the handler returns without splicing.
func TestHandleTorSocks_ResolveUpstreamError(t *testing.T) {
	upstream, stop := fakeTorUpstreamWithReply(t, 0x04) // host unreachable
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()
	reply := driveResolve(t, client, "ok.onion")
	if reply[1] != 0x04 {
		t.Fatalf("RESOLVE reply REP = 0x%02x, want host-unreachable (0x04)", reply[1])
	}
	client.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTorSocks did not return after RESOLVE upstream error")
	}
	assertOnionEvent(t, emit, "allow", "resolve")
}
```

Note: `fakeTorUpstreamWithReply` already reads the request via `readSocksRequest` (Task 1) and replies with the given code, so it serves the upstream-error case for RESOLVE too (it sends a 10-byte null-IPv4 reply with REP 0x04).

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/netmonitor/ -run 'TestHandleTorSocks_Resolve' -v`
Expected: FAIL — `driveResolve` returns `not-allowed`/`command-not-supported` because RESOLVE currently falls into the `default` arm (no `gatewayResolve` yet); `TestHandleTorSocks_ResolveAllowed` fails the REP/addr assertion.

- [ ] **Step 3: Add the RESOLVE dispatch arm and `gatewayResolve` in `socks.go`**

In `handleTorSocks`, add the case (replacing the `// case socksCmdResolve is added in Task 2.` comment):

```go
	case socksCmdResolve:
		return gatewayResolve(conn, upstreamAddr, pol, emit, sessionID, commandID, req)
```

Add the handler:

```go
// gatewayResolve handles a SOCKS RESOLVE (0xF0): it filters the target through
// the same onion_rules as CONNECT and, when allowed, forwards the RESOLVE to
// the upstream Tor daemon and relays its single reply verbatim. RESOLVE is a
// request/reply exchange, not a tunnel — there is no splice. Emits one
// tor_control{vector: onion, socks_cmd: resolve} event.
func gatewayResolve(conn net.Conn, upstreamAddr string, pol TorGatewayPolicy, emit Emitter, sessionID, commandID string, req socksReq) error {
	v, ok := pol.EvalSocksTarget(req.host, req.port)
	if ok {
		emitOnionEvent(emit, sessionID, commandID, v, "resolve")
	}
	if !ok || v.Decision != "allow" {
		_ = writeSocksReply(conn, socksRepNotAllowed)
		return nil
	}

	up, err := net.DialTimeout("tcp", upstreamAddr, 20*time.Second)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	defer up.Close()

	if err := upstreamHandshake(up); err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	if _, err := up.Write(encodeReq(req)); err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	reply, err := readSocksReply(up)
	if err != nil {
		_ = writeSocksReply(conn, socksRepGeneralFailure)
		return err
	}
	// Relay Tor's reply verbatim — success carries the resolved address, an
	// error carries Tor's REP code. No splice: RESOLVE is request/reply.
	_, err = conn.Write(reply)
	return err
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/netmonitor/ -run 'TestHandleTorSocks' -v`
Expected: PASS — all RESOLVE tests plus the Task 1 CONNECT/unsupported tests.

- [ ] **Step 5: Verify build, cross-compile, and format**

Run: `go build ./... && GOOS=windows go build ./... && gofmt -l internal/netmonitor/socks.go internal/netmonitor/socks_handler_test.go`
Expected: both builds succeed; `gofmt -l` prints nothing.

- [ ] **Step 6: Commit**

```bash
git add internal/netmonitor/socks.go internal/netmonitor/socks_handler_test.go
git commit -m "feat(tor): filter-and-forward SOCKS RESOLVE through the onion gateway"
```

---

### Task 3: Spec status + full gates

Mark the Phase 4 spec implemented, note RESOLVE as done in the base design's tracked-future list, and run the full gate suite.

**Files:**
- Modify: `docs/superpowers/specs/2026-06-22-tor-access-control-phase4-design.md`
- Modify: `docs/superpowers/specs/2026-06-20-tor-access-control-phase3-design.md`

- [ ] **Step 1: Update the Phase 4 spec status**

In `docs/superpowers/specs/2026-06-22-tor-access-control-phase4-design.md`, change the status line:

```markdown
**Status:** Implemented (PR pending)
```

- [ ] **Step 2: Mark RESOLVE done in the Phase 3 spec's future list**

In `docs/superpowers/specs/2026-06-20-tor-access-control-phase3-design.md`, under "Out of scope / future", change the "Gateway SOCKS protocol completeness" bullet to record that RESOLVE is now handled:

```markdown
- **Gateway SOCKS protocol completeness** — `handleTorSocks` now filters and
  forwards `RESOLVE` (0xF0) through `onion_rules` (Phase 4,
  `2026-06-22-tor-access-control-phase4-design.md`); `RESOLVE_PTR` (0xF1)
  remains deliberately unsupported (`command not supported`), tracked there.
```

- [ ] **Step 3: Run the full gate suite**

Run:
```
go build ./...
GOOS=windows go build ./...
gofmt -l internal/netmonitor
go test ./internal/netmonitor/ ./internal/tor/
go test ./...
```
Expected: builds clean; `gofmt -l` empty; `internal/netmonitor` + `internal/tor` green; full suite green except the known pre-existing local-env flakes (the `internal/fsmonitor` FUSE flake and the `internal/ocsf` exhaustiveness flake that passes when run standalone — neither is a regression, and Phase 4 adds no `events.EventType`).

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/specs/2026-06-22-tor-access-control-phase4-design.md docs/superpowers/specs/2026-06-20-tor-access-control-phase3-design.md
git commit -m "docs(tor): mark Phase 4 RESOLVE handling implemented"
```

---

## Self-Review

**Spec coverage:**
- RESOLVE (0xF0) filter-and-forward via `onion_rules` → Task 2 (`gatewayResolve` + `EvalSocksTarget` + forward/relay).
- RESOLVE_PTR (0xF1) + other commands → `command not supported` (0x07) → Task 1 (dispatch `default` arm) + test (`TestHandleTorSocks_UnsupportedCommand`).
- No `.onion`-RESOLVE special-casing → honored (RESOLVE is forwarded uniformly; Tor's natural error is relayed by `TestHandleTorSocks_ResolveUpstreamError`'s relay-verbatim path).
- `socks_cmd` field on `vector: onion` events (`connect`/`resolve`) → Task 1 (`emitOnionEvent` + `assertOnionEvent` on connect) + Task 2 (resolve assertions).
- No new `events.EventType` → honored (reuses `tor.BuildControlEvent`; only a free-form `Fields` key added).
- No new config knobs / no new data path → honored (CONNECT splices unchanged; RESOLVE is request/reply).
- Fail-closed parity → Task 1/2 (general-failure on errors, not-allowed on deny) + `TestHandleTorSocks_ResolveDenied`.
- Cross-compile clean → Steps build `GOOS=windows` in every task.
- Reply-verbatim incl. errors → `TestHandleTorSocks_ResolveUpstreamError`.

**Placeholder scan:** No TBD/TODO; every code step shows complete code; the only inline comment marker (`// case socksCmdResolve is added in Task 2.`) is replaced by real code in Task 2 Step 3.

**Type consistency:** `socksReq.cmd byte` is set by `readSocksRequest` and read by `handleTorSocks`/`encodeReq` (all Task 1). `emitOnionEvent(..., socksCmd string)` defined in Task 1, called with `"connect"` (Task 1) and `"resolve"` (Task 2). `upstreamHandshake`, `encodeReq`, `readSocksReply` defined/reused consistently. `assertOnionEvent(t, emit, wantDecision, wantCmd)` and `driveCmd`/`driveResolve` signatures match their call sites. Constants `socksCmdResolve`/`socksRepCmdNotSupported` defined in Task 1, used in both tasks.
