package netmonitor

import (
	"context"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/tor"
	"github.com/agentsh/agentsh/pkg/types"
)

// fakeGatewayPolicy allows exactly one host.
type fakeGatewayPolicy struct{ allow string }

func (f fakeGatewayPolicy) GatewayActive() bool { return true }
func (f fakeGatewayPolicy) EvalSocksTarget(host string, port int) (tor.Verdict, bool) {
	dec := "deny"
	if host == f.allow {
		dec = "allow"
	}
	return tor.Verdict{Vector: tor.VectorOnion, Mode: "allow", Decision: dec, Target: host}, true
}

// torCaptureEmitter records published events (thread-safe; named to avoid
// collision with the plain captureEmitter in dns_test.go).
type torCaptureEmitter struct {
	mu  sync.Mutex
	evs []types.Event
}

func (c *torCaptureEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	c.mu.Lock()
	c.evs = append(c.evs, ev)
	c.mu.Unlock()
	return nil
}
func (c *torCaptureEmitter) Publish(_ types.Event) {}
func (c *torCaptureEmitter) events() []types.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]types.Event(nil), c.evs...)
}

// fakeTorUpstream is a minimal SOCKS5 server that always succeeds and echoes.
func fakeTorUpstream(t *testing.T) (addr string, stop func()) {
	t.Helper()
	return fakeTorUpstreamWithReply(t, socksRepSuccess)
}

// fakeTorUpstreamWithReply is like fakeTorUpstream but sends the given reply code.
// When the reply is non-success, it closes after sending the reply (no echo).
func fakeTorUpstreamWithReply(t *testing.T, rep byte) (addr string, stop func()) {
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
				if _, err := readSocksRequest(c); err != nil {
					return
				}
				_ = writeSocksReply(c, rep)
				if rep == socksRepSuccess {
					_, _ = io.Copy(c, c) // echo only on success
				}
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// assertOnionEvent waits for one tor_control{vector:onion} event and asserts
// its decision, socks_cmd field, and PID.
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

// driveClient runs a SOCKS5 client handshake for host:port over conn and returns the reply code.
func driveClient(t *testing.T, conn net.Conn, host string, port int) byte {
	t.Helper()
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // greeting
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(encodeReq(socksReq{cmd: socksCmdConnect, atyp: atypDomain, addr: []byte(host), host: host, port: port}))
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	return reply[1]
}

func TestHandleTorSocks_Allowed(t *testing.T) {
	upstream, stop := fakeTorUpstream(t)
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	go func() {
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
	}()

	rep := driveClient(t, client, "ok.onion", 443)
	if rep != socksRepSuccess {
		t.Fatalf("allowed target got reply 0x%02x, want success", rep)
	}
	// data path echoes through real upstream
	_, _ = client.Write([]byte("ping"))
	got := make([]byte, 4)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(client, got); err != nil {
		t.Fatalf("echo read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
	client.Close()

	assertOnionEvent(t, emit, "allow", "connect", 4242)
}

func TestHandleTorSocks_Denied(t *testing.T) {
	upstream, stop := fakeTorUpstream(t)
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	go func() {
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
	}()

	rep := driveClient(t, client, "blocked.onion", 443)
	if rep != socksRepNotAllowed {
		t.Fatalf("denied target got reply 0x%02x, want not-allowed", rep)
	}
	client.Close()
	assertOnionEvent(t, emit, "deny", "connect", 4242)
}

// TestHandleTorSocks_UpstreamRefuses verifies that when the upstream Tor daemon
// replies with a non-success code, the handler forwards that reply to the client
// and returns promptly without entering bidirectional proxy mode.
func TestHandleTorSocks_UpstreamRefuses(t *testing.T) {
	upstream, stop := fakeTorUpstreamWithReply(t, socksRepGeneralFailure)
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
	}()

	// Drive client: should receive the upstream's non-success reply.
	rep := driveClient(t, client, "ok.onion", 443)
	if rep != socksRepGeneralFailure {
		t.Fatalf("upstream-refused target got reply 0x%02x, want general-failure (0x%02x)", rep, socksRepGeneralFailure)
	}

	// Close the client side; the handler must exit without hanging.
	client.Close()

	// Bound the wait so the test never hangs if splice is called unexpectedly.
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTorSocks did not return after upstream refusal (possible spurious splice)")
	}

	// The allow event should still have been emitted for the allowed target.
	assertOnionEvent(t, emit, "allow", "connect", 4242)
}

// fakeTorUpstreamRequiresAuth is a fake upstream that rejects the method
// negotiation by replying with method 0xFF (no acceptable method) — simulating
// a misconfigured or auth-requiring upstream.
func fakeTorUpstreamRequiresAuth(t *testing.T) (addr string, stop func()) {
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
				// Reply with 0xFF — no acceptable method / auth required.
				_ = writeSocksMethod(c, 0xFF)
				// Do not read a CONNECT or send a CONNECT reply; just close.
			}()
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

// TestHandleTorSocks_UpstreamRequiresAuth verifies that when the upstream
// selects a non-zero (auth-requiring) method, the handler sends
// socksRepGeneralFailure to the client and returns promptly — no splice.
func TestHandleTorSocks_UpstreamRequiresAuth(t *testing.T) {
	upstream, stop := fakeTorUpstreamRequiresAuth(t)
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
	}()

	// The client must get a general-failure reply — not a success, not a hang.
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	rep := driveClient(t, client, "ok.onion", 443)
	if rep != socksRepGeneralFailure {
		t.Fatalf("auth-requiring upstream: client got reply 0x%02x, want general-failure (0x%02x)", rep, socksRepGeneralFailure)
	}
	client.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleTorSocks did not return after upstream required auth (possible spurious splice)")
	}

	// Policy is evaluated (and the onion event emitted) before the upstream
	// auth failure, so an allow event is still recorded.
	assertOnionEvent(t, emit, "allow", "connect", 4242)
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
		_ = handleTorSocks(server, "127.0.0.1:1", fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
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

// TestSplice_HalfClose verifies that splice returns the correct byte counts and
// does not hang when one direction EOF's. Uses a real TCP socket pair so that
// CloseWrite is exercised (net.Pipe does not implement CloseWrite).
func TestSplice_HalfClose(t *testing.T) {
	// Set up a real TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	dialConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	listenConn := <-accepted

	// We'll use a second real TCP pair as the "b" side of splice.
	ln2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln2.Close()

	accepted2 := make(chan net.Conn, 1)
	go func() {
		c, err := ln2.Accept()
		if err != nil {
			return
		}
		accepted2 <- c
	}()

	dialConn2, err := net.Dial("tcp", ln2.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	listenConn2 := <-accepted2

	// a = listenConn  (receives from dialConn, sends to dialConn)
	// b = listenConn2 (receives from dialConn2, sends to dialConn2)
	// splice(a, b): ab = a->b, ba = b->a
	//
	// To drive bytes a->b: write on dialConn, then CloseWrite dialConn so
	//   listenConn reads EOF (io.Copy a->b finishes).
	// To drive bytes b->a: write on dialConn2, then CloseWrite dialConn2 so
	//   listenConn2 reads EOF (io.Copy b->a finishes).

	aPayload := []byte("hello from a")
	bPayload := []byte("world from b")

	// Write a->b side and close-write so splice can drain it.
	if _, err := dialConn.Write(aPayload); err != nil {
		t.Fatal(err)
	}
	if err := dialConn.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// Write b->a side and close-write.
	if _, err := dialConn2.Write(bPayload); err != nil {
		t.Fatal(err)
	}
	if err := dialConn2.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}

	type result struct {
		ab, ba int64
	}
	ch := make(chan result, 1)
	go func() {
		ab, ba := splice(listenConn, listenConn2)
		ch <- result{ab, ba}
	}()

	select {
	case r := <-ch:
		if r.ab != int64(len(aPayload)) {
			t.Errorf("ab bytes = %d, want %d", r.ab, len(aPayload))
		}
		if r.ba != int64(len(bPayload)) {
			t.Errorf("ba bytes = %d, want %d", r.ba, len(bPayload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not return (half-close hang)")
	}

	dialConn.Close()
	dialConn2.Close()
	listenConn.Close()
	listenConn2.Close()
}

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
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
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
	assertOnionEvent(t, emit, "allow", "resolve", 4242)
}

// TestHandleTorSocks_ResolveDenied verifies a denied RESOLVE replies not-allowed
// with no upstream dial.
func TestHandleTorSocks_ResolveDenied(t *testing.T) {
	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	go func() {
		// upstreamAddr unreachable on purpose; a denied RESOLVE must not dial.
		_ = handleTorSocks(server, "127.0.0.1:1", fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
	}()
	reply := driveResolve(t, client, "blocked.onion")
	if reply[1] != socksRepNotAllowed {
		t.Fatalf("denied RESOLVE reply REP = 0x%02x, want not-allowed", reply[1])
	}
	client.Close()
	assertOnionEvent(t, emit, "deny", "resolve", 4242)
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
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1", 4242)
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
	assertOnionEvent(t, emit, "allow", "resolve", 4242)
}

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
