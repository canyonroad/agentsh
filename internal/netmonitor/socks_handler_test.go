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
				if _, err := readSocksConnect(c); err != nil {
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

// driveClient runs a SOCKS5 client handshake for host:port over conn and returns the reply code.
func driveClient(t *testing.T, conn net.Conn, host string, port int) byte {
	t.Helper()
	_, _ = conn.Write([]byte{0x05, 0x01, 0x00}) // greeting
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write(encodeConnectReq(socksReq{atyp: atypDomain, addr: []byte(host), host: host, port: port}))
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
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
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

	assertOneOnionEvent(t, emit, "allow")
}

func TestHandleTorSocks_Denied(t *testing.T) {
	upstream, stop := fakeTorUpstream(t)
	defer stop()

	client, server := net.Pipe()
	emit := &torCaptureEmitter{}
	go func() {
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
	}()

	rep := driveClient(t, client, "blocked.onion", 443)
	if rep != socksRepNotAllowed {
		t.Fatalf("denied target got reply 0x%02x, want not-allowed", rep)
	}
	client.Close()
	assertOneOnionEvent(t, emit, "deny")
}

func assertOneOnionEvent(t *testing.T, emit *torCaptureEmitter, wantDecision string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		for _, ev := range emit.events() {
			if ev.Type == "tor_control" && ev.Fields["vector"] == tor.VectorOnion {
				if ev.Fields["decision"] != wantDecision {
					t.Fatalf("event decision = %v, want %v", ev.Fields["decision"], wantDecision)
				}
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("no tor_control{vector:onion,decision:%s} event seen", wantDecision)
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
		_ = handleTorSocks(server, upstream, fakeGatewayPolicy{allow: "ok.onion"}, emit, "session-1", "cmd-1")
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
	assertOneOnionEvent(t, emit, "allow")
}
