//go:build linux

package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func newTestProxyConn(t *testing.T, conn net.Conn) *proxyConn {
	t.Helper()
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_test.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return newProxyConn(srv, srv.cfg.Services[0], conn, 1000)
}

func writeRawStartup(t *testing.T, w io.Writer, body []byte) {
	t.Helper()
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := w.Write(hdr); err != nil {
		t.Fatalf("write startup hdr: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("write startup body: %v", err)
	}
}

func TestDispatch_GSSENCRequest_RespondsN(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)

	go func() {
		body := make([]byte, 4)
		binary.BigEndian.PutUint32(body, 80877104) // GSSENCRequest magic
		writeRawStartup(t, b, body)
		buf := make([]byte, 1)
		_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := io.ReadFull(b, buf); err != nil {
			t.Errorf("read response: %v", err)
		}
		if buf[0] != 'N' {
			t.Errorf("response = %q, want 'N'", buf[0])
		}
		b.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := pc.run(ctx); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Logf("run returned: %v (acceptable on EOF)", err)
	}
}

func TestDispatch_CancelRequest_NoMatch_ClosesSilentlyAndEmitsLifecycle(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)

	go func() {
		body := make([]byte, 4+4+4)
		binary.BigEndian.PutUint32(body[0:4], 80877102) // CancelRequest magic
		binary.BigEndian.PutUint32(body[4:8], 12345)
		binary.BigEndian.PutUint32(body[8:12], 67890)
		writeRawStartup(t, b, body)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := pc.run(ctx)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("run on CancelRequest returned %v; want clean exit", err)
	}

	sink := pc.srv.cfg.Sink.(*events.SyncSink)
	lifecycle := sink.DrainLifecycle()
	if len(lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1: %#v", len(lifecycle), lifecycle)
	}
	if lifecycle[0].Kind != "db_cancel_unmatched" {
		t.Errorf("Kind = %q, want db_cancel_unmatched", lifecycle[0].Kind)
	}
	if lifecycle[0].Reason != "unmatched_cancel_request" {
		t.Errorf("Reason = %q, want unmatched_cancel_request", lifecycle[0].Reason)
	}
}

func TestDispatch_Replication_DefaultDeny(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)

	clientDone := make(chan struct{})
	go func() {
		defer close(clientDone)
		body := []byte{}
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, 196608) // protocol 3.0
		body = append(body, v...)
		body = append(body, []byte("user\x00rep\x00replication\x00true\x00\x00")...)
		writeRawStartup(t, b, body)

		buf := make([]byte, 256)
		_ = b.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ := b.Read(buf)
		if n == 0 || buf[0] != 'E' {
			t.Errorf("first byte after replication startup = %q (n=%d), want 'E'", buf[0], n)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pc.run(ctx); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Logf("run on replication=true returned: %v", err)
	}
	<-clientDone
}

func TestDispatch_Passthrough_BytePumpAfterS(t *testing.T) {
	// Fake upstream that echoes any bytes received.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen upstream: %v", err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "passthrough",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "passthrough"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	// Drive proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()

	// Client sends SSLRequest (8 bytes: 0x00000008, 0x04D2162F).
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := b.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}

	// Expect 'S' response.
	resp := make([]byte, 1)
	if _, err := io.ReadFull(b, resp); err != nil {
		t.Fatalf("read SSL resp: %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("SSL resp = %q, want 'S'", resp[0])
	}

	// Now bytes pump through to the echo upstream. Write a payload, read
	// it back.
	payload := []byte("hello-from-client")
	if _, err := b.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
}

func TestDispatch_ReplicationOptIn_PumpsAndEmitsDVW(t *testing.T) {
	// Echo upstream so we can confirm bytes pump.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	startupCh := make(chan []byte, 1)
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the StartupMessage the proxy forwards.
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(c, hdr); err != nil {
			startupCh <- nil
			return
		}
		bodyLen := int(binary.BigEndian.Uint32(hdr)) - 4
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(c, body); err != nil {
			startupCh <- nil
			return
		}
		startupCh <- body
		// Then echo for the rest of the connection lifetime.
		_, _ = io.Copy(c, c)
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upLn.Addr().String()+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-replication
    db_service: appdb
    match_kind: replication
    decision: allow
`)

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	pc.state.tlsTerminated = true // pretend inbound TLS already done

	// Build a StartupMessage with replication=true and write to client side.
	startup := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	startup = append(startup, v...)
	startup = append(startup, []byte("user\x00rep\x00replication\x00true\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(startup)+4))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	if _, err := b.Write(append(hdr, startup...)); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	// Wait for the proxy to forward the StartupMessage upstream.
	select {
	case body := <-startupCh:
		if body == nil {
			t.Fatal("upstream did not receive StartupMessage")
		}
		if !strings.Contains(string(body), "replication") {
			t.Errorf("upstream startup body missing replication param: %q", body)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("upstream timeout waiting for StartupMessage")
	}

	// Pump check: client writes 'X', upstream echoes back.
	if _, err := b.Write([]byte("X")); err != nil {
		t.Fatalf("write X: %v", err)
	}
	buf := make([]byte, 1)
	_ = b.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("echo = %q, want X", buf[0])
	}

	// Tear down.
	b.Close()
	<-done

	// Assert one degraded_visibility_warning event with replication_passthrough.
	evs := sink.DrainLifecycle()
	var found *events.LifecycleEvent
	for i := range evs {
		if evs[i].Kind == "degraded_visibility_warning" {
			found = &evs[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no degraded_visibility_warning event emitted")
	}
	if found.DegradedReason != "replication_passthrough" {
		t.Errorf("DegradedReason = %q, want replication_passthrough", found.DegradedReason)
	}
}

func TestDispatch_CancelRequest_AllowedForwardsRealMappedPacket(t *testing.T) {
	upAddr, ch := captureCancelListener(t)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upAddr+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
`)

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	reg, err := srv.cancelMap.Register(cancelMeta{
		ServiceName:     "appdb",
		UpstreamAddr:    upAddr,
		ClientIdentity:  "uid:1000",
		DBUser:          "alice",
		Database:        "app",
		ApplicationName: "psql",
		PeerUID:         1000,
	}, 11111, []byte{0, 0, 86, 206})
	if err != nil {
		t.Fatalf("Register cancel mapping: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	pkt := buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	var captured []byte
	select {
	case captured = <-ch:
		if captured == nil {
			t.Fatal("upstream did not capture cancel packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not capture cancel packet")
	}
	want := buildCancelPacketBytes(11111, []byte{0, 0, 86, 206})
	if len(captured) != len(want) {
		t.Fatalf("captured %d bytes upstream, want %d", len(captured), len(want))
	}
	for i := range want {
		if captured[i] != want[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, captured[i], want[i])
		}
	}

	if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run on CancelRequest returned %v; want clean exit", err)
	}
	events := sink.DrainStatements()
	if len(events) != 1 {
		t.Fatalf("statement events = %d, want 1: %#v", len(events), events)
	}
	if events[0].Decision.RuleKind != "cancel" {
		t.Errorf("Decision.RuleKind = %q, want cancel", events[0].Decision.RuleKind)
	}
	if events[0].Decision.Verb != "allow" {
		t.Errorf("Decision.Verb = %q, want allow", events[0].Decision.Verb)
	}
	if events[0].Database != "app" {
		t.Errorf("Database = %q, want app", events[0].Database)
	}
}

func TestDispatch_CancelRequest_DenyDoesNotDialAndEmitsDBEvent(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := upLn.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upLn.Addr().String()+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: deny-cancel
    db_service: appdb
    match_kind: cancel
    decision: deny
`)

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	reg, err := srv.cancelMap.Register(cancelMeta{
		ServiceName:    "appdb",
		UpstreamAddr:   upLn.Addr().String(),
		ClientIdentity: "uid:1000",
		Database:       "app",
		PeerUID:        1000,
	}, 11111, []byte{0, 0, 86, 206})
	if err != nil {
		t.Fatalf("Register cancel mapping: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	pkt := buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}

	if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run on CancelRequest returned %v; want clean exit", err)
	}
	select {
	case <-dialed:
		t.Fatal("upstream was dialed despite mapped deny rule")
	case <-time.After(300 * time.Millisecond):
		// Expected: no dial.
	}
	events := sink.DrainStatements()
	if len(events) != 1 {
		t.Fatalf("statement events = %d, want 1: %#v", len(events), events)
	}
	if events[0].Decision.Verb != "deny" {
		t.Errorf("Decision.Verb = %q, want deny", events[0].Decision.Verb)
	}
	if events[0].Decision.RuleKind != "cancel" {
		t.Errorf("Decision.RuleKind = %q, want cancel", events[0].Decision.RuleKind)
	}
	if events[0].Decision.RuleName != "deny-cancel" {
		t.Errorf("Decision.RuleName = %q, want deny-cancel", events[0].Decision.RuleName)
	}
	if events[0].Database != "app" {
		t.Errorf("Database = %q, want app", events[0].Database)
	}
}

func TestDispatch_CancelRequest_ExpiredEmitsLifecycle(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:1",
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	srv.cancelMap = newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Second,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1001, secret: []byte{0, 0, 0, 7}},
		}),
	})
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	reg, err := srv.cancelMap.Register(cancelMeta{
		ServiceName:    "appdb",
		UpstreamAddr:   "127.0.0.1:1",
		ClientIdentity: "uid:1000",
		PeerUID:        1000,
	}, 11111, []byte{0, 0, 86, 206})
	if err != nil {
		t.Fatalf("Register cancel mapping: %v", err)
	}
	reg.Release()
	now = now.Add(2 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	pkt := buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run on CancelRequest returned %v; want clean exit", err)
	}

	lifecycle := sink.DrainLifecycle()
	if len(lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1: %#v", len(lifecycle), lifecycle)
	}
	if lifecycle[0].Kind != "db_cancel_after_disconnect" {
		t.Errorf("Kind = %q, want db_cancel_after_disconnect", lifecycle[0].Kind)
	}
	if lifecycle[0].Reason != "cancel_after_disconnect" {
		t.Errorf("Reason = %q, want cancel_after_disconnect", lifecycle[0].Reason)
	}
}

func TestDispatch_CancelRequest_AuditForwardsRealMappedPacketAndEmitsDBEvent(t *testing.T) {
	upAddr, ch := captureCancelListener(t)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upAddr+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: audit-cancel
    db_service: appdb
    match_kind: cancel
    decision: audit
`)

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	reg, err := srv.cancelMap.Register(cancelMeta{
		ServiceName:     "appdb",
		UpstreamAddr:    upAddr,
		ClientIdentity:  "uid:1000",
		DBUser:          "alice",
		Database:        "app",
		ApplicationName: "psql",
		PeerUID:         1000,
	}, 22222, []byte{0, 0, 212, 49})
	if err != nil {
		t.Fatalf("Register cancel mapping: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	pkt := buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	var captured []byte
	select {
	case captured = <-ch:
		if captured == nil {
			t.Fatal("upstream did not capture cancel packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not capture cancel packet")
	}
	want := buildCancelPacketBytes(22222, []byte{0, 0, 212, 49})
	if len(captured) != len(want) {
		t.Fatalf("captured %d bytes upstream, want %d", len(captured), len(want))
	}
	for i := range want {
		if captured[i] != want[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, captured[i], want[i])
		}
	}

	if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run on CancelRequest returned %v; want clean exit", err)
	}
	events := sink.DrainStatements()
	if len(events) != 1 {
		t.Fatalf("statement events = %d, want 1: %#v", len(events), events)
	}
	if events[0].Decision.Verb != "audit" {
		t.Errorf("Decision.Verb = %q, want audit", events[0].Decision.Verb)
	}
	if events[0].Decision.RuleKind != "cancel" {
		t.Errorf("Decision.RuleKind = %q, want cancel", events[0].Decision.RuleKind)
	}
	if events[0].Database != "app" {
		t.Errorf("Database = %q, want app", events[0].Database)
	}
}

func TestDispatch_CancelRequest_ForwardFailureEmitsLifecycleAndDBEventError(t *testing.T) {
	upAddr := "127.0.0.1:1"

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upAddr+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
`)

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	reg, err := srv.cancelMap.Register(cancelMeta{
		ServiceName:     "appdb",
		UpstreamAddr:    upAddr,
		ClientIdentity:  "uid:1000",
		DBUser:          "alice",
		Database:        "app",
		ApplicationName: "psql",
		PeerUID:         1000,
	}, 11111, []byte{0, 0, 86, 206})
	if err != nil {
		t.Fatalf("Register cancel mapping: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	pkt := buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	if err := <-done; err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("run on CancelRequest returned %v; want clean exit", err)
	}

	events := sink.DrainStatements()
	if len(events) != 1 {
		t.Fatalf("statement events = %d, want 1: %#v", len(events), events)
	}
	if events[0].Decision.Verb != "allow" {
		t.Errorf("Decision.Verb = %q, want allow", events[0].Decision.Verb)
	}
	if events[0].Decision.RuleKind != "cancel" {
		t.Errorf("Decision.RuleKind = %q, want cancel", events[0].Decision.RuleKind)
	}
	if events[0].Result.ErrorCode != "CANCEL_FORWARD_FAILED" {
		t.Errorf("Result.ErrorCode = %q, want CANCEL_FORWARD_FAILED", events[0].Result.ErrorCode)
	}
	if events[0].Database != "app" {
		t.Errorf("Database = %q, want app", events[0].Database)
	}

	lifecycle := sink.DrainLifecycle()
	if len(lifecycle) != 1 {
		t.Fatalf("lifecycle events = %d, want 1: %#v", len(lifecycle), lifecycle)
	}
	if lifecycle[0].Kind != "db_cancel_forward_failed" {
		t.Errorf("Kind = %q, want db_cancel_forward_failed", lifecycle[0].Kind)
	}
	if lifecycle[0].Reason != "forward_failed" {
		t.Errorf("Reason = %q, want forward_failed", lifecycle[0].Reason)
	}
	if lifecycle[0].ErrorCode != "CANCEL_FORWARD_FAILED" {
		t.Errorf("ErrorCode = %q, want CANCEL_FORWARD_FAILED", lifecycle[0].ErrorCode)
	}
}

func TestDispatch_CancelRequest_DeniedSilentClose(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := upLn.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upLn.Addr().String()+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: deny-cancel
    db_service: appdb
    match_kind: cancel
    decision: deny
`)

	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()

	pkt := buildCancelPacket(11111, 22222)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}

	select {
	case <-dialed:
		t.Error("upstream was dialed despite deny rule")
	case <-time.After(300 * time.Millisecond):
		// Expected: no dial.
	}
}
