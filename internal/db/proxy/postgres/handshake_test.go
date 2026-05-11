//go:build linux

package postgres

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
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

func TestDispatch_CancelRequest_ClosesSilently(t *testing.T) {
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
