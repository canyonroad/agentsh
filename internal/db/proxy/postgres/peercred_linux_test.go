//go:build linux

package postgres

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestReadPeerCredUID_FromSocketpair(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[1])

	// Wrap fd[0] as a net.UnixConn so we can call our helper on it.
	f := os.NewFile(uintptr(fds[0]), "peer")
	conn, err := net.FileConn(f)
	if err != nil {
		unix.Close(fds[0])
		t.Fatalf("FileConn: %v", err)
	}
	f.Close() // FileConn dup'd the fd
	defer conn.Close()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("conn is %T, want *net.UnixConn", conn)
	}

	gotUID, gotPID, err := readPeerCred(uc)
	if err != nil {
		t.Fatalf("readPeerCred: %v", err)
	}
	if gotUID != uint32(os.Getuid()) {
		t.Errorf("readPeerCred uid = %d, want %d", gotUID, os.Getuid())
	}
	if gotPID != int32(os.Getpid()) {
		t.Errorf("readPeerCred pid = %d, want %d", gotPID, os.Getpid())
	}
}

func TestReadPeerCredUID_OnNonUnixConn_Errors(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()
	if _, _, err := readPeerCred(r); err == nil {
		t.Fatal("readPeerCred(net.Pipe): want error, got nil")
	}
}

func TestServer_SessionResolverMatch_ContinuesToProxyHandlerPath(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	sink := &events.SyncSink{}
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		AgentSessionID: testAgentSessionID,
		SessionResolver: currentProcessResolver{
			sessionID: testAgentSessionID,
		},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb"},
		}},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	waitForSocket(t, sockPath)
	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
	})

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); !os.IsTimeout(err) {
		t.Errorf("Read after session match: err=%v, want timeout while proxy handler waits", err)
	}
	if got := sink.DrainLifecycle(); len(got) != 0 {
		t.Fatalf("DrainLifecycle after session match = %+v, want none", got)
	}
}

func TestServer_SessionResolverMiss_ClosesAndEmitsLifecycle(t *testing.T) {
	lcs := runSessionAuthFailureTest(t, staticResolver{ok: false})
	if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
		t.Fatalf("DrainLifecycle = %+v, want one db_listener_auth_fail", lcs)
	}
	if lcs[0].DBService != "appdb" {
		t.Errorf("DBService = %q, want appdb", lcs[0].DBService)
	}
	if lcs[0].PeerUID != uint32(os.Getuid()) {
		t.Errorf("PeerUID = %d, want %d", lcs[0].PeerUID, os.Getuid())
	}
	if lcs[0].Reason != "session_unknown" {
		t.Errorf("Reason = %q, want session_unknown", lcs[0].Reason)
	}
	if lcs[0].EventID == "" {
		t.Errorf("EventID is empty, want non-empty UUIDv7")
	}
	if lcs[0].Timestamp.IsZero() {
		t.Errorf("Timestamp is zero, want non-zero")
	}
	if lcs[0].PeerPID == 0 {
		t.Errorf("PeerPID = 0, want non-zero (real peer pid from net.Dial)")
	}
}

func TestServer_SessionResolverMismatch_ClosesAndEmitsLifecycle(t *testing.T) {
	lcs := runSessionAuthFailureTest(t, staticResolver{sessionID: "other-session", ok: true})
	if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
		t.Fatalf("DrainLifecycle = %+v, want one db_listener_auth_fail", lcs)
	}
	if lcs[0].Reason != "session_mismatch" {
		t.Errorf("Reason = %q, want session_mismatch", lcs[0].Reason)
	}
	if lcs[0].PeerSessionID != "other-session" {
		t.Errorf("PeerSessionID = %q, want other-session", lcs[0].PeerSessionID)
	}
	if lcs[0].PeerUID != uint32(os.Getuid()) {
		t.Errorf("PeerUID = %d, want %d", lcs[0].PeerUID, os.Getuid())
	}
	if lcs[0].PeerPID == 0 {
		t.Errorf("PeerPID = 0, want non-zero (real peer pid from net.Dial)")
	}
}

func TestServer_PeercredReadFailure_ClosesAndEmitsLifecycle(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	sink := &events.SyncSink{}
	s := &Server{
		cfg: Config{
			Sink: sink,
		},
		logger: slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	s.handleConn(context.Background(), Service{Name: "appdb"}, server)

	lcs := drainLifecycleEventually(t, sink)
	if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
		t.Fatalf("DrainLifecycle = %+v, want one db_listener_auth_fail", lcs)
	}
	if lcs[0].Reason != "peercred_read_failed" {
		t.Errorf("Reason = %q, want peercred_read_failed", lcs[0].Reason)
	}
	if lcs[0].PeerUID != 0 {
		t.Errorf("PeerUID = %d, want 0", lcs[0].PeerUID)
	}
	if lcs[0].PeerPID != 0 {
		t.Errorf("PeerPID = %d, want 0", lcs[0].PeerPID)
	}
}

func runSessionAuthFailureTest(t *testing.T, resolver SessionResolver) []events.LifecycleEvent {
	t.Helper()
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	sink := &events.SyncSink{}
	cfg := Config{
		Unavoidability:  service.UnavoidabilityObserve,
		StateDir:        t.TempDir(),
		Sink:            sink,
		Logger:          slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		AgentSessionID:  testAgentSessionID,
		SessionResolver: resolver,
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb"},
		}},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	waitForSocket(t, sockPath)
	t.Cleanup(func() {
		_ = s.Shutdown(context.Background())
	})

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) && !isClosedConnError(err) {
		t.Errorf("Read after session auth failure: err=%v, want EOF or closed-conn", err)
	}
	return drainLifecycleEventually(t, sink)
}

func drainLifecycleEventually(t *testing.T, sink *events.SyncSink) []events.LifecycleEvent {
	t.Helper()
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sink.DrainLifecycle(); len(got) > 0 {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

type currentProcessResolver struct {
	sessionID string
}

func (r currentProcessResolver) ResolveSessionID(pid int32) (string, bool) {
	if pid != int32(os.Getpid()) {
		return "", false
	}
	return r.sessionID, true
}

// helper: wait until socket file exists and is a socket
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %q never bound", path)
}

func isClosedConnError(err error) bool {
	return err != nil && (errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed"))
}
