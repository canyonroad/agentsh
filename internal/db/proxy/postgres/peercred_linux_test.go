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

func TestServer_PeercredMismatch_ClosesAndEmitsLifecycle(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	sink := &events.SyncSink{}
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
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
	// Override the equality check for this test only.
	s.uidAllowed = func(uint32) bool { return false }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	waitForSocket(t, sockPath)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Server should close the conn silently after peercred check.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) && !isClosedConnError(err) {
		t.Errorf("Read after peercred mismatch: err=%v, want EOF or closed-conn", err)
	}

	// Capture the lifecycle slice on first non-empty Drain (avoid double-drain).
	var lcs []events.LifecycleEvent
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got := sink.DrainLifecycle(); len(got) > 0 {
			lcs = got
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
		t.Fatalf("DrainLifecycle = %+v, want one db_listener_auth_fail", lcs)
	}
	if lcs[0].DBService != "appdb" {
		t.Errorf("DBService = %q, want appdb", lcs[0].DBService)
	}
	if lcs[0].PeerUID != uint32(os.Getuid()) {
		t.Errorf("PeerUID = %d, want %d", lcs[0].PeerUID, os.Getuid())
	}
	if lcs[0].Reason != "uid_mismatch" {
		t.Errorf("Reason = %q, want uid_mismatch", lcs[0].Reason)
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
