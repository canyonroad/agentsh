//go:build linux

package api

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/wraphandoff"
	"golang.org/x/sys/unix"
)

func waitForTestDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for accept goroutine")
	}
}

func dialUnixConn(t *testing.T, socketPath string) *net.UnixConn {
	t.Helper()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("expected UnixConn, got %T", conn)
	}
	t.Cleanup(func() { _ = unixConn.Close() })
	return unixConn
}

func waitForConnClosed(t *testing.T, conn net.Conn) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("expected closed connection, read %d bytes", n)
	}
	if err == nil {
		t.Fatal("expected connection to be closed")
	}
	if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) && !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("expected closed connection, got %v", err)
	}
}

func sendFDOverUnixConn(t *testing.T, conn *net.UnixConn, fd int) {
	t.Helper()

	file, err := conn.File()
	if err != nil {
		t.Fatalf("get file from connection: %v", err)
	}
	defer file.Close()

	rights := unix.UnixRights(fd)
	if err := unix.Sendmsg(int(file.Fd()), []byte{0}, rights, nil, 0); err != nil {
		t.Fatalf("sendmsg: %v", err)
	}
}

func withNotifyHandoffHook(t *testing.T) chan struct{} {
	t.Helper()

	called := make(chan struct{})
	prev := startNotifyHandlerForWrapHook
	startNotifyHandlerForWrapHook = func(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) error {
		if cleanup != nil {
			_ = cleanup()
		}
		if notifyFD != nil {
			_ = notifyFD.Close()
		}
		close(called)
		return nil
	}
	t.Cleanup(func() {
		startNotifyHandlerForWrapHook = prev
	})
	return called
}

func TestStartNotifyHandlerForWrap_CleansUpAfterProbeFailure(t *testing.T) {
	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	app, _ := newTestAppForWrap(t, cfg)

	notifyFD, notifyW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = notifyFD.Close()
		_ = notifyW.Close()
	})

	var cleanupCalls atomic.Int32
	cleanup := func() error {
		cleanupCalls.Add(1)
		return nil
	}

	if err := startNotifyHandlerForWrap(context.Background(), notifyFD, "test-session", app, false, 999999999, nil, cleanup); err == nil {
		t.Fatal("expected synchronous handler startup failure")
	}

	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestAcceptNotifyFD_RejectsWrongUID(t *testing.T) {
	called := withNotifyHandoffHook(t)

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 99999, false)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	select {
	case <-called:
		t.Fatal("expected notify handoff to be rejected")
	default:
	}

	waitForConnClosed(t, conn)

	_ = listener.Close()
	waitForTestDone(t, done)
}

func TestAcceptNotifyFD_RejectsNegativeUID(t *testing.T) {
	called := withNotifyHandoffHook(t)

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, -1, false)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	waitForTestDone(t, done)
	select {
	case <-called:
		t.Fatal("expected notify handoff to be rejected")
	default:
	}

	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 1)
	n, err := conn.Read(buf)
	if n != 0 {
		t.Fatalf("expected closed connection, read %d bytes", n)
	}
	if err == nil {
		t.Fatal("expected connection to be closed")
	}
	if !errors.Is(err, net.ErrClosed) && !errors.Is(err, io.EOF) {
		t.Fatalf("expected closed connection, got %v", err)
	}
}

func TestAcceptNotifyFD_AcceptsMatchingUID(t *testing.T) {
	currentUID := os.Getuid()
	if currentUID == 0 {
		t.Skip("legacy root sentinel keeps UID 0 permissive")
	}

	called := withNotifyHandoffHook(t)

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, currentUID, false)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("expected UnixConn")
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	sendFDOverUnixConn(t, unixConn, int(pipeR.Fd()))

	waitForTestDone(t, done)
	select {
	case <-called:
	default:
		t.Fatal("expected notify handoff to be called")
	}
}

func TestAcceptNotifyFD_AcceptsLegacyZeroUID(t *testing.T) {
	called := withNotifyHandoffHook(t)

	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0, false)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatal("expected UnixConn")
	}

	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	sendFDOverUnixConn(t, unixConn, int(pipeR.Fd()))

	waitForTestDone(t, done)
	select {
	case <-called:
	default:
		t.Fatal("expected notify handoff to be called")
	}
}

func TestAcceptNotifyFD_UsesMetadataWrapperPIDForCgroupBeforeAck(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	prevSetup := wrapCgroupSetupForNotifyHook
	prevStart := startNotifyHandlerForWrapHook
	setupCalled := make(chan int, 1)
	startCalled := make(chan struct{})
	wrapCgroupSetupForNotifyHook = func(ctx context.Context, a *App, s *session.Session, sessionID string, wrapperPID int) (func() error, error) {
		setupCalled <- wrapperPID
		return func() error { return nil }, nil
	}
	startNotifyHandlerForWrapHook = func(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session, cleanup func() error) error {
		_ = notifyFD.Close()
		if cleanup != nil {
			_ = cleanup()
		}
		close(startCalled)
		return nil
	}
	t.Cleanup(func() {
		wrapCgroupSetupForNotifyHook = prevSetup
		startNotifyHandlerForWrapHook = prevStart
	})

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0, false)
	}()

	conn := dialUnixConn(t, socketPath)
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	if err := wraphandoff.SendNotifyFD(conn, int(pipeR.Fd()), wraphandoff.Metadata{WrapperPID: 7777}); err != nil {
		t.Fatalf("send handoff: %v", err)
	}
	if err := wraphandoff.ReadStatus(conn); err != nil {
		t.Fatalf("read status: %v", err)
	}

	if got := <-setupCalled; got != 7777 {
		t.Fatalf("cgroup setup pid = %d, want 7777", got)
	}
	<-startCalled
	waitForTestDone(t, done)
}

func TestAcceptNotifyFD_RejectsMissingMetadataWhenEBPFRequired(t *testing.T) {
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Network.EBPF.Required = true
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	called := withNotifyHandoffHook(t)
	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0, false)
	}()

	conn := dialUnixConn(t, socketPath)
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	sendFDOverUnixConn(t, conn, int(pipeR.Fd()))
	if err := wraphandoff.ReadStatus(conn); err == nil {
		t.Fatal("expected server rejection status")
	}

	select {
	case <-called:
		t.Fatal("notify handler should not start")
	default:
	}
	waitForTestDone(t, done)
}

func TestAcceptNotifyFD_RejectsWhenNotifyHandlerFailsBeforeAck(t *testing.T) {
	enabled := true
	cfg := &config.Config{}
	cfg.Sandbox.Cgroups.Enabled = true
	cfg.Sandbox.Network.EBPF.Enabled = true
	cfg.Sandbox.Seccomp.FileMonitor.Enabled = &enabled
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	const missingWrapperPID = 999999999
	prevSetup := wrapCgroupSetupForNotifyHook
	setupCalled := make(chan int, 1)
	var cleanupCalls atomic.Int32
	wrapCgroupSetupForNotifyHook = func(ctx context.Context, a *App, s *session.Session, sessionID string, wrapperPID int) (func() error, error) {
		setupCalled <- wrapperPID
		return func() error {
			cleanupCalls.Add(1)
			return nil
		}, nil
	}
	t.Cleanup(func() {
		wrapCgroupSetupForNotifyHook = prevSetup
	})

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0, false)
	}()

	conn := dialUnixConn(t, socketPath)
	pipeR, pipeW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = pipeR.Close()
		_ = pipeW.Close()
	})

	if err := wraphandoff.SendNotifyFD(conn, int(pipeR.Fd()), wraphandoff.Metadata{WrapperPID: missingWrapperPID}); err != nil {
		t.Fatalf("send handoff: %v", err)
	}
	if err := wraphandoff.ReadStatus(conn); err == nil {
		t.Fatal("expected server rejection status")
	}
	waitForTestDone(t, done)

	select {
	case got := <-setupCalled:
		if got != missingWrapperPID {
			t.Fatalf("cgroup setup pid = %d, want %d", got, missingWrapperPID)
		}
	default:
		t.Fatal("expected cgroup setup to be called")
	}
	if got := cleanupCalls.Load(); got != 1 {
		t.Fatalf("cleanup calls = %d, want 1", got)
	}
}

func TestAcceptNotifyFD_ContinuesAfterWrongUID(t *testing.T) {
	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "notify.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, os.Getuid()+1, false)
	}()

	firstConn := dialUnixConn(t, socketPath)
	waitForConnClosed(t, firstConn)

	secondConn := dialUnixConn(t, socketPath)
	waitForConnClosed(t, secondConn)

	_ = listener.Close()
	waitForTestDone(t, done)
}

func TestAcceptSignalFD_ContinuesAfterWrongUID(t *testing.T) {
	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "signal.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptSignalFD(context.Background(), listener, socketPath, s.ID, s, os.Getuid()+1)
	}()

	firstConn := dialUnixConn(t, socketPath)
	waitForConnClosed(t, firstConn)

	secondConn := dialUnixConn(t, socketPath)
	waitForConnClosed(t, secondConn)

	_ = listener.Close()
	waitForTestDone(t, done)
}

func TestAcceptPtracePID_ContinuesAfterWrongUID(t *testing.T) {
	cfg := &config.Config{}
	app, mgr := newTestAppForWrap(t, cfg)
	s, err := mgr.Create(t.TempDir(), "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	socketDir := t.TempDir()
	socketPath := filepath.Join(socketDir, "ptrace.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	done := make(chan struct{})
	go func() {
		defer close(done)
		app.acceptPtracePID(context.Background(), listener, socketPath, s.ID, os.Getuid()+1)
	}()

	firstConn := dialUnixConn(t, socketPath)
	waitForConnClosed(t, firstConn)

	secondConn := dialUnixConn(t, socketPath)
	waitForConnClosed(t, secondConn)

	_ = listener.Close()
	waitForTestDone(t, done)
}
