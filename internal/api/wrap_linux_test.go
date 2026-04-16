//go:build linux

package api

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/session"
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
	startNotifyHandlerForWrapHook = func(ctx context.Context, notifyFD *os.File, sessionID string, a *App, execveEnabled bool, wrapperPID int, s *session.Session) {
		if notifyFD != nil {
			_ = notifyFD.Close()
		}
		close(called)
	}
	t.Cleanup(func() {
		startNotifyHandlerForWrapHook = prev
	})
	return called
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
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 99999)
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
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, -1)
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
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, currentUID)
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
		app.acceptNotifyFD(context.Background(), listener, socketPath, s.ID, s, false, 0)
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
