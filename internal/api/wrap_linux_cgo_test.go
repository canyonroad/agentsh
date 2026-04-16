//go:build linux && cgo

package api

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGetConnPeerCreds(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "peercreds.sock")
	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serverConnCh := make(chan *net.UnixConn, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		unixConn, ok := conn.(*net.UnixConn)
		if !ok {
			_ = conn.Close()
			serverErrCh <- fmt.Errorf("expected *net.UnixConn, got %T", conn)
			return
		}
		serverConnCh <- unixConn
	}()

	clientConn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix socket: %v", err)
	}
	defer clientConn.Close()

	var serverConn *net.UnixConn
	select {
	case err := <-serverErrCh:
		t.Fatalf("accept unix socket: %v", err)
	case serverConn = <-serverConnCh:
	}
	defer serverConn.Close()

	creds := getConnPeerCreds(serverConn)
	if creds.PID != os.Getpid() {
		t.Fatalf("expected peer PID %d, got %d", os.Getpid(), creds.PID)
	}
	if creds.UID != uint32(os.Getuid()) {
		t.Fatalf("expected peer UID %d, got %d", os.Getuid(), creds.UID)
	}
}
