//go:build linux

package cli

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/wraphandoff"
)

func TestStripEnvKey(t *testing.T) {
	in := []string{"A=1", "AGENTSH_WRAPPER_LOG_FD=9", "B=2", "AGENTSH_WRAPPER_LOG_FD=10"}
	out := stripEnvKey(in, "AGENTSH_WRAPPER_LOG_FD")
	want := []string{"A=1", "B=2"}
	if len(out) != len(want) || out[0] != want[0] || out[1] != want[1] {
		t.Fatalf("stripEnvKey = %v, want %v", out, want)
	}
}

func TestForwardNotifyFDWithPIDWaitsForServerOK(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		if err := unixConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		fd, meta, hasMeta, err := wraphandoff.RecvNotifyFD(unixConn)
		if err != nil {
			serverDone <- err
			return
		}
		_ = fd.Close()
		if !hasMeta || meta.WrapperPID != 2468 {
			serverDone <- fmt.Errorf("metadata = %+v, hasMeta=%v", meta, hasMeta)
			return
		}
		serverDone <- wraphandoff.WriteStatus(unixConn, true)
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if err := forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468); err != nil {
		t.Fatalf("forward: %v", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server")
	}
}

func TestForwardNotifyFDWithPIDRejectStatusReturnsError(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		if err := unixConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err == nil {
			_ = fd.Close()
		}
		if err := wraphandoff.WriteStatus(unixConn, false); err != nil {
			serverDone <- err
			return
		}
		serverDone <- nil
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if err := forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468); err == nil {
		t.Fatal("expected reject status error")
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server")
	}
}

func TestForwardNotifyFDWithPIDTimeoutReturnsError(t *testing.T) {
	origTimeout := notifySetupStatusTimeout
	notifySetupStatusTimeout = 20 * time.Millisecond
	t.Cleanup(func() { notifySetupStatusTimeout = origTimeout })

	dir := t.TempDir()
	socketPath := filepath.Join(dir, "notify.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	releaseServer := make(chan struct{})
	defer close(releaseServer)
	serverDone := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()

		unixConn := conn.(*net.UnixConn)
		if err := unixConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			serverDone <- err
			return
		}
		fd, _, _, err := wraphandoff.RecvNotifyFD(unixConn)
		if err != nil {
			serverDone <- err
			return
		}
		_ = fd.Close()
		serverDone <- nil
		<-releaseServer
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	forwardDone := make(chan error, 1)
	go func() {
		forwardDone <- forwardNotifyFDWithPID(socketPath, int(r.Fd()), 2468)
	}()

	select {
	case err = <-forwardDone:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for forwardNotifyFDWithPID")
	}
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "timed out waiting for notify setup status") {
		t.Fatalf("error = %v, want timeout status error", err)
	}

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for server")
	}
}
