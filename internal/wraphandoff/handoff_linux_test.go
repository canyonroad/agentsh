//go:build linux

package wraphandoff

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func socketPairConns(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()

	dir := t.TempDir()
	path := filepath.Join(dir, "handoff.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	clientCh := make(chan *net.UnixConn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, err := net.Dial("unix", path)
		if err != nil {
			errCh <- err
			return
		}
		clientCh <- c.(*net.UnixConn)
	}()

	serverConn, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	var clientConn *net.UnixConn
	select {
	case clientConn = <-clientCh:
	case err := <-errCh:
		t.Fatalf("dial: %v", err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for client dial")
	}

	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	return clientConn, serverConn.(*net.UnixConn)
}

func setReadDeadline(t *testing.T, conn *net.UnixConn) {
	t.Helper()

	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	t.Cleanup(func() { _ = conn.SetReadDeadline(time.Time{}) })
}

func waitForAsync(t *testing.T, label string, errCh <-chan error) {
	t.Helper()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
	case <-time.After(time.Second):
		t.Fatalf("timed out waiting for %s", label)
	}
}

func sendNotifyFDAsync(conn *net.UnixConn, notifyFD int, meta Metadata) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- SendNotifyFD(conn, notifyFD, meta)
	}()
	return errCh
}

func sendFDsAsync(conn *net.UnixConn, payload []byte, fds ...int) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		rights := unix.UnixRights(fds...)
		n, oobn, err := conn.WriteMsgUnix(payload, rights, nil)
		if err != nil {
			errCh <- err
			return
		}
		if n != len(payload) || oobn != len(rights) {
			errCh <- fmt.Errorf("short unix write: n=%d/%d oobn=%d/%d", n, len(payload), oobn, len(rights))
			return
		}
		errCh <- nil
	}()
	return errCh
}

func writeStatusAsync(w io.Writer, ok bool) <-chan error {
	errCh := make(chan error, 1)
	go func() {
		errCh <- WriteStatus(w, ok)
	}()
	return errCh
}

func openFDCount(t *testing.T) int {
	t.Helper()

	entries, err := os.ReadDir(filepath.Join(string(filepath.Separator), "proc", "self", "fd"))
	if err != nil {
		t.Fatalf("read fd directory: %v", err)
	}
	return len(entries)
}

func TestNotifyHandoffRoundTripWithWrapperPID(t *testing.T) {
	client, server := socketPairConns(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	sendErr := sendNotifyFDAsync(client, int(r.Fd()), Metadata{WrapperPID: 4321})

	setReadDeadline(t, server)
	fd, meta, hasMeta, err := RecvNotifyFD(server)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	waitForAsync(t, "send notify fd", sendErr)
	t.Cleanup(func() { _ = fd.Close() })
	if !hasMeta {
		t.Fatal("expected metadata")
	}
	if meta.WrapperPID != 4321 {
		t.Fatalf("WrapperPID = %d, want 4321", meta.WrapperPID)
	}
}

func TestRecvNotifyFDLegacyFDOnly(t *testing.T) {
	client, server := socketPairConns(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	sendErr := sendFDsAsync(client, []byte{0}, int(r.Fd()))

	setReadDeadline(t, server)
	fd, meta, hasMeta, err := RecvNotifyFD(server)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	waitForAsync(t, "send legacy fd", sendErr)
	t.Cleanup(func() { _ = fd.Close() })
	if hasMeta {
		t.Fatal("expected no metadata")
	}
	if meta != (Metadata{}) {
		t.Fatalf("metadata = %+v, want zero value", meta)
	}
	gotInfo, err := fd.Stat()
	if err != nil {
		t.Fatalf("received fd stat: %v", err)
	}
	wantInfo, err := r.Stat()
	if err != nil {
		t.Fatalf("source fd stat: %v", err)
	}
	if !os.SameFile(gotInfo, wantInfo) {
		t.Fatal("received fd does not match source fd")
	}
}

func TestRecvNotifyFDRejectsMultipleFDs(t *testing.T) {
	client, server := socketPairConns(t)
	r1, w1, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe 1: %v", err)
	}
	t.Cleanup(func() {
		_ = r1.Close()
		_ = w1.Close()
	})
	r2, w2, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe 2: %v", err)
	}
	t.Cleanup(func() {
		_ = r2.Close()
		_ = w2.Close()
	})

	before := openFDCount(t)
	sendErr := sendFDsAsync(client, []byte{0}, int(r1.Fd()), int(r2.Fd()))

	setReadDeadline(t, server)
	fd, _, _, err := RecvNotifyFD(server)
	if fd != nil {
		_ = fd.Close()
	}
	waitForAsync(t, "send multiple fds", sendErr)
	if err == nil {
		t.Fatal("expected multiple fd rejection error")
	}
	if after := openFDCount(t); after != before {
		t.Fatalf("open fd count after rejected receive = %d, want %d", after, before)
	}
}

func TestRecvNotifyFDSetsCloseOnExec(t *testing.T) {
	client, server := socketPairConns(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	sendErr := sendNotifyFDAsync(client, int(r.Fd()), Metadata{WrapperPID: 4321})

	setReadDeadline(t, server)
	fd, _, _, err := RecvNotifyFD(server)
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	waitForAsync(t, "send notify fd", sendErr)
	t.Cleanup(func() { _ = fd.Close() })

	flags, err := unix.FcntlInt(fd.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatalf("fcntl getfd: %v", err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("received fd is missing FD_CLOEXEC")
	}
}

type shortWriter struct{}

func (shortWriter) Write([]byte) (int, error) {
	return 0, nil
}

func TestWriteStatusShortWrite(t *testing.T) {
	if err := WriteStatus(shortWriter{}, true); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("WriteStatus short write error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestSetupStatusRoundTrip(t *testing.T) {
	client, server := socketPairConns(t)

	successErr := writeStatusAsync(server, true)
	setReadDeadline(t, client)
	if err := ReadStatus(client); err != nil {
		t.Fatalf("read success status: %v", err)
	}
	waitForAsync(t, "write success status", successErr)

	rejectErr := writeStatusAsync(server, false)
	setReadDeadline(t, client)
	if err := ReadStatus(client); err == nil {
		t.Fatal("expected reject status error")
	}
	waitForAsync(t, "write reject status", rejectErr)
}
