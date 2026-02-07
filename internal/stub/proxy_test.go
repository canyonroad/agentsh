package stub

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// writeExitFrame writes an MsgExit frame with the given exit code to the connection.
func writeExitFrame(t *testing.T, conn net.Conn, code int32) {
	t.Helper()
	payload := make([]byte, 4)
	binary.BigEndian.PutUint32(payload, uint32(code))
	frame := MakeFrame(MsgExit, payload)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("failed to write exit frame: %v", err)
	}
}

// readAndExpectReady reads a frame from conn and asserts it is MsgReady.
func readAndExpectReady(t *testing.T, conn net.Conn) {
	t.Helper()
	msgType, _, err := ReadFrame(conn)
	if err != nil {
		t.Fatalf("failed to read ready frame: %v", err)
	}
	if msgType != MsgReady {
		t.Fatalf("expected MsgReady (0x%02x), got 0x%02x", MsgReady, msgType)
	}
}

func TestProxy_ExitCodePropagation(t *testing.T) {
	serverConn, stubConn := net.Pipe()
	defer serverConn.Close()
	defer stubConn.Close()

	errCh := make(chan error, 1)
	exitCh := make(chan int, 1)

	go func() {
		code, err := RunProxy(stubConn, nil, &bytes.Buffer{}, &bytes.Buffer{})
		errCh <- err
		exitCh <- code
	}()

	// Server side: read the ready message, then send exit 42.
	readAndExpectReady(t, serverConn)
	writeExitFrame(t, serverConn, 42)

	err := <-errCh
	if err != nil {
		t.Fatalf("RunProxy returned error: %v", err)
	}

	code := <-exitCh
	if code != 42 {
		t.Errorf("expected exit code 42, got %d", code)
	}
}

func TestProxy_StdoutStreaming(t *testing.T) {
	serverConn, stubConn := net.Pipe()
	defer serverConn.Close()
	defer stubConn.Close()

	var stdout bytes.Buffer
	errCh := make(chan error, 1)
	exitCh := make(chan int, 1)

	go func() {
		code, err := RunProxy(stubConn, nil, &stdout, &bytes.Buffer{})
		errCh <- err
		exitCh <- code
	}()

	// Server side: read ready, send stdout data, then send exit 0.
	readAndExpectReady(t, serverConn)

	data := []byte("hello from server stdout")
	frame := MakeFrame(MsgStdout, data)
	if _, err := serverConn.Write(frame); err != nil {
		t.Fatalf("failed to write stdout frame: %v", err)
	}

	writeExitFrame(t, serverConn, 0)

	err := <-errCh
	if err != nil {
		t.Fatalf("RunProxy returned error: %v", err)
	}

	<-exitCh

	if stdout.String() != "hello from server stdout" {
		t.Errorf("stdout mismatch: got %q, want %q", stdout.String(), "hello from server stdout")
	}
}

func TestProxy_StderrStreaming(t *testing.T) {
	serverConn, stubConn := net.Pipe()
	defer serverConn.Close()
	defer stubConn.Close()

	var stderr bytes.Buffer
	errCh := make(chan error, 1)
	exitCh := make(chan int, 1)

	go func() {
		code, err := RunProxy(stubConn, nil, &bytes.Buffer{}, &stderr)
		errCh <- err
		exitCh <- code
	}()

	// Server side: read ready, send stderr data, then send exit 0.
	readAndExpectReady(t, serverConn)

	data := []byte("error output from server")
	frame := MakeFrame(MsgStderr, data)
	if _, err := serverConn.Write(frame); err != nil {
		t.Fatalf("failed to write stderr frame: %v", err)
	}

	writeExitFrame(t, serverConn, 0)

	err := <-errCh
	if err != nil {
		t.Fatalf("RunProxy returned error: %v", err)
	}

	<-exitCh

	if stderr.String() != "error output from server" {
		t.Errorf("stderr mismatch: got %q, want %q", stderr.String(), "error output from server")
	}
}

func TestProxy_StdinForwarding(t *testing.T) {
	serverConn, stubConn := net.Pipe()
	defer serverConn.Close()
	defer stubConn.Close()

	stdinData := bytes.NewReader([]byte("input from stdin"))
	errCh := make(chan error, 1)
	exitCh := make(chan int, 1)

	go func() {
		code, err := RunProxy(stubConn, stdinData, &bytes.Buffer{}, &bytes.Buffer{})
		errCh <- err
		exitCh <- code
	}()

	// Server side: read ready, then read stdin frame, then send exit.
	readAndExpectReady(t, serverConn)

	msgType, payload, err := ReadFrame(serverConn)
	if err != nil {
		t.Fatalf("failed to read stdin frame: %v", err)
	}
	if msgType != MsgStdin {
		t.Fatalf("expected MsgStdin (0x%02x), got 0x%02x", MsgStdin, msgType)
	}
	if string(payload) != "input from stdin" {
		t.Errorf("stdin payload mismatch: got %q, want %q", string(payload), "input from stdin")
	}

	writeExitFrame(t, serverConn, 0)

	err = <-errCh
	if err != nil {
		t.Fatalf("RunProxy returned error: %v", err)
	}

	<-exitCh
}

func TestProxy_ServerError(t *testing.T) {
	serverConn, stubConn := net.Pipe()
	defer serverConn.Close()
	defer stubConn.Close()

	errCh := make(chan error, 1)
	exitCh := make(chan int, 1)

	go func() {
		code, err := RunProxy(stubConn, nil, &bytes.Buffer{}, &bytes.Buffer{})
		errCh <- err
		exitCh <- code
	}()

	// Server side: read ready, send error message.
	readAndExpectReady(t, serverConn)

	errMsg := []byte("command not found")
	frame := MakeFrame(MsgError, errMsg)
	if _, err := serverConn.Write(frame); err != nil {
		t.Fatalf("failed to write error frame: %v", err)
	}

	err := <-errCh
	if err == nil {
		t.Fatal("expected error from RunProxy, got nil")
	}
	if err.Error() != "server error: command not found" {
		t.Errorf("error mismatch: got %q", err.Error())
	}
}
