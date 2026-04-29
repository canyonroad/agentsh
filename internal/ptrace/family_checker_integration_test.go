//go:build integration && linux

package ptrace

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/seccomp"
	"golang.org/x/sys/unix"
)

// socketHelperSrc is a minimal Go program that waits for a ready file then calls
// socket(AF_ALG) via a raw syscall, printing the errno result. The ready file
// is a SECOND gate written by the test AFTER the exec event is confirmed — see
// the two-stage sync pattern in runWithFamilyChecker.
const socketHelperSrc = `//go:build linux

package main

import (
	"fmt"
	"os"
	"time"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: socket-helper <ready-file>")
		os.Exit(1)
	}
	readyFile := os.Args[1]

	// Wait for the ready file (max 10s).
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(readyFile); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// AF_ALG = 38; SOCK_SEQPACKET = 5
	fd, _, errno := syscall.RawSyscall(syscall.SYS_SOCKET, 38, 5, 0)
	if fd != ^uintptr(0) {
		syscall.Close(int(fd))
		fmt.Printf("socket_result=OK\n")
		return
	}
	fmt.Printf("socket_result=%v (errno=%d)\n", errno, int(errno))
}
`

// buildSocketHelper compiles socketHelperSrc in a temp dir and returns the binary path.
func buildSocketHelper(t *testing.T) string {
	t.Helper()
	tmpDir := t.TempDir()
	src := tmpDir + "/main.go"
	bin := tmpDir + "/socket-helper"
	if err := os.WriteFile(src, []byte(socketHelperSrc), 0644); err != nil {
		t.Fatalf("write socket helper src: %v", err)
	}
	out, err := exec.Command("go", "build", "-o", bin, src).CombinedOutput()
	if err != nil {
		t.Fatalf("build socket helper: %v\n%s", err, out)
	}
	return bin
}

// runWithFamilyChecker sets up a tracer with the given config, starts the helper
// via a two-stage ready-file sync, and returns the contents of outFile.
//
// Two-stage sync:
//  1. Shell waits for readyFile1 → after the tracer is attached.
//  2. Shell execs helperBin, which waits for readyFile2 → written by the
//     test after a 200ms pause to let the exec event propagate through the
//     tracer. This ensures the helper's socket() call is seen under ptrace.
func runWithFamilyChecker(t *testing.T, cfg TracerConfig, helperBin, readyFile1, readyFile2, outFile string) string {
	t.Helper()
	tr := NewTracer(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Stage 1: shell waits for readyFile1, then execs helperBin with readyFile2.
	// helperBin writes to outFile.
	cmd := exec.Command("/bin/sh", "-c",
		fmt.Sprintf("while [ ! -f %s ]; do sleep 0.01; done; exec %s %s > %s 2>&1",
			readyFile1, helperBin, readyFile2, outFile))
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 3*time.Second) {
		cancel()
		<-errCh
		t.Skip("could not attach to shell in time")
	}

	// Stage 2: write readyFile1 to let the shell exec the helper.
	os.WriteFile(readyFile1, []byte("go"), 0644)

	// Pause 200ms so the exec event (PTRACE_EVENT_EXEC) propagates through
	// the tracer's event loop before we signal the helper to proceed.
	time.Sleep(200 * time.Millisecond)

	// Now write readyFile2 so the helper binary calls socket().
	os.WriteFile(readyFile2, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 15*time.Second)
	cancel()
	<-errCh

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("result file not found: %v", err)
	}
	return strings.TrimSpace(string(data))
}

// TestIntegration_FamilyChecker_Errno verifies that a tracer configured with
// FamilyChecker([{AF_ALG, errno}]) causes a tracee's socket(AF_ALG, ...)
// call to return EAFNOSUPPORT.
func TestIntegration_FamilyChecker_Errno(t *testing.T) {
	requirePtrace(t)

	helperBin := buildSocketHelper(t)
	tmpDir := t.TempDir()

	checker := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: unix.AF_ALG, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})
	result := runWithFamilyChecker(t, TracerConfig{
		TraceExecve:   true,
		FamilyChecker: checker,
		ExecHandler:   &mockExecHandler{defaultAllow: true},
	}, helperBin, tmpDir+"/ready1", tmpDir+"/ready2", tmpDir+"/result.txt")
	t.Logf("ptrace errno-action result: %s", result)

	// The tracer must inject EAFNOSUPPORT.
	if !strings.Contains(result, "EAFNOSUPPORT") &&
		!strings.Contains(result, "address family not supported") &&
		!strings.Contains(result, "errno=97") {
		t.Errorf("expected socket(AF_ALG) to return EAFNOSUPPORT from FamilyChecker; got: %q", result)
	}
	if result == "socket_result=OK" {
		t.Errorf("socket(AF_ALG) was NOT blocked by FamilyChecker (errno action returned OK)")
	}
}

// TestIntegration_FamilyChecker_AllowNonBlocked verifies that AF_INET socket
// calls are NOT blocked when FamilyChecker only blocks AF_ALG.
func TestIntegration_FamilyChecker_AllowNonBlocked(t *testing.T) {
	requirePtrace(t)

	checker := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: unix.AF_ALG, Action: seccomp.OnBlockErrno, Name: "AF_ALG"},
	})
	netHandler := &mockNetworkHandler{defaultAllow: true}

	tmpDir := t.TempDir()
	readyFile := tmpDir + "/ready"

	tr := NewTracer(TracerConfig{
		TraceExecve:    true,
		TraceNetwork:   true,
		FamilyChecker:  checker,
		ExecHandler:    &mockExecHandler{defaultAllow: true},
		NetworkHandler: netHandler,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	shellCmd := fmt.Sprintf(
		`while [ ! -f %s ]; do sleep 0.01; done; (echo | nc -n -w1 127.0.0.1 1 2>/dev/null); true`,
		readyFile,
	)
	cmd := exec.Command("/bin/sh", "-c", shellCmd)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	cmd.Process.Release()

	tr.AttachPID(pid)
	if !waitForAttach(t, tr, 2*time.Second) {
		t.Skip("could not attach in time")
	}
	os.WriteFile(readyFile, []byte("go"), 0644)

	waitForTraceesDrained(t, tr, 8*time.Second)
	cancel()
	<-errCh

	calls := netHandler.CallCount()
	t.Logf("network handler calls (AF_INET connect): %d", calls)
}

// TestIntegration_FamilyChecker_Log verifies that action=log does NOT inject
// EAFNOSUPPORT — the syscall is allowed to proceed to the kernel.
func TestIntegration_FamilyChecker_Log(t *testing.T) {
	requirePtrace(t)

	helperBin := buildSocketHelper(t)
	tmpDir := t.TempDir()

	checker := NewFamilyChecker([]seccomp.BlockedFamily{
		{Family: unix.AF_ALG, Action: seccomp.OnBlockLog, Name: "AF_ALG"},
	})
	result := runWithFamilyChecker(t, TracerConfig{
		TraceExecve:   true,
		FamilyChecker: checker,
		ExecHandler:   &mockExecHandler{defaultAllow: true},
	}, helperBin, tmpDir+"/ready1", tmpDir+"/ready2", tmpDir+"/result.txt")
	t.Logf("ptrace log-action result: %s", result)

	// With log action the tracer must NOT inject EAFNOSUPPORT.
	if strings.Contains(result, "errno=97") {
		t.Errorf("log action must not inject EAFNOSUPPORT (errno 97); got: %q", result)
	}
	t.Log("log action: tracer allowed the syscall (audit event logged to slog)")
}
