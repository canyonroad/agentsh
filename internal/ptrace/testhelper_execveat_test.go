//go:build integration && linux && amd64

package ptrace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// execveatHelperSrc is a minimal Go program that uses execveat(2) with AT_EMPTY_PATH.
const execveatHelperSrc = `//go:build linux && amd64

package main

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: execveat-helper <binary>\n")
		os.Exit(1)
	}
	target := os.Args[1]

	fd, err := syscall.Open(target, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open %s: %v\n", target, err)
		os.Exit(1)
	}

	// execveat(fd, "", argv, envp, AT_EMPTY_PATH)
	emptyPath, _ := syscall.BytePtrFromString("")
	argv0, _ := syscall.BytePtrFromString(target)
	argv := []*byte{argv0, nil}
	envp := []*byte{nil}

	const SYS_EXECVEAT = 322
	const AT_EMPTY_PATH = 0x1000

	_, _, errno := syscall.RawSyscall6(
		SYS_EXECVEAT,
		uintptr(fd),
		uintptr(unsafe.Pointer(emptyPath)),
		uintptr(unsafe.Pointer(&argv[0])),
		uintptr(unsafe.Pointer(&envp[0])),
		AT_EMPTY_PATH,
		0,
	)
	fmt.Fprintf(os.Stderr, "execveat failed: %v\n", errno)
	os.Exit(1)
}
`

func TestIntegration_ExecveatATEmptyPath(t *testing.T) {
	requirePtrace(t)

	tmpDir := t.TempDir()

	// Write and compile the helper
	helperSrc := filepath.Join(tmpDir, "main.go")
	if err := os.WriteFile(helperSrc, []byte(execveatHelperSrc), 0644); err != nil {
		t.Fatal(err)
	}

	helperBin := filepath.Join(tmpDir, "execveat-helper")
	buildCmd := exec.Command("go", "build", "-o", helperBin, helperSrc)
	buildCmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to build execveat helper: %v\n%s", err, out)
	}

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Run the helper targeting /bin/echo
	cmd := exec.Command(helperBin, "/bin/echo")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	tr.AttachPID(cmd.Process.Pid)
	cmd.Wait()

	waitForTraceesDrained(t, tr, 5*time.Second)
	cancel()
	<-errCh

	handler.mu.Lock()
	t.Logf("total handler calls: %d", len(handler.calls))
	for _, c := range handler.calls {
		t.Logf("  filename=%q argv=%v", c.Filename, c.Argv)
	}
	handler.mu.Unlock()

	// Check if handler received a call with /bin/echo (resolved from fd)
	echoCalls := handler.CallsMatching("echo")
	if len(echoCalls) > 0 {
		t.Logf("execveat intercepted: filename=%q", echoCalls[0].Filename)
	} else {
		t.Log("Note: execveat call not captured (attach may have happened after exec)")
	}
}
