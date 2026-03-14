//go:build integration && linux

package ptrace

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestReadyFileWrittenAfterAttach(t *testing.T) {
	requirePtrace(t)

	readyFile := filepath.Join(t.TempDir(), "tracer-ready")

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
		ReadyFile:   readyFile,
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	// Start a child so the tracer has something to attach to.
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()

	tr.AttachPID(cmd.Process.Pid)

	if !waitForAttach(t, tr, 5*time.Second) {
		t.Fatal("tracer did not attach within 5s")
	}

	// Sentinel file should exist after attach.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(readyFile); err == nil {
			data, err := os.ReadFile(readyFile)
			if err != nil {
				t.Fatalf("read sentinel: %v", err)
			}
			if string(data) != "ready\n" {
				t.Fatalf("sentinel content = %q, want %q", string(data), "ready\n")
			}
			cancel()
			<-errCh
			return // success
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("sentinel file not written within 2s of attach")
}

func TestReadyFileNotWrittenWhenEmpty(t *testing.T) {
	requirePtrace(t)

	// Use a known directory so we can assert no file appears.
	sentinelDir := t.TempDir()

	handler := &mockExecHandler{defaultAllow: true}
	cfg := TracerConfig{
		TraceExecve: true,
		ExecHandler: handler,
		// ReadyFile intentionally empty — no sentinel should be written
	}
	tr := NewTracer(cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() { errCh <- tr.Run(ctx) }()

	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start child: %v", err)
	}
	defer cmd.Process.Kill()
	defer cmd.Wait()

	tr.AttachPID(cmd.Process.Pid)

	if !waitForAttach(t, tr, 5*time.Second) {
		t.Fatal("tracer did not attach within 5s")
	}

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-errCh

	// Assert no files were created in the sentinel directory.
	entries, err := os.ReadDir(sentinelDir)
	if err != nil {
		t.Fatalf("read sentinel dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected no files in sentinel dir, found %d", len(entries))
	}
}
