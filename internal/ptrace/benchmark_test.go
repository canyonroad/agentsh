//go:build integration && linux

package ptrace

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func BenchmarkExecOverhead(b *testing.B) {
	requirePtraceBench(b)

	handler := &mockExecHandler{defaultAllow: true}
	tr := NewTracer(TracerConfig{
		TraceExecve:      true,
		SeccompPrefilter: false,
		ExecHandler:      handler,
		MaxHoldMs:        5000,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("/bin/true")
		if err := cmd.Start(); err != nil {
			b.Fatalf("Start failed: %v", err)
		}
		tr.AttachPID(cmd.Process.Pid)
		if err := cmd.Wait(); err != nil {
			b.Fatalf("Wait failed: %v", err)
		}
	}
	b.StopTimer()

	cancel()
}

func BenchmarkFileIOOverhead(b *testing.B) {
	requirePtraceBench(b)

	fileHandler := &benchFileHandler{}
	tr := NewTracer(TracerConfig{
		TraceFile:        true,
		SeccompPrefilter: false,
		FileHandler:      fileHandler,
		MaxHoldMs:        5000,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go tr.Run(ctx)

	dir := b.TempDir()
	script := dir + "/bench.sh"
	if err := os.WriteFile(script, []byte("#!/bin/sh\ni=0\nwhile [ $i -lt 100 ]; do\n    cat /dev/null\n    i=$((i+1))\ndone\n"), 0o755); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command("/bin/sh", script)
		if err := cmd.Start(); err != nil {
			b.Fatalf("Start failed: %v", err)
		}
		tr.AttachPID(cmd.Process.Pid)
		if err := cmd.Wait(); err != nil {
			b.Fatalf("Wait failed: %v", err)
		}
	}
	b.StopTimer()

	cancel()
}

func requirePtraceBench(b *testing.B) {
	b.Helper()
	cmd := exec.Command("/bin/sleep", "0.01")
	if err := cmd.Start(); err != nil {
		b.Skip("cannot start child process")
	}
	pid := cmd.Process.Pid
	err := unix.PtraceSeize(pid)
	cmd.Process.Kill()
	cmd.Wait()
	if err != nil {
		b.Skipf("ptrace not available: %v", err)
	}
}

// benchFileHandler is a minimal allow-all FileHandler for benchmarks.
type benchFileHandler struct{}

func (benchFileHandler) HandleFile(_ context.Context, _ FileContext) FileResult {
	return FileResult{Allow: true}
}
