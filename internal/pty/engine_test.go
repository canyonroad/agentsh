//go:build !windows

package pty

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

func TestEngine_RunPTY(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	e := New()
	s, err := e.Start(ctx, StartRequest{
		Command: "sh",
		Args:    []string{"-lc", "printf hi"},
		InitialSize: Winsize{
			Rows: 24,
			Cols: 80,
		},
	})
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "operation not permitted") || strings.Contains(low, "permission denied") {
			t.Skipf("pty not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}

	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		for b := range s.Output() {
			out.Write(b)
		}
		close(done)
	}()

	code, err := s.Wait()
	if err != nil {
		t.Fatal(err)
	}
	<-done

	if code != 0 {
		t.Fatalf("expected exit_code 0, got %d", code)
	}
	if got := out.String(); got != "hi" {
		t.Fatalf("expected output hi, got %q", got)
	}
}

// ExtraFiles must reach the child as fd 3 (the seccomp/signal sockets the
// supervisor hands over). PTY sessions used to start the raw command with no
// fds, so the wrapper never ran.
func TestStartPassesExtraFiles(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "extra")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	engine := New()
	s, err := engine.Start(context.Background(), StartRequest{
		Command:    "/bin/sh",
		Args:       []string{"-c", "readlink /proc/self/fd/3"},
		ExtraFiles: []*os.File{f},
	})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	done := make(chan struct{})
	go func() {
		for b := range s.Output() {
			out.Write(b)
		}
		close(done)
	}()
	if _, err := s.Wait(); err != nil {
		t.Fatal(err)
	}
	<-done
	if !strings.Contains(out.String(), "extra") {
		t.Fatalf("child did not see the passed fd, output %q", out.String())
	}
}

// The wait override is used instead of cmd.Wait (ptrace reaps the child).
func TestWaitOverride(t *testing.T) {
	engine := New()
	s, err := engine.Start(context.Background(), StartRequest{
		Command: "/bin/sh",
		Args:    []string{"-c", "true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	s.SetWaitOverride(func() (int, error) { return 42, nil })
	go func() {
		for range s.Output() {
		}
	}()
	code, err := s.Wait()
	if err != nil {
		t.Fatal(err)
	}
	if code != 42 {
		t.Fatalf("exit code = %d, want the override value 42", code)
	}
}
