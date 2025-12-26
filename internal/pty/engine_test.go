//go:build !windows

package pty

import (
	"bytes"
	"context"
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
