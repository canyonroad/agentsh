package api

import (
	"bytes"
	"log/slog"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCloseWrapperLogPipe_IdempotentAndNilSafe(t *testing.T) {
	var nilCfg *extraProcConfig
	nilCfg.closeWrapperLogPipe() // must not panic

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cfg := &extraProcConfig{wrapperLogParent: r, wrapperLogChild: w}
	cfg.closeWrapperLogPipe()
	if cfg.wrapperLogParent != nil || cfg.wrapperLogChild != nil {
		t.Fatal("fields not nil-ed after close")
	}
	// Second write end close must have happened: writing to a closed
	// pipe *os.File errors immediately.
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("write end not closed")
	}
	cfg.closeWrapperLogPipe() // idempotent — must not panic
}

// syncBuffer makes bytes.Buffer safe for the drain goroutine + test reader.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestStartWrapperLogDrain_ForwardsLinesToLogger(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}

	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	done := startWrapperLogDrain(r, logger, "sess-1", "/bin/true")

	if _, err := w.WriteString("seccomp: filter loaded fd=8 wait_killable=true\nlandlock: restrictions applied\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	w.Close() // EOF → drain goroutine exits

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("drain goroutine did not finish after EOF")
	}

	out := buf.String()
	for _, want := range []string{
		"seccomp: filter loaded",
		"wait_killable=true",
		"landlock: restrictions applied",
		"session_id=sess-1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("drained log missing %q, got:\n%s", want, out)
		}
	}
}
