package proxy

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

type lockedBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func TestNew_RetentionUsesStorageBaseDir(t *testing.T) {
	storagePath := filepath.Join(t.TempDir(), "sessions")
	if err := os.MkdirAll(storagePath, 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	logs := &lockedBuffer{}
	logger := slog.New(slog.NewTextHandler(io.Writer(logs), nil))

	cfg := Config{
		SessionID: "session-current",
		Proxy:     config.DefaultProxyConfig(),
		DLP:       config.DefaultDLPConfig(),
		Storage:   config.DefaultLLMStorageConfig(),
	}
	cfg.Storage.Retention.MaxAgeDays = 1
	cfg.Storage.Retention.MaxSizeMB = 0

	p, err := New(cfg, storagePath, logger)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if p.storage != nil {
		defer p.storage.Close()
	}

	want := "sessions_dir=" + storagePath
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if out := logs.String(); strings.Contains(out, "retention cleanup started") {
			if !strings.Contains(out, want) {
				t.Fatalf("retention log = %q, want %q", out, want)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	t.Fatalf("did not observe retention startup log; logs=%q", logs.String())
}
