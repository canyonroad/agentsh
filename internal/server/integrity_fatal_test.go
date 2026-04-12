package server

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/store/jsonl"
)

func testServerConfig(t *testing.T) *config.Config {
	t.Helper()

	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	policyContent := `version: 1
name: default
command_rules:
  - name: allow-all
    commands: ["*"]
    decision: allow
file_rules:
  - name: allow-all
    paths: ["/**"]
    operations: ["*"]
    decision: allow
`
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte(policyContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"
	return cfg
}

func TestServer_Run_ReturnsFatalAuditError(t *testing.T) {
	s, err := New(testServerConfig(t))
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer s.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- s.Run(ctx)
	}()

	fatalErr := errors.New("fatal audit integrity error")
	select {
	case s.fatalAuditErr <- fatalErr:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out sending fatal audit error")
	}

	select {
	case err := <-errCh:
		if !errors.Is(err, fatalErr) {
			t.Fatalf("Run() error = %v, want %v", err, fatalErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after fatal audit error")
	}
}

func TestServer_New_ReleasesJSONLLockWhenWebhookConfigInvalid(t *testing.T) {
	cfg := testServerConfig(t)
	cfg.Audit.Output = filepath.Join(filepath.Dir(cfg.Sessions.BaseDir), "audit.jsonl")
	cfg.Audit.Webhook.URL = "https://example.com"
	cfg.Audit.Webhook.FlushInterval = "not-a-duration"

	_, err := New(cfg)
	if err == nil {
		t.Fatal("New() error = nil, want webhook config failure")
	}
	if !strings.Contains(err.Error(), "parse audit.webhook.flush_interval") {
		t.Fatalf("New() error = %v, want webhook parse failure", err)
	}

	store, err := jsonl.New(cfg.Audit.Output, 1, 1)
	if err != nil {
		t.Fatalf("jsonl.New() after failed New() error = %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
}
