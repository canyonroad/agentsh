package server

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/config"
)

func TestServer_UnixSocketPermissionErrorDoesNotPreventHTTP(t *testing.T) {
	dir := t.TempDir()
	policyDir := filepath.Join(dir, "policies")
	if err := os.MkdirAll(policyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policyDir, "default.yaml"), []byte("version: 1\nname: default\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ro := filepath.Join(dir, "ro")
	if err := os.MkdirAll(ro, 0o555); err != nil {
		t.Fatal(err)
	}
	sock := filepath.Join(ro, "agentsh.sock")

	cfg := &config.Config{}
	cfg.Development.DisableAuth = true
	cfg.Server.HTTP.Addr = "127.0.0.1:0"
	cfg.Server.UnixSocket.Enabled = true
	cfg.Server.UnixSocket.Path = sock
	cfg.Server.UnixSocket.Permissions = "0660"
	cfg.Sessions.BaseDir = filepath.Join(dir, "sessions")
	cfg.Audit.Storage.SQLitePath = filepath.Join(dir, "events.db")
	cfg.Policies.Dir = policyDir
	cfg.Policies.Default = "default"
	cfg.Metrics.Enabled = false
	cfg.Health.Path = "/health"
	cfg.Health.ReadinessPath = "/ready"

	s, err := New(cfg)
	if err != nil {
		if strings.Contains(strings.ToLower(err.Error()), "operation not permitted") {
			t.Skipf("listening not permitted in this environment: %v", err)
		}
		t.Fatal(err)
	}
	defer s.Close()
	if s.unixLn != nil || s.unixServer != nil {
		t.Fatalf("expected unix socket listener to be disabled on permission error")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() { errCh <- s.Run(ctx) }()

	url := "http://" + s.httpLn.Addr().String() + "/health"
	waitForHTTP200(t, url, 2*time.Second)
	cancel()
	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatalf("server did not exit after cancel")
	}
}
