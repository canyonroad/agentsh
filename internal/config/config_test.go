package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ParsesServerTransportFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  http:
    addr: "127.0.0.1:8080"
    read_timeout: 30s
    write_timeout: 5m
    max_request_size: 10MB
  unix_socket:
    enabled: true
    path: "`+filepath.Join(dir, "agentsh.sock")+`"
    permissions: "0660"
  tls:
    enabled: true
    cert_file: "/tmp/server.crt"
    key_file: "/tmp/server.key"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.HTTP.ReadTimeout != "30s" {
		t.Fatalf("read_timeout: expected 30s, got %q", cfg.Server.HTTP.ReadTimeout)
	}
	if cfg.Server.HTTP.WriteTimeout != "5m" {
		t.Fatalf("write_timeout: expected 5m, got %q", cfg.Server.HTTP.WriteTimeout)
	}
	if cfg.Server.HTTP.MaxRequestSize != "10MB" {
		t.Fatalf("max_request_size: expected 10MB, got %q", cfg.Server.HTTP.MaxRequestSize)
	}
	if !cfg.Server.UnixSocket.Enabled {
		t.Fatalf("unix_socket.enabled: expected true")
	}
	if cfg.Server.UnixSocket.Permissions != "0660" {
		t.Fatalf("unix_socket.permissions: expected 0660, got %q", cfg.Server.UnixSocket.Permissions)
	}
	if !cfg.Server.TLS.Enabled {
		t.Fatalf("tls.enabled: expected true")
	}
	if cfg.Server.TLS.CertFile != "/tmp/server.crt" || cfg.Server.TLS.KeyFile != "/tmp/server.key" {
		t.Fatalf("tls files: got cert=%q key=%q", cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	}
}

func TestLoad_EnvOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  http:
    addr: "127.0.0.1:8080"
  grpc:
    enabled: true
    addr: "127.0.0.1:9090"
sessions:
  base_dir: "`+filepath.Join(dir, "sessions")+`"
audit:
  storage:
    sqlite_path: "`+filepath.Join(dir, "events.db")+`"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("AGENTSH_HTTP_ADDR", "0.0.0.0:18080")
	t.Setenv("AGENTSH_GRPC_ADDR", "0.0.0.0:19090")
	dataDir := filepath.Join(dir, "data-root")
	t.Setenv("AGENTSH_DATA_DIR", dataDir)

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Server.HTTP.Addr != "0.0.0.0:18080" {
		t.Fatalf("http addr override: got %q", cfg.Server.HTTP.Addr)
	}
	if cfg.Server.GRPC.Addr != "0.0.0.0:19090" {
		t.Fatalf("grpc addr override: got %q", cfg.Server.GRPC.Addr)
	}
	if cfg.Sessions.BaseDir != filepath.Join(dataDir, "sessions") {
		t.Fatalf("data dir override sessions.base_dir: got %q", cfg.Sessions.BaseDir)
	}
	if cfg.Audit.Storage.SQLitePath != filepath.Join(dataDir, "events.db") {
		t.Fatalf("data dir override audit sqlite_path: got %q", cfg.Audit.Storage.SQLitePath)
	}
}

func TestParseByteSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"123", 123},
		{"1KB", 1000},
		{"2MB", 2_000_000},
		{"3GB", 3_000_000_000},
		{"1KiB", 1024},
		{"2MiB", 2 * 1024 * 1024},
		{"3GiB", 3 * 1024 * 1024 * 1024},
	}
	for _, tc := range cases {
		got, err := ParseByteSize(tc.in)
		if err != nil {
			t.Fatalf("ParseByteSize(%q) error: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("ParseByteSize(%q)=%d, want %d", tc.in, got, tc.want)
		}
	}
	if _, err := ParseByteSize("nope"); err == nil {
		t.Fatalf("expected error for invalid size")
	}
}
