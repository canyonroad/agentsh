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
sandbox:
  cgroups:
    enabled: true
    base_path: "`+filepath.Join(dir, "cgroups")+`"
  network:
    ebpf:
      enabled: true
      required: true
      resolve_rdns: true
      enforce: true
      enforce_without_dns: true
      map_allow_entries: 2048
      map_deny_entries: 1024
      map_lpm_entries: 2048
      map_lpm_deny_entries: 512
      map_default_entries: 512
      dns_refresh_seconds: 45
      dns_max_ttl_seconds: 30
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
	if !cfg.Sandbox.Cgroups.Enabled {
		t.Fatalf("sandbox.cgroups.enabled: expected true")
	}
	if cfg.Sandbox.Cgroups.BasePath != filepath.Join(dir, "cgroups") {
		t.Fatalf("sandbox.cgroups.base_path: got %q", cfg.Sandbox.Cgroups.BasePath)
	}
	if !cfg.Sandbox.Network.EBPF.Enabled {
		t.Fatalf("sandbox.network.ebpf.enabled: expected true")
	}
	if !cfg.Sandbox.Network.EBPF.Required {
		t.Fatalf("sandbox.network.ebpf.required: expected true")
	}
	if !cfg.Sandbox.Network.EBPF.ResolveRDNS {
		t.Fatalf("sandbox.network.ebpf.resolve_rdns: expected true")
	}
	if !cfg.Sandbox.Network.EBPF.Enforce {
		t.Fatalf("sandbox.network.ebpf.enforce: expected true")
	}
	if !cfg.Sandbox.Network.EBPF.EnforceWithoutDNS {
		t.Fatalf("sandbox.network.ebpf.enforce_without_dns: expected true")
	}
	if cfg.Sandbox.Network.EBPF.MapAllowEntries != 2048 {
		t.Fatalf("sandbox.network.ebpf.map_allow_entries: expected 2048")
	}
	if cfg.Sandbox.Network.EBPF.MapDenyEntries != 1024 {
		t.Fatalf("sandbox.network.ebpf.map_deny_entries: expected 1024")
	}
	if cfg.Sandbox.Network.EBPF.MapLPMEntries != 2048 {
		t.Fatalf("sandbox.network.ebpf.map_lpm_entries: expected 2048")
	}
	if cfg.Sandbox.Network.EBPF.MapLPMDenyEntries != 512 {
		t.Fatalf("sandbox.network.ebpf.map_lpm_deny_entries: expected 512")
	}
	if cfg.Sandbox.Network.EBPF.MapDefaultEntries != 512 {
		t.Fatalf("sandbox.network.ebpf.map_default_entries: expected 512")
	}
	if cfg.Sandbox.Network.EBPF.DNSRefreshSeconds != 45 {
		t.Fatalf("sandbox.network.ebpf.dns_refresh_seconds: expected 45")
	}
	if cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds != 30 {
		t.Fatalf("sandbox.network.ebpf.dns_max_ttl_seconds: expected 30")
	}
}

func TestLoad_EBPFRequiredImpliesEnabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  network:
    ebpf:
      required: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Sandbox.Network.EBPF.Enabled {
		t.Fatalf("required=true should force enabled=true")
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

func TestLoad_FUSEAuditDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  fuse:
    enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Sandbox.FUSE.Audit.Mode != "monitor" {
		t.Fatalf("audit.mode default: got %q", cfg.Sandbox.FUSE.Audit.Mode)
	}
	if cfg.Sandbox.FUSE.Audit.TrashPath != ".agentsh_trash" {
		t.Fatalf("audit.trash_path default: got %q", cfg.Sandbox.FUSE.Audit.TrashPath)
	}
	if cfg.Sandbox.FUSE.Audit.TTL != "7d" {
		t.Fatalf("audit.ttl default: got %q", cfg.Sandbox.FUSE.Audit.TTL)
	}
	if cfg.Sandbox.FUSE.Audit.Quota != "5GB" {
		t.Fatalf("audit.quota default: got %q", cfg.Sandbox.FUSE.Audit.Quota)
	}
	if cfg.Sandbox.FUSE.Audit.MaxEventQueue != 1024 {
		t.Fatalf("audit.max_event_queue default: got %d", cfg.Sandbox.FUSE.Audit.MaxEventQueue)
	}
	if cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder != "1MB" {
		t.Fatalf("audit.hash_small_files_under default: got %q", cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder)
	}
	if cfg.Sandbox.FUSE.Audit.Enabled == nil || !*cfg.Sandbox.FUSE.Audit.Enabled {
		t.Fatalf("audit.enabled default: expected true")
	}
	if cfg.Sandbox.FUSE.Audit.StrictOnAuditFailure != false {
		t.Fatalf("audit.strict_on_audit_failure default: expected false, got %v", cfg.Sandbox.FUSE.Audit.StrictOnAuditFailure)
	}
}

func TestLoad_FUSEAuditCustomValues(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  fuse:
    enabled: true
    audit:
      enabled: false
      mode: soft_delete
      trash_path: "/tmp/trash"
      ttl: "3d"
      quota: "10GB"
      strict_on_audit_failure: true
      max_event_queue: 2048
      hash_small_files_under: "2MB"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	a := cfg.Sandbox.FUSE.Audit
	if a.Enabled == nil || *a.Enabled != false {
		t.Fatalf("audit.enabled: expected false, got %v", a.Enabled)
	}
	if a.Mode != "soft_delete" {
		t.Fatalf("audit.mode: expected soft_delete, got %q", a.Mode)
	}
	if a.TrashPath != "/tmp/trash" {
		t.Fatalf("audit.trash_path: expected /tmp/trash, got %q", a.TrashPath)
	}
	if a.TTL != "3d" {
		t.Fatalf("audit.ttl: expected 3d, got %q", a.TTL)
	}
	if a.Quota != "10GB" {
		t.Fatalf("audit.quota: expected 10GB, got %q", a.Quota)
	}
	if !a.StrictOnAuditFailure {
		t.Fatalf("audit.strict_on_audit_failure: expected true")
	}
	if a.MaxEventQueue != 2048 {
		t.Fatalf("audit.max_event_queue: expected 2048, got %d", a.MaxEventQueue)
	}
	if a.HashSmallFilesUnder != "2MB" {
		t.Fatalf("audit.hash_small_files_under: expected 2MB, got %q", a.HashSmallFilesUnder)
	}
}

func TestLoad_FUSEAuditInvalidMode(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  fuse:
    audit:
      mode: nope
`), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := Load(cfgPath); err == nil {
		t.Fatalf("expected error for invalid audit.mode")
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

func TestLoadWithSource(t *testing.T) {
	// Create a temp config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := []byte("platform:\n  mode: auto\n")
	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, source, err := LoadWithSource(configPath, ConfigSourceUser)
	if err != nil {
		t.Fatalf("LoadWithSource() error = %v", err)
	}
	if source != ConfigSourceUser {
		t.Errorf("LoadWithSource() source = %v, want %v", source, ConfigSourceUser)
	}
	if cfg.Platform.Mode != "auto" {
		t.Errorf("LoadWithSource() cfg.Platform.Mode = %q, want %q", cfg.Platform.Mode, "auto")
	}
}

func TestApplyDefaultsWithSource_UserSource(t *testing.T) {
	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceUser, "")

	// Sessions.BaseDir should use user data dir
	userDataDir := GetUserDataDir()
	wantSessionsDir := userDataDir + "/sessions"
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}

	// Audit.Storage.SQLitePath should use user data dir
	wantSQLitePath := userDataDir + "/events.db"
	if cfg.Audit.Storage.SQLitePath != wantSQLitePath {
		t.Errorf("Audit.Storage.SQLitePath = %q, want %q", cfg.Audit.Storage.SQLitePath, wantSQLitePath)
	}
}

func TestApplyDefaultsWithSource_SystemSource(t *testing.T) {
	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceSystem, "")

	// Sessions.BaseDir should use system data dir
	systemDataDir := GetDataDir()
	wantSessionsDir := systemDataDir + "/sessions"
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}

	// Audit.Storage.SQLitePath should use system data dir
	wantSQLitePath := systemDataDir + "/events.db"
	if cfg.Audit.Storage.SQLitePath != wantSQLitePath {
		t.Errorf("Audit.Storage.SQLitePath = %q, want %q", cfg.Audit.Storage.SQLitePath, wantSQLitePath)
	}
}

func TestApplyDefaultsWithSource_EnvSource(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "custom", "config.yaml")
	os.MkdirAll(filepath.Dir(configPath), 0755)

	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceEnv, configPath)

	// Should derive data dir from config path location
	wantDataDir := filepath.Join(tmpDir, "custom")
	wantSessionsDir := wantDataDir + "/sessions"
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}
}

func TestApplyDefaultsWithSource_PoliciesDir(t *testing.T) {
	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceUser, "")

	// Policies.Dir should use user config dir
	userConfigDir := GetUserConfigDir()
	wantPoliciesDir := userConfigDir + "/policies"
	if cfg.Policies.Dir != wantPoliciesDir {
		t.Errorf("Policies.Dir = %q, want %q", cfg.Policies.Dir, wantPoliciesDir)
	}
}

func TestLoadWithSource_FileNotFound(t *testing.T) {
	_, source, err := LoadWithSource("/nonexistent/path/config.yaml", ConfigSourceUser)
	if err == nil {
		t.Fatal("LoadWithSource() expected error for nonexistent file")
	}
	// Source should still be returned even on error
	if source != ConfigSourceUser {
		t.Errorf("LoadWithSource() source = %v on error, want %v", source, ConfigSourceUser)
	}
}

func TestLoadWithSource_InvalidYAML(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	// Write invalid YAML
	if err := os.WriteFile(configPath, []byte("invalid: yaml: content: [unclosed"), 0644); err != nil {
		t.Fatal(err)
	}

	_, source, err := LoadWithSource(configPath, ConfigSourceEnv)
	if err == nil {
		t.Fatal("LoadWithSource() expected error for invalid YAML")
	}
	if source != ConfigSourceEnv {
		t.Errorf("LoadWithSource() source = %v on error, want %v", source, ConfigSourceEnv)
	}
}

func TestApplyDefaultsWithSource_EnvSource_AllPaths(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "custom", "config.yaml")
	os.MkdirAll(filepath.Dir(configPath), 0755)

	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceEnv, configPath)

	configDir := filepath.Dir(configPath)

	// Verify Sessions.BaseDir
	wantSessionsDir := filepath.Join(configDir, "sessions")
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}

	// Verify Audit.Storage.SQLitePath
	wantSQLitePath := filepath.Join(configDir, "events.db")
	if cfg.Audit.Storage.SQLitePath != wantSQLitePath {
		t.Errorf("Audit.Storage.SQLitePath = %q, want %q", cfg.Audit.Storage.SQLitePath, wantSQLitePath)
	}

	// Verify Policies.Dir
	wantPoliciesDir := filepath.Join(configDir, "policies")
	if cfg.Policies.Dir != wantPoliciesDir {
		t.Errorf("Policies.Dir = %q, want %q", cfg.Policies.Dir, wantPoliciesDir)
	}
}
