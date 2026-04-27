package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

func loadFromString(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	return Load(p)
}

func TestLoad_ParsesServerTransportFields(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	// Use forward slashes in YAML to avoid Windows backslash escape issues
	sockPath := filepath.ToSlash(filepath.Join(dir, "agentsh.sock"))
	cgroupsPath := filepath.ToSlash(filepath.Join(dir, "cgroups"))
	if err := os.WriteFile(cfgPath, []byte(`
server:
  http:
    addr: "127.0.0.1:18080"
    read_timeout: 30s
    write_timeout: 5m
    max_request_size: 10MB
  unix_socket:
    enabled: true
    path: "`+sockPath+`"
    permissions: "0660"
  tls:
    enabled: true
    cert_file: "/tmp/server.crt"
    key_file: "/tmp/server.key"
sandbox:
  cgroups:
    enabled: true
    base_path: "`+cgroupsPath+`"
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
	// Compare against the forward-slash path that was written to YAML
	if cfg.Sandbox.Cgroups.BasePath != cgroupsPath {
		t.Fatalf("sandbox.cgroups.base_path: got %q, want %q", cfg.Sandbox.Cgroups.BasePath, cgroupsPath)
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
	// Use forward slashes in YAML to avoid Windows backslash escape issues
	sessionsPath := filepath.ToSlash(filepath.Join(dir, "sessions"))
	eventsPath := filepath.ToSlash(filepath.Join(dir, "events.db"))
	if err := os.WriteFile(cfgPath, []byte(`
server:
  http:
    addr: "127.0.0.1:18080"
  grpc:
    enabled: true
    addr: "127.0.0.1:9090"
sessions:
  base_dir: "`+sessionsPath+`"
audit:
  storage:
    sqlite_path: "`+eventsPath+`"
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

func TestLoad_FUSEDeferredConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  fuse:
    enabled: true
    deferred: true
    deferred_marker_file: "/tmp/.fuse-ready"
    deferred_enable_command: ["sudo", "/bin/chmod", "666", "/dev/fuse"]
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, cfg.Sandbox.FUSE.Enabled)
	assert.True(t, cfg.Sandbox.FUSE.Deferred)
	assert.Equal(t, "/tmp/.fuse-ready", cfg.Sandbox.FUSE.DeferredMarkerFile)
	assert.Equal(t, []string{"sudo", "/bin/chmod", "666", "/dev/fuse"}, cfg.Sandbox.FUSE.DeferredEnableCommand)
}

func TestLoad_FUSEDeferredDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  fuse:
    enabled: true
    deferred: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	assert.True(t, cfg.Sandbox.FUSE.Deferred)
	assert.Empty(t, cfg.Sandbox.FUSE.DeferredMarkerFile)
	assert.Empty(t, cfg.Sandbox.FUSE.DeferredEnableCommand)
}

func TestLoad_UnixSocketsDefaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	// Empty config - should get defaults
	if err := os.WriteFile(cfgPath, []byte(``), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// UnixSockets.Enabled should default to true for seccomp enforcement
	if cfg.Sandbox.UnixSockets.Enabled == nil {
		t.Fatal("unix_sockets.enabled should not be nil")
	}
	if !*cfg.Sandbox.UnixSockets.Enabled {
		t.Fatal("unix_sockets.enabled should default to true")
	}
}

func TestLoad_UnixSocketsExplicitDisable(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  unix_sockets:
    enabled: false
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Explicit false should be respected
	if cfg.Sandbox.UnixSockets.Enabled == nil {
		t.Fatal("unix_sockets.enabled should not be nil")
	}
	if *cfg.Sandbox.UnixSockets.Enabled {
		t.Fatal("unix_sockets.enabled: explicit false should be respected")
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
	wantSessionsDir := filepath.Join(userDataDir, "sessions")
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}

	// Audit.Storage.SQLitePath should use user data dir
	wantSQLitePath := filepath.Join(userDataDir, "events.db")
	if cfg.Audit.Storage.SQLitePath != wantSQLitePath {
		t.Errorf("Audit.Storage.SQLitePath = %q, want %q", cfg.Audit.Storage.SQLitePath, wantSQLitePath)
	}
}

func TestApplyDefaultsWithSource_SystemSource(t *testing.T) {
	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceSystem, "")

	// Sessions.BaseDir should use system data dir
	systemDataDir := GetDataDir()
	wantSessionsDir := filepath.Join(systemDataDir, "sessions")
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}

	// Audit.Storage.SQLitePath should use system data dir
	wantSQLitePath := filepath.Join(systemDataDir, "events.db")
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
	wantSessionsDir := filepath.Join(wantDataDir, "sessions")
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}
}

func TestApplyDefaultsWithSource_PoliciesDir(t *testing.T) {
	cfg := &Config{}
	applyDefaultsWithSource(cfg, ConfigSourceUser, "")

	// Policies.Dir should use user config dir
	userConfigDir := GetUserConfigDir()
	wantPoliciesDir := filepath.Join(userConfigDir, "policies")
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

func TestLoad_ExpandsEnvVars(t *testing.T) {
	// Set a test env var
	t.Setenv("TEST_AGENTSH_DIR", "/custom/test/path")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := []byte(`
sessions:
  base_dir: "${TEST_AGENTSH_DIR}/sessions"
policies:
  dir: "$TEST_AGENTSH_DIR/policies"
`)
	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	// Verify env vars were expanded
	wantSessionsDir := "/custom/test/path/sessions"
	if cfg.Sessions.BaseDir != wantSessionsDir {
		t.Errorf("Sessions.BaseDir = %q, want %q", cfg.Sessions.BaseDir, wantSessionsDir)
	}

	wantPoliciesDir := "/custom/test/path/policies"
	if cfg.Policies.Dir != wantPoliciesDir {
		t.Errorf("Policies.Dir = %q, want %q", cfg.Policies.Dir, wantPoliciesDir)
	}
}

func TestLoadWithSource_ExpandsEnvVars(t *testing.T) {
	// Set a test env var
	t.Setenv("TEST_HOME", "/home/testuser")

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	content := []byte(`
audit:
  storage:
    sqlite_path: "${TEST_HOME}/.local/share/agentsh/events.db"
`)
	if err := os.WriteFile(configPath, content, 0644); err != nil {
		t.Fatal(err)
	}

	cfg, _, err := LoadWithSource(configPath, ConfigSourceUser)
	if err != nil {
		t.Fatalf("LoadWithSource() error = %v", err)
	}

	wantPath := "/home/testuser/.local/share/agentsh/events.db"
	if cfg.Audit.Storage.SQLitePath != wantPath {
		t.Errorf("Audit.Storage.SQLitePath = %q, want %q", cfg.Audit.Storage.SQLitePath, wantPath)
	}
}

func TestLoad_ProxyEnvOverrides(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")

	// Create config with default proxy settings
	if err := os.WriteFile(cfgPath, []byte(`
proxy:
  mode: embedded
  port: 0
dlp:
  mode: redact
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Set environment overrides
	t.Setenv("AGENTSH_PROXY_MODE", "disabled")
	t.Setenv("AGENTSH_DLP_MODE", "disabled")
	t.Setenv("AGENTSH_PROXY_PORT", "12345")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Proxy.Mode != "disabled" {
		t.Errorf("Proxy.Mode = %q, want %q", cfg.Proxy.Mode, "disabled")
	}
	if cfg.DLP.Mode != "disabled" {
		t.Errorf("DLP.Mode = %q, want %q", cfg.DLP.Mode, "disabled")
	}
	if cfg.Proxy.Port != 12345 {
		t.Errorf("Proxy.Port = %d, want %d", cfg.Proxy.Port, 12345)
	}
}

func TestLoad_ProxyEnvOverrides_InvalidPort(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")

	// Create config with a specific port
	if err := os.WriteFile(cfgPath, []byte(`
proxy:
  port: 8080
`), 0o600); err != nil {
		t.Fatal(err)
	}

	// Set invalid port value - should be silently ignored
	t.Setenv("AGENTSH_PROXY_PORT", "not-a-number")

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Port should remain at the config value since env override was invalid
	if cfg.Proxy.Port != 8080 {
		t.Errorf("Proxy.Port = %d, want %d (invalid env should be ignored)", cfg.Proxy.Port, 8080)
	}
}

func TestLoad_MCPSecurityConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  mcp:
    enforce_policy: true
    fail_closed: true
    tool_policy: allowlist
    allowed_tools:
      - server: "filesystem"
        tool: "read_file"
        content_hash: "sha256:abc123"
      - server: "*"
        tool: "get_weather"
    denied_tools:
      - server: "dangerous-server"
        tool: "*"
    version_pinning:
      enabled: true
      on_change: block
      auto_trust_first: true
    rate_limits:
      enabled: true
      default_rpm: 60
      default_burst: 10
      per_server:
        "filesystem":
          calls_per_minute: 120
          burst: 20
        "slow-server":
          calls_per_minute: 10
          burst: 2
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	mcp := cfg.Sandbox.MCP

	// Test top-level settings
	if !mcp.EnforcePolicy {
		t.Errorf("MCP.EnforcePolicy = false, want true")
	}
	if !mcp.FailClosed {
		t.Errorf("MCP.FailClosed = false, want true")
	}
	if mcp.ToolPolicy != "allowlist" {
		t.Errorf("MCP.ToolPolicy = %q, want %q", mcp.ToolPolicy, "allowlist")
	}

	// Test allowed_tools
	if len(mcp.AllowedTools) != 2 {
		t.Fatalf("MCP.AllowedTools len = %d, want 2", len(mcp.AllowedTools))
	}
	if mcp.AllowedTools[0].Server != "filesystem" {
		t.Errorf("AllowedTools[0].Server = %q, want %q", mcp.AllowedTools[0].Server, "filesystem")
	}
	if mcp.AllowedTools[0].Tool != "read_file" {
		t.Errorf("AllowedTools[0].Tool = %q, want %q", mcp.AllowedTools[0].Tool, "read_file")
	}
	if mcp.AllowedTools[0].ContentHash != "sha256:abc123" {
		t.Errorf("AllowedTools[0].ContentHash = %q, want %q", mcp.AllowedTools[0].ContentHash, "sha256:abc123")
	}
	if mcp.AllowedTools[1].Server != "*" {
		t.Errorf("AllowedTools[1].Server = %q, want %q", mcp.AllowedTools[1].Server, "*")
	}

	// Test denied_tools
	if len(mcp.DeniedTools) != 1 {
		t.Fatalf("MCP.DeniedTools len = %d, want 1", len(mcp.DeniedTools))
	}
	if mcp.DeniedTools[0].Server != "dangerous-server" {
		t.Errorf("DeniedTools[0].Server = %q, want %q", mcp.DeniedTools[0].Server, "dangerous-server")
	}
	if mcp.DeniedTools[0].Tool != "*" {
		t.Errorf("DeniedTools[0].Tool = %q, want %q", mcp.DeniedTools[0].Tool, "*")
	}

	// Test version_pinning
	if !mcp.VersionPinning.Enabled {
		t.Errorf("MCP.VersionPinning.Enabled = false, want true")
	}
	if mcp.VersionPinning.OnChange != "block" {
		t.Errorf("MCP.VersionPinning.OnChange = %q, want %q", mcp.VersionPinning.OnChange, "block")
	}
	if !mcp.VersionPinning.AutoTrustFirst {
		t.Errorf("MCP.VersionPinning.AutoTrustFirst = false, want true")
	}

	// Test rate_limits
	if !mcp.RateLimits.Enabled {
		t.Errorf("MCP.RateLimits.Enabled = false, want true")
	}
	if mcp.RateLimits.DefaultRPM != 60 {
		t.Errorf("MCP.RateLimits.DefaultRPM = %d, want %d", mcp.RateLimits.DefaultRPM, 60)
	}
	if mcp.RateLimits.DefaultBurst != 10 {
		t.Errorf("MCP.RateLimits.DefaultBurst = %d, want %d", mcp.RateLimits.DefaultBurst, 10)
	}
	if len(mcp.RateLimits.PerServer) != 2 {
		t.Fatalf("MCP.RateLimits.PerServer len = %d, want 2", len(mcp.RateLimits.PerServer))
	}
	if fsLimit, ok := mcp.RateLimits.PerServer["filesystem"]; !ok {
		t.Errorf("MCP.RateLimits.PerServer missing 'filesystem'")
	} else {
		if fsLimit.CallsPerMinute != 120 {
			t.Errorf("filesystem.CallsPerMinute = %d, want %d", fsLimit.CallsPerMinute, 120)
		}
		if fsLimit.Burst != 20 {
			t.Errorf("filesystem.Burst = %d, want %d", fsLimit.Burst, 20)
		}
	}
	if slowLimit, ok := mcp.RateLimits.PerServer["slow-server"]; !ok {
		t.Errorf("MCP.RateLimits.PerServer missing 'slow-server'")
	} else {
		if slowLimit.CallsPerMinute != 10 {
			t.Errorf("slow-server.CallsPerMinute = %d, want %d", slowLimit.CallsPerMinute, 10)
		}
		if slowLimit.Burst != 2 {
			t.Errorf("slow-server.Burst = %d, want %d", slowLimit.Burst, 2)
		}
	}
}

func TestLoad_MCPSecurityConfig_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	// Empty config - MCP should have zero values
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	mcp := cfg.Sandbox.MCP

	// Verify all defaults are zero values
	if mcp.EnforcePolicy {
		t.Errorf("MCP.EnforcePolicy default should be false")
	}
	if mcp.FailClosed {
		t.Errorf("MCP.FailClosed default should be false")
	}
	if mcp.ToolPolicy != "" {
		t.Errorf("MCP.ToolPolicy default should be empty, got %q", mcp.ToolPolicy)
	}
	if len(mcp.AllowedTools) != 0 {
		t.Errorf("MCP.AllowedTools default should be empty")
	}
	if len(mcp.DeniedTools) != 0 {
		t.Errorf("MCP.DeniedTools default should be empty")
	}
	if mcp.VersionPinning.Enabled {
		t.Errorf("MCP.VersionPinning.Enabled default should be false")
	}
	if mcp.RateLimits.Enabled {
		t.Errorf("MCP.RateLimits.Enabled default should be false")
	}
}

func TestPoliciesConfig_ShouldDetectProjectRoot(t *testing.T) {
	t.Run("nil returns true (default)", func(t *testing.T) {
		cfg := &PoliciesConfig{}
		assert.True(t, cfg.ShouldDetectProjectRoot())
	})

	t.Run("explicit true returns true", func(t *testing.T) {
		val := true
		cfg := &PoliciesConfig{DetectProjectRoot: &val}
		assert.True(t, cfg.ShouldDetectProjectRoot())
	})

	t.Run("explicit false returns false", func(t *testing.T) {
		val := false
		cfg := &PoliciesConfig{DetectProjectRoot: &val}
		assert.False(t, cfg.ShouldDetectProjectRoot())
	})
}

func TestPoliciesConfig_GetProjectMarkers(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		cfg := &PoliciesConfig{}
		assert.Nil(t, cfg.GetProjectMarkers())
	})

	t.Run("empty returns nil", func(t *testing.T) {
		cfg := &PoliciesConfig{ProjectMarkers: []string{}}
		assert.Nil(t, cfg.GetProjectMarkers())
	})

	t.Run("custom markers returns markers", func(t *testing.T) {
		markers := []string{".git", "Makefile"}
		cfg := &PoliciesConfig{ProjectMarkers: markers}
		assert.Equal(t, markers, cfg.GetProjectMarkers())
	})
}

func TestLoad_EnvInjectConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
    MY_CUSTOM_VAR: "custom_value"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify env_inject was parsed correctly
	if cfg.Sandbox.EnvInject == nil {
		t.Fatal("sandbox.env_inject should not be nil")
	}
	if len(cfg.Sandbox.EnvInject) != 2 {
		t.Fatalf("sandbox.env_inject: expected 2 entries, got %d", len(cfg.Sandbox.EnvInject))
	}
	if cfg.Sandbox.EnvInject["BASH_ENV"] != "/usr/lib/agentsh/bash_startup.sh" {
		t.Fatalf("sandbox.env_inject[BASH_ENV]: expected '/usr/lib/agentsh/bash_startup.sh', got %q", cfg.Sandbox.EnvInject["BASH_ENV"])
	}
	if cfg.Sandbox.EnvInject["MY_CUSTOM_VAR"] != "custom_value" {
		t.Fatalf("sandbox.env_inject[MY_CUSTOM_VAR]: expected 'custom_value', got %q", cfg.Sandbox.EnvInject["MY_CUSTOM_VAR"])
	}
}

func TestLoad_EnvInjectConfig_Empty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	// Empty config - env_inject should be nil or empty map
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// Verify env_inject is nil or empty when not configured
	if cfg.Sandbox.EnvInject != nil && len(cfg.Sandbox.EnvInject) > 0 {
		t.Fatalf("sandbox.env_inject: expected nil or empty, got %v", cfg.Sandbox.EnvInject)
	}
}

func TestOTELConfigParsing(t *testing.T) {
	yaml := `
audit:
  otel:
    enabled: true
    endpoint: "collector.example.com:4317"
    protocol: grpc
    tls:
      enabled: true
      cert_file: "/etc/certs/client.crt"
      key_file: "/etc/certs/client.key"
    headers:
      Authorization: "Bearer test-token"
    timeout: "15s"
    signals:
      logs: true
      spans: false
    batch:
      max_size: 256
      timeout: "3s"
    filter:
      include_types: ["file_*", "net_*"]
      exclude_types: ["file_stat"]
      include_categories: ["file", "network"]
      min_risk_level: "medium"
    resource:
      service_name: "my-agentsh"
      extra_attributes:
        environment: "production"
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	otel := cfg.Audit.OTEL
	if !otel.Enabled {
		t.Error("expected otel.enabled=true")
	}
	if otel.Endpoint != "collector.example.com:4317" {
		t.Errorf("endpoint = %q", otel.Endpoint)
	}
	if otel.Protocol != "grpc" {
		t.Errorf("protocol = %q", otel.Protocol)
	}
	if !otel.TLS.Enabled {
		t.Error("expected tls.enabled=true")
	}
	if otel.Headers["Authorization"] != "Bearer test-token" {
		t.Errorf("headers = %v", otel.Headers)
	}
	if otel.Timeout != "15s" {
		t.Errorf("timeout = %q", otel.Timeout)
	}
	if !otel.Signals.Logs || otel.Signals.Spans {
		t.Errorf("signals = %+v", otel.Signals)
	}
	if otel.Batch.MaxSize != 256 {
		t.Errorf("batch.max_size = %d", otel.Batch.MaxSize)
	}
	if len(otel.Filter.IncludeTypes) != 2 || otel.Filter.IncludeTypes[0] != "file_*" {
		t.Errorf("filter.include_types = %v", otel.Filter.IncludeTypes)
	}
	if otel.Filter.MinRiskLevel != "medium" {
		t.Errorf("filter.min_risk_level = %q", otel.Filter.MinRiskLevel)
	}
	if otel.Resource.ServiceName != "my-agentsh" {
		t.Errorf("resource.service_name = %q", otel.Resource.ServiceName)
	}
}

func TestOTELConfigDefaults(t *testing.T) {
	yaml := `
audit:
  otel:
    enabled: true
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	otel := cfg.Audit.OTEL
	if otel.Endpoint != "localhost:4317" {
		t.Errorf("default endpoint = %q, want localhost:4317", otel.Endpoint)
	}
	if otel.Protocol != "grpc" {
		t.Errorf("default protocol = %q, want grpc", otel.Protocol)
	}
	if otel.Timeout != "10s" {
		t.Errorf("default timeout = %q, want 10s", otel.Timeout)
	}
	if !otel.Signals.Logs || !otel.Signals.Spans {
		t.Errorf("default signals = %+v, want both true", otel.Signals)
	}
	if otel.Batch.MaxSize != 512 {
		t.Errorf("default batch.max_size = %d, want 512", otel.Batch.MaxSize)
	}
	if otel.Resource.ServiceName != "agentsh" {
		t.Errorf("default resource.service_name = %q, want agentsh", otel.Resource.ServiceName)
	}
}

func TestOTELConfigEnvOverrides(t *testing.T) {
	yaml := `
audit:
  otel:
    enabled: true
`
	path := filepath.Join(t.TempDir(), "config.yaml")
	os.WriteFile(path, []byte(yaml), 0644)

	t.Setenv("AGENTSH_OTEL_ENDPOINT", "otel.prod:4317")
	t.Setenv("AGENTSH_OTEL_PROTOCOL", "http")

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Audit.OTEL.Endpoint != "otel.prod:4317" {
		t.Errorf("endpoint = %q, want otel.prod:4317", cfg.Audit.OTEL.Endpoint)
	}
	if cfg.Audit.OTEL.Protocol != "http" {
		t.Errorf("protocol = %q, want http", cfg.Audit.OTEL.Protocol)
	}
}

func TestOTELConfigValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "invalid protocol",
			yaml: `
audit:
  otel:
    enabled: true
    protocol: websocket
`,
			wantErr: "invalid audit.otel.protocol",
		},
		{
			name: "invalid risk level",
			yaml: `
audit:
  otel:
    enabled: true
    filter:
      min_risk_level: "extreme"
`,
			wantErr: "invalid audit.otel.filter.min_risk_level",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(path, []byte(tt.yaml), 0644)

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("Load() error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_MCPServerDeclarations(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  mcp:
    enforce_policy: true
    fail_closed: true
    servers:
      - id: filesystem
        type: stdio
        command: npx
        args: ["@modelcontextprotocol/server-filesystem", "/home/user"]
      - id: weather-api
        type: http
        url: https://mcp.example.com/sse
      - id: internal-tools
        type: http
        url: https://mcp.internal.corp:8443/mcp
        tls_fingerprint: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    server_policy: allowlist
    allowed_servers:
      - id: filesystem
      - id: weather-api
    denied_servers:
      - id: "*"
    tool_policy: denylist
    allowed_tools:
      - server: "*"
        tool: "*"
    denied_tools:
      - server: weather-api
        tool: "delete_*"
    version_pinning:
      enabled: true
      on_change: block
      auto_trust_first: true
    rate_limits:
      enabled: true
      default_rpm: 60
      per_server:
        weather-api:
          calls_per_minute: 10
          burst: 3
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	mcp := cfg.Sandbox.MCP

	// Verify top-level settings
	assert.True(t, mcp.EnforcePolicy)
	assert.True(t, mcp.FailClosed)

	// Verify server declarations
	assert.Equal(t, 3, len(mcp.Servers))

	assert.Equal(t, "filesystem", mcp.Servers[0].ID)
	assert.Equal(t, "stdio", mcp.Servers[0].Type)
	assert.Equal(t, "npx", mcp.Servers[0].Command)
	assert.Equal(t, []string{"@modelcontextprotocol/server-filesystem", "/home/user"}, mcp.Servers[0].Args)
	assert.Empty(t, mcp.Servers[0].URL)

	assert.Equal(t, "weather-api", mcp.Servers[1].ID)
	assert.Equal(t, "http", mcp.Servers[1].Type)
	assert.Equal(t, "https://mcp.example.com/sse", mcp.Servers[1].URL)
	assert.Empty(t, mcp.Servers[1].Command)

	assert.Equal(t, "internal-tools", mcp.Servers[2].ID)
	assert.Equal(t, "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", mcp.Servers[2].TLSFingerprint)

	// Verify server-level policy
	assert.Equal(t, "allowlist", mcp.ServerPolicy)
	assert.Equal(t, 2, len(mcp.AllowedServers))
	assert.Equal(t, "filesystem", mcp.AllowedServers[0].ID)
	assert.Equal(t, "weather-api", mcp.AllowedServers[1].ID)
	assert.Equal(t, 1, len(mcp.DeniedServers))
	assert.Equal(t, "*", mcp.DeniedServers[0].ID)

	// Verify existing tool-level policy still works
	assert.Equal(t, "denylist", mcp.ToolPolicy)
	assert.Equal(t, 1, len(mcp.AllowedTools))
	assert.Equal(t, "*", mcp.AllowedTools[0].Server)
	assert.Equal(t, 1, len(mcp.DeniedTools))
	assert.Equal(t, "weather-api", mcp.DeniedTools[0].Server)
	assert.Equal(t, "delete_*", mcp.DeniedTools[0].Tool)

	// Verify existing version_pinning and rate_limits still work
	assert.True(t, mcp.VersionPinning.Enabled)
	assert.Equal(t, "block", mcp.VersionPinning.OnChange)
	assert.True(t, mcp.RateLimits.Enabled)
	assert.Equal(t, 60, mcp.RateLimits.DefaultRPM)
}

func TestLoad_MCPServerDeclarations_Defaults(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	// Config with no MCP server declarations - should have zero values
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	mcp := cfg.Sandbox.MCP
	assert.Empty(t, mcp.Servers)
	assert.Empty(t, mcp.ServerPolicy)
	assert.Empty(t, mcp.AllowedServers)
	assert.Empty(t, mcp.DeniedServers)
}

func TestMCPServerDeclaration_YAMLRoundTrip(t *testing.T) {
	original := SandboxMCPConfig{
		EnforcePolicy: true,
		FailClosed:    true,
		Servers: []MCPServerDeclaration{
			{
				ID:      "fs",
				Type:    "stdio",
				Command: "npx",
				Args:    []string{"@mcp/fs", "/data"},
			},
			{
				ID:             "api",
				Type:           "http",
				URL:            "https://mcp.example.com",
				TLSFingerprint: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
			},
		},
		ServerPolicy: "allowlist",
		AllowedServers: []MCPServerRule{
			{ID: "fs"},
			{ID: "api"},
		},
		DeniedServers: []MCPServerRule{
			{ID: "*"},
		},
		ToolPolicy: "denylist",
		AllowedTools: []MCPToolRule{
			{Server: "*", Tool: "*"},
		},
		DeniedTools: []MCPToolRule{
			{Server: "api", Tool: "delete_*"},
		},
		VersionPinning: MCPVersionPinningConfig{
			Enabled:        true,
			OnChange:       "block",
			AutoTrustFirst: true,
		},
		RateLimits: MCPRateLimitsConfig{
			Enabled:    true,
			DefaultRPM: 60,
		},
	}

	// Marshal to YAML
	data, err := yaml.Marshal(&original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Unmarshal back
	var roundTripped SandboxMCPConfig
	if err := yaml.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	// Verify all fields survived the round trip
	assert.Equal(t, original.EnforcePolicy, roundTripped.EnforcePolicy)
	assert.Equal(t, original.FailClosed, roundTripped.FailClosed)
	assert.Equal(t, original.ServerPolicy, roundTripped.ServerPolicy)
	assert.Equal(t, original.ToolPolicy, roundTripped.ToolPolicy)

	// Server declarations
	assert.Equal(t, len(original.Servers), len(roundTripped.Servers))
	assert.Equal(t, "fs", roundTripped.Servers[0].ID)
	assert.Equal(t, "stdio", roundTripped.Servers[0].Type)
	assert.Equal(t, "npx", roundTripped.Servers[0].Command)
	assert.Equal(t, []string{"@mcp/fs", "/data"}, roundTripped.Servers[0].Args)
	assert.Equal(t, "api", roundTripped.Servers[1].ID)
	assert.Equal(t, "http", roundTripped.Servers[1].Type)
	assert.Equal(t, "https://mcp.example.com", roundTripped.Servers[1].URL)
	assert.Equal(t, "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", roundTripped.Servers[1].TLSFingerprint)

	// Server rules
	assert.Equal(t, len(original.AllowedServers), len(roundTripped.AllowedServers))
	assert.Equal(t, "fs", roundTripped.AllowedServers[0].ID)
	assert.Equal(t, "api", roundTripped.AllowedServers[1].ID)
	assert.Equal(t, 1, len(roundTripped.DeniedServers))
	assert.Equal(t, "*", roundTripped.DeniedServers[0].ID)

	// Tool rules (existing fields)
	assert.Equal(t, len(original.AllowedTools), len(roundTripped.AllowedTools))
	assert.Equal(t, len(original.DeniedTools), len(roundTripped.DeniedTools))

	// Version pinning and rate limits
	assert.Equal(t, original.VersionPinning.Enabled, roundTripped.VersionPinning.Enabled)
	assert.Equal(t, original.RateLimits.DefaultRPM, roundTripped.RateLimits.DefaultRPM)
}

func TestMCPAllowedTransportsValidation(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		serverType string
		wantErr    bool
	}{
		{"stdio allowed by default", nil, "stdio", false},
		{"http allowed by default", nil, "http", false},
		{"stdio only rejects http", []string{"stdio"}, "http", true},
		{"stdio only allows stdio", []string{"stdio"}, "stdio", false},
		{"explicit all allows sse", []string{"stdio", "http", "sse"}, "sse", false},
		{"invalid transport value", []string{"stdio", "grpc"}, "stdio", true},
		{"typo in transport", []string{"stdoi"}, "stdio", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := SandboxMCPConfig{
				AllowedTransports: tt.allowed,
				Servers: []MCPServerDeclaration{
					{ID: "test", Type: tt.serverType},
				},
			}
			err := ValidateMCPTransports(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateMCPTransports() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRateLimitsValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "enabled with no limits rejects",
			yaml: `
proxy:
  rate_limits:
    enabled: true
`,
			wantErr: "neither requests_per_minute nor tokens_per_minute is set",
		},
		{
			name: "negative rpm rejects",
			yaml: `
proxy:
  rate_limits:
    enabled: true
    requests_per_minute: -5
`,
			wantErr: "requests_per_minute must be >= 0",
		},
		{
			name: "negative tpm rejects",
			yaml: `
proxy:
  rate_limits:
    enabled: true
    tokens_per_minute: -100
`,
			wantErr: "tokens_per_minute must be >= 0",
		},
		{
			name: "valid rpm only accepts",
			yaml: `
proxy:
  rate_limits:
    enabled: true
    requests_per_minute: 60
`,
			wantErr: "",
		},
		{
			name: "disabled with zero limits accepts",
			yaml: `
proxy:
  rate_limits:
    enabled: false
`,
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(path, []byte(tt.yaml), 0644)

			_, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Load() unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Load() error = %v, want containing %q", err, tt.wantErr)
				}
			}
		})
	}
}

func TestSamplingAndOutputInspectionEnumValidation(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "valid sampling policy",
			yaml: `
sandbox:
  mcp:
    sampling:
      policy: block
`,
			wantErr: "",
		},
		{
			name: "invalid sampling policy",
			yaml: `
sandbox:
  mcp:
    sampling:
      policy: deny
`,
			wantErr: `invalid sandbox.mcp.sampling.policy "deny"`,
		},
		{
			name: "valid per_server override",
			yaml: `
sandbox:
  mcp:
    sampling:
      policy: block
      per_server:
        trusted-srv: allow
`,
			wantErr: "",
		},
		{
			name: "invalid per_server override",
			yaml: `
sandbox:
  mcp:
    sampling:
      per_server:
        bad-srv: reject
`,
			wantErr: `invalid sandbox.mcp.sampling.per_server["bad-srv"] "reject"`,
		},
		{
			name: "valid output_inspection on_detection",
			yaml: `
sandbox:
  mcp:
    output_inspection:
      enabled: true
      on_detection: alert
`,
			wantErr: "",
		},
		{
			name: "invalid output_inspection on_detection",
			yaml: `
sandbox:
  mcp:
    output_inspection:
      enabled: true
      on_detection: warn
`,
			wantErr: `invalid sandbox.mcp.output_inspection.on_detection "warn"`,
		},
		{
			name: "empty values accepted",
			yaml: `
sandbox:
  mcp:
    sampling:
      policy: ""
    output_inspection:
      on_detection: ""
`,
			wantErr: "",
		},
		{
			name: "valid version_pinning on_change",
			yaml: `
sandbox:
  mcp:
    version_pinning:
      on_change: block
`,
			wantErr: "",
		},
		{
			name: "invalid version_pinning on_change",
			yaml: `
sandbox:
  mcp:
    version_pinning:
      on_change: deny
`,
			wantErr: `invalid sandbox.mcp.version_pinning.on_change "deny"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			os.WriteFile(path, []byte(tt.yaml), 0644)

			_, err := Load(path)
			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Load() unexpected error: %v", err)
				}
			} else {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Load() error = %v, want containing %q", err, tt.wantErr)
				}
			}
		})
	}
}

func TestAuditStorageEnabledDefault(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Storage.Enabled == nil {
		t.Fatal("Audit.Storage.Enabled should not be nil after defaults")
	}
	if !*cfg.Audit.Storage.Enabled {
		t.Error("Audit.Storage.Enabled should default to true")
	}
}

func TestAuditStorageDisabled(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
audit:
  storage:
    enabled: false
`), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Audit.Storage.Enabled == nil {
		t.Fatal("Audit.Storage.Enabled should not be nil")
	}
	if *cfg.Audit.Storage.Enabled {
		t.Error("Audit.Storage.Enabled should be false when explicitly set")
	}
}

func TestAuditWatchtowerConfig_DefaultsExpand(t *testing.T) {
	// NOTE: the WTP sink is gated by validate() until plan Task 27 wires it
	// into the daemon. The gate only fires when enabled=true, so we set
	// enabled=false here. applyDefaults runs unconditionally during Load,
	// so all default expansion is still exercised.
	yaml := `
audit:
  watchtower:
    enabled: false
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/etc/agentsh/wtp.token"
    chain:
      key_file: "/etc/agentsh/wtp.key"
`
	cfg, err := loadFromString(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	wtp := cfg.Audit.Watchtower
	if wtp.Batch.MaxEvents != 256 {
		t.Errorf("MaxEvents = %d, want 256", wtp.Batch.MaxEvents)
	}
	if wtp.Batch.MaxBytes != 256*1024 {
		t.Errorf("MaxBytes = %d, want 256 KiB", wtp.Batch.MaxBytes)
	}
	if wtp.WAL.SegmentSize != 16*1024*1024 {
		t.Errorf("SegmentSize = %d, want 16 MiB", wtp.WAL.SegmentSize)
	}
	if wtp.Heartbeat.Interval != 30*time.Second {
		t.Errorf("Heartbeat.Interval = %v, want 30s", wtp.Heartbeat.Interval)
	}
	if wtp.Backoff.Base != 500*time.Millisecond {
		t.Errorf("Backoff.Base = %v, want 500ms", wtp.Backoff.Base)
	}
	if wtp.StateDir == "" {
		t.Error("StateDir default should be non-empty")
	}
}

func TestAuditWatchtowerConfig_EmitExtendedLossReasons_DefaultsFalse(t *testing.T) {
	yamlIn := `
audit:
  watchtower:
    enabled: false
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/etc/agentsh/wtp.token"
    chain:
      key_file: "/etc/agentsh/wtp.key"
`
	cfg, err := loadFromString(t, yamlIn)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Audit.Watchtower.EmitExtendedLossReasons {
		t.Fatalf("EmitExtendedLossReasons default should be false; got true")
	}
}

func TestAuditWatchtowerConfig_EmitExtendedLossReasons_ExplicitTrue(t *testing.T) {
	yamlIn := `
audit:
  watchtower:
    enabled: false
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/etc/agentsh/wtp.token"
    chain:
      key_file: "/etc/agentsh/wtp.key"
    emit_extended_loss_reasons: true
`
	cfg, err := loadFromString(t, yamlIn)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Audit.Watchtower.EmitExtendedLossReasons {
		t.Fatalf("EmitExtendedLossReasons should be true after explicit set")
	}
}

func TestAuditWatchtowerConfig_EphemeralOverridesDefaults(t *testing.T) {
	// See note in TestAuditWatchtowerConfig_DefaultsExpand: enabled=false
	// avoids the WTP-not-wired gate while still exercising applyDefaults.
	yaml := `
audit:
  watchtower:
    enabled: false
    ephemeral_mode: true
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/etc/agentsh/wtp.token"
    chain:
      key_file: "/etc/agentsh/wtp.key"
`
	cfg, err := loadFromString(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	wtp := cfg.Audit.Watchtower
	if wtp.Batch.MaxEvents != 64 {
		t.Errorf("ephemeral MaxEvents = %d, want 64", wtp.Batch.MaxEvents)
	}
	if wtp.Heartbeat.Interval != 10*time.Second {
		t.Errorf("ephemeral Heartbeat.Interval = %v, want 10s", wtp.Heartbeat.Interval)
	}
	if wtp.Batch.FlushInterval != 200*time.Millisecond {
		t.Errorf("ephemeral FlushInterval = %v, want 200ms", wtp.Batch.FlushInterval)
	}
}

func TestAuditWatchtowerConfig_AuthMutualExclusion(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantErr string
	}{
		{
			name: "token_file_and_token_env",
			yaml: `
audit:
  watchtower:
    enabled: true
    endpoint: "x:1"
    chain: {key_file: "/k"}
    auth: {token_file: "/t", token_env: "T"}`,
			wantErr: "exactly one of",
		},
		{
			name: "no_auth_source",
			yaml: `
audit:
  watchtower:
    enabled: true
    endpoint: "x:1"
    chain: {key_file: "/k"}`,
			wantErr: "exactly one of",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadFromString(t, tc.yaml)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want contains %q", err, tc.wantErr)
			}
		})
	}
}

// writeTempFile creates a temporary file in t.TempDir() and returns its path
// in forward-slash form safe for embedding in double-quoted YAML strings.
// Go's os package accepts forward slashes on every OS, so the filesystem
// operations still locate the file, but the YAML parser no longer sees
// backslash-escape sequences like "\U" (from "C:\Users\...") that trip
// up the Windows runner with "did not find expected hexdecimal number".
// Used by WTP tests to materialise TLS cert/key/chain key files referenced
// from YAML fixtures.
func writeTempFile(t *testing.T, name string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("placeholder"), 0o600); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
	return filepath.ToSlash(p)
}

// validWatchtowerYAML returns a YAML fragment with all required WTP fields
// populated using files that actually exist on disk. The state_dir points at
// a writable temp directory. Callers may override individual fields with
// extra YAML appended after the returned base via the overrides parameter.
//
// All embedded paths are converted to forward-slash form so the resulting
// YAML parses cleanly on Windows (see writeTempFile docstring).
func validWatchtowerYAML(t *testing.T, enabled bool, overrides string) string {
	t.Helper()
	chainKey := writeTempFile(t, "wtp.key")
	stateDir := filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state"))
	return "audit:\n  watchtower:\n    enabled: " +
		map[bool]string{true: "true", false: "false"}[enabled] + "\n" +
		"    endpoint: \"wtp.example.com:9443\"\n" +
		"    state_dir: \"" + stateDir + "\"\n" +
		"    auth:\n" +
		"      token_file: \"/t\"\n" +
		"    chain:\n" +
		"      key_file: \"" + chainKey + "\"\n" +
		overrides
}

func TestAuditWatchtowerConfig_StateDirDefault(t *testing.T) {
	// With state_dir omitted entirely, applyDefaults must compute a default
	// path. We use enabled:false so the writability check in validate()
	// doesn't fire (default may live under a path the test process can't
	// create on every OS).
	yaml := `
audit:
  watchtower:
    enabled: false
    endpoint: "wtp.example.com:9443"
    auth:
      token_file: "/t"
    chain:
      key_file: "/k"
`
	cfg, err := loadFromString(t, yaml)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Audit.Watchtower.StateDir == "" {
		t.Fatal("StateDir default should be non-empty when YAML omits it")
	}
	if !filepath.IsAbs(cfg.Audit.Watchtower.StateDir) {
		t.Errorf("StateDir default %q should be absolute", cfg.Audit.Watchtower.StateDir)
	}
}

func TestAuditWatchtowerConfig_StateDirNotWritable(t *testing.T) {
	// Place state_dir under a parent directory whose mode forbids creation.
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod %s: %v", parent, err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })
	// On platforms where the test runs as a user that can still write under
	// 0o500 dirs (e.g., root), skip — the negative case can't be exercised.
	probe, err := os.CreateTemp(parent, "writable-probe-*")
	if err == nil {
		_ = probe.Close()
		_ = os.Remove(probe.Name())
		t.Skip("running as a user that bypasses 0o500 perms; cannot exercise negative writability")
	}

	chainKey := writeTempFile(t, "wtp.key")
	stateDir := filepath.ToSlash(filepath.Join(parent, "wtp-state"))
	yaml := "audit:\n  watchtower:\n    enabled: true\n" +
		"    endpoint: \"wtp.example.com:9443\"\n" +
		"    state_dir: \"" + stateDir + "\"\n" +
		"    auth:\n      token_file: \"/t\"\n" +
		"    chain:\n      key_file: \"" + chainKey + "\"\n"

	_, err = loadFromString(t, yaml)
	if err == nil {
		t.Fatal("expected error for non-writable state_dir, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "state_dir") || !strings.Contains(msg, "writable") {
		t.Errorf("err = %v, want mention of state_dir and writable", err)
	}
}

func TestAuditWatchtowerConfig_TLSFileMissing(t *testing.T) {
	missing := filepath.ToSlash(filepath.Join(t.TempDir(), "does-not-exist.pem"))
	yaml := validWatchtowerYAML(t, true, "    tls:\n      ca_cert_file: \""+missing+"\"\n")
	_, err := loadFromString(t, yaml)
	if err == nil {
		t.Fatal("expected error for missing TLS file, got nil")
	}
	if !strings.Contains(err.Error(), "ca_cert_file") {
		t.Errorf("err = %v, want mention of ca_cert_file", err)
	}
}

func TestAuditWatchtowerConfig_ClientCertAuthRequiresCertAndKey(t *testing.T) {
	// client_cert_auth: true with no cert/key under tls.* must fail.
	chainKey := writeTempFile(t, "wtp.key")
	stateDir := filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state"))
	yaml := "audit:\n  watchtower:\n    enabled: true\n" +
		"    endpoint: \"wtp.example.com:9443\"\n" +
		"    state_dir: \"" + stateDir + "\"\n" +
		"    auth:\n      client_cert_auth: true\n" +
		"    chain:\n      key_file: \"" + chainKey + "\"\n"
	_, err := loadFromString(t, yaml)
	if err == nil {
		t.Fatal("expected error for client_cert_auth without cert/key, got nil")
	}
	if !strings.Contains(err.Error(), "client_cert_auth") {
		t.Errorf("err = %v, want mention of client_cert_auth", err)
	}
}

func TestAuditWatchtowerConfig_PartialTLSClientAuthRejected(t *testing.T) {
	// tls.client_cert_file set without tls.client_key_file (and vice versa)
	// must fail even when client_cert_auth is false.
	cert := writeTempFile(t, "client.crt")
	yaml := validWatchtowerYAML(t, true, "    tls:\n      client_cert_file: \""+cert+"\"\n")
	_, err := loadFromString(t, yaml)
	if err == nil {
		t.Fatal("expected error for partial TLS client-auth pair, got nil")
	}
	if !strings.Contains(err.Error(), "client_cert_file") && !strings.Contains(err.Error(), "client_key_file") {
		t.Errorf("err = %v, want mention of client_cert_file/client_key_file", err)
	}

	// reverse: only client_key_file set
	key := writeTempFile(t, "client.key")
	yaml2 := validWatchtowerYAML(t, true, "    tls:\n      client_key_file: \""+key+"\"\n")
	_, err = loadFromString(t, yaml2)
	if err == nil {
		t.Fatal("expected error for partial TLS client-auth pair (key only), got nil")
	}
	if !strings.Contains(err.Error(), "client_cert_file") && !strings.Contains(err.Error(), "client_key_file") {
		t.Errorf("err = %v, want mention of client_cert_file/client_key_file", err)
	}
}

func TestAuditWatchtowerConfig_FilterMinRiskLevelEnum(t *testing.T) {
	// Invalid value must fail. With enabled:false, validate() short-circuits
	// before reaching the filter check, so we set enabled:true and supply
	// the rest of a valid config via validWatchtowerYAML.
	t.Run("invalid", func(t *testing.T) {
		yaml := validWatchtowerYAML(t, true, "    filter:\n      min_risk_level: \"super-bad\"\n")
		_, err := loadFromString(t, yaml)
		if err == nil {
			t.Fatal("expected error for invalid min_risk_level, got nil")
		}
		if !strings.Contains(err.Error(), "min_risk_level") {
			t.Errorf("err = %v, want mention of min_risk_level", err)
		}
	})
	for _, v := range []string{"low", "medium", "high", "critical"} {
		v := v
		t.Run("valid_"+v, func(t *testing.T) {
			yaml := validWatchtowerYAML(t, true, "    filter:\n      min_risk_level: \""+v+"\"\n")
			_, err := loadFromString(t, yaml)
			// Task 27: the WTP-not-wired gate has been removed; valid configs
			// must now load cleanly. Verify the filter value is accepted and
			// that no schema error mentions min_risk_level.
			if err != nil {
				t.Fatalf("valid min_risk_level %q should load cleanly after Task 27, got: %v", v, err)
			}
		})
	}
}

func TestAuditWatchtowerConfig_KMSSourcesMutualExclusion(t *testing.T) {
	stateDir := filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state"))
	chainKey := writeTempFile(t, "wtp.key")

	t.Run("none", func(t *testing.T) {
		yaml := "audit:\n  watchtower:\n    enabled: true\n" +
			"    endpoint: \"wtp.example.com:9443\"\n" +
			"    state_dir: \"" + stateDir + "\"\n" +
			"    auth:\n      token_file: \"/t\"\n" +
			"    chain: {}\n"
		_, err := loadFromString(t, yaml)
		if err == nil {
			t.Fatal("expected error when no chain key source is set, got nil")
		}
		if !strings.Contains(err.Error(), "chain") {
			t.Errorf("err = %v, want mention of chain", err)
		}
	})

	t.Run("multiple_file_and_env", func(t *testing.T) {
		yaml := "audit:\n  watchtower:\n    enabled: true\n" +
			"    endpoint: \"wtp.example.com:9443\"\n" +
			"    state_dir: \"" + stateDir + "\"\n" +
			"    auth:\n      token_file: \"/t\"\n" +
			"    chain:\n      key_file: \"" + chainKey + "\"\n      key_env: \"WTP_KEY\"\n"
		_, err := loadFromString(t, yaml)
		if err == nil {
			t.Fatal("expected error for multiple chain key sources, got nil")
		}
		if !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("err = %v, want mention of 'exactly one'", err)
		}
	})

	t.Run("multiple_aws_and_gcp", func(t *testing.T) {
		yaml := "audit:\n  watchtower:\n    enabled: true\n" +
			"    endpoint: \"wtp.example.com:9443\"\n" +
			"    state_dir: \"" + stateDir + "\"\n" +
			"    auth:\n      token_file: \"/t\"\n" +
			"    chain:\n      aws_kms:\n        key_id: \"alias/aws-key\"\n" +
			"      gcp_kms:\n        key_name: \"projects/p/locations/l/keyRings/r/cryptoKeys/k\"\n"
		_, err := loadFromString(t, yaml)
		if err == nil {
			t.Fatal("expected error for AWS+GCP chain key sources, got nil")
		}
		if !strings.Contains(err.Error(), "exactly one") {
			t.Errorf("err = %v, want mention of 'exactly one'", err)
		}
	})

	// One of each KMS source individually must pass schema validation.
	// Task 27: the WTP-not-wired gate has been removed; single-source
	// configs must now load cleanly.
	for _, c := range []struct {
		name  string
		chain string
	}{
		{"file", "      key_file: \"" + chainKey + "\"\n"},
		{"env", "      key_env: \"WTP_KEY\"\n"},
		{"aws_kms", "      aws_kms:\n        key_id: \"alias/aws-key\"\n"},
		{"azure_keyvault", "      azure_keyvault:\n        vault_url: \"https://v.vault.azure.net\"\n        key_name: \"k\"\n"},
		{"hashicorp_vault", "      hashicorp_vault:\n        address: \"https://vault.example.com\"\n        secret_path: \"secret/data/agentsh/wtp\"\n"},
		{"gcp_kms", "      gcp_kms:\n        key_name: \"projects/p/locations/l/keyRings/r/cryptoKeys/k\"\n"},
	} {
		c := c
		t.Run("only_"+c.name, func(t *testing.T) {
			yaml := "audit:\n  watchtower:\n    enabled: true\n" +
				"    endpoint: \"wtp.example.com:9443\"\n" +
				"    state_dir: \"" + filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state")) + "\"\n" +
				"    auth:\n      token_file: \"/t\"\n" +
				"    chain:\n" + c.chain
			_, err := loadFromString(t, yaml)
			if err != nil {
				t.Fatalf("single-source %q should load cleanly after Task 27, got: %v", c.name, err)
			}
		})
	}
}

func TestAuditWatchtowerConfig_EnabledWiredInTask27(t *testing.T) {
	// Task 27 removed the "not yet wired" gate. A fully-valid config with
	// enabled:true must now load cleanly (the gate was a temporary measure
	// to prevent operators from enabling WTP before the daemon wiring landed).
	yaml := validWatchtowerYAML(t, true, "")
	if _, err := loadFromString(t, yaml); err != nil {
		t.Fatalf("valid enabled WTP config should load cleanly after Task 27, got: %v", err)
	}

	// With enabled:false the same config must also load cleanly.
	yamlOff := validWatchtowerYAML(t, false, "")
	if _, err := loadFromString(t, yamlOff); err != nil {
		t.Fatalf("load with enabled:false: %v", err)
	}
}

func TestAuditWatchtowerConfig_KeySourceSelectorMismatch(t *testing.T) {
	// chain.key_source = "env" with aws_kms.key_id populated must fail —
	// otherwise the daemon (Task 27) would honor key_source and build a
	// provider that ignores the populated block, silently sending events
	// elsewhere.
	stateDir := filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state"))
	yaml := "audit:\n  watchtower:\n    enabled: true\n" +
		"    endpoint: \"wtp.example.com:9443\"\n" +
		"    state_dir: \"" + stateDir + "\"\n" +
		"    auth:\n      token_file: \"/t\"\n" +
		"    chain:\n      key_source: \"env\"\n      aws_kms:\n        key_id: \"alias/k\"\n"
	_, err := loadFromString(t, yaml)
	if err == nil {
		t.Fatal("expected error for key_source/source-block mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "key_source") {
		t.Errorf("err = %v, want mention of key_source", err)
	}

	// Matching key_source must pass schema validation cleanly (Task 27:
	// the WTP-not-wired gate has been removed).
	yamlMatch := "audit:\n  watchtower:\n    enabled: true\n" +
		"    endpoint: \"wtp.example.com:9443\"\n" +
		"    state_dir: \"" + filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state")) + "\"\n" +
		"    auth:\n      token_file: \"/t\"\n" +
		"    chain:\n      key_source: \"aws_kms\"\n      aws_kms:\n        key_id: \"alias/k\"\n"
	if _, err = loadFromString(t, yamlMatch); err != nil {
		t.Fatalf("matching key_source should load cleanly after Task 27, got: %v", err)
	}
}

func TestAuditWatchtowerConfig_ProviderRequiredFields(t *testing.T) {
	// For each KMS provider that has more than one required field, verify
	// that a partial config (selector populated, mandatory peer field
	// missing) is rejected at load time. Mirrors the per-provider
	// constructors in internal/audit/kms/{azure,vault}.go.
	cases := []struct {
		name    string
		chain   string
		wantErr string
	}{
		{
			name:    "azure_keyvault_missing_key_name",
			chain:   "      azure_keyvault:\n        vault_url: \"https://v.vault.azure.net\"\n",
			wantErr: "azure_keyvault.key_name",
		},
		{
			name:    "hashicorp_vault_missing_secret_path",
			chain:   "      hashicorp_vault:\n        address: \"https://vault.example.com\"\n",
			wantErr: "hashicorp_vault.secret_path",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			yaml := "audit:\n  watchtower:\n    enabled: true\n" +
				"    endpoint: \"wtp.example.com:9443\"\n" +
				"    state_dir: \"" + filepath.ToSlash(filepath.Join(t.TempDir(), "wtp-state")) + "\"\n" +
				"    auth:\n      token_file: \"/t\"\n" +
				"    chain:\n" + tc.chain
			_, err := loadFromString(t, yaml)
			if err == nil {
				t.Fatalf("expected error mentioning %q, got nil", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("err = %v, want mention of %q", err, tc.wantErr)
			}
		})
	}
}

func TestAuditWatchtowerConfig_TLSFileUnreadable(t *testing.T) {
	// Permission-denied is a stronger contract than mere existence —
	// validate() now opens the file. Skip on platforms (or test runs as a
	// user) where chmod 0o000 cannot be enforced.
	cert := writeTempFile(t, "ca.pem")
	if err := os.Chmod(cert, 0o000); err != nil {
		t.Skipf("chmod 0o000 not supported here: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(cert, 0o600) })

	probe, err := os.Open(cert)
	if err == nil {
		_ = probe.Close()
		t.Skip("running as a user that bypasses 0o000 perms; cannot exercise unreadable case")
	}

	yaml := validWatchtowerYAML(t, true, "    tls:\n      ca_cert_file: \""+cert+"\"\n")
	_, err = loadFromString(t, yaml)
	if err == nil {
		t.Fatal("expected error for unreadable TLS file, got nil")
	}
	if !strings.Contains(err.Error(), "ca_cert_file") {
		t.Errorf("err = %v, want mention of ca_cert_file", err)
	}
}

func TestAuditWatchtowerConfig_StateDirCreatedOnValidLoad(t *testing.T) {
	// Task 27: the WTP-not-wired gate has been removed. A valid config with
	// a fresh state_dir path must load cleanly AND the state_dir must be
	// created (or already exist) after successful validation.
	stateRoot := t.TempDir()
	stateDir := filepath.ToSlash(filepath.Join(stateRoot, "fresh-wtp-state"))
	chainKey := writeTempFile(t, "wtp.key")

	yaml := "audit:\n  watchtower:\n    enabled: true\n" +
		"    endpoint: \"wtp.example.com:9443\"\n" +
		"    state_dir: \"" + stateDir + "\"\n" +
		"    auth:\n      token_file: \"/t\"\n" +
		"    chain:\n      key_file: \"" + chainKey + "\"\n"
	_, err := loadFromString(t, yaml)
	if err != nil {
		t.Fatalf("valid WTP config should load cleanly after Task 27, got: %v", err)
	}
	// The state_dir writability probe in validate() creates the directory.
	if _, err := os.Stat(stateDir); err != nil {
		t.Errorf("state_dir %q should exist after successful validation: %v", stateDir, err)
	}
}

// TestAuditWatchtowerConfig_WALSyncModeDeferredRejected pins the
// config/runtime parity that round 2 surfaced. WAL.Open rejects
// SyncDeferred until the periodic-sync timer hook is implemented; config
// validation must reject the same value at the same gate so a config that
// turns the mode on fails fast at load time, not at WAL open.
//
// "immediate" is exercised implicitly by every other passing test (the
// helper omits sync_mode and applyDefaults sets it to "immediate"), so
// we only assert the rejection branches here.
func TestAuditWatchtowerConfig_WALSyncModeDeferredRejected(t *testing.T) {
	t.Run("deferred", func(t *testing.T) {
		yaml := validWatchtowerYAML(t, true, "    wal:\n      sync_mode: \"deferred\"\n")
		_, err := loadFromString(t, yaml)
		if err == nil {
			t.Fatal("expected error for sync_mode=deferred, got nil")
		}
		msg := err.Error()
		if !strings.Contains(msg, "sync_mode") || !strings.Contains(msg, "deferred") {
			t.Errorf("err = %v, want mention of sync_mode and deferred", err)
		}
	})
	t.Run("unknown", func(t *testing.T) {
		yaml := validWatchtowerYAML(t, true, "    wal:\n      sync_mode: \"never\"\n")
		_, err := loadFromString(t, yaml)
		if err == nil {
			t.Fatal("expected error for sync_mode=never, got nil")
		}
		if !strings.Contains(err.Error(), "sync_mode") {
			t.Errorf("err = %v, want mention of sync_mode", err)
		}
	})
}
