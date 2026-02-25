package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v3"
)

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
