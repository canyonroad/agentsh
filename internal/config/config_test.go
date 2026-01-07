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
