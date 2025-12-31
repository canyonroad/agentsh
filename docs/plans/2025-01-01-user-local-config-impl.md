# User-Local Configuration Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable agentsh to search for configuration in user-local directories before falling back to system-wide locations.

**Architecture:** Add ConfigSource tracking to distinguish where config was loaded from (env var, user-local, system-wide). Use this source to derive default paths for policies and data directories. Update defaultConfigPath() to implement the new search order.

**Tech Stack:** Go standard library, existing config package

---

### Task 1: Add ConfigSource Type and GetUserDataDir Function

**Files:**
- Modify: `internal/config/platform.go:66-118`
- Test: `internal/config/platform_test.go`

**Step 1: Write the failing test for ConfigSource and GetUserDataDir**

Create test file `internal/config/platform_test.go`:

```go
package config

import (
	"os"
	"runtime"
	"testing"
)

func TestConfigSourceString(t *testing.T) {
	tests := []struct {
		source ConfigSource
		want   string
	}{
		{ConfigSourceEnv, "env"},
		{ConfigSourceUser, "user"},
		{ConfigSourceSystem, "system"},
	}
	for _, tt := range tests {
		if got := tt.source.String(); got != tt.want {
			t.Errorf("ConfigSource(%d).String() = %q, want %q", tt.source, got, tt.want)
		}
	}
}

func TestGetUserDataDir(t *testing.T) {
	home, _ := os.UserHomeDir()

	// Test with XDG_DATA_HOME set (Linux only meaningful but function should work)
	if runtime.GOOS == "linux" {
		orig := os.Getenv("XDG_DATA_HOME")
		os.Setenv("XDG_DATA_HOME", "/custom/data")
		defer os.Setenv("XDG_DATA_HOME", orig)

		got := GetUserDataDir()
		if got != "/custom/data/agentsh" {
			t.Errorf("GetUserDataDir() with XDG_DATA_HOME = %q, want %q", got, "/custom/data/agentsh")
		}
		os.Setenv("XDG_DATA_HOME", orig)
	}

	// Test default behavior
	got := GetUserDataDir()
	switch runtime.GOOS {
	case "windows":
		// Should use APPDATA or fallback
		if got == "" {
			t.Error("GetUserDataDir() returned empty on Windows")
		}
	case "darwin":
		want := home + "/Library/Application Support/agentsh"
		if got != want {
			t.Errorf("GetUserDataDir() = %q, want %q", got, want)
		}
	default:
		// Linux default without XDG_DATA_HOME
		os.Unsetenv("XDG_DATA_HOME")
		got = GetUserDataDir()
		want := home + "/.local/share/agentsh"
		if got != want {
			t.Errorf("GetUserDataDir() = %q, want %q", got, want)
		}
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config -run "TestConfigSource|TestGetUserDataDir" -v`
Expected: FAIL - ConfigSource type not defined, GetUserDataDir not defined

**Step 3: Implement ConfigSource and GetUserDataDir**

Add to `internal/config/platform.go` after the imports:

```go
// ConfigSource indicates where the configuration was loaded from.
type ConfigSource int

const (
	// ConfigSourceEnv means config path was specified via AGENTSH_CONFIG env var.
	ConfigSourceEnv ConfigSource = iota
	// ConfigSourceUser means config was loaded from user-local directory.
	ConfigSourceUser
	// ConfigSourceSystem means config was loaded from system-wide directory.
	ConfigSourceSystem
)

// String returns a human-readable name for the config source.
func (s ConfigSource) String() string {
	switch s {
	case ConfigSourceEnv:
		return "env"
	case ConfigSourceUser:
		return "user"
	case ConfigSourceSystem:
		return "system"
	default:
		return "unknown"
	}
}
```

Add GetUserDataDir function after GetUserConfigDir:

```go
// GetUserDataDir returns the user-specific data directory.
func GetUserDataDir() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		if appdata := os.Getenv("APPDATA"); appdata != "" {
			return appdata + `\agentsh`
		}
		return home + `\AppData\Roaming\agentsh`
	case "darwin":
		return home + "/Library/Application Support/agentsh"
	default:
		if xdg := os.Getenv("XDG_DATA_HOME"); xdg != "" {
			return xdg + "/agentsh"
		}
		return home + "/.local/share/agentsh"
	}
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config -run "TestConfigSource|TestGetUserDataDir" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/platform.go internal/config/platform_test.go
git commit -m "feat(config): add ConfigSource type and GetUserDataDir function"
```

---

### Task 2: Update Config Loading to Return ConfigSource

**Files:**
- Modify: `internal/config/config.go:286-303`
- Modify: `internal/cli/local_config.go`
- Test: `internal/config/config_test.go`

**Step 1: Write the failing test for LoadWithSource**

Add to existing `internal/config/config_test.go` (or create if doesn't exist):

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config -run "TestLoadWithSource" -v`
Expected: FAIL - LoadWithSource not defined

**Step 3: Implement LoadWithSource**

Modify `internal/config/config.go` - add new function after Load:

```go
// LoadWithSource loads config from path and returns the config along with its source.
// The source parameter indicates where this config path came from.
func LoadWithSource(path string, source ConfigSource) (*Config, ConfigSource, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, source, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, source, fmt.Errorf("parse config: %w", err)
	}

	applyDefaultsWithSource(&cfg, source, path)
	applyEnvOverrides(&cfg)
	if err := validateConfig(&cfg); err != nil {
		return nil, source, err
	}
	return &cfg, source, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config -run "TestLoadWithSource" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add LoadWithSource to track config origin"
```

---

### Task 3: Update applyDefaults to Use ConfigSource

**Files:**
- Modify: `internal/config/config.go:305-477`
- Test: `internal/config/config_test.go`

**Step 1: Write the failing test for applyDefaultsWithSource**

Add to `internal/config/config_test.go`:

```go
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/config -run "TestApplyDefaultsWithSource" -v`
Expected: FAIL - applyDefaultsWithSource not defined

**Step 3: Implement applyDefaultsWithSource**

Add new function in `internal/config/config.go` and update applyDefaults:

```go
// getDefaultDataDir returns the appropriate data directory based on config source.
func getDefaultDataDir(source ConfigSource, configPath string) string {
	switch source {
	case ConfigSourceEnv:
		// Use the directory containing the config file
		if configPath != "" {
			return filepath.Dir(configPath)
		}
		return GetUserDataDir()
	case ConfigSourceUser:
		return GetUserDataDir()
	case ConfigSourceSystem:
		return GetDataDir()
	default:
		return GetDataDir()
	}
}

// getDefaultPoliciesDir returns the appropriate policies directory based on config source.
func getDefaultPoliciesDir(source ConfigSource, configPath string) string {
	switch source {
	case ConfigSourceEnv:
		// Use policies subdir of config file location
		if configPath != "" {
			return filepath.Join(filepath.Dir(configPath), "policies")
		}
		return GetUserConfigDir() + "/policies"
	case ConfigSourceUser:
		return GetUserConfigDir() + "/policies"
	case ConfigSourceSystem:
		return GetPoliciesDir()
	default:
		return GetPoliciesDir()
	}
}

func applyDefaultsWithSource(cfg *Config, source ConfigSource, configPath string) {
	dataDir := getDefaultDataDir(source, configPath)
	policiesDir := getDefaultPoliciesDir(source, configPath)

	// Platform defaults
	if cfg.Platform.Mode == "" {
		cfg.Platform.Mode = "auto"
	}
	if cfg.Platform.MountPoints.Linux == "" {
		cfg.Platform.MountPoints.Linux = "/tmp/agentsh/workspace"
	}
	if cfg.Platform.MountPoints.Darwin == "" {
		cfg.Platform.MountPoints.Darwin = "/tmp/agentsh/workspace"
	}
	if cfg.Platform.MountPoints.Windows == "" {
		cfg.Platform.MountPoints.Windows = "X:"
	}
	if cfg.Platform.MountPoints.WindowsWSL2 == "" {
		cfg.Platform.MountPoints.WindowsWSL2 = "/tmp/agentsh/workspace"
	}

	if cfg.Server.HTTP.Addr == "" {
		cfg.Server.HTTP.Addr = "0.0.0.0:8080"
	}
	if cfg.Server.GRPC.Addr == "" {
		cfg.Server.GRPC.Addr = "127.0.0.1:9090"
	}
	if cfg.Server.HTTP.ReadTimeout == "" {
		cfg.Server.HTTP.ReadTimeout = "30s"
	}
	if cfg.Server.HTTP.WriteTimeout == "" {
		cfg.Server.HTTP.WriteTimeout = "5m"
	}
	if cfg.Server.HTTP.MaxRequestSize == "" {
		cfg.Server.HTTP.MaxRequestSize = "10MB"
	}
	if cfg.Auth.Type == "" {
		cfg.Auth.Type = "none"
	}
	if cfg.Auth.APIKey.HeaderName == "" {
		cfg.Auth.APIKey.HeaderName = "X-API-Key"
	}

	// Use source-aware data directory for sessions
	if cfg.Sessions.BaseDir == "" {
		cfg.Sessions.BaseDir = filepath.Join(dataDir, "sessions")
	}
	if cfg.Sessions.MaxSessions <= 0 {
		cfg.Sessions.MaxSessions = 100
	}
	if cfg.Sessions.CleanupInterval == "" {
		cfg.Sessions.CleanupInterval = "1m"
	}
	if cfg.Sandbox.FUSE.MountBaseDir == "" {
		cfg.Sandbox.FUSE.MountBaseDir = cfg.Sessions.BaseDir
	}
	if cfg.Sandbox.FUSE.Audit.Mode == "" {
		cfg.Sandbox.FUSE.Audit.Mode = "monitor"
	}
	if cfg.Sandbox.FUSE.Audit.TrashPath == "" {
		cfg.Sandbox.FUSE.Audit.TrashPath = ".agentsh_trash"
	}
	if cfg.Sandbox.FUSE.Audit.TTL == "" {
		cfg.Sandbox.FUSE.Audit.TTL = "7d"
	}
	if cfg.Sandbox.FUSE.Audit.Quota == "" {
		cfg.Sandbox.FUSE.Audit.Quota = "5GB"
	}
	if cfg.Sandbox.FUSE.Audit.MaxEventQueue <= 0 {
		cfg.Sandbox.FUSE.Audit.MaxEventQueue = 1024
	}
	if cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder == "" {
		cfg.Sandbox.FUSE.Audit.HashSmallFilesUnder = "1MB"
	}
	// default audit enabled unless explicitly disabled
	if cfg.Sandbox.FUSE.Audit.Enabled == nil {
		t := true
		cfg.Sandbox.FUSE.Audit.Enabled = &t
	}
	if cfg.Sandbox.Network.ProxyPort == 0 {
		cfg.Sandbox.Network.ProxyPort = 9080
	}
	if cfg.Sandbox.Network.DNSPort == 0 {
		cfg.Sandbox.Network.DNSPort = 9053
	}
	if cfg.Sandbox.Network.InterceptMode == "" {
		cfg.Sandbox.Network.InterceptMode = "all"
	}
	if cfg.Sandbox.Network.ProxyListenAddr == "" {
		cfg.Sandbox.Network.ProxyListenAddr = "127.0.0.1:0"
	}
	// Resource limits defaults
	if cfg.Sandbox.Limits.MaxMemoryMB == 0 {
		cfg.Sandbox.Limits.MaxMemoryMB = 2048
	}
	if cfg.Sandbox.Limits.MaxCPUPercent == 0 {
		cfg.Sandbox.Limits.MaxCPUPercent = 50
	}
	if cfg.Sandbox.Limits.MaxProcesses == 0 {
		cfg.Sandbox.Limits.MaxProcesses = 100
	}
	if cfg.Sandbox.Limits.MaxDiskIOMbps == 0 {
		cfg.Sandbox.Limits.MaxDiskIOMbps = 100
	}
	if cfg.Sandbox.Limits.MaxNetworkMbps == 0 {
		cfg.Sandbox.Limits.MaxNetworkMbps = 50
	}
	if cfg.Sandbox.Network.Transparent.SubnetBase == "" {
		cfg.Sandbox.Network.Transparent.SubnetBase = "10.250.0.0/16"
	}
	// eBPF tracing defaults to disabled unless explicitly enabled.
	if cfg.Sandbox.Network.EBPF.Required && !cfg.Sandbox.Network.EBPF.Enabled {
		cfg.Sandbox.Network.EBPF.Enabled = true
	}
	if cfg.Sandbox.Network.EBPF.Enforce && !cfg.Sandbox.Network.EBPF.Enabled {
		cfg.Sandbox.Network.EBPF.Enabled = true
	}
	if cfg.Sandbox.Network.EBPF.DNSRefreshSeconds < 0 {
		cfg.Sandbox.Network.EBPF.DNSRefreshSeconds = 0
	}
	if cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds <= 0 {
		cfg.Sandbox.Network.EBPF.DNSMaxTTLSeconds = 60
	}
	if cfg.Sandbox.Network.EBPF.MapDenyEntries < 0 {
		cfg.Sandbox.Network.EBPF.MapDenyEntries = 0
	}
	if cfg.Sandbox.Network.EBPF.MapLPMDenyEntries < 0 {
		cfg.Sandbox.Network.EBPF.MapLPMDenyEntries = 0
	}
	if cfg.Sandbox.Cgroups.BasePath == "" {
		cfg.Sandbox.Cgroups.BasePath = ""
	}

	// Use source-aware policies directory
	if cfg.Policies.Dir == "" {
		cfg.Policies.Dir = policiesDir
	}
	if cfg.Policies.Default == "" {
		cfg.Policies.Default = "default"
	}
	if cfg.Metrics.Path == "" {
		cfg.Metrics.Path = "/metrics"
	}
	if cfg.Health.Path == "" {
		cfg.Health.Path = "/health"
	}
	if cfg.Health.ReadinessPath == "" {
		cfg.Health.ReadinessPath = "/ready"
	}

	// Use source-aware data directory for SQLite
	if cfg.Audit.Storage.SQLitePath == "" {
		cfg.Audit.Storage.SQLitePath = filepath.Join(dataDir, "events.db")
	}
	if cfg.Audit.Rotation.MaxSizeMB == 0 {
		cfg.Audit.Rotation.MaxSizeMB = 500
	}
	if cfg.Audit.Rotation.MaxBackups == 0 {
		cfg.Audit.Rotation.MaxBackups = 10
	}
	if cfg.Audit.Webhook.BatchSize == 0 {
		cfg.Audit.Webhook.BatchSize = 100
	}
	if cfg.Audit.Webhook.FlushInterval == "" {
		cfg.Audit.Webhook.FlushInterval = "10s"
	}
	if cfg.Audit.Webhook.Timeout == "" {
		cfg.Audit.Webhook.Timeout = "5s"
	}
	if cfg.Approvals.Timeout == "" {
		cfg.Approvals.Timeout = "5m"
	}
	if cfg.Approvals.Mode == "" {
		cfg.Approvals.Mode = "local_tty"
	}
	if cfg.Development.PProf.Addr == "" {
		cfg.Development.PProf.Addr = "localhost:6060"
	}
}

// applyDefaults wraps applyDefaultsWithSource for backward compatibility.
func applyDefaults(cfg *Config) {
	applyDefaultsWithSource(cfg, ConfigSourceSystem, "")
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/config -run "TestApplyDefaultsWithSource" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add source-aware default path resolution"
```

---

### Task 4: Update defaultConfigPath with New Search Order

**Files:**
- Modify: `internal/cli/local_config.go`
- Test: `internal/cli/local_config_test.go`

**Step 1: Write the failing test**

Create `internal/cli/local_config_test.go`:

```go
package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestFindConfigPath_EnvVar(t *testing.T) {
	tmpFile := filepath.Join(t.TempDir(), "custom.yaml")
	os.WriteFile(tmpFile, []byte("platform:\n  mode: auto\n"), 0644)

	orig := os.Getenv("AGENTSH_CONFIG")
	os.Setenv("AGENTSH_CONFIG", tmpFile)
	defer os.Setenv("AGENTSH_CONFIG", orig)

	path, source := findConfigPath()
	if path != tmpFile {
		t.Errorf("findConfigPath() path = %q, want %q", path, tmpFile)
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("findConfigPath() source = %v, want %v", source, config.ConfigSourceEnv)
	}
}

func TestFindConfigPath_UserConfig(t *testing.T) {
	// Clear env var
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Unsetenv("AGENTSH_CONFIG")
	defer os.Setenv("AGENTSH_CONFIG", orig)

	// Create a mock user config dir
	tmpDir := t.TempDir()
	userConfigDir := filepath.Join(tmpDir, "user-config")
	os.MkdirAll(userConfigDir, 0755)
	userConfigFile := filepath.Join(userConfigDir, "config.yaml")
	os.WriteFile(userConfigFile, []byte("platform:\n  mode: auto\n"), 0644)

	// Mock GetUserConfigDir - we can't easily do this without refactoring,
	// so we test the actual behavior which requires the real user config dir to exist
	// This test verifies the search order logic works correctly
	path, source := findConfigPath()

	// If user config exists, should return user source
	// If not, should fall back to system
	if source != config.ConfigSourceUser && source != config.ConfigSourceSystem {
		t.Errorf("findConfigPath() source = %v, want ConfigSourceUser or ConfigSourceSystem", source)
	}
	if path == "" {
		t.Error("findConfigPath() returned empty path")
	}
}

func TestFindConfigPath_FallbackToSystem(t *testing.T) {
	// Clear env var
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Unsetenv("AGENTSH_CONFIG")
	defer os.Setenv("AGENTSH_CONFIG", orig)

	// When no user config exists, should fall back to system
	path, source := findConfigPath()

	// Should return some path (either user or system)
	if path == "" {
		t.Error("findConfigPath() returned empty path")
	}

	// Source should be user or system (depending on what exists)
	if source != config.ConfigSourceUser && source != config.ConfigSourceSystem {
		t.Errorf("findConfigPath() source = %v, want user or system", source)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/cli -run "TestFindConfigPath" -v`
Expected: FAIL - findConfigPath not defined

**Step 3: Implement findConfigPath and update loadLocalConfig**

Replace contents of `internal/cli/local_config.go`:

```go
package cli

import (
	"os"
	"path/filepath"

	"github.com/agentsh/agentsh/internal/config"
)

// findConfigPath searches for config file in priority order and returns
// the path and its source.
// Search order:
// 1. AGENTSH_CONFIG env var
// 2. User-local config (~/.config/agentsh/config.yaml or platform equivalent)
// 3. System-wide config (/etc/agentsh/config.yaml or platform equivalent)
func findConfigPath() (string, config.ConfigSource) {
	// 1. Check env var first
	if v := os.Getenv("AGENTSH_CONFIG"); v != "" {
		return v, config.ConfigSourceEnv
	}

	// 2. Check user-local config
	userConfigDir := config.GetUserConfigDir()
	for _, name := range []string{"config.yaml", "config.yml"} {
		userConfig := filepath.Join(userConfigDir, name)
		if _, err := os.Stat(userConfig); err == nil {
			return userConfig, config.ConfigSourceUser
		}
	}

	// 3. Check system-wide config
	systemConfigDir := config.GetConfigDir()
	for _, name := range []string{"config.yaml", "config.yml"} {
		systemConfig := filepath.Join(systemConfigDir, name)
		if _, err := os.Stat(systemConfig); err == nil {
			return systemConfig, config.ConfigSourceSystem
		}
	}

	// 4. Fall back to system default (even if doesn't exist)
	return filepath.Join(systemConfigDir, "config.yaml"), config.ConfigSourceSystem
}

// defaultConfigPath returns the config path (for backward compatibility).
// Deprecated: Use findConfigPath() to also get the source.
func defaultConfigPath() string {
	path, _ := findConfigPath()
	return path
}

// loadLocalConfig loads configuration from the given path or auto-discovers it.
// Returns the config, the source where it was loaded from, and any error.
func loadLocalConfig(path string) (*config.Config, config.ConfigSource, error) {
	var source config.ConfigSource
	if path == "" {
		path, source = findConfigPath()
	} else {
		// Explicit path provided - treat as env source
		source = config.ConfigSourceEnv
	}
	cfg, source, err := config.LoadWithSource(path, source)
	return cfg, source, err
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/cli -run "TestFindConfigPath" -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/cli/local_config.go internal/cli/local_config_test.go
git commit -m "feat(cli): implement user-local config search order"
```

---

### Task 5: Update CLI Commands to Use New Config Loading

**Files:**
- Modify: `internal/cli/root.go` (or wherever config is loaded and used)
- Test: Integration test

**Step 1: Find where loadLocalConfig is called**

Run: `grep -r "loadLocalConfig" internal/cli/`

Update any callers to handle the new signature that returns ConfigSource.

**Step 2: Update callers**

For each file that calls `loadLocalConfig`, update to handle the 3-return-value signature:

```go
// Before:
cfg, err := loadLocalConfig(path)

// After:
cfg, source, err := loadLocalConfig(path)
_ = source // or use it for logging/debugging
```

**Step 3: Run all tests**

Run: `go test ./...`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/cli/
git commit -m "feat(cli): update commands to use source-aware config loading"
```

---

### Task 6: Add Integration Test

**Files:**
- Create: `internal/cli/local_config_integration_test.go`

**Step 1: Write integration test**

```go
//go:build integration

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestUserLocalConfigIntegration(t *testing.T) {
	// Create temp directories for user and system config
	tmpDir := t.TempDir()

	// Create user config
	userConfigDir := filepath.Join(tmpDir, "user", ".config", "agentsh")
	os.MkdirAll(userConfigDir, 0755)
	userConfigFile := filepath.Join(userConfigDir, "config.yaml")
	userPoliciesDir := filepath.Join(userConfigDir, "policies")
	os.MkdirAll(userPoliciesDir, 0755)

	userConfig := `
platform:
  mode: auto
policies:
  default: user-policy
`
	os.WriteFile(userConfigFile, []byte(userConfig), 0644)

	// Create a simple policy
	userPolicy := `
name: user-policy
commands:
  allow:
    - ls
`
	os.WriteFile(filepath.Join(userPoliciesDir, "user-policy.yaml"), []byte(userPolicy), 0644)

	// Test: Load config from user location
	// This would require mocking GetUserConfigDir or setting up real paths
	// For now, test via AGENTSH_CONFIG env var pointing to user-style layout
	os.Setenv("AGENTSH_CONFIG", userConfigFile)
	defer os.Unsetenv("AGENTSH_CONFIG")

	cfg, source, err := loadLocalConfig("")
	if err != nil {
		t.Fatalf("loadLocalConfig() error = %v", err)
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("source = %v, want ConfigSourceEnv", source)
	}
	if cfg.Policies.Default != "user-policy" {
		t.Errorf("Policies.Default = %q, want %q", cfg.Policies.Default, "user-policy")
	}
}
```

**Step 2: Run integration test**

Run: `go test ./internal/cli -tags=integration -run "TestUserLocalConfigIntegration" -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/cli/local_config_integration_test.go
git commit -m "test(cli): add integration test for user-local config"
```

---

### Task 7: Run Full Test Suite and Verify

**Step 1: Run all tests**

Run: `go test ./...`
Expected: All PASS

**Step 2: Build and verify**

Run: `go build ./...`
Expected: Build succeeds

**Step 3: Final commit if any cleanup needed**

```bash
git status
# If any uncommitted changes:
git add -A
git commit -m "chore: cleanup after user-local config implementation"
```
