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

	// The test verifies the search order logic works correctly
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

func TestFindConfigPath_EnvVarTakesPriority(t *testing.T) {
	// Create a temp config file
	tmpFile := filepath.Join(t.TempDir(), "priority-test.yaml")
	if err := os.WriteFile(tmpFile, []byte("platform:\n  mode: auto\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Set env var
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Setenv("AGENTSH_CONFIG", tmpFile)
	defer os.Setenv("AGENTSH_CONFIG", orig)

	path, source := findConfigPath()

	// Env var should always win, regardless of what user/system configs exist
	if path != tmpFile {
		t.Errorf("findConfigPath() path = %q, want %q (env var should take priority)", path, tmpFile)
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("findConfigPath() source = %v, want ConfigSourceEnv", source)
	}
}

func TestFindConfigPath_EnvVarNonexistent(t *testing.T) {
	// Set env var to nonexistent path - should still return it (validation happens later)
	orig := os.Getenv("AGENTSH_CONFIG")
	os.Setenv("AGENTSH_CONFIG", "/nonexistent/config.yaml")
	defer os.Setenv("AGENTSH_CONFIG", orig)

	path, source := findConfigPath()

	if path != "/nonexistent/config.yaml" {
		t.Errorf("findConfigPath() path = %q, want %q", path, "/nonexistent/config.yaml")
	}
	if source != config.ConfigSourceEnv {
		t.Errorf("findConfigPath() source = %v, want ConfigSourceEnv", source)
	}
}

func TestLoadLocalConfig_ExplicitPath(t *testing.T) {
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "explicit.yaml")
	if err := os.WriteFile(configPath, []byte("platform:\n  mode: auto\n"), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, source, err := loadLocalConfig(configPath)
	if err != nil {
		t.Fatalf("loadLocalConfig() error = %v", err)
	}

	// Explicit path should be treated as ConfigSourceEnv
	if source != config.ConfigSourceEnv {
		t.Errorf("loadLocalConfig() source = %v, want ConfigSourceEnv for explicit path", source)
	}
	if cfg.Platform.Mode != "auto" {
		t.Errorf("loadLocalConfig() cfg.Platform.Mode = %q, want %q", cfg.Platform.Mode, "auto")
	}
}

func TestLoadLocalConfig_ExplicitPath_NotFound(t *testing.T) {
	_, _, err := loadLocalConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("loadLocalConfig() expected error for nonexistent file")
	}
}
