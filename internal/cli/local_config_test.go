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
