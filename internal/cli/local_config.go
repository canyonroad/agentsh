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
