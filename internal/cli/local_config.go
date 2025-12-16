package cli

import (
	"os"

	"github.com/agentsh/agentsh/internal/config"
)

func defaultConfigPath() string {
	if v := os.Getenv("AGENTSH_CONFIG"); v != "" {
		return v
	}
	if _, err := os.Stat("config.yml"); err == nil {
		return "config.yml"
	}
	if _, err := os.Stat("config.yaml"); err == nil {
		return "config.yaml"
	}
	return "/etc/agentsh/config.yaml"
}

func loadLocalConfig(path string) (*config.Config, error) {
	if path == "" {
		path = defaultConfigPath()
	}
	return config.Load(path)
}
