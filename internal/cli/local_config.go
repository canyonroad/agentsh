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
	if _, err := os.Stat("/etc/agentsh/config.yaml"); err == nil {
		return "/etc/agentsh/config.yaml"
	}
	if _, err := os.Stat("/etc/agentsh/config.yml"); err == nil {
		return "/etc/agentsh/config.yml"
	}
	return "/etc/agentsh/config.yaml"
}

func loadLocalConfig(path string) (*config.Config, error) {
	if path == "" {
		path = defaultConfigPath()
	}
	return config.Load(path)
}
