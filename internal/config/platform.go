package config

import (
	"fmt"
	"os"
	"runtime"

	"github.com/agentsh/agentsh/internal/platform"
)

// InitializePlatform creates and configures a platform based on the config.
func InitializePlatform(cfg *Config) (platform.Platform, error) {
	opts := platform.PlatformOptions{
		Mode:            cfg.Platform.Mode,
		FallbackEnabled: cfg.Platform.Fallback.Enabled,
		FallbackOrder:   cfg.Platform.Fallback.Order,
	}

	p, err := platform.NewWithOptions(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize platform: %w", err)
	}

	// Validate platform capabilities meet requirements
	caps := p.Capabilities()

	if cfg.Sandbox.Enabled && !cfg.Sandbox.AllowDegraded {
		if caps.IsolationLevel < platform.IsolationFull {
			return nil, fmt.Errorf(
				"platform %s has degraded isolation (level %s), "+
					"set sandbox.allow_degraded=true to continue",
				p.Name(), caps.IsolationLevel,
			)
		}
	}

	return p, nil
}

// GetMountPoint returns the appropriate mount point for the current platform.
func GetMountPoint(cfg *Config) string {
	mode := platform.ParsePlatformMode(cfg.Platform.Mode)

	switch mode {
	case platform.ModeLinuxNative:
		return cfg.Platform.MountPoints.Linux
	case platform.ModeDarwinNative, platform.ModeDarwinLima:
		return cfg.Platform.MountPoints.Darwin
	case platform.ModeWindowsNative:
		return cfg.Platform.MountPoints.Windows
	case platform.ModeWindowsWSL2:
		return cfg.Platform.MountPoints.WindowsWSL2
	default:
		// Fallback based on runtime OS
		switch runtime.GOOS {
		case "windows":
			return cfg.Platform.MountPoints.Windows
		case "darwin":
			return cfg.Platform.MountPoints.Darwin
		default:
			return cfg.Platform.MountPoints.Linux
		}
	}
}

// GetDataDir returns the platform-appropriate data directory.
func GetDataDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("PROGRAMDATA"); dir != "" {
			return dir + `\agentsh`
		}
		return `C:\ProgramData\agentsh`
	case "darwin":
		return "/usr/local/var/agentsh"
	default:
		return "/var/lib/agentsh"
	}
}

// GetConfigDir returns the platform-appropriate config directory.
func GetConfigDir() string {
	switch runtime.GOOS {
	case "windows":
		if dir := os.Getenv("PROGRAMDATA"); dir != "" {
			return dir + `\agentsh`
		}
		return `C:\ProgramData\agentsh`
	case "darwin":
		return "/usr/local/etc/agentsh"
	default:
		return "/etc/agentsh"
	}
}

// GetPoliciesDir returns the platform-appropriate policies directory.
func GetPoliciesDir() string {
	return GetConfigDir() + string(os.PathSeparator) + "policies"
}

// GetUserConfigDir returns the user-specific config directory.
func GetUserConfigDir() string {
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
		if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
			return xdg + "/agentsh"
		}
		return home + "/.config/agentsh"
	}
}
