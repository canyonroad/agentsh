package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/agentsh/agentsh/internal/platform"
)

// ConfigSource indicates where the configuration was loaded from.
type ConfigSource int

const (
	// ConfigSourceEnv means config path was specified via AGENTSH_CONFIG env var.
	ConfigSourceEnv ConfigSource = iota
	// ConfigSourceUser means config was loaded from user-local directory.
	ConfigSourceUser
	// ConfigSourceSystem means config was loaded from system-wide directory.
	ConfigSourceSystem
	// ConfigSourceBundle means config was loaded from the macOS .app bundle Resources.
	ConfigSourceBundle
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
	case ConfigSourceBundle:
		return "bundle"
	default:
		return "unknown"
	}
}

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

// GetBundleResourcesDir returns the Resources directory inside the macOS .app bundle,
// or empty string if not running from a bundle or not on macOS.
func GetBundleResourcesDir() string {
	if runtime.GOOS != "darwin" {
		return ""
	}
	execPath, err := os.Executable()
	if err != nil {
		return ""
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return ""
	}
	// Check if running from inside a .app bundle (e.g. /Applications/AgentSH.app/Contents/MacOS/agentsh)
	if idx := strings.Index(execPath, ".app/"); idx >= 0 {
		return filepath.Join(execPath[:idx+4], "Contents", "Resources")
	}
	return ""
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

// GetUserStateDir returns the user-specific state directory used for ephemeral
// runtime artifacts (e.g., WTP WAL/cursor/replay store). On Linux this honors
// the XDG_STATE_HOME env var with a fallback to ~/.local/state, matching the
// XDG Base Directory specification. macOS and Windows have no canonical state
// directory, so we reuse the data directory location there.
func GetUserStateDir() string {
	home, _ := os.UserHomeDir()
	switch runtime.GOOS {
	case "windows":
		if appdata := os.Getenv("LOCALAPPDATA"); appdata != "" {
			return appdata + `\agentsh`
		}
		return home + `\AppData\Local\agentsh`
	case "darwin":
		return home + "/Library/Application Support/agentsh"
	default:
		if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
			return xdg + "/agentsh"
		}
		return home + "/.local/state/agentsh"
	}
}
