package dialog

import (
	"os"
	"runtime"
	"strings"
)

// ciEnvVars is a list of environment variables that indicate CI environment
var ciEnvVars = []string{
	"CI",
	"GITHUB_ACTIONS",
	"GITLAB_CI",
	"CIRCLECI",
	"TRAVIS",
	"JENKINS_URL",
	"BUILDKITE",
	"TEAMCITY_VERSION",
	"TF_BUILD", // Azure Pipelines
}

// IsCI returns true if running in a CI environment.
func IsCI() bool {
	for _, env := range ciEnvVars {
		if os.Getenv(env) != "" {
			return true
		}
	}
	return false
}

// HasDisplay returns true if a display is available for showing dialogs.
func HasDisplay() bool {
	switch runtime.GOOS {
	case "linux":
		// Check for X11 or Wayland display
		return os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != ""
	case "darwin", "windows":
		// macOS and Windows always have display available in desktop session
		return true
	default:
		return false
	}
}

// IsWSL returns true if running in Windows Subsystem for Linux.
func IsWSL() bool {
	if runtime.GOOS != "linux" {
		return false
	}

	data, err := os.ReadFile("/proc/version")
	if err != nil {
		return false
	}

	lower := strings.ToLower(string(data))
	return strings.Contains(lower, "microsoft") || strings.Contains(lower, "wsl")
}

// IsEnabled returns true if dialog should be shown based on mode setting.
// Valid modes: "auto" (default), "enabled", "disabled"
func IsEnabled(mode string) bool {
	switch mode {
	case "disabled":
		return false
	case "enabled":
		return true
	case "auto", "":
		// Auto-detect: disable in CI, enable if display available or WSL
		if IsCI() {
			return false
		}
		return HasDisplay() || IsWSL()
	default:
		// Unknown mode, treat as auto
		return IsEnabled("auto")
	}
}

// CanShowDialog returns true if a dialog backend is available on this platform.
func CanShowDialog() bool {
	if !HasDisplay() && !IsWSL() {
		return false
	}
	return hasDialogBackend()
}
