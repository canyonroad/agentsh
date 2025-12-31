package config

import (
	"os"
	"runtime"
	"strings"
)

// GetSystemMounts returns the built-in read-only system mounts for the current platform.
func GetSystemMounts() []MountSpec {
	switch runtime.GOOS {
	case "linux":
		return linuxSystemMounts()
	case "darwin":
		return darwinSystemMounts()
	case "windows":
		return windowsSystemMounts()
	default:
		return minimalSystemMounts()
	}
}

func linuxSystemMounts() []MountSpec {
	mounts := []MountSpec{
		{Path: "/usr", Policy: "system-readonly"},
		{Path: "/lib", Policy: "system-readonly"},
		{Path: "/lib64", Policy: "system-readonly"},
		{Path: "/bin", Policy: "system-readonly"},
		{Path: "/sbin", Policy: "system-readonly"},
		{Path: "/etc/hosts", Policy: "system-readonly"},
		{Path: "/etc/resolv.conf", Policy: "system-readonly"},
		{Path: "/etc/ssl/certs", Policy: "system-readonly"},
	}

	if isRunningInContainer() {
		mounts = append(mounts, MountSpec{
			Path: "/etc/alternatives", Policy: "system-readonly",
		})
	}

	return mounts
}

func darwinSystemMounts() []MountSpec {
	mounts := []MountSpec{
		{Path: "/usr", Policy: "system-readonly"},
		{Path: "/bin", Policy: "system-readonly"},
		{Path: "/sbin", Policy: "system-readonly"},
		{Path: "/System/Library", Policy: "system-readonly"},
		{Path: "/etc/hosts", Policy: "system-readonly"},
		{Path: "/etc/resolv.conf", Policy: "system-readonly"},
	}

	// Add Homebrew paths if they exist
	if _, err := os.Stat("/opt/homebrew"); err == nil {
		mounts = append(mounts, MountSpec{Path: "/opt/homebrew", Policy: "system-readonly"})
	}
	if _, err := os.Stat("/usr/local/Cellar"); err == nil {
		mounts = append(mounts, MountSpec{Path: "/usr/local/Cellar", Policy: "system-readonly"})
	}

	return mounts
}

func windowsSystemMounts() []MountSpec {
	return []MountSpec{
		{Path: "C:\\Windows\\System32", Policy: "system-readonly"},
		{Path: "C:\\Program Files", Policy: "system-readonly"},
		{Path: "C:\\Program Files (x86)", Policy: "system-readonly"},
	}
}

func minimalSystemMounts() []MountSpec {
	return []MountSpec{
		{Path: "/usr", Policy: "system-readonly"},
		{Path: "/bin", Policy: "system-readonly"},
	}
}

func isRunningInContainer() bool {
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	if data, err := os.ReadFile("/proc/1/cgroup"); err == nil {
		s := string(data)
		return strings.Contains(s, "docker") || strings.Contains(s, "kubepods")
	}
	return false
}

// Environment contains information about the current runtime environment.
type Environment struct {
	OS             string
	InContainer    bool
	InWSL          bool
	InDevContainer bool
}

// DetectEnvironment returns information about the current runtime environment.
func DetectEnvironment() Environment {
	env := Environment{OS: runtime.GOOS}

	env.InContainer = isRunningInContainer()

	if runtime.GOOS == "linux" {
		if data, err := os.ReadFile("/proc/version"); err == nil {
			env.InWSL = strings.Contains(strings.ToLower(string(data)), "microsoft")
		}
	}

	env.InDevContainer = os.Getenv("REMOTE_CONTAINERS") != "" ||
		os.Getenv("CODESPACES") != ""

	return env
}
