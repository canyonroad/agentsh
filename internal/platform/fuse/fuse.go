package fuse

import (
	"runtime"

	"github.com/agentsh/agentsh/internal/platform"
)

// Config holds FUSE mount configuration.
type Config struct {
	platform.FSConfig

	// VolumeName is the display name shown in file managers.
	VolumeName string

	// ReadOnly mounts the filesystem read-only.
	ReadOnly bool

	// Debug enables verbose FUSE logging.
	Debug bool
}

// InstallInstructions returns platform-specific install help.
func InstallInstructions() string {
	switch runtime.GOOS {
	case "darwin":
		return "Install FUSE-T: brew install fuse-t"
	case "windows":
		return "Install WinFsp: winget install WinFsp.WinFsp"
	default:
		return "FUSE not supported on this platform"
	}
}
