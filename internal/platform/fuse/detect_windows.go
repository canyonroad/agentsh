// internal/platform/fuse/detect_windows.go
//go:build windows

package fuse

import (
	"os"
	"os/exec"
	"path/filepath"
)

func checkAvailable() bool {
	paths := []string{
		filepath.Join(os.Getenv("ProgramFiles"), "WinFsp", "bin", "winfsp-x64.dll"),
		filepath.Join(os.Getenv("ProgramFiles(x86)"), "WinFsp", "bin", "winfsp-x86.dll"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "winfsp-x64.dll"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Check registry for WinFsp installation
	cmd := exec.Command("reg", "query", `HKLM\SOFTWARE\WinFsp`, "/ve")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

func detectImplementation() string {
	if checkAvailable() {
		return "winfsp"
	}
	return "none"
}
