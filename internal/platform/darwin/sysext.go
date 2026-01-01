//go:build darwin

// Package darwin provides the macOS platform implementation for agentsh.
package darwin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SysExtStatus represents the state of the System Extension.
type SysExtStatus struct {
	Installed   bool   `json:"installed"`
	Running     bool   `json:"running"`
	Version     string `json:"version,omitempty"`
	BundleID    string `json:"bundle_id,omitempty"`
	ExtensionID string `json:"extension_id,omitempty"`
	Error       string `json:"error,omitempty"`
}

// SysExtManager manages the agentsh System Extension lifecycle.
type SysExtManager struct {
	bundlePath string
	bundleID   string
}

// NewSysExtManager creates a new System Extension manager.
func NewSysExtManager() *SysExtManager {
	// Find the app bundle - either we're running from it or it's adjacent
	execPath, _ := os.Executable()
	bundlePath := findAppBundle(execPath)

	return &SysExtManager{
		bundlePath: bundlePath,
		bundleID:   "com.agentsh.sysext",
	}
}

// findAppBundle locates the AgentSH.app bundle.
func findAppBundle(execPath string) string {
	// If running from within .app bundle
	if idx := strings.Index(execPath, ".app/"); idx >= 0 {
		return execPath[:idx+4]
	}

	// Check common locations
	candidates := []string{
		"/Applications/AgentSH.app",
		filepath.Join(filepath.Dir(execPath), "AgentSH.app"),
		filepath.Join(filepath.Dir(execPath), "..", "AgentSH.app"),
	}

	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c
		}
	}

	return ""
}

// Status returns the current System Extension status.
// This method never returns an error - any errors are reported via status.Error.
func (m *SysExtManager) Status() (*SysExtStatus, error) {
	status := &SysExtStatus{
		BundleID: m.bundleID,
	}

	if m.bundlePath == "" {
		status.Error = "AgentSH.app bundle not found"
		return status, nil
	}

	// Check if extension is installed via systemextensionsctl
	out, err := exec.Command("systemextensionsctl", "list").Output()
	if err != nil {
		status.Error = fmt.Sprintf("systemextensionsctl: %v", err)
		return status, nil
	}

	output := string(out)
	if contains(output, m.bundleID) {
		status.Installed = true
		if contains(output, "activated enabled") {
			status.Running = true
		}
	}

	return status, nil
}

// Install requests installation of the System Extension.
func (m *SysExtManager) Install() error {
	if m.bundlePath == "" {
		return fmt.Errorf("AgentSH.app bundle not found; install it first")
	}

	// The actual installation is triggered by OSSystemExtensionManager in Swift
	// This Go code just validates prerequisites
	extPath := filepath.Join(m.bundlePath, "Contents", "Library", "SystemExtensions",
		m.bundleID+".systemextension")

	if _, err := os.Stat(extPath); err != nil {
		return fmt.Errorf("System Extension not found at %s", extPath)
	}

	fmt.Println("System Extension installation will require user approval.")
	fmt.Println("A system dialog will appear asking for permission.")

	// In the real implementation, this would use NSWorkspace to launch
	// the app with an argument that triggers the Swift installation code
	return fmt.Errorf("not implemented: requires Swift integration")
}

// Uninstall removes the System Extension.
func (m *SysExtManager) Uninstall() error {
	return fmt.Errorf("not implemented: requires Swift integration")
}

// contains checks if substr is present in s.
// Handles empty strings safely.
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(s) < len(substr) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
