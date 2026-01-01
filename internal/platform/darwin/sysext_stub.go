//go:build !darwin

// Package darwin provides stubs for non-macOS platforms.
package darwin

import "fmt"

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
type SysExtManager struct{}

// NewSysExtManager creates a new System Extension manager.
func NewSysExtManager() *SysExtManager {
	return &SysExtManager{}
}

// Status returns the current System Extension status.
func (m *SysExtManager) Status() (*SysExtStatus, error) {
	return &SysExtStatus{Error: "System Extensions are only available on macOS"}, nil
}

// Install requests installation of the System Extension.
func (m *SysExtManager) Install() error {
	return fmt.Errorf("System Extensions are only available on macOS")
}

// Uninstall removes the System Extension.
func (m *SysExtManager) Uninstall() error {
	return fmt.Errorf("System Extensions are only available on macOS")
}
