// internal/platform/windows/windivert_stub.go
//go:build !windows

package windows

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/platform"
)

// WinDivertHandle is a stub for non-Windows platforms.
type WinDivertHandle struct{}

// NewWinDivertHandle returns an error on non-Windows platforms.
func NewWinDivertHandle(natTable *NATTable, config platform.NetConfig, driver *DriverClient) (*WinDivertHandle, error) {
	return nil, fmt.Errorf("WinDivert is only available on Windows")
}

// Start is a no-op stub.
func (w *WinDivertHandle) Start() error {
	return fmt.Errorf("WinDivert is only available on Windows")
}

// Stop is a no-op stub.
func (w *WinDivertHandle) Stop() error {
	return nil
}

// AddSessionPID is a no-op stub.
func (w *WinDivertHandle) AddSessionPID(pid uint32) {}

// RemoveSessionPID is a no-op stub.
func (w *WinDivertHandle) RemoveSessionPID(pid uint32) {}

// IsSessionPID is a no-op stub.
func (w *WinDivertHandle) IsSessionPID(pid uint32) bool {
	return false
}
