//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Network implements platform.NetworkInterceptor for Windows using WinDivert.
type Network struct {
	available      bool
	implementation string
	mu             sync.Mutex
	configured     bool
	config         platform.NetConfig
}

// NewNetwork creates a new Windows network interceptor.
func NewNetwork() *Network {
	n := &Network{}
	n.available = n.checkAvailable()
	n.implementation = "windivert"
	return n
}

// checkAvailable checks if WinDivert is available.
func (n *Network) checkAvailable() bool {
	// Check for WinDivert driver
	paths := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "WinDivert.sys"),
		filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "WinDivert64.sys"),
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	// Also check for WinDivert DLL
	dllPaths := []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "WinDivert.dll"),
	}

	for _, path := range dllPaths {
		if _, err := os.Stat(path); err == nil {
			return true
		}
	}

	return false
}

// Available returns whether network interception is available.
func (n *Network) Available() bool {
	return n.available
}

// Implementation returns the network implementation name.
func (n *Network) Implementation() string {
	return n.implementation
}

// Setup configures network interception using WinDivert.
// Note: Requires administrator privileges to load WinDivert driver.
func (n *Network) Setup(config platform.NetConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.config = config
	n.configured = true

	// TODO: Implement WinDivert packet capture and redirection
	// This would involve:
	// 1. Loading WinDivert driver
	// 2. Setting up packet filters
	// 3. Redirecting traffic to proxy ports

	return nil
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// TODO: Unload WinDivert filters

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
