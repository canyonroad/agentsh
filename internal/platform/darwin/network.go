//go:build darwin

package darwin

import (
	"os/exec"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Network implements platform.NetworkInterceptor for macOS using pf.
type Network struct {
	available      bool
	implementation string
	mu             sync.Mutex
	configured     bool
	config         platform.NetConfig
}

// NewNetwork creates a new macOS network interceptor.
func NewNetwork() *Network {
	n := &Network{}
	n.available = n.checkAvailable()
	n.implementation = "pf"
	return n
}

// checkAvailable checks if pf is available.
func (n *Network) checkAvailable() bool {
	// pf is always available on macOS, check for pfctl
	_, err := exec.LookPath("pfctl")
	return err == nil
}

// Available returns whether network interception is available.
func (n *Network) Available() bool {
	return n.available
}

// Implementation returns the network implementation name.
func (n *Network) Implementation() string {
	return n.implementation
}

// Setup configures network interception using pf.
// Note: Requires root privileges to modify pf rules.
func (n *Network) Setup(config platform.NetConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.config = config
	n.configured = true

	// TODO: Implement pf rule management
	// This would involve:
	// 1. Creating pf rules for traffic redirection
	// 2. Loading rules with pfctl -f
	// 3. Enabling pf with pfctl -e

	return nil
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	// TODO: Remove pf rules

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
