//go:build linux

package linux

import (
	"os"
	"os/exec"
	"sync"

	"github.com/agentsh/agentsh/internal/platform"
)

// Network implements platform.NetworkInterceptor for Linux.
// It uses iptables for traffic redirection and network namespaces for isolation.
type Network struct {
	available      bool
	implementation string
	mu             sync.Mutex
	configured     bool
	config         platform.NetConfig
}

// NewNetwork creates a new Linux network interceptor.
func NewNetwork() *Network {
	n := &Network{}
	n.available = n.checkAvailable()
	n.implementation = n.detectImplementation()
	return n
}

// checkAvailable checks if network interception is available.
func (n *Network) checkAvailable() bool {
	// Check for iptables
	if _, err := exec.LookPath("iptables"); err != nil {
		return false
	}
	// Check for ip command (for netns management)
	if _, err := exec.LookPath("ip"); err != nil {
		return false
	}
	// Check if we have network namespace support
	if _, err := os.Stat("/proc/self/ns/net"); err != nil {
		return false
	}
	return true
}

// detectImplementation returns the network implementation name.
func (n *Network) detectImplementation() string {
	// Check for nftables (newer)
	if _, err := exec.LookPath("nft"); err == nil {
		// Check if nftables is actually in use
		if data, err := os.ReadFile("/proc/net/nf_tables"); err == nil && len(data) > 0 {
			return "nftables+netns"
		}
	}
	// Default to iptables
	return "iptables+netns"
}

// Available returns whether network interception is available.
func (n *Network) Available() bool {
	return n.available
}

// Implementation returns the network implementation name.
func (n *Network) Implementation() string {
	return n.implementation
}

// Setup configures network interception.
// Note: The actual per-session network namespace setup is currently handled
// by the api layer (tryStartTransparentNetwork). This method stores the config
// for future use when we migrate the netns logic to the platform layer.
func (n *Network) Setup(config platform.NetConfig) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.config = config
	n.configured = true
	return nil
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	n.mu.Lock()
	defer n.mu.Unlock()

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
