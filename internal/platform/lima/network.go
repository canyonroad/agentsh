//go:build darwin

package lima

import (
	"github.com/agentsh/agentsh/internal/platform"
)

// Network implements platform.NetworkInterceptor for Lima.
// It delegates to the Linux iptables implementation running inside the Lima VM.
type Network struct {
	platform       *Platform
	available      bool
	implementation string
	configured     bool
	config         platform.NetConfig
}

// NewNetwork creates a new Lima network interceptor.
func NewNetwork(p *Platform) *Network {
	n := &Network{
		platform: p,
	}
	n.available = n.checkAvailable()
	n.implementation = "iptables"
	return n
}

// checkAvailable checks if iptables is available in the Lima VM.
func (n *Network) checkAvailable() bool {
	_, err := n.platform.RunInLima("which", "iptables")
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

// Setup configures network interception using iptables inside the Lima VM.
func (n *Network) Setup(config platform.NetConfig) error {
	n.config = config
	n.configured = true

	// TODO: Execute iptables rules inside Lima VM
	// This would set up traffic redirection to the proxy ports

	return nil
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	// TODO: Remove iptables rules inside Lima VM

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
