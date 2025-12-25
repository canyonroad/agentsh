//go:build windows

package wsl2

import (
	"github.com/agentsh/agentsh/internal/platform"
)

// Network implements platform.NetworkInterceptor for WSL2.
// It delegates to the Linux iptables implementation running inside WSL2.
type Network struct {
	platform       *Platform
	available      bool
	implementation string
	configured     bool
	config         platform.NetConfig
}

// NewNetwork creates a new WSL2 network interceptor.
func NewNetwork(p *Platform) *Network {
	n := &Network{
		platform: p,
	}
	n.available = n.checkAvailable()
	n.implementation = "iptables"
	return n
}

// checkAvailable checks if iptables is available in WSL2.
func (n *Network) checkAvailable() bool {
	_, err := n.platform.RunInWSL("which", "iptables")
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

// Setup configures network interception using iptables inside WSL2.
func (n *Network) Setup(config platform.NetConfig) error {
	n.config = config
	n.configured = true

	// TODO: Execute iptables rules inside WSL2
	// This would set up traffic redirection to the proxy ports

	return nil
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	// TODO: Remove iptables rules inside WSL2

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
