//go:build windows

package wsl2

import (
	"fmt"
	"strconv"

	"github.com/agentsh/agentsh/internal/platform"
)

const (
	// iptablesChain is the custom chain name for agentsh rules
	iptablesChain = "AGENTSH"
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
// It creates DNAT rules to redirect TCP and DNS traffic to the proxy ports.
func (n *Network) Setup(config platform.NetConfig) error {
	if !n.available {
		return fmt.Errorf("iptables not available in WSL2")
	}

	n.config = config

	// Create custom chain for agentsh rules
	_, _ = n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-N", iptablesChain)

	// Flush existing rules in our chain
	_, _ = n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-F", iptablesChain)

	// Add jump to our chain from OUTPUT
	// First remove any existing jump, then add fresh
	_, _ = n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-D", "OUTPUT", "-j", iptablesChain)
	if _, err := n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-A", "OUTPUT", "-j", iptablesChain); err != nil {
		return fmt.Errorf("add OUTPUT jump: %w", err)
	}

	// Redirect TCP traffic to proxy port
	if config.ProxyPort > 0 {
		proxyDest := "127.0.0.1:" + strconv.Itoa(config.ProxyPort)
		// Redirect all outbound TCP (except to localhost) to proxy
		if _, err := n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-A", iptablesChain,
			"-p", "tcp",
			"!", "-d", "127.0.0.0/8",
			"-j", "DNAT", "--to-destination", proxyDest); err != nil {
			return fmt.Errorf("add TCP DNAT rule: %w", err)
		}
	}

	// Redirect DNS traffic (UDP port 53) to DNS proxy port
	if config.DNSPort > 0 {
		dnsDest := "127.0.0.1:" + strconv.Itoa(config.DNSPort)
		if _, err := n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-A", iptablesChain,
			"-p", "udp", "--dport", "53",
			"-j", "DNAT", "--to-destination", dnsDest); err != nil {
			return fmt.Errorf("add DNS DNAT rule: %w", err)
		}
	}

	n.configured = true
	return nil
}

// Teardown removes network interception.
func (n *Network) Teardown() error {
	if !n.configured {
		return nil
	}

	// Remove jump from OUTPUT chain
	_, _ = n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-D", "OUTPUT", "-j", iptablesChain)

	// Flush and delete our chain
	_, _ = n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-F", iptablesChain)
	_, _ = n.platform.RunInWSL("sudo", "iptables", "-t", "nat", "-X", iptablesChain)

	n.configured = false
	return nil
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
