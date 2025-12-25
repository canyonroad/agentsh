//go:build linux

package linux

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewNetwork(t *testing.T) {
	n := NewNetwork()
	if n == nil {
		t.Fatal("NewNetwork returned nil")
	}

	// Implementation should be set
	impl := n.Implementation()
	if impl == "" {
		t.Error("Implementation() returned empty string")
	}
	if impl != "iptables+netns" && impl != "nftables+netns" {
		t.Errorf("Implementation() = %q, want iptables+netns or nftables+netns", impl)
	}
}

func TestNetwork_SetupTeardown(t *testing.T) {
	n := NewNetwork()

	// Setup should succeed
	cfg := platform.NetConfig{
		ProxyPort: 8080,
		DNSPort:   5353,
	}
	if err := n.Setup(cfg); err != nil {
		t.Errorf("Setup() error = %v", err)
	}

	// Teardown should succeed
	if err := n.Teardown(); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}
}

// Compile-time interface check
var _ platform.NetworkInterceptor = (*Network)(nil)
