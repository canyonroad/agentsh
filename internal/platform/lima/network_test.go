//go:build darwin

package lima

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNetwork_Available(t *testing.T) {
	n := &Network{
		available: true,
	}

	if !n.Available() {
		t.Error("Available() should return true when available is true")
	}

	n.available = false
	if n.Available() {
		t.Error("Available() should return false when available is false")
	}
}

func TestNetwork_Implementation(t *testing.T) {
	n := &Network{
		implementation: "iptables",
	}

	if got := n.Implementation(); got != "iptables" {
		t.Errorf("Implementation() = %q, want iptables", got)
	}
}

func TestNetwork_SetupNotAvailable(t *testing.T) {
	n := &Network{
		available: false,
	}

	err := n.Setup(platform.NetConfig{ProxyPort: 8080})
	if err == nil {
		t.Error("Setup() should error when iptables not available")
	}
}

func TestNetwork_TeardownNotConfigured(t *testing.T) {
	n := &Network{
		configured: false,
	}

	err := n.Teardown()
	if err != nil {
		t.Errorf("Teardown() should return nil when not configured, got: %v", err)
	}
}

func TestIptablesChainName(t *testing.T) {
	if iptablesChain != "AGENTSH" {
		t.Errorf("iptablesChain = %q, want AGENTSH", iptablesChain)
	}
}

func TestNetwork_InterfaceCompliance(t *testing.T) {
	var _ platform.NetworkInterceptor = (*Network)(nil)
}
