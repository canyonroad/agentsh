//go:build windows

package wsl2

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewNetwork(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	n := NewNetwork(p)

	if n == nil {
		t.Fatal("NewNetwork() returned nil")
	}

	if n.platform != p {
		t.Error("platform not set correctly")
	}

	if n.implementation != "iptables" {
		t.Errorf("implementation = %q, want iptables", n.implementation)
	}
}

func TestNetwork_Implementation(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	n := NewNetwork(p)

	if got := n.Implementation(); got != "iptables" {
		t.Errorf("Implementation() = %q, want iptables", got)
	}
}

func TestNetwork_Available(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	n := &Network{
		platform:  p,
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

func TestNetwork_Setup(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	n := &Network{
		platform:  p,
		available: true,
	}

	cfg := platform.NetConfig{
		ProxyPort: 8080,
		DNSPort:   5353,
	}

	err := n.Setup(cfg)
	if err != nil {
		t.Errorf("Setup() error = %v", err)
	}

	if !n.configured {
		t.Error("configured should be true after Setup()")
	}

	if n.config.ProxyPort != cfg.ProxyPort {
		t.Errorf("config.ProxyPort = %d, want %d", n.config.ProxyPort, cfg.ProxyPort)
	}
}

func TestNetwork_Teardown(t *testing.T) {
	p := &Platform{distro: "Ubuntu"}
	n := &Network{
		platform:   p,
		available:  true,
		configured: true,
	}

	err := n.Teardown()
	if err != nil {
		t.Errorf("Teardown() error = %v", err)
	}

	if n.configured {
		t.Error("configured should be false after Teardown()")
	}
}

func TestNetwork_InterfaceCompliance(t *testing.T) {
	var _ platform.NetworkInterceptor = (*Network)(nil)
}
