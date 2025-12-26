//go:build windows

package windows

import (
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewNetwork(t *testing.T) {
	n := NewNetwork()

	if n == nil {
		t.Fatal("NewNetwork() returned nil")
	}

	// WFP should always be available on Windows Vista+
	if !n.hasWFP {
		t.Error("hasWFP should be true")
	}

	// Available should be true since WFP is always available
	if !n.available {
		t.Error("Available() should be true")
	}
}

func TestNetwork_Implementation(t *testing.T) {
	n := NewNetwork()

	impl := n.Implementation()
	if impl != "windivert" && impl != "wfp" && impl != "none" {
		t.Errorf("Implementation() = %q, want windivert, wfp, or none", impl)
	}
}

func TestNetwork_DetectImplementation(t *testing.T) {
	n := &Network{hasWinDivert: true, hasWFP: true}
	if n.detectImplementation() != "windivert" {
		t.Error("Should prefer WinDivert when available")
	}

	n = &Network{hasWinDivert: false, hasWFP: true}
	if n.detectImplementation() != "wfp" {
		t.Error("Should use WFP when WinDivert not available")
	}

	n = &Network{hasWinDivert: false, hasWFP: false}
	if n.detectImplementation() != "none" {
		t.Error("Should return none when nothing available")
	}
}

func TestNetwork_CanRedirectTraffic(t *testing.T) {
	n := &Network{hasWinDivert: true}
	if !n.CanRedirectTraffic() {
		t.Error("CanRedirectTraffic should be true with WinDivert")
	}

	n = &Network{hasWinDivert: false}
	if n.CanRedirectTraffic() {
		t.Error("CanRedirectTraffic should be false without WinDivert")
	}
}

func TestNetwork_Setup(t *testing.T) {
	n := NewNetwork()

	config := platform.NetConfig{
		ProxyPort: 9090,
		DNSPort:   5454,
	}

	err := n.Setup(config)
	if err != nil {
		t.Errorf("Setup() error = %v", err)
	}

	if !n.configured {
		t.Error("configured should be true after Setup()")
	}

	if n.proxyPort != 9090 {
		t.Errorf("proxyPort = %d, want 9090", n.proxyPort)
	}

	if n.dnsPort != 5454 {
		t.Errorf("dnsPort = %d, want 5454", n.dnsPort)
	}
}

func TestNetwork_Setup_DefaultPorts(t *testing.T) {
	n := NewNetwork()

	config := platform.NetConfig{}
	err := n.Setup(config)
	if err != nil {
		t.Errorf("Setup() error = %v", err)
	}

	if n.proxyPort != 8080 {
		t.Errorf("proxyPort = %d, want 8080 (default)", n.proxyPort)
	}

	if n.dnsPort != 5353 {
		t.Errorf("dnsPort = %d, want 5353 (default)", n.dnsPort)
	}
}

func TestNetwork_WinDivertFilter(t *testing.T) {
	n := &Network{proxyPort: 8080}

	filter := n.WinDivertFilter()
	if filter == "" {
		t.Error("WinDivertFilter() returned empty string")
	}

	// Should contain proxy port exclusion
	expected := "8080"
	if !containsString(filter, expected) {
		t.Errorf("WinDivertFilter() = %q, should contain %q", filter, expected)
	}
}

func TestNetwork_Teardown(t *testing.T) {
	n := NewNetwork()

	config := platform.NetConfig{ProxyPort: 8080}
	if err := n.Setup(config); err != nil {
		t.Fatalf("Setup() error = %v", err)
	}

	if err := n.Teardown(); err != nil {
		t.Errorf("Teardown() error = %v", err)
	}

	if n.configured {
		t.Error("configured should be false after Teardown()")
	}
}

func TestNetwork_Teardown_NotConfigured(t *testing.T) {
	n := NewNetwork()

	// Should not error when not configured
	if err := n.Teardown(); err != nil {
		t.Errorf("Teardown() error = %v, want nil", err)
	}
}

func TestNetwork_AddBlockRule_NotConfigured(t *testing.T) {
	n := NewNetwork()
	n.hasWFP = true

	err := n.AddBlockRule("192.168.1.1", 80)
	if err == nil {
		t.Error("AddBlockRule() should error when not configured")
	}
}

func TestNetwork_AddAllowRule_NotConfigured(t *testing.T) {
	n := NewNetwork()
	n.hasWFP = true

	err := n.AddAllowRule("192.168.1.1", 80)
	if err == nil {
		t.Error("AddAllowRule() should error when not configured")
	}
}

func TestNetwork_InterfaceCompliance(t *testing.T) {
	var _ platform.NetworkInterceptor = (*Network)(nil)
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsString(s[1:], substr) || s[:len(substr)] == substr)
}
