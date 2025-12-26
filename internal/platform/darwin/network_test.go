//go:build darwin

package darwin

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestNewNetwork(t *testing.T) {
	n := NewNetwork()

	if n == nil {
		t.Fatal("NewNetwork() returned nil")
	}

	if n.anchorName != "com.agentsh" {
		t.Errorf("anchorName = %q, want %q", n.anchorName, "com.agentsh")
	}

	if n.rulesFile != "/tmp/agentsh-pf.rules" {
		t.Errorf("rulesFile = %q, want %q", n.rulesFile, "/tmp/agentsh-pf.rules")
	}

	if n.implementation != "pf" {
		t.Errorf("implementation = %q, want %q", n.implementation, "pf")
	}
}

func TestNetwork_Implementation(t *testing.T) {
	n := NewNetwork()
	if got := n.Implementation(); got != "pf" {
		t.Errorf("Implementation() = %q, want %q", got, "pf")
	}
}

func TestNetwork_generatePFRules(t *testing.T) {
	tests := []struct {
		name      string
		config    platform.NetConfig
		wantPorts []string
	}{
		{
			name:      "default ports",
			config:    platform.NetConfig{},
			wantPorts: []string{"port 8080", "port 5353"},
		},
		{
			name: "custom ports",
			config: platform.NetConfig{
				ProxyPort: 9090,
				DNSPort:   5454,
			},
			wantPorts: []string{"port 9090", "port 5454"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNetwork()
			n.config = tt.config
			rules := n.generatePFRules()

			// Check header
			if !strings.Contains(rules, "agentsh network interception rules") {
				t.Error("Rules missing header comment")
			}

			// Check anchor name
			if !strings.Contains(rules, "com.agentsh") {
				t.Error("Rules missing anchor name")
			}

			// Check ports
			for _, port := range tt.wantPorts {
				if !strings.Contains(rules, port) {
					t.Errorf("Rules missing %q", port)
				}
			}

			// Check rdr rules
			if !strings.Contains(rules, "rdr pass") {
				t.Error("Rules missing rdr pass directive")
			}

			// Check DNS redirect
			if !strings.Contains(rules, "port 53") {
				t.Error("Rules missing DNS port 53 redirect")
			}
		})
	}
}

func TestNetwork_Available(t *testing.T) {
	n := NewNetwork()
	// On macOS, pfctl should typically be available
	// Just verify the method works
	_ = n.Available()
}

func TestNetwork_Teardown_NotConfigured(t *testing.T) {
	n := NewNetwork()
	// Should not error when not configured
	if err := n.Teardown(); err != nil {
		t.Errorf("Teardown() error = %v, want nil", err)
	}
}

func TestNetwork_InterfaceCompliance(t *testing.T) {
	var _ platform.NetworkInterceptor = (*Network)(nil)
}
