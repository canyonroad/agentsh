// internal/policygen/risky_test.go
package policygen

import "testing"

func TestIsBuiltinRisky(t *testing.T) {
	tests := []struct {
		cmd      string
		expected bool
		reason   string
	}{
		{"curl", true, "network"},
		{"wget", true, "network"},
		{"ssh", true, "network"},
		{"rm", true, "destructive"},
		{"sudo", true, "privileged"},
		{"docker", true, "container"},
		{"npm", false, ""},
		{"node", false, ""},
		{"git", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			risky, reason := IsBuiltinRisky(tt.cmd)
			if risky != tt.expected {
				t.Errorf("IsBuiltinRisky(%q) = %v, want %v", tt.cmd, risky, tt.expected)
			}
			if tt.expected && reason != tt.reason {
				t.Errorf("IsBuiltinRisky(%q) reason = %q, want %q", tt.cmd, reason, tt.reason)
			}
		})
	}
}

func TestRiskyDetector_MarkNetworkCapable(t *testing.T) {
	d := NewRiskyDetector()
	d.MarkNetworkCapable("my-custom-tool")

	if !d.IsRisky("my-custom-tool") {
		t.Error("expected my-custom-tool to be risky after marking")
	}
	reason := d.Reason("my-custom-tool")
	if reason != "network-observed" {
		t.Errorf("expected reason 'network-observed', got %q", reason)
	}
}

func TestRiskyDetector_MarkDestructive(t *testing.T) {
	d := NewRiskyDetector()
	d.MarkDestructive("cleanup-script")

	if !d.IsRisky("cleanup-script") {
		t.Error("expected cleanup-script to be risky after marking")
	}
}
