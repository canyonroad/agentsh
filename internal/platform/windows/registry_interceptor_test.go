//go:build windows

package windows

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestRegistryInterceptor_HandleRequest(t *testing.T) {
	eventChan := make(chan types.Event, 10)

	cfg := &config.RegistryPolicyConfig{
		DefaultAction:   "deny",
		DefaultCacheTTL: 30,
		Rules: []config.RegistryPolicyRule{
			{
				Name:       "allow-test-app",
				Paths:      []string{`HKCU\SOFTWARE\TestApp\*`},
				Operations: []string{"*"},
				Action:     "allow",
			},
		},
	}

	interceptor, err := NewRegistryInterceptor(cfg, eventChan, "test-session")
	if err != nil {
		t.Fatalf("NewRegistryInterceptor: %v", err)
	}

	tests := []struct {
		name    string
		req     *RegistryRequest
		wantDec PolicyDecision
	}{
		{
			name: "allow configured path",
			req: &RegistryRequest{
				KeyPath:   `HKCU\SOFTWARE\TestApp\Config`,
				Operation: DriverRegOpSetValue,
				ProcessId: 1234,
			},
			wantDec: DecisionAllow,
		},
		{
			name: "deny unconfigured path",
			req: &RegistryRequest{
				KeyPath:   `HKLM\SOFTWARE\Other`,
				Operation: DriverRegOpSetValue,
				ProcessId: 1234,
			},
			wantDec: DecisionDeny,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, cacheTTL := interceptor.HandleRequest(tt.req)
			if decision != tt.wantDec {
				t.Errorf("decision = %v, want %v", decision, tt.wantDec)
			}
			if cacheTTL == 0 {
				t.Error("cacheTTL should not be 0")
			}
		})
	}
}
