//go:build windows

package windows

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
)

func TestRegistryPolicyEvaluator_Evaluate(t *testing.T) {
	cfg := &config.RegistryPolicyConfig{
		DefaultAction:   "deny",
		LogAll:          true,
		DefaultCacheTTL: 30,
		Rules: []config.RegistryPolicyRule{
			{
				Name:       "allow-app",
				Paths:      []string{`HKCU\SOFTWARE\TestApp\*`},
				Operations: []string{"read", "write"},
				Action:     "allow",
				CacheTTL:   60,
			},
			{
				Name:       "block-run-keys",
				Paths:      []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`},
				Operations: []string{"write", "create", "delete"},
				Action:     "deny",
				Priority:   100,
				Notify:     true,
			},
		},
	}

	eval, err := NewRegistryPolicyEvaluator(cfg)
	if err != nil {
		t.Fatalf("NewRegistryPolicyEvaluator: %v", err)
	}

	tests := []struct {
		name         string
		path         string
		op           DriverRegistryOp
		wantDec      PolicyDecision
		wantCacheTTL uint32
	}{
		{
			name:         "allow app read",
			path:         `HKCU\SOFTWARE\TestApp\Config`,
			op:           DriverRegOpQueryValue,
			wantDec:      DecisionAllow,
			wantCacheTTL: 60000,
		},
		{
			name:         "block run key write",
			path:         `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware`,
			op:           DriverRegOpSetValue,
			wantDec:      DecisionDeny,
			wantCacheTTL: 30000,
		},
		{
			name:         "default deny",
			path:         `HKLM\SOFTWARE\RandomPath`,
			op:           DriverRegOpSetValue,
			wantDec:      DecisionDeny,
			wantCacheTTL: 30000,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &RegistryRequest{
				KeyPath:   tt.path,
				Operation: tt.op,
			}
			resp := eval.Evaluate(req)
			if resp.Decision != tt.wantDec {
				t.Errorf("decision = %v, want %v", resp.Decision, tt.wantDec)
			}
			if resp.CacheTTL != tt.wantCacheTTL {
				t.Errorf("cacheTTL = %d, want %d", resp.CacheTTL, tt.wantCacheTTL)
			}
		})
	}
}

func TestRegistryPolicyEvaluator_HighRiskPaths(t *testing.T) {
	cfg := &config.RegistryPolicyConfig{
		DefaultAction: "allow",
	}

	eval, err := NewRegistryPolicyEvaluator(cfg)
	if err != nil {
		t.Fatalf("NewRegistryPolicyEvaluator: %v", err)
	}

	req := &RegistryRequest{
		KeyPath:   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\TestApp`,
		Operation: DriverRegOpSetValue,
	}
	resp := eval.Evaluate(req)

	if resp.Decision != DecisionDeny {
		t.Errorf("high-risk path decision = %v, want deny", resp.Decision)
	}
}
