package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestEngine_CheckRegistry(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		RegistryRules: []RegistryRule{
			{
				Name:       "block-run-keys",
				Paths:      []string{`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run*`},
				Operations: []string{"set", "create", "delete"},
				Decision:   "deny",
				Priority:   100,
			},
			{
				Name:       "allow-app-settings",
				Paths:      []string{`HKCU\SOFTWARE\MyApp\*`},
				Operations: []string{"*"},
				Decision:   "allow",
				Priority:   50,
			},
		},
	}

	e, err := NewEngine(p, false)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		op       string
		wantDec  types.Decision
		wantRule string
	}{
		{
			name:     "block run key write",
			path:     `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Malware`,
			op:       "set",
			wantDec:  types.DecisionDeny,
			wantRule: "block-run-keys",
		},
		{
			name:     "allow app settings",
			path:     `HKCU\SOFTWARE\MyApp\Config`,
			op:       "set",
			wantDec:  types.DecisionAllow,
			wantRule: "allow-app-settings",
		},
		{
			name:     "default deny unmatched",
			path:     `HKLM\SOFTWARE\RandomPath`,
			op:       "set",
			wantDec:  types.DecisionDeny,
			wantRule: "default-deny-registry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dec := e.CheckRegistry(tt.path, tt.op)
			if dec.EffectiveDecision != tt.wantDec {
				t.Errorf("decision = %v, want %v", dec.EffectiveDecision, tt.wantDec)
			}
			if dec.Rule != tt.wantRule {
				t.Errorf("rule = %q, want %q", dec.Rule, tt.wantRule)
			}
		})
	}
}
