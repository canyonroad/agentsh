package platform

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestNewPolicyAdapter_Nil(t *testing.T) {
	adapter := NewPolicyAdapter(nil)
	if adapter != nil {
		t.Error("NewPolicyAdapter(nil) should return nil")
	}
}

func TestPolicyAdapter_NilEngine(t *testing.T) {
	var adapter *PolicyAdapter

	// All methods should return DecisionAllow on nil adapter
	if got := adapter.CheckFile("/test", FileOpRead); got != DecisionAllow {
		t.Errorf("CheckFile on nil adapter = %v, want %v", got, DecisionAllow)
	}
	if got := adapter.CheckNetwork("example.com", 443, "tcp"); got != DecisionAllow {
		t.Errorf("CheckNetwork on nil adapter = %v, want %v", got, DecisionAllow)
	}
	if got := adapter.CheckEnv("HOME", EnvOpRead); got != DecisionAllow {
		t.Errorf("CheckEnv on nil adapter = %v, want %v", got, DecisionAllow)
	}
	if got := adapter.CheckCommand("ls", nil); got != DecisionAllow {
		t.Errorf("CheckCommand on nil adapter = %v, want %v", got, DecisionAllow)
	}
	if got := adapter.Engine(); got != nil {
		t.Error("Engine() on nil adapter should return nil")
	}
}

func TestPolicyAdapter_WithEngine(t *testing.T) {
	// Create a simple allow-all policy
	pol := &policy.Policy{
		Version: 1,
		Name:    "test-policy",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-all",
				Paths:      []string{"/**"},
				Operations: []string{"*"},
				Decision:   "allow",
			},
		},
		CommandRules: []policy.CommandRule{
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
			},
		},
		NetworkRules: []policy.NetworkRule{
			{
				Name:     "allow-all",
				Domains:  []string{"**"},
				Decision: "allow",
			},
		},
	}

	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	adapter := NewPolicyAdapter(engine)
	if adapter == nil {
		t.Fatal("NewPolicyAdapter returned nil for valid engine")
	}

	// Check that Engine() returns the original engine
	if adapter.Engine() != engine {
		t.Error("Engine() should return the wrapped engine")
	}

	// Check that decisions work (allow-all policy)
	if got := adapter.CheckFile("/workspace/test.txt", FileOpRead); got != DecisionAllow {
		t.Errorf("CheckFile = %v, want %v", got, DecisionAllow)
	}
	if got := adapter.CheckCommand("ls", []string{"-la"}); got != DecisionAllow {
		t.Errorf("CheckCommand = %v, want %v", got, DecisionAllow)
	}
	if got := adapter.CheckNetwork("example.com", 443, "tcp"); got != DecisionAllow {
		t.Errorf("CheckNetwork = %v, want %v", got, DecisionAllow)
	}
}

func TestPolicyAdapter_DenyPolicy(t *testing.T) {
	// Create a deny-all policy
	pol := &policy.Policy{
		Version: 1,
		Name:    "deny-policy",
		FileRules: []policy.FileRule{
			{
				Name:       "deny-all",
				Paths:      []string{"/**"},
				Operations: []string{"*"},
				Decision:   "deny",
			},
		},
	}

	engine, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatalf("Failed to create policy engine: %v", err)
	}

	adapter := NewPolicyAdapter(engine)

	// Check that deny decision works
	if got := adapter.CheckFile("/test.txt", FileOpWrite); got != DecisionDeny {
		t.Errorf("CheckFile with deny policy = %v, want %v", got, DecisionDeny)
	}
}

// Compile-time check
var _ PolicyEngine = (*PolicyAdapter)(nil)
