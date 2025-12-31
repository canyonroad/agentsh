package session

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestPolicyRouter_CheckFile(t *testing.T) {
	// Create a simple allow policy
	allowPolicy := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{
				Name:       "allow",
				Paths:      []string{"/**"},
				Operations: []string{"read", "write"},
				Decision:   "allow",
			},
		},
	}
	allowEngine, err := policy.NewEngine(allowPolicy, false)
	if err != nil {
		t.Fatalf("failed to create allow engine: %v", err)
	}

	// Create a deny-write policy
	denyWritePolicy := &policy.Policy{
		Version: 1,
		Name:    "deny-write",
		FileRules: []policy.FileRule{
			{
				Name:       "allow-read",
				Paths:      []string{"/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
			{
				Name:       "deny-write",
				Paths:      []string{"/**"},
				Operations: []string{"write"},
				Decision:   "deny",
			},
		},
	}
	denyWriteEngine, err := policy.NewEngine(denyWritePolicy, false)
	if err != nil {
		t.Fatalf("failed to create deny-write engine: %v", err)
	}

	mounts := []ResolvedMount{
		{Path: "/workspace", PolicyEngine: allowEngine},
		{Path: "/config", PolicyEngine: denyWriteEngine},
	}

	router := NewPolicyRouter(nil, mounts)

	tests := []struct {
		path string
		op   string
		want types.Decision
	}{
		{"/workspace/file.txt", "read", types.DecisionAllow},
		{"/workspace/file.txt", "write", types.DecisionAllow},
		{"/config/app.json", "read", types.DecisionAllow},
		{"/config/app.json", "write", types.DecisionDeny},
		{"/unmounted/file.txt", "read", types.DecisionDeny}, // unmounted = deny
	}

	for _, tt := range tests {
		dec := router.CheckFile(tt.path, tt.op)
		if dec.EffectiveDecision != tt.want {
			t.Errorf("CheckFile(%q, %q) = %v, want %v", tt.path, tt.op, dec.EffectiveDecision, tt.want)
		}
	}
}

func TestPolicyRouter_BasePolicyDenies(t *testing.T) {
	// Mount allows everything
	allowPolicy := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow", Paths: []string{"/**"}, Operations: []string{"read", "write"}, Decision: "allow"},
		},
	}
	allowEngine, err := policy.NewEngine(allowPolicy, false)
	if err != nil {
		t.Fatalf("failed to create allow engine: %v", err)
	}

	// Base policy denies write
	denyWritePolicy := &policy.Policy{
		Version: 1,
		Name:    "deny-write",
		FileRules: []policy.FileRule{
			{Name: "allow-read", Paths: []string{"/**"}, Operations: []string{"read"}, Decision: "allow"},
			{Name: "deny-write", Paths: []string{"/**"}, Operations: []string{"write"}, Decision: "deny"},
		},
	}
	denyWriteEngine, err := policy.NewEngine(denyWritePolicy, false)
	if err != nil {
		t.Fatalf("failed to create deny-write engine: %v", err)
	}

	mounts := []ResolvedMount{
		{Path: "/workspace", PolicyEngine: allowEngine},
	}

	router := NewPolicyRouter(denyWriteEngine, mounts)

	// Read should be allowed (both allow)
	dec := router.CheckFile("/workspace/file.txt", "read")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("read should be allowed, got %v", dec.EffectiveDecision)
	}

	// Write should be denied (mount allows, but base denies)
	dec = router.CheckFile("/workspace/file.txt", "write")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("write should be denied by base policy, got %v", dec.EffectiveDecision)
	}
}

func TestPolicyRouter_CheckCommand(t *testing.T) {
	// No base policy - should allow
	router := NewPolicyRouter(nil, nil)
	dec := router.CheckCommand("ls", []string{"-la"})
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("nil base policy should allow command, got %v", dec.EffectiveDecision)
	}
}

func TestPolicyRouter_CheckNetwork(t *testing.T) {
	// No base policy - should allow
	router := NewPolicyRouter(nil, nil)
	dec := router.CheckNetwork("example.com", 443)
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Errorf("nil base policy should allow network, got %v", dec.EffectiveDecision)
	}
}
