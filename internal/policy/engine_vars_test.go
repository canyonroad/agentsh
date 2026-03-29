package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEngineWithVariables(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		FileRules: []FileRule{
			{
				Name:       "allow-project",
				Paths:      []string{"${PROJECT_ROOT}/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
			{
				Name:       "allow-home",
				Paths:      []string{"${HOME}/.config/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
		},
	}

	vars := map[string]string{
		"PROJECT_ROOT": "/home/user/myproject",
		"HOME":         "/home/user",
	}

	engine, err := NewEngineWithVariables(p, false, true, vars)
	require.NoError(t, err)

	// Should allow files under project root
	decision := engine.CheckFile("/home/user/myproject/src/main.go", "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should allow files under home config
	decision = engine.CheckFile("/home/user/.config/app/settings.json", "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should allow reads outside (no deny rule, engine defaults reads to allow)
	decision = engine.CheckFile("/etc/passwd", "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should deny writes outside (engine defaults writes to deny)
	decision = engine.CheckFile("/etc/passwd", "write")
	assert.Equal(t, "deny", string(decision.PolicyDecision))
}

func TestNewEngineWithVariables_UndefinedError(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		FileRules: []FileRule{
			{
				Name:       "allow-project",
				Paths:      []string{"${UNDEFINED}/**"},
				Operations: []string{"read"},
				Decision:   "allow",
			},
		},
	}

	vars := map[string]string{}

	_, err := NewEngineWithVariables(p, false, true, vars)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefined variable")
}

// TestDenyPrecedenceWhenHomeEqualsProjectRoot verifies that deny rules for
// ${HOME} paths take priority over workspace allow rules when HOME and
// PROJECT_ROOT resolve to the same directory (common in containers/devboxes).
func TestDenyPrecedenceWhenHomeEqualsProjectRoot(t *testing.T) {
	// Simulate the default policy rule ordering: denies for ${HOME} first,
	// then workspace allows for ${PROJECT_ROOT}.
	p := &Policy{
		Version: 1,
		Name:    "test-deny-precedence",
		FileRules: []FileRule{
			// Deny sensitive HOME paths (must come first)
			{
				Name:       "deny-shell-rc",
				Paths:      []string{"${HOME}/.bashrc", "${HOME}/.profile"},
				Operations: []string{"write", "create", "rename"},
				Decision:   "deny",
			},
			{
				Name:       "deny-ssh-keys",
				Paths:      []string{"${HOME}/.ssh/**"},
				Operations: []string{"*"},
				Decision:   "deny",
			},
			{
				Name:       "deny-git-credentials",
				Paths:      []string{"${HOME}/.gitconfig"},
				Operations: []string{"*"},
				Decision:   "deny",
			},
			// Workspace allow (comes after denies)
			{
				Name:       "allow-workspace-write",
				Paths:      []string{"${PROJECT_ROOT}/**"},
				Operations: []string{"write", "create", "rename"},
				Decision:   "allow",
			},
		},
	}

	// HOME == PROJECT_ROOT — the case that was broken before reordering
	vars := map[string]string{
		"PROJECT_ROOT": "/home/user",
		"HOME":         "/home/user",
	}

	engine, err := NewEngineWithVariables(p, false, true, vars)
	require.NoError(t, err)

	tests := []struct {
		path      string
		operation string
		wantDeny  bool
		desc      string
	}{
		{"/home/user/.bashrc", "write", true, "shell rc write denied"},
		{"/home/user/.bashrc", "rename", true, "shell rc rename denied"},
		{"/home/user/.profile", "create", true, "shell profile create denied"},
		{"/home/user/.ssh/id_rsa", "read", true, "ssh key read denied"},
		{"/home/user/.gitconfig", "write", true, "gitconfig write denied"},
		{"/home/user/project/main.go", "write", false, "workspace write allowed"},
		{"/home/user/project/main.go", "create", false, "workspace create allowed"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			dec := engine.CheckFile(tt.path, tt.operation)
			if tt.wantDeny {
				assert.Equal(t, "deny", string(dec.PolicyDecision), "expected deny for %s %s", tt.operation, tt.path)
			} else {
				assert.Equal(t, "allow", string(dec.PolicyDecision), "expected allow for %s %s", tt.operation, tt.path)
			}
		})
	}
}

func TestNewEngineWithVariables_NetworkRulesDomainExpansion(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		NetworkRules: []NetworkRule{
			{
				Name:     "allow-company-domain",
				Domains:  []string{"*.${COMPANY_DOMAIN}", "${INTERNAL_HOST}"},
				Ports:    []int{443},
				Decision: "allow",
			},
		},
	}

	vars := map[string]string{
		"COMPANY_DOMAIN": "example.com",
		"INTERNAL_HOST":  "internal.corp.net",
	}

	engine, err := NewEngineWithVariables(p, false, true, vars)
	require.NoError(t, err)

	// Should allow subdomains of example.com
	decision := engine.CheckNetwork("api.example.com", 443)
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should allow internal host
	decision = engine.CheckNetwork("internal.corp.net", 443)
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should deny other domains
	decision = engine.CheckNetwork("other.com", 443)
	assert.Equal(t, "deny", string(decision.PolicyDecision))
}
