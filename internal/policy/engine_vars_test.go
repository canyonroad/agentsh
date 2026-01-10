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

	engine, err := NewEngineWithVariables(p, false, vars)
	require.NoError(t, err)

	// Should allow files under project root
	decision := engine.CheckFile("/home/user/myproject/src/main.go", "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should allow files under home config
	decision = engine.CheckFile("/home/user/.config/app/settings.json", "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	// Should deny files outside
	decision = engine.CheckFile("/etc/passwd", "read")
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

	_, err := NewEngineWithVariables(p, false, vars)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "undefined variable")
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

	engine, err := NewEngineWithVariables(p, false, vars)
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
