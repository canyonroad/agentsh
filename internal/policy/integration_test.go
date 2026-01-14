// internal/policy/integration_test.go
package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProjectRootAwarePolicies_Integration(t *testing.T) {
	// Create temp project structure
	base := t.TempDir()
	// Resolve symlinks for macOS /var -> /private/var
	if resolved, err := filepath.EvalSymlinks(base); err == nil {
		base = resolved
	}
	repoDir := filepath.Join(base, "myrepo")
	gitDir := filepath.Join(repoDir, ".git")
	srcDir := filepath.Join(repoDir, "src")

	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.MkdirAll(srcDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(repoDir, "go.mod"), []byte("module myrepo"), 0644))

	// Create a test policy using variables
	policy := &Policy{
		Version: 1,
		Name:    "test",
		FileRules: []FileRule{
			{
				Name:       "allow-project",
				Paths:      []string{"${PROJECT_ROOT}/**"},
				Operations: []string{"read", "write"},
				Decision:   "allow",
			},
			{
				Name:       "deny-all",
				Paths:      []string{"**"},
				Operations: []string{"*"},
				Decision:   "deny",
			},
		},
	}

	// Detect from src directory
	roots, err := DetectProjectRoots(srcDir, DefaultProjectMarkers())
	require.NoError(t, err)
	assert.Equal(t, repoDir, roots.ProjectRoot)
	assert.Equal(t, repoDir, roots.GitRoot)

	// Create engine with detected roots
	vars := map[string]string{
		"PROJECT_ROOT": roots.ProjectRoot,
		"GIT_ROOT":     roots.GitRoot,
	}

	engine, err := NewEngineWithVariables(policy, false, vars)
	require.NoError(t, err)

	// Test file access
	decision := engine.CheckFile(filepath.Join(repoDir, "src", "main.go"), "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	decision = engine.CheckFile(filepath.Join(repoDir, "go.mod"), "read")
	assert.Equal(t, "allow", string(decision.PolicyDecision))

	decision = engine.CheckFile("/etc/passwd", "read")
	assert.Equal(t, "deny", string(decision.PolicyDecision))

	decision = engine.CheckFile(filepath.Join(base, "other", "file.txt"), "read")
	assert.Equal(t, "deny", string(decision.PolicyDecision))
}
