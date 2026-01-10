# Project-Root Aware Policies Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Enable policies to use `${PROJECT_ROOT}`, `${GIT_ROOT}`, and environment variables with bash-like fallback syntax.

**Architecture:** Server-side project detection walks up from workspace to find markers (.git, go.mod, etc.). Variables are expanded in policy files before glob compilation. Detection is configurable and can be disabled per-session.

**Tech Stack:** Go, gobwas/glob (existing), filepath/os for detection

---

## Task 1: Variable Expansion Parser

**Files:**
- Create: `internal/policy/vars.go`
- Create: `internal/policy/vars_test.go`

**Step 1: Write the failing test for simple variable expansion**

```go
// internal/policy/vars_test.go
package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExpandVariables_Simple(t *testing.T) {
	vars := map[string]string{
		"PROJECT_ROOT": "/home/user/myproject",
		"HOME":         "/home/user",
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "simple variable",
			input: "${PROJECT_ROOT}/src",
			want:  "/home/user/myproject/src",
		},
		{
			name:  "multiple variables",
			input: "${HOME}/.config/${PROJECT_ROOT}",
			want:  "/home/user/.config//home/user/myproject",
		},
		{
			name:  "no variables",
			input: "/tmp/foo/bar",
			want:  "/tmp/foo/bar",
		},
		{
			name:  "variable at end",
			input: "/prefix/${PROJECT_ROOT}",
			want:  "/prefix//home/user/myproject",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandVariables(tt.input, vars)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -run TestExpandVariables_Simple -v`
Expected: FAIL with "undefined: ExpandVariables"

**Step 3: Write minimal implementation**

```go
// internal/policy/vars.go
package policy

import (
	"fmt"
	"os"
	"regexp"
	"strings"
)

// varPattern matches ${VAR} or ${VAR:-fallback}
var varPattern = regexp.MustCompile(`\$\{([a-zA-Z_][a-zA-Z0-9_]*)(?::-([^}]*))?\}`)

// ExpandVariables expands ${VAR} and ${VAR:-fallback} syntax in a string.
// Variables are looked up in vars map first, then environment.
// If a variable is undefined and has no fallback, returns an error.
func ExpandVariables(s string, vars map[string]string) (string, error) {
	var expandErr error

	result := varPattern.ReplaceAllStringFunc(s, func(match string) string {
		if expandErr != nil {
			return match
		}

		parts := varPattern.FindStringSubmatch(match)
		if len(parts) < 2 {
			return match
		}

		varName := parts[1]
		fallback := ""
		hasFallback := len(parts) > 2 && strings.Contains(match, ":-")
		if hasFallback {
			fallback = parts[2]
		}

		// Look up in provided vars first
		if val, ok := vars[varName]; ok {
			return val
		}

		// Fall back to environment
		if val := os.Getenv(varName); val != "" {
			return val
		}

		// Use fallback if provided
		if hasFallback {
			return fallback
		}

		// No value and no fallback - error
		expandErr = fmt.Errorf("undefined variable: %s", varName)
		return match
	})

	if expandErr != nil {
		return "", expandErr
	}
	return result, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/... -run TestExpandVariables_Simple -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/vars.go internal/policy/vars_test.go
git commit -m "feat(policy): add variable expansion with simple substitution"
```

---

## Task 2: Fallback Syntax Support

**Files:**
- Modify: `internal/policy/vars_test.go`

**Step 1: Write the failing test for fallback syntax**

```go
// Add to internal/policy/vars_test.go

func TestExpandVariables_Fallback(t *testing.T) {
	vars := map[string]string{
		"PROJECT_ROOT": "/home/user/myproject",
	}

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "fallback not used when var exists",
			input: "${PROJECT_ROOT:-/fallback}",
			want:  "/home/user/myproject",
		},
		{
			name:  "fallback used when var missing",
			input: "${UNDEFINED:-/fallback}",
			want:  "/fallback",
		},
		{
			name:  "empty fallback",
			input: "${UNDEFINED:-}",
			want:  "",
		},
		{
			name:  "fallback with path",
			input: "${GIT_ROOT:-${PROJECT_ROOT}}/config",
			want:  "${PROJECT_ROOT}/config", // nested not expanded
		},
		{
			name:    "undefined without fallback errors",
			input:   "${UNDEFINED}",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandVariables(tt.input, vars)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "undefined variable")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
```

**Step 2: Run test to verify it passes (implementation already handles this)**

Run: `go test ./internal/policy/... -run TestExpandVariables_Fallback -v`
Expected: PASS (the implementation from Task 1 already handles fallbacks)

**Step 3: Commit**

```bash
git add internal/policy/vars_test.go
git commit -m "test(policy): add variable fallback syntax tests"
```

---

## Task 3: Project Root Detection

**Files:**
- Create: `internal/policy/detect.go`
- Create: `internal/policy/detect_test.go`

**Step 1: Write the failing test for project detection**

```go
// internal/policy/detect_test.go
package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDetectProjectRoots(t *testing.T) {
	// Create temp directory structure
	base := t.TempDir()

	// /base/repo/.git
	// /base/repo/services/api/go.mod
	// /base/repo/services/api/cmd/  <- workspace

	repoDir := filepath.Join(base, "repo")
	gitDir := filepath.Join(repoDir, ".git")
	apiDir := filepath.Join(repoDir, "services", "api")
	cmdDir := filepath.Join(apiDir, "cmd")

	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.MkdirAll(cmdDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(apiDir, "go.mod"), []byte("module api"), 0644))

	markers := DefaultProjectMarkers()
	roots, err := DetectProjectRoots(cmdDir, markers)
	require.NoError(t, err)

	assert.Equal(t, apiDir, roots.ProjectRoot)
	assert.Equal(t, repoDir, roots.GitRoot)
}

func TestDetectProjectRoots_NoMarkers(t *testing.T) {
	// Create temp directory with no markers
	base := t.TempDir()
	workspace := filepath.Join(base, "some", "dir")
	require.NoError(t, os.MkdirAll(workspace, 0755))

	markers := DefaultProjectMarkers()
	roots, err := DetectProjectRoots(workspace, markers)
	require.NoError(t, err)

	// Should fall back to workspace
	assert.Equal(t, workspace, roots.ProjectRoot)
	assert.Equal(t, "", roots.GitRoot)
}

func TestDetectProjectRoots_GitOnly(t *testing.T) {
	base := t.TempDir()
	repoDir := filepath.Join(base, "repo")
	gitDir := filepath.Join(repoDir, ".git")
	subDir := filepath.Join(repoDir, "src")

	require.NoError(t, os.MkdirAll(gitDir, 0755))
	require.NoError(t, os.MkdirAll(subDir, 0755))

	markers := DefaultProjectMarkers()
	roots, err := DetectProjectRoots(subDir, markers)
	require.NoError(t, err)

	// Both should be the git root
	assert.Equal(t, repoDir, roots.ProjectRoot)
	assert.Equal(t, repoDir, roots.GitRoot)
}
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -run TestDetectProjectRoots -v`
Expected: FAIL with "undefined: DetectProjectRoots"

**Step 3: Write minimal implementation**

```go
// internal/policy/detect.go
package policy

import (
	"os"
	"path/filepath"
)

// ProjectRoots holds detected project root paths.
type ProjectRoots struct {
	ProjectRoot string // Nearest project marker or workspace
	GitRoot     string // Nearest .git, or empty if not in git repo
}

// DefaultProjectMarkers returns the default set of project markers to detect.
func DefaultProjectMarkers() []string {
	return []string{
		".git",
		"go.mod",
		"package.json",
		"Cargo.toml",
		"pyproject.toml",
	}
}

// DetectProjectRoots walks up from workspace to find project markers.
// Returns ProjectRoot (nearest language marker or workspace) and GitRoot (nearest .git).
func DetectProjectRoots(workspace string, markers []string) (*ProjectRoots, error) {
	// Resolve to absolute path
	absWorkspace, err := filepath.Abs(workspace)
	if err != nil {
		return nil, err
	}

	// Resolve symlinks
	absWorkspace, err = filepath.EvalSymlinks(absWorkspace)
	if err != nil {
		return nil, err
	}

	roots := &ProjectRoots{
		ProjectRoot: absWorkspace, // Default to workspace
	}

	// Walk up looking for markers
	dir := absWorkspace
	foundLanguageMarker := false

	for {
		for _, marker := range markers {
			markerPath := filepath.Join(dir, marker)
			if _, err := os.Stat(markerPath); err == nil {
				if marker == ".git" {
					if roots.GitRoot == "" {
						roots.GitRoot = dir
					}
					// If no language marker found yet, git root is also project root
					if !foundLanguageMarker {
						roots.ProjectRoot = dir
					}
				} else {
					// Language marker - this is the project root
					if !foundLanguageMarker {
						roots.ProjectRoot = dir
						foundLanguageMarker = true
					}
				}
			}
		}

		// Move to parent
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root
			break
		}
		dir = parent
	}

	return roots, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/... -run TestDetectProjectRoots -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/detect.go internal/policy/detect_test.go
git commit -m "feat(policy): add project root detection"
```

---

## Task 4: Config Changes

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go` (if exists)

**Step 1: Add config fields**

```go
// In internal/config/config.go, modify PoliciesConfig struct:

// PoliciesConfig configures policy loading.
type PoliciesConfig struct {
	Dir               string   `yaml:"dir"`
	Default           string   `yaml:"default"`
	ReloadInterval    string   `yaml:"reload_interval"`
	DetectProjectRoot *bool    `yaml:"detect_project_root"` // nil means true (default enabled)
	ProjectMarkers    []string `yaml:"project_markers"`     // Override default markers
}

// Add helper method
func (c *PoliciesConfig) ShouldDetectProjectRoot() bool {
	if c.DetectProjectRoot == nil {
		return true // Default enabled
	}
	return *c.DetectProjectRoot
}

func (c *PoliciesConfig) GetProjectMarkers() []string {
	if len(c.ProjectMarkers) > 0 {
		return c.ProjectMarkers
	}
	return nil // Use defaults from policy package
}
```

**Step 2: Run existing config tests**

Run: `go test ./internal/config/... -v`
Expected: PASS (no breaking changes)

**Step 3: Commit**

```bash
git add internal/config/config.go
git commit -m "feat(config): add project root detection settings"
```

---

## Task 5: Session Fields

**Files:**
- Modify: `internal/session/manager.go`
- Modify: `pkg/types/sessions.go`

**Step 1: Add fields to Session struct in manager.go**

```go
// In internal/session/manager.go, add to Session struct:

type Session struct {
	// ... existing fields ...

	// Project detection results
	ProjectRoot string `json:"project_root,omitempty"`
	GitRoot     string `json:"git_root,omitempty"`
}
```

**Step 2: Add field to CreateSessionRequest in types**

```go
// In pkg/types/sessions.go, add to CreateSessionRequest:

type CreateSessionRequest struct {
	ID                string  `json:"id,omitempty"`
	Workspace         string  `json:"workspace,omitempty"`
	Policy            string  `json:"policy,omitempty"`
	Profile           string  `json:"profile,omitempty"`
	DetectProjectRoot *bool   `json:"detect_project_root,omitempty"` // Override server default
	ProjectRoot       string  `json:"project_root,omitempty"`        // Explicit override
}
```

**Step 3: Run session tests**

Run: `go test ./internal/session/... -v`
Expected: PASS

**Step 4: Commit**

```bash
git add internal/session/manager.go pkg/types/sessions.go
git commit -m "feat(session): add project root fields"
```

---

## Task 6: Policy Expansion Integration

**Files:**
- Modify: `internal/policy/engine.go`
- Create: `internal/policy/engine_vars_test.go`

**Step 1: Write test for policy expansion**

```go
// internal/policy/engine_vars_test.go
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
	decision, _, _ := engine.CheckFile("/home/user/myproject/src/main.go", "read", 0, 0)
	assert.Equal(t, "allow", decision)

	// Should allow files under home config
	decision, _, _ = engine.CheckFile("/home/user/.config/app/settings.json", "read", 0, 0)
	assert.Equal(t, "allow", decision)

	// Should deny files outside
	decision, _, _ = engine.CheckFile("/etc/passwd", "read", 0, 0)
	assert.Equal(t, "deny", decision)
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
```

**Step 2: Run test to verify it fails**

Run: `go test ./internal/policy/... -run TestNewEngineWithVariables -v`
Expected: FAIL with "undefined: NewEngineWithVariables"

**Step 3: Implement NewEngineWithVariables**

```go
// Add to internal/policy/engine.go

// NewEngineWithVariables creates an engine with variable expansion.
// Variables in policy paths are expanded before glob compilation.
func NewEngineWithVariables(p *Policy, enforceApprovals bool, vars map[string]string) (*Engine, error) {
	// Deep copy and expand the policy
	expanded, err := expandPolicy(p, vars)
	if err != nil {
		return nil, fmt.Errorf("expand policy variables: %w", err)
	}
	return NewEngine(expanded, enforceApprovals)
}

// expandPolicy creates a copy of the policy with all variables expanded.
func expandPolicy(p *Policy, vars map[string]string) (*Policy, error) {
	// Create a shallow copy
	expanded := *p

	// Expand file rules
	expanded.FileRules = make([]FileRule, len(p.FileRules))
	for i, rule := range p.FileRules {
		expandedRule := rule
		expandedRule.Paths = make([]string, len(rule.Paths))
		for j, path := range rule.Paths {
			expandedPath, err := ExpandVariables(path, vars)
			if err != nil {
				return nil, fmt.Errorf("rule %q path %q: %w", rule.Name, path, err)
			}
			expandedRule.Paths[j] = expandedPath
		}
		expanded.FileRules[i] = expandedRule
	}

	// Expand network rules (domains might use variables)
	expanded.NetworkRules = make([]NetworkRule, len(p.NetworkRules))
	for i, rule := range p.NetworkRules {
		expandedRule := rule
		expandedRule.Domains = make([]string, len(rule.Domains))
		for j, domain := range rule.Domains {
			expandedDomain, err := ExpandVariables(domain, vars)
			if err != nil {
				return nil, fmt.Errorf("network rule %q domain %q: %w", rule.Name, domain, err)
			}
			expandedRule.Domains[j] = expandedDomain
		}
		expanded.NetworkRules[i] = expandedRule
	}

	// Copy other rules as-is (command rules unlikely to need variables)
	expanded.CommandRules = append([]CommandRule(nil), p.CommandRules...)
	expanded.RegistryRules = append([]RegistryRule(nil), p.RegistryRules...)

	return &expanded, nil
}
```

**Step 4: Run test to verify it passes**

Run: `go test ./internal/policy/... -run TestNewEngineWithVariables -v`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_vars_test.go
git commit -m "feat(policy): add NewEngineWithVariables for variable expansion"
```

---

## Task 7: API Integration

**Files:**
- Modify: `internal/api/core.go`

**Step 1: Update createSessionCore to detect and expand**

Find the `createSessionCore` function and update the policy loading section:

```go
// In createSessionCore, after determining policyName, replace policy loading with:

// Determine if we should detect project root
shouldDetect := a.cfg.Policies.ShouldDetectProjectRoot()
if req.DetectProjectRoot != nil {
	shouldDetect = *req.DetectProjectRoot
}

// Build variables map for policy expansion
policyVars := make(map[string]string)

if req.ProjectRoot != "" {
	// Explicit project root provided
	policyVars["PROJECT_ROOT"] = req.ProjectRoot
	policyVars["GIT_ROOT"] = req.ProjectRoot // Assume same if explicit
} else if shouldDetect && req.Workspace != "" {
	// Detect project roots
	markers := a.cfg.Policies.GetProjectMarkers()
	if markers == nil {
		markers = policy.DefaultProjectMarkers()
	}
	roots, err := policy.DetectProjectRoots(req.Workspace, markers)
	if err != nil {
		// Log warning but continue with workspace as fallback
		// (detection failure shouldn't block session creation)
		policyVars["PROJECT_ROOT"] = req.Workspace
	} else {
		policyVars["PROJECT_ROOT"] = roots.ProjectRoot
		if roots.GitRoot != "" {
			policyVars["GIT_ROOT"] = roots.GitRoot
		}
	}
} else {
	// No detection, use workspace as project root
	policyVars["PROJECT_ROOT"] = req.Workspace
}

// Load and expand policy
pol, err := policy.LoadFromFile(policy.ResolvePolicyPath(a.cfg.Policies.Dir, policyName))
if err != nil {
	return nil, http.StatusInternalServerError, fmt.Errorf("load policy: %w", err)
}

engine, err := policy.NewEngineWithVariables(pol, enforceApprovals, policyVars)
if err != nil {
	return nil, http.StatusBadRequest, fmt.Errorf("compile policy: %w", err)
}

// Store roots in session
sess.ProjectRoot = policyVars["PROJECT_ROOT"]
sess.GitRoot = policyVars["GIT_ROOT"]
```

**Step 2: Run API tests**

Run: `go test ./internal/api/... -v -run Create`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/api/core.go
git commit -m "feat(api): integrate project detection in session creation"
```

---

## Task 8: CLI Flags

**Files:**
- Modify: `internal/cli/exec.go`

**Step 1: Add CLI flags**

```go
// In internal/cli/exec.go, add flags to the exec command:

var (
	noDetectRoot bool
	projectRoot  string
)

// In the command setup:
cmd.Flags().BoolVar(&noDetectRoot, "no-detect-root", false, "Disable project root detection")
cmd.Flags().StringVar(&projectRoot, "project-root", "", "Explicit project root (skips detection)")

// When building CreateSessionRequest, add:
if noDetectRoot {
	falseVal := false
	req.DetectProjectRoot = &falseVal
}
if projectRoot != "" {
	req.ProjectRoot = projectRoot
}
```

**Step 2: Run CLI tests**

Run: `go test ./internal/cli/... -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/cli/exec.go
git commit -m "feat(cli): add --no-detect-root and --project-root flags"
```

---

## Task 9: Update dev-safe.yaml Policy

**Files:**
- Modify: `configs/policies/dev-safe.yaml`

**Step 1: Update policy to use variables**

Replace hardcoded `/workspace` paths with `${PROJECT_ROOT}`:

```yaml
# Update file_rules section to use variables
file_rules:
  - name: allow-project-read
    description: Allow reading any file in project
    paths:
      - "${PROJECT_ROOT}"
      - "${PROJECT_ROOT}/**"
    operations:
      - read
      - open
      - stat
      - list
      - readlink
    decision: allow

  - name: allow-project-write
    description: Allow writing/creating files in project
    paths:
      - "${PROJECT_ROOT}/**"
    operations:
      - write
      - create
      - mkdir
      - chmod
      - rename
    decision: allow

  - name: approve-project-delete
    description: Require approval for deleting files in project
    paths:
      - "${PROJECT_ROOT}/**"
    operations:
      - delete
      - rmdir
    decision: approve
    message: "Delete {{.Path}}?"
    timeout: 5m

  # Git root for monorepo read access
  - name: allow-git-root-read
    description: Read-only access to git repository root (for monorepos)
    paths:
      - "${GIT_ROOT:-}/**"
    operations:
      - read
      - open
      - stat
      - list
      - readlink
    decision: allow

  # ... keep rest of rules but update ${HOME} references
```

**Step 2: Verify policy loads**

Run: `go test ./internal/policy/... -v`
Expected: PASS

**Step 3: Commit**

```bash
git add configs/policies/dev-safe.yaml
git commit -m "feat(policy): update dev-safe.yaml to use project root variables"
```

---

## Task 10: Integration Test

**Files:**
- Create: `internal/policy/integration_test.go`

**Step 1: Write end-to-end test**

```go
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
	decision, _, _ := engine.CheckFile(filepath.Join(repoDir, "src", "main.go"), "read", 0, 0)
	assert.Equal(t, "allow", decision)

	decision, _, _ = engine.CheckFile(filepath.Join(repoDir, "go.mod"), "read", 0, 0)
	assert.Equal(t, "allow", decision)

	decision, _, _ = engine.CheckFile("/etc/passwd", "read", 0, 0)
	assert.Equal(t, "deny", decision)

	decision, _, _ = engine.CheckFile(filepath.Join(base, "other", "file.txt"), "read", 0, 0)
	assert.Equal(t, "deny", decision)
}
```

**Step 2: Run integration test**

Run: `go test ./internal/policy/... -run Integration -v`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/policy/integration_test.go
git commit -m "test(policy): add integration test for project-root aware policies"
```

---

## Task 11: Documentation

**Files:**
- Update: `docs/operations/policies.md` (or create if not exists)

**Step 1: Add documentation section**

Add a section explaining variable usage in policies:

```markdown
## Policy Variables

Policies support variable substitution using `${VAR}` syntax.

### Built-in Variables

| Variable | Description |
|----------|-------------|
| `${PROJECT_ROOT}` | Detected project root (nearest go.mod, package.json, etc.) |
| `${GIT_ROOT}` | Nearest .git directory |
| `${HOME}` | User's home directory (from environment) |
| `${TMPDIR}` | System temp directory (from environment) |

### Fallback Syntax

Use `${VAR:-fallback}` to provide a default value:

```yaml
paths:
  - "${GIT_ROOT:-${PROJECT_ROOT}}/**"  # Use git root, fall back to project root
  - "${TMPDIR:-/tmp}/**"               # Use TMPDIR, fall back to /tmp
```

### Disabling Detection

Server config:
```yaml
policies:
  detect_project_root: false
```

Per-session:
```bash
agentsh exec --no-detect-root SESSION -- cmd
```

Explicit root:
```bash
agentsh exec --project-root /path/to/project SESSION -- cmd
```
```

**Step 2: Commit**

```bash
git add docs/
git commit -m "docs: add policy variables documentation"
```

---

## Final Steps

**Step 1: Run full test suite**

```bash
go test ./... -v
```

**Step 2: Build and verify**

```bash
go build ./...
```

**Step 3: Final commit and push**

```bash
git push -u origin feature/project-root-aware-policies
```
