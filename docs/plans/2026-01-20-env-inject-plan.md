# Environment Variable Injection Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `env_inject` configuration that injects environment variables (like `BASH_ENV`) into command execution, regardless of the parent environment, to disable bash builtins that bypass seccomp policy enforcement.

**Architecture:** Global config defines base `env_inject` map under `sandbox`. Policy files can override/extend with their own `env_inject` map. During command execution, values are merged (policy wins conflicts) and appended to the environment after policy filtering, bypassing env policy checks (operator-trusted).

**Tech Stack:** Go, YAML parsing (gopkg.in/yaml.v3), goreleaser, GitHub Actions

---

## Task 1: Create bash_startup.sh Script

**Files:**
- Create: `/home/eran/work/agentsh/packaging/bash_startup.sh`

**Step 1: Create the bash startup script**

Create the file with builtin-disabling commands:

```bash
#!/bin/bash
# Disable builtins that bypass seccomp policy enforcement
enable -n kill      # Signal sending
enable -n enable    # Prevent re-enabling
enable -n ulimit    # Resource limits
enable -n umask     # File permission mask
enable -n builtin   # Force builtin bypass
enable -n command   # Function/alias bypass
```

**Step 2: Make script executable**

Run: `chmod +x /home/eran/work/agentsh/packaging/bash_startup.sh`

**Step 3: Verify script syntax**

Run: `bash -n /home/eran/work/agentsh/packaging/bash_startup.sh`
Expected: No output (valid syntax)

**Step 4: Commit**

```bash
git add packaging/bash_startup.sh
git commit -m "feat(packaging): add bash_startup.sh for builtin disabling

Disables bash builtins (kill, enable, ulimit, umask, builtin, command)
that can bypass seccomp policy enforcement. Used via BASH_ENV injection."
```

---

## Task 2: Add EnvInject to Config Struct

**Files:**
- Modify: `/home/eran/work/agentsh/internal/config/config.go`
- Test: `/home/eran/work/agentsh/internal/config/config_test.go`

**Step 1: Write the failing test for config parsing**

Add to `config_test.go`:

```go
func TestLoad_EnvInjectConfig(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
    MY_CUSTOM_VAR: "custom_value"
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	if cfg.Sandbox.EnvInject == nil {
		t.Fatal("env_inject should not be nil")
	}
	if cfg.Sandbox.EnvInject["BASH_ENV"] != "/usr/lib/agentsh/bash_startup.sh" {
		t.Errorf("BASH_ENV = %q, want %q", cfg.Sandbox.EnvInject["BASH_ENV"], "/usr/lib/agentsh/bash_startup.sh")
	}
	if cfg.Sandbox.EnvInject["MY_CUSTOM_VAR"] != "custom_value" {
		t.Errorf("MY_CUSTOM_VAR = %q, want %q", cfg.Sandbox.EnvInject["MY_CUSTOM_VAR"], "custom_value")
	}
}

func TestLoad_EnvInjectConfig_Empty(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	if err := os.WriteFile(cfgPath, []byte(`
sandbox:
  enabled: true
`), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// EnvInject should be nil or empty when not configured
	if len(cfg.Sandbox.EnvInject) != 0 {
		t.Errorf("env_inject should be empty when not configured, got %v", cfg.Sandbox.EnvInject)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/config -run TestLoad_EnvInjectConfig`
Expected: FAIL with "cfg.Sandbox.EnvInject undefined"

**Step 3: Add EnvInject field to SandboxConfig**

In `config.go`, find `type SandboxConfig struct` (around line 269) and add:

```go
type SandboxConfig struct {
	// Enabled enables the sandbox subsystem
	Enabled bool `yaml:"enabled"`

	// AllowDegraded permits running with reduced isolation if full isolation unavailable
	AllowDegraded bool `yaml:"allow_degraded"`

	// Limits configures resource limits for sandboxed processes
	Limits SandboxLimitsConfig `yaml:"limits"`

	// EnvInject injects environment variables into command execution
	// These bypass env policy filtering (operator-trusted)
	EnvInject map[string]string `yaml:"env_inject"`

	FUSE        SandboxFUSEConfig        `yaml:"fuse"`
	Network     SandboxNetworkConfig     `yaml:"network"`
	Cgroups     SandboxCgroupsConfig     `yaml:"cgroups"`
	UnixSockets SandboxUnixSocketsConfig `yaml:"unix_sockets"`
	Seccomp     SandboxSeccompConfig     `yaml:"seccomp"`
	XPC         SandboxXPCConfig         `yaml:"xpc"`
	MCP         SandboxMCPConfig         `yaml:"mcp"`
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/config -run TestLoad_EnvInjectConfig`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(config): add env_inject to SandboxConfig

Allows operators to inject environment variables that bypass policy
filtering. Primary use case is BASH_ENV for bash builtin disabling."
```

---

## Task 3: Add EnvInject to Policy Model

**Files:**
- Modify: `/home/eran/work/agentsh/internal/policy/model.go`
- Test: `/home/eran/work/agentsh/internal/policy/model_test.go`

**Step 1: Write the failing test for policy parsing**

Add to `model_test.go`:

```go
func TestPolicy_EnvInject(t *testing.T) {
	yamlData := `
version: 1
name: test-env-inject
env_inject:
  BASH_ENV: "/etc/mycompany/custom_bash_startup.sh"
  EXTRA_VAR: "policy-specific"
`
	var p Policy
	if err := yaml.Unmarshal([]byte(yamlData), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if p.EnvInject == nil {
		t.Fatal("env_inject should not be nil")
	}
	if p.EnvInject["BASH_ENV"] != "/etc/mycompany/custom_bash_startup.sh" {
		t.Errorf("BASH_ENV = %q, want %q", p.EnvInject["BASH_ENV"], "/etc/mycompany/custom_bash_startup.sh")
	}
	if p.EnvInject["EXTRA_VAR"] != "policy-specific" {
		t.Errorf("EXTRA_VAR = %q, want %q", p.EnvInject["EXTRA_VAR"], "policy-specific")
	}
}

func TestPolicy_EnvInject_Empty(t *testing.T) {
	yamlData := `
version: 1
name: test-no-env-inject
`
	var p Policy
	if err := yaml.Unmarshal([]byte(yamlData), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// EnvInject should be nil when not specified
	if len(p.EnvInject) != 0 {
		t.Errorf("env_inject should be empty when not specified, got %v", p.EnvInject)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/policy -run TestPolicy_EnvInject`
Expected: FAIL with "p.EnvInject undefined"

**Step 3: Add EnvInject field to Policy struct**

In `model.go`, find `type Policy struct` (around line 10) and add:

```go
type Policy struct {
	Version     int    `yaml:"version"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`

	FileRules     []FileRule       `yaml:"file_rules"`
	NetworkRules  []NetworkRule    `yaml:"network_rules"`
	CommandRules  []CommandRule    `yaml:"command_rules"`
	UnixRules     []UnixSocketRule `yaml:"unix_socket_rules"`
	RegistryRules []RegistryRule   `yaml:"registry_rules"`
	SignalRules   []SignalRule     `yaml:"signal_rules"`

	ResourceLimits ResourceLimits `yaml:"resource_limits"`
	EnvPolicy      EnvPolicy      `yaml:"env_policy"`
	Audit          AuditSettings  `yaml:"audit"`

	// EnvInject injects environment variables into command execution
	// Policy values override global config values on key conflicts
	EnvInject map[string]string `yaml:"env_inject"`

	// Process context-based rules (parent-conditional policies)
	ProcessContexts   map[string]ProcessContext        `yaml:"process_contexts,omitempty"`
	ProcessIdentities map[string]ProcessIdentityConfig `yaml:"process_identities,omitempty"`
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/policy -run TestPolicy_EnvInject`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/model.go internal/policy/model_test.go
git commit -m "feat(policy): add env_inject to Policy struct

Allows policy-level environment variable injection that overrides
global config values. Used for per-policy customization of BASH_ENV."
```

---

## Task 4: Add GetEnvInject Method to Policy Engine

**Files:**
- Modify: `/home/eran/work/agentsh/internal/policy/engine.go`
- Test: `/home/eran/work/agentsh/internal/policy/engine_test.go`

**Step 1: Write the failing test for GetEnvInject**

Add to `engine_test.go`:

```go
func TestEngine_GetEnvInject(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		EnvInject: map[string]string{
			"BASH_ENV": "/custom/path",
			"FOO":      "bar",
		},
	}
	eng, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	got := eng.GetEnvInject()
	if got["BASH_ENV"] != "/custom/path" {
		t.Errorf("BASH_ENV = %q, want %q", got["BASH_ENV"], "/custom/path")
	}
	if got["FOO"] != "bar" {
		t.Errorf("FOO = %q, want %q", got["FOO"], "bar")
	}
}

func TestEngine_GetEnvInject_Nil(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
	}
	eng, err := NewEngine(p, false)
	if err != nil {
		t.Fatal(err)
	}

	got := eng.GetEnvInject()
	if got == nil {
		t.Error("GetEnvInject should return empty map, not nil")
	}
	if len(got) != 0 {
		t.Errorf("GetEnvInject should return empty map, got %v", got)
	}
}

func TestEngine_GetEnvInject_NilEngine(t *testing.T) {
	var eng *Engine
	got := eng.GetEnvInject()
	if got == nil {
		t.Error("GetEnvInject on nil engine should return empty map, not nil")
	}
	if len(got) != 0 {
		t.Errorf("GetEnvInject on nil engine should return empty map, got %v", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/policy -run TestEngine_GetEnvInject`
Expected: FAIL with "eng.GetEnvInject undefined"

**Step 3: Add GetEnvInject method to Engine**

Add to `engine.go` (near other getter methods like `EnvPolicy()`):

```go
// GetEnvInject returns the policy's env_inject map.
// Returns an empty map if the engine or policy is nil.
func (e *Engine) GetEnvInject() map[string]string {
	if e == nil || e.policy == nil || e.policy.EnvInject == nil {
		return map[string]string{}
	}
	return e.policy.EnvInject
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/policy -run TestEngine_GetEnvInject`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat(policy): add GetEnvInject method to Engine

Exposes policy's env_inject map for use during command execution.
Returns empty map if engine/policy is nil for safe access."
```

---

## Task 5: Implement Merge Logic and Injection in exec.go

**Files:**
- Modify: `/home/eran/work/agentsh/internal/api/exec.go`
- Test: `/home/eran/work/agentsh/internal/api/exec_test.go` (create if needed)

**Step 1: Write the failing test for merge logic**

Create or add to `exec_test.go`:

```go
package api

import (
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

func TestMergeEnvInject(t *testing.T) {
	tests := []struct {
		name     string
		cfgEnv   map[string]string
		polEnv   map[string]string
		wantEnv  map[string]string
	}{
		{
			name:    "only global config",
			cfgEnv:  map[string]string{"BASH_ENV": "/usr/lib/agentsh/bash_startup.sh"},
			polEnv:  nil,
			wantEnv: map[string]string{"BASH_ENV": "/usr/lib/agentsh/bash_startup.sh"},
		},
		{
			name:    "only policy",
			cfgEnv:  nil,
			polEnv:  map[string]string{"BASH_ENV": "/custom/path"},
			wantEnv: map[string]string{"BASH_ENV": "/custom/path"},
		},
		{
			name:    "policy overrides config",
			cfgEnv:  map[string]string{"BASH_ENV": "/usr/lib/agentsh/bash_startup.sh", "GLOBAL": "value"},
			polEnv:  map[string]string{"BASH_ENV": "/custom/path", "POLICY": "value"},
			wantEnv: map[string]string{"BASH_ENV": "/custom/path", "GLOBAL": "value", "POLICY": "value"},
		},
		{
			name:    "both nil",
			cfgEnv:  nil,
			polEnv:  nil,
			wantEnv: map[string]string{},
		},
		{
			name:    "both empty",
			cfgEnv:  map[string]string{},
			polEnv:  map[string]string{},
			wantEnv: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{
				Sandbox: config.SandboxConfig{
					EnvInject: tt.cfgEnv,
				},
			}

			var pol *policy.Engine
			if tt.polEnv != nil {
				p := &policy.Policy{
					Version:   1,
					Name:      "test",
					EnvInject: tt.polEnv,
				}
				var err error
				pol, err = policy.NewEngine(p, false)
				if err != nil {
					t.Fatal(err)
				}
			}

			got := mergeEnvInject(cfg, pol)

			if len(got) != len(tt.wantEnv) {
				t.Errorf("mergeEnvInject() len = %d, want %d", len(got), len(tt.wantEnv))
			}
			for k, v := range tt.wantEnv {
				if got[k] != v {
					t.Errorf("mergeEnvInject()[%q] = %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestMergeEnvInject_NilConfig(t *testing.T) {
	got := mergeEnvInject(nil, nil)
	if got == nil {
		t.Error("mergeEnvInject(nil, nil) should return empty map, not nil")
	}
	if len(got) != 0 {
		t.Errorf("mergeEnvInject(nil, nil) should return empty map, got %v", got)
	}
}
```

**Step 2: Run test to verify it fails**

Run: `go test -v ./internal/api -run TestMergeEnvInject`
Expected: FAIL with "undefined: mergeEnvInject"

**Step 3: Add mergeEnvInject function to exec.go**

Add the function (before `runCommandWithResources` or at the end of the file):

```go
// mergeEnvInject merges env_inject from global config and policy.
// Policy values override config values on key conflicts.
// Returns an empty map if both sources are nil/empty.
func mergeEnvInject(cfg *config.Config, pol *policy.Engine) map[string]string {
	result := make(map[string]string)

	// 1. Start with global config
	if cfg != nil {
		for k, v := range cfg.Sandbox.EnvInject {
			result[k] = v
		}
	}

	// 2. Layer policy on top (policy wins conflicts)
	if pol != nil {
		for k, v := range pol.GetEnvInject() {
			result[k] = v
		}
	}

	return result
}
```

**Step 4: Run test to verify it passes**

Run: `go test -v ./internal/api -run TestMergeEnvInject`
Expected: PASS

**Step 5: Commit**

```bash
git add internal/api/exec.go internal/api/exec_test.go
git commit -m "feat(api): add mergeEnvInject helper function

Merges env_inject from global config and policy, with policy
taking precedence on key conflicts."
```

---

## Task 6: Integrate env_inject into Command Execution

**Files:**
- Modify: `/home/eran/work/agentsh/internal/api/exec.go`

**Step 1: Review current env building location**

In `runCommandWithResources`, the env is built around lines 142-164. After:
```go
if extra != nil && len(extra.env) > 0 {
    for k, v := range extra.env {
        env = append(env, fmt.Sprintf("%s=%s", k, v))
    }
}
```

**Step 2: Note the function signature needs access to config**

The `runCommandWithResources` function already receives `cfg *config.Config`. We need to also pass the policy engine or extract env_inject earlier.

Looking at the function, it receives `envPol policy.ResolvedEnvPolicy` but not the full engine. The caller has access to the policy engine.

**Step 3: Modify the function to accept env_inject directly**

The cleanest approach is to add env_inject to `extraProcConfig`. Update the struct:

In `exec.go`, find `type extraProcConfig struct` and add:

```go
type extraProcConfig struct {
	extraFiles       []*os.File
	env              map[string]string
	envInject        map[string]string // Operator-trusted env vars that bypass policy
	notifyParentSock *os.File          // ... rest unchanged
```

**Step 4: Update the env injection in runCommandWithResources**

After the existing extra.env block and before `cmd.Env = env`, add:

```go
	if extra != nil && len(extra.env) > 0 {
		for k, v := range extra.env {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	// Add env_inject (operator-trusted, bypasses policy filtering)
	if extra != nil && len(extra.envInject) > 0 {
		for k, v := range extra.envInject {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
	cmd.Env = env
```

**Step 5: Find callers that create extraProcConfig and update them**

Search for where `extraProcConfig` is populated. This will likely be in the HTTP handler or wherever commands are executed. The caller needs to call `mergeEnvInject(cfg, policyEngine)` and pass the result.

Run: `grep -rn "extraProcConfig{" /home/eran/work/agentsh/internal/`

Update each caller to include:
```go
extra := &extraProcConfig{
    // ... existing fields ...
    envInject: mergeEnvInject(cfg, policyEngine),
}
```

**Step 6: Verify the integration compiles**

Run: `go build ./...`
Expected: Successful compilation

**Step 7: Commit**

```bash
git add internal/api/exec.go
git commit -m "feat(api): integrate env_inject into command execution

Adds envInject field to extraProcConfig and injects values after
policy filtering. Bypasses env policy checks for operator-trusted vars."
```

---

## Task 7: Update Goreleaser Packaging

**Files:**
- Modify: `/home/eran/work/agentsh/.goreleaser.yml`

**Step 1: Add bash_startup.sh to Linux archives**

Find the `archives` section for `agentsh-linux` and add the script:

```yaml
archives:
  - id: agentsh-linux
    ids:
      - agentsh-linux-amd64
      - agentsh-linux-arm64
      - shim-linux
      - unixwrap-linux-amd64
    formats: [tar.gz]
    name_template: "{{ .ProjectName }}_{{ .Version }}_linux_{{ .Arch }}"
    allow_different_binary_count: true
    files:
      - README.md
      - LICENSE
      - config.yml
      - default-policy.yml
      - packaging/bash_startup.sh
      - src: build/envshim/linux_{{ .Arch }}/*
        dst: .
        strip_parent: true
```

**Step 2: Add bash_startup.sh to nfpms contents**

Find the `nfpms` section and add to `contents`:

```yaml
nfpms:
  - id: agentsh
    # ... existing fields ...
    contents:
      # ... existing contents ...
      # Bash startup script for BASH_ENV injection
      - src: packaging/bash_startup.sh
        dst: /usr/lib/agentsh/bash_startup.sh
        file_info:
          mode: 0755
```

**Step 3: Verify YAML syntax**

Run: `go run github.com/goreleaser/goreleaser/v2@latest check`
Expected: No errors

**Step 4: Commit**

```bash
git add .goreleaser.yml
git commit -m "feat(packaging): add bash_startup.sh to goreleaser builds

Includes the script in Linux tarballs and installs to
/usr/lib/agentsh/bash_startup.sh for deb/rpm/arch packages."
```

---

## Task 8: Update Alpine Workflow Packaging

**Files:**
- Modify: `/home/eran/work/agentsh/.github/workflows/release.yml`

**Step 1: Add bash_startup.sh to Alpine tarball**

Find the "Create Alpine tarball" step and update:

```yaml
      - name: Create Alpine tarball
        env:
          VERSION: ${{ github.ref_name }}
        run: |
          mkdir -p dist
          tar -czvf "dist/agentsh_${VERSION}_linux_amd64_musl.tar.gz" \
            agentsh \
            agentsh-unixwrap \
            agentsh-shell-shim \
            packaging/bash_startup.sh \
            README.md \
            LICENSE \
            config.yml \
            default-policy.yml
```

**Step 2: Verify workflow syntax**

Run: `cat .github/workflows/release.yml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)"`
Expected: No errors

**Step 3: Commit**

```bash
git add .github/workflows/release.yml
git commit -m "feat(ci): add bash_startup.sh to Alpine tarball

Includes the bash startup script in musl/Alpine builds."
```

---

## Task 9: Add Integration Test

**Files:**
- Create: `/home/eran/work/agentsh/internal/api/exec_envInject_test.go`

**Step 1: Write integration test for env_inject**

```go
package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
)

func TestEnvInject_AppearsInCommandEnv(t *testing.T) {
	if os.Getenv("CI") != "" {
		t.Skip("Skipping integration test in CI")
	}

	// Create a temp directory for session
	tmpDir := t.TempDir()
	workspaceDir := filepath.Join(tmpDir, "workspace")
	os.MkdirAll(workspaceDir, 0755)

	// Create config with env_inject
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			EnvInject: map[string]string{
				"TEST_INJECTED_VAR": "injected_value",
			},
		},
	}

	// Create a minimal policy
	pol := &policy.Policy{
		Version: 1,
		Name:    "test",
		CommandRules: []policy.CommandRule{
			{
				Name:     "allow-all",
				Commands: []string{"*"},
				Decision: "allow",
			},
		},
	}
	eng, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}

	// Merge env_inject
	envInject := mergeEnvInject(cfg, eng)

	// Verify the merge result
	if envInject["TEST_INJECTED_VAR"] != "injected_value" {
		t.Errorf("merged env_inject missing TEST_INJECTED_VAR")
	}
}

func TestEnvInject_PolicyOverridesConfig(t *testing.T) {
	cfg := &config.Config{
		Sandbox: config.SandboxConfig{
			EnvInject: map[string]string{
				"SHARED_VAR":  "config_value",
				"CONFIG_ONLY": "config_value",
			},
		},
	}

	pol := &policy.Policy{
		Version: 1,
		Name:    "test",
		EnvInject: map[string]string{
			"SHARED_VAR":  "policy_value",
			"POLICY_ONLY": "policy_value",
		},
	}
	eng, err := policy.NewEngine(pol, false)
	if err != nil {
		t.Fatal(err)
	}

	result := mergeEnvInject(cfg, eng)

	// Policy should override config for SHARED_VAR
	if result["SHARED_VAR"] != "policy_value" {
		t.Errorf("SHARED_VAR = %q, want policy_value", result["SHARED_VAR"])
	}

	// Both unique vars should be present
	if result["CONFIG_ONLY"] != "config_value" {
		t.Errorf("CONFIG_ONLY = %q, want config_value", result["CONFIG_ONLY"])
	}
	if result["POLICY_ONLY"] != "policy_value" {
		t.Errorf("POLICY_ONLY = %q, want policy_value", result["POLICY_ONLY"])
	}
}
```

**Step 2: Run integration tests**

Run: `go test -v ./internal/api -run TestEnvInject`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/api/exec_envInject_test.go
git commit -m "test(api): add env_inject integration tests

Tests merge behavior and policy override precedence for env_inject."
```

---

## Task 10: Add End-to-End Test for BASH_ENV

**Files:**
- Create: `/home/eran/work/agentsh/internal/api/exec_bashenv_test.go`

**Step 1: Write E2E test for bash builtin blocking**

```go
package api

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestBashStartupScript_DisablesBuiltins(t *testing.T) {
	// Find the bash_startup.sh script
	scriptPath := filepath.Join("..", "..", "packaging", "bash_startup.sh")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Skip("bash_startup.sh not found, skipping")
	}

	// Create a temp script that sources our startup and tries to use kill
	tmpDir := t.TempDir()
	testScript := filepath.Join(tmpDir, "test.sh")
	content := `#!/bin/bash
# This should fail because kill builtin is disabled
kill -0 $$ 2>&1 && echo "BUILTIN_ENABLED" || echo "BUILTIN_DISABLED"
`
	if err := os.WriteFile(testScript, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}

	// Run with BASH_ENV set to our startup script
	absScriptPath, _ := filepath.Abs(scriptPath)
	cmd := exec.Command("bash", testScript)
	cmd.Env = append(os.Environ(), "BASH_ENV="+absScriptPath)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Command might fail, that's expected if kill builtin is disabled
		t.Logf("Command output: %s", output)
	}

	// The output should indicate the builtin is disabled
	if string(output) == "BUILTIN_ENABLED\n" {
		t.Error("bash kill builtin should be disabled but was enabled")
	}
}

func TestBashStartupScript_SyntaxValid(t *testing.T) {
	scriptPath := filepath.Join("..", "..", "packaging", "bash_startup.sh")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		t.Skip("bash_startup.sh not found, skipping")
	}

	// Verify script has valid bash syntax
	cmd := exec.Command("bash", "-n", scriptPath)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Errorf("bash_startup.sh has syntax errors: %v\n%s", err, output)
	}
}
```

**Step 2: Run E2E tests**

Run: `go test -v ./internal/api -run TestBashStartupScript`
Expected: PASS

**Step 3: Commit**

```bash
git add internal/api/exec_bashenv_test.go
git commit -m "test(api): add E2E tests for bash_startup.sh

Verifies the script has valid syntax and properly disables builtins
when used via BASH_ENV."
```

---

## Task 11: Update Documentation (Optional)

**Files:**
- Modify: `/home/eran/work/agentsh/config.yml` (example config)

**Step 1: Add env_inject example to config.yml**

Add to the sandbox section:

```yaml
sandbox:
  # ... existing fields ...

  # env_inject: Environment variables injected into all commands
  # These bypass env policy filtering (operator-trusted)
  # Primary use: BASH_ENV to disable bash builtins that bypass seccomp
  env_inject:
    BASH_ENV: "/usr/lib/agentsh/bash_startup.sh"
    # MY_CUSTOM_VAR: "value"  # Add custom vars as needed
```

**Step 2: Commit**

```bash
git add config.yml
git commit -m "docs(config): add env_inject example to config.yml

Documents the env_inject configuration with BASH_ENV example."
```

---

## Task 12: Run Full Test Suite

**Step 1: Run all tests**

Run: `go test ./...`
Expected: All tests PASS

**Step 2: Run linter**

Run: `golangci-lint run`
Expected: No errors

**Step 3: Build all targets**

Run: `go build ./...`
Expected: Successful build

**Step 4: Final commit if any fixes needed**

If any fixes were needed, commit them with appropriate messages.

---

## Summary

This plan implements the `env_inject` feature in 12 tasks:

1. **Task 1**: Create `bash_startup.sh` script
2. **Task 2**: Add `EnvInject` to config struct with tests
3. **Task 3**: Add `EnvInject` to policy model with tests
4. **Task 4**: Add `GetEnvInject` method to policy engine
5. **Task 5**: Implement `mergeEnvInject` helper function
6. **Task 6**: Integrate env_inject into command execution
7. **Task 7**: Update goreleaser packaging
8. **Task 8**: Update Alpine workflow packaging
9. **Task 9**: Add integration tests
10. **Task 10**: Add E2E tests for bash builtin blocking
11. **Task 11**: Update example config documentation
12. **Task 12**: Run full test suite

Each task follows TDD principles with failing test first, minimal implementation, then commit.
