# Plan 7: Env Var Injection & Per-Service Scrub Toggle

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire service fake credentials into the spawned agent's environment via `inject.env`, with collision detection against `env_inject`, and make response scrubbing conditional per service via `scrub_response`.

**Architecture:** Extend the resolver to extract `inject.env` and `scrub_response` from policy YAML, build a service env var map from the credsub.Table after bootstrap, store the map on the Session, and inject into the spawned process env (bypassing policy filtering since vars like `GITHUB_TOKEN` are in the default-deny list). Make `CredsSubHook.PostHook` conditional on the service's `scrub_response` flag.

**Tech Stack:** Go 1.24, internal packages (`session`, `proxy`, `policy`, `api`)

---

## File Structure

| File | Responsibility |
|------|----------------|
| `internal/session/secretsconfig.go` | Add `ServiceEnvVar`, `ScrubServices` to resolver output |
| `internal/session/secretsconfig_test.go` | Tests for resolver changes |
| `internal/session/secrets.go` | New `BuildServiceEnvVars` function |
| `internal/session/secrets_test.go` | Tests for env var builder |
| `internal/session/envcheck.go` | New `CheckEnvCollisions` function |
| `internal/session/envcheck_test.go` | Tests for collision detection |
| `internal/session/manager.go` | Add `serviceEnvVars` field + setter/getter |
| `internal/session/llmproxy.go` | Wire env vars + scrub config through `StartLLMProxy` |
| `internal/session/llmproxy_test.go` | Tests for session wiring |
| `internal/policy/secrets.go` | Validate `inject.env` names in `ValidateSecrets` |
| `internal/policy/secrets_test.go` | Tests for validation |
| `internal/proxy/credshook.go` | Make `CredsSubHook` per-service scrub-aware |
| `internal/proxy/credshook_test.go` | Tests for scrub toggle |
| `internal/api/exec.go` | Inject service env vars into spawned process |
| `internal/session/secrets_integration_test.go` | End-to-end integration test |

---

### Task 1: Extend Resolver to Extract inject.env and scrub_response

**Files:**
- Modify: `internal/session/secretsconfig.go:22-27` (ResolvedServices struct)
- Modify: `internal/session/secretsconfig.go:49-80` (ResolveServiceConfigs function)
- Modify: `internal/session/secretsconfig_test.go`

- [ ] **Step 1: Write failing tests**

Add two tests to `internal/session/secretsconfig_test.go`:

```go
func TestResolveServiceConfigs_InjectEnv(t *testing.T) {
	svcs := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{{Name: "GITHUB_TOKEN"}},
			},
		},
	}
	result, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result.EnvVars) != 1 {
		t.Fatalf("expected 1 env var, got %d", len(result.EnvVars))
	}
	if result.EnvVars[0].ServiceName != "github" {
		t.Errorf("ServiceName = %q, want github", result.EnvVars[0].ServiceName)
	}
	if result.EnvVars[0].VarName != "GITHUB_TOKEN" {
		t.Errorf("VarName = %q, want GITHUB_TOKEN", result.EnvVars[0].VarName)
	}
}

func TestResolveServiceConfigs_ScrubResponse(t *testing.T) {
	svcs := []policy.ServiceYAML{
		{
			Name:          "github",
			Match:         policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret:        policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:          policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			ScrubResponse: true,
		},
		{
			Name:   "stripe",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.stripe.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/stripe"},
			Fake:   policy.ServiceFakeYAML{Format: "xk_test_{rand:24}"},
		},
	}
	result, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.ScrubServices["github"] {
		t.Error("expected github in ScrubServices")
	}
	if result.ScrubServices["stripe"] {
		t.Error("stripe should not be in ScrubServices")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/ -run TestResolveServiceConfigs_InjectEnv -v && go test ./internal/session/ -run TestResolveServiceConfigs_ScrubResponse -v`
Expected: FAIL — `result.EnvVars` and `result.ScrubServices` do not exist

- [ ] **Step 3: Add ServiceEnvVar type and extend ResolvedServices**

In `internal/session/secretsconfig.go`, add after the `InjectHeaderConfig` type (after line 20):

```go
// ServiceEnvVar maps a service name to an env var that should receive
// the service's fake credential.
type ServiceEnvVar struct {
	ServiceName string
	VarName     string
}
```

Modify `ResolvedServices` (lines 22-27) to:

```go
// ResolvedServices holds the parsed outputs needed by the bootstrap flow.
type ResolvedServices struct {
	ServiceConfigs []ServiceConfig
	Patterns       []services.ServicePattern
	InjectHeaders  []InjectHeaderConfig
	EnvVars        []ServiceEnvVar    // inject.env entries
	ScrubServices  map[string]bool    // service name -> scrub_response flag
}
```

- [ ] **Step 4: Extract inject.env and scrub_response in ResolveServiceConfigs**

In `ResolveServiceConfigs`, after the `InjectHeaders` block (after line 77), add:

```go
		for _, ev := range svc.Inject.Env {
			result.EnvVars = append(result.EnvVars, ServiceEnvVar{
				ServiceName: svc.Name,
				VarName:     ev.Name,
			})
		}
		if svc.ScrubResponse {
			if result.ScrubServices == nil {
				result.ScrubServices = make(map[string]bool)
			}
			result.ScrubServices[svc.Name] = true
		}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/session/ -run TestResolveServiceConfigs -v`
Expected: All PASS (including existing tests + two new ones)

- [ ] **Step 6: Commit**

```bash
git add internal/session/secretsconfig.go internal/session/secretsconfig_test.go
git commit -m "feat(session): resolve inject.env and scrub_response from service YAML (Plan 7)"
```

---

### Task 2: BuildServiceEnvVars Function

**Files:**
- Modify: `internal/session/secrets.go` (add function after BootstrapCredentials)
- Modify: `internal/session/secrets_test.go` (add tests)

- [ ] **Step 1: Write failing test**

Add to `internal/session/secrets_test.go`:

```go
func TestBuildServiceEnvVars(t *testing.T) {
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"github/token": []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
		},
	}
	services := []ServiceConfig{
		{
			Name:       "github",
			SecretRef:  secrets.SecretRef{Scheme: "memory", Host: "github", Path: "token"},
			FakeFormat: "ghp_{rand:36}",
		},
	}
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, services)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	envVars := []ServiceEnvVar{
		{ServiceName: "github", VarName: "GITHUB_TOKEN"},
	}
	result := BuildServiceEnvVars(envVars, table)
	if len(result) != 1 {
		t.Fatalf("expected 1 env var, got %d", len(result))
	}
	val, ok := result["GITHUB_TOKEN"]
	if !ok {
		t.Fatal("GITHUB_TOKEN not in result")
	}
	if len(val) != 40 {
		t.Errorf("value length = %d, want 40", len(val))
	}
	if val[:4] != "ghp_" {
		t.Errorf("value prefix = %q, want ghp_", val[:4])
	}
}

func TestBuildServiceEnvVars_UnknownService(t *testing.T) {
	table := credsub.New()
	envVars := []ServiceEnvVar{
		{ServiceName: "nonexistent", VarName: "FOO"},
	}
	result := BuildServiceEnvVars(envVars, table)
	if len(result) != 0 {
		t.Errorf("expected empty map, got %v", result)
	}
}

func TestBuildServiceEnvVars_Empty(t *testing.T) {
	table := credsub.New()
	result := BuildServiceEnvVars(nil, table)
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}
```

Add the `credsub` import to the test file:

```go
import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/proxy/credsub"
	"github.com/agentsh/agentsh/internal/proxy/secrets"
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/ -run TestBuildServiceEnvVars -v`
Expected: FAIL — `BuildServiceEnvVars` undefined

- [ ] **Step 3: Implement BuildServiceEnvVars**

Add to `internal/session/secrets.go` after `LogSecretsInitialized`:

```go
// BuildServiceEnvVars builds a map of env var name -> fake credential
// for services that declare inject.env. Looks up each service's fake
// from the table; services not found in the table are silently skipped.
func BuildServiceEnvVars(envVars []ServiceEnvVar, table *credsub.Table) map[string]string {
	if len(envVars) == 0 {
		return nil
	}
	result := make(map[string]string, len(envVars))
	for _, ev := range envVars {
		fake, ok := table.FakeForService(ev.ServiceName)
		if !ok {
			continue
		}
		result[ev.VarName] = string(fake)
	}
	if len(result) == 0 {
		return nil
	}
	return result
}
```

Add `"github.com/agentsh/agentsh/internal/proxy/credsub"` to the imports if not already present (it already is via the `credsub.New()` usage in `BootstrapCredentials`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/ -run TestBuildServiceEnvVars -v`
Expected: All 3 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/session/secrets.go internal/session/secrets_test.go
git commit -m "feat(session): BuildServiceEnvVars maps service fakes to env var names (Plan 7)"
```

---

### Task 3: Validate inject.env Names in ValidateSecrets

**Files:**
- Modify: `internal/policy/secrets.go:66-144` (ValidateSecrets function)
- Modify: `internal/policy/secrets_test.go`

- [ ] **Step 1: Write failing tests**

Add to `internal/policy/secrets_test.go`:

```go
func TestValidateSecrets_InjectEnvEmptyName(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{{Name: ""}},
			},
		},
	}
	_, err := policy.ValidateSecrets(providers, services)
	if err == nil {
		t.Fatal("expected error for empty inject.env name")
	}
}

func TestValidateSecrets_InjectEnvDuplicateAcrossServices(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{{Name: "MY_TOKEN"}},
			},
		},
		{
			Name:   "stripe",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.stripe.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/stripe"},
			Fake:   policy.ServiceFakeYAML{Format: "xk_test_{rand:24}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{{Name: "MY_TOKEN"}},
			},
		},
	}
	_, err := policy.ValidateSecrets(providers, services)
	if err == nil {
		t.Fatal("expected error for duplicate env var name across services")
	}
}

func TestValidateSecrets_InjectEnvValid(t *testing.T) {
	providers := map[string]yaml.Node{
		"kr": mustNode(t, "type: keyring"),
	}
	services := []policy.ServiceYAML{
		{
			Name:   "github",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:   policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{{Name: "GITHUB_TOKEN"}},
			},
		},
	}
	_, err := policy.ValidateSecrets(providers, services)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}
```

Note: Existing tests use a helper `mustNode`. Check the test file for the exact helper name — it may be `mustNode` or `mustYAMLNode`. Use whatever the existing tests use. If the helper parses a YAML string into a `yaml.Node`, the above code should work. Adapt the helper name if needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run TestValidateSecrets_InjectEnv -v`
Expected: FAIL — EmptyName and DuplicateAcrossServices tests pass (should fail), Valid test passes

Actually: the first two tests should pass through validation without error since the validation doesn't exist yet. So they will fail (`expected error` but got nil).

- [ ] **Step 3: Add inject.env validation to ValidateSecrets**

In `internal/policy/secrets.go`, inside the `ValidateSecrets` function, add a `envOwner` map alongside the existing `hostOwner` map (around line 85):

```go
	envOwner := make(map[string]string) // env var name -> first service name
```

Then, inside the per-service loop (after the `inject.header.template` validation block ending around line 140), add:

```go
		// inject.env validation
		for j, ev := range svc.Inject.Env {
			if ev.Name == "" {
				return nil, fmt.Errorf("services[%d] %q: inject.env[%d].name is required", i, svc.Name, j)
			}
			if prev, dup := envOwner[ev.Name]; dup {
				return nil, fmt.Errorf("services[%d] %q: inject.env name %q already declared by service %q", i, svc.Name, ev.Name, prev)
			}
			envOwner[ev.Name] = svc.Name
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run TestValidateSecrets -v`
Expected: All PASS (existing + 3 new)

- [ ] **Step 5: Commit**

```bash
git add internal/policy/secrets.go internal/policy/secrets_test.go
git commit -m "feat(policy): validate inject.env names in ValidateSecrets (Plan 7)"
```

---

### Task 4: CheckEnvCollisions Function

**Files:**
- Create: `internal/session/envcheck.go`
- Create: `internal/session/envcheck_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/session/envcheck_test.go`:

```go
package session

import "testing"

func TestCheckEnvCollisions_NoCollision(t *testing.T) {
	serviceEnv := map[string]string{
		"GITHUB_TOKEN": "fake_gh",
	}
	envInject := map[string]string{
		"MY_VAR": "value",
	}
	if err := CheckEnvCollisions(serviceEnv, envInject); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEnvCollisions_Collision(t *testing.T) {
	serviceEnv := map[string]string{
		"GITHUB_TOKEN": "fake_gh",
	}
	envInject := map[string]string{
		"GITHUB_TOKEN": "other_value",
	}
	err := CheckEnvCollisions(serviceEnv, envInject)
	if err == nil {
		t.Fatal("expected error for collision")
	}
}

func TestCheckEnvCollisions_BothNil(t *testing.T) {
	if err := CheckEnvCollisions(nil, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestCheckEnvCollisions_MultipleCollisions(t *testing.T) {
	serviceEnv := map[string]string{
		"A": "1",
		"B": "2",
	}
	envInject := map[string]string{
		"A": "x",
		"B": "y",
		"C": "z",
	}
	err := CheckEnvCollisions(serviceEnv, envInject)
	if err == nil {
		t.Fatal("expected error for collisions")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/ -run TestCheckEnvCollisions -v`
Expected: FAIL — `CheckEnvCollisions` undefined

- [ ] **Step 3: Implement CheckEnvCollisions**

Create `internal/session/envcheck.go`:

```go
package session

import (
	"fmt"
	"sort"
	"strings"
)

// CheckEnvCollisions returns an error if any service env var name
// collides with an env_inject key. Both maps use env var names as keys.
func CheckEnvCollisions(serviceEnv, envInject map[string]string) error {
	if len(serviceEnv) == 0 || len(envInject) == 0 {
		return nil
	}
	var collisions []string
	for name := range serviceEnv {
		if _, ok := envInject[name]; ok {
			collisions = append(collisions, name)
		}
	}
	if len(collisions) == 0 {
		return nil
	}
	sort.Strings(collisions)
	return fmt.Errorf("env_inject_service_collision: %s", strings.Join(collisions, ", "))
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/ -run TestCheckEnvCollisions -v`
Expected: All 4 PASS

- [ ] **Step 5: Commit**

```bash
git add internal/session/envcheck.go internal/session/envcheck_test.go
git commit -m "feat(session): CheckEnvCollisions detects env_inject vs service env var conflicts (Plan 7)"
```

---

### Task 5: Wire Env Vars and Scrub Config Through StartLLMProxy

**Files:**
- Modify: `internal/session/manager.go:86-92` (add serviceEnvVars field)
- Modify: `internal/session/llmproxy.go:25-162` (StartLLMProxy signature + env wiring)
- Modify: `internal/session/llmproxy_test.go` (tests)
- Modify: `internal/api/app.go:466-475` (update call site)

- [ ] **Step 1: Write failing test**

Add to `internal/session/llmproxy_test.go`:

```go
func TestSession_ServiceEnvVars_Nil(t *testing.T) {
	sess := &Session{ID: "test"}
	result := sess.ServiceEnvVars()
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestSession_ServiceEnvVars_Set(t *testing.T) {
	sess := &Session{ID: "test"}
	envMap := map[string]string{"GITHUB_TOKEN": "fake_gh"}
	sess.SetServiceEnvVars(envMap)
	result := sess.ServiceEnvVars()
	if len(result) != 1 {
		t.Fatalf("expected 1 var, got %d", len(result))
	}
	if result["GITHUB_TOKEN"] != "fake_gh" {
		t.Errorf("GITHUB_TOKEN = %q", result["GITHUB_TOKEN"])
	}
}

func TestSession_ServiceEnvVars_DeepCopy(t *testing.T) {
	sess := &Session{ID: "test"}
	original := map[string]string{"K": "V"}
	sess.SetServiceEnvVars(original)
	result := sess.ServiceEnvVars()
	result["K"] = "mutated"
	result2 := sess.ServiceEnvVars()
	if result2["K"] != "V" {
		t.Error("ServiceEnvVars should return a copy")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/ -run TestSession_ServiceEnvVars -v`
Expected: FAIL — `SetServiceEnvVars` and `ServiceEnvVars` undefined

- [ ] **Step 3: Add serviceEnvVars field and methods to Session**

In `internal/session/manager.go`, after the `secretsClose` field (line 91), add:

```go
	// serviceEnvVars holds fake credentials keyed by env var name.
	// Injected into spawned processes bypassing policy filtering.
	// Nil if no services declare inject.env.
	serviceEnvVars map[string]string
```

Add setter and getter methods (near the other Set* methods, e.g., after `SetCredsTable`):

```go
// SetServiceEnvVars stores the service env var map on the session.
func (s *Session) SetServiceEnvVars(env map[string]string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serviceEnvVars = env
}

// ServiceEnvVars returns a copy of the service env var map.
// Returns nil if no services declare inject.env.
func (s *Session) ServiceEnvVars() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.serviceEnvVars == nil {
		return nil
	}
	out := make(map[string]string, len(s.serviceEnvVars))
	for k, v := range s.serviceEnvVars {
		out[k] = v
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/ -run TestSession_ServiceEnvVars -v`
Expected: All 3 PASS

- [ ] **Step 5: Modify StartLLMProxy to accept envInject and wire env vars**

In `internal/session/llmproxy.go`, change the `StartLLMProxy` signature (line 25-35) to add `envInject`:

```go
func StartLLMProxy(
	sess *Session,
	proxyCfg config.ProxyConfig,
	dlpCfg config.DLPConfig,
	storageCfg config.LLMStorageConfig,
	mcpCfg config.SandboxMCPConfig,
	storagePath string,
	logger *slog.Logger,
	providers map[string]yaml.Node,
	policyServices []policy.ServiceYAML,
	envInject map[string]string,
) (string, func() error, error) {
```

Inside the `if len(policyServices) > 0` block, after `BootstrapCredentials` (after line 129), add the env var wiring before the hook registration:

```go
		// Build and validate service env vars.
		svcEnv := BuildServiceEnvVars(resolved.EnvVars, table)
		if err := CheckEnvCollisions(svcEnv, envInject); err != nil {
			secretsCleanup()
			_ = registry.Close()
			_ = p.Stop(ctx)
			return "", nil, fmt.Errorf("service env collision: %w", err)
		}
		sess.SetServiceEnvVars(svcEnv)
```

- [ ] **Step 6: Update app.go call site**

In `internal/api/app.go`, update the `StartLLMProxy` call (around line 466-475) to pass `nil` for `envInject`:

```go
	proxyURL, closeFn, err := session.StartLLMProxy(
		s,
		a.cfg.Proxy,
		a.cfg.DLP,
		a.cfg.LLMStorage,
		a.cfg.Sandbox.MCP,
		storagePath,
		slog.Default(),
		nil, nil, nil,
	)
```

- [ ] **Step 7: Run all tests to verify nothing broke**

Run: `go test ./internal/session/ ./internal/api/ -v -count=1`
Expected: All PASS

- [ ] **Step 8: Commit**

```bash
git add internal/session/manager.go internal/session/llmproxy.go internal/session/llmproxy_test.go internal/api/app.go
git commit -m "feat(session): wire service env vars through StartLLMProxy with collision detection (Plan 7)"
```

---

### Task 6: Inject Service Env Vars Into Spawned Process

**Files:**
- Modify: `internal/api/exec.go:199-222` (add service env var block)

- [ ] **Step 1: Understand the injection point**

In `internal/api/exec.go`, the function `runCommandWithResources` (called from multiple exec paths) builds the process environment at lines 177-222:

1. `buildPolicyEnv()` (line 177) — applies allow/deny filtering
2. `extra.env` (lines 194-198) — seccomp wrapper vars
3. `extra.envInject` (lines 199-221) — operator-trusted, bypasses policy

Service env vars like `GITHUB_TOKEN` are in the default-deny list (`defaultSecretDeny` in `env_policy.go`), so they MUST bypass policy filtering. Add them after `envInject` using the same override pattern.

- [ ] **Step 2: Add service env var injection block**

In `internal/api/exec.go`, after the `env_inject` block (after line 221, before `cmd.Env = env`), add:

```go
	// Add service env vars (fake credentials, bypass policy filtering).
	// These must come after env_inject; collisions are caught at session start.
	if svcEnv := s.ServiceEnvVars(); len(svcEnv) > 0 {
		svcKeys := make(map[string]bool, len(svcEnv))
		for k := range svcEnv {
			svcKeys[k] = true
		}
		filtered := env[:0]
		for _, e := range env {
			if k, _, ok := strings.Cut(e, "="); ok && svcKeys[k] {
				continue
			}
			filtered = append(filtered, e)
		}
		env = filtered
		for k, v := range svcEnv {
			env = append(env, fmt.Sprintf("%s=%s", k, v))
		}
	}
```

- [ ] **Step 3: Run tests**

Run: `go test ./internal/api/ -v -count=1`
Expected: All PASS (the change is injected into the existing flow; existing tests still work)

Run: `go build ./...`
Expected: Compiles cleanly

- [ ] **Step 4: Commit**

```bash
git add internal/api/exec.go
git commit -m "feat(api): inject service fake credentials into spawned process env (Plan 7)"
```

---

### Task 7: Per-Service scrub_response in CredsSubHook

**Files:**
- Modify: `internal/proxy/credshook.go:16-82` (CredsSubHook struct + PostHook)
- Modify: `internal/proxy/credshook_test.go`
- Modify: `internal/session/llmproxy.go` (pass scrub config to NewCredsSubHook)

- [ ] **Step 1: Write failing tests**

Add to `internal/proxy/credshook_test.go`:

```go
func TestCredsSubHook_PostHook_ScrubDisabled(t *testing.T) {
	table := credsub.New()
	_ = table.Add("github", []byte("fake_cred_ABCDEFGHIJKLMNO"), []byte("real_cred_ABCDEFGHIJKLMNO"))

	// scrubServices does not include "github" -> PostHook should be a no-op
	hook := NewCredsSubHook(table, map[string]bool{"other": true})

	body := []byte(`{"key":"real_cred_ABCDEFGHIJKLMNO"}`)
	resp := &http.Response{
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	ctx := &RequestContext{ServiceName: "github"}

	err := hook.PostHook(resp, ctx)
	if err != nil {
		t.Fatalf("PostHook error: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if !bytes.Contains(got, []byte("real_cred_ABCDEFGHIJKLMNO")) {
		t.Error("expected real credential to remain (scrub disabled for this service)")
	}
}

func TestCredsSubHook_PostHook_ScrubEnabled(t *testing.T) {
	table := credsub.New()
	_ = table.Add("github", []byte("fake_cred_ABCDEFGHIJKLMNO"), []byte("real_cred_ABCDEFGHIJKLMNO"))

	hook := NewCredsSubHook(table, map[string]bool{"github": true})

	body := []byte(`{"key":"real_cred_ABCDEFGHIJKLMNO"}`)
	resp := &http.Response{
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	ctx := &RequestContext{ServiceName: "github"}

	err := hook.PostHook(resp, ctx)
	if err != nil {
		t.Fatalf("PostHook error: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if bytes.Contains(got, []byte("real_cred_ABCDEFGHIJKLMNO")) {
		t.Error("expected real credential to be scrubbed")
	}
	if !bytes.Contains(got, []byte("fake_cred_ABCDEFGHIJKLMNO")) {
		t.Error("expected fake credential in scrubbed output")
	}
}

func TestCredsSubHook_PostHook_NilScrubMap_ScrubsAll(t *testing.T) {
	table := credsub.New()
	_ = table.Add("github", []byte("fake_cred_ABCDEFGHIJKLMNO"), []byte("real_cred_ABCDEFGHIJKLMNO"))

	// nil scrubServices = backward compat, scrub everything
	hook := NewCredsSubHook(table, nil)

	body := []byte(`{"key":"real_cred_ABCDEFGHIJKLMNO"}`)
	resp := &http.Response{
		Body:          io.NopCloser(bytes.NewReader(body)),
		ContentLength: int64(len(body)),
	}
	ctx := &RequestContext{ServiceName: "github"}

	err := hook.PostHook(resp, ctx)
	if err != nil {
		t.Fatalf("PostHook error: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	if bytes.Contains(got, []byte("real_cred_ABCDEFGHIJKLMNO")) {
		t.Error("expected real credential to be scrubbed (nil map = scrub all)")
	}
}
```

These tests need `bytes`, `io`, `net/http` imports. Check the test file's existing imports and add if needed.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/ -run TestCredsSubHook_PostHook_Scrub -v`
Expected: FAIL — `NewCredsSubHook` only takes 1 argument

- [ ] **Step 3: Modify CredsSubHook to accept scrubServices**

In `internal/proxy/credshook.go`, change the struct and constructor (lines 16-23):

```go
// CredsSubHook performs credential substitution using a credsub.Table.
// PreHook replaces fake credentials with real ones in request bodies.
// PostHook replaces real credentials with fakes in response bodies
// for services listed in scrubServices. If scrubServices is nil,
// all responses are scrubbed (backward compatibility).
type CredsSubHook struct {
	table         *credsub.Table
	scrubServices map[string]bool
}

// NewCredsSubHook returns a CredsSubHook that uses the given table.
// scrubServices controls which services get response scrubbing.
// Pass nil to scrub all responses (backward compatibility).
func NewCredsSubHook(table *credsub.Table, scrubServices map[string]bool) *CredsSubHook {
	return &CredsSubHook{table: table, scrubServices: scrubServices}
}
```

Modify `PostHook` (lines 68-82) to check the scrub config:

```go
// PostHook replaces real credentials with fakes in the response body.
// Only scrubs if the service is in scrubServices (or if scrubServices is nil).
func (h *CredsSubHook) PostHook(resp *http.Response, ctx *RequestContext) error {
	if resp.Body == nil {
		return nil
	}
	// Check per-service scrub config.
	if h.scrubServices != nil && !h.scrubServices[ctx.ServiceName] {
		return nil
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil // best-effort
	}

	replaced := h.table.ReplaceRealToFake(body)
	resp.Body = io.NopCloser(bytes.NewReader(replaced))
	resp.ContentLength = int64(len(replaced))
	return nil
}
```

- [ ] **Step 4: Fix existing NewCredsSubHook call sites**

Update `internal/session/llmproxy.go` line 133 to pass `resolved.ScrubServices`:

```go
		credsSub := proxy.NewCredsSubHook(table, resolved.ScrubServices)
```

Search for any other `NewCredsSubHook` call sites in tests and update them. They likely pass only the table — add `nil` as the second argument for backward-compatible behavior:

Run: `grep -rn 'NewCredsSubHook' internal/`

For each call site in test files, change `NewCredsSubHook(table)` to `NewCredsSubHook(table, nil)`.

- [ ] **Step 5: Run all proxy + session tests**

Run: `go test ./internal/proxy/ ./internal/session/ -v -count=1`
Expected: All PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/credshook.go internal/proxy/credshook_test.go internal/session/llmproxy.go
git commit -m "feat(proxy): per-service scrub_response toggle in CredsSubHook (Plan 7)"
```

---

### Task 8: Integration Test

**Files:**
- Modify: `internal/session/secrets_integration_test.go`

- [ ] **Step 1: Write the integration test**

Add to `internal/session/secrets_integration_test.go`:

```go
func TestIntegration_EnvVarInjection_FullFlow(t *testing.T) {
	// 1. Define service YAML with inject.env and scrub_response.
	svcs := []policy.ServiceYAML{
		{
			Name:          "github",
			Match:         policy.ServiceMatchYAML{Hosts: []string{"api.github.com"}},
			Secret:        policy.ServiceSecretYAML{Ref: "keyring://agentsh/gh"},
			Fake:          policy.ServiceFakeYAML{Format: "ghp_{rand:36}"},
			ScrubResponse: true,
			Inject: policy.ServiceInjectYAML{
				Header: &policy.ServiceInjectHeaderYAML{
					Name: "Authorization", Template: "Bearer {{secret}}",
				},
				Env: []policy.ServiceInjectEnvYAML{
					{Name: "GITHUB_TOKEN"},
					{Name: "GH_TOKEN"},
				},
			},
		},
		{
			Name:   "stripe",
			Match:  policy.ServiceMatchYAML{Hosts: []string{"api.stripe.com"}},
			Secret: policy.ServiceSecretYAML{Ref: "keyring://agentsh/stripe"},
			Fake:   policy.ServiceFakeYAML{Format: "xk_test_{rand:24}"},
			Inject: policy.ServiceInjectYAML{
				Env: []policy.ServiceInjectEnvYAML{
					{Name: "STRIPE_API_KEY"},
				},
			},
			// scrub_response intentionally false
		},
	}

	// 2. Resolve services.
	resolved, err := ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("ResolveServiceConfigs: %v", err)
	}

	// Verify env vars resolved.
	if len(resolved.EnvVars) != 3 {
		t.Fatalf("expected 3 env vars, got %d", len(resolved.EnvVars))
	}

	// Verify scrub config.
	if !resolved.ScrubServices["github"] {
		t.Error("github should be in ScrubServices")
	}
	if resolved.ScrubServices["stripe"] {
		t.Error("stripe should NOT be in ScrubServices")
	}

	// 3. Bootstrap credentials with a memory provider.
	mp := &memoryProvider{
		secrets: map[string][]byte{
			"agentsh/gh":     []byte("ghp_realABCDEFGHIJKLMNOPQRSTUVWXYZ123456"),
			"agentsh/stripe": []byte("xk_test_realABCDEFGHIJKLMNOPQRST"),
		},
	}
	table, cleanup, err := BootstrapCredentials(context.Background(), mp, resolved.ServiceConfigs)
	if err != nil {
		t.Fatalf("BootstrapCredentials: %v", err)
	}
	defer cleanup()

	// 4. Build service env vars.
	svcEnv := BuildServiceEnvVars(resolved.EnvVars, table)
	if len(svcEnv) != 3 {
		t.Fatalf("expected 3 service env vars, got %d", len(svcEnv))
	}
	if _, ok := svcEnv["GITHUB_TOKEN"]; !ok {
		t.Error("GITHUB_TOKEN missing from service env vars")
	}
	if _, ok := svcEnv["GH_TOKEN"]; !ok {
		t.Error("GH_TOKEN missing from service env vars")
	}
	if _, ok := svcEnv["STRIPE_API_KEY"]; !ok {
		t.Error("STRIPE_API_KEY missing from service env vars")
	}

	// Verify env var values are the fake credentials.
	ghFake, _ := table.FakeForService("github")
	if svcEnv["GITHUB_TOKEN"] != string(ghFake) {
		t.Errorf("GITHUB_TOKEN value doesn't match fake")
	}
	// Both GITHUB_TOKEN and GH_TOKEN should have the same fake (same service).
	if svcEnv["GH_TOKEN"] != string(ghFake) {
		t.Errorf("GH_TOKEN value doesn't match fake")
	}

	// 5. Collision detection: no collision.
	envInject := map[string]string{"PATH": "/usr/bin"}
	if err := CheckEnvCollisions(svcEnv, envInject); err != nil {
		t.Fatalf("unexpected collision: %v", err)
	}

	// 6. Collision detection: collision.
	envInjectBad := map[string]string{"GITHUB_TOKEN": "something_else"}
	if err := CheckEnvCollisions(svcEnv, envInjectBad); err == nil {
		t.Error("expected collision error")
	}
}
```

- [ ] **Step 2: Run the integration test**

Run: `go test ./internal/session/ -run TestIntegration_EnvVarInjection_FullFlow -v`
Expected: PASS

- [ ] **Step 3: Run all tests**

Run: `go test ./... -count=1`
Expected: All PASS

Run: `GOOS=windows go build ./...`
Expected: Cross-compilation succeeds

- [ ] **Step 4: Commit**

```bash
git add internal/session/secrets_integration_test.go
git commit -m "test(session): integration test for env var injection + collision detection (Plan 7)"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] `inject.env` parsed → Task 1 (resolver)
- [x] Fake values mapped to env var names → Task 2 (BuildServiceEnvVars)
- [x] `inject.env.name` validation → Task 3 (ValidateSecrets)
- [x] Collision detection with `env_inject` → Task 4 (CheckEnvCollisions)
- [x] Env vars stored on Session → Task 5 (manager.go + StartLLMProxy)
- [x] Env vars injected into spawned process (bypass policy) → Task 6 (exec.go)
- [x] Per-service `scrub_response` toggle → Task 7 (CredsSubHook)
- [x] Integration test → Task 8

**Placeholder scan:** No TBD, TODO, or vague steps. All steps have concrete code.

**Type consistency:**
- `ServiceEnvVar` — used consistently in Tasks 1, 2, 5, 8
- `ResolvedServices.ScrubServices` — map[string]bool, used in Tasks 1, 7, 8
- `BuildServiceEnvVars` signature — `([]ServiceEnvVar, *credsub.Table) map[string]string` throughout
- `CheckEnvCollisions` signature — `(map[string]string, map[string]string) error` throughout
- `NewCredsSubHook` — `(*credsub.Table, map[string]bool)` after Task 7, all call sites updated

**Deferred to Plan 8+:**
- Process context `secrets:` scoping
- Additional providers (AWS SM, GCP SM, Azure KV, 1Password)
- Go service plugins (AWS SigV4, GCP OAuth)
- SSE streaming substitution
- Distinct audit event names (split `secret_leak_blocked`)
