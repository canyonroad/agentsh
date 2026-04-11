# HTTP Path/Verb Filtering Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let operators declare HTTP services in policy with per-service method/path rules, route cooperating agents through a local gateway that enforces those rules, and fail closed on direct HTTPS to declared hosts.

**Architecture:** A new `http_services:` policy section compiles into the engine and exposes `CheckHTTPService(service, method, path)`. The LLM proxy (`internal/proxy/proxy.go`) gains a path-prefix dispatch (`/svc/<name>/...`) that routes cooperating child processes into a `serveDeclaredService` handler reusing the existing hook registry, storage, and redaction pipelines. `internal/netmonitor/proxy.go` gains a fail-closed check that denies CONNECT and plain-HTTP requests to declared upstream hosts.

**Tech Stack:** Go 1.22+, `gobwas/glob` (already a dependency), `yaml.v3` (already a dependency), existing `internal/policy`, `internal/proxy`, `internal/netmonitor`, `internal/approvals` packages.

**Spec:** `docs/superpowers/specs/2026-04-10-http-path-verb-filtering-design.md`

---

## File Structure

**New files:**

| File | Responsibility |
|---|---|
| `internal/policy/http_service.go` | `HTTPService`, `HTTPServiceRule` YAML types; `ValidateHTTPServices`; `validateHTTPServiceName` |
| `internal/policy/http_service_test.go` | Unit tests for validation |
| `internal/policy/http_service_compile.go` | `compiledHTTPService`, `compiledHTTPServiceRule`, `compileHTTPServices` |
| `internal/policy/http_service_check.go` | `CheckHTTPService`, `DeclaredHTTPServiceHost`, `HTTPServices` methods |
| `internal/policy/http_service_check_test.go` | Table-driven evaluator tests |
| `internal/policy/http_service_fuzz_test.go` | `FuzzCheckHTTPServicePath` |
| `internal/proxy/declared_service.go` | `declaredService` lookup, `serveDeclaredService`, request-clone helper |
| `internal/proxy/declared_service_test.go` | Gateway integration tests |

**Modified files:**

| File | Change |
|---|---|
| `internal/policy/model.go` | Add `HTTPServices` field to `Policy`; wire `ValidateHTTPServices` into `Policy.Validate` |
| `internal/policy/engine.go` | Call `compileHTTPServices` in `NewEngine`; add `Engine.httpServices` and `Engine.httpServiceHosts` fields |
| `internal/proxy/proxy.go` | Add path-prefix dispatch at the top of `ServeHTTP`; extend `EnvVars()` |
| `internal/proxy/storage.go` | Extend `RequestLogEntry` with `ServiceKind`, `ServiceName`, `RuleName` (all omitempty) |
| `internal/proxy/proxy_test.go` | Add `EnvVars()` assertion |
| `internal/netmonitor/proxy.go` | Add declared-host check in `handleConnect` and `handleHTTP` |
| `internal/netmonitor/proxy_test.go` | Tests for declared-host fail-closed |

---

## Task 1: Add HTTPService YAML types

**Files:**
- Create: `internal/policy/http_service.go`
- Create: `internal/policy/http_service_test.go`
- Modify: `internal/policy/model.go`

- [ ] **Step 1.1: Create the type file**

Create `internal/policy/http_service.go`:

```go
package policy

// HTTPService declares an HTTP service that a cooperating child process
// can reach through the proxy gateway. Requests are matched to the service
// by a URL path prefix (/svc/<name>/), then evaluated against Rules in
// declaration order. First-match-wins; if no rule matches, Default applies
// (empty or "deny" means deny).
type HTTPService struct {
	Name        string            `yaml:"name"`
	Upstream    string            `yaml:"upstream"`                // https://api.github.com
	ExposeAs    string            `yaml:"expose_as,omitempty"`     // env var name; derived from Name if empty
	Aliases     []string          `yaml:"aliases,omitempty"`       // extra hostnames for the fail-closed check
	AllowDirect bool              `yaml:"allow_direct,omitempty"`  // escape hatch; default false
	Default     string            `yaml:"default,omitempty"`       // allow | deny; default deny
	Rules       []HTTPServiceRule `yaml:"rules,omitempty"`
}

// HTTPServiceRule is a single method+path matching rule for an HTTP service.
type HTTPServiceRule struct {
	Name     string   `yaml:"name"`
	Methods  []string `yaml:"methods,omitempty"` // empty or "*" means any method
	Paths    []string `yaml:"paths"`             // gobwas/glob patterns, '/' separator
	Decision string   `yaml:"decision"`          // allow | deny | approve | audit
	Message  string   `yaml:"message,omitempty"`
	Timeout  duration `yaml:"timeout,omitempty"` // parsed but not wired in v1
}
```

- [ ] **Step 1.2: Add the field to Policy**

Edit `internal/policy/model.go`. Find the `Policy` struct and add the field alongside `Services`:

```go
// External secrets: provider definitions and service declarations.
// Parsed from YAML but validated by ValidateSecrets in secrets.go.
Providers map[string]yaml.Node `yaml:"providers,omitempty"`
Services  []ServiceYAML        `yaml:"services,omitempty"`

// HTTP services for path/verb filtering. Orthogonal to `services:` (Plan 6).
// See internal/policy/http_service.go and
// docs/superpowers/specs/2026-04-10-http-path-verb-filtering-design.md
HTTPServices []HTTPService `yaml:"http_services,omitempty"`
```

- [ ] **Step 1.3: Write the parsing test**

Create `internal/policy/http_service_test.go`:

```go
package policy

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestHTTPServiceYAMLUnmarshal(t *testing.T) {
	src := []byte(`
http_services:
  - name: github
    upstream: https://api.github.com
    expose_as: GITHUB_API_URL
    default: deny
    rules:
      - name: read-issues
        methods: [GET]
        paths:
          - /repos/*/*/issues
        decision: allow
`)

	var p Policy
	if err := yaml.Unmarshal(src, &p); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(p.HTTPServices) != 1 {
		t.Fatalf("expected 1 http_service, got %d", len(p.HTTPServices))
	}
	svc := p.HTTPServices[0]
	if svc.Name != "github" {
		t.Errorf("Name = %q, want github", svc.Name)
	}
	if svc.Upstream != "https://api.github.com" {
		t.Errorf("Upstream = %q, want https://api.github.com", svc.Upstream)
	}
	if svc.ExposeAs != "GITHUB_API_URL" {
		t.Errorf("ExposeAs = %q, want GITHUB_API_URL", svc.ExposeAs)
	}
	if svc.Default != "deny" {
		t.Errorf("Default = %q, want deny", svc.Default)
	}
	if len(svc.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(svc.Rules))
	}
	r := svc.Rules[0]
	if r.Name != "read-issues" || r.Decision != "allow" {
		t.Errorf("rule = %+v, want name=read-issues decision=allow", r)
	}
	if len(r.Methods) != 1 || r.Methods[0] != "GET" {
		t.Errorf("Methods = %v, want [GET]", r.Methods)
	}
	if len(r.Paths) != 1 || r.Paths[0] != "/repos/*/*/issues" {
		t.Errorf("Paths = %v, want [/repos/*/*/issues]", r.Paths)
	}
}
```

- [ ] **Step 1.4: Run the test — expect PASS**

```bash
go test ./internal/policy/ -run TestHTTPServiceYAMLUnmarshal -v
```

Expected: PASS (the test only exercises unmarshaling, which is driven entirely by YAML struct tags).

- [ ] **Step 1.5: Commit**

```bash
git add internal/policy/http_service.go internal/policy/http_service_test.go internal/policy/model.go
git commit -m "feat(policy): add HTTPService YAML types

Introduces http_services top-level section with HTTPService and
HTTPServiceRule types for path/verb filtering. No validation or
enforcement yet - wired in subsequent tasks."
```

---

## Task 2: Validate HTTPService entries

**Files:**
- Modify: `internal/policy/http_service.go`
- Modify: `internal/policy/http_service_test.go`
- Modify: `internal/policy/model.go`

- [ ] **Step 2.1: Write validation tests first**

Add to `internal/policy/http_service_test.go`:

```go
func TestValidateHTTPServices(t *testing.T) {
	tests := []struct {
		name    string
		svcs    []HTTPService
		wantErr string // substring match; empty means no error
	}{
		{
			name: "valid single service",
			svcs: []HTTPService{{
				Name: "github", Upstream: "https://api.github.com",
				Default: "deny",
				Rules: []HTTPServiceRule{{
					Name: "read", Methods: []string{"GET"},
					Paths: []string{"/repos/*"}, Decision: "allow",
				}},
			}},
		},
		{
			name:    "empty name rejected",
			svcs:    []HTTPService{{Upstream: "https://api.github.com"}},
			wantErr: "name is required",
		},
		{
			name: "duplicate name rejected",
			svcs: []HTTPService{
				{Name: "github", Upstream: "https://api.github.com"},
				{Name: "GITHUB", Upstream: "https://other.example.com"},
			},
			wantErr: "duplicate http_service name",
		},
		{
			name:    "non-https upstream rejected",
			svcs:    []HTTPService{{Name: "x", Upstream: "http://example.com"}},
			wantErr: "upstream must be https",
		},
		{
			name:    "unparseable upstream rejected",
			svcs:    []HTTPService{{Name: "x", Upstream: "://broken"}},
			wantErr: "invalid upstream URL",
		},
		{
			name: "duplicate upstream host rejected",
			svcs: []HTTPService{
				{Name: "a", Upstream: "https://api.example.com"},
				{Name: "b", Upstream: "https://api.example.com"},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "alias collides with other upstream",
			svcs: []HTTPService{
				{Name: "a", Upstream: "https://api.example.com"},
				{Name: "b", Upstream: "https://other.example.com", Aliases: []string{"api.example.com"}},
			},
			wantErr: "duplicate upstream host",
		},
		{
			name: "invalid default rejected",
			svcs: []HTTPService{{
				Name: "x", Upstream: "https://api.example.com", Default: "maybe",
			}},
			wantErr: "invalid default",
		},
		{
			name: "invalid rule decision rejected",
			svcs: []HTTPService{{
				Name: "x", Upstream: "https://api.example.com",
				Rules: []HTTPServiceRule{{
					Name: "r", Paths: []string{"/foo"}, Decision: "redirect",
				}},
			}},
			wantErr: "invalid rule decision",
		},
		{
			name: "invalid glob rejected",
			svcs: []HTTPService{{
				Name: "x", Upstream: "https://api.example.com",
				Rules: []HTTPServiceRule{{
					Name: "r", Paths: []string{"[unterminated"}, Decision: "allow",
				}},
			}},
			wantErr: "invalid path glob",
		},
		{
			name: "empty paths rejected",
			svcs: []HTTPService{{
				Name: "x", Upstream: "https://api.example.com",
				Rules: []HTTPServiceRule{{
					Name: "r", Paths: nil, Decision: "allow",
				}},
			}},
			wantErr: "rule must have at least one path",
		},
		{
			name: "expose_as invalid rejected",
			svcs: []HTTPService{{
				Name: "x", Upstream: "https://api.example.com", ExposeAs: "1_INVALID",
			}},
			wantErr: "invalid expose_as",
		},
		{
			name: "expose_as with hyphen derived from name invalid",
			svcs: []HTTPService{{
				Name: "my-svc", Upstream: "https://api.example.com",
			}},
			wantErr: "derived env var name is invalid",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateHTTPServices(tc.svcs)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantErr)
			}
			if !containsString(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func containsString(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
```

- [ ] **Step 2.2: Run test — expect FAIL**

```bash
go test ./internal/policy/ -run TestValidateHTTPServices -v
```

Expected: FAIL — `ValidateHTTPServices` does not exist yet.

- [ ] **Step 2.3: Implement validation**

Append to `internal/policy/http_service.go`:

```go
import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/gobwas/glob"
)

var envVarNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateHTTPServices checks an HTTPServices list for well-formedness.
// It is called from Policy.Validate. Errors include the offending service
// name (and rule name, when applicable) to aid debugging.
func ValidateHTTPServices(svcs []HTTPService) error {
	nameSeen := make(map[string]bool, len(svcs))
	hostSeen := make(map[string]string, len(svcs)) // host -> owning service name
	for i := range svcs {
		s := &svcs[i]
		if strings.TrimSpace(s.Name) == "" {
			return fmt.Errorf("http_services[%d]: name is required", i)
		}
		lower := strings.ToLower(s.Name)
		if nameSeen[lower] {
			return fmt.Errorf("http_services: duplicate http_service name %q", s.Name)
		}
		nameSeen[lower] = true

		u, err := url.Parse(s.Upstream)
		if err != nil || u == nil || u.Host == "" {
			return fmt.Errorf("http_services[%q]: invalid upstream URL %q", s.Name, s.Upstream)
		}
		if u.Scheme != "https" {
			return fmt.Errorf("http_services[%q]: upstream must be https (got %q)", s.Name, u.Scheme)
		}

		host := strings.ToLower(u.Hostname())
		if other, dup := hostSeen[host]; dup {
			return fmt.Errorf("http_services[%q]: duplicate upstream host %q (also claimed by %q)", s.Name, host, other)
		}
		hostSeen[host] = s.Name
		for _, alias := range s.Aliases {
			a := strings.ToLower(strings.TrimSpace(alias))
			if a == "" {
				return fmt.Errorf("http_services[%q]: empty alias", s.Name)
			}
			if other, dup := hostSeen[a]; dup {
				return fmt.Errorf("http_services[%q]: duplicate upstream host %q via alias (also claimed by %q)", s.Name, a, other)
			}
			hostSeen[a] = s.Name
		}

		switch s.Default {
		case "", "allow", "deny":
			// OK
		default:
			return fmt.Errorf("http_services[%q]: invalid default %q (want allow|deny)", s.Name, s.Default)
		}

		exposeAs := s.ExposeAs
		if exposeAs == "" {
			// Derive from name: uppercase, add "_API_URL" suffix.
			exposeAs = strings.ToUpper(s.Name) + "_API_URL"
			if !envVarNameRe.MatchString(exposeAs) {
				return fmt.Errorf("http_services[%q]: derived env var name %q is invalid; set expose_as explicitly", s.Name, exposeAs)
			}
		} else if !envVarNameRe.MatchString(exposeAs) {
			return fmt.Errorf("http_services[%q]: invalid expose_as %q", s.Name, exposeAs)
		}

		for j := range s.Rules {
			r := &s.Rules[j]
			if err := validateHTTPServiceRule(s.Name, j, r); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateHTTPServiceRule(svc string, idx int, r *HTTPServiceRule) error {
	label := fmt.Sprintf("http_services[%q].rules[%d] (%s)", svc, idx, r.Name)
	switch r.Decision {
	case "allow", "deny", "approve", "audit":
		// OK
	default:
		return fmt.Errorf("%s: invalid rule decision %q", label, r.Decision)
	}
	if len(r.Paths) == 0 {
		return fmt.Errorf("%s: rule must have at least one path", label)
	}
	for _, pat := range r.Paths {
		if _, err := glob.Compile(pat, '/'); err != nil {
			return fmt.Errorf("%s: invalid path glob %q: %w", label, pat, err)
		}
	}
	for _, m := range r.Methods {
		if strings.TrimSpace(m) == "" {
			return fmt.Errorf("%s: empty method", label)
		}
	}
	return nil
}
```

- [ ] **Step 2.4: Wire into Policy.Validate**

Find `Policy.Validate` in `internal/policy/model.go` (look near line 500 where `ValidateSecrets` is already called). Add a call to `ValidateHTTPServices`:

```go
if err := ValidateHTTPServices(p.HTTPServices); err != nil {
	return err
}
```

Place it alongside `ValidateSecrets` so both run in the same pass.

- [ ] **Step 2.5: Run tests — expect PASS**

```bash
go test ./internal/policy/ -run TestValidateHTTPServices -v
```

Expected: PASS for all table entries.

- [ ] **Step 2.6: Run full policy test suite — nothing should break**

```bash
go test ./internal/policy/ -v
```

Expected: PASS. If existing tests break because `Validate` is stricter, investigate — the added call should be a no-op on policies without `http_services:`.

- [ ] **Step 2.7: Commit**

```bash
git add internal/policy/http_service.go internal/policy/http_service_test.go internal/policy/model.go
git commit -m "feat(policy): validate http_services entries

Adds ValidateHTTPServices covering: non-empty names, unique names, https
upstream URLs, unique upstream hosts (including aliases), allow/deny
default, allow/deny/approve/audit rule decisions, non-empty paths,
compiling path globs, and env var name regex checks."
```

---

## Task 3: Compile HTTPServices on engine construction

**Files:**
- Create: `internal/policy/http_service_compile.go`
- Modify: `internal/policy/engine.go`

- [ ] **Step 3.1: Create compile file**

Create `internal/policy/http_service_compile.go`:

```go
package policy

import (
	"net/url"
	"strings"

	"github.com/gobwas/glob"
)

// compiledHTTPServiceRule is an HTTPServiceRule with pre-compiled path
// globs and a method set for O(1) matching.
type compiledHTTPServiceRule struct {
	rule    HTTPServiceRule
	methods map[string]struct{} // uppercase; empty or containing "*" means any
	paths   []glob.Glob
}

// compiledHTTPService holds the compiled form of an HTTPService entry.
type compiledHTTPService struct {
	cfg             HTTPService
	rules           []compiledHTTPServiceRule
	upstream        *url.URL
	envVar          string // resolved ExposeAs or derived
	defaultDecision string // "allow" or "deny" (empty treated as "deny")
	upstreamHost    string // lowercased for host-based lookup
}

// compileHTTPServices transforms validated HTTPService entries into the
// compiled form used by CheckHTTPService. Panics on re-validation failure;
// callers MUST call ValidateHTTPServices first.
func compileHTTPServices(svcs []HTTPService) (byName, byHost map[string]*compiledHTTPService, err error) {
	byName = make(map[string]*compiledHTTPService, len(svcs))
	byHost = make(map[string]*compiledHTTPService, len(svcs))
	for i := range svcs {
		s := svcs[i]
		u, parseErr := url.Parse(s.Upstream)
		if parseErr != nil {
			return nil, nil, parseErr
		}

		envVar := s.ExposeAs
		if envVar == "" {
			envVar = strings.ToUpper(s.Name) + "_API_URL"
		}
		defDec := s.Default
		if defDec == "" {
			defDec = "deny"
		}
		host := strings.ToLower(u.Hostname())

		cs := &compiledHTTPService{
			cfg:             s,
			upstream:        u,
			envVar:          envVar,
			defaultDecision: defDec,
			upstreamHost:    host,
		}
		for _, r := range s.Rules {
			cr := compiledHTTPServiceRule{rule: r}
			if len(r.Methods) > 0 {
				cr.methods = make(map[string]struct{}, len(r.Methods))
				for _, m := range r.Methods {
					cr.methods[strings.ToUpper(strings.TrimSpace(m))] = struct{}{}
				}
			}
			for _, pat := range r.Paths {
				g, gerr := glob.Compile(pat, '/')
				if gerr != nil {
					return nil, nil, gerr
				}
				cr.paths = append(cr.paths, g)
			}
			cs.rules = append(cs.rules, cr)
		}
		byName[strings.ToLower(s.Name)] = cs
		byHost[host] = cs
		for _, alias := range s.Aliases {
			byHost[strings.ToLower(strings.TrimSpace(alias))] = cs
		}
	}
	return byName, byHost, nil
}
```

- [ ] **Step 3.2: Wire into NewEngine**

Find `NewEngine` in `internal/policy/engine.go` (around line 127). Add two new fields to the `Engine` struct (find the struct declaration — usually near the top of the file):

```go
type Engine struct {
	// ... existing fields ...
	httpServices     map[string]*compiledHTTPService
	httpServiceHosts map[string]*compiledHTTPService
}
```

Inside `NewEngine`, after validation but before returning, add:

```go
if byName, byHost, err := compileHTTPServices(p.HTTPServices); err != nil {
	return nil, err
} else {
	e.httpServices = byName
	e.httpServiceHosts = byHost
}
```

Place this alongside other rule compilation calls (`compiledNetworkRule` etc. are built in a similar section — look for patterns like `e.compiledNetworkRules = ...`).

- [ ] **Step 3.3: Write a compilation smoke test**

Add to `internal/policy/http_service_test.go`:

```go
func TestCompileHTTPServices_Smoke(t *testing.T) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Default: "deny",
		Rules: []HTTPServiceRule{{
			Name: "read", Methods: []string{"GET"},
			Paths: []string{"/repos/*/*/issues"}, Decision: "allow",
		}},
	}}
	if err := ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	byName, byHost, err := compileHTTPServices(svcs)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	cs, ok := byName["github"]
	if !ok {
		t.Fatal("github not in byName map")
	}
	if cs.envVar != "GITHUB_API_URL" {
		t.Errorf("envVar = %q, want GITHUB_API_URL", cs.envVar)
	}
	if cs.upstreamHost != "api.github.com" {
		t.Errorf("upstreamHost = %q", cs.upstreamHost)
	}
	if cs.defaultDecision != "deny" {
		t.Errorf("defaultDecision = %q", cs.defaultDecision)
	}
	if len(cs.rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(cs.rules))
	}
	if _, ok := cs.rules[0].methods["GET"]; !ok {
		t.Errorf("method GET not compiled")
	}
	if len(cs.rules[0].paths) != 1 {
		t.Errorf("paths not compiled")
	}
	if _, ok := byHost["api.github.com"]; !ok {
		t.Error("api.github.com not in byHost map")
	}
}
```

- [ ] **Step 3.4: Run tests**

```bash
go build ./internal/policy/
go test ./internal/policy/ -run TestCompileHTTPServices_Smoke -v
```

Expected: PASS.

- [ ] **Step 3.5: Commit**

```bash
git add internal/policy/http_service_compile.go internal/policy/engine.go internal/policy/http_service_test.go
git commit -m "feat(policy): compile http_services in NewEngine

Adds compiledHTTPService and compiledHTTPServiceRule with pre-compiled
path globs and method sets. NewEngine builds byName and byHost maps
that later tasks use for dispatch and fail-closed checks."
```

---

## Task 4: Implement CheckHTTPService

**Files:**
- Create: `internal/policy/http_service_check.go`
- Create: `internal/policy/http_service_check_test.go`

- [ ] **Step 4.1: Write the evaluator tests first**

Create `internal/policy/http_service_check_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func newTestEngineForHTTP(t *testing.T, svcs []HTTPService) *Engine {
	t.Helper()
	p := &Policy{HTTPServices: svcs}
	if err := ValidateHTTPServices(p.HTTPServices); err != nil {
		t.Fatalf("validate: %v", err)
	}
	byName, byHost, err := compileHTTPServices(p.HTTPServices)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	return &Engine{
		policy:           p,
		httpServices:     byName,
		httpServiceHosts: byHost,
		enforceApprovals: true,
	}
}

func TestCheckHTTPService(t *testing.T) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Default: "deny",
		Rules: []HTTPServiceRule{
			{Name: "read-issues", Methods: []string{"GET"}, Paths: []string{"/repos/*/*/issues", "/repos/*/*/issues/*"}, Decision: "allow"},
			{Name: "wildcard-subtree", Methods: []string{"GET"}, Paths: []string{"/orgs/**"}, Decision: "allow"},
			{Name: "any-method", Methods: []string{"*"}, Paths: []string{"/public/*"}, Decision: "allow"},
			{Name: "multi-method", Methods: []string{"PUT", "PATCH"}, Paths: []string{"/repos/*/*"}, Decision: "allow"},
			{Name: "block-delete", Methods: []string{"DELETE"}, Paths: []string{"/repos/**"}, Decision: "deny", Message: "no deletes"},
		},
	}, {
		Name: "open", Upstream: "https://open.example.com",
		Default: "allow",
	}}

	e := newTestEngineForHTTP(t, svcs)

	tests := []struct {
		name         string
		service      string
		method       string
		path         string
		wantDecision types.Decision
		wantRule     string
	}{
		{"simple allow", "github", "GET", "/repos/a/b/issues", types.DecisionAllow, "read-issues"},
		{"sub path allow", "github", "GET", "/repos/a/b/issues/42", types.DecisionAllow, "read-issues"},
		{"wildcard subtree", "github", "GET", "/orgs/acme/members/list", types.DecisionAllow, "wildcard-subtree"},
		{"method wildcard", "github", "POST", "/public/thing", types.DecisionAllow, "any-method"},
		{"multi method PUT", "github", "PUT", "/repos/a/b", types.DecisionAllow, "multi-method"},
		{"multi method PATCH", "github", "PATCH", "/repos/a/b", types.DecisionAllow, "multi-method"},
		{"delete denied by rule", "github", "DELETE", "/repos/a/b", types.DecisionDeny, "block-delete"},
		{"wrong method falls through", "github", "POST", "/repos/a/b/issues", types.DecisionDeny, "default"},
		{"default deny", "github", "GET", "/unmatched", types.DecisionDeny, "default"},
		{"lowercase method canonicalized", "github", "get", "/repos/a/b/issues", types.DecisionAllow, "read-issues"},
		{"unknown service deny", "nosuch", "GET", "/anything", types.DecisionDeny, ""},
		{"empty path coerced", "open", "GET", "", types.DecisionAllow, "default"},
		{"traversal rejected", "github", "GET", "/repos/../etc/passwd", types.DecisionDeny, ""},
		{"double slash rejected", "github", "GET", "/repos//a/b/issues", types.DecisionDeny, ""},
		{"dot segment rejected", "github", "GET", "/repos/./a/b/issues", types.DecisionDeny, ""},
		{"case sensitive path no match", "github", "GET", "/REPOS/a/b/issues", types.DecisionDeny, "default"},
		{"query string ignored", "github", "GET", "/repos/a/b/issues?state=open", types.DecisionDeny, ""}, // traversal check is strict — '?' doesn't survive path.Clean
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Strip query string before calling — that's the gateway's job.
			reqPath := tc.path
			if idx := strings.Index(reqPath, "?"); idx != -1 {
				reqPath = reqPath[:idx]
			}
			dec := e.CheckHTTPService(tc.service, tc.method, reqPath)
			if dec.EffectiveDecision != tc.wantDecision {
				t.Errorf("decision = %q, want %q (rule=%q msg=%q)",
					dec.EffectiveDecision, tc.wantDecision, dec.Rule, dec.Message)
			}
			if tc.wantRule != "" && dec.Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q", dec.Rule, tc.wantRule)
			}
		})
	}
}
```

Note the query-string handling: the gateway itself strips the query before calling `CheckHTTPService`, so the evaluator does not have to. Leave the test entry as a reminder that the gateway owns this.

Add the required imports:

```go
import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)
```

- [ ] **Step 4.2: Run test — expect FAIL (no method yet)**

```bash
go test ./internal/policy/ -run TestCheckHTTPService -v
```

Expected: FAIL (compile error: `e.CheckHTTPService` undefined).

- [ ] **Step 4.3: Implement CheckHTTPService**

Create `internal/policy/http_service_check.go`:

```go
package policy

import (
	"path"
	"strings"
)

// CheckHTTPService evaluates method+reqPath against the rules for service.
// reqPath is the path portion AFTER the /svc/<name> prefix has been stripped
// and the query string removed. The gateway is responsible for stripping
// both before calling this method.
//
// Returns a wrapped Decision in the same shape as CheckNetworkCtx. First-
// match-wins on rules. If no rule matches, the service's Default applies
// (empty or "deny" means deny). Unknown services always deny.
func (e *Engine) CheckHTTPService(service, method, reqPath string) Decision {
	cs, ok := e.httpServices[strings.ToLower(service)]
	if !ok {
		return e.wrapDecision("deny", "", "unknown http_service", nil)
	}

	if reqPath == "" {
		reqPath = "/"
	}
	// Traversal guard: reject any path that doesn't survive path.Clean.
	if path.Clean(reqPath) != reqPath {
		return e.wrapDecision("deny", "", "path traversal rejected", nil)
	}

	m := strings.ToUpper(method)

	for _, r := range cs.rules {
		if !methodMatchesHTTPRule(r, m) {
			continue
		}
		if !pathMatchesHTTPRule(r, reqPath) {
			continue
		}
		return e.wrapDecision(r.rule.Decision, r.rule.Name, r.rule.Message, nil)
	}

	if cs.defaultDecision == "allow" {
		return e.wrapDecision("allow", "default", "", nil)
	}
	return e.wrapDecision("deny", "default", "no rule matched", nil)
}

func methodMatchesHTTPRule(r compiledHTTPServiceRule, method string) bool {
	if len(r.methods) == 0 {
		return true
	}
	if _, ok := r.methods["*"]; ok {
		return true
	}
	_, ok := r.methods[method]
	return ok
}

func pathMatchesHTTPRule(r compiledHTTPServiceRule, reqPath string) bool {
	for _, g := range r.paths {
		if g.Match(reqPath) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4.4: Run test — expect PASS**

```bash
go test ./internal/policy/ -run TestCheckHTTPService -v
```

Expected: all sub-tests PASS.

- [ ] **Step 4.5: Commit**

```bash
git add internal/policy/http_service_check.go internal/policy/http_service_check_test.go
git commit -m "feat(policy): implement CheckHTTPService evaluator

Table-driven tests cover first-match-wins, method/path matching,
case canonicalization, default fallback, unknown service, empty path
coercion, and traversal rejection."
```

---

## Task 5: Implement DeclaredHTTPServiceHost and HTTPServices getters

**Files:**
- Modify: `internal/policy/http_service_check.go`
- Modify: `internal/policy/http_service_check_test.go`

- [ ] **Step 5.1: Write the tests first**

Add to `internal/policy/http_service_check_test.go`:

```go
func TestDeclaredHTTPServiceHost(t *testing.T) {
	svcs := []HTTPService{{
		Name:     "github",
		Upstream: "https://api.github.com",
		ExposeAs: "GITHUB_API_URL",
		Aliases:  []string{"api.github.example"},
	}}
	e := newTestEngineForHTTP(t, svcs)

	tests := []struct {
		host    string
		wantOK  bool
		wantSvc string
		wantEnv string
	}{
		{"api.github.com", true, "github", "GITHUB_API_URL"},
		{"API.GITHUB.COM", true, "github", "GITHUB_API_URL"},
		{"api.github.com:443", true, "github", "GITHUB_API_URL"},
		{"api.github.example", true, "github", "GITHUB_API_URL"},
		{"example.com", false, "", ""},
		{"", false, "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.host, func(t *testing.T) {
			svc, env, ok := e.DeclaredHTTPServiceHost(tc.host)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if svc != tc.wantSvc || env != tc.wantEnv {
				t.Errorf("got (%q, %q), want (%q, %q)", svc, env, tc.wantSvc, tc.wantEnv)
			}
		})
	}
}

func TestHTTPServicesEnumeration(t *testing.T) {
	svcs := []HTTPService{
		{Name: "a", Upstream: "https://a.example.com"},
		{Name: "b", Upstream: "https://b.example.com"},
	}
	e := newTestEngineForHTTP(t, svcs)
	got := e.HTTPServices()
	if len(got) != 2 {
		t.Fatalf("got %d, want 2", len(got))
	}
	if got[0].Name != "a" || got[1].Name != "b" {
		t.Errorf("ordering not preserved: %+v", got)
	}
}
```

- [ ] **Step 5.2: Run tests — expect FAIL**

```bash
go test ./internal/policy/ -run "TestDeclaredHTTPServiceHost|TestHTTPServicesEnumeration" -v
```

Expected: FAIL (undefined methods).

- [ ] **Step 5.3: Implement the getters**

Append to `internal/policy/http_service_check.go`:

```go
// DeclaredHTTPServiceHost reports whether host belongs to a declared
// http_services entry. host may include a port (stripped before lookup)
// and may be in any case. Returns the canonical service name and the
// env var name used by the gateway, for inclusion in guidance messages.
func (e *Engine) DeclaredHTTPServiceHost(host string) (serviceName, envVar string, ok bool) {
	h := stripHTTPServiceHostPort(host)
	h = strings.ToLower(strings.TrimSuffix(h, "."))
	cs, found := e.httpServiceHosts[h]
	if !found {
		return "", "", false
	}
	return cs.cfg.Name, cs.envVar, true
}

// HTTPServices returns the source config list. Used by the proxy to
// enumerate declared services for EnvVars() injection. Returns a shallow
// copy so callers cannot mutate the engine's state.
func (e *Engine) HTTPServices() []HTTPService {
	if len(e.httpServices) == 0 {
		return nil
	}
	out := make([]HTTPService, 0, len(e.policy.HTTPServices))
	out = append(out, e.policy.HTTPServices...)
	return out
}

// stripHTTPServiceHostPort removes the :port suffix, preserving IPv6
// brackets if present. Mirrors net/http's behavior for Host headers.
func stripHTTPServiceHostPort(host string) string {
	if strings.HasPrefix(host, "[") {
		if i := strings.Index(host, "]:"); i != -1 {
			return host[:i+1]
		}
		return host
	}
	if i := strings.LastIndex(host, ":"); i != -1 {
		return host[:i]
	}
	return host
}
```

- [ ] **Step 5.4: Run tests**

```bash
go test ./internal/policy/ -run "TestDeclaredHTTPServiceHost|TestHTTPServicesEnumeration" -v
```

Expected: PASS.

- [ ] **Step 5.5: Commit**

```bash
git add internal/policy/http_service_check.go internal/policy/http_service_check_test.go
git commit -m "feat(policy): add DeclaredHTTPServiceHost and HTTPServices

DeclaredHTTPServiceHost resolves a Host header (with optional port,
case, IPv6 brackets) to the owning service name and env var, for
netmonitor's fail-closed check. HTTPServices returns the source
config list for gateway env-var plumbing."
```

---

## Task 6: Extend Proxy.EnvVars() to emit per-service entries

**Files:**
- Modify: `internal/proxy/proxy.go`
- Modify: `internal/proxy/proxy_test.go` (or create)

- [ ] **Step 6.1: Find the existing EnvVars method**

Read `internal/proxy/proxy.go` around line 672 (where the summary says `EnvVars()` lives):

```bash
grep -n "func (p \*Proxy) EnvVars" internal/proxy/proxy.go
```

The method currently returns a map with `ANTHROPIC_BASE_URL`, `OPENAI_BASE_URL`, and `AGENTSH_SESSION_ID`. You will extend it to also include per-service entries from the policy engine.

- [ ] **Step 6.2: Add an accessor method on Proxy for the policy engine**

Look for whether `p.policy` is already stored on `*Proxy`. If it is — good, use it. If not, add it.

The LLM proxy is constructed in `internal/api/app.go` (around line 433 per the spec). If the policy engine isn't yet passed in, you will need to add it — but in practice, the proxy currently accesses policy via several paths (`p.getRegistry()`, MCP intercept, etc.). Add a `policy *policy.Engine` field on `Proxy` if one doesn't already exist, and wire it through `Config` or a setter.

**Decision point:** if adding a field requires touching many construction sites, instead add a new setter `func (p *Proxy) SetHTTPServices(svcs []policy.HTTPService)` and call it from the construction site in `app.go`. This keeps the blast radius minimal.

- [ ] **Step 6.3: Write the test first**

Add to `internal/proxy/proxy_test.go` (or create if needed):

```go
func TestEnvVars_IncludesDeclaredServices(t *testing.T) {
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	// Simulate the proxy having started with a bound listener.
	p.setAddrForTest("127.0.0.1:12345")

	p.SetHTTPServices([]policy.HTTPService{
		{Name: "github", Upstream: "https://api.github.com", ExposeAs: "GITHUB_API_URL"},
		{Name: "stripe", Upstream: "https://api.stripe.com"},
	})

	env := p.EnvVars()
	if got := env["GITHUB_API_URL"]; got != "http://127.0.0.1:12345/svc/github" {
		t.Errorf("GITHUB_API_URL = %q", got)
	}
	if got := env["STRIPE_API_URL"]; got != "http://127.0.0.1:12345/svc/stripe" {
		t.Errorf("STRIPE_API_URL = %q", got)
	}
	if _, ok := env["ANTHROPIC_BASE_URL"]; !ok {
		t.Error("ANTHROPIC_BASE_URL should still be set")
	}
}
```

Note: `setAddrForTest` does not exist yet; add it in the next step as an unexported-but-accessible-from-test helper.

- [ ] **Step 6.4: Extend EnvVars() and add the test helper**

In `internal/proxy/proxy.go`:

```go
// SetHTTPServices stores the declared HTTP services for env var injection.
// Called once during proxy startup in app.go. Thread-safe.
func (p *Proxy) SetHTTPServices(svcs []policy.HTTPService) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpServices = svcs
}

// EnvVars returns the environment variables that the gateway injects into
// child processes. In addition to the LLM base URLs, this now includes one
// entry per declared http_services entry.
func (p *Proxy) EnvVars() map[string]string {
	env := map[string]string{
		// ... existing LLM entries ...
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	addr := p.listenerAddr
	for _, svc := range p.httpServices {
		name := svc.ExposeAs
		if name == "" {
			name = strings.ToUpper(svc.Name) + "_API_URL"
		}
		env[name] = "http://" + addr + "/svc/" + svc.Name
	}
	return env
}
```

Keep the existing LLM entries in place; the new code appends after them.

Add the test helper at the bottom of `internal/proxy/proxy.go` (or a new `proxy_testing.go` file):

```go
// setAddrForTest lets tests populate the listener address without
// actually binding a socket. Unexported to keep it out of the public API.
func (p *Proxy) setAddrForTest(addr string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listenerAddr = addr
}
```

You will also need a `listenerAddr string` field on the `Proxy` struct, populated from `listener.Addr().String()` when `Start` runs. Look for where `p.listener = listener` happens and add `p.listenerAddr = listener.Addr().String()` right after.

- [ ] **Step 6.5: Run tests**

```bash
go test ./internal/proxy/ -run TestEnvVars_IncludesDeclaredServices -v
go test ./internal/proxy/ -v
```

Expected: new test PASS. Existing tests should still PASS.

- [ ] **Step 6.6: Commit**

```bash
git add internal/proxy/proxy.go internal/proxy/proxy_test.go
git commit -m "feat(proxy): extend EnvVars with per-service base URLs

Adds SetHTTPServices and extends EnvVars() to emit <NAME>_API_URL
entries pointing at /svc/<name> on the proxy listener. Callers inject
these into child env so SDKs can route via base URL override."
```

---

## Task 7: Path-prefix dispatch in ServeHTTP

**Files:**
- Create: `internal/proxy/declared_service.go`
- Modify: `internal/proxy/proxy.go`
- Create: `internal/proxy/declared_service_test.go`

- [ ] **Step 7.1: Write the dispatch test first**

Create `internal/proxy/declared_service_test.go`:

```go
package proxy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func newTestProxyWithHTTPService(t *testing.T, upstream string, rules []policy.HTTPServiceRule) *Proxy {
	t.Helper()
	cfg := Config{SessionID: "test-session"}
	p, err := New(cfg, "", nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	svcs := []policy.HTTPService{{
		Name: "github", Upstream: upstream, Default: "deny", Rules: rules,
	}}
	if err := policy.ValidateHTTPServices(svcs); err != nil {
		t.Fatalf("validate: %v", err)
	}
	pol := &policy.Policy{HTTPServices: svcs}
	eng, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	p.SetPolicyEngine(eng) // see step 7.3
	p.SetHTTPServices(svcs)
	return p
}

func TestServeHTTP_PathPrefixDispatch_NoSuchService(t *testing.T) {
	p := newTestProxyWithHTTPService(t, "https://api.github.com", nil)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/nosuch/foo", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "no such service") {
		t.Errorf("body = %q, want 'no such service'", body)
	}
}
```

- [ ] **Step 7.2: Run test — expect FAIL**

```bash
go test ./internal/proxy/ -run TestServeHTTP_PathPrefixDispatch_NoSuchService -v
```

Expected: compile error (SetPolicyEngine / dispatch logic not yet added).

- [ ] **Step 7.3: Add SetPolicyEngine and the declaredService helper**

Create `internal/proxy/declared_service.go`:

```go
package proxy

import (
	"io"
	"net/http"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)

const declaredServicePathPrefix = "/svc/"

// SetPolicyEngine wires the policy engine for http_services dispatch.
// Called once during startup.
func (p *Proxy) SetPolicyEngine(e *policy.Engine) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.policyEngine = e
}

// declaredService resolves a request path to a compiled http_service entry
// if the path starts with /svc/<name>/. Returns the service name, the
// remaining path (starting with '/'), and ok=true when resolved.
//
// A path that starts with /svc/ but names a service that does not exist
// returns ok=false with name != "". Callers use the name vs "" distinction
// to decide between "fall through to LLM path" (no /svc/ prefix) and
// "return 404 for unknown declared service".
func (p *Proxy) declaredService(reqPath string) (name, rest string, ok bool) {
	if !strings.HasPrefix(reqPath, declaredServicePathPrefix) {
		return "", "", false
	}
	tail := strings.TrimPrefix(reqPath, declaredServicePathPrefix)
	slash := strings.IndexByte(tail, '/')
	if slash == -1 {
		name = tail
		rest = "/"
	} else {
		name = tail[:slash]
		rest = tail[slash:]
	}
	if name == "" {
		return "", "", false
	}

	p.mu.Lock()
	eng := p.policyEngine
	p.mu.Unlock()
	if eng == nil {
		// Not yet wired — treat as unknown so tests with no engine don't crash.
		return name, rest, false
	}
	// Look up by calling an Engine method that tells us if the service exists.
	// We reuse CheckHTTPService to NOT call here; instead just check via a
	// cheap lookup. For now use the enumeration API: iterate HTTPServices.
	for _, svc := range eng.HTTPServices() {
		if strings.EqualFold(svc.Name, name) {
			return svc.Name, rest, true
		}
	}
	return name, rest, false
}
```

Add the new field to the `Proxy` struct in `proxy.go`:

```go
type Proxy struct {
	// ... existing fields ...
	httpServices []policy.HTTPService
	policyEngine *policy.Engine
}
```

- [ ] **Step 7.4: Add the dispatch branch to ServeHTTP**

In `internal/proxy/proxy.go`, at the top of `ServeHTTP` (right after the request-ID generation and startTime), add:

```go
// Declared HTTP service dispatch — check before LLM dialect detection.
if name, rest, ok := p.declaredService(r.URL.Path); ok {
	p.serveDeclaredService(w, r, name, rest, requestID, startTime)
	return
} else if name != "" {
	// Path starts with /svc/<name>/ but the service is not declared.
	// Return a dedicated 404 instead of falling through to dialect
	// detection, so operators aren't confused by "unknown LLM dialect".
	http.Error(w, "no such service", http.StatusNotFound)
	return
}
```

Add a stub `serveDeclaredService` to `declared_service.go` so it compiles:

```go
// serveDeclaredService handles a request routed to a declared http_service.
// See docs/superpowers/specs/2026-04-10-http-path-verb-filtering-design.md §2.
func (p *Proxy) serveDeclaredService(w http.ResponseWriter, r *http.Request, svcName, reqPath, requestID string, startTime time.Time) {
	// TODO: fleshed out in Task 8. For Task 7, just 501 so tests exercising
	// the dispatch path (not the handler) pass.
	http.Error(w, "not implemented", http.StatusNotImplemented)
}
```

Wait — that TODO violates the "no placeholders" rule. Instead: implement the skeleton that makes the dispatch test pass without body forwarding. Replace the stub with:

```go
func (p *Proxy) serveDeclaredService(w http.ResponseWriter, r *http.Request, svcName, reqPath, requestID string, startTime time.Time) {
	// Look up the compiled service via the engine (redundant with
	// declaredService above, but keeps serveDeclaredService self-contained
	// for later extension).
	p.mu.Lock()
	eng := p.policyEngine
	p.mu.Unlock()
	if eng == nil {
		http.Error(w, "http_services not configured", http.StatusInternalServerError)
		return
	}

	// Strip query string before evaluation — the evaluator does not look at it.
	pathForEval := reqPath
	if idx := strings.IndexByte(pathForEval, '?'); idx != -1 {
		pathForEval = pathForEval[:idx]
	}

	dec := eng.CheckHTTPService(svcName, r.Method, pathForEval)

	switch dec.EffectiveDecision {
	case "deny":
		msg := dec.Message
		if msg == "" {
			msg = "blocked by http_services rule"
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	case "allow", "audit":
		// Forwarding implemented in Task 8. For now, return 501 so we
		// can prove the deny path while Task 8 is in progress.
		http.Error(w, "forwarding not implemented", http.StatusNotImplemented)
		return
	default:
		http.Error(w, "unsupported decision", http.StatusInternalServerError)
		return
	}
}
```

Add the required imports (`time`, `io`) as needed. The `io` import is needed only once the full handler lands in Task 8.

- [ ] **Step 7.5: Run the dispatch test**

```bash
go build ./internal/proxy/
go test ./internal/proxy/ -run TestServeHTTP_PathPrefixDispatch_NoSuchService -v
```

Expected: PASS.

Add a deny-path test as well:

```go
func TestServeDeclaredService_Deny(t *testing.T) {
	p := newTestProxyWithHTTPService(t, "https://api.github.com", []policy.HTTPServiceRule{
		{Name: "block-delete", Methods: []string{"DELETE"}, Paths: []string{"/repos/**"}, Decision: "deny", Message: "no deletes"},
	})

	req := httptest.NewRequest(http.MethodDelete, "http://127.0.0.1/svc/github/repos/a/b", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
	body, _ := io.ReadAll(w.Body)
	if !strings.Contains(string(body), "no deletes") {
		t.Errorf("body = %q, want 'no deletes'", body)
	}
}
```

Run it:

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_Deny -v
```

Expected: PASS.

- [ ] **Step 7.6: Commit**

```bash
git add internal/proxy/declared_service.go internal/proxy/declared_service_test.go internal/proxy/proxy.go
git commit -m "feat(proxy): /svc/<name>/ dispatch for declared http_services

Adds path-prefix dispatch at the top of ServeHTTP. Unknown service
under /svc/ returns 404 instead of falling through to LLM dialect
detection. Deny rule returns 403 with the rule message. Allow/audit
path returns 501 pending Task 8."
```

---

## Task 8: Forward allow/audit decisions to the upstream

**Files:**
- Modify: `internal/proxy/declared_service.go`
- Modify: `internal/proxy/declared_service_test.go`

- [ ] **Step 8.1: Write the forwarding test**

Add to `internal/proxy/declared_service_test.go`:

```go
func TestServeDeclaredService_Allow_Forwards(t *testing.T) {
	// Fake upstream that records the incoming request.
	var gotMethod, gotPath string
	var gotBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"ok":true}`)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "post-issues", Methods: []string{"POST"}, Paths: []string{"/repos/*/*/issues"}, Decision: "allow"},
	})

	body := strings.NewReader(`{"title":"bug"}`)
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/repos/anthropics/claude-code/issues", body)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", w.Code)
	}
	if gotMethod != "POST" {
		t.Errorf("upstream method = %q, want POST", gotMethod)
	}
	if gotPath != "/repos/anthropics/claude-code/issues" {
		t.Errorf("upstream path = %q, want /repos/anthropics/claude-code/issues", gotPath)
	}
	if string(gotBody) != `{"title":"bug"}` {
		t.Errorf("upstream body = %q", gotBody)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("response Content-Type = %q, want application/json", ct)
	}
}
```

Note the test uses `upstream.URL` — that's `http://127.0.0.1:<rand>`. For tests, the gateway must accept an `http://` upstream, not just `https://`. To make this work without weakening production validation, add a test-only knob:

- Either skip the `https` validation in `ValidateHTTPServices` when the upstream host is `127.0.0.1` / `localhost` (ugly).
- Or inject a transport override via a test helper (cleaner).

**Chosen approach:** inject a transport override. Add a test helper `SetUpstreamTransportForTest(rt http.RoundTripper)` on `Proxy`, and relax the `https` check to accept `http://` URLs whose host is `127.0.0.1` or `localhost`. Rationale: test-facing but the relaxation is trivially recognized and documented.

Actually, the cleanest approach: add a build-time test hook (`httpsvcTestAllowInsecure` bool) in `ValidateHTTPServices` that is set only in `_test.go` files via a package-scoped helper. Simpler:

```go
// In http_service.go, add a package var:
var httpServiceAllowInsecureUpstreamForTest bool

// In ValidateHTTPServices, replace:
//   if u.Scheme != "https" { ... }
// with:
if u.Scheme != "https" && !(httpServiceAllowInsecureUpstreamForTest && u.Scheme == "http") {
    return fmt.Errorf("...")
}
```

And in the test init:

```go
func init() {
    httpServiceAllowInsecureUpstreamForTest = true
}
```

Place the `init()` in `internal/proxy/declared_service_test.go` so it only applies during `go test` of that package.

- [ ] **Step 8.2: Relax the validator for tests**

Edit `internal/policy/http_service.go` to add the test toggle:

```go
// httpServiceAllowInsecureUpstreamForTest, when true, lets ValidateHTTPServices
// accept http:// upstreams. Set from test init() functions only. Never set in
// production code.
var httpServiceAllowInsecureUpstreamForTest bool

// TestAllowInsecureHTTPServiceUpstream enables the test-only relaxation.
// This function exists so test files in other packages can flip the toggle
// without touching package-private state. Not thread-safe.
func TestAllowInsecureHTTPServiceUpstream(v bool) {
	httpServiceAllowInsecureUpstreamForTest = v
}
```

Update the scheme check in `ValidateHTTPServices`:

```go
if u.Scheme != "https" && !(httpServiceAllowInsecureUpstreamForTest && u.Scheme == "http") {
    return fmt.Errorf("http_services[%q]: upstream must be https (got %q)", s.Name, u.Scheme)
}
```

Add an `init()` to `internal/proxy/declared_service_test.go`:

```go
func init() {
	policy.TestAllowInsecureHTTPServiceUpstream(true)
}
```

- [ ] **Step 8.3: Run the forwarding test — expect FAIL**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_Allow_Forwards -v
```

Expected: FAIL (current allow branch returns 501).

- [ ] **Step 8.4: Implement forwarding**

Rewrite the allow/audit branch in `serveDeclaredService`. Replace the entire method in `internal/proxy/declared_service.go`:

```go
func (p *Proxy) serveDeclaredService(w http.ResponseWriter, r *http.Request, svcName, reqPath, requestID string, startTime time.Time) {
	p.mu.Lock()
	eng := p.policyEngine
	p.mu.Unlock()
	if eng == nil {
		http.Error(w, "http_services not configured", http.StatusInternalServerError)
		return
	}

	pathForEval := reqPath
	if idx := strings.IndexByte(pathForEval, '?'); idx != -1 {
		pathForEval = pathForEval[:idx]
	}

	dec := eng.CheckHTTPService(svcName, r.Method, pathForEval)

	switch dec.EffectiveDecision {
	case "deny":
		msg := dec.Message
		if msg == "" {
			msg = "blocked by http_services rule"
		}
		http.Error(w, msg, http.StatusForbidden)
		return
	case "allow", "audit":
		// Proceed to forwarding.
	default:
		http.Error(w, "unsupported decision", http.StatusInternalServerError)
		return
	}

	svc := p.findHTTPService(eng, svcName)
	if svc == nil {
		http.Error(w, "service vanished", http.StatusInternalServerError)
		return
	}

	outReq, err := p.buildUpstreamRequest(r, svc.Upstream, reqPath)
	if err != nil {
		http.Error(w, "rewrite failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := p.httpServiceTransport().RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers and status, then body.
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// findHTTPService looks up a service by name from the engine's enumeration.
// Used in the serve path to access fields (Upstream, ExposeAs) that are
// not in the Decision struct.
func (p *Proxy) findHTTPService(eng *policy.Engine, name string) *policy.HTTPService {
	for _, s := range eng.HTTPServices() {
		if strings.EqualFold(s.Name, name) {
			s := s
			return &s
		}
	}
	return nil
}

// buildUpstreamRequest clones the inbound request and retargets it at
// svcUpstream + reqPath + (optional query string). Preserves method, body,
// and headers. Does NOT apply hooks — hooks are called by the caller.
func (p *Proxy) buildUpstreamRequest(r *http.Request, svcUpstream, reqPath string) (*http.Request, error) {
	u, err := url.Parse(svcUpstream)
	if err != nil {
		return nil, err
	}
	// Preserve query string if present on the inbound request.
	rawQuery := r.URL.RawQuery
	u.Path = singleSlashJoin(u.Path, reqPath)
	u.RawQuery = rawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, u.String(), r.Body)
	if err != nil {
		return nil, err
	}
	// Copy headers, excluding hop-by-hop.
	for k, vs := range r.Header {
		if isHopByHopHeader(k) {
			continue
		}
		for _, v := range vs {
			outReq.Header.Add(k, v)
		}
	}
	outReq.Host = u.Host
	outReq.ContentLength = r.ContentLength
	return outReq, nil
}

func singleSlashJoin(a, b string) string {
	aSlash := strings.HasSuffix(a, "/")
	bSlash := strings.HasPrefix(b, "/")
	switch {
	case aSlash && bSlash:
		return a + b[1:]
	case !aSlash && !bSlash:
		return a + "/" + b
	}
	return a + b
}

func isHopByHopHeader(h string) bool {
	switch strings.ToLower(h) {
	case "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
		"te", "trailer", "transfer-encoding", "upgrade":
		return true
	}
	return false
}

// httpServiceTransport returns the transport used to forward declared-service
// requests. Currently http.DefaultTransport; testable via the setter below.
func (p *Proxy) httpServiceTransport() http.RoundTripper {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.httpSvcTransport != nil {
		return p.httpSvcTransport
	}
	return http.DefaultTransport
}

// SetHTTPServiceTransportForTest injects a RoundTripper used for
// declared-service forwarding. Test-only.
func (p *Proxy) SetHTTPServiceTransportForTest(rt http.RoundTripper) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpSvcTransport = rt
}
```

Add the field to the struct in `proxy.go`:

```go
type Proxy struct {
	// ... existing fields ...
	httpSvcTransport http.RoundTripper
}
```

Add missing imports to `declared_service.go`: `net/url`, `time`.

- [ ] **Step 8.5: Run the test**

```bash
go build ./internal/proxy/
go test ./internal/proxy/ -run TestServeDeclaredService_Allow_Forwards -v
```

Expected: PASS.

Also run the full proxy test suite to catch regressions:

```bash
go test ./internal/proxy/ -v
```

- [ ] **Step 8.6: Commit**

```bash
git add internal/proxy/declared_service.go internal/proxy/declared_service_test.go internal/proxy/proxy.go internal/policy/http_service.go
git commit -m "feat(proxy): forward allow decisions to upstream

serveDeclaredService now builds a fresh outbound request targeting the
service upstream, strips hop-by-hop headers, preserves method/body/
query/headers, and copies the response back to the caller.

Adds a package-private test toggle in internal/policy that lets tests
point at an httptest.Server over http://. Production upstreams still
must be https."
```

---

## Task 9: Wire hooks into the declared-service path

**Files:**
- Modify: `internal/proxy/declared_service.go`
- Modify: `internal/proxy/declared_service_test.go`

- [ ] **Step 9.1: Write the hook test**

Add to `internal/proxy/declared_service_test.go`:

```go
func TestServeDeclaredService_HooksRunPerService(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "get", Methods: []string{"GET"}, Paths: []string{"/**"}, Decision: "allow"},
	})

	// Register a hook under "github" that sets the Authorization header.
	p.HookRegistry().Register("github", &serviceRecorderHook{
		name: "fake-injector",
		preFn: func(r *http.Request, ctx *RequestContext) error {
			r.Header.Set("Authorization", "Bearer real-token")
			if ctx.ServiceName != "github" {
				t.Errorf("ctx.ServiceName = %q, want github", ctx.ServiceName)
			}
			return nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if gotAuth != "Bearer real-token" {
		t.Errorf("upstream Authorization = %q, want 'Bearer real-token'", gotAuth)
	}
}
```

`serviceRecorderHook` already exists in `internal/proxy/proxy_hooks_test.go`; reuse it.

- [ ] **Step 9.2: Run test — expect FAIL**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_HooksRunPerService -v
```

Expected: FAIL — hooks are not yet invoked.

- [ ] **Step 9.3: Call hookRegistry from serveDeclaredService**

In `internal/proxy/declared_service.go`, after the decision switch and before `buildUpstreamRequest`, add hook invocation. Replace the allow/audit branch and the forwarding code with:

```go
case "allow", "audit":
    // fall through
default:
    http.Error(w, "unsupported decision", http.StatusInternalServerError)
    return
}

// Build RequestContext for hook dispatch.
reqCtx := &RequestContext{
    RequestID:   requestID,
    SessionID:   p.sessionIDFor(r),
    ServiceName: svcName,
    StartTime:   startTime,
    Attrs:       make(map[string]any),
}

// Buffer the request body so hooks can read/replace it without
// exhausting the stream.
if r.Body != nil {
    body, err := io.ReadAll(r.Body)
    if err == nil {
        r.Body = io.NopCloser(bytes.NewReader(body))
        r.ContentLength = int64(len(body))
    }
}

if p.hookRegistry != nil {
    if err := p.hookRegistry.ApplyPreHooks(svcName, r, reqCtx); err != nil {
        var abortErr *HookAbortError
        if errors.As(err, &abortErr) {
            code := abortErr.StatusCode
            if code < 400 || code > 599 {
                code = http.StatusBadGateway
            }
            http.Error(w, abortErr.Message, code)
            return
        }
        http.Error(w, "hook error: "+err.Error(), http.StatusBadGateway)
        return
    }
}
```

Then continue with `buildUpstreamRequest` / forwarding / response copy as before.

Add `p.sessionIDFor(r)` helper (if one doesn't already exist — look at how the LLM path reads session ID):

```go
func (p *Proxy) sessionIDFor(r *http.Request) string {
    if sid := r.Header.Get("X-Session-ID"); sid != "" {
        return sid
    }
    return p.cfg.SessionID
}
```

Add imports: `bytes`, `errors`. `HookAbortError` and `RequestContext` already exist in the package.

- [ ] **Step 9.4: Run the test**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_HooksRunPerService -v
```

Expected: PASS.

Also run the full proxy suite:

```bash
go test ./internal/proxy/ -v
```

- [ ] **Step 9.5: Commit**

```bash
git add internal/proxy/declared_service.go internal/proxy/declared_service_test.go
git commit -m "feat(proxy): dispatch service-scoped hooks in declared path

serveDeclaredService now invokes hookRegistry.ApplyPreHooks with the
service name, buffering the request body first so hooks can substitute
it. Plan 6's HeaderInjectionHook and CredsSubHook both Just Work under
the new dispatch because they already key on ServiceName."
```

---

## Task 10: Approval gating for approve decisions

**Files:**
- Modify: `internal/proxy/declared_service.go`
- Modify: `internal/proxy/declared_service_test.go`

**Design decision for this task:** do NOT lift `maybeApprove` from netmonitor yet. Duplicate the logic inline in `declared_service.go` with a clear comment referencing the original. A future refactor task can consolidate both call sites into `internal/approvals` or a shared helper; for v1, duplication has the smallest blast radius.

- [ ] **Step 10.1: Write the approval test**

Add to `internal/proxy/declared_service_test.go`:

```go
type fakeApprovalsManager struct {
	approve bool
}

func (f *fakeApprovalsManager) RequestApproval(ctx context.Context, req approvals.Request) (approvals.Result, error) {
	return approvals.Result{Approved: f.approve}, nil
}

func TestServeDeclaredService_Approve_Approved(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/issues"}, Decision: "approve"},
	})
	p.SetApprovalsForTest(&fakeApprovalsManager{approve: true})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/issues", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
}

func TestServeDeclaredService_Approve_Denied(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("upstream should not be reached when approval denies")
	}))
	defer upstream.Close()

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "require-approval", Methods: []string{"POST"}, Paths: []string{"/issues"}, Decision: "approve"},
	})
	p.SetApprovalsForTest(&fakeApprovalsManager{approve: false})

	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/svc/github/issues", strings.NewReader("{}"))
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", w.Code)
	}
}
```

`approvals.Request` / `approvals.Result` live in `internal/approvals`; import the package. `fakeApprovalsManager` implements whatever interface the engine expects — confirm by reading `internal/approvals/manager.go` before writing this test and adjust the method signature if needed.

- [ ] **Step 10.2: Run — expect FAIL**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_Approve -v
```

Expected: compile error (`SetApprovalsForTest` / approval logic not implemented).

- [ ] **Step 10.3: Implement approval path**

Add to `internal/proxy/declared_service.go`:

```go
import (
	"context"
	// ... existing imports ...

	"github.com/agentsh/agentsh/internal/approvals"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/google/uuid"
)

// HTTPServiceApprovalsManager is the subset of approvals.Manager needed by
// the declared-service path. Declared here as a local interface to keep
// the import surface narrow and to simplify testing.
type HTTPServiceApprovalsManager interface {
	RequestApproval(ctx context.Context, req approvals.Request) (approvals.Result, error)
}

// SetApprovalsForTest installs an approvals manager for the declared-
// service path. In production, wiring flows from app.go through
// SetHTTPServiceApprovals. Kept as an explicit test setter to make the
// dependency visible.
func (p *Proxy) SetApprovalsForTest(m HTTPServiceApprovalsManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpSvcApprovals = m
}

// SetHTTPServiceApprovals is the production wiring hook, called from
// app.go alongside SetPolicyEngine and SetHTTPServices.
func (p *Proxy) SetHTTPServiceApprovals(m HTTPServiceApprovalsManager) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.httpSvcApprovals = m
}
```

Add the field to `Proxy`:

```go
httpSvcApprovals HTTPServiceApprovalsManager
```

Insert approval gating into `serveDeclaredService` after `CheckHTTPService` and before the deny/allow switch:

```go
// Gate approve decisions on an interactive approval. This mirrors the
// logic in internal/netmonitor/proxy.go maybeApprove; see the spec for
// the plan to consolidate these into a shared helper.
if dec.PolicyDecision == types.DecisionApprove && dec.EffectiveDecision == types.DecisionApprove {
	p.mu.Lock()
	appr := p.httpSvcApprovals
	p.mu.Unlock()
	if appr != nil {
		req := approvals.Request{
			ID:        "approval-" + uuid.NewString(),
			SessionID: reqCtx.SessionID, // built after this block in Task 9; move construction earlier
			CommandID: requestID,
			Kind:      "http_service",
			Target:    svcName + " " + r.Method + " " + pathForEval,
			Rule:      dec.Rule,
			Message:   dec.Message,
		}
		res, err := appr.RequestApproval(r.Context(), req)
		if dec.Approval != nil {
			dec.Approval.ID = req.ID
		}
		if err != nil || !res.Approved {
			dec.EffectiveDecision = types.DecisionDeny
		} else {
			dec.EffectiveDecision = types.DecisionAllow
		}
	}
}
```

Note the comment about moving the `RequestContext` construction earlier — Task 9 built it after the decision. Move it before this block so `reqCtx.SessionID` is populated. Restructure as:

```go
reqCtx := &RequestContext{
    RequestID:   requestID,
    SessionID:   p.sessionIDFor(r),
    ServiceName: svcName,
    StartTime:   startTime,
    Attrs:       make(map[string]any),
}

dec := eng.CheckHTTPService(svcName, r.Method, pathForEval)

// Approval gating (see comment above).
// ... approval block ...

switch dec.EffectiveDecision {
case "deny":
    // ... existing deny handling ...
case "allow", "audit":
    // fall through to hook invocation and forwarding
}

// Hook invocation (Task 9).
// Body buffering (Task 9).
// buildUpstreamRequest + forward (Task 8).
```

- [ ] **Step 10.4: Run the approval tests**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_Approve -v
```

Expected: both PASS.

- [ ] **Step 10.5: Commit**

```bash
git add internal/proxy/declared_service.go internal/proxy/declared_service_test.go internal/proxy/proxy.go
git commit -m "feat(proxy): approval gating for approve decisions

Adds approval flow to serveDeclaredService mirroring netmonitor's
maybeApprove. Duplicated intentionally for minimal blast radius; a
future refactor task will consolidate both call sites into a shared
helper in internal/approvals."
```

---

## Task 11: Wire startup plumbing in app.go

**Files:**
- Modify: `internal/api/app.go`

This task wires the proxy's new setters to the real construction path.

- [ ] **Step 11.1: Find the proxy construction**

```bash
grep -n "proxy.New\|StartLLMProxy\|proxy\.Start" internal/api/app.go
```

Locate where the LLM proxy is constructed and started. The existing code already passes the policy engine somewhere — find it (`a.policy` is likely the reference).

- [ ] **Step 11.2: Wire the three setters**

After `proxy.New(...)` (or equivalent) and before the proxy is started (`proxy.Start(...)`) or handed to the session launcher, add:

```go
p.SetPolicyEngine(a.policy)
p.SetHTTPServices(a.policy.HTTPServices())
if a.approvals != nil {
	p.SetHTTPServiceApprovals(a.approvals)
}
```

The approvals manager on `a.approvals` already satisfies `HTTPServiceApprovalsManager` (it has a `RequestApproval(ctx, req)` method — confirm by reading `internal/approvals/manager.go`).

- [ ] **Step 11.3: Build everything**

```bash
go build ./...
```

Expected: no errors. If there are errors in app.go from mismatched types, investigate — the common issue is `a.approvals` being a concrete type whose `RequestApproval` signature differs slightly from the interface. Adjust the `HTTPServiceApprovalsManager` interface to match.

- [ ] **Step 11.4: Run full test suite**

```bash
go test ./...
```

Expected: PASS. Any failing tests probably need `p.SetPolicyEngine` injection in their harness; fix them.

- [ ] **Step 11.5: Commit**

```bash
git add internal/api/app.go
git commit -m "feat(api): wire http_services plumbing into proxy construction

Calls SetPolicyEngine, SetHTTPServices, and SetHTTPServiceApprovals
on the proxy during session setup so declared services are reachable
via /svc/<name>/ and approve rules gate on the real approval manager."
```

---

## Task 12: Netmonitor fail-closed CONNECT and HTTP checks

**Files:**
- Modify: `internal/netmonitor/proxy.go`
- Modify: `internal/netmonitor/proxy_test.go` (or create)

- [ ] **Step 12.1: Write the fail-closed tests**

Find an existing netmonitor test file and add, or create `internal/netmonitor/declared_services_test.go`:

```go
package netmonitor

import (
	"bufio"
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func newTestEngineWithGitHubService(t *testing.T) *policy.Engine {
	t.Helper()
	pol := &policy.Policy{
		HTTPServices: []policy.HTTPService{{
			Name: "github", Upstream: "https://api.github.com", ExposeAs: "GITHUB_API_URL",
		}},
	}
	if err := policy.ValidateHTTPServices(pol.HTTPServices); err != nil {
		t.Fatalf("validate: %v", err)
	}
	e, err := policy.NewEngine(pol, true, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func TestHandleConnect_DeniesDeclaredHost(t *testing.T) {
	// Test harness: construct a minimal netmonitor.Proxy and drive
	// handleConnect directly with a fake client.
	eng := newTestEngineWithGitHubService(t)
	p := newTestNetmonitorProxy(t, eng)

	client, server := newPipedConn(t)
	go func() {
		_, _ = client.Write([]byte("CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n"))
	}()
	req, err := http.ReadRequest(bufio.NewReader(server))
	if err != nil {
		t.Fatalf("read request: %v", err)
	}

	p.handleConnect(context.Background(), server, req, /* commandID */ "c1")

	// Read the 403 response.
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "GITHUB_API_URL") {
		t.Errorf("body = %q, want mention of GITHUB_API_URL", body)
	}
}
```

Test helpers `newTestNetmonitorProxy` and `newPipedConn` need to exist. Look at existing netmonitor tests first; if none exist, write them minimally in the same file:

```go
// newTestNetmonitorProxy builds a Proxy with just enough fields to
// exercise handleConnect. Fields that matter: policy engine, emitter.
// Everything else can be nil or a no-op.
func newTestNetmonitorProxy(t *testing.T, eng *policy.Engine) *Proxy {
	t.Helper()
	return &Proxy{
		policy:    eng,
		emit:      newNoOpEmitter(),
		sessionID: "test-session",
	}
}

func newPipedConn(t *testing.T) (client, server net.Conn) {
	// ...
}
```

- [ ] **Step 12.2: Run — expect FAIL**

```bash
go test ./internal/netmonitor/ -run TestHandleConnect_DeniesDeclaredHost -v
```

Expected: FAIL or compile error (no check implemented yet).

- [ ] **Step 12.3: Add the fail-closed check in handleConnect**

In `internal/netmonitor/proxy.go`, find `handleConnect` around line 110 and the point where `dec` is computed from `p.policy.CheckNetworkCtx(...)`. Right after that — before `maybeApprove` — add:

```go
// Fail-closed check: if the target host is declared as an
// http_services upstream, deny direct HTTPS regardless of the
// CheckNetworkCtx decision. The only way to reach the upstream is
// through the gateway via /svc/<name>/.
if svcName, envVar, ok := p.policy.DeclaredHTTPServiceHost(host); ok {
	// Respect the allow_direct escape hatch (future work: query the
	// engine for the flag; for v1, require explicit opt-out elsewhere).
	msg := "direct HTTPS to " + host + " is blocked; use " + envVar + " to route through the gateway"
	_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: "+strconv.Itoa(len(msg))+"\r\n\r\n"+msg)
	p.emitHTTPServiceDeniedDirect(ctx, commandID, svcName, envVar, host, resolvedIP)
	return nil
}
```

Add the same check to `handleHTTP` (around line 275) at the analogous point — right after `p.policy.CheckNetworkCtx(...)` and before `maybeApprove`.

Add the event helper to the same file:

```go
func (p *Proxy) emitHTTPServiceDeniedDirect(ctx context.Context, commandID, svcName, envVar, host, resolvedIP string) {
	if p.emit == nil {
		return
	}
	ev := types.Event{
		ID:        uuid.NewString(),
		Timestamp: time.Now().UTC(),
		Type:      "http_service_denied_direct",
		SessionID: p.sessionID,
		CommandID: commandID,
		Domain:    strings.ToLower(host),
		Fields: map[string]any{
			"service_name": svcName,
			"env_var":      envVar,
			"request_host": host,
			"resolved_ip":  resolvedIP,
		},
	}
	_ = p.emit.AppendEvent(ctx, ev)
	p.emit.Publish(ev)
}
```

Accounting for the `allow_direct` escape hatch: add a method `DeclaredHTTPServiceAllowsDirect(host string) bool` on `policy.Engine` and gate the block:

```go
if svcName, envVar, ok := p.policy.DeclaredHTTPServiceHost(host); ok && !p.policy.DeclaredHTTPServiceAllowsDirect(host) {
	// ... deny path ...
}
```

Implement the new engine method in `internal/policy/http_service_check.go`:

```go
// DeclaredHTTPServiceAllowsDirect returns true when the declared service
// for host has allow_direct: true set. Callers of DeclaredHTTPServiceHost
// should query this before denying direct access.
func (e *Engine) DeclaredHTTPServiceAllowsDirect(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(stripHTTPServiceHostPort(host), "."))
	cs, ok := e.httpServiceHosts[h]
	if !ok {
		return false
	}
	return cs.cfg.AllowDirect
}
```

- [ ] **Step 12.4: Run tests**

```bash
go build ./internal/netmonitor/
go test ./internal/netmonitor/ -run TestHandleConnect_DeniesDeclaredHost -v
```

Expected: PASS.

Also add a plain-HTTP test:

```go
func TestHandleHTTP_DeniesDeclaredHost(t *testing.T) {
	// Similar to TestHandleConnect_DeniesDeclaredHost but uses an HTTP
	// GET against api.github.com (not a CONNECT). Expect 403 with the
	// same guidance message.
}
```

And a regression test for the escape hatch:

```go
func TestHandleConnect_AllowDirectSkipsCheck(t *testing.T) {
	pol := &policy.Policy{
		HTTPServices: []policy.HTTPService{{
			Name: "github", Upstream: "https://api.github.com", AllowDirect: true,
		}},
	}
	// ... drive handleConnect and assert it does NOT return 403 at the
	// fail-closed check (it will likely return 403 from CheckNetworkCtx
	// unless a permissive network_rules entry is also set — design the
	// test accordingly).
}
```

- [ ] **Step 12.5: Commit**

```bash
git add internal/netmonitor/proxy.go internal/netmonitor/declared_services_test.go internal/policy/http_service_check.go
git commit -m "feat(netmonitor): fail-closed CONNECT and HTTP checks

handleConnect and handleHTTP now reject requests targeting a declared
http_services upstream with 403 and a guidance message pointing at
the env var name. allow_direct: true opts a service out of the check.
Emits http_service_denied_direct events for audit."
```

---

## Task 13: Log declared-service requests to storage

**Files:**
- Modify: `internal/proxy/storage.go`
- Modify: `internal/proxy/declared_service.go`
- Modify: `internal/proxy/declared_service_test.go`

Spec §6 ("Events and Audit") requires that declared-service traffic is auditable with the service/rule name recorded alongside each request. This task extends `RequestLogEntry` with three new fields and adds logging to `serveDeclaredService` so every request+response pair hits the same JSONL store the LLM path already writes to.

Rationale for re-using the existing `Storage` instead of adding a new event emitter: the LLM proxy already uses `Storage.LogRequest` / `LogResponse` / `StoreRequestBody` / `StoreResponseBody` as its audit trail. Declared-service traffic is exactly analogous — request/response pairs through a gateway — so it belongs in the same JSONL. Keeping the two paths on one mechanism avoids a second audit surface and matches the user-facing reality that both paths serve policy-enforced outbound HTTP.

- [ ] **Step 13.1: Extend RequestLogEntry**

Edit `internal/proxy/storage.go`. Replace the `RequestLogEntry` struct with:

```go
// RequestLogEntry represents a logged request.
type RequestLogEntry struct {
	ID          string      `json:"id"`
	SessionID   string      `json:"session_id"`
	Timestamp   time.Time   `json:"timestamp"`
	Dialect     Dialect     `json:"dialect,omitempty"`
	ServiceKind string      `json:"service_kind,omitempty"` // "llm" or "http_service"
	ServiceName string      `json:"service_name,omitempty"` // e.g. "github"
	RuleName    string      `json:"rule_name,omitempty"`    // e.g. "read-issues"
	Request     RequestInfo `json:"request"`
	DLP         *DLPInfo    `json:"dlp,omitempty"`
}
```

The change is additive: `Dialect` gains `omitempty` (existing LLM entries still carry a dialect; declared-service entries omit it). The three new fields are all optional — LLM entries leave them blank.

- [ ] **Step 13.2: Write the logging test**

Add to `internal/proxy/declared_service_test.go`:

```go
func TestServeDeclaredService_LogsRequestAndResponseToStorage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, `{"login":"octocat"}`)
	}))
	defer upstream.Close()

	// Point storage at a temp dir so we can read back the JSONL.
	tmpDir := t.TempDir()
	storage, err := NewStorage(tmpDir, "test-session", false)
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}

	p := newTestProxyWithHTTPService(t, upstream.URL, []policy.HTTPServiceRule{
		{Name: "read-user", Methods: []string{"GET"}, Paths: []string{"/user"}, Decision: "allow"},
	})
	p.SetStorageForTest(storage)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/svc/github/user", nil)
	w := httptest.NewRecorder()
	p.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}

	entries := readAllRequestLogEntries(t, tmpDir, "test-session")
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	e := entries[0]
	if e.ServiceKind != "http_service" {
		t.Errorf("ServiceKind = %q, want http_service", e.ServiceKind)
	}
	if e.ServiceName != "github" {
		t.Errorf("ServiceName = %q, want github", e.ServiceName)
	}
	if e.RuleName != "read-user" {
		t.Errorf("RuleName = %q, want read-user", e.RuleName)
	}
	if e.Request.Method != "GET" || e.Request.Path != "/user" {
		t.Errorf("Request = %+v, want GET /user", e.Request)
	}
	if e.Dialect != "" {
		t.Errorf("Dialect = %q, want empty for http_service", e.Dialect)
	}

	resps := readAllResponseLogEntries(t, tmpDir, "test-session")
	if len(resps) != 1 {
		t.Fatalf("got %d response entries, want 1", len(resps))
	}
	if resps[0].Response.Status != http.StatusOK {
		t.Errorf("response status = %d, want 200", resps[0].Response.Status)
	}
}

// readAllRequestLogEntries reads the request JSONL file for a session and
// returns every RequestLogEntry. Lives next to the test so it can inspect
// unexported storage internals if needed.
//
// Note: Storage writes requests AND responses to the same file
// (llm-requests.jsonl — see internal/proxy/storage.go). We discriminate by
// looking at which JSON fields are populated: RequestLogEntry has the
// "request" object, ResponseLogEntry has the "response" object and a
// "request_id" field.
func readAllRequestLogEntries(t *testing.T, basePath, sessionID string) []RequestLogEntry {
	t.Helper()
	lines := readLogLines(t, basePath, sessionID)
	var out []RequestLogEntry
	for _, line := range lines {
		// Skip response entries by peeking at field names.
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("unmarshal probe: %v", err)
		}
		if _, isResponse := probe["request_id"]; isResponse {
			continue
		}
		var e RequestLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode request log: %v", err)
		}
		out = append(out, e)
	}
	return out
}

func readAllResponseLogEntries(t *testing.T, basePath, sessionID string) []ResponseLogEntry {
	t.Helper()
	lines := readLogLines(t, basePath, sessionID)
	var out []ResponseLogEntry
	for _, line := range lines {
		var probe map[string]json.RawMessage
		if err := json.Unmarshal(line, &probe); err != nil {
			t.Fatalf("unmarshal probe: %v", err)
		}
		if _, isResponse := probe["request_id"]; !isResponse {
			continue
		}
		var e ResponseLogEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("decode response log: %v", err)
		}
		out = append(out, e)
	}
	return out
}

// readLogLines reads the shared JSONL log file line-by-line.
func readLogLines(t *testing.T, basePath, sessionID string) [][]byte {
	t.Helper()
	path := filepath.Join(basePath, sessionID, "llm-requests.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	var lines [][]byte
	for _, l := range bytes.Split(data, []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}
```

Add imports if missing: `bytes`, `encoding/json`, `os`, `path/filepath`.

The file is named `llm-requests.jsonl` for historical reasons — it holds every request/response the proxy touches, not just LLM ones. Do NOT rename it in this plan; a rename would break consumers reading the audit log and is out of scope for http_services.

- [ ] **Step 13.3: Add SetStorageForTest**

Add to `internal/proxy/declared_service.go`:

```go
// SetStorageForTest installs a Storage instance for the declared-service
// logging path. Production uses the same Storage that the LLM path uses;
// tests point it at a temp dir. Test-only setter to keep the dependency
// visible.
func (p *Proxy) SetStorageForTest(s *Storage) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.storage = s
}
```

`p.storage` already exists on `*Proxy` — this setter just exposes it. Confirm by reading `internal/proxy/proxy.go:55`.

- [ ] **Step 13.4: Run test — expect FAIL**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_LogsRequestAndResponseToStorage -v
```

Expected: FAIL — no logging wired into `serveDeclaredService` yet (assertions on service kind/name and log file count will fail).

- [ ] **Step 13.5: Add logging helpers**

Add to `internal/proxy/declared_service.go`:

```go
// logDeclaredServiceRequest writes a RequestLogEntry for a declared-service
// request to p.storage, mirroring how logRequest works for the LLM path but
// without a Dialect and with ServiceKind/ServiceName/RuleName set.
//
// Matches the logRequest signature so future refactors can consolidate the
// two. ruleName is the name of the rule that matched; if the decision came
// from the service default (no rule matched), ruleName is the empty string.
func (p *Proxy) logDeclaredServiceRequest(requestID, sessionID, svcName, ruleName string, r *http.Request, body []byte) {
	if p.storage == nil {
		return
	}
	entry := &RequestLogEntry{
		ID:          requestID,
		SessionID:   sessionID,
		Timestamp:   time.Now().UTC(),
		ServiceKind: "http_service",
		ServiceName: svcName,
		RuleName:    ruleName,
		Request: RequestInfo{
			Method:   r.Method,
			Path:     r.URL.Path,
			Headers:  sanitizeHeaders(r.Header),
			BodySize: len(body),
			BodyHash: HashBody(body),
		},
	}
	if err := p.storage.LogRequest(entry); err != nil {
		p.logger.Error("log declared-service request", "error", err, "request_id", requestID)
	}
	if err := p.storage.StoreRequestBody(requestID, body); err != nil {
		p.logger.Error("store declared-service request body", "error", err, "request_id", requestID)
	}
}

// logDeclaredServiceResponse mirrors logResponseDirect for the declared-
// service path. resp.Body must already be drained into respBody; the
// caller is responsible for restoring resp.Body before writing it back
// to the client.
func (p *Proxy) logDeclaredServiceResponse(requestID, sessionID string, resp *http.Response, respBody []byte, startTime time.Time) {
	if p.storage == nil {
		return
	}
	entry := &ResponseLogEntry{
		RequestID:  requestID,
		SessionID:  sessionID,
		Timestamp:  time.Now().UTC(),
		DurationMs: time.Since(startTime).Milliseconds(),
		Response: ResponseInfo{
			Status:   resp.StatusCode,
			Headers:  sanitizeHeaders(resp.Header),
			BodySize: len(respBody),
			BodyHash: HashBody(respBody),
		},
	}
	if err := p.storage.LogResponse(entry); err != nil {
		p.logger.Error("log declared-service response", "error", err, "request_id", requestID)
	}
	if err := p.storage.StoreResponseBody(requestID, respBody); err != nil {
		p.logger.Error("store declared-service response body", "error", err, "request_id", requestID)
	}
}
```

- [ ] **Step 13.6: Call the helpers from serveDeclaredService**

Edit `internal/proxy/declared_service.go`. The forwarding block from Task 8 / 9 / 10 currently does:

```go
// ... hook dispatch runs, body already buffered as `body` ...

outReq, err := p.buildUpstreamRequest(r, svc.Upstream, reqPath)
// ... error handling ...

resp, err := p.httpServiceTransport().RoundTrip(outReq)
// ... error handling ...
defer resp.Body.Close()

// Copy response headers and status, then body.
for k, vs := range resp.Header {
	for _, v := range vs {
		w.Header().Add(k, v)
	}
}
w.WriteHeader(resp.StatusCode)
_, _ = io.Copy(w, resp.Body)
```

Two changes. First, call `logDeclaredServiceRequest` right after the request body is buffered (which Task 9 already does to feed the hook dispatch). That body buffer is available as the local `body` variable — if Task 9 named it differently, rename for consistency:

```go
// After Task 9's body-buffering block, and after ApplyPreHooks returns:
p.logDeclaredServiceRequest(requestID, reqCtx.SessionID, svcName, dec.Rule, r, body)
```

Pass `dec.Rule` as `ruleName` — it holds the matched rule name from `wrapDecision` (empty string when the default fired).

Second, replace the response-copy block with a buffer-and-log version:

```go
// Buffer the response body so we can log it and still write it back.
respBody, err := io.ReadAll(resp.Body)
if err != nil {
	http.Error(w, "read upstream response: "+err.Error(), http.StatusBadGateway)
	return
}
p.logDeclaredServiceResponse(requestID, reqCtx.SessionID, resp, respBody, startTime)

for k, vs := range resp.Header {
	for _, v := range vs {
		w.Header().Add(k, v)
	}
}
w.WriteHeader(resp.StatusCode)
_, _ = w.Write(respBody)
```

This replaces `io.Copy(w, resp.Body)` with a read-then-write. For declared-service traffic this is acceptable because the bodies are bounded by real API responses (not model streams). Streaming is NOT a goal for v1 of http_services — the spec §6 explicitly requires the body be logged, which requires buffering.

If a future task needs to support streaming (e.g., GitHub release asset downloads), the right answer is a `ServiceStream` flag on `HTTPService` that disables logging for that service — not a fork of the log path.

- [ ] **Step 13.7: Run the test**

```bash
go test ./internal/proxy/ -run TestServeDeclaredService_LogsRequestAndResponseToStorage -v
```

Expected: PASS.

Also run the full declared-service suite to catch regressions in earlier tasks:

```bash
go test ./internal/proxy/ -run TestServeDeclaredService -v
```

Expected: PASS.

- [ ] **Step 13.8: Confirm the LLM path still logs correctly**

The change to `RequestLogEntry` added `omitempty` to `Dialect` and three new optional fields. Existing LLM entries should be unaffected. Run:

```bash
go test ./internal/proxy/ -v
```

Expected: PASS. If any LLM test failed because it asserted a JSON key's presence (`dialect` must always appear), that test was over-specified — relax it to allow omitempty or update the expected JSON.

- [ ] **Step 13.9: Commit**

```bash
git add internal/proxy/storage.go internal/proxy/declared_service.go internal/proxy/declared_service_test.go
git commit -m "feat(proxy): log declared-service requests to storage

RequestLogEntry gains ServiceKind/ServiceName/RuleName fields (all
omitempty). serveDeclaredService buffers the request and response
bodies and writes them through Storage.LogRequest/LogResponse, matching
the audit shape the LLM path already uses.

Closes spec §6 request/response audit requirement. The approve/deny
direct event types remain covered by the approvals manager and by
Task 12 respectively."
```

---

## Task 14: Path-matching fuzz target

**Files:**
- Create: `internal/policy/http_service_fuzz_test.go`

- [ ] **Step 14.1: Create the fuzz target**

Create `internal/policy/http_service_fuzz_test.go`:

```go
package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

// FuzzCheckHTTPServicePath feeds random method/path combinations into the
// evaluator and asserts three invariants:
//
//  1. It never panics.
//  2. An allow decision implies the path survived path.Clean unchanged
//     (traversal attempts cannot reach upstream).
//  3. Method matching is stable under arbitrary casing.
func FuzzCheckHTTPServicePath(f *testing.F) {
	svcs := []HTTPService{{
		Name: "github", Upstream: "https://api.github.com",
		Default: "deny",
		Rules: []HTTPServiceRule{
			{Name: "read", Methods: []string{"GET"}, Paths: []string{"/repos/*/*"}, Decision: "allow"},
			{Name: "open", Methods: []string{"*"}, Paths: []string{"/public/**"}, Decision: "allow"},
		},
	}}
	if err := ValidateHTTPServices(svcs); err != nil {
		f.Fatal(err)
	}
	byName, byHost, err := compileHTTPServices(svcs)
	if err != nil {
		f.Fatal(err)
	}
	e := &Engine{
		policy:           &Policy{HTTPServices: svcs},
		httpServices:     byName,
		httpServiceHosts: byHost,
		enforceApprovals: true,
	}

	f.Add("GET", "/repos/a/b")
	f.Add("get", "/REPOS/a/b")
	f.Add("GET", "/repos/../etc/passwd")
	f.Add("GET", "/repos//a/b")
	f.Add("POST", "/public/\x00bar")
	f.Add("PUT", "/repos/a/b?%2e%2e")

	f.Fuzz(func(t *testing.T, method, reqPath string) {
		// Skip inputs with null bytes in the method — invalid HTTP.
		if strings.ContainsRune(method, 0) {
			return
		}
		dec := e.CheckHTTPService("github", method, reqPath)
		if dec.EffectiveDecision == types.DecisionAllow {
			// Invariant 2: allow implies clean path.
			if reqPath == "" {
				reqPath = "/"
			}
			if got := pathCleanForFuzz(reqPath); got != reqPath {
				t.Errorf("allow decision with non-canonical path: got=%q clean=%q", reqPath, got)
			}
		}
		// Invariant 3: casing-insensitive method.
		lower := strings.ToLower(method)
		upper := strings.ToUpper(method)
		decL := e.CheckHTTPService("github", lower, reqPath)
		decU := e.CheckHTTPService("github", upper, reqPath)
		if decL.EffectiveDecision != decU.EffectiveDecision {
			t.Errorf("case mismatch: lower=%q upper=%q dec differs", lower, upper)
		}
	})
}

// Use a separate name to make the fuzz target self-contained without
// importing path here (the eval path already imports it).
func pathCleanForFuzz(p string) string {
	return cleanPath(p)
}

func cleanPath(p string) string {
	// Mirror of path.Clean, imported via the eval file, but we don't
	// want to collide package imports. Delegate to the stdlib.
	if p == "" {
		return "/"
	}
	return p // placeholder; replace with path.Clean(p) — see step 14.2
}
```

- [ ] **Step 14.2: Replace the `cleanPath` stub with the stdlib call**

```go
import (
	"path"
	// ...
)

func cleanPath(p string) string {
	if p == "" {
		return "/"
	}
	return path.Clean(p)
}
```

- [ ] **Step 14.3: Run a quick fuzz pass**

```bash
go test ./internal/policy/ -run '^FuzzCheckHTTPServicePath$' -fuzz=FuzzCheckHTTPServicePath -fuzztime=20s
```

Expected: no panics, no invariant failures. 20 seconds is a sanity check; CI can run longer if desired.

- [ ] **Step 14.4: Commit**

```bash
git add internal/policy/http_service_fuzz_test.go
git commit -m "test(policy): fuzz target for http_services path handling

FuzzCheckHTTPServicePath feeds random method/path pairs into the
evaluator and checks: no panics, allow decisions require canonical
paths, and method matching is case-stable."
```

---

## Task 15: Cross-compile and final smoke test

**Files:** none (verification only)

- [ ] **Step 15.1: Full build**

```bash
go build ./...
```

Expected: success.

- [ ] **Step 15.2: Windows cross-compile**

```bash
GOOS=windows go build ./...
```

Expected: success. If it fails, investigate — the new code should be pure Go without `runtime.GOOS` branching, but imports may pull in Linux-only packages via netmonitor.

- [ ] **Step 15.3: Full test suite**

```bash
go test ./...
```

Expected: all PASS.

- [ ] **Step 15.4: Smoke test with a real config**

Write a smoke test policy to a temp file and load it, exercising the end-to-end path:

```bash
cat > /tmp/smoke-http-services.yaml <<'EOF'
http_services:
  - name: github
    upstream: https://api.github.com
    expose_as: GITHUB_API_URL
    default: deny
    rules:
      - name: read-issues
        methods: [GET]
        paths: [/repos/*/*/issues]
        decision: allow
EOF
go run ./cmd/agentsh-... -config /tmp/smoke-http-services.yaml --validate-only  # or whatever the CLI entrypoint is
```

Confirm the CLI prints no validation errors. (If the CLI doesn't have a `--validate-only` flag, skip this step — it's a nice-to-have, not a gate.)

- [ ] **Step 15.5: Commit a changelog or release note**

Skip unless the project tracks changelogs in-repo. If `CHANGELOG.md` exists:

```bash
cat >> CHANGELOG.md <<'EOF'
## Unreleased
- **http_services**: declare HTTP services in policy with per-service method/path rules; cooperating children reach them via `<NAME>_API_URL` env vars routed through the proxy gateway; direct HTTPS to declared hosts fails closed at netmonitor.
EOF
git add CHANGELOG.md
git commit -m "docs: changelog entry for http_services"
```

---

## Open sub-decisions for the implementer

These were intentionally left for the implementation plan, not the spec:

1. **Where `sessionIDFor` lives.** I assumed a small helper method on `*Proxy`. If there's an existing helper, use it; do not add a second.
2. **Whether to lift `maybeApprove`.** The plan duplicates it (Task 10) for minimal blast radius. A follow-up task titled "refactor: lift maybeApprove to shared helper" can consolidate netmonitor and declared-service call sites.
3. **The `HTTPService.Timeout` field.** Parsed and validated (Task 2) but not wired into the approval flow in Task 10 — the global approval timeout governs for v1. When the rule-level timeout is wired, it should flow through the `approvals.Request` rather than through the `Decision` struct.
4. **Approvals interface shape.** `HTTPServiceApprovalsManager` in Task 10 is a local interface. If it doesn't match `approvals.Manager`'s real method signature exactly, adjust the interface definition — the point is to have a narrow, testable surface, not to match the concrete manager byte-for-byte.
