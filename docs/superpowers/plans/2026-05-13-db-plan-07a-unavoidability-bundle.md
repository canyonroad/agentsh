# DB Plan 07a Unavoidability Bundle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generate a DB unavoidability policy bundle from declared `db_services`, including Unix-socket connect redirects, direct destination denies, local socket denies, bypass-tool command denies, and stable DB rule metadata.

**Architecture:** Keep generation in `internal/db/service` because the bundle is derived from static DB service config, not observed session activity. Extend existing policy primitives narrowly: add an explicit Unix target for `connect_redirects` and top-level rule metadata so later Plan 07b event mapping can identify DB-generated denies without rule-name inference. Apply generated rules to the governed agent session policy; the DB proxy runs under a separate session whose policy does not include these deny rules.

**Tech Stack:** Go, existing `internal/policy` rule model/engine, existing `internal/netmonitor` CONNECT proxy, existing `internal/db/service` config types, table-driven Go tests.

---

## File Structure

**Created:**

- `internal/db/service/bundle.go` - DB unavoidability bundle types and `GenerateBundle`.
- `internal/db/service/bundle_test.go` - bundle generation, metadata, DNS behavior, and compile tests.

**Modified:**

- `internal/policy/model.go` - add `Policy.Metadata`, `RuleMetadata`, and `ConnectRedirectRule.RedirectToUnix`.
- `internal/policy/engine.go` - return `RedirectToUnix` from `EvaluateConnectRedirect`.
- `internal/policy/redirect_test.go` - validate Unix redirect target semantics and evaluator output.
- `internal/netmonitor/proxy.go` - dial Unix sockets when a connect redirect resolves to `redirect_to_unix`.
- `internal/netmonitor/proxy_test.go` - unit-test CONNECT dial target selection for Unix redirects.

---

### Task 1: Add Explicit Unix Targets To Connect Redirect Rules

**Files:**
- Modify: `internal/policy/model.go`
- Modify: `internal/policy/engine.go`
- Modify: `internal/policy/redirect_test.go`

- [ ] **Step 1: Write failing validation and evaluator tests**

Append these tests to `internal/policy/redirect_test.go` near the existing connect redirect tests:

```go
func TestConnectRedirectRuleValidation_UnixTarget(t *testing.T) {
	tests := []struct {
		name    string
		rule    ConnectRedirectRule
		wantErr bool
	}{
		{
			name: "valid unix target",
			rule: ConnectRedirectRule{
				Name:           "db-appdb-redirect",
				Match:          "^db\\.internal:5432$",
				RedirectToUnix: "/run/agentsh/sessions/sess-1/db/appdb.sock",
			},
		},
		{
			name: "both tcp and unix targets",
			rule: ConnectRedirectRule{
				Name:           "db-appdb-redirect",
				Match:          "^db\\.internal:5432$",
				RedirectTo:     "proxy.internal:15432",
				RedirectToUnix: "/run/agentsh/sessions/sess-1/db/appdb.sock",
			},
			wantErr: true,
		},
		{
			name: "no target",
			rule: ConnectRedirectRule{
				Name:  "db-appdb-redirect",
				Match: "^db\\.internal:5432$",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Policy{
				Version:              1,
				Name:                 "test",
				ConnectRedirectRules: []ConnectRedirectRule{tt.rule},
			}
			err := p.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEvaluateConnectRedirect_UnixTarget(t *testing.T) {
	p := &Policy{
		Version: 1,
		Name:    "test",
		ConnectRedirectRules: []ConnectRedirectRule{
			{
				Name:           "db-appdb-redirect",
				Match:          "^db\\.internal:5432$",
				RedirectToUnix: "/run/agentsh/sessions/sess-1/db/appdb.sock",
				Message:        "Routed through AgentSH DB proxy",
			},
		},
	}
	engine, err := NewEngine(p, false, true)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	got := engine.EvaluateConnectRedirect("DB.Internal:5432")
	if !got.Matched {
		t.Fatal("EvaluateConnectRedirect did not match")
	}
	if got.RedirectTo != "" {
		t.Fatalf("RedirectTo = %q, want empty tcp target", got.RedirectTo)
	}
	if got.RedirectToUnix != "/run/agentsh/sessions/sess-1/db/appdb.sock" {
		t.Fatalf("RedirectToUnix = %q", got.RedirectToUnix)
	}
	if got.Rule != "db-appdb-redirect" {
		t.Fatalf("Rule = %q", got.Rule)
	}
	if got.Message != "Routed through AgentSH DB proxy" {
		t.Fatalf("Message = %q", got.Message)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/policy -run 'TestConnectRedirectRuleValidation_UnixTarget|TestEvaluateConnectRedirect_UnixTarget' -count=1
```

Expected: FAIL because `ConnectRedirectRule.RedirectToUnix` and `ConnectRedirectResult.RedirectToUnix` do not exist.

- [ ] **Step 3: Implement the model and evaluator changes**

In `internal/policy/model.go`, update `ConnectRedirectRule`:

```go
// ConnectRedirectRule redirects TCP connections for matching host:port.
// Exactly one target must be set:
//   - redirect_to for TCP host:port targets
//   - redirect_to_unix for Unix-socket targets
type ConnectRedirectRule struct {
	Name           string                    `yaml:"name"`
	Match          string                    `yaml:"match"` // regex pattern for host:port
	RedirectTo     string                    `yaml:"redirect_to,omitempty"`
	RedirectToUnix string                    `yaml:"redirect_to_unix,omitempty"`
	TLS            *ConnectRedirectTLSConfig `yaml:"tls,omitempty"`
	Visibility     string                    `yaml:"visibility,omitempty"` // silent, audit_only, warn
	Message        string                    `yaml:"message,omitempty"`
	OnFailure      string                    `yaml:"on_failure,omitempty"` // fail_closed, fail_open, retry_original
}
```

In `Policy.Validate`, replace the existing `redirect_to` required check with:

```go
targets := 0
if r.RedirectTo != "" {
	targets++
}
if r.RedirectToUnix != "" {
	targets++
}
if targets != 1 {
	return fmt.Errorf("connect_redirects[%d]: exactly one of redirect_to or redirect_to_unix is required", i)
}
```

In `internal/policy/engine.go`, update `ConnectRedirectResult`:

```go
type ConnectRedirectResult struct {
	Matched        bool
	Rule           string
	RedirectTo     string
	RedirectToUnix string
	TLSMode        string
	SNI            string
	Visibility     string
	Message        string
	OnFailure      string
}
```

In `EvaluateConnectRedirect`, populate the Unix target:

```go
return &ConnectRedirectResult{
	Matched:        true,
	Rule:           r.rule.Name,
	RedirectTo:     r.rule.RedirectTo,
	RedirectToUnix: r.rule.RedirectToUnix,
	TLSMode:        tlsMode,
	SNI:            sni,
	Visibility:     visibility,
	Message:        r.rule.Message,
	OnFailure:      onFailure,
}
```

- [ ] **Step 4: Run policy tests**

Run:

```bash
go test ./internal/policy -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/model.go internal/policy/engine.go internal/policy/redirect_test.go
git commit -m "policy: support unix connect redirect targets"
```

---

### Task 2: Teach Netmonitor CONNECT Redirects To Dial Unix Targets

**Files:**
- Modify: `internal/netmonitor/proxy.go`
- Modify: `internal/netmonitor/proxy_test.go`

- [ ] **Step 1: Write failing dial-target tests**

Append these tests to `internal/netmonitor/proxy_test.go`:

```go
func TestConnectDialTarget_UnixRedirect(t *testing.T) {
	got := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: "db.internal:5432",
		ResolvedIP:      "10.0.0.10",
		OriginalPort:    "5432",
		Redirect: &policy.ConnectRedirectResult{
			Matched:        true,
			RedirectToUnix: "/run/agentsh/sessions/sess-1/db/appdb.sock",
		},
	})
	if got.Network != "unix" {
		t.Fatalf("Network = %q, want unix", got.Network)
	}
	if got.Address != "/run/agentsh/sessions/sess-1/db/appdb.sock" {
		t.Fatalf("Address = %q", got.Address)
	}
}

func TestConnectDialTarget_TCPRedirectWinsOverResolvedIP(t *testing.T) {
	got := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: "api.example.com:443",
		ResolvedIP:      "10.0.0.10",
		OriginalPort:    "443",
		Redirect: &policy.ConnectRedirectResult{
			Matched:    true,
			RedirectTo: "proxy.internal:8443",
		},
	})
	if got.Network != "tcp" {
		t.Fatalf("Network = %q, want tcp", got.Network)
	}
	if got.Address != "proxy.internal:8443" {
		t.Fatalf("Address = %q", got.Address)
	}
}

func TestConnectDialTarget_ResolvedIPFallback(t *testing.T) {
	got := connectDialTarget(connectDialTargetInput{
		OriginalHostPort: "api.example.com:443",
		ResolvedIP:      "10.0.0.10",
		OriginalPort:    "443",
	})
	if got.Network != "tcp" {
		t.Fatalf("Network = %q, want tcp", got.Network)
	}
	if got.Address != "10.0.0.10:443" {
		t.Fatalf("Address = %q", got.Address)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/netmonitor -run 'TestConnectDialTarget_' -count=1
```

Expected: FAIL because `connectDialTarget` and `connectDialTargetInput` do not exist.

- [ ] **Step 3: Implement dial-target selection**

In `internal/netmonitor/proxy.go`, add this helper near `handleCONNECT`:

```go
type connectDialTargetInput struct {
	OriginalHostPort string
	ResolvedIP      string
	OriginalPort    string
	Redirect        *policy.ConnectRedirectResult
}

type resolvedConnectDialTarget struct {
	Network string
	Address string
}

func connectDialTarget(in connectDialTargetInput) resolvedConnectDialTarget {
	if in.Redirect != nil && in.Redirect.RedirectToUnix != "" {
		return resolvedConnectDialTarget{Network: "unix", Address: in.Redirect.RedirectToUnix}
	}
	if in.Redirect != nil && in.Redirect.RedirectTo != "" {
		return resolvedConnectDialTarget{Network: "tcp", Address: in.Redirect.RedirectTo}
	}
	if in.ResolvedIP != "" {
		return resolvedConnectDialTarget{
			Network: "tcp",
			Address: net.JoinHostPort(in.ResolvedIP, in.OriginalPort),
		}
	}
	return resolvedConnectDialTarget{Network: "tcp", Address: in.OriginalHostPort}
}
```

In `handleCONNECT`, keep the full `redirectResult` instead of splitting only strings:

```go
var redirectResult *policy.ConnectRedirectResult
if p.policy != nil {
	result := p.policy.EvaluateConnectRedirect(hostPort)
	if result.Matched {
		redirectResult = result
		redirectTLS = result.TLSMode
		redirectSNI = result.SNI
		if result.Visibility != "silent" {
			p.emitConnectRedirectEvent(context.Background(), commandID, host, hostPort, port, result)
		}
	}
}
```

When adding event fields:

```go
if redirectResult != nil {
	if redirectResult.RedirectTo != "" {
		eventFields["redirect_to"] = redirectResult.RedirectTo
	}
	if redirectResult.RedirectToUnix != "" {
		eventFields["redirect_to_unix"] = redirectResult.RedirectToUnix
	}
	eventFields["redirect_tls"] = redirectTLS
	if redirectSNI != "" {
		eventFields["redirect_sni"] = redirectSNI
	}
}
```

Replace the existing dial-target block:

```go
dialTarget := connectDialTarget(connectDialTargetInput{
	OriginalHostPort: hostPort,
	ResolvedIP:      resolvedIP,
	OriginalPort:    portStr,
	Redirect:        redirectResult,
})

up, err := net.DialTimeout(dialTarget.Network, dialTarget.Address, 20*time.Second)
```

- [ ] **Step 4: Run netmonitor tests**

Run:

```bash
go test ./internal/netmonitor -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/netmonitor/proxy.go internal/netmonitor/proxy_test.go
git commit -m "netmonitor: dial unix connect redirect targets"
```

---

### Task 3: Add Stable Rule Metadata To Policy Model

**Files:**
- Modify: `internal/policy/model.go`
- Modify: `internal/policy/redirect_test.go`

- [ ] **Step 1: Write failing metadata validation tests**

Append these tests to `internal/policy/redirect_test.go`:

```go
func TestPolicyMetadataValidation(t *testing.T) {
	tests := []struct {
		name    string
		meta    []RuleMetadata
		wantErr bool
	}{
		{
			name: "valid db metadata",
			meta: []RuleMetadata{{
				RuleName:    "db-appdb-deny-direct",
				Source:      "db_unavoidability",
				DBService:   "appdb",
				BypassMode:  "tcp_direct",
				Destination: "db.internal:5432",
			}},
		},
		{
			name: "missing rule name",
			meta: []RuleMetadata{{
				Source:      "db_unavoidability",
				DBService:   "appdb",
				BypassMode:  "tcp_direct",
				Destination: "db.internal:5432",
			}},
			wantErr: true,
		},
		{
			name: "missing source",
			meta: []RuleMetadata{{
				RuleName:    "db-appdb-deny-direct",
				DBService:   "appdb",
				BypassMode:  "tcp_direct",
				Destination: "db.internal:5432",
			}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := Policy{Version: 1, Name: "test", Metadata: tt.meta}
			err := p.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/policy -run TestPolicyMetadataValidation -count=1
```

Expected: FAIL because `RuleMetadata` and `Policy.Metadata` do not exist.

- [ ] **Step 3: Implement metadata fields and validation**

In `internal/policy/model.go`, add the metadata field to `Policy`:

```go
Metadata []RuleMetadata `yaml:"metadata,omitempty"`
```

Add the struct near the rule model types:

```go
// RuleMetadata is non-enforcing metadata attached to generated policy rules.
// The policy engine ignores it for decisions; consumers use it to correlate
// generic rule names back to higher-level generated bundles.
type RuleMetadata struct {
	RuleName    string `yaml:"rule_name"`
	Source      string `yaml:"source"`
	DBService   string `yaml:"db_service,omitempty"`
	BypassMode  string `yaml:"bypass_mode,omitempty"`
	Destination string `yaml:"destination,omitempty"`
}
```

At the beginning of `Policy.Validate`, after the name/version checks, add:

```go
for i, m := range p.Metadata {
	if m.RuleName == "" {
		return fmt.Errorf("metadata[%d]: rule_name is required", i)
	}
	if m.Source == "" {
		return fmt.Errorf("metadata[%d]: source is required", i)
	}
}
```

- [ ] **Step 4: Run policy tests**

Run:

```bash
go test ./internal/policy -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/model.go internal/policy/redirect_test.go
git commit -m "policy: preserve generated rule metadata"
```

---

### Task 4: Add DB Bundle Types And Option Validation

**Files:**
- Create: `internal/db/service/bundle.go`
- Create: `internal/db/service/bundle_test.go`

- [ ] **Step 1: Write failing validation tests**

Create `internal/db/service/bundle_test.go`:

```go
package service

import (
	"errors"
	"strings"
	"testing"
)

func TestGenerateBundle_RequiresSessionID(t *testing.T) {
	_, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		Mode: UnavoidabilityEnforce,
	})
	if !errors.Is(err, ErrBundleInvalidOptions) {
		t.Fatalf("GenerateBundle err = %v, want ErrBundleInvalidOptions", err)
	}
}

func TestGenerateBundle_RejectsTCPListenerInEnforce(t *testing.T) {
	svc := validBundleService("appdb")
	svc.Listen = Listener{Kind: "tcp", Host: "127.0.0.1", Port: 15432}

	_, err := GenerateBundle(Config{Services: []Service{svc}}, BundleOptions{
		SessionID:      "sess-1",
		ProxySessionID: "db-proxy-sess",
		Mode:           UnavoidabilityEnforce,
	})
	if err == nil {
		t.Fatal("GenerateBundle returned nil error")
	}
	if !strings.Contains(err.Error(), "spec section 12.5") {
		t.Fatalf("error = %v, want spec section 12.5 reference", err)
	}
}

func validBundleService(name string) Service {
	return Service{
		Name:    name,
		Family:  "postgres",
		Dialect: "postgres",
		Upstream: Endpoint{
			Host: "db.internal",
			Port: 5432,
		},
		Listen: Listener{
			Kind: "unix",
			Path: "/run/agentsh/sessions/sess-1/db/" + name + ".sock",
		},
		TLSMode: "terminate_reissue",
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/db/service -run 'TestGenerateBundle_RequiresSessionID|TestGenerateBundle_RejectsTCPListenerInEnforce' -count=1
```

Expected: FAIL because bundle types and `GenerateBundle` do not exist.

- [ ] **Step 3: Implement bundle skeleton and validation**

Create `internal/db/service/bundle.go`:

```go
package service

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/agentsh/agentsh/internal/policy"
)

const (
	RuleSourceDBUnavoidability = "db_unavoidability"

	BypassModeTCPDirect       = "tcp_direct"
	BypassModeUnixSocket      = "unix_socket"
	BypassModePortForwardTool = "port_forward_tool"
	BypassModeDNSAlias        = "dns_alias"
	BypassModeCustomTunnel    = "custom_tunnel"
)

var ErrBundleInvalidOptions = errors.New("db unavoidability bundle invalid options")

type IPResolver interface {
	LookupIP(ctx context.Context, host string) ([]net.IP, error)
}

type BundleOptions struct {
	SessionID                  string
	ProxySessionID             string
	SocketBaseDir              string
	IncludeToolRules           bool
	Mode                       Unavoidability
	AllowHostnameOnlyInEnforce bool
	Resolver                   IPResolver
}

type BundleWarning struct {
	Code    string
	Service string
	Message string
}

type Bundle struct {
	Policy   policy.Policy
	Metadata []policy.RuleMetadata
	Warnings []BundleWarning
}

func GenerateBundle(cfg Config, opts BundleOptions) (Bundle, error) {
	if err := validateBundleOptions(cfg, opts); err != nil {
		return Bundle{}, err
	}
	return Bundle{
		Policy: policy.Policy{
			Version:     1,
			Name:        "db-unavoidability-" + sanitizeRulePart(opts.SessionID),
			Description: "Generated DB unavoidability bundle for AgentSH session " + opts.SessionID,
		},
	}, nil
}

func validateBundleOptions(cfg Config, opts BundleOptions) error {
	if opts.SessionID == "" {
		return fmt.Errorf("%w: SessionID is required", ErrBundleInvalidOptions)
	}
	if opts.ProxySessionID == "" {
		return fmt.Errorf("%w: ProxySessionID is required", ErrBundleInvalidOptions)
	}
	if opts.Mode != UnavoidabilityObserve && opts.Mode != UnavoidabilityEnforce {
		return fmt.Errorf("%w: Mode must be observe or enforce", ErrBundleInvalidOptions)
	}
	for i, svc := range cfg.Services {
		if svc.Listen.Kind == "tcp" && opts.Mode == UnavoidabilityEnforce {
			return fmt.Errorf("services[%d] %s: tcp listeners are not supported for DB enforce mode in spec section 12.5", i, svc.Name)
		}
	}
	return nil
}

func sanitizeRulePart(s string) string {
	if s == "" {
		return "empty"
	}
	out := make([]byte, 0, len(s))
	lastDash := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, c)
			lastDash = false
		case c >= 'A' && c <= 'Z':
			out = append(out, c+'a'-'A')
			lastDash = false
		case c >= '0' && c <= '9':
			out = append(out, c)
			lastDash = false
		default:
			if !lastDash {
				out = append(out, '-')
				lastDash = true
			}
		}
	}
	for len(out) > 0 && out[len(out)-1] == '-' {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return "empty"
	}
	return string(out)
}
```

- [ ] **Step 4: Run service tests**

Run:

```bash
go test ./internal/db/service -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/service/bundle.go internal/db/service/bundle_test.go
git commit -m "db: add unavoidability bundle skeleton"
```

---

### Task 5: Generate Core Redirect, Network, Unix Socket Rules, And Metadata

**Files:**
- Modify: `internal/db/service/bundle.go`
- Modify: `internal/db/service/bundle_test.go`

- [ ] **Step 1: Write failing core bundle tests**

Append to `internal/db/service/bundle_test.go`:

```go
func TestGenerateBundle_SingleServiceCoreRules(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	if len(b.Policy.ConnectRedirectRules) != 1 {
		t.Fatalf("connect redirects = %d, want 1", len(b.Policy.ConnectRedirectRules))
	}
	redirect := b.Policy.ConnectRedirectRules[0]
	if redirect.Name != "db-appdb-redirect" {
		t.Fatalf("redirect name = %q", redirect.Name)
	}
	if redirect.RedirectToUnix != "/run/agentsh/sessions/sess-1/db/appdb.sock" {
		t.Fatalf("redirect_to_unix = %q", redirect.RedirectToUnix)
	}
	if redirect.RedirectTo != "" {
		t.Fatalf("redirect_to = %q, want empty", redirect.RedirectTo)
	}

	if len(b.Policy.NetworkRules) != 1 {
		t.Fatalf("network rules = %d, want 1", len(b.Policy.NetworkRules))
	}
	netRule := b.Policy.NetworkRules[0]
	if netRule.Name != "db-appdb-deny-direct" {
		t.Fatalf("network rule name = %q", netRule.Name)
	}
	if len(netRule.Domains) != 1 || netRule.Domains[0] != "db.internal" {
		t.Fatalf("network domains = %+v", netRule.Domains)
	}
	if len(netRule.Ports) != 1 || netRule.Ports[0] != 5432 {
		t.Fatalf("network ports = %+v", netRule.Ports)
	}
	if netRule.Decision != "deny" {
		t.Fatalf("network decision = %q", netRule.Decision)
	}

	if len(b.Policy.UnixRules) != 1 {
		t.Fatalf("unix rules = %d, want 1", len(b.Policy.UnixRules))
	}
	if b.Policy.UnixRules[0].Decision != "deny" {
		t.Fatalf("unix decision = %q", b.Policy.UnixRules[0].Decision)
	}

	if len(b.Metadata) != len(b.Policy.Metadata) {
		t.Fatalf("Bundle.Metadata length = %d, Policy.Metadata length = %d", len(b.Metadata), len(b.Policy.Metadata))
	}
	assertMetadata(t, b.Metadata, "db-appdb-redirect", "appdb", BypassModeTCPDirect, "db.internal:5432")
	assertMetadata(t, b.Metadata, "db-appdb-deny-direct", "appdb", BypassModeTCPDirect, "db.internal:5432")
	assertMetadata(t, b.Metadata, "db-appdb-deny-local-postgres-sockets", "appdb", BypassModeUnixSocket, "postgres-local-sockets")
}

func TestGenerateBundle_MultipleServicesHaveStableNames(t *testing.T) {
	app := validBundleService("appdb")
	warehouse := validBundleService("warehouse-db")
	warehouse.Upstream.Host = "warehouse.internal"
	warehouse.Upstream.Port = 15432
	warehouse.Listen.Path = "/run/agentsh/sessions/sess-1/db/warehouse.sock"

	b, err := GenerateBundle(Config{Services: []Service{app, warehouse}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	seen := map[string]bool{}
	for _, m := range b.Metadata {
		if seen[m.RuleName] {
			t.Fatalf("duplicate metadata rule name %q", m.RuleName)
		}
		seen[m.RuleName] = true
	}
	for _, name := range []string{
		"db-appdb-redirect",
		"db-warehouse-db-redirect",
		"db-appdb-deny-direct",
		"db-warehouse-db-deny-direct",
	} {
		if !seen[name] {
			t.Fatalf("missing metadata for %q in %+v", name, b.Metadata)
		}
	}
}

func TestGenerateBundle_PolicyCompiles(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if err := b.Policy.Validate(); err != nil {
		t.Fatalf("Policy.Validate: %v", err)
	}
	if _, err := policy.NewEngine(&b.Policy, false, true); err != nil {
		t.Fatalf("policy.NewEngine: %v", err)
	}
}

func assertMetadata(t *testing.T, got []policy.RuleMetadata, ruleName, service, mode, destination string) {
	t.Helper()
	for _, m := range got {
		if m.RuleName == ruleName {
			if m.Source != RuleSourceDBUnavoidability || m.DBService != service || m.BypassMode != mode || m.Destination != destination {
				t.Fatalf("metadata for %q = %+v", ruleName, m)
			}
			return
		}
	}
	t.Fatalf("missing metadata for rule %q in %+v", ruleName, got)
}
```

Add the import to `internal/db/service/bundle_test.go`:

```go
import (
	"errors"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/db/service -run 'TestGenerateBundle_SingleServiceCoreRules|TestGenerateBundle_MultipleServicesHaveStableNames|TestGenerateBundle_PolicyCompiles' -count=1
```

Expected: FAIL because the skeleton does not generate rules or metadata.

- [ ] **Step 3: Implement core bundle generation**

In `internal/db/service/bundle.go`, update `GenerateBundle`:

```go
func GenerateBundle(cfg Config, opts BundleOptions) (Bundle, error) {
	if err := validateBundleOptions(cfg, opts); err != nil {
		return Bundle{}, err
	}
	b := Bundle{
		Policy: policy.Policy{
			Version:     1,
			Name:        "db-unavoidability-" + sanitizeRulePart(opts.SessionID),
			Description: "Generated DB unavoidability bundle for AgentSH session " + opts.SessionID,
		},
	}
	for _, svc := range cfg.Services {
		addCoreServiceRules(&b, svc)
	}
	b.Policy.Metadata = append([]policy.RuleMetadata(nil), b.Metadata...)
	return b, nil
}
```

Add helpers:

```go
func addCoreServiceRules(b *Bundle, svc Service) {
	servicePart := sanitizeRulePart(svc.Name)
	destination := serviceDestination(svc)
	redirectName := "db-" + servicePart + "-redirect"
	networkName := "db-" + servicePart + "-deny-direct"
	unixName := "db-" + servicePart + "-deny-local-postgres-sockets"

	b.Policy.ConnectRedirectRules = append(b.Policy.ConnectRedirectRules, policy.ConnectRedirectRule{
		Name:           redirectName,
		Match:          "^" + regexp.QuoteMeta(destination) + "$",
		RedirectToUnix: svc.Listen.Path,
		Visibility:     "audit_only",
		OnFailure:      "fail_closed",
		Message:        "Routed through AgentSH DB proxy",
	})
	addMetadata(b, redirectName, svc.Name, BypassModeTCPDirect, destination)

	b.Policy.NetworkRules = append(b.Policy.NetworkRules, policy.NetworkRule{
		Name:        networkName,
		Description: "Deny direct DB egress; traffic must use AgentSH DB proxy",
		Domains:     []string{strings.ToLower(svc.Upstream.Host)},
		Ports:       []int{svc.Upstream.Port},
		Decision:    "deny",
		Message:     "Direct database egress is blocked; use the AgentSH DB proxy",
	})
	addMetadata(b, networkName, svc.Name, BypassModeTCPDirect, destination)

	b.Policy.UnixRules = append(b.Policy.UnixRules, policy.UnixSocketRule{
		Name:        unixName,
		Description: "Deny direct local Postgres Unix socket access for DB unavoidability",
		Paths: []string{
			"/var/run/postgresql/.s.PGSQL.*",
			"/tmp/.s.PGSQL.*",
		},
		Operations: []string{"connect"},
		Decision:   "deny",
		Message:    "Direct local database socket access is blocked; use the AgentSH DB proxy",
	})
	addMetadata(b, unixName, svc.Name, BypassModeUnixSocket, "postgres-local-sockets")
}

func addMetadata(b *Bundle, ruleName, serviceName, bypassMode, destination string) {
	b.Metadata = append(b.Metadata, policy.RuleMetadata{
		RuleName:    ruleName,
		Source:      RuleSourceDBUnavoidability,
		DBService:   serviceName,
		BypassMode:  bypassMode,
		Destination: destination,
	})
}

func serviceDestination(svc Service) string {
	return net.JoinHostPort(strings.ToLower(svc.Upstream.Host), strconv.Itoa(svc.Upstream.Port))
}
```

Add imports:

```go
import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/agentsh/agentsh/internal/policy"
)
```

- [ ] **Step 4: Run service tests**

Run:

```bash
go test ./internal/db/service -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/service/bundle.go internal/db/service/bundle_test.go
git commit -m "db: generate core unavoidability bundle rules"
```

---

### Task 6: Add DNS Resolution Expansion With Observe/Enforce Semantics

**Files:**
- Modify: `internal/db/service/bundle.go`
- Modify: `internal/db/service/bundle_test.go`

- [ ] **Step 1: Write failing DNS expansion tests**

Append to `internal/db/service/bundle_test.go`:

```go
type fakeIPResolver struct {
	ips []net.IP
	err error
}

func (f fakeIPResolver) LookupIP(ctx context.Context, host string) ([]net.IP, error) {
	return f.ips, f.err
}

func TestGenerateBundle_AddsResolvedIPDenies(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
		Resolver: fakeIPResolver{ips: []net.IP{
			net.ParseIP("10.0.0.15"),
			net.ParseIP("2001:db8::15"),
		}},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	assertMetadata(t, b.Metadata, "db-appdb-deny-ip-10-0-0-15", "appdb", BypassModeDNSAlias, "10.0.0.15:5432")
	assertMetadata(t, b.Metadata, "db-appdb-deny-ip-2001-db8-15", "appdb", BypassModeDNSAlias, "[2001:db8::15]:5432")
}

func TestGenerateBundle_DNSFailureObserveWarns(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityObserve,
		IncludeToolRules: false,
		Resolver:         fakeIPResolver{err: errors.New("dns unavailable")},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if len(b.Warnings) != 1 {
		t.Fatalf("warnings = %+v, want one warning", b.Warnings)
	}
	if b.Warnings[0].Code != "DNS_EXPANSION_FAILED" {
		t.Fatalf("warning code = %q", b.Warnings[0].Code)
	}
}

func TestGenerateBundle_DNSFailureEnforceFailsUnlessAllowed(t *testing.T) {
	_, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
		Resolver:         fakeIPResolver{err: errors.New("dns unavailable")},
	})
	if err == nil {
		t.Fatal("GenerateBundle returned nil error")
	}

	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:                  "sess-1",
		ProxySessionID:             "db-proxy-sess",
		Mode:                       UnavoidabilityEnforce,
		IncludeToolRules:           false,
		AllowHostnameOnlyInEnforce: true,
		Resolver:                   fakeIPResolver{err: errors.New("dns unavailable")},
	})
	if err != nil {
		t.Fatalf("GenerateBundle with hostname-only override: %v", err)
	}
	if len(b.Warnings) != 1 {
		t.Fatalf("warnings = %+v, want one warning", b.Warnings)
	}
}
```

Update imports:

```go
import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/db/service -run 'TestGenerateBundle_AddsResolvedIPDenies|TestGenerateBundle_DNSFailure' -count=1
```

Expected: FAIL because DNS expansion is not implemented.

- [ ] **Step 3: Implement resolver-backed IP deny expansion**

Update imports:

```go
import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/policy"
)
```

Inside the service loop, after `addCoreServiceRules`, call:

```go
if err := addResolvedIPRules(context.Background(), &b, svc, opts); err != nil {
	return Bundle{}, err
}
```

Add helpers:

```go
func addResolvedIPRules(ctx context.Context, b *Bundle, svc Service, opts BundleOptions) error {
	if opts.Resolver == nil {
		return nil
	}
	if net.ParseIP(svc.Upstream.Host) != nil {
		return nil
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	ips, err := opts.Resolver.LookupIP(resolveCtx, svc.Upstream.Host)
	if err != nil {
		w := BundleWarning{
			Code:    "DNS_EXPANSION_FAILED",
			Service: svc.Name,
			Message: "could not resolve " + svc.Upstream.Host + ": " + err.Error(),
		}
		b.Warnings = append(b.Warnings, w)
		if opts.Mode == UnavoidabilityEnforce && !opts.AllowHostnameOnlyInEnforce {
			return fmt.Errorf("%w: %s", ErrBundleInvalidOptions, w.Message)
		}
		return nil
	}

	for _, ip := range ips {
		if ip == nil {
			continue
		}
		cidr := ipCIDR(ip)
		ipString := ip.String()
		name := "db-" + sanitizeRulePart(svc.Name) + "-deny-ip-" + sanitizeRulePart(ipString)
		destination := net.JoinHostPort(ipString, strconv.Itoa(svc.Upstream.Port))
		b.Policy.NetworkRules = append(b.Policy.NetworkRules, policy.NetworkRule{
			Name:        name,
			Description: "Deny direct DB egress to resolved upstream IP",
			CIDRs:       []string{cidr},
			Ports:       []int{svc.Upstream.Port},
			Decision:    "deny",
			Message:     "Direct database egress is blocked; use the AgentSH DB proxy",
		})
		addMetadata(b, name, svc.Name, BypassModeDNSAlias, destination)
	}
	return nil
}

func ipCIDR(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String() + "/32"
	}
	return ip.String() + "/128"
}
```

- [ ] **Step 4: Run service tests**

Run:

```bash
go test ./internal/db/service -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/service/bundle.go internal/db/service/bundle_test.go
git commit -m "db: add dns-expanded unavoidability denies"
```

---

### Task 7: Generate Bypass-Tool Command Rules

**Files:**
- Modify: `internal/db/service/bundle.go`
- Modify: `internal/db/service/bundle_test.go`

- [ ] **Step 1: Write failing bypass-tool tests**

Append to `internal/db/service/bundle_test.go`:

```go
func TestGenerateBundle_BypassToolRules(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: true,
		Resolver:         fakeIPResolver{},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}

	wantCommands := map[string]string{
		"ssh":             "db-bypass-ssh-forward",
		"socat":           "db-bypass-socat",
		"kubectl":         "db-bypass-kubectl-port-forward",
		"cloud-sql-proxy": "db-bypass-cloud-sql-proxy",
		"gcloud":          "db-bypass-gcloud-sql-connect",
		"aws":             "db-bypass-aws-rds-connect",
		"chisel":          "db-bypass-chisel",
		"gost":            "db-bypass-gost",
		"frpc":            "db-bypass-frpc",
		"nc":              "db-bypass-netcat",
		"ncat":            "db-bypass-netcat",
		"docker":          "db-bypass-container-net-host",
	}

	seen := map[string]string{}
	for _, r := range b.Policy.CommandRules {
		for _, cmd := range r.Commands {
			seen[cmd] = r.Name
		}
		if r.Decision != "deny" {
			t.Fatalf("command rule %q decision = %q", r.Name, r.Decision)
		}
	}
	for cmd, ruleName := range wantCommands {
		if seen[cmd] != ruleName {
			t.Fatalf("command %q mapped to rule %q, want %q; all seen=%+v", cmd, seen[cmd], ruleName, seen)
		}
		assertMetadata(t, b.Metadata, ruleName, "*", BypassModePortForwardTool, "db-service-ports")
	}
}

func TestGenerateBundle_BypassToolRulesOptional(t *testing.T) {
	b, err := GenerateBundle(Config{Services: []Service{validBundleService("appdb")}}, BundleOptions{
		SessionID:        "sess-1",
		ProxySessionID:   "db-proxy-sess",
		Mode:             UnavoidabilityEnforce,
		IncludeToolRules: false,
		Resolver:         fakeIPResolver{},
	})
	if err != nil {
		t.Fatalf("GenerateBundle: %v", err)
	}
	if len(b.Policy.CommandRules) != 0 {
		t.Fatalf("command rules = %+v, want none", b.Policy.CommandRules)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/db/service -run 'TestGenerateBundle_BypassToolRules' -count=1
```

Expected: FAIL because `IncludeToolRules` does not add command rules.

- [ ] **Step 3: Implement bypass-tool rules**

In `GenerateBundle`, after the service loop:

```go
if opts.IncludeToolRules {
	addBypassToolRules(&b, cfg.Services)
}
b.Policy.Metadata = append([]policy.RuleMetadata(nil), b.Metadata...)
return b, nil
```

Add helpers:

```go
func addBypassToolRules(b *Bundle, services []Service) {
	portPattern := dbPortPattern(services)
	rules := []policy.CommandRule{
		{Name: "db-bypass-ssh-forward", Commands: []string{"ssh"}, ArgsPatterns: []string{"(^|\\s)-L(\\s|[^\\s]*:).*:(" + portPattern + ")(\\s|$)"}, Decision: "deny", Message: "DB port forwarding is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-socat", Commands: []string{"socat"}, ArgsPatterns: []string{"(?i)(tcp-listen|listen|tcp:).*(" + portPattern + ")"}, Decision: "deny", Message: "DB socket forwarding is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-kubectl-port-forward", Commands: []string{"kubectl"}, ArgsPatterns: []string{"(^|\\s)port-forward(\\s|$).*(:" + portPattern + "|\\s" + portPattern + ":)"}, Decision: "deny", Message: "DB port forwarding is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-cloud-sql-proxy", Commands: []string{"cloud-sql-proxy"}, ArgsPatterns: []string{".*"}, Decision: "deny", Message: "Cloud SQL proxy is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-gcloud-sql-connect", Commands: []string{"gcloud"}, ArgsPatterns: []string{"(^|\\s)sql\\s+connect(\\s|$)"}, Decision: "deny", Message: "gcloud SQL connect is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-aws-rds-connect", Commands: []string{"aws"}, ArgsPatterns: []string{"(^|\\s)rds\\s+connect(\\s|$)"}, Decision: "deny", Message: "AWS RDS connect is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-chisel", Commands: []string{"chisel"}, ArgsPatterns: []string{".*"}, Decision: "deny", Message: "Tunnel tool is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-gost", Commands: []string{"gost"}, ArgsPatterns: []string{".*"}, Decision: "deny", Message: "Tunnel tool is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-frpc", Commands: []string{"frpc"}, ArgsPatterns: []string{".*"}, Decision: "deny", Message: "Tunnel tool is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-netcat", Commands: []string{"nc", "ncat"}, ArgsPatterns: []string{"(?i)(-l|--listen|(" + portPattern + "))"}, Decision: "deny", Message: "Raw TCP forwarding is blocked by AgentSH DB unavoidability"},
		{Name: "db-bypass-container-net-host", Commands: []string{"docker", "podman", "nerdctl"}, ArgsPatterns: []string{"(^|\\s)(run|create)(\\s|$).*(--net=host|--network=host)"}, Decision: "deny", Message: "Host-network containers are blocked by AgentSH DB unavoidability"},
	}
	for _, r := range rules {
		r.Description = "Convenience detection for DB proxy bypass attempts; destination egress deny is the security boundary"
		b.Policy.CommandRules = append(b.Policy.CommandRules, r)
		addMetadata(b, r.Name, "*", BypassModePortForwardTool, "db-service-ports")
	}
}

func dbPortPattern(services []Service) string {
	seen := map[int]bool{}
	ports := make([]int, 0, len(services))
	for _, svc := range services {
		if !seen[svc.Upstream.Port] {
			seen[svc.Upstream.Port] = true
			ports = append(ports, svc.Upstream.Port)
		}
	}
	sort.Ints(ports)
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, "|")
}
```

Add `sort` to imports.

- [ ] **Step 4: Run service tests**

Run:

```bash
go test ./internal/db/service -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/service/bundle.go internal/db/service/bundle_test.go
git commit -m "db: generate bypass tool detection rules"
```

---

### Task 8: Final Verification For 07a

**Files:**
- No new files.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./internal/policy ./internal/netmonitor ./internal/db/service -count=1
```

Expected: PASS.

- [ ] **Step 2: Run DB package tests**

Run:

```bash
go test ./internal/db/... -count=1 -timeout 240s
```

Expected: PASS.

- [ ] **Step 3: Verify Windows build**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS. The new bundle code is platform-neutral; Unix-socket redirect fields are data model only and must compile on Windows.

- [ ] **Step 4: Run diff whitespace check**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 5: Commit verification fixes if needed**

If any verification step required code fixes, commit the fixes:

```bash
git add internal/policy internal/netmonitor internal/db/service
git commit -m "db: finish unavoidability bundle verification"
```

Expected: either a small follow-up commit exists, or `git status --short` shows no uncommitted tracked changes.

## Completion Criteria

Plan 07a is complete when:

- DB services generate compileable policy bundles with Unix connect redirects.
- Direct host and resolved-IP egress denies are generated.
- Local Postgres Unix socket denies are generated.
- Bypass-tool command denies are generated when requested.
- Every generated DB rule has stable metadata available in both `Bundle.Metadata` and `Policy.Metadata`.
- Netmonitor can dial Unix redirect targets.
- Focused tests, DB tests, Windows build, and `git diff --check` pass.

Plan 07b can start after 07a lands because it consumes the rule metadata and listener socket path behavior produced here.
