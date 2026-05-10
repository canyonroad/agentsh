# db-access Plan 02 — Policy Evaluator Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `internal/db/policy/`: a pure-Go, platform-agnostic policy evaluator that turns a `*policy.Policy` (with three new `yaml.Node` rule families) plus an `effects.ClassifiedStatement` into a `Decision`, per spec §9 / §10.

**Architecture:** Decode → Validate → Compile pipeline produces an immutable `*RuleSet`. Two pure functions, `Evaluate` (statement) and `EvaluateConnection` (connection), consume the RuleSet on the hot path. Globs precompiled via `gobwas/glob`; alias expansion via existing `effects.ExpandAlias`. `internal/policy.Policy` gains three `yaml.Node` fields so YAML parses without error; the DB-side `Decode` does the real work. Per spec, no I/O, no goroutines, no events, no approvals — those land in Plans 04+.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, `github.com/gobwas/glob` (already deps), `text/template` (stdlib), table-driven tests with `testing.T`.

---

## File Structure

**Created:**

- `internal/db/policy/types.go` — public types: `RuleSet`, `StatementRule`, `ConnectionRule`, `DBService`, `ConnectionInfo`, `Decision`, `ApprovalRequest`, `Warning`, enums.
- `internal/db/policy/redaction.go` — `RedactionTier` + `RedactionConfig` (policy-load config; distinct from `events.Redaction` to avoid an import cycle).
- `internal/db/policy/decode.go` — `Decode(*policy.Policy) (*RuleSet, []Warning, error)` orchestrates Phase A (yaml decode) + Phase B (validate) + Phase C (compile).
- `internal/db/policy/validate.go` — pure function returning errors + warnings over decoded shapes.
- `internal/db/policy/compile.go` — `compiledStatementRule`, `compiledConnectionRule`; glob compilation, alias expansion, message-template parsing, `serviceMatcher`, `resolutionMatcher`.
- `internal/db/policy/evaluate.go` — `Evaluate(stmt, rs, svc) Decision`.
- `internal/db/policy/evaluate_conn.go` — `EvaluateConnection(info, rs) Decision`.
- `internal/db/policy/sample.go` — `//go:embed testdata/sample-policy.yaml`; `MustLoadSample()`.
- `internal/db/policy/testdata/sample-policy.yaml` — exact §9.2 example; source of truth for Plan 03.
- `internal/db/policy/types_test.go`, `validate_test.go`, `compile_test.go`, `decode_test.go`, `evaluate_coverage_test.go`, `evaluate_implicit_deny_test.go`, `evaluate_audit_coverage_test.go`, `evaluate_approve_scope_test.go`, `evaluate_deny_precedence_test.go`, `evaluate_resolution_test.go`, `evaluate_multi_effect_test.go`, `evaluate_primary_ordering_test.go`, `evaluate_order_independence_test.go`, `evaluate_conn_test.go`, `sample_test.go`, `bench_test.go`.

**Modified:**

- `internal/db/effects/subtype.go` — add `ParseSubtype(string) (Subtype, bool)`.
- `internal/db/effects/subtype_test.go` — exercise `ParseSubtype`.
- `internal/db/effects/resolution.go` — add `ParseResolution(string) (Resolution, bool)`.
- `internal/db/effects/resolution_test.go` — exercise `ParseResolution`.
- `internal/policy/model.go` — add three `yaml.Node` fields on `Policy`: `DBServices`, `DatabaseRules`, `DatabaseConnectionRules`.
- `internal/policy/load_additional_test.go` — add a regression test that YAML containing the three keys still loads under `KnownFields(true)`.

**Object-field matching policy** (resolved in this plan; applies to `objects:` glob in `StatementRule`):

| `ObjectKind` | Glob matches against |
|--------------|----------------------|
| `ObjectTable`, `ObjectView`, `ObjectFunction`, `ObjectSchema`, `ObjectIndex`, `ObjectSequence`, `ObjectSubscription`, `ObjectPublication`, `ObjectServer`, `ObjectUserMapping`, `ObjectTablespace`, `ObjectRole` | `ObjectRef.Name` |
| `ObjectGUC` | `ObjectRef.Name` (already lowercased per §6.3) |
| `ObjectExternalEndpoint` | `ObjectRef.Host` |
| `ObjectFilesystemPath` | `ObjectRef.Path` |
| `ObjectProgram` | `ObjectRef.Argv0` |

The `schemas:` glob, when present, matches against `ObjectRef.Schema` for relation-kind objects only; non-relation objects (external_endpoint, filesystem_path, program) ignore the `schemas:` clause (treat as covered if `schemas:` is absent; treat as unmatched if present and non-empty).

---

## Task 1: Preflight — add `ParseSubtype` and `ParseResolution` to `effects`

**Why:** `validate.go` will reject unknown `operations` and `subtypes` tokens. `ExpandAlias` covers operations; subtypes need their own parser. Resolution parsing supports `match_object_resolution`.

**Files:**
- Modify: `internal/db/effects/subtype.go`
- Modify: `internal/db/effects/subtype_test.go`
- Modify: `internal/db/effects/resolution.go`
- Modify: `internal/db/effects/resolution_test.go`

- [ ] **Step 1: Write the failing test for `ParseSubtype`**

Append to `internal/db/effects/subtype_test.go`:

```go
func TestParseSubtype(t *testing.T) {
	cases := []struct {
		in    string
		want  Subtype
		ok    bool
	}{
		{"set", SubtypeSet, true},
		{"set_search_path", SubtypeSetSearchPath, true},
		{"discard_plans", SubtypeDiscardPlans, true},
		{"create_subscription", SubtypeCreateSubscription, true},
		{"", SubtypeNone, false},
		{"not_a_subtype", SubtypeNone, false},
	}
	for _, c := range cases {
		got, ok := ParseSubtype(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseSubtype(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
```

- [ ] **Step 2: Run the test, expect failure**

Run: `go test ./internal/db/effects -run TestParseSubtype`
Expected: `undefined: ParseSubtype`.

- [ ] **Step 3: Implement `ParseSubtype`**

Append to `internal/db/effects/subtype.go`:

```go
// ParseSubtype parses the canonical lowercase subtype name. The empty string
// returns (SubtypeNone, false) — operators wishing to match group-level only
// should leave the rule's subtypes clause absent. Returns ok=false on unknown.
func ParseSubtype(name string) (Subtype, bool) {
	if name == "" {
		return SubtypeNone, false
	}
	for s, info := range subtypeTable {
		if info.name == name {
			return s, true
		}
	}
	return SubtypeNone, false
}
```

- [ ] **Step 4: Run the test, expect pass**

Run: `go test ./internal/db/effects -run TestParseSubtype -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for `ParseResolution`**

Append to `internal/db/effects/resolution_test.go`:

```go
func TestParseResolution(t *testing.T) {
	cases := []struct {
		in   string
		want Resolution
		ok   bool
	}{
		{"qualified_syntactic", ResolutionQualified, true},
		{"unqualified_syntactic", ResolutionUnqualified, true},
		{"ambiguous_after_search_path", ResolutionAmbiguousAfterSearchPath, true},
		{"maybe_temp_shadowed", ResolutionMaybeTempShadowed, true},
		{"unresolved", ResolutionUnresolved, true},
		{"", 0, false},
		{"nonsense", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseResolution(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseResolution(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
```

- [ ] **Step 6: Run the test, expect failure**

Run: `go test ./internal/db/effects -run TestParseResolution`
Expected: `undefined: ParseResolution`.

- [ ] **Step 7: Implement `ParseResolution`**

Append to `internal/db/effects/resolution.go`:

```go
// ParseResolution parses the canonical lowercase resolution-tag name.
// Returns ok=false on unknown input (including the empty string).
func ParseResolution(name string) (Resolution, bool) {
	for i, n := range resolutionNames {
		if n == name {
			return Resolution(i), true
		}
	}
	return 0, false
}
```

- [ ] **Step 8: Run the test, expect pass**

Run: `go test ./internal/db/effects -run TestParseResolution -v`
Expected: PASS.

- [ ] **Step 9: Run all effects tests**

Run: `go test ./internal/db/effects/...`
Expected: PASS (no regression).

- [ ] **Step 10: Commit**

```bash
git add internal/db/effects/subtype.go internal/db/effects/subtype_test.go \
        internal/db/effects/resolution.go internal/db/effects/resolution_test.go
git commit -m "$(cat <<'EOF'
db/effects: add ParseSubtype and ParseResolution

Plan 02's policy validator needs these helpers to reject unknown
operations/subtypes/match_object_resolution tokens at config-load time.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Public types and enums in `internal/db/policy/types.go`

**Why:** Lock the public surface before any logic depends on it. Pure data types, no methods beyond `String()` for enums.

**Files:**
- Create: `internal/db/policy/types.go`
- Create: `internal/db/policy/redaction.go`
- Create: `internal/db/policy/types_test.go`

- [ ] **Step 1: Write `internal/db/policy/types_test.go`**

```go
package policy

import "testing"

func TestDecisionVerbString(t *testing.T) {
	cases := []struct {
		v    DecisionVerb
		want string
	}{
		{VerbAllow, "allow"},
		{VerbAudit, "audit"},
		{VerbApprove, "approve"},
		{VerbDeny, "deny"},
	}
	for _, c := range cases {
		if got := c.v.String(); got != c.want {
			t.Errorf("DecisionVerb(%d).String() = %q, want %q", c.v, got, c.want)
		}
	}
}

func TestRuleKindString(t *testing.T) {
	cases := []struct {
		k    RuleKind
		want string
	}{
		{RuleKindStatement, "statement"},
		{RuleKindConnection, "connection"},
		{RuleKindCancel, "cancel"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("RuleKind(%d).String() = %q, want %q", c.k, got, c.want)
		}
	}
}

func TestRedactionTierString(t *testing.T) {
	cases := []struct {
		r    RedactionTier
		want string
	}{
		{RedactNone, "none"},
		{RedactParametersRedacted, "parameters_redacted"},
		{RedactFull, "full"},
	}
	for _, c := range cases {
		if got := c.r.String(); got != c.want {
			t.Errorf("RedactionTier(%d).String() = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestParseRedactionTier(t *testing.T) {
	cases := []struct {
		in   string
		want RedactionTier
		ok   bool
	}{
		{"none", RedactNone, true},
		{"parameters_redacted", RedactParametersRedacted, true},
		{"full", RedactFull, true},
		{"", 0, false},
		{"REDACTED", 0, false},
	}
	for _, c := range cases {
		got, ok := ParseRedactionTier(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("ParseRedactionTier(%q) = (%v, %v), want (%v, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}
```

- [ ] **Step 2: Run, expect failure (package missing)**

Run: `go test ./internal/db/policy/...`
Expected: `no Go files in internal/db/policy`.

- [ ] **Step 3: Write `internal/db/policy/types.go`**

```go
// Package policy implements the AgentSH database-access policy evaluator
// per docs/agentsh-db-access-spec.md §9–§10. The package is platform-agnostic
// and produces only data types and pure functions; events, approvals, and
// wire I/O belong to later plans (Plan 04+).
package policy

import (
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// ServiceID is the operator-supplied identifier of a db_service.
type ServiceID string

// DecisionVerb mirrors the §10.1 verbs. Implicit deny is *not* a separate
// verb; it is encoded as Verb == VerbDeny with RuleName == "" (see §7 of the
// design doc and Decision below).
type DecisionVerb uint8

const (
	VerbAllow DecisionVerb = iota
	VerbAudit
	VerbApprove
	VerbDeny
)

func (v DecisionVerb) String() string {
	switch v {
	case VerbAllow:
		return "allow"
	case VerbAudit:
		return "audit"
	case VerbApprove:
		return "approve"
	case VerbDeny:
		return "deny"
	default:
		return ""
	}
}

// RuleKind labels which rule family produced a Decision; surfaced to DBEvent
// as decision.rule_kind in §8.
type RuleKind uint8

const (
	RuleKindStatement RuleKind = iota
	RuleKindConnection
	RuleKindCancel
)

func (k RuleKind) String() string {
	switch k {
	case RuleKindStatement:
		return "statement"
	case RuleKindConnection:
		return "connection"
	case RuleKindCancel:
		return "cancel"
	default:
		return ""
	}
}

// ConnectionMatchKind is the connection rule's match_kind field, used by
// EvaluateConnection.
type ConnectionMatchKind uint8

const (
	MatchConnect ConnectionMatchKind = iota
	MatchCancel
	MatchReplication
)

// DBService is the on-disk shape of a db_services entry per §9.1.
type DBService struct {
	Name                      string `yaml:"-"` // populated from map key
	Family                    string `yaml:"family"`
	Dialect                   string `yaml:"dialect"`
	Upstream                  string `yaml:"upstream"`
	TLSMode                   string `yaml:"tls_mode"`
	DenyModeInTx              string `yaml:"deny_mode_in_tx,omitempty"`
	AllowFunctionCallProtocol bool   `yaml:"allow_function_call_protocol,omitempty"`
	AllowGSSEncryption        bool   `yaml:"allow_gss_encryption,omitempty"`
	TrustedNetwork            bool   `yaml:"trusted_network,omitempty"`
}

// StatementRule is the on-disk shape of a database_rules entry per §9.2.
type StatementRule struct {
	Name                        string        `yaml:"name"`
	DBService                   string        `yaml:"db_service,omitempty"`
	DBFamily                    string        `yaml:"db_family,omitempty"`
	DBDialect                   string        `yaml:"db_dialect,omitempty"`
	Schemas                     []string      `yaml:"schemas,omitempty"`
	Objects                     []string      `yaml:"objects,omitempty"`
	Operations                  []string      `yaml:"operations"`
	Subtypes                    []string      `yaml:"subtypes,omitempty"`
	MatchObjectResolution       string        `yaml:"match_object_resolution,omitempty"`
	Decision                    string        `yaml:"decision"`
	Message                     string        `yaml:"message,omitempty"`
	Timeout                     time.Duration `yaml:"timeout,omitempty"`
	AcknowledgeAuditOnDangerous bool          `yaml:"acknowledge_audit_on_dangerous,omitempty"`
}

// ConnectionRule is the on-disk shape of a database_connection_rules entry per §9.3.
type ConnectionRule struct {
	Name            string        `yaml:"name"`
	DBService       string        `yaml:"db_service,omitempty"`
	MatchKind       string        `yaml:"match_kind,omitempty"`
	DBUser          []string      `yaml:"db_user,omitempty"`
	Database        string        `yaml:"database,omitempty"`
	ApplicationName string        `yaml:"application_name,omitempty"`
	ClientIdentity  string        `yaml:"client_identity,omitempty"`
	Decision        string        `yaml:"decision"`
	Message         string        `yaml:"message,omitempty"`
	Timeout         time.Duration `yaml:"timeout,omitempty"`
}

// ConnectionInfo is the input to EvaluateConnection. Plan 04 populates it
// from StartupMessage parameters (or sentinel zero values under passthrough TLS).
type ConnectionInfo struct {
	Service         ServiceID
	MatchKind       ConnectionMatchKind
	DBUser          string
	Database        string
	ApplicationName string
	ClientIdentity  string
}

// Decision is the output of Evaluate / EvaluateConnection.
//
// Implicit deny (no rule covers an object in some effect) is encoded as
// Verb == VerbDeny with RuleName == "" and Reason == "no rule covers ..." —
// this matches the §8 DBEvent wire schema (decision.verb has only four values)
// while still letting tests assert on the distinction via RuleName.
type Decision struct {
	Verb                   DecisionVerb
	RuleKind               RuleKind
	RuleName               string
	MatchingEffectIndex    int           // -1 for connection-level decisions
	MatchingEffectGroup    effects.Group // GroupUnknown for connection-level decisions
	Reason                 string
	ContributingAuditRules []string // populated only when Verb == VerbApprove
	Approval               *ApprovalRequest
}

// ApprovalRequest carries data Plan 04 needs to spin up the approval flow.
// Plan 02 produces it but does not act on it.
type ApprovalRequest struct {
	Timeout                  time.Duration
	ContributingApproveRules []string
}

// Warning is a non-fatal issue surfaced by Decode. Errors abort load; warnings
// accumulate so operators can fix them at leisure.
type Warning struct {
	Rule    string // rule name, "" for service-level
	Field   string // YAML field, e.g. "decision"
	Code    string // stable identifier for callers / tests
	Message string
	Line    int // yaml.v3 node Line, for IDE-friendly output
}

// RuleSet is the immutable, evaluator-ready policy. Build via Decode.
// Internals are private; callers consume via Evaluate / EvaluateConnection /
// Redaction / Service.
type RuleSet struct {
	services   map[ServiceID]*DBService
	statement  []*compiledStatementRule
	connection []*compiledConnectionRule
	redaction  RedactionConfig
}

// Redaction returns the policies.db block configuration.
func (rs *RuleSet) Redaction() RedactionConfig { return rs.redaction }

// Service returns the named db_service definition, if present.
func (rs *RuleSet) Service(id ServiceID) (DBService, bool) {
	if rs == nil {
		return DBService{}, false
	}
	s, ok := rs.services[id]
	if !ok {
		return DBService{}, false
	}
	return *s, true
}
```

- [ ] **Step 4: Write `internal/db/policy/redaction.go`**

```go
package policy

// RedactionTier is the statement-text redaction tier per §10.3. It is locally
// defined (not imported from internal/db/events) so that internal/db/events
// can later import this package without a cycle.
type RedactionTier uint8

const (
	RedactNone RedactionTier = iota
	RedactParametersRedacted
	RedactFull
)

var redactionTierNames = [...]string{
	RedactNone:               "none",
	RedactParametersRedacted: "parameters_redacted",
	RedactFull:               "full",
}

func (r RedactionTier) String() string {
	if int(r) >= len(redactionTierNames) {
		return ""
	}
	return redactionTierNames[r]
}

// ParseRedactionTier parses the canonical lowercase tier name. Empty input
// returns ok=false (callers may want to apply a default at a higher level).
func ParseRedactionTier(s string) (RedactionTier, bool) {
	for i, n := range redactionTierNames {
		if n == s {
			return RedactionTier(i), true
		}
	}
	return 0, false
}

// RedactionConfig is the policies.db block. See §10.3.
//
// Defaults applied by Decode when a field is missing:
//   LogStatements:            RedactParametersRedacted
//   ApprovalStatementPreview: RedactParametersRedacted (named "redacted" in YAML)
//   ApprovalStatementChars:   200
type RedactionConfig struct {
	LogStatements            RedactionTier
	ApprovalStatementPreview RedactionTier
	ApprovalStatementChars   int
}
```

Note: `compiledStatementRule` and `compiledConnectionRule` are referenced by `RuleSet` but defined in `compile.go` (Task 6). Stub them now to keep the package compiling:

- [ ] **Step 5: Stub `compile.go`**

Create `internal/db/policy/compile.go`:

```go
package policy

// Stubs filled in by Task 6. They exist now so RuleSet compiles.
type compiledStatementRule struct{}
type compiledConnectionRule struct{}
```

- [ ] **Step 6: Run, expect pass**

Run: `go test ./internal/db/policy/...`
Expected: PASS (only types_test).

- [ ] **Step 7: Cross-compile check**

Run: `GOOS=windows go build ./internal/db/policy/...`
Expected: success.

- [ ] **Step 8: Commit**

```bash
git add internal/db/policy/
git commit -m "$(cat <<'EOF'
db/policy: scaffold types and enums

Public surface for the policy evaluator: DecisionVerb, RuleKind,
ConnectionMatchKind, DBService, StatementRule, ConnectionRule, Decision,
ApprovalRequest, Warning, RedactionTier, RedactionConfig, RuleSet skeleton.

Logic lands in subsequent commits; this commit only locks the data shapes
so internal/policy can declare matching yaml.Node fields.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: Wire `yaml.Node` fields into `internal/policy.Policy`

**Why:** Without this, `KnownFields(true)` in `internal/policy/load.go` rejects YAML containing `db_services`, `database_rules`, or `database_connection_rules`. Internal/policy stores them opaquely; `dbpolicy.Decode` does the real parsing.

**Files:**
- Modify: `internal/policy/model.go`
- Modify: `internal/policy/load_additional_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/policy/load_additional_test.go`:

```go
func TestLoadAcceptsDBRuleFamilies(t *testing.T) {
	yaml := []byte(`
version: 1
name: db-test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: r1
    db_service: appdb
    operations: [READ]
    decision: allow
database_connection_rules:
  - name: c1
    db_service: appdb
    decision: allow
`)
	if _, err := LoadFromBytes(yaml); err != nil {
		t.Fatalf("LoadFromBytes rejected DB rule families: %v", err)
	}
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/policy -run TestLoadAcceptsDBRuleFamilies -v`
Expected: FAIL with `field db_services not found in type policy.Policy` (or similar).

- [ ] **Step 3: Add the three fields to `Policy`**

In `internal/policy/model.go`, locate the `type Policy struct {` block (around line 12) and add these three fields immediately before the closing brace (place them after `HTTPServices`):

```go
	// DB access (Phase 1, Plan 02). Stored opaquely as yaml.Node so this
	// package does not depend on internal/db/policy. Decoding and validation
	// live in internal/db/policy.Decode.
	DBServices              yaml.Node `yaml:"db_services,omitempty"`
	DatabaseRules           yaml.Node `yaml:"database_rules,omitempty"`
	DatabaseConnectionRules yaml.Node `yaml:"database_connection_rules,omitempty"`
```

- [ ] **Step 4: Run, expect pass**

Run: `go test ./internal/policy -run TestLoadAcceptsDBRuleFamilies -v`
Expected: PASS.

- [ ] **Step 5: Run full internal/policy tests for regression**

Run: `go test ./internal/policy/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/policy/model.go internal/policy/load_additional_test.go
git commit -m "$(cat <<'EOF'
policy: accept db_services / database_rules / database_connection_rules

Three new yaml.Node fields on Policy let YAML containing the DB rule families
parse under KnownFields(true) without coupling internal/policy to
internal/db/policy. The DB-side Decode handles the real parsing and
validation per spec §9.4.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Validate — errors

**Why:** §9.4 lists 11 hard errors plus 3 we add (`glob_compile`, `message_template_parse`, `service_unknown_tls_mode`, `service_tls_mode_required`, `approve_timeout_exceeds_max`). Validation runs over decoded shapes so it can be tested without invoking compile.

**Files:**
- Create: `internal/db/policy/validate.go`
- Create: `internal/db/policy/validate_test.go`

- [ ] **Step 1: Write `internal/db/policy/validate_test.go`**

```go
package policy

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// helperValidate runs validate against the decoded shapes; tests construct
// these directly rather than going through Decode so each error code is
// reachable in isolation.
func helperValidate(t *testing.T, svcs map[ServiceID]*DBService, stmt []*StatementRule, conn []*ConnectionRule) ([]Warning, error) {
	t.Helper()
	return validate(svcs, stmt, conn)
}

func TestValidate_NoErrors(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres",
			Upstream: "db.internal:5432", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{Name: "r1", DBService: "appdb", Operations: []string{"READ"}, Decision: "allow"}}
	conn := []*ConnectionRule{{Name: "c1", DBService: "appdb", Decision: "allow"}}
	if _, err := helperValidate(t, svcs, stmt, conn); err != nil {
		t.Fatalf("validate: %v", err)
	}
}

func TestValidate_ServiceTLSModeRequired(t *testing.T) {
	svcs := map[ServiceID]*DBService{"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1"}}
	_, err := helperValidate(t, svcs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "service_tls_mode_required") {
		t.Fatalf("want service_tls_mode_required, got %v", err)
	}
}

func TestValidate_ServiceUnknownTLSMode(t *testing.T) {
	svcs := map[ServiceID]*DBService{"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "weird"}}
	_, err := helperValidate(t, svcs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "service_unknown_tls_mode") {
		t.Fatalf("want service_unknown_tls_mode, got %v", err)
	}
}

func TestValidate_ServicePlaintextUnsafeDest(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"warehouse": {Name: "warehouse", Family: "postgres", Dialect: "postgres",
			Upstream: "warehouse.public.example.com:5432",
			TLSMode:  "terminate_plaintext_upstream"},
	}
	_, err := helperValidate(t, svcs, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "service_plaintext_unsafe_dest") {
		t.Fatalf("want service_plaintext_unsafe_dest, got %v", err)
	}
}

func TestValidate_ServicePlaintextAllowedOnLoopback(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"local": {Name: "local", Family: "postgres", Dialect: "postgres",
			Upstream: "127.0.0.1:5432", TLSMode: "terminate_plaintext_upstream"},
	}
	if _, err := helperValidate(t, svcs, nil, nil); err != nil {
		t.Fatalf("loopback plaintext should be allowed: %v", err)
	}
}

func TestValidate_RuleServicePassthrough(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"legacy": {Name: "legacy", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "passthrough"},
	}
	stmt := []*StatementRule{{Name: "r", DBService: "legacy", Operations: []string{"READ"}, Decision: "allow"}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_service_passthrough") {
		t.Fatalf("want rule_service_passthrough, got %v", err)
	}
}

func TestValidate_RuleServiceUnknown(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", DBService: "ghost", Operations: []string{"READ"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_service_unknown") {
		t.Fatalf("want rule_service_unknown, got %v", err)
	}
}

func TestValidate_ConnPassthroughFieldUnavailable(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"legacy": {Name: "legacy", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "passthrough"},
	}
	conn := []*ConnectionRule{{Name: "c", DBService: "legacy", DBUser: []string{"foo"}, Decision: "allow"}}
	_, err := helperValidate(t, svcs, nil, conn)
	if err == nil || !strings.Contains(err.Error(), "conn_passthrough_field_unavailable") {
		t.Fatalf("want conn_passthrough_field_unavailable, got %v", err)
	}
}

func TestValidate_RuleDecisionRedirect(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", Operations: []string{"READ"}, Decision: "redirect"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_decision_redirect") {
		t.Fatalf("want rule_decision_redirect, got %v", err)
	}
}

func TestValidate_RuleUnknownSubtype(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", Operations: []string{"session"}, Subtypes: []string{"not_real"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_unknown_subtype") {
		t.Fatalf("want rule_unknown_subtype, got %v", err)
	}
}

func TestValidate_RuleUnknownOperation(t *testing.T) {
	stmt := []*StatementRule{{Name: "r", Operations: []string{"NONSENSE"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_unknown_operation") {
		t.Fatalf("want rule_unknown_operation, got %v", err)
	}
}

func TestValidate_RuleTooBroadAllow(t *testing.T) {
	stmt := []*StatementRule{{Name: "yolo", Operations: []string{"*"}, Decision: "allow"}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "rule_too_broad_allow") {
		t.Fatalf("want rule_too_broad_allow, got %v", err)
	}
}

func TestValidate_CancelRuleApprove(t *testing.T) {
	conn := []*ConnectionRule{{Name: "c", MatchKind: "cancel", Decision: "approve"}}
	_, err := helperValidate(t, nil, nil, conn)
	if err == nil || !strings.Contains(err.Error(), "cancel_rule_approve") {
		t.Fatalf("want cancel_rule_approve, got %v", err)
	}
}

func TestValidate_ApproveTimeoutExceedsMax(t *testing.T) {
	stmt := []*StatementRule{{Name: "slow", Operations: []string{"READ"}, Decision: "approve", Timeout: 700 * time.Second}}
	_, err := helperValidate(t, nil, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "approve_timeout_exceeds_max") {
		t.Fatalf("want approve_timeout_exceeds_max, got %v", err)
	}
}

func TestValidate_AllErrorsJoin(t *testing.T) {
	// Two unrelated errors must both surface (errors.Join).
	svcs := map[ServiceID]*DBService{"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1"}}
	stmt := []*StatementRule{{Name: "r", DBService: "ghost", Operations: []string{"READ"}, Decision: "allow"}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if !strings.Contains(err.Error(), "service_tls_mode_required") || !strings.Contains(err.Error(), "rule_service_unknown") {
		t.Fatalf("expected both error codes joined, got: %v", err)
	}
	// Sanity: errors.Is over the joined error.
	_ = errors.Unwrap(err)
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/db/policy -run TestValidate_`
Expected: `undefined: validate`.

- [ ] **Step 3: Implement `validate.go`**

Create `internal/db/policy/validate.go`:

```go
package policy

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

const approveTimeoutMax = 600 * time.Second

// validate checks decoded shapes against §9.4. It returns warnings (load
// proceeds) plus a joined error containing every fatal issue found, in source
// order: services first, then statement rules, then connection rules.
func validate(svcs map[ServiceID]*DBService, stmt []*StatementRule, conn []*ConnectionRule) ([]Warning, error) {
	var errs []error
	var warns []Warning

	for _, s := range svcs {
		errs = append(errs, validateService(s)...)
	}
	for _, r := range stmt {
		es, ws := validateStatementRule(r, svcs)
		errs = append(errs, es...)
		warns = append(warns, ws...)
	}
	for _, r := range conn {
		es, ws := validateConnectionRule(r, svcs)
		errs = append(errs, es...)
		warns = append(warns, ws...)
	}

	if len(errs) == 0 {
		return warns, nil
	}
	return warns, errors.Join(errs...)
}

func validateService(s *DBService) []error {
	var errs []error
	switch s.TLSMode {
	case "":
		errs = append(errs, fmt.Errorf("service_tls_mode_required: db_services[%q]: tls_mode is required", s.Name))
	case "passthrough", "terminate_reissue", "terminate_plaintext_upstream":
		// ok
	default:
		errs = append(errs, fmt.Errorf("service_unknown_tls_mode: db_services[%q]: unknown tls_mode %q", s.Name, s.TLSMode))
	}
	if s.TLSMode == "terminate_plaintext_upstream" && !s.TrustedNetwork {
		host := upstreamHost(s.Upstream)
		if !isLoopbackOrPrivate(host) {
			errs = append(errs, fmt.Errorf("service_plaintext_unsafe_dest: db_services[%q]: terminate_plaintext_upstream to %q requires trusted_network: true", s.Name, host))
		}
	}
	return errs
}

func validateStatementRule(r *StatementRule, svcs map[ServiceID]*DBService) ([]error, []Warning) {
	var errs []error
	var warns []Warning

	// db_service reference checks.
	if r.DBService != "" {
		svc, ok := svcs[ServiceID(r.DBService)]
		switch {
		case !ok:
			errs = append(errs, fmt.Errorf("rule_service_unknown: database_rules[%q]: db_service %q does not exist", r.Name, r.DBService))
		case svc.TLSMode == "passthrough":
			errs = append(errs, fmt.Errorf("rule_service_passthrough: database_rules[%q]: db_service %q is passthrough; statement rules unavailable", r.Name, r.DBService))
		}
	}

	// decision verb.
	switch r.Decision {
	case "allow", "deny", "approve", "audit":
		// ok
	case "redirect":
		errs = append(errs, fmt.Errorf("rule_decision_redirect: database_rules[%q]: redirect is Phase 2", r.Name))
	default:
		errs = append(errs, fmt.Errorf("rule_unknown_decision: database_rules[%q]: unknown decision %q", r.Name, r.Decision))
	}

	// operations / subtypes / match_object_resolution.
	if len(r.Operations) == 0 {
		errs = append(errs, fmt.Errorf("rule_operations_required: database_rules[%q]: operations is required", r.Name))
	}
	groups := map[effects.Group]struct{}{}
	for _, op := range r.Operations {
		gs, ok := effects.ExpandAlias(op)
		if !ok {
			errs = append(errs, fmt.Errorf("rule_unknown_operation: database_rules[%q]: unknown operations token %q", r.Name, op))
			continue
		}
		for _, g := range gs {
			groups[g] = struct{}{}
		}
	}
	for _, st := range r.Subtypes {
		if _, ok := effects.ParseSubtype(st); !ok {
			errs = append(errs, fmt.Errorf("rule_unknown_subtype: database_rules[%q]: unknown subtypes token %q", r.Name, st))
		}
	}
	if r.MatchObjectResolution != "" && r.MatchObjectResolution != "*" {
		if _, ok := effects.ParseResolution(r.MatchObjectResolution); !ok {
			errs = append(errs, fmt.Errorf("rule_unknown_resolution: database_rules[%q]: unknown match_object_resolution %q", r.Name, r.MatchObjectResolution))
		}
	}

	// approve timeout.
	if r.Decision == "approve" && r.Timeout > approveTimeoutMax {
		errs = append(errs, fmt.Errorf("approve_timeout_exceeds_max: database_rules[%q]: timeout %s exceeds %s", r.Name, r.Timeout, approveTimeoutMax))
	}

	// rule_too_broad_allow.
	if r.Decision == "allow" && r.DBService == "" && r.DBFamily == "" {
		hasStar := false
		for _, op := range r.Operations {
			if op == "*" {
				hasStar = true
				break
			}
		}
		if hasStar {
			errs = append(errs, fmt.Errorf("rule_too_broad_allow: database_rules[%q]: refusing to allow operations:[\"*\"] without db_service or db_family scope", r.Name))
		}
	}

	// audit-on-dangerous warning.
	if r.Decision == "audit" && !r.AcknowledgeAuditOnDangerous {
		if hasHighRisk(groups) {
			warns = append(warns, Warning{
				Rule:    r.Name,
				Field:   "decision",
				Code:    "audit_on_dangerous",
				Message: fmt.Sprintf("rule %q audits operations of risk tier >= high; set acknowledge_audit_on_dangerous: true to silence", r.Name),
			})
		}
	}

	return errs, warns
}

func validateConnectionRule(r *ConnectionRule, svcs map[ServiceID]*DBService) ([]error, []Warning) {
	var errs []error
	var warns []Warning

	mk := r.MatchKind
	if mk == "" {
		mk = "connect"
	}

	// service ref + passthrough field checks.
	var svc *DBService
	if r.DBService != "" {
		s, ok := svcs[ServiceID(r.DBService)]
		if !ok {
			errs = append(errs, fmt.Errorf("rule_service_unknown: database_connection_rules[%q]: db_service %q does not exist", r.Name, r.DBService))
		} else {
			svc = s
		}
	}
	if svc != nil && svc.TLSMode == "passthrough" {
		if len(r.DBUser) > 0 || r.Database != "" || r.ApplicationName != "" {
			errs = append(errs, fmt.Errorf("conn_passthrough_field_unavailable: database_connection_rules[%q]: db_user/database/application_name not visible under passthrough", r.Name))
		}
	}

	// match_kind sanity.
	switch mk {
	case "connect", "cancel", "replication":
		// ok
	default:
		errs = append(errs, fmt.Errorf("conn_unknown_match_kind: database_connection_rules[%q]: unknown match_kind %q", r.Name, r.MatchKind))
	}

	// decision verb.
	switch r.Decision {
	case "allow", "deny", "approve", "audit":
		// ok
	case "redirect":
		errs = append(errs, fmt.Errorf("rule_decision_redirect: database_connection_rules[%q]: redirect is Phase 2", r.Name))
	default:
		errs = append(errs, fmt.Errorf("rule_unknown_decision: database_connection_rules[%q]: unknown decision %q", r.Name, r.Decision))
	}

	// cancel + approve forbidden (R19).
	if mk == "cancel" && r.Decision == "approve" {
		errs = append(errs, fmt.Errorf("cancel_rule_approve: database_connection_rules[%q]: approve on match_kind: cancel is invalid (cancel is real-time; cannot be held)", r.Name))
	}

	// approve timeout.
	if r.Decision == "approve" && r.Timeout > approveTimeoutMax {
		errs = append(errs, fmt.Errorf("approve_timeout_exceeds_max: database_connection_rules[%q]: timeout %s exceeds %s", r.Name, r.Timeout, approveTimeoutMax))
	}

	// approve-on-replication warning.
	if mk == "replication" && r.Decision == "approve" {
		warns = append(warns, Warning{
			Rule:    r.Name,
			Field:   "decision",
			Code:    "approve_on_replication",
			Message: fmt.Sprintf("rule %q approves a match_kind: replication connection; replication is default-deny per §11.1", r.Name),
		})
	}

	return errs, warns
}

// hasHighRisk reports whether the alias-expanded group set includes any
// risk tier >= high (per §9.4 R13).
func hasHighRisk(groups map[effects.Group]struct{}) bool {
	for g := range groups {
		switch g.RiskTier() {
		case effects.High, effects.Critical:
			return true
		}
	}
	return false
}

// upstreamHost extracts the host portion of "host:port"; returns the input
// unchanged on parse failure.
func upstreamHost(upstream string) string {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream
	}
	return host
}

// isLoopbackOrPrivate reports whether host is a loopback address, a private
// (RFC1918 / ULA) IP, or the literal "localhost".
func isLoopbackOrPrivate(host string) bool {
	if host == "" {
		return false
	}
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	if ip == nil {
		// Hostnames other than "localhost" are not assumed safe.
		return false
	}
	return ip.IsLoopback() || ip.IsPrivate()
}
```

Note: `effects.High` and `effects.Critical` exist (`internal/db/effects/risk_tier.go` defines `Safe / Low / Medium / High / Critical`).

- [ ] **Step 4: Run, expect pass**

Run: `go test ./internal/db/policy -run TestValidate_ -v`
Expected: PASS for all subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/db/policy/validate.go internal/db/policy/validate_test.go
git commit -m "$(cat <<'EOF'
db/policy: validate decoded rule shapes per spec §9.4

Errors: service_tls_mode_required, service_unknown_tls_mode,
service_plaintext_unsafe_dest, rule_service_passthrough,
rule_service_unknown, conn_passthrough_field_unavailable,
rule_decision_redirect, rule_unknown_subtype, rule_unknown_operation,
rule_unknown_resolution, rule_unknown_decision, rule_operations_required,
rule_too_broad_allow, cancel_rule_approve, approve_timeout_exceeds_max,
conn_unknown_match_kind.

Warnings: audit_on_dangerous (silenced by acknowledge_audit_on_dangerous),
approve_on_replication.

errors.Join across all failures so operators see every problem per load.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Compile — globs, aliases, message templates

**Why:** `validate` operates on raw shapes. The evaluator needs precompiled forms (compiled globs, alias-expanded group sets, parsed message templates) so the hot path stays alloc-light.

**Files:**
- Modify: `internal/db/policy/compile.go` (replace stubs from Task 2 Step 5)
- Create: `internal/db/policy/compile_test.go`

- [ ] **Step 1: Write `internal/db/policy/compile_test.go`**

```go
package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestCompileStatementRule_GlobMatch(t *testing.T) {
	r := &StatementRule{
		Name: "pii", Objects: []string{"pii.*", "secrets"},
		Operations: []string{"READ"}, Decision: "deny",
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Name: "pii.ssns"}) {
		t.Errorf("expected pii.ssns to match pii.*")
	}
	if !c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Name: "secrets"}) {
		t.Errorf("expected secrets to match secrets literal")
	}
	if c.objectMatches(effects.ObjectRef{Kind: effects.ObjectTable, Name: "users"}) {
		t.Errorf("did not expect users to match")
	}
}

func TestCompileStatementRule_NoObjectsCoversAll(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.coversAllObjects() {
		t.Errorf("expected coversAllObjects() to be true when objects: is empty")
	}
}

func TestCompileStatementRule_ExternalEndpointHostMatch(t *testing.T) {
	r := &StatementRule{Name: "endpoint", Objects: []string{"*.internal"},
		Operations: []string{"READ"}, Decision: "deny"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	obj := effects.ObjectRef{Kind: effects.ObjectExternalEndpoint, Host: "db.internal", Port: 5432}
	if !c.objectMatches(obj) {
		t.Errorf("expected db.internal to match *.internal for ObjectExternalEndpoint")
	}
}

func TestCompileStatementRule_GroupAliasExpanded(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"MUTATE"}, Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	want := []effects.Group{effects.GroupWrite, effects.GroupModify, effects.GroupDelete}
	for _, g := range want {
		if _, ok := c.groups[g]; !ok {
			t.Errorf("MUTATE missing group %v", g)
		}
	}
	if _, ok := c.groups[effects.GroupRead]; ok {
		t.Errorf("MUTATE should not include GroupRead")
	}
}

func TestCompileStatementRule_MessageTemplate(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "deny",
		Message: "denied {{.Operation}} on {{.Object}}"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	got := c.renderMessage(messageContext{Operation: "read", Object: "users"})
	if got != "denied read on users" {
		t.Errorf("renderMessage = %q", got)
	}
}

func TestCompileStatementRule_BadGlob(t *testing.T) {
	r := &StatementRule{Name: "r", Objects: []string{"["}, Operations: []string{"READ"}, Decision: "allow"}
	_, err := compileStatementRule(r)
	if err == nil || !strings.Contains(err.Error(), "glob_compile") {
		t.Fatalf("want glob_compile error, got %v", err)
	}
}

func TestCompileStatementRule_BadTemplate(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "deny",
		Message: "{{.Unclosed"}
	_, err := compileStatementRule(r)
	if err == nil || !strings.Contains(err.Error(), "message_template_parse") {
		t.Fatalf("want message_template_parse error, got %v", err)
	}
}

func TestCompileStatementRule_DefaultApproveTimeout(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"}, Decision: "approve"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.timeout != 60*time.Second {
		t.Errorf("default approve timeout = %v, want 60s", c.timeout)
	}
}

func TestCompileStatementRule_ResolutionMatcher(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"},
		MatchObjectResolution: "qualified_syntactic", Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.matchesResolution(effects.ResolutionQualified) {
		t.Errorf("expected qualified to match")
	}
	if c.matchesResolution(effects.ResolutionUnqualified) {
		t.Errorf("did not expect unqualified to match")
	}
}

func TestCompileStatementRule_ResolutionWildcard(t *testing.T) {
	r := &StatementRule{Name: "r", Operations: []string{"READ"},
		MatchObjectResolution: "*", Decision: "allow"}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if !c.matchesResolution(effects.ResolutionUnresolved) {
		t.Errorf("* should match every resolution")
	}
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/db/policy -run TestCompile`
Expected: FAIL — `compileStatementRule` undefined.

- [ ] **Step 3: Replace `internal/db/policy/compile.go`**

```go
package policy

import (
	"fmt"
	"strings"
	"text/template"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/gobwas/glob"
)

const defaultApproveTimeout = 60 * time.Second

// compiledStatementRule is the evaluator-ready form of a StatementRule.
type compiledStatementRule struct {
	src             *StatementRule
	verb            DecisionVerb
	groups          map[effects.Group]struct{}
	subtypes        map[effects.Subtype]struct{} // empty = all subtypes match
	resolution      resolutionMatcher
	schemas         []glob.Glob // empty = all schemas match
	objects         []glob.Glob // empty = all objects match
	timeout         time.Duration
	msgTemplate     *template.Template // nil = no message rendering
	serviceFilter   serviceFilter
}

// compiledConnectionRule is the evaluator-ready form of a ConnectionRule.
type compiledConnectionRule struct {
	src             *ConnectionRule
	verb            DecisionVerb
	matchKind       ConnectionMatchKind
	dbUsers         map[string]struct{} // empty = no constraint
	database        string              // "" = no constraint
	applicationName glob.Glob           // nil = no constraint
	clientIdentity  glob.Glob           // nil = no constraint
	timeout         time.Duration
	msgTemplate     *template.Template
	serviceFilter   serviceFilter
}

// resolutionMatcher selects which Resolution values match.
//
//   kind=any  → matches anything (corresponds to MatchObjectResolution == "" or "*")
//   kind=eq   → matches exactly r
type resolutionMatcher struct {
	kind resMatcherKind
	r    effects.Resolution
}

type resMatcherKind uint8

const (
	resAny resMatcherKind = iota
	resEq
)

func (m resolutionMatcher) matches(r effects.Resolution) bool {
	switch m.kind {
	case resAny:
		return true
	case resEq:
		return m.r == r
	default:
		return false
	}
}

// serviceFilter encodes the (db_service, db_family, db_dialect) filter on a rule.
// Empty fields mean "any". A rule applies to a service S iff every non-empty
// filter field equals the corresponding field on S.
type serviceFilter struct {
	service ServiceID
	family  string
	dialect string
}

// matches reports whether the rule applies to the named service. svcs[id] must
// exist (rule_service_unknown is caught at validate time).
func (f serviceFilter) matches(id ServiceID, svc *DBService) bool {
	if f.service != "" && f.service != id {
		return false
	}
	if f.family != "" && (svc == nil || svc.Family != f.family) {
		return false
	}
	if f.dialect != "" && (svc == nil || svc.Dialect != f.dialect) {
		return false
	}
	return true
}

// messageContext is the data passed to a rule's message template.
type messageContext struct {
	Operation        string
	Subtype          string
	Schema           string
	Object           string
	Verb             string
	StatementPreview string
}

// compileStatementRule transforms a validated StatementRule into a
// compiledStatementRule. Errors carry the "glob_compile" or
// "message_template_parse" prefix for caller surfacing.
func compileStatementRule(r *StatementRule) (*compiledStatementRule, error) {
	c := &compiledStatementRule{
		src:           r,
		groups:        map[effects.Group]struct{}{},
		subtypes:      map[effects.Subtype]struct{}{},
		serviceFilter: serviceFilter{service: ServiceID(r.DBService), family: r.DBFamily, dialect: r.DBDialect},
	}
	switch r.Decision {
	case "allow":
		c.verb = VerbAllow
	case "deny":
		c.verb = VerbDeny
	case "approve":
		c.verb = VerbApprove
	case "audit":
		c.verb = VerbAudit
	default:
		return nil, fmt.Errorf("compile: rule %q has unhandled decision %q (validate should have rejected)", r.Name, r.Decision)
	}

	for _, op := range r.Operations {
		gs, ok := effects.ExpandAlias(op)
		if !ok {
			return nil, fmt.Errorf("compile: rule %q has unknown operation %q (validate should have rejected)", r.Name, op)
		}
		for _, g := range gs {
			c.groups[g] = struct{}{}
		}
	}
	for _, st := range r.Subtypes {
		s, ok := effects.ParseSubtype(st)
		if !ok {
			return nil, fmt.Errorf("compile: rule %q has unknown subtype %q", r.Name, st)
		}
		c.subtypes[s] = struct{}{}
	}

	switch r.MatchObjectResolution {
	case "", "*":
		c.resolution = resolutionMatcher{kind: resAny}
	default:
		res, ok := effects.ParseResolution(r.MatchObjectResolution)
		if !ok {
			return nil, fmt.Errorf("compile: rule %q has unknown match_object_resolution %q", r.Name, r.MatchObjectResolution)
		}
		c.resolution = resolutionMatcher{kind: resEq, r: res}
	}

	for _, pat := range r.Schemas {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: rule %q schemas %q: %w", r.Name, pat, err)
		}
		c.schemas = append(c.schemas, g)
	}
	for _, pat := range r.Objects {
		g, err := glob.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: rule %q objects %q: %w", r.Name, pat, err)
		}
		c.objects = append(c.objects, g)
	}

	if strings.TrimSpace(r.Message) != "" {
		tmpl, err := template.New("msg").Parse(r.Message)
		if err != nil {
			return nil, fmt.Errorf("message_template_parse: rule %q: %w", r.Name, err)
		}
		c.msgTemplate = tmpl
	}

	c.timeout = r.Timeout
	if r.Decision == "approve" && c.timeout == 0 {
		c.timeout = defaultApproveTimeout
	}

	return c, nil
}

func (c *compiledStatementRule) coversAllObjects() bool { return len(c.objects) == 0 }

func (c *compiledStatementRule) matchesResolution(r effects.Resolution) bool {
	return c.resolution.matches(r)
}

// objectMatches reports whether any of the rule's `objects` globs matches
// the given ObjectRef per the kind→field table in this plan's File Structure
// section. Returns true unconditionally when c.objects is empty.
func (c *compiledStatementRule) objectMatches(o effects.ObjectRef) bool {
	if c.coversAllObjects() {
		return true
	}
	target := objectMatchField(o)
	for _, g := range c.objects {
		if g.Match(target) {
			return true
		}
	}
	return false
}

// schemaMatches reports whether the schemas: clause is absent or any glob in
// it matches the object's schema. Non-relation objects (no schema) are treated
// as covered when schemas: is absent and uncovered when it is present.
func (c *compiledStatementRule) schemaMatches(o effects.ObjectRef) bool {
	if len(c.schemas) == 0 {
		return true
	}
	if o.Schema == "" {
		return false
	}
	for _, g := range c.schemas {
		if g.Match(o.Schema) {
			return true
		}
	}
	return false
}

// renderMessage applies the rule's message template, or returns the raw
// Message string if no template was set.
func (c *compiledStatementRule) renderMessage(ctx messageContext) string {
	if c.msgTemplate == nil {
		return c.src.Message
	}
	var sb strings.Builder
	if err := c.msgTemplate.Execute(&sb, ctx); err != nil {
		// Templates were validated at compile time; runtime failure here means
		// a bug. Surface it visibly rather than silently swallowing.
		return fmt.Sprintf("<message render error: %v>", err)
	}
	return sb.String()
}

// objectMatchField returns the canonical glob target for an ObjectRef per the
// File Structure table in this plan.
func objectMatchField(o effects.ObjectRef) string {
	switch o.Kind {
	case effects.ObjectExternalEndpoint:
		return o.Host
	case effects.ObjectFilesystemPath:
		return o.Path
	case effects.ObjectProgram:
		return o.Argv0
	default:
		return o.Name
	}
}

// compileConnectionRule transforms a validated ConnectionRule.
func compileConnectionRule(r *ConnectionRule) (*compiledConnectionRule, error) {
	c := &compiledConnectionRule{
		src:           r,
		serviceFilter: serviceFilter{service: ServiceID(r.DBService)},
	}
	switch r.Decision {
	case "allow":
		c.verb = VerbAllow
	case "deny":
		c.verb = VerbDeny
	case "approve":
		c.verb = VerbApprove
	case "audit":
		c.verb = VerbAudit
	default:
		return nil, fmt.Errorf("compile: conn rule %q has unhandled decision %q", r.Name, r.Decision)
	}
	switch r.MatchKind {
	case "", "connect":
		c.matchKind = MatchConnect
	case "cancel":
		c.matchKind = MatchCancel
	case "replication":
		c.matchKind = MatchReplication
	default:
		return nil, fmt.Errorf("compile: conn rule %q has unhandled match_kind %q", r.Name, r.MatchKind)
	}
	if len(r.DBUser) > 0 {
		c.dbUsers = make(map[string]struct{}, len(r.DBUser))
		for _, u := range r.DBUser {
			c.dbUsers[u] = struct{}{}
		}
	}
	c.database = r.Database
	if r.ApplicationName != "" {
		g, err := glob.Compile(r.ApplicationName)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: conn rule %q application_name %q: %w", r.Name, r.ApplicationName, err)
		}
		c.applicationName = g
	}
	if r.ClientIdentity != "" {
		g, err := glob.Compile(r.ClientIdentity)
		if err != nil {
			return nil, fmt.Errorf("glob_compile: conn rule %q client_identity %q: %w", r.Name, r.ClientIdentity, err)
		}
		c.clientIdentity = g
	}
	if strings.TrimSpace(r.Message) != "" {
		tmpl, err := template.New("msg").Parse(r.Message)
		if err != nil {
			return nil, fmt.Errorf("message_template_parse: conn rule %q: %w", r.Name, err)
		}
		c.msgTemplate = tmpl
	}
	c.timeout = r.Timeout
	if r.Decision == "approve" && c.timeout == 0 {
		c.timeout = defaultApproveTimeout
	}
	return c, nil
}

func (c *compiledConnectionRule) renderMessage(ctx messageContext) string {
	if c.msgTemplate == nil {
		return c.src.Message
	}
	var sb strings.Builder
	if err := c.msgTemplate.Execute(&sb, ctx); err != nil {
		return fmt.Sprintf("<message render error: %v>", err)
	}
	return sb.String()
}
```

- [ ] **Step 4: Run, expect pass**

Run: `go test ./internal/db/policy -run TestCompile -v`
Expected: PASS for all subtests.

- [ ] **Step 5: Run all policy tests for regression**

Run: `go test ./internal/db/policy/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/policy/compile.go internal/db/policy/compile_test.go
git commit -m "$(cat <<'EOF'
db/policy: compile statement+connection rules

Glob compile via gobwas/glob, alias expansion via effects.ExpandAlias,
message templates via text/template, default approve timeout 60s,
resolution matcher with any/eq kinds, object kind-aware glob target
selection (Name / Host / Path / Argv0).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: Decode — Phase A (yaml decode) + B (validate) + C (compile)

**Why:** Combines the three phases into the single public entry point `Decode(*policy.Policy) (*RuleSet, []Warning, error)`.

**Files:**
- Create: `internal/db/policy/decode.go`
- Create: `internal/db/policy/decode_test.go`

- [ ] **Step 1: Write `internal/db/policy/decode_test.go`**

```go
package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func loadDB(t *testing.T, src string) (*RuleSet, []Warning, error) {
	t.Helper()
	p, err := policy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	return Decode(p)
}

func TestDecode_Empty(t *testing.T) {
	rs, warns, err := loadDB(t, `version: 1
name: x
`)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("warns = %v", warns)
	}
	if rs == nil {
		t.Fatal("nil RuleSet")
	}
	if rs.Redaction().LogStatements != RedactParametersRedacted {
		t.Errorf("default LogStatements = %v, want parameters_redacted", rs.Redaction().LogStatements)
	}
	if rs.Redaction().ApprovalStatementChars != 200 {
		t.Errorf("default ApprovalStatementChars = %d, want 200", rs.Redaction().ApprovalStatementChars)
	}
}

func TestDecode_FullPolicy(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: r1
    db_service: appdb
    operations: [READ]
    decision: allow
database_connection_rules:
  - name: c1
    db_service: appdb
    decision: allow
`
	rs, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Errorf("warns = %v", warns)
	}
	svc, ok := rs.Service("appdb")
	if !ok || svc.TLSMode != "terminate_reissue" {
		t.Fatalf("Service appdb missing or wrong: %+v", svc)
	}
}

func TestDecode_RedactionConfig(t *testing.T) {
	src := `version: 1
name: t
policies:
  db:
    log_statements: full
    approval_statement_preview: redacted
    approval_statement_preview_chars: 50
`
	rs, _, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if rs.Redaction().LogStatements != RedactFull {
		t.Errorf("LogStatements = %v, want full", rs.Redaction().LogStatements)
	}
	// "redacted" is the YAML name for parameters_redacted in the
	// approval-preview field per §10.3.
	if rs.Redaction().ApprovalStatementPreview != RedactParametersRedacted {
		t.Errorf("ApprovalStatementPreview = %v, want parameters_redacted", rs.Redaction().ApprovalStatementPreview)
	}
	if rs.Redaction().ApprovalStatementChars != 50 {
		t.Errorf("ApprovalStatementChars = %d, want 50", rs.Redaction().ApprovalStatementChars)
	}
}

func TestDecode_PropagatesValidationError(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    # tls_mode missing
`
	_, _, err := loadDB(t, src)
	if err == nil || !strings.Contains(err.Error(), "service_tls_mode_required") {
		t.Fatalf("want service_tls_mode_required, got %v", err)
	}
}

func TestDecode_PropagatesGlobCompileError(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: r
    db_service: appdb
    objects: ["["]
    operations: [READ]
    decision: allow
`
	_, _, err := loadDB(t, src)
	if err == nil || !strings.Contains(err.Error(), "glob_compile") {
		t.Fatalf("want glob_compile error, got %v", err)
	}
}

func TestDecode_AuditOnDangerousWarning(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: aud
    db_service: appdb
    operations: [DROP]
    decision: audit
`
	_, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	found := false
	for _, w := range warns {
		if w.Code == "audit_on_dangerous" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected audit_on_dangerous warning, got %v", warns)
	}
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/db/policy -run TestDecode`
Expected: `undefined: Decode`.

- [ ] **Step 3: Implement `internal/db/policy/decode.go`**

```go
package policy

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"

	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// Decode turns a parsed *internal/policy.Policy into a fully validated and
// compiled *RuleSet. It performs three phases per the design doc §5:
//
//   A. Decode each yaml.Node (db_services, database_rules,
//      database_connection_rules) into typed shapes with KnownFields(true).
//   B. Validate the typed shapes (§9.4 errors + warnings).
//   C. Compile validated rules into the evaluator-ready *RuleSet.
//
// Decode returns (rs, warnings, nil) on success. On error, warnings collected
// up to the point of failure are returned alongside the error.
func Decode(p *rootpolicy.Policy) (*RuleSet, []Warning, error) {
	if p == nil {
		return nil, nil, fmt.Errorf("policy is nil")
	}

	// Phase A.
	svcs, err := decodeServices(p.DBServices)
	if err != nil {
		return nil, nil, err
	}
	stmtRules, err := decodeStatementRules(p.DatabaseRules)
	if err != nil {
		return nil, nil, err
	}
	connRules, err := decodeConnectionRules(p.DatabaseConnectionRules)
	if err != nil {
		return nil, nil, err
	}
	red, err := decodeRedaction(p)
	if err != nil {
		return nil, nil, err
	}

	// Phase B.
	warns, err := validate(svcs, stmtRules, connRules)
	if err != nil {
		return nil, warns, err
	}

	// Phase C.
	rs := &RuleSet{services: svcs, redaction: red}
	for _, r := range stmtRules {
		c, err := compileStatementRule(r)
		if err != nil {
			return nil, warns, err
		}
		rs.statement = append(rs.statement, c)
	}
	for _, r := range connRules {
		c, err := compileConnectionRule(r)
		if err != nil {
			return nil, warns, err
		}
		rs.connection = append(rs.connection, c)
	}
	return rs, warns, nil
}

func decodeServices(n yaml.Node) (map[ServiceID]*DBService, error) {
	if n.IsZero() {
		return map[ServiceID]*DBService{}, nil
	}
	raw := map[string]*DBService{}
	if err := strictDecode(n, &raw); err != nil {
		return nil, fmt.Errorf("decode db_services: %w", err)
	}
	out := make(map[ServiceID]*DBService, len(raw))
	for name, svc := range raw {
		svc.Name = name
		out[ServiceID(name)] = svc
	}
	return out, nil
}

func decodeStatementRules(n yaml.Node) ([]*StatementRule, error) {
	if n.IsZero() {
		return nil, nil
	}
	var rules []*StatementRule
	if err := strictDecode(n, &rules); err != nil {
		return nil, fmt.Errorf("decode database_rules: %w", err)
	}
	return rules, nil
}

func decodeConnectionRules(n yaml.Node) ([]*ConnectionRule, error) {
	if n.IsZero() {
		return nil, nil
	}
	var rules []*ConnectionRule
	if err := strictDecode(n, &rules); err != nil {
		return nil, fmt.Errorf("decode database_connection_rules: %w", err)
	}
	return rules, nil
}

// redactionYAML is the on-disk shape of the policies.db block. Only the
// statement-redaction-related fields are decoded here; the rest of the
// policies block is owned by other packages.
type redactionYAML struct {
	LogStatements                 string `yaml:"log_statements,omitempty"`
	ApprovalStatementPreview      string `yaml:"approval_statement_preview,omitempty"`
	ApprovalStatementPreviewChars int    `yaml:"approval_statement_preview_chars,omitempty"`
}

// policiesPeek peeks at the policies.db sub-block. We do *not* add a typed
// Policies field to internal/policy.Policy here — too much surface for a
// single sub-block — and instead re-decode the full bytes into a transient
// shape. Plan 02 owns only the db sub-block.
type policiesPeek struct {
	Policies struct {
		DB redactionYAML `yaml:"db,omitempty"`
	} `yaml:"policies,omitempty"`
}

// decodeRedaction reads the policies.db sub-block from the source policy.
// Defaults: LogStatements=parameters_redacted, ApprovalStatementPreview=
// parameters_redacted (YAML alias "redacted"), ApprovalStatementChars=200.
func decodeRedaction(p *rootpolicy.Policy) (RedactionConfig, error) {
	out := RedactionConfig{
		LogStatements:            RedactParametersRedacted,
		ApprovalStatementPreview: RedactParametersRedacted,
		ApprovalStatementChars:   200,
	}
	// The redaction config lives under policies.db, which internal/policy does
	// not currently own. Decode by re-marshalling and re-decoding the
	// policy.Policy via yaml.Marshal/Unmarshal — slow, but Decode runs once at
	// load time and avoids a second mutable field on internal/policy.Policy.
	bs, err := yaml.Marshal(p)
	if err != nil {
		return out, fmt.Errorf("decode redaction (marshal): %w", err)
	}
	var peek policiesPeek
	if err := yaml.Unmarshal(bs, &peek); err != nil {
		return out, fmt.Errorf("decode redaction (unmarshal): %w", err)
	}
	rb := peek.Policies.DB
	if rb.LogStatements != "" {
		t, ok := ParseRedactionTier(rb.LogStatements)
		if !ok {
			return out, fmt.Errorf("redaction_unknown_log_statements: %q", rb.LogStatements)
		}
		out.LogStatements = t
	}
	if rb.ApprovalStatementPreview != "" {
		t, ok := parseApprovalPreviewTier(rb.ApprovalStatementPreview)
		if !ok {
			return out, fmt.Errorf("redaction_unknown_approval_preview: %q", rb.ApprovalStatementPreview)
		}
		out.ApprovalStatementPreview = t
	}
	if rb.ApprovalStatementPreviewChars > 0 {
		out.ApprovalStatementChars = rb.ApprovalStatementPreviewChars
	}
	return out, nil
}

// parseApprovalPreviewTier handles the §10.3 alias: in approval_statement_preview,
// the value "redacted" maps to RedactParametersRedacted. (LogStatements uses
// the canonical "parameters_redacted" name only.)
func parseApprovalPreviewTier(s string) (RedactionTier, bool) {
	if s == "redacted" {
		return RedactParametersRedacted, true
	}
	return ParseRedactionTier(s)
}

// strictDecode round-trips a yaml.Node through a strict decoder so unknown
// fields fail to load. yaml.Node.Decode does not respect KnownFields by
// default; this re-emits the node and decodes the bytes with the strict flag.
func strictDecode(n yaml.Node, out any) error {
	bs, err := yaml.Marshal(&n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(bs))
	dec.KnownFields(true)
	return dec.Decode(out)
}
```

- [ ] **Step 4: Run, expect pass**

Run: `go test ./internal/db/policy -run TestDecode -v`
Expected: PASS for all subtests.

- [ ] **Step 5: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add internal/db/policy/decode.go internal/db/policy/decode_test.go
git commit -m "$(cat <<'EOF'
db/policy: Decode (yaml.Node -> validated, compiled RuleSet)

Three-phase pipeline: yaml.Node decode (strict KnownFields) -> validate
(§9.4) -> compile. Reads policies.db sub-block for redaction defaults.
Returns warnings alongside the RuleSet so audit_on_dangerous and
approve_on_replication don't break load.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `Evaluate` — deny pass + coverage pass + fold

**Why:** This is the §10.2 algorithm. Tests cover the §23.3 categories incrementally; the table-driven §10.2 worked-examples test in Task 11 is the integration check.

**Files:**
- Create: `internal/db/policy/evaluate.go`
- Create: `internal/db/policy/evaluate_coverage_test.go`
- Create: `internal/db/policy/evaluate_implicit_deny_test.go`
- Create: `internal/db/policy/evaluate_audit_coverage_test.go`
- Create: `internal/db/policy/evaluate_approve_scope_test.go`
- Create: `internal/db/policy/evaluate_deny_precedence_test.go`
- Create: `internal/db/policy/evaluate_resolution_test.go`
- Create: `internal/db/policy/evaluate_multi_effect_test.go`
- Create: `internal/db/policy/evaluate_primary_ordering_test.go`

- [ ] **Step 1: Write the foundational coverage test**

Create `internal/db/policy/evaluate_coverage_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

// loadRules is a tiny helper used across evaluator tests.
func loadRules(t *testing.T, src string) *RuleSet {
	t.Helper()
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}

// table builds a ClassifiedStatement of one read effect with the given object
// names; convenience for repetitive single-effect tests.
func tableRead(names ...string) effects.ClassifiedStatement {
	objs := make([]effects.ObjectRef, len(names))
	for i, n := range names {
		objs[i] = effects.ObjectRef{Kind: effects.ObjectTable, Name: n}
	}
	return effects.ClassifiedStatement{
		Effects: []effects.Effect{{Group: effects.GroupRead, Objects: objs, Resolution: effects.ResolutionQualified}},
	}
}

func TestEvaluate_AllowCoversAllObjectsByDefault(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-all, db_service: appdb, operations: [READ], decision: allow}
`)
	d := Evaluate(tableRead("users", "orders"), rs, "appdb")
	if d.Verb != VerbAllow {
		t.Fatalf("verb = %v, want allow", d.Verb)
	}
	if d.RuleName != "read-all" {
		t.Errorf("RuleName = %q", d.RuleName)
	}
}

func TestEvaluate_AllowSpecificObjectsCovers(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-pii, db_service: appdb, operations: [READ], objects: [pii.*, "users"], decision: allow}
`)
	d := Evaluate(tableRead("pii.ssns", "users"), rs, "appdb")
	if d.Verb != VerbAllow {
		t.Fatalf("verb = %v, want allow (both objects covered)", d.Verb)
	}
}

func TestEvaluate_AuditCoversObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: aud, db_service: appdb, operations: [READ], objects: [customers], decision: audit, acknowledge_audit_on_dangerous: true}
`)
	d := Evaluate(tableRead("customers"), rs, "appdb")
	if d.Verb != VerbAudit {
		t.Fatalf("verb = %v, want audit", d.Verb)
	}
}

func TestEvaluate_ApproveCoversObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: app, db_service: appdb, operations: [READ], objects: [needs_approval], decision: approve}
`)
	d := Evaluate(tableRead("needs_approval"), rs, "appdb")
	if d.Verb != VerbApprove {
		t.Fatalf("verb = %v, want approve", d.Verb)
	}
	if d.Approval == nil {
		t.Fatal("Approval nil")
	}
	if d.Approval.Timeout == 0 {
		t.Errorf("Timeout zero (default 60s expected)")
	}
}
```

- [ ] **Step 2: Write the implicit-deny test**

Create `internal/db/policy/evaluate_implicit_deny_test.go`:

```go
package policy

import "testing"

func TestEvaluate_ImplicitDenyOnUncoveredObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-users, db_service: appdb, operations: [READ], objects: [users], decision: allow}
`)
	d := Evaluate(tableRead("users", "uncovered_table"), rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny", d.Verb)
	}
	if d.RuleName != "" {
		t.Errorf("RuleName = %q, want \"\" for implicit deny", d.RuleName)
	}
}

func TestEvaluate_ImplicitDenyWhenNoRules(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
`)
	d := Evaluate(tableRead("users"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb = %v, RuleName = %q; want implicit deny", d.Verb, d.RuleName)
	}
}
```

- [ ] **Step 3: Write the audit-coverage test**

Create `internal/db/policy/evaluate_audit_coverage_test.go`:

```go
package policy

import "testing"

func TestEvaluate_AuditDoesNotCoverUnrelatedObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: aud, db_service: appdb, operations: [READ], objects: [customers], decision: audit, acknowledge_audit_on_dangerous: true}
`)
	d := Evaluate(tableRead("customers", "orders"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb = %v, RuleName = %q; want implicit deny (orders uncovered)", d.Verb, d.RuleName)
	}
}
```

- [ ] **Step 4: Write the approve-scope test**

Create `internal/db/policy/evaluate_approve_scope_test.go`:

```go
package policy

import "testing"

func TestEvaluate_ApproveDoesNotExtendCoverage(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: app, db_service: appdb, operations: [READ], objects: [needs_approval], decision: approve}
`)
	d := Evaluate(tableRead("uncovered", "needs_approval"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb = %v, RuleName = %q; want implicit deny (uncovered uncovered)", d.Verb, d.RuleName)
	}
}

func TestEvaluate_ApproveAndAllowCombineToApprove(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: allow-x, db_service: appdb, operations: [READ], objects: [allowed], decision: allow}
  - {name: appr-y, db_service: appdb, operations: [READ], objects: [needs_approval], decision: approve}
`)
	d := Evaluate(tableRead("allowed", "needs_approval"), rs, "appdb")
	if d.Verb != VerbApprove {
		t.Fatalf("verb = %v, want approve (most-restrictive of allow+approve)", d.Verb)
	}
	if d.Approval == nil || len(d.Approval.ContributingApproveRules) != 1 || d.Approval.ContributingApproveRules[0] != "appr-y" {
		t.Errorf("ContributingApproveRules = %v, want [appr-y]", d.Approval)
	}
}
```

- [ ] **Step 5: Write the deny-precedence test**

Create `internal/db/policy/evaluate_deny_precedence_test.go`:

```go
package policy

import "testing"

func TestEvaluate_DenyBeatsAllow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: r-allow, db_service: appdb, operations: [READ], decision: allow}
  - {name: r-deny,  db_service: appdb, operations: [READ], objects: [pii.*], decision: deny}
`)
	d := Evaluate(tableRead("users", "pii.ssns"), rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny", d.Verb)
	}
	if d.RuleName != "r-deny" {
		t.Errorf("RuleName = %q, want r-deny", d.RuleName)
	}
}

func TestEvaluate_DenyBeatsApprove(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: appr,  db_service: appdb, operations: [READ], decision: approve}
  - {name: deny,  db_service: appdb, operations: [READ], objects: [pii.*], decision: deny}
`)
	d := Evaluate(tableRead("pii.ssns"), rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny", d.Verb)
	}
}
```

- [ ] **Step 6: Write the resolution-matcher test**

Create `internal/db/policy/evaluate_resolution_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_MatchObjectResolution(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: r, db_service: appdb, operations: [READ], match_object_resolution: qualified_syntactic, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Resolution: effects.ResolutionQualified, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}}},
	}}
	if d := Evaluate(stmt, rs, "appdb"); d.Verb != VerbAllow {
		t.Errorf("qualified should match: verb=%v", d.Verb)
	}

	stmt.Effects[0].Resolution = effects.ResolutionUnqualified
	if d := Evaluate(stmt, rs, "appdb"); d.Verb != VerbDeny || d.RuleName != "" {
		t.Errorf("unqualified should NOT match qualified rule: verb=%v rule=%q", d.Verb, d.RuleName)
	}
}
```

- [ ] **Step 7: Write the multi-effect test**

Create `internal/db/policy/evaluate_multi_effect_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_MultiEffect_DenyFromAnyEffect(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-allow, db_service: appdb, operations: [READ], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupWrite, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "log"}}},
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "x"}}},
	}}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v, want deny (write effect implicitly denied)", d.Verb)
	}
	// MatchingEffectIndex should point at the denying (write) effect.
	if d.MatchingEffectIndex != 0 {
		t.Errorf("MatchingEffectIndex = %d, want 0", d.MatchingEffectIndex)
	}
}
```

- [ ] **Step 8: Write the primary-ordering test**

Create `internal/db/policy/evaluate_primary_ordering_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// The fold step picks the most-restrictive verb across effects. When two
// effects tie at the same verb (e.g., both deny), the lowest index wins.
// Independently of the fold tiebreak, the input statement may have effects
// in arbitrary order — Evaluate must honor MatchingEffectIndex per the input,
// not re-sort.
func TestEvaluate_FoldTieBreaksOnLowestIndex(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: deny-pii, db_service: appdb, operations: [READ], objects: [pii.*], decision: deny}
  - {name: deny-x,   db_service: appdb, operations: [READ], objects: [x],      decision: deny}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "pii.ssns"}}},
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "x"}}},
	}}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny {
		t.Fatalf("verb = %v", d.Verb)
	}
	if d.MatchingEffectIndex != 0 {
		t.Errorf("MatchingEffectIndex = %d, want 0 (lowest index)", d.MatchingEffectIndex)
	}
	if d.RuleName != "deny-pii" {
		t.Errorf("RuleName = %q, want deny-pii", d.RuleName)
	}
}
```

- [ ] **Step 9: Run all eight tests, expect failure**

Run: `go test ./internal/db/policy -run TestEvaluate_`
Expected: `undefined: Evaluate`.

- [ ] **Step 10: Implement `internal/db/policy/evaluate.go`**

```go
package policy

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Evaluate applies the statement-rule policy to a classified statement per
// spec §10.2. Pure function; safe to call concurrently against the same
// *RuleSet (RuleSet is immutable after Decode).
func Evaluate(stmt effects.ClassifiedStatement, rs *RuleSet, svc ServiceID) Decision {
	if rs == nil {
		return implicitDeny(stmt, 0, "policy not loaded")
	}
	applicable := rs.statementRulesFor(svc)
	if len(stmt.Effects) == 0 {
		return implicitDeny(stmt, 0, "no effects on statement")
	}

	perEffect := make([]effectDecision, len(stmt.Effects))
	for i, e := range stmt.Effects {
		perEffect[i] = evaluateEffect(e, applicable)
	}
	return foldEffects(stmt, perEffect)
}

// statementRulesFor returns rules whose service filter matches svc.
func (rs *RuleSet) statementRulesFor(svc ServiceID) []*compiledStatementRule {
	out := make([]*compiledStatementRule, 0, len(rs.statement))
	s := rs.services[svc]
	for _, r := range rs.statement {
		if r.serviceFilter.matches(svc, s) {
			out = append(out, r)
		}
	}
	return out
}

// effectDecision is the per-effect verdict. internalVerb includes
// implicitDeny as a distinct value; foldEffects normalizes to DecisionVerb.
type effectDecision struct {
	verb                 internalVerb
	rule                 *compiledStatementRule // primary contributing rule (nil for implicit deny)
	contributingApprove  []*compiledStatementRule
	contributingAudit    []*compiledStatementRule
	uncoveredObject      effects.ObjectRef // populated when verb == implicitDeny
	denyMatchingObject   effects.ObjectRef // populated when verb == verbDeny
}

type internalVerb uint8

const (
	verbAllow internalVerb = iota
	verbAudit
	verbApprove
	verbImplicitDeny
	verbDeny
)

func evaluateEffect(e effects.Effect, applicable []*compiledStatementRule) effectDecision {
	// Pass 1 — deny.
	for _, r := range applicable {
		if r.verb != VerbDeny {
			continue
		}
		if !ruleMatchesEffectMeta(r, e) {
			continue
		}
		// Find the first matching object (deterministic).
		for _, o := range e.Objects {
			if !r.schemaMatches(o) {
				continue
			}
			if r.objectMatches(o) {
				return effectDecision{verb: verbDeny, rule: r, denyMatchingObject: o}
			}
		}
	}

	// Pass 2 — coverage. For each object, collect rules that cover it.
	type cover struct {
		rule *compiledStatementRule
	}
	coverage := make(map[int][]cover, len(e.Objects)) // keyed by object index
	for i, o := range e.Objects {
		for _, r := range applicable {
			if r.verb == VerbDeny {
				continue
			}
			if !ruleMatchesEffectMeta(r, e) {
				continue
			}
			if !r.schemaMatches(o) {
				continue
			}
			if !r.objectMatches(o) {
				continue
			}
			coverage[i] = append(coverage[i], cover{rule: r})
		}
	}

	// Implicit deny if any object has empty coverage.
	for i, o := range e.Objects {
		if len(coverage[i]) == 0 {
			return effectDecision{verb: verbImplicitDeny, uncoveredObject: o}
		}
	}

	// Pass 3 — most-restrictive among covering rules.
	var (
		best          internalVerb = verbAllow
		primary       *compiledStatementRule
		approveRules  []*compiledStatementRule
		auditRules    []*compiledStatementRule
		approveSeen   = map[string]bool{}
		auditSeen     = map[string]bool{}
	)
	// Walk coverage in object order, preserving rule order (rules remain in
	// policy file order in `applicable`). This guarantees R14
	// order-independence: result depends on the rule set, not on iteration
	// path beyond ties broken by file order.
	for i := range e.Objects {
		for _, cv := range coverage[i] {
			r := cv.rule
			switch r.verb {
			case VerbApprove:
				if best < verbApprove {
					best = verbApprove
				}
				if !approveSeen[r.src.Name] {
					approveSeen[r.src.Name] = true
					approveRules = append(approveRules, r)
				}
			case VerbAudit:
				if best < verbAudit {
					best = verbAudit
				}
				if !auditSeen[r.src.Name] {
					auditSeen[r.src.Name] = true
					auditRules = append(auditRules, r)
				}
			}
		}
	}
	switch best {
	case verbApprove:
		primary = approveRules[0] // first by policy file order (D-OQ3)
	case verbAudit:
		primary = auditRules[0]
	default:
		// Pick the first allow rule from coverage[0].
		primary = coverage[0][0].rule
	}
	return effectDecision{
		verb:                best,
		rule:                primary,
		contributingApprove: approveRules,
		contributingAudit:   auditRules,
	}
}

// ruleMatchesEffectMeta checks group/subtype/resolution. Object matching is
// done per-object by the caller.
func ruleMatchesEffectMeta(r *compiledStatementRule, e effects.Effect) bool {
	if _, ok := r.groups[e.Group]; !ok {
		return false
	}
	if len(r.subtypes) > 0 {
		if _, ok := r.subtypes[e.Subtype]; !ok {
			return false
		}
	}
	if !r.matchesResolution(e.Resolution) {
		return false
	}
	return true
}

// foldEffects picks the most-restrictive per-effect verdict and turns it into
// a public Decision. Tie-break on lowest index. Explicit deny beats implicit
// deny so RuleName is non-empty whenever possible.
func foldEffects(stmt effects.ClassifiedStatement, perEffect []effectDecision) Decision {
	bestIdx := 0
	for i := 1; i < len(perEffect); i++ {
		if compareInternalVerb(perEffect[i].verb, perEffect[bestIdx].verb) > 0 {
			bestIdx = i
		}
	}
	d := perEffect[bestIdx]
	e := stmt.Effects[bestIdx]

	switch d.verb {
	case verbAllow:
		return Decision{
			Verb:                VerbAllow,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt, d.rule.src.Name)),
		}
	case verbAudit:
		return Decision{
			Verb:                VerbAudit,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt, d.rule.src.Name)),
		}
	case verbApprove:
		// Shortest timeout wins (D-OQ2).
		timeout := d.contributingApprove[0].timeout
		approveNames := make([]string, len(d.contributingApprove))
		for i, r := range d.contributingApprove {
			approveNames[i] = r.src.Name
			if r.timeout < timeout {
				timeout = r.timeout
			}
		}
		auditNames := make([]string, len(d.contributingAudit))
		for i, r := range d.contributingAudit {
			auditNames[i] = r.src.Name
		}
		return Decision{
			Verb:                   VerbApprove,
			RuleKind:               RuleKindStatement,
			RuleName:               d.rule.src.Name,
			MatchingEffectIndex:    bestIdx,
			MatchingEffectGroup:    e.Group,
			Reason:                 d.rule.renderMessage(messageContextFor(e, stmt, d.rule.src.Name)),
			ContributingAuditRules: auditNames,
			Approval: &ApprovalRequest{
				Timeout:                  timeout,
				ContributingApproveRules: approveNames,
			},
		}
	case verbImplicitDeny:
		return implicitDeny(stmt, bestIdx, fmt.Sprintf("no rule covers %q in %q effect", objectMatchField(d.uncoveredObject), e.Group))
	case verbDeny:
		return Decision{
			Verb:                VerbDeny,
			RuleKind:            RuleKindStatement,
			RuleName:            d.rule.src.Name,
			MatchingEffectIndex: bestIdx,
			MatchingEffectGroup: e.Group,
			Reason:              d.rule.renderMessage(messageContextFor(e, stmt, d.rule.src.Name)),
		}
	default:
		return implicitDeny(stmt, bestIdx, "unknown effect verdict")
	}
}

// compareInternalVerb returns +1 if a more restrictive than b, -1 if less,
// 0 if equal. Order: allow < audit < approve < implicit_deny < deny.
// implicit_deny ranks just below explicit deny so the explicit deny path
// wins ties (preserving RuleName per the design doc).
func compareInternalVerb(a, b internalVerb) int {
	if a > b {
		return 1
	}
	if a < b {
		return -1
	}
	return 0
}

func messageContextFor(e effects.Effect, stmt effects.ClassifiedStatement, _ string) messageContext {
	var schema, object string
	if len(e.Objects) > 0 {
		schema = e.Objects[0].Schema
		object = objectMatchField(e.Objects[0])
	}
	subtype := ""
	if e.Subtype != effects.SubtypeNone {
		subtype = e.Subtype.String()
	}
	return messageContext{
		Operation: e.Group.String(),
		Subtype:   subtype,
		Schema:    schema,
		Object:    object,
		Verb:      stmt.RawVerb,
	}
}

func implicitDeny(stmt effects.ClassifiedStatement, idx int, reason string) Decision {
	d := Decision{
		Verb:                VerbDeny,
		RuleKind:            RuleKindStatement,
		MatchingEffectIndex: idx,
		Reason:              reason,
	}
	if idx >= 0 && idx < len(stmt.Effects) {
		d.MatchingEffectGroup = stmt.Effects[idx].Group
	}
	return d
}
```

- [ ] **Step 11: Run tests, expect pass**

Run: `go test ./internal/db/policy -run TestEvaluate_ -v`
Expected: PASS for all eight test files.

- [ ] **Step 12: Commit**

```bash
git add internal/db/policy/evaluate.go internal/db/policy/evaluate_*_test.go
git commit -m "$(cat <<'EOF'
db/policy: Evaluate (statement) per spec §10.2

Two passes per effect: deny pass, then coverage pass; fold across effects
picks most-restrictive (lowest index breaks ties; explicit deny preferred
over implicit deny so RuleName is non-empty whenever possible).

Approve fold honors D-OQ2 (shortest timeout wins) and D-OQ3 (first by
policy file order for RuleName tiebreak).

Tests cover §23.3 categories: strict coverage, implicit deny, audit
coverage, approve scope, deny precedence, match_object_resolution,
multi-effect, primary ordering.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: `EvaluateConnection`

**Why:** Connection rules are simpler than statement rules — no object coverage, just field-by-field matching followed by a most-restrictive fold.

**Files:**
- Create: `internal/db/policy/evaluate_conn.go`
- Create: `internal/db/policy/evaluate_conn_test.go`

- [ ] **Step 1: Write `internal/db/policy/evaluate_conn_test.go`**

```go
package policy

import "testing"

func TestEvaluateConnection_Allow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: c1, db_service: appdb, decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb"}, rs)
	if d.Verb != VerbAllow || d.RuleName != "c1" {
		t.Fatalf("verb=%v rule=%q, want allow/c1", d.Verb, d.RuleName)
	}
	if d.MatchingEffectIndex != -1 {
		t.Errorf("MatchingEffectIndex = %d, want -1", d.MatchingEffectIndex)
	}
}

func TestEvaluateConnection_DenyByUser(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: only-readonly, db_service: appdb, db_user: [readonly], decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", DBUser: "writer"}, rs)
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("verb=%v rule=%q, want implicit deny", d.Verb, d.RuleName)
	}
}

func TestEvaluateConnection_DenyBeatsAllow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: a, db_service: appdb, decision: allow}
  - {name: d, db_service: appdb, db_user: [evil], decision: deny}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", DBUser: "evil"}, rs)
	if d.Verb != VerbDeny || d.RuleName != "d" {
		t.Fatalf("verb=%v rule=%q, want deny/d", d.Verb, d.RuleName)
	}
}

func TestEvaluateConnection_CancelKindFiltersByMatchKind(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: connect-allow, db_service: appdb, decision: allow}
  - {name: cancel-allow,  db_service: appdb, match_kind: cancel, decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", MatchKind: MatchCancel}, rs)
	if d.RuleName != "cancel-allow" {
		t.Fatalf("RuleName = %q, want cancel-allow", d.RuleName)
	}
	if d.RuleKind != RuleKindCancel {
		t.Errorf("RuleKind = %v, want cancel", d.RuleKind)
	}
}

func TestEvaluateConnection_ApplicationNameGlob(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_connection_rules:
  - {name: psql-only, db_service: appdb, application_name: "psql*", decision: allow}
`)
	d := EvaluateConnection(ConnectionInfo{Service: "appdb", ApplicationName: "psql 16"}, rs)
	if d.Verb != VerbAllow {
		t.Errorf("psql 16 should match psql*: verb=%v", d.Verb)
	}
	d = EvaluateConnection(ConnectionInfo{Service: "appdb", ApplicationName: "myapp"}, rs)
	if d.Verb != VerbDeny {
		t.Errorf("myapp should NOT match: verb=%v", d.Verb)
	}
}
```

- [ ] **Step 2: Run, expect failure**

Run: `go test ./internal/db/policy -run TestEvaluateConnection`
Expected: `undefined: EvaluateConnection`.

- [ ] **Step 3: Implement `internal/db/policy/evaluate_conn.go`**

```go
package policy

import "github.com/agentsh/agentsh/internal/db/effects"

// EvaluateConnection applies connection-rule policy to a candidate connection.
// Returns implicit deny if no rule matches.
func EvaluateConnection(info ConnectionInfo, rs *RuleSet) Decision {
	if rs == nil {
		return Decision{
			Verb:                VerbDeny,
			RuleKind:            connectionRuleKindFor(info.MatchKind),
			MatchingEffectIndex: -1,
			MatchingEffectGroup: effects.GroupUnknown,
			Reason:              "policy not loaded",
		}
	}
	var matched []*compiledConnectionRule
	for _, r := range rs.connection {
		if r.matchKind != info.MatchKind {
			continue
		}
		if r.serviceFilter.service != "" && r.serviceFilter.service != info.Service {
			continue
		}
		if !connRuleMatchesInfo(r, info) {
			continue
		}
		matched = append(matched, r)
	}

	if len(matched) == 0 {
		return Decision{
			Verb:                VerbDeny,
			RuleKind:            connectionRuleKindFor(info.MatchKind),
			MatchingEffectIndex: -1,
			MatchingEffectGroup: effects.GroupUnknown,
			Reason:              "no connection rule matched",
		}
	}

	best := matched[0]
	for _, r := range matched[1:] {
		if compareConnVerb(r.verb, best.verb) > 0 {
			best = r
		}
	}
	d := Decision{
		Verb:                best.verb,
		RuleKind:            connectionRuleKindFor(info.MatchKind),
		RuleName:            best.src.Name,
		MatchingEffectIndex: -1,
		MatchingEffectGroup: effects.GroupUnknown,
		Reason: best.renderMessage(messageContext{
			Operation: connKindString(info.MatchKind),
		}),
	}
	if best.verb == VerbApprove {
		d.Approval = &ApprovalRequest{
			Timeout:                  best.timeout,
			ContributingApproveRules: []string{best.src.Name},
		}
	}
	return d
}

func connRuleMatchesInfo(r *compiledConnectionRule, info ConnectionInfo) bool {
	if len(r.dbUsers) > 0 {
		if _, ok := r.dbUsers[info.DBUser]; !ok {
			return false
		}
	}
	if r.database != "" && r.database != info.Database {
		return false
	}
	if r.applicationName != nil && !r.applicationName.Match(info.ApplicationName) {
		return false
	}
	if r.clientIdentity != nil && !r.clientIdentity.Match(info.ClientIdentity) {
		return false
	}
	return true
}

func connectionRuleKindFor(mk ConnectionMatchKind) RuleKind {
	switch mk {
	case MatchCancel:
		return RuleKindCancel
	default:
		return RuleKindConnection
	}
}

func connKindString(mk ConnectionMatchKind) string {
	switch mk {
	case MatchConnect:
		return "connect"
	case MatchCancel:
		return "cancel"
	case MatchReplication:
		return "replication"
	default:
		return ""
	}
}

// compareConnVerb: most-restrictive ordering for connection-level verbs.
// allow < audit < approve < deny
func compareConnVerb(a, b DecisionVerb) int {
	rank := func(v DecisionVerb) int {
		switch v {
		case VerbAllow:
			return 0
		case VerbAudit:
			return 1
		case VerbApprove:
			return 2
		case VerbDeny:
			return 3
		}
		return -1
	}
	return rank(a) - rank(b)
}
```

- [ ] **Step 4: Run, expect pass**

Run: `go test ./internal/db/policy -run TestEvaluateConnection -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/policy/evaluate_conn.go internal/db/policy/evaluate_conn_test.go
git commit -m "$(cat <<'EOF'
db/policy: EvaluateConnection per spec §9.3 / §13.3

Filter by match_kind + service, evaluate field constraints (db_user,
database, application_name glob, client_identity glob), pick
most-restrictive verb among matches. Implicit deny when no rule matches.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 9: §10.2 worked-examples table + R14 order-independence

**Why:** Single integration table covering every §10.2 row, plus a property test that randomly permutes rule order to catch accidental order-dependence.

**Files:**
- Create: `internal/db/policy/sample_test.go`
- Create: `internal/db/policy/evaluate_order_independence_test.go`
- Create: `internal/db/policy/testdata/sample-policy.yaml`
- Create: `internal/db/policy/sample.go`

- [ ] **Step 1: Create the sample policy file**

Write `internal/db/policy/testdata/sample-policy.yaml` — exact contents of spec §9.2:

```yaml
version: 1
name: db-access-sample
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
    deny_mode_in_tx: terminate
    allow_function_call_protocol: false
  warehouse:
    family: postgres
    dialect: redshift
    upstream: warehouse.cluster.region.redshift.amazonaws.com:5439
    tls_mode: terminate_reissue
  legacy_pg:
    family: postgres
    dialect: postgres
    upstream: legacy.internal:5432
    tls_mode: passthrough

database_rules:
  - name: app-read-and-update
    db_service: appdb
    operations: [READ, UPDATE]
    decision: allow

  - name: app-allow-tx-control
    db_service: appdb
    operations: [transaction]
    decision: allow

  - name: app-allow-safe-session-settings
    db_service: appdb
    operations: [session]
    subtypes: [set, reset, set_local,
               discard_plans, discard_all, discard_temp, discard_sequences]
    objects: ["application_name", "timezone", "datestyle", "client_encoding",
              "statement_timeout", "lock_timeout",
              "idle_in_transaction_session_timeout",
              "default_transaction_isolation"]
    decision: allow

  - name: app-deny-search-path-and-role-changes
    db_service: appdb
    operations: [session]
    subtypes: [set_search_path, set_role, set_session_authorization]
    decision: deny
    message: "search_path / role manipulation not allowed"

  - name: app-deny-mutations
    db_service: appdb
    operations: [DELETE, CREATE, DROP, ALTER, EXPORT]
    decision: deny
    message: "Agent is read+update only on appdb. Requested: {{.Operation}}"

  - name: app-deny-dangerous
    db_service: appdb
    operations: [DANGEROUS]
    decision: deny

  - name: warehouse-read-only
    db_service: warehouse
    operations: [READ]
    decision: allow

  - name: warehouse-deny-everything-else
    db_service: warehouse
    operations: ["*"]
    decision: deny

  - name: catch-all-unknown
    operations: [unknown]
    decision: deny
    message: "Statement could not be classified. Failing closed."

database_connection_rules:
  - name: legacy-connect-readonly-agent-only
    db_service: legacy_pg
    client_identity: "readonly-agent"
    decision: allow

  - name: legacy-deny-other
    db_service: legacy_pg
    decision: deny
    message: "legacy_pg is restricted to the readonly-agent identity"

  - name: warehouse-connect-allow
    db_service: warehouse
    decision: allow

  - name: appdb-allow-self-cancels
    db_service: appdb
    match_kind: cancel
    decision: allow
```

- [ ] **Step 2: Implement `internal/db/policy/sample.go`**

```go
package policy

import (
	"bytes"
	_ "embed"
	"fmt"

	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

//go:embed testdata/sample-policy.yaml
var sampleYAML []byte

// MustLoadSample returns a *RuleSet built from the embedded sample policy
// (testdata/sample-policy.yaml). Panics on any error — the file is part of
// the package and a parse failure indicates a development-time bug, not a
// runtime condition. Plan 03's golden corpus also calls this.
func MustLoadSample() *RuleSet {
	rs, _, err := loadSample()
	if err != nil {
		panic(fmt.Sprintf("MustLoadSample: %v", err))
	}
	return rs
}

func loadSample() (*RuleSet, []Warning, error) {
	p, err := rootpolicy.LoadFromBytes(bytes.Clone(sampleYAML))
	if err != nil {
		return nil, nil, fmt.Errorf("LoadFromBytes: %w", err)
	}
	return Decode(p)
}
```

- [ ] **Step 3: Implement the §10.2 worked-examples table test**

Create `internal/db/policy/sample_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// Each row mirrors one example from spec §10.2. Effects are constructed
// directly; the proxy (Plan 04+) and classifier (Plan 03) will produce
// equivalent ClassifiedStatement values from real SQL.

type sampleCase struct {
	name    string
	stmt    effects.ClassifiedStatement
	service ServiceID
	want    DecisionVerb
}

func tbl(group effects.Group, sub effects.Subtype, names ...string) effects.Effect {
	objs := make([]effects.ObjectRef, len(names))
	for i, n := range names {
		objs[i] = effects.ObjectRef{Kind: effects.ObjectTable, Name: n}
	}
	return effects.Effect{Group: group, Subtype: sub, Objects: objs, Resolution: effects.ResolutionQualified}
}
func guc(sub effects.Subtype, name string) effects.Effect {
	return effects.Effect{
		Group:      effects.GroupSession,
		Subtype:    sub,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectGUC, Name: name}},
		Resolution: effects.ResolutionQualified,
	}
}

func cases() []sampleCase {
	return []sampleCase{
		{
			name:    "SELECT * FROM users",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupRead, effects.SubtypeNone, "users")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "SELECT * FROM users JOIN orders",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupRead, effects.SubtypeNone, "users", "orders")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "INSERT INTO log SELECT * FROM x — write effect implicitly denied",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupWrite, effects.SubtypeNone, "log"), tbl(effects.GroupRead, effects.SubtypeNone, "x")}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "DELETE FROM u — deny rule fires",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupDelete, effects.SubtypeNone, "u")}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "CREATE SUBSCRIPTION — DANGEROUS rule fires",
			stmt: effects.ClassifiedStatement{Effects: []effects.Effect{
				{Group: effects.GroupUnsafeIO, Subtype: effects.SubtypeCreateSubscription,
					Objects: []effects.ObjectRef{
						{Kind: effects.ObjectSubscription, Name: "sub_orders"},
						{Kind: effects.ObjectExternalEndpoint, Host: "upstream.example", Port: 5432},
					},
					Resolution: effects.ResolutionQualified},
			}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "UPDATE users — allow",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{tbl(effects.GroupModify, effects.SubtypeNone, "users")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "SET TimeZone='UTC' — allowed safe session setting",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{guc(effects.SubtypeSet, "timezone")}},
			service: "appdb",
			want:    VerbAllow,
		},
		{
			name:    "SET work_mem='64MB' — denied other session setting",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{guc(effects.SubtypeSet, "work_mem")}},
			service: "appdb",
			want:    VerbDeny,
		},
		{
			name:    "SET search_path = ... — denied search-path change",
			stmt:    effects.ClassifiedStatement{Effects: []effects.Effect{guc(effects.SubtypeSetSearchPath, "search_path")}},
			service: "appdb",
			want:    VerbDeny,
		},
	}
}

func TestSamplePolicy_WorkedExamples(t *testing.T) {
	rs := MustLoadSample()
	for _, c := range cases() {
		t.Run(c.name, func(t *testing.T) {
			d := Evaluate(c.stmt, rs, c.service)
			if d.Verb != c.want {
				t.Errorf("got Verb=%v, want %v (rule=%q reason=%q)", d.Verb, c.want, d.RuleName, d.Reason)
			}
		})
	}
}
```

- [ ] **Step 4: Implement R14 order-independence test**

Create `internal/db/policy/evaluate_order_independence_test.go`:

```go
package policy

import (
	"math/rand"
	"testing"
)

func TestEvaluate_R14OrderIndependent(t *testing.T) {
	// Build a fresh RuleSet on every permutation by reordering the slice
	// post-Decode. Doing this means we don't have to re-shuffle the YAML
	// itself — the evaluator must produce the same decision regardless of
	// statement[] slice order.
	rs := MustLoadSample()
	if len(rs.statement) < 2 {
		t.Fatal("need at least two rules to permute")
	}
	original := append([]*compiledStatementRule(nil), rs.statement...)
	defer func() { rs.statement = original }()

	const permutations = 8
	rng := rand.New(rand.NewSource(1234))

	for _, c := range cases() {
		c := c
		// Snapshot the baseline outcome.
		rs.statement = append([]*compiledStatementRule(nil), original...)
		baseline := Evaluate(c.stmt, rs, c.service)

		for p := 0; p < permutations; p++ {
			permuted := append([]*compiledStatementRule(nil), original...)
			rng.Shuffle(len(permuted), func(i, j int) { permuted[i], permuted[j] = permuted[j], permuted[i] })
			rs.statement = permuted
			got := Evaluate(c.stmt, rs, c.service)
			if got.Verb != baseline.Verb {
				t.Errorf("[%s] permutation %d: Verb=%v want %v (baseline rule=%q got rule=%q)", c.name, p, got.Verb, baseline.Verb, baseline.RuleName, got.RuleName)
			}
		}
	}
}
```

- [ ] **Step 5: Run all tests**

Run: `go test ./internal/db/policy -run "TestSamplePolicy|TestEvaluate_R14"`
Expected: PASS for the worked-examples table and the order-independence permutations.

- [ ] **Step 6: Commit**

```bash
git add internal/db/policy/sample.go internal/db/policy/sample_test.go \
        internal/db/policy/evaluate_order_independence_test.go \
        internal/db/policy/testdata/sample-policy.yaml
git commit -m "$(cat <<'EOF'
db/policy: sample policy + §10.2 worked-examples + R14 order independence

Embeds testdata/sample-policy.yaml (the §9.2 example, source of truth for
Plan 03's golden corpus) and verifies the §10.2 worked-examples table
against MustLoadSample. R14 randomized permutation test guarantees
evaluator outcomes do not depend on rule slice order.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 10: Hot-path allocation bench

**Why:** Spec acceptance criterion 7: no surprise allocations on the evaluate hot path beyond the result Decision and its slices. Bench is a smoke check, not a regression gate, but it documents the intent.

**Files:**
- Create: `internal/db/policy/bench_test.go`

- [ ] **Step 1: Write the bench**

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func BenchmarkEvaluate_AllowReadUsers(b *testing.B) {
	rs := MustLoadSample()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupRead, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}}, Resolution: effects.ResolutionQualified},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(stmt, rs, "appdb")
	}
}

func BenchmarkEvaluate_DenyDangerous(b *testing.B) {
	rs := MustLoadSample()
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{
		{Group: effects.GroupSchemaDestroy, Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "u"}}, Resolution: effects.ResolutionQualified},
	}}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Evaluate(stmt, rs, "appdb")
	}
}

func BenchmarkEvaluateConnection_Allow(b *testing.B) {
	rs := MustLoadSample()
	info := ConnectionInfo{Service: "warehouse", MatchKind: MatchConnect}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = EvaluateConnection(info, rs)
	}
}
```

- [ ] **Step 2: Run the bench**

Run: `go test -bench=. -benchmem -run='^$' ./internal/db/policy`
Expected: bench prints allocs/op. Document the numbers in the commit message; no hard threshold gates this bench, but a future regression that adds, say, 100 allocs/op would be visible.

- [ ] **Step 3: Commit**

```bash
git add internal/db/policy/bench_test.go
git commit -m "$(cat <<'EOF'
db/policy: hot-path benchmarks for Evaluate / EvaluateConnection

Smoke bench against the sample policy. Future regressions in allocs/op
or ns/op are visible at -benchmem. Acceptance criterion 7 documented.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 11: Final verification

- [ ] **Step 1: Full package test**

Run: `go test ./internal/db/policy/...`
Expected: PASS.

- [ ] **Step 2: Full repo test**

Run: `go test ./...`
Expected: PASS (no regression from the three yaml.Node fields added to internal/policy.Policy).

- [ ] **Step 3: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: success.

- [ ] **Step 4: Vet + go build**

Run: `go vet ./... && go build ./...`
Expected: no warnings, success.

- [ ] **Step 5: Confirm acceptance criteria**

Walk through §11 of the design spec (`docs/superpowers/specs/2026-05-09-db-plan-02-policy-evaluator-design.md`). Each item has a passing artifact in this branch:

1. `go test ./internal/db/policy/...` passes — verified in Step 1.
2. `GOOS=windows go build ./...` passes — verified in Step 3.
3. `internal/policy/load.go` accepts the three rule families — verified by `TestLoadAcceptsDBRuleFamilies` in Task 3.
4. `MustLoadSample()` non-nil + worked-examples pass — verified by `TestSamplePolicy_WorkedExamples` in Task 9.
5. Each error/warning code has a subtest — verified by `validate_test.go` in Task 4 (errors) and the audit_on_dangerous test in `decode_test.go`/the approve_on_replication test added below.
6. R14 order-independence — verified by `TestEvaluate_R14OrderIndependent` in Task 9.
7. Allocation budget — documented by `bench_test.go` in Task 10.

If any criterion lacks an artifact, add the missing test to the appropriate file in this branch before considering the plan complete. Specifically:

- If `validate_test.go` lacks a subtest for `approve_on_replication`, add it now:

```go
func TestValidate_ApproveOnReplicationWarning(t *testing.T) {
	conn := []*ConnectionRule{{Name: "r", MatchKind: "replication", Decision: "approve"}}
	ws, err := helperValidate(t, nil, nil, conn)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	found := false
	for _, w := range ws {
		if w.Code == "approve_on_replication" {
			found = true
		}
	}
	if !found {
		t.Errorf("want approve_on_replication warning, got %v", ws)
	}
}
```

- [ ] **Step 6: Final commit if needed**

If the previous step added a test:

```bash
git add internal/db/policy/validate_test.go
git commit -m "$(cat <<'EOF'
db/policy: cover approve_on_replication warning in validate_test

Closes the §11 acceptance gap: every error/warning code now has a
dedicated subtest.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

Plan complete.
