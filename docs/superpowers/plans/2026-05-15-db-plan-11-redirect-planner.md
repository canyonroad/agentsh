# DB Plan 11 Redirect Planner Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement DB Plan 11 so DB statement policy can return `decision: redirect` and a pure Postgres planner can safely rewrite one catalog-resolved source relation to one configured target relation in a single read-only `SELECT`.

**Architecture:** Keep policy support in `internal/db/policy`, expose a narrow parse/deparse backend from `internal/db/classify/postgres`, and put AST rewrite planning in a new pure package `internal/db/redirect`. Runtime forwarding, prepared-cache changes, DB event fields, and client-visible redirect execution stay out of this plan for DB Plan 12.

**Tech Stack:** Go, `github.com/pganalyze/pg_query_go/v6`, `github.com/wasilibs/go-pgquery`, existing DB policy/effects packages, Go unit tests, `GOOS=windows go build ./...`.

---

## Source Spec

Implement the approved design:

- `docs/superpowers/specs/2026-05-15-db-plan-11-redirect-planner-design.md`

## File Structure

Create:

- `internal/db/redirect/types.go` - planner input, output, reason codes, rejection error type.
- `internal/db/redirect/validate.go` - input and classified-statement safety checks.
- `internal/db/redirect/planner.go` - parse, AST mutation, deparse orchestration.
- `internal/db/redirect/walk.go` - relation-bearing `RangeVar` traversal for supported `SELECT` shapes.
- `internal/db/redirect/planner_test.go` - planner rewrite and rejection tests.

Modify:

- `internal/db/policy/types.go` - add `VerbRedirect`, `StatementRule.Redirect`, redirect action/decision metadata types.
- `internal/db/policy/validate.go` - accept statement redirect and validate redirect-specific shape.
- `internal/db/policy/compile.go` - compile redirect verbs and target/source action metadata.
- `internal/db/policy/evaluate.go` - fold redirect with precedence `deny == implicit_deny > approve > redirect > audit > allow`.
- `internal/db/policy/types_test.go` - redirect verb string coverage.
- `internal/db/policy/validate_test.go` - redirect validation coverage.
- `internal/db/policy/decode_test.go` - YAML decode/round-trip coverage for redirect action.
- `internal/db/policy/compile_test.go` - redirect compile coverage.
- `internal/db/policy/evaluate_redirect_test.go` - redirect policy evaluation and precedence tests.
- `internal/db/classify/postgres/parser.go` - define a rewrite backend interface.
- `internal/db/classify/postgres/libpgquery.go` - cgo parse/deparse implementation.
- `internal/db/classify/postgres/wasm.go` - WASM parse/deparse implementation.
- `internal/db/classify/postgres/rewrite_backend_test.go` - parse/deparse backend coverage.
- `docs/agentsh-db-access-spec.md` - update statement rule decision docs from Phase 1 redirect rejection to Phase 2 redirect support.

Do not modify:

- `internal/db/proxy/postgres/simplequery.go`
- `internal/db/proxy/postgres/extquery.go`
- `internal/db/proxy/postgres/preparedcache/*`
- `internal/db/events/*`

## Task 0: Worktree And Baseline

**Files:**
- No code files

- [ ] **Step 1: Create an isolated worktree**

Run from `/home/eran/work/agentsh`:

```bash
git status --short --branch
git worktree add .worktrees/db-plan-11-redirect-planner -b feature/db-plan-11-redirect-planner
cd .worktrees/db-plan-11-redirect-planner
```

Expected: new worktree on `feature/db-plan-11-redirect-planner`. Do not copy the untracked files from the main worktree.

- [ ] **Step 2: Download modules**

```bash
go mod download
```

Expected: exit 0.

- [ ] **Step 3: Run focused baseline tests**

```bash
go test ./internal/db/policy ./internal/db/classify/postgres -count=1
```

Expected: PASS. If this fails before edits, stop and record the baseline failure.

## Task 1: Policy Types And Redirect Validation

**Files:**
- Modify: `internal/db/policy/types.go`
- Modify: `internal/db/policy/validate.go`
- Modify: `internal/db/policy/types_test.go`
- Modify: `internal/db/policy/validate_test.go`
- Modify: `internal/db/policy/decode_test.go`

- [ ] **Step 1: Add failing type and decode tests**

In `internal/db/policy/types_test.go`, extend `TestDecisionVerbString` to include redirect:

```go
{VerbRedirect, "redirect"},
```

In `internal/db/policy/decode_test.go`, add:

```go
func TestDecode_RedirectStatementRule(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`
	rs, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("warnings = %+v", warns)
	}
	rules := rs.AllStatementRules()
	if len(rules) != 1 {
		t.Fatalf("rules = %d, want 1", len(rules))
	}
	if rules[0].Redirect == nil || rules[0].Redirect.Relation != "public.safe_users" {
		t.Fatalf("Redirect = %+v", rules[0].Redirect)
	}
}
```

In `internal/db/policy/validate_test.go`, replace `TestValidate_RuleDecisionRedirect` with:

```go
func TestValidate_RuleDecisionRedirect(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		DBService:             "appdb",
		Operations:            []string{"READ"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}}
	if _, err := helperValidate(t, svcs, stmt, nil); err != nil {
		t.Fatalf("validate redirect statement rule: %v", err)
	}
}
```

Append these redirect validation tests to `internal/db/policy/validate_test.go`:

```go
func TestValidate_RedirectRequiresAction(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		DBService:             "appdb",
		Operations:            []string{"READ"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_relation_required") {
		t.Fatalf("want redirect_relation_required, got %v", err)
	}
}

func TestValidate_RedirectRequiresCanonicalTarget(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		DBService:             "appdb",
		Operations:            []string{"READ"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "safe_users"},
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_relation_not_canonical") {
		t.Fatalf("want redirect_relation_not_canonical, got %v", err)
	}
}

func TestValidate_RedirectRequiresCanonicalSourceRelation(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		DBService:             "appdb",
		Operations:            []string{"READ"},
		Relations:             []string{"public.*"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_source_relation_not_canonical") {
		t.Fatalf("want redirect_source_relation_not_canonical, got %v", err)
	}
}

func TestValidate_RedirectRequiresRelations(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		DBService:             "appdb",
		Operations:            []string{"READ"},
		Objects:               []string{"users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_source_relation_required") {
		t.Fatalf("want redirect_source_relation_required, got %v", err)
	}
}

func TestValidate_RedirectRequiresCatalogResolved(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:       "redirect-users",
		DBService:  "appdb",
		Operations: []string{"READ"},
		Relations:  []string{"public.users"},
		Decision:   "redirect",
		Redirect:   &RedirectAction{Relation: "public.safe_users"},
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_requires_catalog_resolved") {
		t.Fatalf("want redirect_requires_catalog_resolved, got %v", err)
	}
}

func TestValidate_RedirectRequiresReadOnlyOperations(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		DBService:             "appdb",
		Operations:            []string{"MUTATE"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_operations_must_be_read") {
		t.Fatalf("want redirect_operations_must_be_read, got %v", err)
	}
}

func TestValidate_RedirectRequiresTerminatePostgresService(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"legacy": {Name: "legacy", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "passthrough"},
	}
	stmt := []*StatementRule{{
		Name:                  "redirect-users",
		Operations:            []string{"READ"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}}
	_, err := helperValidate(t, svcs, stmt, nil)
	if err == nil || !strings.Contains(err.Error(), "redirect_requires_terminate_postgres_service") {
		t.Fatalf("want redirect_requires_terminate_postgres_service, got %v", err)
	}
}

func TestValidate_ConnectionRuleRedirectStillInvalid(t *testing.T) {
	conn := []*ConnectionRule{{Name: "c", Decision: "redirect"}}
	_, err := helperValidate(t, nil, nil, conn)
	if err == nil || !strings.Contains(err.Error(), "conn_redirect_invalid") {
		t.Fatalf("want conn_redirect_invalid, got %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/db/policy -run 'TestDecisionVerbString|TestDecode_RedirectStatementRule|TestValidate_.*Redirect' -count=1
```

Expected: FAIL with compile errors for `VerbRedirect`, `RedirectAction`, and `StatementRule.Redirect`.

- [ ] **Step 3: Add policy types**

In `internal/db/policy/types.go`, update `DecisionVerb`:

```go
const (
	VerbAllow DecisionVerb = iota
	VerbAudit
	VerbRedirect
	VerbApprove
	VerbDeny
)
```

Update `DecisionVerb.String()`:

```go
case VerbRedirect:
	return "redirect"
```

Add the redirect action and decision metadata types near `StatementRule`:

```go
// RedirectAction is the on-disk action for statement-level decision: redirect.
type RedirectAction struct {
	Relation string `yaml:"relation"`
}

// RedirectDecision carries the selected source and target relation for a
// statement-level redirect decision. Both names are canonical schema.name values.
type RedirectDecision struct {
	SourceRelation string
	TargetRelation string
}
```

Add the field to `StatementRule`:

```go
Redirect *RedirectAction `yaml:"redirect,omitempty"`
```

Add redirect metadata to `Decision`:

```go
Redirect *RedirectDecision
```

Update the restrictiveness comment above `DecisionVerb` to say:

```go
// The numeric ordering (Allow < Audit < Redirect < Approve < Deny) encodes
// restrictiveness for public verbs. The evaluator uses internalVerb so
// implicit deny can rank between approve and deny.
```

- [ ] **Step 4: Add validation helpers**

In `internal/db/policy/validate.go`, change the statement decision switch so statement redirect is accepted:

```go
case "allow", "deny", "approve", "audit", "redirect":
	// ok
```

Then call redirect validation after decision validation:

```go
if r.Decision == "redirect" {
	errs = append(errs, validateRedirectStatementRule(r, svcs)...)
}
```

In the connection rule decision switch, replace the redirect case with:

```go
case "redirect":
	errs = append(errs, fmt.Errorf("conn_redirect_invalid: database_connection_rules[%q]: decision redirect is not valid for DB connection rules", r.Name))
```

Add these helpers to `internal/db/policy/validate.go`:

```go
func validateRedirectStatementRule(r *StatementRule, svcs map[ServiceID]*DBService) []error {
	var errs []error
	if r.Redirect == nil || strings.TrimSpace(r.Redirect.Relation) == "" {
		errs = append(errs, fmt.Errorf("redirect_relation_required: database_rules[%q]: redirect.relation is required when decision is redirect", r.Name))
	} else if !isCanonicalRelationName(r.Redirect.Relation) {
		errs = append(errs, fmt.Errorf("redirect_relation_not_canonical: database_rules[%q]: redirect.relation %q must be canonical schema.name", r.Name, r.Redirect.Relation))
	}
	if len(r.Relations) == 0 {
		errs = append(errs, fmt.Errorf("redirect_source_relation_required: database_rules[%q]: decision redirect requires exactly one canonical relations selector", r.Name))
	} else if len(r.Relations) != 1 || !isCanonicalRelationName(r.Relations[0]) {
		errs = append(errs, fmt.Errorf("redirect_source_relation_not_canonical: database_rules[%q]: decision redirect requires exactly one canonical relations selector, got %v", r.Name, r.Relations))
	}
	if r.MatchObjectResolution != "catalog_resolved" {
		errs = append(errs, fmt.Errorf("redirect_requires_catalog_resolved: database_rules[%q]: decision redirect requires match_object_resolution: catalog_resolved", r.Name))
	}
	if !redirectOperationsReadOnly(r) {
		errs = append(errs, fmt.Errorf("redirect_operations_must_be_read: database_rules[%q]: decision redirect supports read operations only", r.Name))
	}
	if !ruleMatchesTerminatePostgresService(r, svcs) {
		errs = append(errs, fmt.Errorf("redirect_requires_terminate_postgres_service: database_rules[%q]: decision redirect requires at least one matching terminate-mode Postgres service", r.Name))
	}
	return errs
}

func redirectOperationsReadOnly(r *StatementRule) bool {
	if len(r.Operations) == 0 {
		return false
	}
	for _, op := range r.Operations {
		groups, ok := effects.ExpandAlias(op)
		if !ok {
			return false
		}
		for _, g := range groups {
			if g != effects.GroupRead {
				return false
			}
		}
	}
	return true
}

func isCanonicalRelationName(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	return isPlainIdentifier(parts[0]) && isPlainIdentifier(parts[1])
}

func isPlainIdentifier(s string) bool {
	for i, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' && i > 0 || r == '_' {
			continue
		}
		return false
	}
	return true
}
```

- [ ] **Step 5: Run and fix precedence of existing validation checks**

```bash
go test ./internal/db/policy -run 'TestDecisionVerbString|TestDecode_RedirectStatementRule|TestValidate_.*Redirect' -count=1
```

Expected: PASS for the new redirect type/validation tests.

- [ ] **Step 6: Run the full policy package**

```bash
go test ./internal/db/policy -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/db/policy/types.go internal/db/policy/validate.go internal/db/policy/types_test.go internal/db/policy/validate_test.go internal/db/policy/decode_test.go
git commit -m "feat: accept db redirect policy rules"
```

## Task 2: Compile And Evaluate Redirect Decisions

**Files:**
- Modify: `internal/db/policy/compile.go`
- Modify: `internal/db/policy/evaluate.go`
- Modify: `internal/db/policy/compile_test.go`
- Create: `internal/db/policy/evaluate_redirect_test.go`

- [ ] **Step 1: Add failing compile test**

Append to `internal/db/policy/compile_test.go`:

```go
func TestCompileStatementRule_RedirectAction(t *testing.T) {
	r := &StatementRule{
		Name:                  "redirect-users",
		Operations:            []string{"READ"},
		Relations:             []string{"public.users"},
		MatchObjectResolution: "catalog_resolved",
		Decision:              "redirect",
		Redirect:              &RedirectAction{Relation: "public.safe_users"},
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	if c.verb != VerbRedirect {
		t.Fatalf("verb = %v, want redirect", c.verb)
	}
	if c.redirect == nil || c.redirect.SourceRelation != "public.users" || c.redirect.TargetRelation != "public.safe_users" {
		t.Fatalf("redirect = %+v", c.redirect)
	}
}
```

- [ ] **Step 2: Add failing evaluation tests**

Create `internal/db/policy/evaluate_redirect_test.go`:

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func catalogRead(schema, name string) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: name}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    16384,
			Schema: schema,
			Name:   name,
		}},
	}}}
}

func TestEvaluate_RedirectCoversResolvedRelation(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect: {relation: public.safe_users}
`)
	d := Evaluate(catalogRead("public", "users"), rs, "appdb")
	if d.Verb != VerbRedirect || d.RuleName != "redirect-users" {
		t.Fatalf("decision = %+v, want redirect by redirect-users", d)
	}
	if d.Redirect == nil || d.Redirect.SourceRelation != "public.users" || d.Redirect.TargetRelation != "public.safe_users" {
		t.Fatalf("redirect metadata = %+v", d.Redirect)
	}
}

func TestEvaluate_DenyBeatsRedirect(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect: {relation: public.safe_users}
  - name: deny-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: deny
`)
	d := Evaluate(catalogRead("public", "users"), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "deny-users" {
		t.Fatalf("decision = %+v, want deny by deny-users", d)
	}
}

func TestEvaluate_ApproveBeatsRedirect(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect: {relation: public.safe_users}
  - name: approve-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: approve
`)
	d := Evaluate(catalogRead("public", "users"), rs, "appdb")
	if d.Verb != VerbApprove || d.RuleName != "approve-users" {
		t.Fatalf("decision = %+v, want approve by approve-users", d)
	}
	if d.Redirect != nil {
		t.Fatalf("approve decision should not carry redirect metadata: %+v", d.Redirect)
	}
}

func TestEvaluate_RedirectBeatsAuditAndAllow(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: allow-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: allow
  - name: audit-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: audit
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect: {relation: public.safe_users}
`)
	d := Evaluate(catalogRead("public", "users"), rs, "appdb")
	if d.Verb != VerbRedirect || d.RuleName != "redirect-users" {
		t.Fatalf("decision = %+v, want redirect by redirect-users", d)
	}
}

func TestEvaluate_ImplicitDenyBeatsRedirect(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: redirect-users
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect: {relation: public.safe_users}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects: []effects.ObjectRef{
			{Kind: effects.ObjectTable, Name: "users"},
			{Kind: effects.ObjectTable, Name: "orders"},
		},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "public",
			Name:   "users",
		}, {
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "public",
			Name:   "orders",
		}},
	}}}
	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny for uncovered orders", d)
	}
}
```

- [ ] **Step 3: Run tests to verify failure**

```bash
go test ./internal/db/policy -run 'TestCompileStatementRule_RedirectAction|TestEvaluate_.*Redirect|TestEvaluate_DenyBeatsRedirect|TestEvaluate_ApproveBeatsRedirect|TestEvaluate_ImplicitDenyBeatsRedirect' -count=1
```

Expected: FAIL because compile/evaluation do not yet handle `VerbRedirect`.

- [ ] **Step 4: Compile redirect rules**

In `internal/db/policy/compile.go`, add a compiled redirect field:

```go
redirect *RedirectDecision
```

Update the decision switch:

```go
case "redirect":
	c.verb = VerbRedirect
	if r.Redirect != nil && len(r.Relations) == 1 {
		c.redirect = &RedirectDecision{
			SourceRelation: r.Relations[0],
			TargetRelation: r.Redirect.Relation,
		}
	}
```

- [ ] **Step 5: Add internal redirect precedence**

In `internal/db/policy/evaluate.go`, update the `internalVerb` constants and comments:

```go
const (
	verbAllow internalVerb = iota
	verbAudit
	verbRedirect
	verbApprove
	verbImplicitDeny
	verbDeny
)
```

Add redirect state to `effectDecision`:

```go
redirect *RedirectDecision
```

In `foldCoverageRules`, add redirect tracking:

```go
redirectRules []*compiledStatementRule
```

Inside the rule loop:

```go
case VerbRedirect:
	if verbRedirect > best {
		best = verbRedirect
	}
	redirectRules = append(redirectRules, r)
```

In the primary selection switch:

```go
case verbRedirect:
	primary = redirectRules[0]
```

In the returned `effectDecision`, include:

```go
redirect: redirectDecisionForRule(primary),
```

Add this helper:

```go
func redirectDecisionForRule(r *compiledStatementRule) *RedirectDecision {
	if r == nil || r.redirect == nil {
		return nil
	}
	return &RedirectDecision{
		SourceRelation: r.redirect.SourceRelation,
		TargetRelation: r.redirect.TargetRelation,
	}
}
```

In `foldEffects`, add a `verbRedirect` case before `verbApprove`:

```go
case verbRedirect:
	return Decision{
		Verb:                VerbRedirect,
		RuleKind:            RuleKindStatement,
		RuleName:            d.rule.src.Name,
		MatchingEffectIndex: bestIdx,
		MatchingEffectGroup: e.Group,
		Reason:              d.rule.renderMessage(messageContextFor(e, stmt)),
		Redirect:            d.redirect,
	}
```

- [ ] **Step 6: Run policy tests**

```bash
go test ./internal/db/policy -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/db/policy/compile.go internal/db/policy/evaluate.go internal/db/policy/compile_test.go internal/db/policy/evaluate_redirect_test.go
git commit -m "feat: evaluate db redirect decisions"
```

## Task 3: Postgres Rewrite Backend

**Files:**
- Modify: `internal/db/classify/postgres/parser.go`
- Modify: `internal/db/classify/postgres/libpgquery.go`
- Modify: `internal/db/classify/postgres/wasm.go`
- Create: `internal/db/classify/postgres/rewrite_backend_test.go`

- [ ] **Step 1: Add failing rewrite backend test**

Create `internal/db/classify/postgres/rewrite_backend_test.go`:

```go
package postgres

import (
	"strings"
	"testing"
)

func TestRewriteBackend_ParseDeparse(t *testing.T) {
	backend := NewRewriteBackend(DialectPostgres)
	tree, err := backend.Parse("SELECT * FROM public.users")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	out, err := backend.Deparse(tree)
	if err != nil {
		t.Fatalf("Deparse: %v", err)
	}
	if !strings.Contains(strings.ToLower(out), "public.users") {
		t.Fatalf("deparsed SQL = %q, want public.users", out)
	}
	if backend.Backend().String() == "" {
		t.Fatalf("Backend string is empty")
	}
}
```

- [ ] **Step 2: Run test to verify failure**

```bash
go test ./internal/db/classify/postgres -run TestRewriteBackend_ParseDeparse -count=1
```

Expected: FAIL with `undefined: NewRewriteBackend`.

- [ ] **Step 3: Add the interface and constructor**

In `internal/db/classify/postgres/parser.go`, add:

```go
// RewriteBackend exposes parse/deparse operations through the active
// build-tag-selected libpg_query backend. It is intentionally narrower than
// Parser so statement rewriting does not depend on classifier internals.
type RewriteBackend interface {
	Parse(sql string) (*pg_query.ParseResult, error)
	Deparse(tree *pg_query.ParseResult) (string, error)
	Backend() effects.ParserBackend
}

// NewRewriteBackend returns the rewrite backend for the given dialect.
func NewRewriteBackend(d Dialect) RewriteBackend {
	if d.String() == "" {
		panic(fmt.Sprintf("postgres.NewRewriteBackend: unknown dialect %d", d))
	}
	return newRewriteBackend(d)
}
```

- [ ] **Step 4: Implement cgo backend**

In `internal/db/classify/postgres/libpgquery.go`, add:

```go
func newRewriteBackend(d Dialect) RewriteBackend {
	return &cgoParser{dialect: d}
}

func (p *cgoParser) Parse(sql string) (*pg_query.ParseResult, error) {
	return parseCGO(sql)
}

func (p *cgoParser) Deparse(tree *pg_query.ParseResult) (string, error) {
	return pg_query.Deparse(tree)
}

func (p *cgoParser) Backend() effects.ParserBackend {
	return effects.ParserBackendLibPgQuery
}
```

- [ ] **Step 5: Implement WASM backend**

In `internal/db/classify/postgres/wasm.go`, add:

```go
func newRewriteBackend(d Dialect) RewriteBackend {
	return &wasmParser{dialect: d}
}

func (p *wasmParser) Parse(sql string) (*pg_query.ParseResult, error) {
	return parseWASM(sql)
}

func (p *wasmParser) Deparse(tree *pg_query.ParseResult) (string, error) {
	return pgquery_wasm.Deparse(tree)
}

func (p *wasmParser) Backend() effects.ParserBackend {
	return effects.ParserBackendPureGo
}
```

- [ ] **Step 6: Run focused and cross-platform checks**

```bash
go test ./internal/db/classify/postgres -run TestRewriteBackend_ParseDeparse -count=1
GOOS=windows go build ./...
```

Expected: both commands PASS. The Windows build proves the planner can later import `internal/db/classify/postgres` without pulling in cgo-only deparse code.

- [ ] **Step 7: Commit**

```bash
git add internal/db/classify/postgres/parser.go internal/db/classify/postgres/libpgquery.go internal/db/classify/postgres/wasm.go internal/db/classify/postgres/rewrite_backend_test.go
git commit -m "feat: expose postgres rewrite backend"
```

## Task 4: Redirect Planner Contract And Rejections

**Files:**
- Create: `internal/db/redirect/types.go`
- Create: `internal/db/redirect/validate.go`
- Create: `internal/db/redirect/planner.go`
- Create: `internal/db/redirect/planner_test.go`

- [ ] **Step 1: Add planner contract tests**

Create `internal/db/redirect/planner_test.go`:

```go
package redirect

import (
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
)

func testPlanner() Planner {
	return Planner{Backend: postgres.NewRewriteBackend(postgres.DialectPostgres)}
}

func testAction() Action {
	return Action{
		RuleName:       "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users",
	}
}

func resolvedRead(name string) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Resolution: effects.ResolutionCatalogResolved,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: name}},
			ResolvedObjects: []effects.ResolvedObjectRef{{
				Source: effects.ResolvedObjectSourceCatalog,
				Kind:   effects.ResolvedObjectRelation,
				Schema: "public",
				Name:   name,
			}},
		}},
	}
}

func rejectionReason(t *testing.T, err error) Reason {
	t.Helper()
	var r Rejection
	if !errors.As(err, &r) {
		t.Fatalf("error = %v, want Rejection", err)
	}
	return r.Reason
}

func TestPlannerRejectsMissingTarget(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: resolvedRead("users"),
		Action:    Action{RuleName: "redirect-users", SourceRelation: "public.users"},
	})
	if got := rejectionReason(t, err); got != ReasonMissingRedirectTarget {
		t.Fatalf("reason = %q, want %q", got, ReasonMissingRedirectTarget)
	}
}

func TestPlannerRejectsUnresolvedObject(t *testing.T) {
	stmt := resolvedRead("users")
	stmt.Effects[0].Resolution = effects.ResolutionCatalogUnresolved
	stmt.Effects[0].ResolvedObjects[0].UnresolvedReason = "missing"
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: stmt,
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonUnresolvedObject {
		t.Fatalf("reason = %q, want %q", got, ReasonUnresolvedObject)
	}
}

func TestPlannerRejectsWriteStatement(t *testing.T) {
	stmt := effects.ClassifiedStatement{
		RawVerb: "INSERT",
		Effects: []effects.Effect{{
			Group:      effects.GroupWrite,
			Resolution: effects.ResolutionCatalogResolved,
		}},
	}
	_, err := testPlanner().Plan(Input{
		SQL:       "INSERT INTO public.users(id) VALUES (1)",
		Statement: stmt,
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonWriteStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonWriteStatement)
	}
}

func TestPlannerRejectsMultiStatement(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users; SELECT 1",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonMultiStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonMultiStatement)
	}
}

func TestPlannerRejectsNonSelectStatement(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "EXPLAIN SELECT * FROM public.users",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonNonSelectStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonNonSelectStatement)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/db/redirect -count=1
```

Expected: FAIL because package `internal/db/redirect` does not exist.

- [ ] **Step 3: Add planner types**

Create `internal/db/redirect/types.go`:

```go
package redirect

import (
	"fmt"

	"github.com/agentsh/agentsh/internal/db/effects"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

type Reason string

const (
	ReasonUnsupportedStatement  Reason = "unsupported_statement"
	ReasonMultiStatement        Reason = "multi_statement"
	ReasonNonSelectStatement    Reason = "non_select_statement"
	ReasonWriteStatement        Reason = "write_statement"
	ReasonDDLStatement          Reason = "ddl_statement"
	ReasonCopyStatement         Reason = "copy_statement"
	ReasonProceduralStatement   Reason = "procedural_statement"
	ReasonFunctionCallProtocol  Reason = "function_call_protocol"
	ReasonUnresolvedObject      Reason = "unresolved_object"
	ReasonMissingRedirectTarget Reason = "missing_redirect_target"
	ReasonAmbiguousSource       Reason = "ambiguous_redirect_source"
	ReasonSourceNotFound        Reason = "source_relation_not_found"
	ReasonDeparseFailed         Reason = "deparse_failed"
)

type Rejection struct {
	Reason Reason
	Err    error
}

func (r Rejection) Error() string {
	if r.Err != nil {
		return fmt.Sprintf("%s: %v", r.Reason, r.Err)
	}
	return string(r.Reason)
}

func (r Rejection) Unwrap() error { return r.Err }

type Action struct {
	RuleName       string
	SourceRelation string
	TargetRelation string
}

type Input struct {
	SQL       string
	Statement effects.ClassifiedStatement
	Action    Action
}

type Plan struct {
	RewrittenSQL   string
	RuleName       string
	SourceRelation string
	TargetRelation string
}

type SQLBackend interface {
	Parse(sql string) (*pg_query.ParseResult, error)
	Deparse(tree *pg_query.ParseResult) (string, error)
	Backend() effects.ParserBackend
}

type Planner struct {
	Backend SQLBackend
}
```

- [ ] **Step 4: Add validation**

Create `internal/db/redirect/validate.go`:

```go
package redirect

import (
	"strings"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func validateInput(in Input) error {
	if strings.TrimSpace(in.Action.TargetRelation) == "" {
		return Rejection{Reason: ReasonMissingRedirectTarget}
	}
	if strings.TrimSpace(in.Action.SourceRelation) == "" {
		return Rejection{Reason: ReasonSourceNotFound}
	}
	if len(in.Statement.Effects) == 0 {
		return Rejection{Reason: ReasonUnsupportedStatement}
	}
	for _, eff := range in.Statement.Effects {
		if eff.Subtype == effects.SubtypeFunctionCallProtocol {
			return Rejection{Reason: ReasonFunctionCallProtocol}
		}
		switch eff.Group {
		case effects.GroupRead:
			if eff.Resolution != effects.ResolutionCatalogResolved {
				return Rejection{Reason: ReasonUnresolvedObject}
			}
			for _, resolved := range eff.ResolvedObjects {
				if resolved.UnresolvedReason != "" {
					return Rejection{Reason: ReasonUnresolvedObject}
				}
			}
		case effects.GroupWrite, effects.GroupModify, effects.GroupDelete:
			return Rejection{Reason: ReasonWriteStatement}
		case effects.GroupSchemaCreate, effects.GroupSchemaAlter, effects.GroupSchemaDestroy, effects.GroupPrivilege:
			return Rejection{Reason: ReasonDDLStatement}
		case effects.GroupBulkLoad, effects.GroupBulkExport:
			return Rejection{Reason: ReasonCopyStatement}
		case effects.GroupProcedural, effects.GroupUnsafeIO:
			return Rejection{Reason: ReasonProceduralStatement}
		case effects.GroupUnknown:
			return Rejection{Reason: ReasonUnsupportedStatement}
		default:
			return Rejection{Reason: ReasonUnsupportedStatement}
		}
	}
	if !statementContainsResolvedRelation(in.Statement, in.Action.SourceRelation) {
		return Rejection{Reason: ReasonSourceNotFound}
	}
	return nil
}

func statementContainsResolvedRelation(stmt effects.ClassifiedStatement, canonical string) bool {
	for _, eff := range stmt.Effects {
		for _, resolved := range eff.ResolvedObjects {
			if resolved.Source == effects.ResolvedObjectSourceCatalog &&
				resolved.Kind == effects.ResolvedObjectRelation &&
				resolved.UnresolvedReason == "" &&
				resolved.CanonicalName() == canonical {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 5: Add planner orchestration**

Create `internal/db/redirect/planner.go`:

```go
package redirect

import pg_query "github.com/pganalyze/pg_query_go/v6"

func (p Planner) Plan(in Input) (Plan, error) {
	if err := validateInput(in); err != nil {
		return Plan{}, err
	}
	if p.Backend == nil {
		return Plan{}, Rejection{Reason: ReasonUnsupportedStatement}
	}
	tree, err := p.Backend.Parse(in.SQL)
	if err != nil {
		return Plan{}, Rejection{Reason: ReasonUnsupportedStatement, Err: err}
	}
	if tree == nil || len(tree.Stmts) != 1 {
		return Plan{}, Rejection{Reason: ReasonMultiStatement}
	}
	raw := tree.Stmts[0]
	if raw == nil || raw.Stmt == nil {
		return Plan{}, Rejection{Reason: ReasonUnsupportedStatement}
	}
	node, ok := raw.Stmt.Node.(*pg_query.Node_SelectStmt)
	if !ok || node.SelectStmt == nil {
		return Plan{}, Rejection{Reason: ReasonNonSelectStatement}
	}
	if node.SelectStmt.IntoClause != nil {
		return Plan{}, Rejection{Reason: ReasonDDLStatement}
	}
	if len(node.SelectStmt.LockingClause) > 0 {
		return Plan{}, Rejection{Reason: ReasonUnsupportedStatement}
	}
	return Plan{}, Rejection{Reason: ReasonSourceNotFound}
}
```

- [ ] **Step 6: Run rejection tests**

```bash
go test ./internal/db/redirect -run 'TestPlannerRejects' -count=1
```

Expected: PASS for the rejection tests added in this task.

- [ ] **Step 7: Commit**

```bash
git add internal/db/redirect/types.go internal/db/redirect/validate.go internal/db/redirect/planner.go internal/db/redirect/planner_test.go
git commit -m "feat: add redirect planner contract"
```

## Task 5: Relation Rewrite For Simple SELECT And Joins

**Files:**
- Modify: `internal/db/redirect/planner.go`
- Create: `internal/db/redirect/walk.go`
- Modify: `internal/db/redirect/planner_test.go`

- [ ] **Step 1: Add failing rewrite tests**

Append to `internal/db/redirect/planner_test.go`:

```go
func TestPlannerRewritesQualifiedRelation(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if plan.RuleName != "redirect-users" || plan.SourceRelation != "public.users" || plan.TargetRelation != "public.safe_users" {
		t.Fatalf("metadata = %+v", plan)
	}
	want := "public.safe_users"
	if !strings.Contains(strings.ToLower(plan.RewrittenSQL), want) {
		t.Fatalf("rewritten SQL = %q, want %s", plan.RewrittenSQL, want)
	}
	if strings.Contains(strings.ToLower(plan.RewrittenSQL), "public.users") {
		t.Fatalf("rewritten SQL still contains source relation: %q", plan.RewrittenSQL)
	}
}

func TestPlannerRewritesUnqualifiedResolvedRelation(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM users",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(strings.ToLower(plan.RewrittenSQL), "public.safe_users") {
		t.Fatalf("rewritten SQL = %q, want public.safe_users", plan.RewrittenSQL)
	}
}

func TestPlannerPreservesAlias(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT u.id FROM public.users AS u WHERE u.id = $1",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	lower := strings.ToLower(plan.RewrittenSQL)
	if !strings.Contains(lower, "public.safe_users") || !strings.Contains(lower, "u") {
		t.Fatalf("rewritten SQL = %q, want target relation and alias", plan.RewrittenSQL)
	}
}

func TestPlannerRewritesOneRelationInJoin(t *testing.T) {
	stmt := resolvedRead("users")
	stmt.Effects[0].Objects = append(stmt.Effects[0].Objects, effects.ObjectRef{Kind: effects.ObjectTable, Name: "orders"})
	stmt.Effects[0].ResolvedObjects = append(stmt.Effects[0].ResolvedObjects, effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: "public",
		Name:   "orders",
	})
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT u.id FROM public.users u JOIN public.orders o ON o.user_id = u.id",
		Statement: stmt,
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	lower := strings.ToLower(plan.RewrittenSQL)
	if !strings.Contains(lower, "public.safe_users") || !strings.Contains(lower, "public.orders") {
		t.Fatalf("rewritten SQL = %q, want rewritten users and unchanged orders", plan.RewrittenSQL)
	}
}
```

Add `strings` to the test imports:

```go
import (
	"errors"
	"strings"
	"testing"
)
```

- [ ] **Step 2: Run tests to verify failure**

```bash
go test ./internal/db/redirect -run 'TestPlannerRewrites|TestPlannerPreservesAlias' -count=1
```

Expected: FAIL with `source_relation_not_found`.

- [ ] **Step 3: Add relation walker**

Create `internal/db/redirect/walk.go`:

```go
package redirect

import pg_query "github.com/pganalyze/pg_query_go/v6"

func rewriteSelectRelations(sel *pg_query.SelectStmt, source, targetSchema, targetName string) (int, error) {
	if sel == nil {
		return 0, nil
	}
	if len(sel.LockingClause) > 0 {
		return 0, Rejection{Reason: ReasonUnsupportedStatement}
	}
	total, err := rewriteRangeList(sel.FromClause, source, targetSchema, targetName)
	if err != nil {
		return 0, err
	}
	if sel.WithClause != nil {
		for _, c := range sel.WithClause.Ctes {
			count, err := rewriteCTE(c, source, targetSchema, targetName)
			if err != nil {
				return 0, err
			}
			total += count
		}
	}
	if sel.Larg != nil {
		count, err := rewriteSelectRelations(sel.Larg, source, targetSchema, targetName)
		if err != nil {
			return 0, err
		}
		total += count
	}
	if sel.Rarg != nil {
		count, err := rewriteSelectRelations(sel.Rarg, source, targetSchema, targetName)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func rewriteRangeList(list []*pg_query.Node, source, targetSchema, targetName string) (int, error) {
	total := 0
	for _, n := range list {
		count, err := rewriteRangeNode(n, source, targetSchema, targetName)
		if err != nil {
			return 0, err
		}
		total += count
	}
	return total, nil
}

func rewriteRangeNode(n *pg_query.Node, source, targetSchema, targetName string) (int, error) {
	if n == nil {
		return 0, nil
	}
	switch v := n.Node.(type) {
	case *pg_query.Node_RangeVar:
		if v.RangeVar == nil {
			return 0, nil
		}
		if !rangeVarMatchesSource(v.RangeVar, source) {
			return 0, nil
		}
		v.RangeVar.Schemaname = targetSchema
		v.RangeVar.Relname = targetName
		return 1, nil
	case *pg_query.Node_JoinExpr:
		if v.JoinExpr == nil {
			return 0, nil
		}
		left, err := rewriteRangeNode(v.JoinExpr.Larg, source, targetSchema, targetName)
		if err != nil {
			return 0, err
		}
		right, err := rewriteRangeNode(v.JoinExpr.Rarg, source, targetSchema, targetName)
		if err != nil {
			return 0, err
		}
		return left + right, nil
	case *pg_query.Node_RangeSubselect:
		if v.RangeSubselect == nil || v.RangeSubselect.Subquery == nil {
			return 0, nil
		}
		sub, ok := v.RangeSubselect.Subquery.Node.(*pg_query.Node_SelectStmt)
		if !ok || sub.SelectStmt == nil {
			return 0, Rejection{Reason: ReasonUnsupportedStatement}
		}
		return rewriteSelectRelations(sub.SelectStmt, source, targetSchema, targetName)
	case *pg_query.Node_RangeFunction:
		return 0, Rejection{Reason: ReasonProceduralStatement}
	default:
		return 0, nil
	}
}

func rewriteCTE(n *pg_query.Node, source, targetSchema, targetName string) (int, error) {
	if n == nil {
		return 0, nil
	}
	cte, ok := n.Node.(*pg_query.Node_CommonTableExpr)
	if !ok || cte.CommonTableExpr == nil || cte.CommonTableExpr.Ctequery == nil {
		return 0, nil
	}
	sub, ok := cte.CommonTableExpr.Ctequery.Node.(*pg_query.Node_SelectStmt)
	if !ok || sub.SelectStmt == nil {
		return 0, Rejection{Reason: ReasonWriteStatement}
	}
	return rewriteSelectRelations(sub.SelectStmt, source, targetSchema, targetName)
}

func rangeVarMatchesSource(r *pg_query.RangeVar, source string) bool {
	if r == nil {
		return false
	}
	if r.Schemaname != "" {
		return r.Schemaname+"."+r.Relname == source
	}
	return r.Relname == relationName(source)
}
```

- [ ] **Step 4: Complete planner rewrite**

In `internal/db/redirect/planner.go`, after the `SelectStmt` checks, replace the `ReasonSourceNotFound` return with:

```go
targetSchema, targetName := splitCanonical(in.Action.TargetRelation)
count, err := rewriteSelectRelations(node.SelectStmt, in.Action.SourceRelation, targetSchema, targetName)
if err != nil {
	return Plan{}, err
}
if count == 0 {
	return Plan{}, Rejection{Reason: ReasonSourceNotFound}
}
if count > 1 {
	return Plan{}, Rejection{Reason: ReasonAmbiguousSource}
}
rewritten, err := p.Backend.Deparse(tree)
if err != nil {
	return Plan{}, Rejection{Reason: ReasonDeparseFailed, Err: err}
}
return Plan{
	RewrittenSQL:   rewritten,
	RuleName:       in.Action.RuleName,
	SourceRelation: in.Action.SourceRelation,
	TargetRelation: in.Action.TargetRelation,
}, nil
```

Add helpers to `internal/db/redirect/planner.go`:

```go
func splitCanonical(s string) (string, string) {
	for i, r := range s {
		if r == '.' {
			return s[:i], s[i+1:]
		}
	}
	return "", s
}

func relationName(canonical string) string {
	_, name := splitCanonical(canonical)
	return name
}
```

- [ ] **Step 5: Run redirect planner tests**

```bash
go test ./internal/db/redirect -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/redirect/planner.go internal/db/redirect/walk.go internal/db/redirect/planner_test.go
git commit -m "feat: rewrite redirected select relations"
```

## Task 6: Nested SELECT Forms And Safety Rejections

**Files:**
- Modify: `internal/db/redirect/planner_test.go`
- Modify: `internal/db/redirect/walk.go`
- Modify: `internal/db/redirect/validate.go`

- [ ] **Step 1: Add nested rewrite and safety tests**

Append to `internal/db/redirect/planner_test.go`:

```go
func TestPlannerRewritesNestedSubselect(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM (SELECT id FROM public.users) s",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(strings.ToLower(plan.RewrittenSQL), "public.safe_users") {
		t.Fatalf("rewritten SQL = %q, want public.safe_users", plan.RewrittenSQL)
	}
}

func TestPlannerRewritesReadOnlyCTE(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "WITH u AS (SELECT id FROM public.users) SELECT * FROM u",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(strings.ToLower(plan.RewrittenSQL), "public.safe_users") {
		t.Fatalf("rewritten SQL = %q, want public.safe_users", plan.RewrittenSQL)
	}
}

func TestPlannerRewritesSetOperation(t *testing.T) {
	plan, err := testPlanner().Plan(Input{
		SQL:       "SELECT id FROM public.users UNION ALL SELECT id FROM public.archive_users",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if !strings.Contains(strings.ToLower(plan.RewrittenSQL), "public.safe_users") {
		t.Fatalf("rewritten SQL = %q, want public.safe_users", plan.RewrittenSQL)
	}
}

func TestPlannerRejectsSelectInto(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * INTO new_users FROM public.users",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonDDLStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonDDLStatement)
	}
}

func TestPlannerRejectsDataModifyingCTE(t *testing.T) {
	stmt := resolvedRead("users")
	stmt.Effects = append(stmt.Effects, effects.Effect{Group: effects.GroupDelete, Resolution: effects.ResolutionCatalogResolved})
	_, err := testPlanner().Plan(Input{
		SQL:       "WITH d AS (DELETE FROM public.users RETURNING id) SELECT * FROM d",
		Statement: stmt,
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonWriteStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonWriteStatement)
	}
}

func TestPlannerRejectsLockingClause(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users FOR UPDATE",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonUnsupportedStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonUnsupportedStatement)
	}
}

func TestPlannerRejectsRangeFunction(t *testing.T) {
	stmt := resolvedRead("users")
	stmt.Effects = append(stmt.Effects, effects.Effect{Group: effects.GroupProcedural, Resolution: effects.ResolutionCatalogResolved})
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM generate_series(1, 3)",
		Statement: stmt,
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonProceduralStatement {
		t.Fatalf("reason = %q, want %q", got, ReasonProceduralStatement)
	}
}

func TestPlannerRejectsMultipleSourceOccurrences(t *testing.T) {
	_, err := testPlanner().Plan(Input{
		SQL:       "SELECT * FROM public.users u1 JOIN public.users u2 ON u1.id = u2.id",
		Statement: resolvedRead("users"),
		Action:    testAction(),
	})
	if got := rejectionReason(t, err); got != ReasonAmbiguousSource {
		t.Fatalf("reason = %q, want %q", got, ReasonAmbiguousSource)
	}
}
```

- [ ] **Step 2: Run tests**

```bash
go test ./internal/db/redirect -count=1
```

Expected: PASS. The validation layer should reject data-modifying CTEs and procedural effects before AST rewrite reaches unsupported nodes.

- [ ] **Step 3: Run policy and redirect packages together**

```bash
go test ./internal/db/policy ./internal/db/redirect -count=1
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/db/redirect/planner_test.go internal/db/redirect/walk.go internal/db/redirect/validate.go
git commit -m "test: cover redirect planner safety boundaries"
```

## Task 7: Documentation And Final Verification

**Files:**
- Modify: `docs/agentsh-db-access-spec.md`
- Read: `docs/superpowers/specs/2026-05-15-db-plan-11-redirect-planner-design.md`

- [ ] **Step 1: Update DB access spec statement-rule field table**

In `docs/agentsh-db-access-spec.md`, update the statement rule `decision` row from:

```markdown
| `decision` | yes | `allow`, `deny`, `approve`, `audit`. |
```

to:

```markdown
| `decision` | yes | `allow`, `deny`, `approve`, `audit`, `redirect`. `redirect` is statement-level only and requires `redirect.relation`, `relations`, `match_object_resolution: catalog_resolved`, read-only operations, and an eligible terminate-mode Postgres service. |
```

Add a row after `decision`:

```markdown
| `redirect.relation` | only for `decision: redirect` | Canonical target relation formatted as `schema.name`. Plan 11 supports one source relation selected by a canonical `relations` entry and one target relation. Runtime execution is wired in DB Plan 12. |
```

- [ ] **Step 2: Update Phase 1 redirect rejection text**

Find the bullet:

```markdown
- Rule with `decision: redirect` in Phase 1 → load error.
```

Replace it with:

```markdown
- Statement rule with malformed `decision: redirect` shape → load error. Connection-rule redirect remains invalid.
```

- [ ] **Step 3: Run docs diff check**

```bash
git diff -- docs/agentsh-db-access-spec.md
```

Expected: diff only updates redirect policy documentation. It must not describe Simple Query or Extended Query redirect execution as implemented in this plan.

- [ ] **Step 4: Run full verification**

```bash
go test ./internal/db/policy ./internal/db/classify/postgres ./internal/db/redirect -count=1
GOOS=windows go build ./...
```

Expected: both commands PASS.

- [ ] **Step 5: Confirm Plan 12 dependency gate**

```bash
rg -n "VerbRedirect|RedirectDecision|type Planner|func \\(p Planner\\) Plan|ReasonAmbiguousSource" internal/db/policy internal/db/redirect
```

Expected: output includes:

- `VerbRedirect`
- `RedirectDecision`
- `type Planner`
- `func (p Planner) Plan`
- `ReasonAmbiguousSource`

- [ ] **Step 6: Commit**

```bash
git add docs/agentsh-db-access-spec.md
git commit -m "docs: update db redirect policy spec"
```

## Task 8: Final Branch Check

**Files:**
- No code files

- [ ] **Step 1: Run complete tests for touched DB packages**

```bash
go test ./internal/db/... -count=1
```

Expected: PASS. If unrelated integration tests require external Postgres and fail in the local environment, run the focused command from Task 7 Step 4 and record the exact skipped/failing package.

- [ ] **Step 2: Run cross-platform build**

```bash
GOOS=windows go build ./...
```

Expected: PASS.

- [ ] **Step 3: Review final diff**

```bash
git status --short --branch
git log --oneline --max-count=8
```

Expected: clean worktree on `feature/db-plan-11-redirect-planner`, with commits from Tasks 1-7.

## Self-Review Checklist

- Spec coverage:
  - Redirect YAML/action support: Task 1.
  - Redirect validation for statement-only, terminate-mode Postgres, read-only, canonical source/target, catalog resolution: Task 1.
  - Redirect precedence and policy metadata: Task 2.
  - Cross-platform parse/deparse seam: Task 3.
  - Planner contract and rejection reasons: Task 4.
  - AST relation replacement with aliases, joins, nested subselects, CTEs, set operations: Tasks 5 and 6.
  - Runtime boundaries: File Structure and Task 7 docs explicitly exclude proxy runtime changes.
- Placeholder scan:
  - The plan contains concrete tests, commands, expected results, and code snippets for each implementation step.
- Type consistency:
  - Policy uses `RedirectAction` for YAML and `RedirectDecision` for evaluated metadata.
  - Planner uses `Action`, `Input`, `Plan`, `Reason`, `Rejection`, and `Planner.Plan`.
  - Postgres rewrite seam uses `RewriteBackend`.
