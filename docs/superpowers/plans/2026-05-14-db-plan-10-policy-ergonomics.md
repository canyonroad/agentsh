# DB Plan 10 Policy Ergonomics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add catalog-resolved DB policy selectors, policy explanation data, and `agentsh policy db explain` without weakening strict coverage.

**Architecture:** Keep enforcement in `internal/db/policy` pure and platform-neutral. Add canonical selector matching against Plan 09 `effects.ResolvedObjectRef`, then build a separate `internal/db/policyexplain` package for offline classification, catalog fixture resolution, and CLI output shaping. Wire the operator command under the existing `agentsh policy` tree.

**Tech Stack:** Go, `gopkg.in/yaml.v3`, `github.com/gobwas/glob`, Cobra CLI, existing Postgres classifier/catalog/effects/policy packages.

---

## File Structure

- Modify `internal/db/policy/types.go`: add `Relations` and `Functions` fields to `StatementRule`.
- Modify `internal/db/policy/compile.go`: compile canonical selector globs and add resolved relation/function match helpers.
- Modify `internal/db/policy/validate.go`: emit new warning codes and update redirect error wording.
- Modify `internal/db/policy/evaluate.go`: share evaluation with an explanation path and use canonical selector coverage.
- Create `internal/db/policy/explain.go`: exported explanation API types and `ExplainStatement`.
- Modify tests in `internal/db/policy/*_test.go`: decode, compile, validate, canonical evaluation, explanation.
- Create `internal/db/policyexplain/fixture.go`: YAML fixture decode into `catalog.Snapshot` plus search path.
- Create `internal/db/policyexplain/resolve.go`: platform-neutral catalog resolution for classified statements.
- Create `internal/db/policyexplain/run.go`: classify SQL, optionally resolve via fixture, call policy explanation API.
- Create `internal/db/policyexplain/types.go`: stable JSON report structs for CLI output.
- Create tests in `internal/db/policyexplain/*_test.go`.
- Modify `internal/cli/policy_cmd.go`: add `policy db explain` and make `policy validate` surface DB warnings.
- Create `internal/cli/policy_db_explain_test.go`.
- Modify `internal/db/policy/testdata/sample-policy.yaml`: add canonical selector examples.
- Modify `docs/agentsh-db-access-spec.md`: document `relations`, `functions`, resolved `schemas`, and offline explain.

---

## Task 1: Decode, Compile, And Warn For Canonical Selectors

**Files:**
- Modify: `internal/db/policy/types.go`
- Modify: `internal/db/policy/compile.go`
- Modify: `internal/db/policy/validate.go`
- Modify: `internal/db/policy/decode_test.go`
- Modify: `internal/db/policy/compile_test.go`
- Modify: `internal/db/policy/validate_test.go`

- [ ] **Step 1: Write decode and compile tests for selector fields**

Add these tests to `internal/db/policy/decode_test.go` and `internal/db/policy/compile_test.go`.

```go
func TestDecode_CanonicalSelectors(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: canonical-read
    db_service: appdb
    operations: [READ]
    relations: ["public.users", "sales.*"]
    functions: ["public.safe_fn(integer)", "pg_catalog.*"]
    match_object_resolution: catalog_resolved
    decision: allow
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
	if got := rules[0].Relations; len(got) != 2 || got[0] != "public.users" || got[1] != "sales.*" {
		t.Fatalf("Relations = %#v", got)
	}
	if got := rules[0].Functions; len(got) != 2 || got[0] != "public.safe_fn(integer)" || got[1] != "pg_catalog.*" {
		t.Fatalf("Functions = %#v", got)
	}
}

func TestCompileStatementRule_CanonicalSelectorGlobs(t *testing.T) {
	r := &StatementRule{
		Name:       "canonical",
		Operations: []string{"READ"},
		Relations:  []string{"public.users", "sales.*"},
		Functions:  []string{"public.safe_fn(integer)", "pg_catalog.*"},
		Decision:   "allow",
	}
	c, err := compileStatementRule(r)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	rel := effects.ResolvedObjectRef{
		Source: effects.ResolvedObjectSourceCatalog,
		Kind:   effects.ResolvedObjectRelation,
		Schema: "public",
		Name:   "users",
	}
	if !c.relationMatches(rel) {
		t.Fatalf("public.users relation should match")
	}
	fn := effects.ResolvedObjectRef{
		Source:               effects.ResolvedObjectSourceCatalog,
		Kind:                 effects.ResolvedObjectFunction,
		Schema:               "public",
		Name:                 "safe_fn",
		FunctionIdentityArgs: "integer",
	}
	if !c.functionMatches(fn) {
		t.Fatalf("public.safe_fn(integer) function should match")
	}
}

func TestCompileStatementRule_BadCanonicalGlob(t *testing.T) {
	_, err := compileStatementRule(&StatementRule{
		Name:       "bad-relation",
		Operations: []string{"READ"},
		Relations:  []string{"["},
		Decision:   "allow",
	})
	if err == nil || !strings.Contains(err.Error(), "glob_compile") || !strings.Contains(err.Error(), "relations") {
		t.Fatalf("want relation glob_compile error, got %v", err)
	}

	_, err = compileStatementRule(&StatementRule{
		Name:       "bad-function",
		Operations: []string{"READ"},
		Functions:  []string{"["},
		Decision:   "allow",
	})
	if err == nil || !strings.Contains(err.Error(), "glob_compile") || !strings.Contains(err.Error(), "functions") {
		t.Fatalf("want function glob_compile error, got %v", err)
	}
}
```

- [ ] **Step 2: Run selector decode/compile tests and verify they fail**

Run:

```bash
go test ./internal/db/policy -run 'TestDecode_CanonicalSelectors|TestCompileStatementRule_CanonicalSelectorGlobs|TestCompileStatementRule_BadCanonicalGlob' -count=1
```

Expected: FAIL because `StatementRule.Relations`, `StatementRule.Functions`, `compiledStatementRule.relationMatches`, and `compiledStatementRule.functionMatches` do not exist.

- [ ] **Step 3: Add selector fields and compiled matcher fields**

Update `internal/db/policy/types.go`.

```go
type StatementRule struct {
	Name                        string        `yaml:"name"`
	DBService                   string        `yaml:"db_service,omitempty"`
	DBFamily                    string        `yaml:"db_family,omitempty"`
	DBDialect                   string        `yaml:"db_dialect,omitempty"`
	Schemas                     []string      `yaml:"schemas,omitempty"`
	Objects                     []string      `yaml:"objects,omitempty"`
	Relations                   []string      `yaml:"relations,omitempty"`
	Functions                   []string      `yaml:"functions,omitempty"`
	Operations                  []string      `yaml:"operations"`
	Subtypes                    []string      `yaml:"subtypes,omitempty"`
	MatchObjectResolution       string        `yaml:"match_object_resolution,omitempty"`
	Decision                    string        `yaml:"decision"`
	Message                     string        `yaml:"message,omitempty"`
	Timeout                     time.Duration `yaml:"timeout,omitempty"`
	AcknowledgeAuditOnDangerous bool          `yaml:"acknowledge_audit_on_dangerous,omitempty"`
	DenyModeInTx                string        `yaml:"deny_mode_in_tx,omitempty"`
}
```

Update `compiledStatementRule` in `internal/db/policy/compile.go`.

```go
type compiledStatementRule struct {
	src           *StatementRule
	verb          DecisionVerb
	groups        map[effects.Group]struct{}
	subtypes      map[effects.Subtype]struct{} // empty = all subtypes match
	resolution    resolutionMatcher
	schemas       []glob.Glob // empty = all schemas match
	objects       []glob.Glob // syntactic objects; empty = all objects match
	relations     []glob.Glob // resolved relation canonical names
	functions     []glob.Glob // resolved function identity names
	timeout       time.Duration
	msgTemplate   *template.Template // nil = no message rendering
	serviceFilter serviceFilter
}
```

- [ ] **Step 4: Compile canonical selector globs**

In `compileStatementRule`, after compiling `Objects`, add:

```go
for _, pat := range r.Relations {
	g, err := glob.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("glob_compile: rule %q relations %q: %w", r.Name, pat, err)
	}
	c.relations = append(c.relations, g)
}
for _, pat := range r.Functions {
	g, err := glob.Compile(pat)
	if err != nil {
		return nil, fmt.Errorf("glob_compile: rule %q functions %q: %w", r.Name, pat, err)
	}
	c.functions = append(c.functions, g)
}
```

- [ ] **Step 5: Add canonical selector helper methods**

Add these helpers to `internal/db/policy/compile.go`.

```go
func (c *compiledStatementRule) hasObjectSelectors() bool {
	return len(c.objects) > 0 || len(c.relations) > 0 || len(c.functions) > 0
}

func (c *compiledStatementRule) relationMatches(r effects.ResolvedObjectRef) bool {
	if len(c.relations) == 0 {
		return false
	}
	if r.Source != effects.ResolvedObjectSourceCatalog ||
		r.Kind != effects.ResolvedObjectRelation ||
		r.UnresolvedReason != "" {
		return false
	}
	target := r.CanonicalName()
	for _, g := range c.relations {
		if g.Match(target) {
			return true
		}
	}
	return false
}

func (c *compiledStatementRule) functionMatches(r effects.ResolvedObjectRef) bool {
	if len(c.functions) == 0 {
		return false
	}
	if r.Source != effects.ResolvedObjectSourceCatalog ||
		r.Kind != effects.ResolvedObjectFunction ||
		r.UnresolvedReason != "" {
		return false
	}
	target := resolvedFunctionIdentity(r)
	for _, g := range c.functions {
		if g.Match(target) {
			return true
		}
	}
	return false
}

func resolvedFunctionIdentity(r effects.ResolvedObjectRef) string {
	name := r.CanonicalName()
	return name + "(" + r.FunctionIdentityArgs + ")"
}
```

- [ ] **Step 6: Run selector compile tests and verify they pass**

Run:

```bash
go test ./internal/db/policy -run 'TestDecode_CanonicalSelectors|TestCompileStatementRule_CanonicalSelectorGlobs|TestCompileStatementRule_BadCanonicalGlob' -count=1
```

Expected: PASS.

- [ ] **Step 7: Write warning tests**

Add these tests to `internal/db/policy/validate_test.go`.

```go
func TestValidate_CanonicalSelectorWarnings(t *testing.T) {
	src := `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_rules:
  - name: canonical-without-resolution
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    decision: allow
  - name: selector-on-transaction
    db_service: appdb
    operations: [transaction]
    relations: ["public.users"]
    decision: allow
`
	_, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertWarningCode(t, warns, "canonical_selector_without_resolution_guard")
	assertWarningCode(t, warns, "selector_on_objectless_operation")
}

func TestValidate_CanonicalSelectorWithoutCatalogServiceWarning(t *testing.T) {
	src := `version: 1
name: t
db_services:
  legacy:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_rules:
  - name: canonical-wide
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: allow
`
	_, warns, err := loadDB(t, src)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	assertWarningCode(t, warns, "canonical_selector_without_catalog_service")
}

func assertWarningCode(t *testing.T, warns []Warning, code string) {
	t.Helper()
	for _, w := range warns {
		if w.Code == code {
			return
		}
	}
	t.Fatalf("warning %q not found in %+v", code, warns)
}
```

- [ ] **Step 8: Run warning tests and verify they fail**

Run:

```bash
go test ./internal/db/policy -run 'TestValidate_CanonicalSelector' -count=1
```

Expected: FAIL because the warning logic is not implemented.

- [ ] **Step 9: Add warning logic**

Add these helpers to `internal/db/policy/validate.go`.

```go
func ruleHasCanonicalSelectors(r *StatementRule) bool {
	return len(r.Relations) > 0 || len(r.Functions) > 0
}

func ruleHasAnyObjectSelector(r *StatementRule) bool {
	return len(r.Objects) > 0 || len(r.Relations) > 0 || len(r.Functions) > 0
}

func expandedGroups(r *StatementRule) map[effects.Group]struct{} {
	groups := map[effects.Group]struct{}{}
	for _, op := range r.Operations {
		gs, ok := effects.ExpandAlias(op)
		if !ok {
			continue
		}
		for _, g := range gs {
			groups[g] = struct{}{}
		}
	}
	return groups
}

func allGroupsObjectless(groups map[effects.Group]struct{}) bool {
	if len(groups) == 0 {
		return false
	}
	for g := range groups {
		if !isObjectlessGroup(g) {
			return false
		}
	}
	return true
}
```

Inside `validateStatementRule`, reuse the local `groups` map and append warnings:

```go
if ruleHasCanonicalSelectors(r) {
	if r.MatchObjectResolution != "catalog_resolved" {
		warns = append(warns, Warning{
			Rule:    r.Name,
			Field:   "match_object_resolution",
			Code:    "canonical_selector_without_resolution_guard",
			Message: fmt.Sprintf("rule %q uses catalog selectors without match_object_resolution: catalog_resolved", r.Name),
		})
	}
	if !ruleMatchesTerminatePostgresService(r, svcs) {
		warns = append(warns, Warning{
			Rule:    r.Name,
			Field:   "relations",
			Code:    "canonical_selector_without_catalog_service",
			Message: fmt.Sprintf("rule %q uses catalog selectors but matches no terminate-mode Postgres service", r.Name),
		})
	}
}
if ruleHasAnyObjectSelector(r) && allGroupsObjectless(groups) {
	warns = append(warns, Warning{
		Rule:    r.Name,
		Field:   "objects",
		Code:    "selector_on_objectless_operation",
		Message: fmt.Sprintf("rule %q constrains object selectors on objectless operations", r.Name),
	})
}
```

Add the service helper in `validate.go`:

```go
func ruleMatchesTerminatePostgresService(r *StatementRule, svcs map[ServiceID]*DBService) bool {
	for id, svc := range svcs {
		if svc == nil {
			continue
		}
		if svc.Family != "postgres" {
			continue
		}
		if svc.TLSMode == "passthrough" {
			continue
		}
		filter := serviceFilter{service: ServiceID(r.DBService), family: r.DBFamily, dialect: r.DBDialect}
		if filter.matches(id, svc) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 10: Update redirect error wording**

Change both redirect validation errors in `validate.go`:

```go
errs = append(errs, fmt.Errorf("redirect_not_supported_until_plan_11: database_rules[%q]: decision redirect is supported starting in DB Plan 11", r.Name))
```

For connection rules:

```go
errs = append(errs, fmt.Errorf("redirect_not_supported_until_plan_11: database_connection_rules[%q]: decision redirect is not valid for DB connection rules", r.Name))
```

Update existing tests that asserted `rule_decision_redirect` to assert `redirect_not_supported_until_plan_11`.

- [ ] **Step 11: Run policy package tests**

Run:

```bash
go test ./internal/db/policy -count=1
```

Expected: PASS.

- [ ] **Step 12: Commit Task 1**

Run:

```bash
git add internal/db/policy
git commit -m "db/policy: decode canonical selectors"
```

---

## Task 2: Apply Canonical Selectors In Policy Evaluation

**Files:**
- Modify: `internal/db/policy/evaluate.go`
- Modify: `internal/db/policy/compile.go`
- Create: `internal/db/policy/evaluate_canonical_test.go`

- [ ] **Step 1: Write relation selector evaluation tests**

Create `internal/db/policy/evaluate_canonical_test.go`.

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestEvaluate_RelationSelectorCoversResolvedRelation(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			OID:    16384,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v, want allow by canonical-read", d)
	}
}

func TestEvaluate_RelationSelectorDoesNotCoverUnresolvedRelation(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_unresolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogUnresolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           "public",
			Name:             "users",
			UnresolvedReason: "missing",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
}
```

- [ ] **Step 2: Write function and resolved-schema tests**

Append to `evaluate_canonical_test.go`.

```go
func TestEvaluate_FunctionSelectorCoversResolvedFunction(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: safe-fn, db_service: appdb, operations: [procedural], functions: ["public.safe_fn(integer)"], match_object_resolution: catalog_resolved, decision: allow}
`)
	oid := int32(2200)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:       effects.GroupProcedural,
		Resolution:  effects.ResolutionCatalogResolved,
		FunctionOID: &oid,
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source:               effects.ResolvedObjectSourceCatalog,
			Kind:                 effects.ResolvedObjectFunction,
			OID:                  2200,
			Schema:               "public",
			Name:                 "safe_fn",
			FunctionIdentityArgs: "integer",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "safe-fn" {
		t.Fatalf("decision = %+v, want allow by safe-fn", d)
	}
}

func TestEvaluate_SchemasMatchesResolvedSchema(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: sales-read, db_service: appdb, operations: [READ], schemas: ["sales"], relations: ["sales.orders"], match_object_resolution: catalog_resolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "orders"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "sales",
			Name:   "orders",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "sales-read" {
		t.Fatalf("decision = %+v, want allow by sales-read", d)
	}
}

func TestEvaluate_MixedSelectorsCoverByEitherFamily(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: migration-read, db_service: appdb, operations: [READ], objects: ["legacy_users"], relations: ["public.users"], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	d := Evaluate(stmt, rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "migration-read" {
		t.Fatalf("decision = %+v, want allow by migration-read", d)
	}
}
```

- [ ] **Step 3: Run canonical evaluation tests and verify they fail**

Run:

```bash
go test ./internal/db/policy -run 'TestEvaluate_(RelationSelector|FunctionSelector|SchemasMatchesResolved|MixedSelectors)' -count=1
```

Expected: FAIL because evaluation still checks only syntactic object matching and treats procedural FunctionCall effects as objectless.

- [ ] **Step 4: Add object slot helpers**

In `internal/db/policy/evaluate.go`, add helpers near `evaluateEffect`.

```go
func resolvedForObjectIndex(e effects.Effect, idx int) (effects.ResolvedObjectRef, bool) {
	if idx < 0 || idx >= len(e.ResolvedObjects) {
		return effects.ResolvedObjectRef{}, false
	}
	return e.ResolvedObjects[idx], true
}

func functionResolvedObject(e effects.Effect) (effects.ResolvedObjectRef, bool) {
	for _, r := range e.ResolvedObjects {
		if r.Kind == effects.ResolvedObjectFunction {
			return r, true
		}
	}
	return effects.ResolvedObjectRef{}, false
}

func ruleMatchesObjectSlot(r *compiledStatementRule, e effects.Effect, idx int) (bool, string) {
	o := e.Objects[idx]
	resolved, hasResolved := resolvedObjectAt(e, idx)
	if !r.schemaMatchesObjectSlot(o, resolved, hasResolved) {
		return false, ""
	}
	if !r.hasObjectSelectors() {
		return true, "all"
	}
	if len(r.objects) > 0 && r.objectMatches(o) {
		return true, "objects"
	}
	if hasResolved && r.relationMatches(resolved) {
		return true, "relations"
	}
	if hasResolved && r.functionMatches(resolved) {
		return true, "functions"
	}
	return false, ""
}

func resolvedObjectAt(e effects.Effect, idx int) (effects.ResolvedObjectRef, bool) {
	if idx < 0 || idx >= len(e.ResolvedObjects) {
		return effects.ResolvedObjectRef{}, false
	}
	return e.ResolvedObjects[idx], true
}
```

Then add a method in `compile.go`:

```go
func (c *compiledStatementRule) schemaMatchesObjectSlot(o effects.ObjectRef, resolved effects.ResolvedObjectRef, hasResolved bool) bool {
	if len(c.schemas) == 0 {
		return true
	}
	for _, g := range c.schemas {
		if o.Schema != "" && g.Match(o.Schema) {
			return true
		}
		if hasResolved && resolved.Schema != "" && g.Match(resolved.Schema) {
			return true
		}
	}
	return false
}
```

- [ ] **Step 5: Use object slot helpers in deny and coverage passes**

In `evaluateEffect`, replace:

```go
if !r.schemaMatches(o) {
	continue
}
if r.objectMatches(o) {
	return effectDecision{verb: verbDeny, rule: r, denyMatchingObject: o}
}
```

with:

```go
if ok, _ := ruleMatchesObjectSlot(r, e, i); ok {
	return effectDecision{verb: verbDeny, rule: r, denyMatchingObject: o}
}
```

Also replace the non-deny coverage checks:

```go
if !r.schemaMatches(o) {
	continue
}
if !r.objectMatches(o) {
	continue
}
coverage[i] = append(coverage[i], r)
```

with:

```go
if ok, _ := ruleMatchesObjectSlot(r, e, i); ok {
	coverage[i] = append(coverage[i], r)
}
```

- [ ] **Step 6: Support function-only effects with resolved function metadata**

Update `isObjectlessEffect` in `evaluate.go` so a function selector can cover an OID-only FunctionCall effect:

```go
func isObjectlessEffect(e effects.Effect) bool {
	if isObjectlessGroup(e.Group) {
		return true
	}
	if e.Subtype == effects.SubtypeFunctionCallProtocol && len(e.ResolvedObjects) == 0 {
		return true
	}
	return false
}
```

At the start of `evaluateEffect`, before the objectless branch, add:

```go
if len(e.Objects) == 0 && len(e.ResolvedObjects) > 0 {
	return evaluateEffectResolvedOnly(e, applicable)
}
```

Add `evaluateEffectResolvedOnly`:

```go
func evaluateEffectResolvedOnly(e effects.Effect, applicable []*compiledStatementRule) effectDecision {
	for _, r := range applicable {
		if r.verb != VerbDeny || !ruleMatchesEffectMeta(r, e) {
			continue
		}
		for _, resolved := range e.ResolvedObjects {
			if r.functionMatches(resolved) || r.relationMatches(resolved) {
				return effectDecision{verb: verbDeny, rule: r}
			}
		}
	}

	var coverage []*compiledStatementRule
	for _, r := range applicable {
		if r.verb == VerbDeny || !ruleMatchesEffectMeta(r, e) {
			continue
		}
		for _, resolved := range e.ResolvedObjects {
			if r.functionMatches(resolved) || r.relationMatches(resolved) || !r.hasObjectSelectors() {
				coverage = append(coverage, r)
				break
			}
		}
	}
	if len(coverage) == 0 {
		return effectDecision{verb: verbImplicitDeny}
	}
	return foldCoverageRules(coverage)
}
```

Extract the repeated objectless coverage fold into a helper:

```go
func foldCoverageRules(coverage []*compiledStatementRule) effectDecision {
	var (
		best         internalVerb = verbAllow
		primary      *compiledStatementRule
		approveRules []*compiledStatementRule
		auditRules   []*compiledStatementRule
		approveSeen  = map[string]bool{}
		auditSeen    = map[string]bool{}
	)
	for _, r := range coverage {
		switch r.verb {
		case VerbApprove:
			if verbApprove > best {
				best = verbApprove
			}
			if !approveSeen[r.src.Name] {
				approveSeen[r.src.Name] = true
				approveRules = append(approveRules, r)
			}
		case VerbAudit:
			if verbAudit > best {
				best = verbAudit
			}
			if !auditSeen[r.src.Name] {
				auditSeen[r.src.Name] = true
				auditRules = append(auditRules, r)
			}
		}
	}
	switch best {
	case verbApprove:
		primary = approveRules[0]
	case verbAudit:
		primary = auditRules[0]
	default:
		primary = coverage[0]
	}
	return effectDecision{
		verb:                best,
		rule:                primary,
		contributingApprove: approveRules,
		contributingAudit:   auditRules,
	}
}
```

Use `foldCoverageRules(coverage)` inside `evaluateEffectObjectless` to remove duplicated fold logic.

- [ ] **Step 7: Run canonical evaluation tests**

Run:

```bash
go test ./internal/db/policy -run 'TestEvaluate_(RelationSelector|FunctionSelector|SchemasMatchesResolved|MixedSelectors)' -count=1
```

Expected: PASS.

- [ ] **Step 8: Run full policy package tests**

Run:

```bash
go test ./internal/db/policy -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit Task 2**

Run:

```bash
git add internal/db/policy
git commit -m "db/policy: match canonical selectors"
```

---

## Task 3: Add Policy Explanation API

**Files:**
- Create: `internal/db/policy/explain.go`
- Modify: `internal/db/policy/evaluate.go`
- Create: `internal/db/policy/explain_test.go`

- [ ] **Step 1: Write explanation API tests**

Create `internal/db/policy/explain_test.go`.

```go
package policy

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestExplainStatement_ReturnsCoverageAndDecision(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	stmt := effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionCatalogResolved,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "users"}},
		ResolvedObjects: []effects.ResolvedObjectRef{{
			Source: effects.ResolvedObjectSourceCatalog,
			Kind:   effects.ResolvedObjectRelation,
			Schema: "public",
			Name:   "users",
		}},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbAllow || ex.Decision.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].Coverage) != 1 {
		t.Fatalf("coverage = %+v", ex.Effects)
	}
	cov := ex.Effects[0].Coverage[0]
	if !cov.Covered {
		t.Fatalf("coverage = %+v, want covered", cov)
	}
	if len(cov.CoveringRules) != 1 || cov.CoveringRules[0].RuleName != "canonical-read" {
		t.Fatalf("covering rules = %+v", cov.CoveringRules)
	}
	if cov.CoveringRules[0].Selector != "relations" {
		t.Fatalf("selector = %q, want relations", cov.CoveringRules[0].Selector)
	}
}

func TestExplainStatement_ReportsUncoveredObject(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: read-users, db_service: appdb, operations: [READ], objects: ["users"], decision: allow}
`)
	stmt := effects.ClassifiedStatement{Effects: []effects.Effect{{
		Group:      effects.GroupRead,
		Resolution: effects.ResolutionQualified,
		Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Name: "payments"}},
	}}}

	ex := ExplainStatement(stmt, rs, "appdb")
	if ex.Decision.Verb != VerbDeny || ex.Decision.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", ex.Decision)
	}
	if len(ex.Effects) != 1 || len(ex.Effects[0].Coverage) != 1 {
		t.Fatalf("coverage = %+v", ex.Effects)
	}
	cov := ex.Effects[0].Coverage[0]
	if cov.Covered || cov.UncoveredReason == "" {
		t.Fatalf("coverage = %+v, want uncovered reason", cov)
	}
}
```

- [ ] **Step 2: Run explanation tests and verify they fail**

Run:

```bash
go test ./internal/db/policy -run TestExplainStatement -count=1
```

Expected: FAIL because `ExplainStatement` and explanation types do not exist.

- [ ] **Step 3: Add explanation types**

Create `internal/db/policy/explain.go`.

```go
package policy

import "github.com/agentsh/agentsh/internal/db/effects"

type StatementExplanation struct {
	Decision        Decision
	ApplicableRules []string
	Effects         []EffectExplanation
}

type EffectExplanation struct {
	Index      int
	Group      effects.Group
	Subtype    effects.Subtype
	Resolution effects.Resolution
	Coverage   []ObjectCoverage
	DenyRules  []RuleMatch
}

type ObjectCoverage struct {
	Index            int
	Object           effects.ObjectRef
	ResolvedObject   *effects.ResolvedObjectRef
	Covered          bool
	CoveringRules    []RuleMatch
	UncoveredReason  string
}

type RuleMatch struct {
	RuleName string
	Verb     DecisionVerb
	Selector string
}

func ExplainStatement(stmt effects.ClassifiedStatement, rs *RuleSet, svc ServiceID) StatementExplanation {
	if rs == nil {
		return StatementExplanation{Decision: implicitDeny(stmt, 0, "policy not loaded")}
	}
	applicable := rs.statementRulesFor(svc)
	perEffect := make([]effectDecision, len(stmt.Effects))
	effectsOut := make([]EffectExplanation, len(stmt.Effects))
	for i, e := range stmt.Effects {
		perEffect[i], effectsOut[i] = explainEffect(i, e, applicable)
	}
	applicableNames := make([]string, 0, len(applicable))
	for _, r := range applicable {
		applicableNames = append(applicableNames, r.src.Name)
	}
	if len(stmt.Effects) == 0 {
		return StatementExplanation{Decision: implicitDeny(stmt, 0, "no effects on statement"), ApplicableRules: applicableNames}
	}
	return StatementExplanation{
		Decision:        foldEffects(stmt, perEffect),
		ApplicableRules: applicableNames,
		Effects:         effectsOut,
	}
}
```

- [ ] **Step 4: Implement `explainEffect` for object-bearing effects**

Add to `explain.go`.

```go
func explainEffect(index int, e effects.Effect, applicable []*compiledStatementRule) (effectDecision, EffectExplanation) {
	d := evaluateEffect(e, applicable)
	ex := EffectExplanation{
		Index:      index,
		Group:      e.Group,
		Subtype:    e.Subtype,
		Resolution: e.Resolution,
	}
	if len(e.Objects) == 0 {
		return d, ex
	}
	for i, obj := range e.Objects {
		cov := ObjectCoverage{Index: i, Object: obj}
		if resolved, ok := resolvedObjectAt(e, i); ok {
			r := resolved
			cov.ResolvedObject = &r
		}
		for _, r := range applicable {
			if !ruleMatchesEffectMeta(r, e) {
				continue
			}
			ok, selector := ruleMatchesObjectSlot(r, e, i)
			if !ok {
				continue
			}
			if r.verb == VerbDeny {
				ex.DenyRules = append(ex.DenyRules, RuleMatch{RuleName: r.src.Name, Verb: r.verb, Selector: selector})
				continue
			}
			cov.Covered = true
			cov.CoveringRules = append(cov.CoveringRules, RuleMatch{RuleName: r.src.Name, Verb: r.verb, Selector: selector})
		}
		if !cov.Covered {
			cov.UncoveredReason = "no matching non-deny rule covers object"
		}
		ex.Coverage = append(ex.Coverage, cov)
	}
	return d, ex
}
```

- [ ] **Step 5: Preserve enforcement behavior**

Do not change the exported `Evaluate` signature. Keep `Evaluate` returning only
`Decision`, and ensure `ExplainStatement` calls the same `evaluateEffect`
function that `Evaluate` calls. The enforcement and explanation paths must
share `ruleMatchesEffectMeta`, `ruleMatchesObjectSlot`, and `foldEffects`.

- [ ] **Step 6: Run explanation tests**

Run:

```bash
go test ./internal/db/policy -run TestExplainStatement -count=1
```

Expected: PASS.

- [ ] **Step 7: Run policy package tests**

Run:

```bash
go test ./internal/db/policy -count=1
```

Expected: PASS.

- [ ] **Step 8: Commit Task 3**

Run:

```bash
git add internal/db/policy
git commit -m "db/policy: explain statement coverage"
```

---

## Task 4: Build Offline DB Policy Explain Runner

**Files:**
- Create: `internal/db/policyexplain/types.go`
- Create: `internal/db/policyexplain/fixture.go`
- Create: `internal/db/policyexplain/resolve.go`
- Create: `internal/db/policyexplain/run.go`
- Create: `internal/db/policyexplain/fixture_test.go`
- Create: `internal/db/policyexplain/run_test.go`

- [ ] **Step 1: Write fixture loader test**

Create `internal/db/policyexplain/fixture_test.go`.

```go
package policyexplain

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadCatalogFixture(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "catalog.yaml")
	err := os.WriteFile(path, []byte(`search_path: [public, pg_catalog]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
functions:
  - oid: 2200
    schema: public
    name: safe_fn
    identity_args: integer
    volatility: stable
    strict: true
    return_type_oid: 23
`), 0644)
	if err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	fixture, err := LoadCatalogFixture(path)
	if err != nil {
		t.Fatalf("LoadCatalogFixture: %v", err)
	}
	if got := fixture.SearchPath; len(got) != 2 || got[0] != "public" || got[1] != "pg_catalog" {
		t.Fatalf("SearchPath = %#v", got)
	}
	if rel, ok := fixture.Snapshot.RelationByOID(16384); !ok || rel.Name.String() != "public.users" {
		t.Fatalf("relation lookup = %+v, %v", rel, ok)
	}
	if fn, ok := fixture.Snapshot.FunctionByOID(2200); !ok || fn.IdentityArgs != "integer" {
		t.Fatalf("function lookup = %+v, %v", fn, ok)
	}
}
```

- [ ] **Step 2: Run fixture test and verify it fails**

Run:

```bash
go test ./internal/db/policyexplain -run TestLoadCatalogFixture -count=1
```

Expected: FAIL because package `internal/db/policyexplain` does not exist.

- [ ] **Step 3: Add report and fixture types**

Create `internal/db/policyexplain/types.go`.

```go
package policyexplain

import (
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/effects"
)

type Options struct {
	SQL            string
	Service        dbpolicy.ServiceID
	Dialect        string
	SearchPath     []string
	TempTables      []string
	CatalogFixture string
}

type Report struct {
	Service       string            `json:"service"`
	Dialect       string            `json:"dialect"`
	CatalogSource string            `json:"catalog_source"`
	Statements    []StatementReport `json:"statements"`
	Warnings      []WarningReport   `json:"warnings,omitempty"`
}

type StatementReport struct {
	Index         int                  `json:"index"`
	RawVerb       string               `json:"raw_verb,omitempty"`
	ParserBackend string               `json:"parser_backend,omitempty"`
	Effects       []EffectReport       `json:"effects"`
	Decision      DecisionReport       `json:"decision"`
	Error         string               `json:"error,omitempty"`
}

type EffectReport struct {
	Index           int                         `json:"index"`
	Operation       string                      `json:"operation"`
	Subtype         string                      `json:"subtype,omitempty"`
	Resolution      string                      `json:"resolution"`
	Objects         []effects.ObjectRef         `json:"objects,omitempty"`
	ResolvedObjects []effects.ResolvedObjectRef `json:"resolved_objects,omitempty"`
	Coverage        []CoverageReport            `json:"coverage,omitempty"`
}

type CoverageReport struct {
	Object          string       `json:"object,omitempty"`
	ResolvedObject  string       `json:"resolved_object,omitempty"`
	Covered         bool         `json:"covered"`
	CoveringRules   []RuleReport `json:"covering_rules,omitempty"`
	UncoveredReason string       `json:"uncovered_reason,omitempty"`
	Selector        string       `json:"selector,omitempty"`
}

type RuleReport struct {
	RuleName string `json:"rule_name"`
	Verb     string `json:"verb"`
	Selector string `json:"selector,omitempty"`
}

type DecisionReport struct {
	Verb                string `json:"verb"`
	RuleKind            string `json:"rule_kind,omitempty"`
	RuleName            string `json:"rule_name,omitempty"`
	MatchingEffectIndex int    `json:"matching_effect_index"`
	MatchingEffectGroup string `json:"matching_effect_group,omitempty"`
	Reason              string `json:"reason,omitempty"`
}

type WarningReport struct {
	Rule    string `json:"rule,omitempty"`
	Field   string `json:"field,omitempty"`
	Code    string `json:"code"`
	Message string `json:"message"`
}
```

Create `internal/db/policyexplain/fixture.go`.

```go
package policyexplain

import (
	"fmt"
	"os"

	"github.com/agentsh/agentsh/internal/db/catalog"
	"gopkg.in/yaml.v3"
)

type CatalogFixture struct {
	SearchPath []string
	Snapshot   catalog.Snapshot
}

type fixtureYAML struct {
	SearchPath []string          `yaml:"search_path"`
	Relations  []fixtureRelation `yaml:"relations"`
	Functions  []fixtureFunction `yaml:"functions"`
}

type fixtureRelation struct {
	OID    uint32 `yaml:"oid"`
	Schema string `yaml:"schema"`
	Name   string `yaml:"name"`
	Kind   string `yaml:"kind"`
	Owner  string `yaml:"owner"`
}

type fixtureFunction struct {
	OID           uint32 `yaml:"oid"`
	Schema        string `yaml:"schema"`
	Name          string `yaml:"name"`
	IdentityArgs  string `yaml:"identity_args"`
	Volatility    string `yaml:"volatility"`
	Strict        bool   `yaml:"strict"`
	ReturnTypeOID uint32 `yaml:"return_type_oid"`
}
```

- [ ] **Step 4: Implement fixture parsing**

Add to `fixture.go`.

```go
func LoadCatalogFixture(path string) (CatalogFixture, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return CatalogFixture{}, fmt.Errorf("read catalog fixture: %w", err)
	}
	var in fixtureYAML
	if err := yaml.Unmarshal(raw, &in); err != nil {
		return CatalogFixture{}, fmt.Errorf("parse catalog fixture: %w", err)
	}
	relations := make([]catalog.Relation, 0, len(in.Relations))
	for i, rel := range in.Relations {
		kind, ok := parseRelationKind(rel.Kind)
		if !ok {
			return CatalogFixture{}, fmt.Errorf("relations[%d].kind: unknown relation kind %q", i, rel.Kind)
		}
		relations = append(relations, catalog.Relation{
			OID:   catalog.OID(rel.OID),
			Name:  catalog.Name{Schema: rel.Schema, Name: rel.Name},
			Kind:  kind,
			Owner: rel.Owner,
		})
	}
	functions := make([]catalog.Function, 0, len(in.Functions))
	for i, fn := range in.Functions {
		vol, ok := parseVolatility(fn.Volatility)
		if !ok {
			return CatalogFixture{}, fmt.Errorf("functions[%d].volatility: unknown volatility %q", i, fn.Volatility)
		}
		functions = append(functions, catalog.Function{
			OID:           catalog.OID(fn.OID),
			Name:          catalog.Name{Schema: fn.Schema, Name: fn.Name},
			IdentityArgs:  fn.IdentityArgs,
			Volatility:    vol,
			Strict:        fn.Strict,
			ReturnTypeOID: catalog.OID(fn.ReturnTypeOID),
		})
	}
	return CatalogFixture{
		SearchPath: append([]string(nil), in.SearchPath...),
		Snapshot:   catalog.NewSnapshot(relations, functions),
	}, nil
}

func parseRelationKind(s string) (catalog.RelationKind, bool) {
	switch s {
	case "table":
		return catalog.RelationTable, true
	case "partitioned_table":
		return catalog.RelationPartitionedTable, true
	case "view":
		return catalog.RelationView, true
	case "materialized_view":
		return catalog.RelationMaterializedView, true
	case "foreign_table":
		return catalog.RelationForeignTable, true
	case "sequence":
		return catalog.RelationSequence, true
	default:
		return 0, false
	}
}

func parseVolatility(s string) (catalog.FunctionVolatility, bool) {
	switch s {
	case "", "volatile":
		return catalog.VolatilityVolatile, true
	case "stable":
		return catalog.VolatilityStable, true
	case "immutable":
		return catalog.VolatilityImmutable, true
	default:
		return 0, false
	}
}
```

- [ ] **Step 5: Run fixture test**

Run:

```bash
go test ./internal/db/policyexplain -run TestLoadCatalogFixture -count=1
```

Expected: PASS.

- [ ] **Step 6: Write runner test**

Create `internal/db/policyexplain/run_test.go`.

```go
package policyexplain

import (
	"os"
	"path/filepath"
	"testing"

	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

func TestRun_WithCatalogFixtureAllowsCanonicalRelation(t *testing.T) {
	rs := loadRuleSetForExplain(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - {name: canonical-read, db_service: appdb, operations: [READ], relations: ["public.users"], match_object_resolution: catalog_resolved, decision: allow}
`)
	dir := t.TempDir()
	fixture := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(fixture, []byte(`search_path: [public]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
`), 0644); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	report, err := Run(rs, []dbpolicy.Warning(nil), Options{
		SQL:            "SELECT * FROM users",
		Service:        "appdb",
		Dialect:        "postgres",
		CatalogFixture: fixture,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if report.CatalogSource != "fixture" {
		t.Fatalf("CatalogSource = %q", report.CatalogSource)
	}
	if len(report.Statements) != 1 {
		t.Fatalf("statements = %d", len(report.Statements))
	}
	dec := report.Statements[0].Decision
	if dec.Verb != "allow" || dec.RuleName != "canonical-read" {
		t.Fatalf("decision = %+v", dec)
	}
}

func loadRuleSetForExplain(t *testing.T, src string) *dbpolicy.RuleSet {
	t.Helper()
	p, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := dbpolicy.Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	return rs
}
```

- [ ] **Step 7: Run runner test and verify it fails**

Run:

```bash
go test ./internal/db/policyexplain -run TestRun_WithCatalogFixtureAllowsCanonicalRelation -count=1
```

Expected: FAIL because `Run` and fixture resolution do not exist.

- [ ] **Step 8: Implement platform-neutral resolution**

Create `internal/db/policyexplain/resolve.go`.

```go
package policyexplain

import (
	"github.com/agentsh/agentsh/internal/db/catalog"
	"github.com/agentsh/agentsh/internal/db/effects"
)

func resolveStatements(stmts []effects.ClassifiedStatement, fixture CatalogFixture) []effects.ClassifiedStatement {
	out := make([]effects.ClassifiedStatement, len(stmts))
	for i := range stmts {
		out[i] = resolveStatement(stmts[i], fixture)
	}
	return out
}

func resolveStatement(stmt effects.ClassifiedStatement, fixture CatalogFixture) effects.ClassifiedStatement {
	out := stmt
	out.Effects = make([]effects.Effect, len(stmt.Effects))
	for i, eff := range stmt.Effects {
		out.Effects[i] = resolveEffect(eff, fixture)
	}
	return out
}

func resolveEffect(eff effects.Effect, fixture CatalogFixture) effects.Effect {
	out := eff
	resolved := make([]effects.ResolvedObjectRef, 0, len(eff.Objects)+1)
	allResolved := true
	for _, obj := range eff.Objects {
		ref := resolveObject(obj, fixture)
		if ref.UnresolvedReason != "" {
			allResolved = false
		}
		resolved = append(resolved, ref)
	}
	if eff.FunctionOID != nil {
		ref := resolveFunctionOID(*eff.FunctionOID, fixture)
		if ref.UnresolvedReason != "" {
			allResolved = false
		}
		resolved = append(resolved, ref)
	}
	if len(resolved) == 0 {
		return out
	}
	out.ResolvedObjects = resolved
	if allResolved {
		out.Resolution = effects.ResolutionCatalogResolved
	} else {
		out.Resolution = effects.ResolutionCatalogUnresolved
	}
	return out
}

func resolveObject(obj effects.ObjectRef, fixture CatalogFixture) effects.ResolvedObjectRef {
	if obj.Kind != effects.ObjectTable && obj.Kind != effects.ObjectView && obj.Kind != effects.ObjectSequence {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: "unsupported",
		}
	}
	res := catalog.ResolveRelation(fixture.Snapshot, catalog.Name{Schema: obj.Schema, Name: obj.Name}, fixture.SearchPath)
	if !res.OK() {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectRelation,
			Schema:           obj.Schema,
			Name:             obj.Name,
			UnresolvedReason: res.Reason.String(),
		}
	}
	rel := res.Relation
	return effects.ResolvedObjectRef{
		Source:       effects.ResolvedObjectSourceCatalog,
		Kind:         effects.ResolvedObjectRelation,
		OID:          uint32(rel.OID),
		Schema:       rel.Name.Schema,
		Name:         rel.Name.Name,
		RelationKind: rel.Kind.String(),
	}
}

func resolveFunctionOID(oid int32, fixture CatalogFixture) effects.ResolvedObjectRef {
	res := catalog.ResolveFunctionByOID(fixture.Snapshot, catalog.OID(oid))
	if !res.OK() {
		return effects.ResolvedObjectRef{
			Source:           effects.ResolvedObjectSourceCatalog,
			Kind:             effects.ResolvedObjectFunction,
			OID:              uint32(oid),
			UnresolvedReason: res.Reason.String(),
		}
	}
	fn := res.Function
	return effects.ResolvedObjectRef{
		Source:               effects.ResolvedObjectSourceCatalog,
		Kind:                 effects.ResolvedObjectFunction,
		OID:                  uint32(fn.OID),
		Schema:               fn.Name.Schema,
		Name:                 fn.Name.Name,
		FunctionIdentityArgs: fn.IdentityArgs,
		FunctionVolatility:   functionVolatility(fn.Volatility),
	}
}

func functionVolatility(v catalog.FunctionVolatility) string {
	switch v {
	case catalog.VolatilityImmutable:
		return "immutable"
	case catalog.VolatilityStable:
		return "stable"
	case catalog.VolatilityVolatile:
		return "volatile"
	default:
		return ""
	}
}
```

- [ ] **Step 9: Implement `Run`**

Create `internal/db/policyexplain/run.go`.

```go
package policyexplain

import (
	"fmt"
	"strings"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
)

func Run(rs *dbpolicy.RuleSet, warns []dbpolicy.Warning, opts Options) (Report, error) {
	dialect, ok := classify_pg.ParseDialect(defaultString(opts.Dialect, "postgres"))
	if !ok {
		return Report{}, fmt.Errorf("unknown dialect %q", opts.Dialect)
	}
	sess := classify_pg.SessionState{SearchPath: append([]string(nil), opts.SearchPath...)}
	if len(opts.TempTables) > 0 {
		sess.TempTables = make(map[string]struct{}, len(opts.TempTables))
		for _, name := range opts.TempTables {
			sess.TempTables[strings.ToLower(strings.TrimSpace(name))] = struct{}{}
		}
	}
	stmts, err := classify_pg.New(dialect).Classify(opts.SQL, sess, classify_pg.Options{})
	if err != nil {
		return Report{}, err
	}
	catalogSource := "none"
	if opts.CatalogFixture != "" {
		fixture, err := LoadCatalogFixture(opts.CatalogFixture)
		if err != nil {
			return Report{}, err
		}
		stmts = resolveStatements(stmts, fixture)
		catalogSource = "fixture"
	}
	report := Report{
		Service:       string(opts.Service),
		Dialect:       dialect.String(),
		CatalogSource: catalogSource,
		Warnings:      warningReports(warns),
	}
	for i, stmt := range stmts {
		report.Statements = append(report.Statements, statementReport(i, stmt, dbpolicy.ExplainStatement(stmt, rs, opts.Service)))
	}
	return report, nil
}

func defaultString(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func warningReports(warns []dbpolicy.Warning) []WarningReport {
	out := make([]WarningReport, 0, len(warns))
	for _, w := range warns {
		out = append(out, WarningReport{Rule: w.Rule, Field: w.Field, Code: w.Code, Message: w.Message})
	}
	return out
}

func statementReport(index int, stmt effects.ClassifiedStatement, ex dbpolicy.StatementExplanation) StatementReport {
	out := StatementReport{
		Index:         index,
		RawVerb:       stmt.RawVerb,
		ParserBackend: stmt.ParserBackend.String(),
		Decision: DecisionReport{
			Verb:                ex.Decision.Verb.String(),
			RuleKind:            ex.Decision.RuleKind.String(),
			RuleName:            ex.Decision.RuleName,
			MatchingEffectIndex: ex.Decision.MatchingEffectIndex,
			MatchingEffectGroup: ex.Decision.MatchingEffectGroup.String(),
			Reason:              ex.Decision.Reason,
		},
		Error: stmt.Error,
	}
	for _, eff := range ex.Effects {
		out.Effects = append(out.Effects, effectReport(eff, stmt.Effects[eff.Index]))
	}
	return out
}
```

Add effect conversion helpers to `run.go`.

```go
func effectReport(ex dbpolicy.EffectExplanation, eff effects.Effect) EffectReport {
	out := EffectReport{
		Index:           ex.Index,
		Operation:       ex.Group.String(),
		Resolution:      ex.Resolution.String(),
		Objects:         append([]effects.ObjectRef(nil), eff.Objects...),
		ResolvedObjects: append([]effects.ResolvedObjectRef(nil), eff.ResolvedObjects...),
	}
	if ex.Subtype != effects.SubtypeNone {
		out.Subtype = ex.Subtype.String()
	}
	for _, cov := range ex.Coverage {
		out.Coverage = append(out.Coverage, coverageReport(cov))
	}
	return out
}

func coverageReport(cov dbpolicy.ObjectCoverage) CoverageReport {
	out := CoverageReport{
		Object:          objectName(cov.Object),
		Covered:         cov.Covered,
		UncoveredReason: cov.UncoveredReason,
	}
	if cov.ResolvedObject != nil {
		out.ResolvedObject = cov.ResolvedObject.CanonicalName()
	}
	for _, r := range cov.CoveringRules {
		out.CoveringRules = append(out.CoveringRules, RuleReport{
			RuleName: r.RuleName,
			Verb:     r.Verb.String(),
			Selector: r.Selector,
		})
		if out.Selector == "" {
			out.Selector = r.Selector
		}
	}
	return out
}

func objectName(o effects.ObjectRef) string {
	switch o.Kind {
	case effects.ObjectExternalEndpoint:
		return o.Host
	case effects.ObjectFilesystemPath:
		return o.Path
	case effects.ObjectProgram:
		return o.Argv0
	default:
		if o.Schema == "" {
			return o.Name
		}
		return o.Schema + "." + o.Name
	}
}
```

- [ ] **Step 10: Run policyexplain tests**

Run:

```bash
go test ./internal/db/policyexplain -count=1
```

Expected: PASS.

- [ ] **Step 11: Run Windows build for the new package path**

Run:

```bash
GOOS=windows go build ./internal/db/policyexplain
```

Expected: PASS. This confirms the package did not import Linux-only proxy runtime files.

- [ ] **Step 12: Commit Task 4**

Run:

```bash
git add internal/db/policyexplain
git commit -m "db/policyexplain: add offline explain runner"
```

---

## Task 5: Wire `agentsh policy db explain` And DB Warnings

**Files:**
- Modify: `internal/cli/policy_cmd.go`
- Create: `internal/cli/policy_db_explain_test.go`
- Modify: `internal/cli/policy_config_test.go`
- Modify: `internal/api/db_proxy.go`

- [ ] **Step 1: Write CLI tests**

Create `internal/cli/policy_db_explain_test.go`.

```go
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyDBExplainJSONWithSQLFlag(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	fixturePath := filepath.Join(dir, "catalog.yaml")
	writeFile(t, policyPath, `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: x:1
    tls_mode: terminate_reissue
database_rules:
  - name: canonical-read
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: allow
`)
	writeFile(t, fixturePath, `search_path: [public]
relations:
  - oid: 16384
    schema: public
    name: users
    kind: table
`)

	root := NewRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"policy", "db", "explain", policyPath, "--service", "appdb", "--catalog-fixture", fixturePath, "--sql", "SELECT * FROM users"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	body := out.String()
	if !strings.Contains(body, `"verb": "allow"`) {
		t.Fatalf("missing allow decision:\n%s", body)
	}
	if !strings.Contains(body, `"rule_name": "canonical-read"`) {
		t.Fatalf("missing rule name:\n%s", body)
	}
	if !strings.Contains(body, `"resolved_object": "public.users"`) {
		t.Fatalf("missing resolved object:\n%s", body)
	}
}

func TestPolicyDBExplainTextFromStdin(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.yaml")
	writeFile(t, policyPath, `version: 1
name: t
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: x:1
    tls_mode: terminate_reissue
database_rules:
  - {name: read-all, db_service: appdb, operations: [READ], decision: allow}
`)
	root := NewRoot("test")
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetIn(strings.NewReader("SELECT 1"))
	root.SetArgs([]string{"policy", "db", "explain", policyPath, "--service", "appdb", "--output", "text"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute: %v\n%s", err, out.String())
	}
	body := out.String()
	if !strings.Contains(body, "decision: allow") || !strings.Contains(body, "rule: read-all") {
		t.Fatalf("unexpected text output:\n%s", body)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
```

- [ ] **Step 2: Run CLI explain tests and verify they fail**

Run:

```bash
go test ./internal/cli -run TestPolicyDBExplain -count=1
```

Expected: FAIL because the command is not wired.

- [ ] **Step 3: Add DB policy command wiring**

Update imports in `internal/cli/policy_cmd.go`:

```go
import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/policyexplain"
	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/policygen"
	"github.com/agentsh/agentsh/internal/policy/signing"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/spf13/cobra"
)
```

Add this command registration before `return cmd` in `newPolicyCmd`:

```go
cmd.AddCommand(newPolicyDBCmd(configPath, dir))
```

Add helpers near the bottom of `policy_cmd.go`.

```go
func newPolicyDBCmd(configPath, dir string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "db",
		Short: "Inspect database policy behavior",
	}
	cmd.AddCommand(newPolicyDBExplainCmd(configPath, dir))
	return cmd
}

func newPolicyDBExplainCmd(configPath, dir string) *cobra.Command {
	var serviceName string
	var dialect string
	var searchPath string
	var tempTables string
	var catalogFixture string
	var sqlFlag string
	var output string

	cmd := &cobra.Command{
		Use:   "explain POLICY_OR_PATH",
		Short: "Explain DB policy classification, resolution, coverage, and decision",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(serviceName) == "" {
				return fmt.Errorf("--service is required")
			}
			pdir, err := resolvePolicyDir(configPath, dir)
			if err != nil {
				return err
			}
			policyPath, err := resolvePolicyPath(pdir, args[0])
			if err != nil {
				return err
			}
			rootPolicy, err := policy.LoadFromFile(policyPath)
			if err != nil {
				return err
			}
			rs, warns, err := dbpolicy.Decode(rootPolicy)
			if err != nil {
				return err
			}
			sqlText := sqlFlag
			if sqlText == "" {
				raw, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return err
				}
				sqlText = string(raw)
			}
			if strings.TrimSpace(sqlText) == "" {
				return fmt.Errorf("SQL is required via --sql or stdin")
			}
			if dialect == "" {
				if svc, ok := rs.Service(dbpolicy.ServiceID(serviceName)); ok && svc.Dialect != "" {
					dialect = svc.Dialect
				} else {
					dialect = "postgres"
				}
			}
			report, err := policyexplain.Run(rs, warns, policyexplain.Options{
				SQL:            sqlText,
				Service:        dbpolicy.ServiceID(serviceName),
				Dialect:        dialect,
				SearchPath:     splitCSV(searchPath),
				TempTables:      splitCSV(tempTables),
				CatalogFixture: catalogFixture,
			})
			if err != nil {
				return err
			}
			switch output {
			case "", "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			case "text":
				return printDBExplainText(cmd, report)
			default:
				return fmt.Errorf("--output must be json or text")
			}
		},
	}
	cmd.Flags().StringVar(&serviceName, "service", "", "DB service name (required)")
	cmd.Flags().StringVar(&dialect, "dialect", "", "postgres|aurora_postgres|cockroachdb|redshift")
	cmd.Flags().StringVar(&searchPath, "search-path", "", "comma-separated search path")
	cmd.Flags().StringVar(&tempTables, "temp-tables", "", "comma-separated temp table names")
	cmd.Flags().StringVar(&catalogFixture, "catalog-fixture", "", "YAML catalog fixture path")
	cmd.Flags().StringVar(&sqlFlag, "sql", "", "SQL statement text (default: stdin)")
	cmd.Flags().StringVar(&output, "output", "json", "json|text")
	return cmd
}
```

- [ ] **Step 4: Add CLI formatting helpers**

Add to `policy_cmd.go`.

```go
func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		p := strings.TrimSpace(part)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printDBExplainText(cmd *cobra.Command, report policyexplain.Report) error {
	for _, stmt := range report.Statements {
		fmt.Fprintf(cmd.OutOrStdout(), "statement %d: %s\n", stmt.Index, stmt.RawVerb)
		fmt.Fprintf(cmd.OutOrStdout(), "decision: %s\n", stmt.Decision.Verb)
		if stmt.Decision.RuleName != "" {
			fmt.Fprintf(cmd.OutOrStdout(), "rule: %s\n", stmt.Decision.RuleName)
		}
		for _, eff := range stmt.Effects {
			fmt.Fprintf(cmd.OutOrStdout(), "effect %d: %s resolution=%s\n", eff.Index, eff.Operation, eff.Resolution)
			for _, cov := range eff.Coverage {
				if cov.Covered {
					fmt.Fprintf(cmd.OutOrStdout(), "  covered: %s selector=%s\n", cov.Object, cov.Selector)
				} else {
					fmt.Fprintf(cmd.OutOrStdout(), "  uncovered: %s reason=%s\n", cov.Object, cov.UncoveredReason)
				}
			}
		}
	}
	if len(report.Warnings) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "warnings:")
		for _, w := range report.Warnings {
			fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s\n", w.Code, w.Message)
		}
	}
	return nil
}
```

- [ ] **Step 5: Surface DB warnings in `policy validate`**

In the existing `validate` subcommand, after `policy.NewEngine`, add:

```go
if _, warns, err := dbpolicy.Decode(po); err != nil {
	return err
} else {
	for _, w := range warns {
		fmt.Fprintf(cmd.ErrOrStderr(), "warning[%s]", w.Code)
		if w.Rule != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), " rule=%s", w.Rule)
		}
		if w.Field != "" {
			fmt.Fprintf(cmd.ErrOrStderr(), " field=%s", w.Field)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), ": %s\n", w.Message)
	}
}
```

- [ ] **Step 6: Surface DB warnings during session policy compilation**

Update `internal/api/db_proxy.go` so `loadDBRuleSet` returns warnings:

```go
func loadDBRuleSet(p *rootpolicy.Policy) (*dbpolicy.RuleSet, []dbpolicy.Warning, error) {
	if p == nil {
		return nil, nil, nil
	}
	rs, warns, err := dbpolicy.Decode(p)
	if err != nil {
		return nil, warns, fmt.Errorf("loadDBRuleSet: decode db policy: %w", err)
	}
	return rs, warns, nil
}
```

Update the caller in `internal/api/db_unavoidability.go`:

```go
rs, warns, err := loadDBRuleSet(base)
if err != nil {
	return nil, nil, "", err
}
for _, w := range warns {
	slog.Warn("db policy warning", "code", w.Code, "rule", w.Rule, "field", w.Field, "message", w.Message)
}
```

`internal/api/db_unavoidability.go` already imports `log/slog`; keep that
import and use the package-level logger shown above.

- [ ] **Step 7: Run CLI tests**

Run:

```bash
go test ./internal/cli -run 'TestPolicyDBExplain|TestRoot_WiresPolicyAndConfig' -count=1
```

Expected: PASS.

- [ ] **Step 8: Run API compile tests for changed signature**

Run:

```bash
go test ./internal/api -count=1
```

Expected: PASS.

- [ ] **Step 9: Commit Task 5**

Run:

```bash
git add internal/cli internal/api
git commit -m "cli: add db policy explain"
```

---

## Task 6: Update Samples, Docs, And Final Verification

**Files:**
- Modify: `internal/db/policy/testdata/sample-policy.yaml`
- Modify: `internal/db/policy/sample_test.go`
- Modify: `docs/agentsh-db-access-spec.md`
- Modify: `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`

- [ ] **Step 1: Add sample canonical policies**

Modify `internal/db/policy/testdata/sample-policy.yaml` by adding these rules after `app-read-and-update`.

```yaml
  - name: app-read-users-canonical
    db_service: appdb
    operations: [READ]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: allow

  - name: app-safe-functions-canonical
    db_service: appdb
    operations: [procedural]
    functions: ["public.safe_fn(*)"]
    match_object_resolution: catalog_resolved
    decision: approve
```

- [ ] **Step 2: Run sample tests**

`internal/db/policy/sample_test.go` currently checks worked examples only, so no
test change is required for the new sample rules.

Run:

```bash
go test ./internal/db/policy -run TestSample -count=1
```

Expected: PASS.

- [ ] **Step 3: Document new rule fields in the DB access spec**

In `docs/agentsh-db-access-spec.md`, update the statement-rule field table with these rows near `objects` and `schemas`:

```markdown
| `relations` | no | Glob list. Matches catalog-resolved relation canonical names formatted as `schema.name`. A selector only matches when the effect contains a successful catalog `resolved_objects[]` relation. Recommended with `match_object_resolution: catalog_resolved`. |
| `functions` | no | Glob list. Matches catalog-resolved function identities formatted as `schema.name(identity_args)`. Use `schema.name(*)` to match all overloads for a function name. Recommended with `match_object_resolution: catalog_resolved`. |
```

Update the `schemas` row to:

```markdown
| `schemas` | no | Glob. Matches `objects[].schema` for syntactic refs and successful `resolved_objects[].schema` for catalog-resolved refs. |
```

Add this paragraph after the field table:

```markdown
`objects` remains syntactic-only. `relations` and `functions` are catalog selectors and do not match unresolved or unavailable catalog metadata. Strict object coverage still applies: every object slot in an effect must be covered by an allow/audit/approve rule, and any matching deny rule still wins.
```

- [ ] **Step 4: Document offline explain command**

Add this subsection near the DB policy authoring documentation in `docs/agentsh-db-access-spec.md`.

````markdown
### DB policy explain

Operators can inspect DB policy behavior offline:

```bash
agentsh policy db explain ./policy.yaml --service appdb --sql 'SELECT * FROM users'
```

The command reports classifier effects, syntactic objects, catalog-resolved objects when a fixture is supplied, per-object coverage, policy warnings, and the final decision. Catalog fixtures are YAML snapshots used for local debugging; they are not live DB connections and are not used by the proxy runtime.
````

- [ ] **Step 5: Update Phase 2 roadmap status**

In `docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md`, change the Plan 10 external behavior paragraph from future wording to implementation-ready wording:

```markdown
External behavior: policy authoring and debugging improve; default enforcement semantics remain strict. Plan 10 is implemented and ready for DB Plan 11 redirect planner work.
```

Only make this wording change after code and tests in Tasks 1-5 pass.

- [ ] **Step 6: Run focused DB and CLI tests**

Run:

```bash
go test ./internal/db/policy ./internal/db/policyexplain ./internal/cli -count=1
```

Expected: PASS.

- [ ] **Step 7: Run full verification**

Run:

```bash
go test ./...
```

Expected: PASS.

Then run:

```bash
GOOS=windows go build ./...
```

Expected: PASS.

Then run:

```bash
git diff --check
```

Expected: no output and exit code 0.

- [ ] **Step 8: Commit Task 6**

Run:

```bash
git add internal/db/policy/testdata/sample-policy.yaml internal/db/policy/sample_test.go docs/agentsh-db-access-spec.md docs/superpowers/specs/2026-05-14-db-phase-2-roadmap-design.md
git commit -m "docs: explain db policy ergonomics"
```

When staging, include `internal/db/policy/sample_test.go` only if the file has
local modifications.

---

## Final Checklist

- [ ] `go test ./internal/db/policy ./internal/db/policyexplain ./internal/cli -count=1` passes.
- [ ] `go test ./...` passes.
- [ ] `GOOS=windows go build ./...` passes.
- [ ] `git diff --check` passes.
- [ ] `agentsh policy db explain` works with `--sql` and stdin.
- [ ] Canonical selectors only match successful catalog-resolved objects.
- [ ] Existing syntactic policies keep the same decisions.
- [ ] DB warning codes are visible in `policy validate`.
