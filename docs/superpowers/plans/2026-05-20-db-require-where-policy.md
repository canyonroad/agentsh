# DB Require WHERE Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `require_where: true` database statement-rule guard that allows Postgres `UPDATE` and `DELETE` mutation effects only when the top-level statement has a syntactic `WHERE` clause.

**Architecture:** Capture top-level `WHERE` presence on the mutation `effects.Effect`, compile `require_where` into statement rules, and let the existing policy coverage model fail closed when a guarded rule does not match. Keep the feature Postgres-only and limited to `modify` and `delete` operation groups in v1.

**Tech Stack:** Go, `github.com/pganalyze/pg_query_go/v5`, existing AgentSH DB classifier, DB policy evaluator, Postgres proxy tests, YAML policy config.

---

## File Structure

- `internal/db/effects/effect.go`: add `HasWhere bool` observed-shape metadata to `Effect`.
- `internal/db/effects/statement_test.go`: add JSON tests proving `has_where` is emitted only when true.
- `internal/db/classify/postgres/ast_dml.go`: set `HasWhere` on primary `UPDATE` and `DELETE` effects.
- `internal/db/classify/postgres/ast_dml_test.go`: add classifier tests for with-WHERE and no-WHERE `UPDATE`/`DELETE`.
- `internal/db/policy/types.go`: add `RequireWhere bool` to `StatementRule`.
- `internal/db/policy/compile.go`: add `requireWhere` to `compiledStatementRule` and copy it from `StatementRule`.
- `internal/db/policy/validate.go`: reject `require_where` unless the expanded operation groups are exactly a subset of `modify` and `delete`.
- `internal/db/policy/validate_test.go`: add validation accept/reject coverage.
- `internal/db/policy/evaluate.go`: make `ruleMatchesEffectMeta` require `e.HasWhere` when compiled `requireWhere` is true.
- `internal/db/policy/evaluate_require_where_test.go`: add focused evaluator tests for allow and implicit-deny behavior.
- `internal/db/proxy/postgres/simplequery_test.go`: add a simple-query regression proving no-WHERE mutations are denied before forwarding.
- `docs/agentsh-db-access-spec.md`: document the statement-rule field and semantics.
- `docs/operations/policies.md`: add an operator example.
- `skills/agentsh-policy-shared/schema-reference.md`: add the field to the policy skill schema reference.
- `skills/agentsh-policy-create/SKILL.md`: mention the guard during DB policy creation.
- `skills/agentsh-policy-edit/SKILL.md`: mention the guard during DB policy edits.

### Task 1: Record WHERE Presence In Classified Effects

**Files:**
- Modify: `internal/db/effects/effect.go`
- Modify: `internal/db/effects/statement_test.go`
- Modify: `internal/db/classify/postgres/ast_dml.go`
- Modify: `internal/db/classify/postgres/ast_dml_test.go`

- [ ] **Step 1: Write failing JSON tests for `Effect.HasWhere`**

Append these tests to `internal/db/effects/statement_test.go`:

```go
func TestEffect_HasWhere_JSON(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupModify, HasWhere: true}},
		RawVerb: "UPDATE",
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"has_where":true`) {
		t.Fatalf("has_where missing: %s", bs)
	}
}

func TestEffect_HasWhere_OmitFalse(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupModify}},
		RawVerb: "UPDATE",
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if strings.Contains(string(bs), "has_where") {
		t.Fatalf("has_where should be omitted when false: %s", bs)
	}
}
```

- [ ] **Step 2: Run the JSON tests and verify they fail**

Run:

```bash
go test ./internal/db/effects -run 'TestEffect_HasWhere' -count=1
```

Expected: fail with an output containing `has_where missing`.

- [ ] **Step 3: Add `HasWhere` to `effects.Effect`**

In `internal/db/effects/effect.go`, update `Effect`:

```go
type Effect struct {
	Group           Group
	Subtype         Subtype
	Objects         []ObjectRef
	ResolvedObjects []ResolvedObjectRef `json:"resolved_objects,omitempty"`
	Resolution      Resolution

	// HasWhere is observed statement-shape metadata. It is set only on
	// mutation effects whose owning statement has a top-level WHERE clause.
	HasWhere bool `json:"has_where,omitempty"`

	// FunctionOID is populated for procedural effects with Subtype
	// SubtypeFunctionCallProtocol (the Postgres 'F' FunctionCall frame) or
	// SubtypeEscalatedFunctionCall (when classifier escalation produced
	// the effect). Pointer so JSON omits zero.
	FunctionOID *int32 `json:"function_oid,omitempty"`
}
```

- [ ] **Step 4: Run the JSON tests and verify they pass**

Run:

```bash
go test ./internal/db/effects -run 'TestEffect_HasWhere' -count=1
```

Expected: pass.

- [ ] **Step 5: Write failing classifier tests**

Add these tests to `internal/db/classify/postgres/ast_dml_test.go` near the existing update/delete smoke tests:

```go
func TestClassifyUpdate_HasWhere(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false WHERE id = 1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupModify {
		t.Fatalf("primary group: got %v want modify", prim.Group)
	}
	if !prim.HasWhere {
		t.Fatalf("UPDATE with WHERE should set HasWhere on primary effect: %+v", prim)
	}
}

func TestClassifyUpdate_NoWhere(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupModify {
		t.Fatalf("primary group: got %v want modify", prim.Group)
	}
	if prim.HasWhere {
		t.Fatalf("UPDATE without WHERE should not set HasWhere: %+v", prim)
	}
}

func TestClassifyUpdate_HasWhereOnlyOnModifyEffect(t *testing.T) {
	cs := classifyOne(t, "UPDATE users SET active = false FROM logins WHERE users.id = logins.user_id", SessionState{})
	if len(cs.Effects) != 2 {
		t.Fatalf("effects count: got %d want 2: %+v", len(cs.Effects), cs.Effects)
	}
	if !cs.Effects[0].HasWhere {
		t.Fatalf("primary modify effect should have HasWhere: %+v", cs.Effects[0])
	}
	if cs.Effects[1].Group != effects.GroupRead {
		t.Fatalf("secondary effect group = %v want read", cs.Effects[1].Group)
	}
	if cs.Effects[1].HasWhere {
		t.Fatalf("secondary read effect should not inherit HasWhere: %+v", cs.Effects[1])
	}
}

func TestClassifyDelete_HasWhere(t *testing.T) {
	cs := classifyOne(t, "DELETE FROM users WHERE id = 1", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete", prim.Group)
	}
	if !prim.HasWhere {
		t.Fatalf("DELETE with WHERE should set HasWhere on primary effect: %+v", prim)
	}
}

func TestClassifyDelete_NoWhere(t *testing.T) {
	cs := classifyOne(t, "DELETE FROM users", SessionState{})
	prim, _ := cs.Primary()
	if prim.Group != effects.GroupDelete {
		t.Fatalf("primary group: got %v want delete", prim.Group)
	}
	if prim.HasWhere {
		t.Fatalf("DELETE without WHERE should not set HasWhere: %+v", prim)
	}
}
```

- [ ] **Step 6: Run the classifier tests and verify they fail**

Run:

```bash
go test ./internal/db/classify/postgres -run 'TestClassify(Update|Delete)_(HasWhere|NoWhere|HasWhereOnlyOnModifyEffect)' -count=1
```

Expected: fail because `HasWhere` is false for the with-WHERE cases.

- [ ] **Step 7: Set `HasWhere` in update/delete classification**

In `internal/db/classify/postgres/ast_dml.go`, update the primary effects in `classifyUpdate` and `classifyDelete`:

```go
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupModify,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
		HasWhere:   s.WhereClause != nil,
	})
```

```go
	cs.Effects = append(cs.Effects, effects.Effect{
		Group:      effects.GroupDelete,
		Objects:    []effects.ObjectRef{tgt},
		Resolution: tgtRes,
		HasWhere:   s.WhereClause != nil,
	})
```

- [ ] **Step 8: Run task tests**

Run:

```bash
go test ./internal/db/effects ./internal/db/classify/postgres -run 'TestEffect_HasWhere|TestClassify(Update|Delete)_(HasWhere|NoWhere|HasWhereOnlyOnModifyEffect)' -count=1
```

Expected: pass.

- [ ] **Step 9: Commit Task 1**

```bash
git add internal/db/effects/effect.go internal/db/effects/statement_test.go internal/db/classify/postgres/ast_dml.go internal/db/classify/postgres/ast_dml_test.go
git commit -m "Track WHERE presence on DB mutation effects"
```

### Task 2: Add Policy Validation And Evaluator Support

**Files:**
- Modify: `internal/db/policy/types.go`
- Modify: `internal/db/policy/compile.go`
- Modify: `internal/db/policy/validate.go`
- Modify: `internal/db/policy/validate_test.go`
- Modify: `internal/db/policy/evaluate.go`
- Create: `internal/db/policy/evaluate_require_where_test.go`

- [ ] **Step 1: Write failing validation tests**

Append to `internal/db/policy/validate_test.go`:

```go
func TestValidate_RequireWhereAllowsModifyAndDeleteOnly(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	cases := []struct {
		name string
		ops  []string
	}{
		{name: "modify", ops: []string{"modify"}},
		{name: "delete", ops: []string{"delete"}},
		{name: "modify_delete", ops: []string{"modify", "delete"}},
		{name: "UPDATE_alias", ops: []string{"UPDATE"}},
		{name: "DELETE_alias", ops: []string{"DELETE"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt := []*StatementRule{{
				Name:         "guarded",
				DBService:    "appdb",
				Operations:   tc.ops,
				Decision:     "allow",
				RequireWhere: true,
			}}
			if _, err := helperValidate(t, svcs, stmt, nil); err != nil {
				t.Fatalf("validate: %v", err)
			}
		})
	}
}

func TestValidate_RequireWhereRejectsUnsupportedOperations(t *testing.T) {
	svcs := map[ServiceID]*DBService{
		"appdb": {Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "x:1", TLSMode: "terminate_reissue"},
	}
	cases := []struct {
		name string
		ops  []string
	}{
		{name: "read", ops: []string{"read"}},
		{name: "star", ops: []string{"*"}},
		{name: "read_delete", ops: []string{"read", "delete"}},
		{name: "MUTATE_includes_write", ops: []string{"MUTATE"}},
		{name: "transaction", ops: []string{"transaction"}},
		{name: "schema_destroy", ops: []string{"schema_destroy"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stmt := []*StatementRule{{
				Name:         "guarded",
				DBService:    "appdb",
				Operations:   tc.ops,
				Decision:     "allow",
				RequireWhere: true,
			}}
			_, err := helperValidate(t, svcs, stmt, nil)
			if err == nil || !strings.Contains(err.Error(), "rule_require_where_invalid_operation") {
				t.Fatalf("want rule_require_where_invalid_operation, got %v", err)
			}
		})
	}
}
```

- [ ] **Step 2: Run validation tests and verify they fail to compile**

Run:

```bash
go test ./internal/db/policy -run 'TestValidate_RequireWhere' -count=1
```

Expected: fail to compile because `StatementRule.RequireWhere` does not exist.

- [ ] **Step 3: Add the YAML field and validation helper**

In `internal/db/policy/types.go`, add `RequireWhere` near `MatchObjectResolution`:

```go
	MatchObjectResolution       string          `yaml:"match_object_resolution,omitempty"`
	RequireWhere                bool            `yaml:"require_where,omitempty"`
	Decision                    string          `yaml:"decision"`
```

In `internal/db/policy/validate.go`, add this check after `groups := expandedGroups(r)` and after unknown operation validation:

```go
	if r.RequireWhere && !groupsOnlyModifyDelete(groups) {
		errs = append(errs, fmt.Errorf("rule_require_where_invalid_operation: database_rules[%q]: require_where is supported only for modify/delete operations", r.Name))
	}
```

Add this helper near `groupsOnlyRead`:

```go
func groupsOnlyModifyDelete(groups map[effects.Group]struct{}) bool {
	if len(groups) == 0 {
		return false
	}
	for g := range groups {
		if g != effects.GroupModify && g != effects.GroupDelete {
			return false
		}
	}
	return true
}
```

- [ ] **Step 4: Run validation tests and verify they pass**

Run:

```bash
go test ./internal/db/policy -run 'TestValidate_RequireWhere' -count=1
```

Expected: pass.

- [ ] **Step 5: Write failing evaluator tests**

Create `internal/db/policy/evaluate_require_where_test.go`:

```go
package policy

import (
	"strings"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)

func mutationStmt(group effects.Group, hasWhere bool) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{
		RawVerb: "UPDATE",
		Effects: []effects.Effect{{
			Group:      group,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
			Resolution: effects.ResolutionQualified,
			HasWhere:   hasWhere,
		}},
	}
}

func TestDecode_RequireWhereAccepted(t *testing.T) {
	p, err := rootpolicy.LoadFromBytes([]byte(`version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: guarded
    db_service: appdb
    operations: [modify, delete]
    objects: [users]
    require_where: true
    decision: allow
`))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	rs, _, err := Decode(p)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	rules := rs.AllStatementRules()
	if len(rules) != 1 || !rules[0].RequireWhere {
		t.Fatalf("RequireWhere not decoded: %+v", rules)
	}
}

func TestEvaluate_RequireWhereAllowsMutationWithWhere(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: guarded
    db_service: appdb
    operations: [modify]
    objects: [users]
    require_where: true
    decision: allow
`)
	d := Evaluate(mutationStmt(effects.GroupModify, true), rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "guarded" {
		t.Fatalf("decision = %+v, want allow by guarded", d)
	}
}

func TestEvaluate_RequireWhereDeniesMutationWithoutWhere(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: guarded
    db_service: appdb
    operations: [modify]
    objects: [users]
    require_where: true
    decision: allow
`)
	d := Evaluate(mutationStmt(effects.GroupModify, false), rs, "appdb")
	if d.Verb != VerbDeny || d.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", d)
	}
	if !strings.Contains(d.Reason, "no rule covers") {
		t.Fatalf("Reason = %q, want coverage failure", d.Reason)
	}
}

func TestEvaluate_RequireWhereDoesNotBlockRuleWithoutGuard(t *testing.T) {
	rs := loadRules(t, `version: 1
name: t
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: x:1, tls_mode: terminate_reissue}
database_rules:
  - name: unguarded
    db_service: appdb
    operations: [delete]
    objects: [users]
    decision: allow
`)
	d := Evaluate(mutationStmt(effects.GroupDelete, false), rs, "appdb")
	if d.Verb != VerbAllow || d.RuleName != "unguarded" {
		t.Fatalf("decision = %+v, want allow by unguarded", d)
	}
}
```

- [ ] **Step 6: Run evaluator tests and verify the guarded no-WHERE case fails**

Run:

```bash
go test ./internal/db/policy -run 'TestDecode_RequireWhereAccepted|TestEvaluate_RequireWhere' -count=1
```

Expected: fail because `require_where` decodes but is not compiled/evaluated yet.

- [ ] **Step 7: Compile and enforce `require_where`**

In `internal/db/policy/compile.go`, update `compiledStatementRule`:

```go
type compiledStatementRule struct {
	src           *StatementRule
	verb          DecisionVerb
	groups        map[effects.Group]struct{}
	subtypes      map[effects.Subtype]struct{} // empty = all subtypes match
	requireWhere  bool
	resolution    resolutionMatcher
	schemas       []glob.Glob // empty = all schemas match
	objects       []glob.Glob // syntactic object selectors
	relations     []glob.Glob // resolved relation canonical names
	functions     []glob.Glob // resolved function identity names
	timeout       time.Duration
	msgTemplate   *template.Template // nil = no message rendering
	redirect      *RedirectDecision
	serviceFilter serviceFilter
}
```

In `compileStatementRule`, set the field in the struct literal:

```go
	c := &compiledStatementRule{
		src:           r,
		groups:        map[effects.Group]struct{}{},
		subtypes:      map[effects.Subtype]struct{}{},
		requireWhere:  r.RequireWhere,
		serviceFilter: serviceFilter{service: ServiceID(r.DBService), family: r.DBFamily, dialect: r.DBDialect},
	}
```

In `internal/db/policy/evaluate.go`, update `ruleMatchesEffectMeta`:

```go
func ruleMatchesEffectMeta(r *compiledStatementRule, e effects.Effect) bool {
	if _, ok := r.groups[e.Group]; !ok {
		return false
	}
	if r.requireWhere && !e.HasWhere {
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
```

- [ ] **Step 8: Run policy package tests**

Run:

```bash
go test ./internal/db/policy -count=1
```

Expected: pass.

- [ ] **Step 9: Commit Task 2**

```bash
git add internal/db/policy/types.go internal/db/policy/compile.go internal/db/policy/validate.go internal/db/policy/validate_test.go internal/db/policy/evaluate.go internal/db/policy/evaluate_require_where_test.go
git commit -m "Enforce require_where in DB policy rules"
```

### Task 3: Prove Proxy Enforcement Before Forwarding

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write a proxy regression test**

Add this helper and test near `denyDeletesRuleSet` in `internal/db/proxy/postgres/simplequery_test.go`:

```go
func requireWhereRuleSet(t *testing.T) *policy.RuleSet {
	t.Helper()
	return loadRuleSet(t, `version: 1
name: test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: 127.0.0.1:5432
    tls_mode: terminate_reissue
database_rules:
  - name: allow-where-updates
    db_service: test
    operations: [modify]
    objects: [users]
    require_where: true
    decision: allow
`)
}

func TestHandleQuery_RequireWhere_DeniesNoWhereBeforeForward(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.state.smState.LastUpstreamRFQ = 'I'
	pc.srv.SetPolicy(requireWhereRuleSet(t))

	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)
	upBackend := pgproto3.NewBackend(upClient, upClient)
	drainClientBackendMessages(clientFE)

	upRecv := make(chan pgproto3.FrontendMessage, 1)
	go func() {
		msg, err := upBackend.Receive()
		if err == nil {
			upRecv <- msg
		}
	}()

	done := make(chan error, 1)
	go func() {
		done <- pc.handleQuery(context.Background(), &pgproto3.Query{String: "UPDATE users SET active = false"})
	}()

	select {
	case msg := <-upRecv:
		t.Fatalf("upstream received no-WHERE mutation: %T", msg)
	case err := <-done:
		if err != nil {
			t.Fatalf("handleQuery returned transport error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatalf("handleQuery did not return")
	}

	var evs []events.DBEvent
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		evs = sink.DrainStatements()
		if len(evs) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(evs) != 1 {
		t.Fatalf("statement events = %+v", evs)
	}
	if evs[0].Decision.Verb != "deny" || evs[0].Decision.RuleName != "" {
		t.Fatalf("decision = %+v, want implicit deny", evs[0].Decision)
	}
}
```

- [ ] **Step 2: Run the proxy test**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestHandleQuery_RequireWhere_DeniesNoWhereBeforeForward -count=1
```

Expected: pass after Tasks 1 and 2.

- [ ] **Step 3: Run neighboring simple-query tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestHandleQuery_(DenyPath|RequireWhere)' -count=1
```

Expected: pass.

- [ ] **Step 4: Commit Task 3**

```bash
git add internal/db/proxy/postgres/simplequery_test.go
git commit -m "Test require_where proxy enforcement"
```

### Task 4: Document Operator Semantics And Skill Guidance

**Files:**
- Modify: `docs/agentsh-db-access-spec.md`
- Modify: `docs/operations/policies.md`
- Modify: `skills/agentsh-policy-shared/schema-reference.md`
- Modify: `skills/agentsh-policy-create/SKILL.md`
- Modify: `skills/agentsh-policy-edit/SKILL.md`

- [ ] **Step 1: Update the DB access spec field table**

In `docs/agentsh-db-access-spec.md`, add this row after `match_object_resolution`:

```markdown
| `require_where` | no | Boolean. When true, this rule covers Postgres `modify`/`delete` effects only if the top-level `UPDATE` or `DELETE` statement has a syntactic `WHERE` clause. Valid only when `operations` expands exclusively to `modify` and/or `delete`. |
```

After the paragraph beginning `` `objects` remains syntactic-only. ``, add:

```markdown
`require_where: true` is a syntactic mutation guard for Postgres `UPDATE` and `DELETE`. It does not prove predicate selectivity; `WHERE true` satisfies the guard. Operators who need tenant, primary-key, or row-count constraints must enforce those separately with database-native controls or a future predicate-aware policy feature.
```

- [ ] **Step 2: Update the skill schema reference**

In `skills/agentsh-policy-shared/schema-reference.md`, add this row after `match_object_resolution`:

```markdown
| require_where | bool | no | For Postgres `modify`/`delete` rules only: require the top-level `UPDATE` or `DELETE` statement to include a syntactic `WHERE` clause |
```

After the alias paragraph that starts `Uppercase aliases are also supported`, add:

```markdown
`require_where: true` is valid only when `operations` expands exclusively to `modify` and/or `delete`; `MUTATE` is rejected because it also includes `write`. The guard is syntactic only, so `WHERE true` satisfies it.
```

- [ ] **Step 3: Add an operator example**

In `docs/operations/policies.md`, add this example in the database policy section:

````markdown
### Require WHERE For Sensitive Mutations

Use `require_where: true` on narrow mutation rules when accidental full-table updates or deletes are the main risk:

```yaml
database_rules:
  - name: allow-scoped-user-mutations
    db_service: appdb
    operations: [modify, delete]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    require_where: true
    decision: allow
```

This allows `UPDATE public.users SET disabled = true WHERE id = 123` when the relation selector matches, but it does not cover `UPDATE public.users SET disabled = true`. The guard checks only that a top-level `WHERE` exists; it does not prove the predicate is selective or tenant-safe.
````

- [ ] **Step 4: Update policy creation guidance**

In `skills/agentsh-policy-create/SKILL.md`, add this bullet in the DB policy authoring guidance:

```markdown
- For Postgres `UPDATE`/`DELETE` access to sensitive relations, ask whether accidental full-table mutation should be blocked. Use `require_where: true` only on rules whose `operations` expand exclusively to `modify` and/or `delete`; explain that it is syntactic and `WHERE true` still satisfies it.
```

- [ ] **Step 5: Update policy edit guidance**

In `skills/agentsh-policy-edit/SKILL.md`, add this bullet in the DB rule editing guidance:

```markdown
- When editing mutation allow/approve/audit rules, preserve or add `require_where: true` for sensitive Postgres `modify`/`delete` rules when the operator wants no-WHERE mutations to fail closed. Do not add it to `MUTATE`, `*`, `read`, DDL, session, transaction, or procedural rules.
```

- [ ] **Step 6: Run docs/skill checks**

Run:

```bash
python3 /home/eran/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/agentsh-policy-create
python3 /home/eran/.codex/skills/.system/skill-creator/scripts/quick_validate.py skills/agentsh-policy-edit
```

Expected: both pass.

- [ ] **Step 7: Commit Task 4**

```bash
git add docs/agentsh-db-access-spec.md docs/operations/policies.md skills/agentsh-policy-shared/schema-reference.md skills/agentsh-policy-create/SKILL.md skills/agentsh-policy-edit/SKILL.md
git commit -m "Document require_where DB policy guard"
```

### Task 5: Final Verification

**Files:**
- No source changes.

- [ ] **Step 1: Run focused package tests**

Run:

```bash
go test ./internal/db/effects ./internal/db/classify/postgres ./internal/db/policy ./internal/db/proxy/postgres -count=1
```

Expected: pass.

- [ ] **Step 2: Run DB service regression tests**

Run:

```bash
go test ./internal/db/service ./internal/db/effects ./internal/db/policy -count=1
```

Expected: pass.

- [ ] **Step 3: Verify Windows compilation**

Run:

```bash
GOOS=windows go build ./...
```

Expected: pass.

- [ ] **Step 4: Check staged cleanliness**

Run:

```bash
git status --short
git diff --check
```

Expected: only unrelated pre-existing dirty files may remain; no whitespace errors.

- [ ] **Step 5: Summarize implemented behavior**

Report these points:

```text
- require_where is decoded on database_rules and validated for modify/delete-only operation sets.
- Postgres UPDATE/DELETE classification records top-level WHERE presence on the primary mutation effect.
- Rules with require_where do not cover no-WHERE mutation effects, so existing implicit deny behavior blocks them.
- Proxy simple-query tests prove no-WHERE mutations are denied before upstream forwarding.
- Docs and policy skills describe the syntactic-only limitation.
```
