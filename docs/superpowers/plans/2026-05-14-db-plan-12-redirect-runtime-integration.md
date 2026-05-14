# DB Plan 12 Redirect Runtime Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire DB Plan 11 redirect plans into the Postgres proxy runtime for Simple Query and Extended Query `Parse`, with prepared-cache metadata, audit fields, fail-closed behavior, and real Postgres integration coverage.

**Architecture:** Keep SQL rewrite logic in the Plan 11 redirect planner. Add a small Linux-only proxy runtime adapter that converts policy decisions plus classified/resolved statements into local redirect runtime plans. Simple Query forwards rewritten `Query` frames; Extended Query redirects only at `Parse`, caches rewritten metadata under the original client prepared statement name, preserves it through `Bind` portal cache copies, and emits redirect audit fields for redirected execution.

**Tech Stack:** Go, `pgproto3`, `pgx/v5`, existing Postgres classifier/catalog/policy/proxy packages, existing `internal/integration` Docker-backed real Postgres harness.

---

## Dependency Gate

This plan depends on DB Plan 11. Execute it only on a branch where the Plan 11 redirect planner contract is present.

Required Plan 11 capabilities:

- Policy decode accepts statement `decision: redirect`.
- Policy evaluation can return a redirect decision without treating it as deny.
- A planner package exists that accepts a resolved read-only statement plus redirect action and returns rewritten SQL, source relation, target relation, redirect rule id/name, and rejection reason.
- The planner rejects writes, DDL, COPY, FunctionCall, unresolved objects, missing target relations, and multi-statement inputs.

Do not implement planner logic in Plan 12. If this gate fails, stop and implement or merge DB Plan 11 first.

---

## File Structure

- Modify `internal/db/events/event.go`: add redirect audit fields to `events.DBEvent`.
- Modify `internal/db/events/event_test.go`: add redirect JSON round-trip coverage.
- Modify `internal/db/proxy/postgres/eventbuilder.go`: add redirect inputs to `buildArgs`, compute rewritten digest, and populate DBEvent redirect fields.
- Modify `internal/db/proxy/postgres/eventbuilder_test.go`: cover original digest preservation and rewritten digest population.
- Modify `internal/db/proxy/postgres/preparedcache/cache.go`: add redirect metadata to prepared-cache entries.
- Modify `internal/db/proxy/postgres/preparedcache/cache_test.go`: cover metadata round-trip and replacement.
- Create `internal/db/proxy/postgres/redirect_runtime.go`: isolate the runtime adapter around the Plan 11 planner contract, digest helpers, and fail-closed redirect event helpers.
- Create `internal/db/proxy/postgres/redirect_runtime_test.go`: unit-test adapter validation without touching the planner internals.
- Modify `internal/db/proxy/postgres/simplequery.go`: redirect Simple Query before the allow path, forward rewritten SQL, and fail closed on runtime rejection.
- Modify `internal/db/proxy/postgres/simplequery_test.go`: unit-test rewritten forwarding, deny precedence, fail-closed no-forward, and event fields.
- Modify `internal/db/proxy/postgres/extquery.go`: handle redirected `Parse`, preserve full redirect metadata through `Bind`, queue redirected `Execute` audit entries, and emit them after `Sync` drain.
- Modify `internal/db/proxy/postgres/extquery_spine_test.go`: unit-test redirected Parse forwarding, named prepared statement cache metadata, Bind/Execute no re-planning, and Parse fail-closed behavior.
- Create `internal/db/proxy/postgres/redirect_integration_test.go`: direct-proxy real Postgres redirect tests for policy reload on an open connection.
- Modify `internal/integration/db07cclient/main.go`: add helper modes for repeated prepared execution and policy reload probes.
- Modify `internal/integration/db_postgres_07c_test.go`: add DB Plan 12 real Postgres redirect tests.

---

## Task 0: Verify Plan 11 Is Present

**Files:**
- Read: `internal/db/policy/types.go`
- Read: `internal/db/policy/validate.go`
- Read: Plan 11 planner package path from the branch under test
- No code changes

- [ ] **Step 1: Verify policy redirect support exists**

Run:

```bash
rg -n "VerbRedirect|redirect" internal/db/policy
```

Expected: output includes a redirect decision verb or equivalent Plan 11 redirect action support. `internal/db/policy/validate.go` must not still reject statement `decision: redirect` with `redirect_not_supported_until_plan_11`.

- [ ] **Step 2: Verify planner package exists**

Run:

```bash
rg -n "type .*Plan|type .*Planner|RewrittenSQL|RejectionReason|TargetRelation" internal/db
```

Expected: output includes the Plan 11 redirect planner package and a result type carrying rewritten SQL, redirect rule, source relation, target relation, and rejection reason.

- [ ] **Step 3: Stop if the gate fails**

If Step 1 or Step 2 fails, do not continue with Plan 12. Finish DB Plan 11 first, then restart this plan from Task 1.

No commit for this task.

---

## Task 1: Add Redirect Audit Fields

**Files:**
- Modify: `internal/db/events/event.go`
- Modify: `internal/db/events/event_test.go`

- [ ] **Step 1: Write failing DBEvent JSON test**

Add this test to `internal/db/events/event_test.go`.

```go
func TestDBEvent_RedirectMetadataRoundTrip(t *testing.T) {
	in := DBEvent{
		EventID:                  "db-redirect-1",
		SessionID:                "sess-1",
		Timestamp:                time.Date(2026, 5, 14, 13, 0, 0, 0, time.UTC),
		DBService:                "appdb",
		DBFamily:                 "postgres",
		DBDialect:                "postgres",
		StatementDigest:          "sha256:original",
		RewrittenStatementDigest: "sha256:rewritten",
		Redirected:               true,
		RedirectRule:             "redirect-users-to-safe-users",
		RedirectSourceRelation:   "public.users",
		RedirectTargetRelation:   "public.safe_users",
		RedirectRuntimeStatus:    "executed",
		StatementRedaction:       RedactionParametersRedacted,
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	s := string(raw)
	for _, want := range []string{
		`"redirected":true`,
		`"redirect_rule":"redirect-users-to-safe-users"`,
		`"rewritten_statement_digest":"sha256:rewritten"`,
		`"redirect_source_relation":"public.users"`,
		`"redirect_target_relation":"public.safe_users"`,
		`"redirect_runtime_status":"executed"`,
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("json %s missing %s", s, want)
		}
	}

	var out DBEvent
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !out.Redirected || out.RedirectRule != in.RedirectRule || out.RewrittenStatementDigest != in.RewrittenStatementDigest {
		t.Fatalf("redirect fields lost: %+v", out)
	}
	if out.StatementDigest != "sha256:original" {
		t.Fatalf("StatementDigest = %q, want original digest", out.StatementDigest)
	}
}

func TestDBEvent_RedirectRejectionRoundTrip(t *testing.T) {
	in := DBEvent{
		EventID:                  "db-redirect-reject-1",
		SessionID:                "sess-1",
		Timestamp:                time.Date(2026, 5, 14, 13, 1, 0, 0, time.UTC),
		DBService:                "appdb",
		DBFamily:                 "postgres",
		DBDialect:                "postgres",
		StatementDigest:          "sha256:original",
		Redirected:               true,
		RedirectRule:             "redirect-users-to-safe-users",
		RedirectSourceRelation:   "public.users",
		RedirectTargetRelation:   "public.safe_users",
		RedirectRuntimeStatus:    "rejected",
		RedirectRejectionReason:  "unsupported_statement",
		StatementRedaction:       RedactionParametersRedacted,
		Result:                   EventResult{ErrorCode: "0A000"},
		TxContext:                EventTxContext{DenyAction: "none"},
	}

	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out DBEvent
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.RedirectRuntimeStatus != "rejected" || out.RedirectRejectionReason != "unsupported_statement" {
		t.Fatalf("redirect rejection fields lost: %+v", out)
	}
}
```

- [ ] **Step 2: Run the failing event tests**

Run:

```bash
go test ./internal/db/events -run 'TestDBEvent_Redirect.*RoundTrip' -count=1
```

Expected: FAIL because redirect fields do not exist on `DBEvent`.

- [ ] **Step 3: Add fields to DBEvent**

In `internal/db/events/event.go`, add these fields immediately after the statement fields.

```go
	StatementDigest    string    `json:"statement_digest,omitempty"`
	StatementText      string    `json:"statement_text,omitempty"`
	StatementRedaction Redaction `json:"statement_redaction"`

	Redirected               bool   `json:"redirected,omitempty"`
	RedirectRule             string `json:"redirect_rule,omitempty"`
	RewrittenStatementDigest string `json:"rewritten_statement_digest,omitempty"`
	RedirectSourceRelation   string `json:"redirect_source_relation,omitempty"`
	RedirectTargetRelation   string `json:"redirect_target_relation,omitempty"`
	RedirectRuntimeStatus    string `json:"redirect_runtime_status,omitempty"`
	RedirectRejectionReason  string `json:"redirect_rejection_reason,omitempty"`
```

Update the `EventDecision` comment to include redirect:

```go
// EventDecision mirrors spec §8 decision{}. Verb is one of "allow"|"deny"|
// "approve"|"audit"|"redirect".
```

- [ ] **Step 4: Run event tests**

Run:

```bash
go test ./internal/db/events -run 'TestDBEvent_Redirect.*RoundTrip|TestDBEvent_' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit event schema**

Run:

```bash
git add internal/db/events/event.go internal/db/events/event_test.go
git commit -m "db/events: add redirect audit fields"
```

---

## Task 2: Add Event Builder Redirect Inputs

**Files:**
- Modify: `internal/db/proxy/postgres/eventbuilder.go`
- Modify: `internal/db/proxy/postgres/eventbuilder_test.go`

- [ ] **Step 1: Write failing event builder test**

Add this test to `internal/db/proxy/postgres/eventbuilder_test.go`.

```go
func TestBuildStatementEvent_RedirectMetadataPreservesOriginalDigest(t *testing.T) {
	parser := classify_pg.New(classify_pg.DialectPostgres)
	stmt := effects.ClassifiedStatement{
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group:      effects.GroupRead,
			Subtype:   effects.SubtypeSelect,
			Resolution: effects.ResolutionCatalogResolved,
			Objects:    []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
		}},
	}

	ev := buildStatementEvent(buildArgs{
		Stmt:       stmt,
		StmtIndex:  0,
		BatchTotal: 1,
		Decision: policy.Decision{
			Verb:                policy.VerbRedirect,
			RuleKind:            policy.RuleKindStatement,
			RuleName:            "redirect-users",
			MatchingEffectIndex: 0,
			MatchingEffectGroup: effects.GroupRead,
		},
		SQL:      "select id from public.users",
		Tier:     policy.RedactParametersRedacted,
		Conn:     connState{dbService: "appdb", smState: &statemachine.ConnState{LastUpstreamRFQ: 'I'}},
		BatchSHA: sha256HexBatch("select id from public.users"),
		Parser:   parser,
		Redirect: redirectEventArgs{
			Redirected:               true,
			Rule:                     "redirect-users",
			RewrittenSQL:             "select id from public.safe_users",
			SourceRelation:           "public.users",
			TargetRelation:           "public.safe_users",
			RuntimeStatus:            "executed",
		},
	})

	if !ev.Redirected {
		t.Fatalf("Redirected = false")
	}
	if ev.RedirectRule != "redirect-users" {
		t.Fatalf("RedirectRule = %q", ev.RedirectRule)
	}
	if ev.RedirectSourceRelation != "public.users" || ev.RedirectTargetRelation != "public.safe_users" {
		t.Fatalf("redirect relations = %q -> %q", ev.RedirectSourceRelation, ev.RedirectTargetRelation)
	}
	if ev.RedirectRuntimeStatus != "executed" {
		t.Fatalf("RedirectRuntimeStatus = %q", ev.RedirectRuntimeStatus)
	}
	if ev.StatementDigest == "" || ev.RewrittenStatementDigest == "" {
		t.Fatalf("digests missing: original=%q rewritten=%q", ev.StatementDigest, ev.RewrittenStatementDigest)
	}
	if ev.StatementDigest == ev.RewrittenStatementDigest {
		t.Fatalf("original and rewritten digests must differ: %q", ev.StatementDigest)
	}
	if ev.StatementText != "select id from public.users" {
		t.Fatalf("StatementText = %q, want original statement text", ev.StatementText)
	}
}
```

- [ ] **Step 2: Run the failing event builder test**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestBuildStatementEvent_RedirectMetadataPreservesOriginalDigest -count=1
```

Expected: FAIL because `buildArgs.Redirect`, `redirectEventArgs`, and `policy.VerbRedirect` are missing until Plan 11 and this task land.

- [ ] **Step 3: Add redirect event args and digest helper**

In `internal/db/proxy/postgres/eventbuilder.go`, add:

```go
type redirectEventArgs struct {
	Redirected              bool
	Rule                    string
	RewrittenSQL            string
	RewrittenStatementDigest string
	SourceRelation          string
	TargetRelation          string
	RuntimeStatus           string
	RejectionReason         string
}
```

Add this field to `buildArgs`:

```go
	Redirect redirectEventArgs
```

Extract the existing digest logic into a helper:

```go
func statementDigest(parser classify_pg.Parser, sql string) string {
	normalized, err := parser.Normalize(sql)
	if err != nil || normalized == "" {
		normalized = strings.TrimSpace(sql)
	}
	digestBytes := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(digestBytes[:])
}
```

Replace the existing inline digest calculation in `buildStatementEvent` with:

```go
	digest := statementDigest(a.Parser, slice)
```

Before the `return events.DBEvent{...}`, compute rewritten digest:

```go
	rewrittenDigest := a.Redirect.RewrittenStatementDigest
	if rewrittenDigest == "" && a.Redirect.RewrittenSQL != "" {
		rewrittenDigest = statementDigest(a.Parser, a.Redirect.RewrittenSQL)
	}
```

Populate the event fields in the returned `events.DBEvent`:

```go
		Redirected:               a.Redirect.Redirected,
		RedirectRule:             a.Redirect.Rule,
		RewrittenStatementDigest: rewrittenDigest,
		RedirectSourceRelation:   a.Redirect.SourceRelation,
		RedirectTargetRelation:   a.Redirect.TargetRelation,
		RedirectRuntimeStatus:    a.Redirect.RuntimeStatus,
		RedirectRejectionReason:  a.Redirect.RejectionReason,
```

- [ ] **Step 4: Run event builder tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestBuildStatementEvent_RedirectMetadataPreservesOriginalDigest|TestBuildStatementEvent' -count=1
```

Expected: PASS after Plan 11 has introduced `policy.VerbRedirect`. If Plan 11 uses a different exported redirect constant, update only this test and any local comparisons to that actual constant.

- [ ] **Step 5: Commit event builder wiring**

Run:

```bash
git add internal/db/proxy/postgres/eventbuilder.go internal/db/proxy/postgres/eventbuilder_test.go
git commit -m "db/proxy: populate redirect event metadata"
```

---

## Task 3: Extend Prepared Cache Metadata

**Files:**
- Modify: `internal/db/proxy/postgres/preparedcache/cache.go`
- Modify: `internal/db/proxy/postgres/preparedcache/cache_test.go`

- [ ] **Step 1: Write failing cache tests**

Add these tests to `internal/db/proxy/postgres/preparedcache/cache_test.go`.

```go
func TestCache_RedirectMetadataRoundTrip(t *testing.T) {
	c := New(2)
	entry := Entry{
		Classification: effects.ClassifiedStatement{RawVerb: "SELECT"},
		Redirect: &RedirectMetadata{
			OriginalClassification: effects.ClassifiedStatement{RawVerb: "SELECT"},
			OriginalSQL: "select note from public.users",
			OriginalStatementDigest: "sha256:original",
			RewrittenStatementDigest: "sha256:rewritten",
			Rule: "redirect-users",
			SourceRelation: "public.users",
			TargetRelation: "public.safe_users",
			PolicyIdentity: "redirect-users",
		},
	}
	c.Put("stmt", entry)

	got, ok := c.Get("stmt")
	if !ok {
		t.Fatal("cache miss")
	}
	if got.Redirect == nil {
		t.Fatal("Redirect metadata missing")
	}
	if got.Redirect.Rule != "redirect-users" || got.Redirect.TargetRelation != "public.safe_users" {
		t.Fatalf("Redirect metadata = %+v", got.Redirect)
	}
}

func TestCache_RedirectMetadataReplacementClearsOldValue(t *testing.T) {
	c := New(2)
	c.Put("stmt", Entry{
		Classification: effects.ClassifiedStatement{RawVerb: "SELECT"},
		Redirect:       &RedirectMetadata{Rule: "redirect-users"},
	})
	c.Put("stmt", Entry{Classification: effects.ClassifiedStatement{RawVerb: "SELECT"}})

	got, ok := c.Get("stmt")
	if !ok {
		t.Fatal("cache miss")
	}
	if got.Redirect != nil {
		t.Fatalf("old redirect metadata leaked after replacement: %+v", got.Redirect)
	}
}
```

- [ ] **Step 2: Run failing cache tests**

Run:

```bash
go test ./internal/db/proxy/postgres/preparedcache -run 'TestCache_RedirectMetadata' -count=1
```

Expected: FAIL because `RedirectMetadata` and `Entry.Redirect` do not exist.

- [ ] **Step 3: Add redirect metadata type**

In `internal/db/proxy/postgres/preparedcache/cache.go`, add:

```go
// RedirectMetadata captures parse-time redirect state for wire-protocol
// prepared statements. Classification on Entry is the rewritten statement;
// OriginalClassification keeps the client statement for audit.
type RedirectMetadata struct {
	OriginalClassification effects.ClassifiedStatement
	OriginalSQL string
	OriginalStatementDigest string
	RewrittenStatementDigest string
	Rule string
	SourceRelation string
	TargetRelation string
	PolicyIdentity string
}
```

Add this field to `Entry`:

```go
	Redirect *RedirectMetadata
```

- [ ] **Step 4: Run cache tests**

Run:

```bash
go test ./internal/db/proxy/postgres/preparedcache -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit cache metadata**

Run:

```bash
git add internal/db/proxy/postgres/preparedcache/cache.go internal/db/proxy/postgres/preparedcache/cache_test.go
git commit -m "db/proxy: cache redirect metadata for prepared statements"
```

---

## Task 4: Add Redirect Runtime Adapter

**Files:**
- Create: `internal/db/proxy/postgres/redirect_runtime.go`
- Create: `internal/db/proxy/postgres/redirect_runtime_test.go`

- [ ] **Step 1: Create adapter tests with a fake planner**

Create `internal/db/proxy/postgres/redirect_runtime_test.go`.

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

type fakeRedirectPlanner struct {
	plan redirectRuntimePlan
	err  error
	calls int
}

func (f *fakeRedirectPlanner) PlanRedirect(context.Context, redirectRuntimeInput) (redirectRuntimePlan, error) {
	f.calls++
	if f.err != nil {
		return redirectRuntimePlan{}, f.err
	}
	return f.plan, nil
}

func TestRedirectRuntime_PlansAndClassifiesRewrittenSQL(t *testing.T) {
	pc, _, _ := newSimpleQueryFixture(t)
	planner := &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:    "select id from public.safe_users",
		Rule:            "redirect-users",
		SourceRelation:  "public.users",
		TargetRelation:  "public.safe_users",
		RuntimeStatus:   "planned",
	}}
	pc.redirectPlanner = planner

	stmt := effects.ClassifiedStatement{
		RawVerb: "SELECT",
		Effects: []effects.Effect{{
			Group: effects.GroupRead,
			Objects: []effects.ObjectRef{{Kind: effects.ObjectTable, Schema: "public", Name: "users"}},
		}},
	}
	decision := policy.Decision{Verb: policy.VerbRedirect, RuleName: "redirect-users", RuleKind: policy.RuleKindStatement}

	plan, ok := pc.planRuntimeRedirect(context.Background(), "select id from public.users", stmt, decision)
	if !ok {
		t.Fatalf("planRuntimeRedirect rejected: %+v", plan)
	}
	if planner.calls != 1 {
		t.Fatalf("planner calls = %d, want 1", planner.calls)
	}
	if plan.RewrittenSQL != "select id from public.safe_users" || len(plan.RewrittenStatements) != 1 {
		t.Fatalf("unexpected runtime plan: %+v", plan)
	}
	if plan.RewrittenStatements[0].RawVerb != "SELECT" {
		t.Fatalf("rewritten classification = %+v", plan.RewrittenStatements)
	}
	if plan.RewrittenStatementDigest == "" {
		t.Fatalf("rewritten digest missing")
	}
}

func TestRedirectRuntime_FailsClosedOnPlannerError(t *testing.T) {
	pc, _, _ := newSimpleQueryFixture(t)
	pc.redirectPlanner = &fakeRedirectPlanner{err: errors.New("unsupported_statement")}

	stmt := effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{Group: effects.GroupRead}}}
	decision := policy.Decision{Verb: policy.VerbRedirect, RuleName: "redirect-users", RuleKind: policy.RuleKindStatement}

	plan, ok := pc.planRuntimeRedirect(context.Background(), "select 1", stmt, decision)
	if ok {
		t.Fatalf("planRuntimeRedirect unexpectedly succeeded: %+v", plan)
	}
	if plan.RejectionReason == "" {
		t.Fatalf("rejection reason missing: %+v", plan)
	}
}

func TestRedirectRuntime_FailsClosedOnUnsafeReclassification(t *testing.T) {
	pc, _, _ := newSimpleQueryFixture(t)
	pc.redirectPlanner = &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:     "delete from public.safe_users",
		Rule:             "redirect-users",
		SourceRelation:   "public.users",
		TargetRelation:   "public.safe_users",
	}}

	stmt := effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{Group: effects.GroupRead}}}
	decision := policy.Decision{Verb: policy.VerbRedirect, RuleName: "redirect-users", RuleKind: policy.RuleKindStatement}

	plan, ok := pc.planRuntimeRedirect(context.Background(), "select 1", stmt, decision)
	if ok {
		t.Fatalf("unsafe rewritten SQL unexpectedly accepted: %+v", plan)
	}
	if plan.RejectionReason != "rewritten_statement_not_read_only" {
		t.Fatalf("RejectionReason = %q", plan.RejectionReason)
	}
}
```

- [ ] **Step 2: Run failing adapter tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestRedirectRuntime -count=1
```

Expected: FAIL because the adapter types and `proxyConn.redirectPlanner` do not exist.

- [ ] **Step 3: Add adapter implementation**

Create `internal/db/proxy/postgres/redirect_runtime.go`.

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"

	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

const sqlstateRedirectRejected = "0A000"

type redirectRuntimePlanner interface {
	PlanRedirect(context.Context, redirectRuntimeInput) (redirectRuntimePlan, error)
}

type redirectRuntimeInput struct {
	SQL      string
	Stmt     effects.ClassifiedStatement
	Decision policy.Decision
	Rule     policy.StatementRule
	Service  policy.ServiceID
}

type redirectRuntimePlan struct {
	RewrittenSQL             string
	RewrittenStatements      []effects.ClassifiedStatement
	OriginalStatementDigest  string
	RewrittenStatementDigest string
	Rule                     string
	SourceRelation           string
	TargetRelation           string
	RuntimeStatus            string
	RejectionReason          string
}

func (pc *proxyConn) activeRedirectPlanner() redirectRuntimePlanner {
	if pc.redirectPlanner != nil {
		return pc.redirectPlanner
	}
	return plan11RedirectPlanner{}
}

func (pc *proxyConn) planRuntimeRedirect(
	ctx context.Context,
	sql string,
	stmt effects.ClassifiedStatement,
	decision policy.Decision,
) (redirectRuntimePlan, bool) {
	parser := pc.resolvingParser(pc.svc.Dialect)
	rule := lookupStatementRuleByName(pc.srv.policy(), decision.RuleName)
	input := redirectRuntimeInput{
		SQL:      sql,
		Stmt:     stmt,
		Decision: decision,
		Rule:     rule,
		Service:  policy.ServiceID(pc.svc.Name),
	}
	plan, err := pc.activeRedirectPlanner().PlanRedirect(ctx, input)
	if err != nil {
		plan.RejectionReason = err.Error()
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	if plan.Rule == "" {
		plan.Rule = decision.RuleName
	}
	if plan.RewrittenSQL == "" {
		plan.RejectionReason = "empty_rewritten_statement"
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	opts := classifierOptionsFromPolicy(pc.srv.policy())
	rewritten, err := parser.Classify(plan.RewrittenSQL, classify_pg.SessionState{}, opts)
	if err != nil || len(rewritten) != 1 {
		plan.RejectionReason = "rewritten_statement_unclassifiable"
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	if !statementIsReadOnly(rewritten[0]) {
		plan.RejectionReason = "rewritten_statement_not_read_only"
		plan.RuntimeStatus = "rejected"
		return plan, false
	}
	plan.RewrittenStatements = rewritten
	plan.OriginalStatementDigest = statementDigest(parser, sql)
	plan.RewrittenStatementDigest = statementDigest(parser, plan.RewrittenSQL)
	plan.RuntimeStatus = "planned"
	return plan, true
}

func statementIsReadOnly(stmt effects.ClassifiedStatement) bool {
	if len(stmt.Effects) == 0 {
		return false
	}
	for _, eff := range stmt.Effects {
		if eff.Group != effects.GroupRead {
			return false
		}
	}
	return true
}

func redirectEventFromPlan(plan redirectRuntimePlan, status string) redirectEventArgs {
	if status == "" {
		status = plan.RuntimeStatus
	}
	return redirectEventArgs{
		Redirected:                true,
		Rule:                      plan.Rule,
		RewrittenSQL:              plan.RewrittenSQL,
		RewrittenStatementDigest:  plan.RewrittenStatementDigest,
		SourceRelation:            plan.SourceRelation,
		TargetRelation:            plan.TargetRelation,
		RuntimeStatus:             status,
		RejectionReason:           plan.RejectionReason,
	}
}

type plan11RedirectPlanner struct{}

func (plan11RedirectPlanner) PlanRedirect(ctx context.Context, input redirectRuntimeInput) (redirectRuntimePlan, error) {
	_ = ctx
	_ = input
	return redirectRuntimePlan{}, fmt.Errorf("plan11_redirect_planner_unwired")
}
```

Add this field to `proxyConn` in `internal/db/proxy/postgres/proxyconn.go`:

```go
	redirectPlanner redirectRuntimePlanner
```

After this compiles, replace the `plan11RedirectPlanner` stub body with the real Plan 11 package call. Keep all Plan 11 import and type mapping inside `redirect_runtime.go`. The final method must return a local `redirectRuntimePlan`, not Plan 11 package types.

- [ ] **Step 4: Run adapter tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestRedirectRuntime -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit adapter**

Run:

```bash
git add internal/db/proxy/postgres/redirect_runtime.go internal/db/proxy/postgres/redirect_runtime_test.go internal/db/proxy/postgres/proxyconn.go
git commit -m "db/proxy: add redirect runtime adapter"
```

---

## Task 5: Wire Simple Query Redirect

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write failing Simple Query tests**

Add tests to `internal/db/proxy/postgres/simplequery_test.go` that use `fakeRedirectPlanner`.
Add `errors` to the import block; `net`, `pgproto3`, `events`, and `policy` are already imported in this file.

```go
func TestHandleQuery_RedirectForwardsRewrittenSQL(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.srv.SetPolicy(redirectReadRuleSet(t))
	pc.redirectPlanner = &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:    "select note from public.safe_users",
		Rule:            "redirect-users",
		SourceRelation:  "public.users",
		TargetRelation:  "public.safe_users",
	}}

	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)
	upBackend := pgproto3.NewBackend(upClient, upClient)
	drainClientBackendMessages(clientFE)

	done := make(chan error, 1)
	go func() {
		done <- pc.handleQuery(context.Background(), &pgproto3.Query{String: "select note from public.users"})
	}()

	msg, err := upBackend.Receive()
	if err != nil {
		t.Fatalf("upstream Receive: %v", err)
	}
	q, ok := msg.(*pgproto3.Query)
	if !ok {
		t.Fatalf("upstream got %T", msg)
	}
	if q.String != "select note from public.safe_users" {
		t.Fatalf("forwarded SQL = %q", q.String)
	}
	upBackend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")})
	upBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := upBackend.Flush(); err != nil {
		t.Fatalf("upstream flush: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("handleQuery: %v", err)
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 {
		t.Fatalf("events = %d: %+v", len(evs), evs)
	}
	ev := evs[0]
	if !ev.Redirected || ev.RedirectRule != "redirect-users" || ev.RedirectRuntimeStatus != "executed" {
		t.Fatalf("redirect event fields = %+v", ev)
	}
	if ev.StatementDigest == "" || ev.RewrittenStatementDigest == "" || ev.StatementDigest == ev.RewrittenStatementDigest {
		t.Fatalf("bad digests: original=%q rewritten=%q", ev.StatementDigest, ev.RewrittenStatementDigest)
	}
}

func TestHandleQuery_RedirectPlannerFailureFailsClosed(t *testing.T) {
	pc, clientFE, sink := newSimpleQueryFixture(t)
	pc.srv.SetPolicy(redirectReadRuleSet(t))
	pc.redirectPlanner = &fakeRedirectPlanner{err: errors.New("missing_target_relation")}

	upClient, upServer := net.Pipe()
	t.Cleanup(func() { _ = upClient.Close(); _ = upServer.Close() })
	pc.state.upstream = upServer
	pc.state.upstreamFE = pgproto3.NewFrontend(upServer, upServer)
	upBackend := pgproto3.NewBackend(upClient, upClient)
	drainClientBackendMessages(clientFE)

	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "select note from public.users"})
	if err != nil {
		t.Fatalf("handleQuery returned transport error: %v", err)
	}

	upRecv := make(chan pgproto3.FrontendMessage, 1)
	go func() {
		msg, err := upBackend.Receive()
		if err == nil {
			upRecv <- msg
		}
	}()
	select {
	case msg := <-upRecv:
		t.Fatalf("upstream received original SQL after redirect rejection: %T", msg)
	case <-time.After(200 * time.Millisecond):
	}

	evs := sink.DrainStatements()
	if len(evs) != 1 {
		t.Fatalf("events = %d: %+v", len(evs), evs)
	}
	if evs[0].RedirectRuntimeStatus != "rejected" || evs[0].RedirectRejectionReason != "missing_target_relation" {
		t.Fatalf("redirect rejection event = %+v", evs[0])
	}
	if evs[0].Result.ErrorCode != sqlstateRedirectRejected {
		t.Fatalf("ErrorCode = %q", evs[0].Result.ErrorCode)
	}
}
```

Add helper:

```go
func drainClientBackendMessages(fe *pgproto3.Frontend) {
	go func() {
		for {
			if _, err := fe.Receive(); err != nil {
				return
			}
		}
	}()
}

func redirectReadRuleSet(t *testing.T) *policy.RuleSet {
	t.Helper()
	return loadRuleSet(t, `version: 1
name: redirect-test
db_services:
  test:
    family: postgres
    dialect: postgres
    upstream: "127.0.0.1:5432"
    tls_mode: terminate_reissue
database_rules:
  - name: block-delete
    db_service: test
    operations: [delete]
    decision: deny
  - name: redirect-users
    db_service: test
    operations: [read]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`)
}
```

If Plan 11 chose a different YAML shape for redirect actions, use the exact Plan 11 YAML while keeping the rule name `redirect-users` and target relation `public.safe_users`.

- [ ] **Step 2: Run failing Simple Query tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestHandleQuery_Redirect' -count=1
```

Expected: FAIL because `handleQuery` still forwards original SQL or denies redirect.

- [ ] **Step 3: Add Simple Query redirect branch**

In `handleQuery`, after decisions are computed and before approval/allow handling, add:

```go
	redirectIndex := -1
	for i, d := range decisions {
		if d.Verb == policy.VerbRedirect {
			redirectIndex = i
			break
		}
	}
	if !anyDeny && redirectIndex >= 0 {
		return pc.runSimpleQueryRedirect(ctx, q, stmts, decisions, redirectIndex, batchSHA)
	}
```

Add helper in `simplequery.go`:

```go
func (pc *proxyConn) runSimpleQueryRedirect(
	ctx context.Context,
	q *pgproto3.Query,
	stmts []effects.ClassifiedStatement,
	decisions []policy.Decision,
	redirectIndex int,
	batchSHA string,
) error {
	if len(stmts) != 1 || redirectIndex != 0 {
		plan := redirectRuntimePlan{
			Rule:            decisions[redirectIndex].RuleName,
			RuntimeStatus:   "rejected",
			RejectionReason: "multi_statement_redirect_unsupported",
		}
		pc.emitRedirectRejectedEvent(ctx, stmts[redirectIndex], decisions[redirectIndex], q.String, batchSHA, plan)
		return pc.synthErrorAndRFQ(sqlstateRedirectRejected, "redirect rejected by AgentSH policy: multi-statement redirect unsupported")
	}

	plan, ok := pc.planRuntimeRedirect(ctx, q.String, stmts[redirectIndex], decisions[redirectIndex])
	if !ok {
		pc.emitRedirectRejectedEvent(ctx, stmts[redirectIndex], decisions[redirectIndex], q.String, batchSHA, plan)
		return pc.synthErrorAndRFQ(sqlstateRedirectRejected, "redirect rejected by AgentSH policy: "+plan.RejectionReason)
	}

	sentAt := timeNow()
	pc.state.upstreamFE.Send(&pgproto3.Query{String: plan.RewrittenSQL})
	if err := pc.state.upstreamFE.Flush(); err != nil {
		return err
	}
	result, ferr := pc.forwardUpstreamUntilRFQ(ctx, sentAt, len(q.String))
	pc.emitRedirectAllowEvent(ctx, stmts[redirectIndex], decisions[redirectIndex], q.String, batchSHA, plan, result)
	pc.refreshCatalogAfterSuccessfulStatements(ctx, plan.RewrittenStatements, result)
	return ferr
}
```

Add emit helpers:

```go
func (pc *proxyConn) emitRedirectAllowEvent(ctx context.Context, stmt effects.ClassifiedStatement, decision policy.Decision, sql, batchSHA string, plan redirectRuntimePlan, result upstreamResult) {
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	var rowsReturned, rowsAffected *int64
	if len(result.RowsByStmt) > 0 {
		rowsReturned = result.RowsByStmt[0]
	}
	if len(result.AffectedByStmt) > 0 {
		rowsAffected = result.AffectedByStmt[0]
	}
	ev := buildStatementEvent(buildArgs{
		Stmt:            stmt,
		StmtIndex:       0,
		BatchTotal:      1,
		Decision:        decision,
		SQL:             sql,
		Tier:            pc.srv.policy().Redaction().Tier,
		Conn:            *pc.state,
		BytesIn:         int64(len(sql)),
		BytesOut:        result.BytesOut,
		LatencyMs:       result.LatencyMs,
		RowsReturned:    rowsReturned,
		RowsAffected:    rowsAffected,
		UpstreamErrCode: result.ErrorCode,
		DenyAction:      "none",
		BatchSHA:        batchSHA,
		Parser:          parser,
		Redirect:        redirectEventFromPlan(plan, "executed"),
	})
	_ = pc.srv.cfg.Sink.EmitStatement(ctx, ev)
}

func (pc *proxyConn) emitRedirectRejectedEvent(ctx context.Context, stmt effects.ClassifiedStatement, decision policy.Decision, sql, batchSHA string, plan redirectRuntimePlan) {
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	ev := buildStatementEvent(buildArgs{
		Stmt:            stmt,
		StmtIndex:       0,
		BatchTotal:      1,
		Decision:        decision,
		SQL:             sql,
		Tier:            pc.srv.policy().Redaction().Tier,
		Conn:            *pc.state,
		BytesIn:         int64(len(sql)),
		UpstreamErrCode: sqlstateRedirectRejected,
		DenyAction:      "none",
		BatchSHA:        batchSHA,
		Parser:          parser,
		Redirect:        redirectEventFromPlan(plan, "rejected"),
	})
	_ = pc.srv.cfg.Sink.EmitStatement(ctx, ev)
}
```

- [ ] **Step 4: Run Simple Query tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestHandleQuery_Redirect|TestHandleQuery_' -count=1
```

Expected: PASS.

- [ ] **Step 5: Commit Simple Query redirect**

Run:

```bash
git add internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/simplequery_test.go
git commit -m "db/proxy: execute simple-query redirects"
```

---

## Task 6: Wire Extended Query Parse Redirect

**Files:**
- Modify: `internal/db/proxy/postgres/extquery.go`
- Modify: `internal/db/proxy/postgres/extquery_spine_test.go`

- [ ] **Step 1: Write failing Extended Query Parse tests**

Add tests to `internal/db/proxy/postgres/extquery_spine_test.go`.
Add `github.com/agentsh/agentsh/internal/db/events` to the import block for the execute-audit test in Task 7.

```go
func TestExtquery_RedirectParse_ForwardsRewrittenAndCachesMetadata(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, redirectExtqueryPolicyYAML())
	pc.redirectPlanner = &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:   "select note from public.safe_users where id=$1",
		Rule:           "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users",
	}}

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "client_stmt", Query: "select note from public.users where id=$1"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	msg, err := upBackend.Receive()
	if err != nil {
		t.Fatalf("upstream Receive: %v", err)
	}
	parse, ok := msg.(*pgproto3.Parse)
	if !ok {
		t.Fatalf("upstream got %T", msg)
	}
	if parse.Name != "client_stmt" {
		t.Fatalf("Parse.Name = %q", parse.Name)
	}
	if parse.Query != "select note from public.safe_users where id=$1" {
		t.Fatalf("Parse.Query = %q", parse.Query)
	}

	entry, ok := pc.wireCache.Get("client_stmt")
	if !ok {
		t.Fatal("wire cache missing client_stmt")
	}
	if entry.Redirect == nil {
		t.Fatal("redirect metadata missing")
	}
	if entry.Redirect.TargetRelation != "public.safe_users" || entry.Classification.RawVerb != "SELECT" {
		t.Fatalf("cache entry = %+v", entry)
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}

func TestExtquery_RedirectParse_FailureDoesNotCacheOrForward(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, redirectExtqueryPolicyYAML())
	pc.redirectPlanner = &fakeRedirectPlanner{err: errors.New("unsupported_statement")}
	drainClientBackendMessages(clientFE)

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "client_stmt", Query: "select note from public.users"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	if _, ok := pc.wireCache.Get("client_stmt"); ok {
		t.Fatal("failed redirect Parse must not cache statement")
	}

	upRecv := make(chan struct{}, 1)
	go func() {
		if _, err := upBackend.Receive(); err == nil {
			upRecv <- struct{}{}
		}
	}()
	select {
	case <-upRecv:
		t.Fatal("upstream received Parse after redirect failure")
	case <-time.After(200 * time.Millisecond):
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}
```

Add helper YAML:

```go
func redirectExtqueryPolicyYAML() string {
	return `version: 1
name: redirect-extquery
db_services:
  test: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: block-delete
    db_service: test
    operations: [delete]
    decision: deny
  - name: redirect-users
    db_service: test
    operations: [read]
    relations: ["public.users"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: public.safe_users
`
}
```

Use the exact Plan 11 redirect YAML if the action shape differs.

- [ ] **Step 2: Run failing Extended Query tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestExtquery_RedirectParse' -count=1
```

Expected: FAIL because Parse still forwards original SQL or redirect fails through existing state machine behavior.

- [ ] **Step 3: Add redirected Parse fast path**

In `handleExtendedFrame`, after Parse classification and before `TransitionWithParser`, add:

```go
	if isParse && len(parseStmts) > 0 {
		handled, err := pc.tryHandleRedirectParse(ctx, parse, parseStmts)
		if handled || err != nil {
			return err
		}
	}
```

Add helper:

```go
func (pc *proxyConn) tryHandleRedirectParse(ctx context.Context, parse *pgproto3.Parse, stmts []effects.ClassifiedStatement) (bool, error) {
	rs := pc.srv.policy()
	decisions := make([]policy.Decision, len(stmts))
	redirectIndex := -1
	for i, stmt := range stmts {
		decisions[i] = policy.Evaluate(stmt, rs, policy.ServiceID(pc.svc.Name))
		if decisions[i].Verb == policy.VerbDeny || decisions[i].Verb == policy.VerbApprove {
			return false, nil
		}
		if decisions[i].Verb == policy.VerbRedirect && redirectIndex == -1 {
			redirectIndex = i
		}
	}
	if redirectIndex < 0 {
		return false, nil
	}
	if len(stmts) != 1 || redirectIndex != 0 {
		plan := redirectRuntimePlan{
			Rule:            decisions[redirectIndex].RuleName,
			RuntimeStatus:   "rejected",
			RejectionReason: "multi_statement_redirect_unsupported",
		}
		pc.emitRedirectRejectedEvent(ctx, stmts[redirectIndex], decisions[redirectIndex], parse.Query, sha256HexBatch(parse.Query), plan)
		return true, pc.executeActions(ctx, parse, statemachine.DenyRoute(*pc.state.smState, policy.StatementRule{}, "redirect rejected by AgentSH policy: multi-statement redirect unsupported", sqlstateRedirectRejected))
	}
	plan, ok := pc.planRuntimeRedirect(ctx, parse.Query, stmts[0], decisions[0])
	if !ok {
		pc.emitRedirectRejectedEvent(ctx, stmts[0], decisions[0], parse.Query, sha256HexBatch(parse.Query), plan)
		actions := statemachine.DenyRoute(*pc.state.smState, policy.StatementRule{}, "redirect rejected by AgentSH policy: "+plan.RejectionReason, sqlstateRedirectRejected)
		next := *pc.state.smState
		if !containsCloseAction(actions) {
			next.Absorbing = true
		}
		*pc.state.smState = next
		return true, pc.executeActions(ctx, parse, actions)
	}

	searchPath, snapshot := statementsNeedCatalogRefresh(plan.RewrittenStatements)
	pc.wireCache.Put(parse.Name, preparedcache.Entry{
		Classification:           plan.RewrittenStatements[0],
		CatalogRefreshSearchPath: searchPath,
		CatalogRefreshSnapshot:   snapshot,
		Redirect: &preparedcache.RedirectMetadata{
			OriginalClassification:  stmts[0],
			OriginalSQL:             parse.Query,
			OriginalStatementDigest: plan.OriginalStatementDigest,
			RewrittenStatementDigest: plan.RewrittenStatementDigest,
			Rule:                    plan.Rule,
			SourceRelation:          plan.SourceRelation,
			TargetRelation:          plan.TargetRelation,
			PolicyIdentity:          decisions[0].RuleName,
		},
	})
	forward := *parse
	forward.Query = plan.RewrittenSQL
	pc.state.upstreamFE.Send(&forward)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		return true, err
	}
	pc.state.smState.UpstreamDirtySinceSync = true
	return true, nil
}
```

Add helper:

```go
func containsCloseAction(actions []statemachine.Action) bool {
	for _, action := range actions {
		if _, ok := action.(*statemachine.ActionClose); ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Preserve full redirect metadata through Bind**

In `handleExtendedFrame`, after `TransitionWithParser` and before `Execute` handling, add:

```go
	if bind, ok := msg.(*pgproto3.Bind); ok && actionsCanForward(actions) {
		pc.preserveRedirectPortalMetadata(bind)
	}
```

Add helper:

```go
func (pc *proxyConn) preserveRedirectPortalMetadata(bind *pgproto3.Bind) {
	if bind == nil || pc.wireCache == nil {
		return
	}
	entry, ok := pc.wireCache.Get(bind.PreparedStatement)
	if !ok || entry.Redirect == nil {
		return
	}
	pc.wireCache.Put(wirePortalCacheKey(bind.DestinationPortal), entry)
}
```

- [ ] **Step 5: Run Extended Query Parse tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestExtquery_RedirectParse|TestExtquery_Spine_Parse' -count=1
```

Expected: PASS.

- [ ] **Step 6: Commit Extended Query Parse redirect**

Run:

```bash
git add internal/db/proxy/postgres/extquery.go internal/db/proxy/postgres/extquery_spine_test.go
git commit -m "db/proxy: execute redirects at extended-query parse"
```

---

## Task 7: Emit Redirect Events For Extended Execute

**Files:**
- Modify: `internal/db/proxy/postgres/proxyconn.go`
- Modify: `internal/db/proxy/postgres/extquery.go`
- Modify: `internal/db/proxy/postgres/extquery_spine_test.go`

- [ ] **Step 1: Write failing Bind/Execute audit test**

Add this test to `internal/db/proxy/postgres/extquery_spine_test.go`.
Add `strings` and `github.com/agentsh/agentsh/internal/db/events` to the import block.

```go
func TestExtquery_RedirectExecute_UsesCachedMetadataAndEmitsEventAfterSync(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, redirectExtqueryPolicyYAML())
	planner := &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:   "select note from public.safe_users where id=$1",
		Rule:           "redirect-users",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users",
	}}
	pc.redirectPlanner = planner
	drainClientBackendMessages(clientFE)

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "client_stmt", Query: "select note from public.users where id=$1"})
	clientFE.Send(&pgproto3.Bind{DestinationPortal: "p1", PreparedStatement: "client_stmt"})
	clientFE.Send(&pgproto3.Execute{Portal: "p1"})
	clientFE.Send(&pgproto3.Sync{})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush: %v", err)
	}

	for i := 0; i < 3; i++ {
		if _, err := upBackend.Receive(); err != nil {
			t.Fatalf("upstream Receive %d: %v", i, err)
		}
	}
	upBackend.Send(&pgproto3.ParseComplete{})
	upBackend.Send(&pgproto3.BindComplete{})
	upBackend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 0")})
	upBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := upBackend.Flush(); err != nil {
		t.Fatalf("upstream flush: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	var evs []events.DBEvent
	for time.Now().Before(deadline) {
		evs = pc.srv.cfg.Sink.(*events.SyncSink).DrainStatements()
		if len(evs) > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(evs) != 1 {
		t.Fatalf("events = %d: %+v", len(evs), evs)
	}
	if !evs[0].Redirected || evs[0].RedirectRuntimeStatus != "executed" || evs[0].RedirectTargetRelation != "public.safe_users" {
		t.Fatalf("redirect execute event = %+v", evs[0])
	}
	if planner.calls != 1 {
		t.Fatalf("planner calls = %d, want Parse-only planning", planner.calls)
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}
```

Add a second unit test for reload stability:

```go
func TestExtquery_RedirectPolicyReloadKeepsPreparedPlanAndUsesNewPlanForNewParse(t *testing.T) {
	pc, clientFE, upBackend, _ := extqueryFixture(t, redirectExtqueryPolicyYAML())
	planner := &fakeRedirectPlanner{plan: redirectRuntimePlan{
		RewrittenSQL:   "select note from public.safe_users_a where id=$1",
		Rule:           "redirect-users-a",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users_a",
	}}
	pc.redirectPlanner = planner

	loopErr := make(chan error, 1)
	go func() { loopErr <- pc.simpleQueryLoop(context.Background()) }()

	clientFE.Send(&pgproto3.Parse{Name: "old_stmt", Query: "select note from public.users where id=$1"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush old parse: %v", err)
	}
	oldMsg, err := upBackend.Receive()
	if err != nil {
		t.Fatalf("old upstream Receive: %v", err)
	}
	oldParse := oldMsg.(*pgproto3.Parse)
	if oldParse.Query != "select note from public.safe_users_a where id=$1" {
		t.Fatalf("old rewritten SQL = %q", oldParse.Query)
	}

	pc.srv.SetPolicy(loadRuleSet(t, redirectExtqueryPolicyYAMLTarget("public.safe_users_b", "redirect-users-b")))
	planner.plan = redirectRuntimePlan{
		RewrittenSQL:   "select note from public.safe_users_b where id=$1",
		Rule:           "redirect-users-b",
		SourceRelation: "public.users",
		TargetRelation: "public.safe_users_b",
	}

	clientFE.Send(&pgproto3.Parse{Name: "new_stmt", Query: "select note from public.users where id=$1"})
	clientFE.Send(&pgproto3.Bind{DestinationPortal: "old_portal", PreparedStatement: "old_stmt"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("client flush reload frames: %v", err)
	}
	newMsg, err := upBackend.Receive()
	if err != nil {
		t.Fatalf("new upstream Receive: %v", err)
	}
	newParse := newMsg.(*pgproto3.Parse)
	if newParse.Query != "select note from public.safe_users_b where id=$1" {
		t.Fatalf("new rewritten SQL = %q", newParse.Query)
	}
	if oldPortal, ok := pc.wireCache.Get(wirePortalCacheKey("old_portal")); !ok || oldPortal.Redirect == nil || oldPortal.Redirect.TargetRelation != "public.safe_users_a" {
		t.Fatalf("old prepared redirect was corrupted after reload: ok=%v entry=%+v", ok, oldPortal)
	}

	_ = pc.conn.Close()
	select {
	case <-loopErr:
	case <-time.After(time.Second):
	}
}
```

Add helper:

```go
func redirectExtqueryPolicyYAMLTarget(target, ruleName string) string {
	return strings.ReplaceAll(
		strings.ReplaceAll(redirectExtqueryPolicyYAML(), "redirect-users", ruleName),
		"public.safe_users",
		target,
	)
}
```

- [ ] **Step 2: Run failing audit test**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestExtquery_RedirectExecute_UsesCachedMetadataAndEmitsEventAfterSync -count=1
```

Expected: FAIL because redirected Execute does not emit audit events.

- [ ] **Step 3: Add pending redirected execute state**

In `proxyConn` add:

```go
	pendingRedirectExec []pendingRedirectExecute
```

In `extquery.go`, add:

```go
type pendingRedirectExecute struct {
	Entry preparedcache.Entry
}
```

- [ ] **Step 4: Queue redirected Execute metadata**

Update `markCatalogRefreshPendingForExecute` after portal cache lookup:

```go
	if entry.Redirect != nil {
		pc.pendingRedirectExec = append(pc.pendingRedirectExec, pendingRedirectExecute{Entry: entry})
	}
```

- [ ] **Step 5: Emit pending events after drain**

In `executeActions`, change the drain case from discarding the result to capturing it:

```go
		case *statemachine.ActionDrainUntilRFQ:
			result, err := pc.forwardUpstreamUntilRFQ(ctx, timeNow(), 0)
			if err != nil {
				return fmt.Errorf("drain: %w", err)
			}
			pc.emitPendingRedirectExecuteEvents(ctx, result)
			pc.refreshPendingCatalogContext(ctx)
```

Add:

```go
func (pc *proxyConn) emitPendingRedirectExecuteEvents(ctx context.Context, result upstreamResult) {
	if len(pc.pendingRedirectExec) == 0 {
		return
	}
	pending := pc.pendingRedirectExec
	pc.pendingRedirectExec = nil
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	for i, p := range pending {
		if p.Entry.Redirect == nil {
			continue
		}
		var rowsReturned, rowsAffected *int64
		if i < len(result.RowsByStmt) {
			rowsReturned = result.RowsByStmt[i]
		}
		if i < len(result.AffectedByStmt) {
			rowsAffected = result.AffectedByStmt[i]
		}
		redir := p.Entry.Redirect
		ev := buildStatementEvent(buildArgs{
			Stmt:            redir.OriginalClassification,
			StmtIndex:       i,
			BatchTotal:      len(pending),
			Decision:        policy.Decision{Verb: policy.VerbRedirect, RuleKind: policy.RuleKindStatement, RuleName: redir.Rule, MatchingEffectIndex: 0},
			SQL:             redir.OriginalSQL,
			Tier:            pc.srv.policy().Redaction().Tier,
			Conn:            *pc.state,
			BytesOut:        result.BytesOut,
			LatencyMs:       result.LatencyMs,
			RowsReturned:    rowsReturned,
			RowsAffected:    rowsAffected,
			UpstreamErrCode: result.ErrorCode,
			DenyAction:      "none",
			BatchSHA:        redir.OriginalStatementDigest,
			Parser:          parser,
			Redirect: redirectEventArgs{
				Redirected:                true,
				Rule:                      redir.Rule,
				RewrittenStatementDigest:  redir.RewrittenStatementDigest,
				SourceRelation:            redir.SourceRelation,
				TargetRelation:            redir.TargetRelation,
				RuntimeStatus:             "executed",
			},
		})
		if ev.StatementDigest == "" {
			ev.StatementDigest = redir.OriginalStatementDigest
		}
		_ = pc.srv.cfg.Sink.EmitStatement(ctx, ev)
	}
}
```

The cached `OriginalSQL` is the client Parse SQL. Do not cache rewritten SQL text for audit; the rewritten digest and target relation fields carry that visibility without adding another raw-SQL exposure path.

- [ ] **Step 6: Run Extended redirect tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestExtquery_Redirect|TestExtquery_Spine' -count=1
```

Expected: PASS.

- [ ] **Step 7: Commit Extended redirect audit**

Run:

```bash
git add internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/extquery.go internal/db/proxy/postgres/extquery_spine_test.go internal/db/proxy/postgres/preparedcache/cache.go
git commit -m "db/proxy: emit extended-query redirect events"
```

---

## Task 8: Add Real Postgres Plan 12 Integration Tests

**Files:**
- Modify: `internal/integration/db07cclient/main.go`
- Modify: `internal/integration/db_postgres_07c_test.go`

- [ ] **Step 1: Add client mode for repeated prepared execution**

In `internal/integration/db07cclient/main.go`, update the mode flag help string:

```go
mode     = flag.String("mode", "scalar", "scalar, exec, prepared-repeat, tx-deny, cancel, copy-to, or copy-from")
```

Add this case to `run`:

```go
	case "prepared-repeat":
		var first string
		var second string
		if err := conn.QueryRow(ctx, sqlText, 1).Scan(&first); err != nil {
			return output{}, err
		}
		if err := conn.QueryRow(ctx, sqlText, 1).Scan(&second); err != nil {
			return output{}, err
		}
		return output{Scalar: first + "," + second}, nil
```

- [ ] **Step 2: Seed redirect source and target relations**

In `seedDB07C`, append:

```sql
drop table if exists plan12.users_source;
drop table if exists plan12.users_target_a;
drop table if exists plan12.users_target_b;
create schema if not exists plan12;
create table plan12.users_source(id int primary key, note text);
create table plan12.users_target_a(id int primary key, note text);
create table plan12.users_target_b(id int primary key, note text);
insert into plan12.users_source(id, note) values (1, 'source');
insert into plan12.users_target_a(id, note) values (1, 'target-a');
insert into plan12.users_target_b(id, note) values (1, 'target-b');
```

- [ ] **Step 3: Add redirect rules to policy**

In `db07cPolicyYAML`, add redirect rules before the generic `allow-read` rule:

```yaml
  - name: redirect-plan12-source-a
    db_service: appdb
    operations: [read]
    relations: ["plan12.users_source"]
    match_object_resolution: catalog_resolved
    decision: redirect
    redirect:
      relation: plan12.users_target_a
```

Use the exact Plan 11 redirect action field names if they differ from `redirect.relation`.

- [ ] **Step 4: Add Simple Query integration test**

Add:

```go
func TestDB12RealPostgresSimpleQueryRedirect(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	out := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from plan12.users_source where id = 1", "-simple")
	if out.Scalar != "target-a" {
		t.Fatalf("Plan 12 simple redirect returned %+v, want target-a", out)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		return ev.Type == "db_statement" &&
			ev.Fields["redirected"] == true &&
			ev.Fields["redirect_rule"] == "redirect-plan12-source-a" &&
			ev.Fields["redirect_target_relation"] == "plan12.users_target_a" &&
			ev.Fields["redirect_runtime_status"] == "executed"
	}, "Plan 12 simple redirect event")
}
```

- [ ] **Step 5: Add Extended Query prepared integration test**

Add:

```go
func TestDB12RealPostgresExtendedPreparedRedirect(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	out := execDB07CClient(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "prepared-repeat", "-sql", "select note from plan12.users_source where id = $1")
	if out.Scalar != "target-a,target-a" {
		t.Fatalf("Plan 12 prepared redirect returned %+v, want repeated target-a", out)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		return ev.Type == "db_statement" &&
			ev.Fields["redirected"] == true &&
			ev.Fields["redirect_rule"] == "redirect-plan12-source-a" &&
			ev.Fields["redirect_target_relation"] == "plan12.users_target_a"
	}, "Plan 12 extended redirect event")
}
```

- [ ] **Step 6: Add unsupported-form integration test**

Add:

```go
func TestDB12RealPostgresRedirectUnsupportedFormsFailClosed(t *testing.T) {
	ctx := context.Background()
	env := startDB07CEnvironment(t, ctx)
	defer env.cleanup()

	seedDB07C(t, ctx, env.hostDSN)
	sess := createDB07CSession(t, ctx, env.client)
	socket := filepath.Join(sess.DBProxySocketDir, "appdb.sock")

	multi := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "scalar", "-sql", "select note from plan12.users_source where id = 1; select note from plan12.users_source where id = 1", "-simple")
	if multi.OK {
		t.Fatalf("multi-statement redirect unexpectedly succeeded: %+v", multi)
	}

	write := execDB07CClientAllowFailure(t, ctx, env.client, sess.ID, "-socket", socket, "-mode", "exec", "-sql", "insert into plan12.users_source(id, note) values (2, 'blocked')", "-simple")
	if write.OK {
		t.Fatalf("write through redirect policy unexpectedly succeeded: %+v", write)
	}
	waitForSessionEvent07C(t, ctx, env.client, sess.ID, func(ev types.Event) bool {
		return ev.Type == "db_statement" &&
			ev.Fields["redirected"] == true &&
			ev.Fields["redirect_runtime_status"] == "rejected"
	}, "Plan 12 redirect rejection event")
}
```

- [ ] **Step 7: Add direct-proxy policy reload integration test**

Create `internal/db/proxy/postgres/redirect_integration_test.go` with build tag `//go:build integration && linux`. Put it in package `postgres` so it can reuse `runServer`, `renameSocketForPgx`, `pgxConnString`, and `pgxErrorCode` from existing proxy spine tests.

The test must start a real `postgres:16-alpine` container, seed `plan12.users_source`, `plan12.users_target_a`, and `plan12.users_target_b`, start a local `postgres.Server` pointed at that container, then call `srv.SetPolicy` while a pgx connection remains open.

Add this assertion shape:

```go
func TestDB12RealPostgresPolicyReloadKeepsPreparedRedirectPlan(t *testing.T) {
	ctx := context.Background()
	pg := startDB12PostgresContainer(t, ctx)
	seedDB12RedirectTables(t, ctx, pg.hostDSN)

	srv, sockPath := startDB12DirectProxy(t, pg.upstream, db12RedirectPolicyYAML("plan12.users_target_a", "redirect-plan12-a"))
	stop := runServer(t, srv)
	defer stop()

	sockDir := renameSocketForPgx(t, sockPath, 5452)
	conn, err := pgx.Connect(ctx, pgxConnString(sockDir, 5452))
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(ctx)

	if _, err := conn.Prepare(ctx, "old_redirect", "select note from plan12.users_source where id=$1"); err != nil {
		t.Fatalf("Prepare old_redirect: %v", err)
	}
	var oldBefore string
	if err := conn.QueryRow(ctx, "old_redirect", 1).Scan(&oldBefore); err != nil {
		t.Fatalf("old prepared before reload: %v", err)
	}
	if oldBefore != "target-a" {
		t.Fatalf("old prepared before reload = %q", oldBefore)
	}

	srv.SetPolicy(db12RedirectPolicyYAML("plan12.users_target_b", "redirect-plan12-b"))

	var oldAfter string
	if err := conn.QueryRow(ctx, "old_redirect", 1).Scan(&oldAfter); err != nil {
		t.Fatalf("old prepared after reload: %v", err)
	}
	if oldAfter != "target-a" {
		t.Fatalf("old prepared after reload = %q, want parse-time target-a", oldAfter)
	}

	var newAfter string
	if err := conn.QueryRow(ctx, "select note from plan12.users_source where id=$1", 1).Scan(&newAfter); err != nil {
		t.Fatalf("new statement after reload: %v", err)
	}
	if newAfter != "target-b" {
		t.Fatalf("new statement after reload = %q, want target-b", newAfter)
	}
}
```

Implement the helpers in the same file using `testcontainers-go`, `wait.ForLog("database system is ready to accept connections")`, `pgx.Connect` for seeding, and `postgres.New(Config{...})` following `startSpineHarness` but without `catalogLoaderForTest` so the real catalog loader resolves `plan12` relations.

- [ ] **Step 8: Run DB Plan 12 integration tests**

Run:

```bash
go test -v -tags=integration ./internal/integration ./internal/db/proxy/postgres -run TestDB12RealPostgres -count=1
```

Expected: PASS. If Docker is unavailable locally, note that explicitly and run the unit gates before pushing.

- [ ] **Step 9: Commit integration coverage**

Run:

```bash
git add internal/integration/db07cclient/main.go internal/integration/db_postgres_07c_test.go internal/db/proxy/postgres/redirect_integration_test.go
git commit -m "test: add db plan 12 postgres redirect integration"
```

---

## Task 9: Final Verification

**Files:**
- All files touched by prior tasks

- [ ] **Step 1: Run focused unit tests**

Run:

```bash
go test ./internal/db/events ./internal/db/proxy/postgres/preparedcache ./internal/db/proxy/postgres -run 'Redirect|TestHandleQuery|TestExtquery|TestBuildStatementEvent' -count=1
```

Expected: PASS.

- [ ] **Step 2: Run full DB unit packages**

Run:

```bash
go test ./internal/db/...
```

Expected: PASS.

- [ ] **Step 3: Verify Windows compilation**

Run:

```bash
GOOS=windows go build ./...
```

Expected: PASS. Linux-only proxy files are guarded by build tags and platform-neutral event/cache changes compile on Windows.

- [ ] **Step 4: Run real Postgres integration gate**

Run:

```bash
go test -v -tags=integration ./internal/integration -run 'TestDB07C|TestDB09|TestDB12' -count=1
```

Expected: PASS.

- [ ] **Step 5: Inspect final diff**

Run:

```bash
git status --short
git log --oneline --max-count=10
```

Expected: working tree clean except unrelated pre-existing untracked files. Recent commits should show the Plan 12 task commits.

---

## Implementation Notes

- Keep Plan 11 planner imports isolated in `redirect_runtime.go`.
- Do not add redirect fallback-to-allow behavior.
- Do not re-plan at `Bind` or `Execute`.
- Do not emit client-facing `NoticeResponse`.
- Preserve client prepared statement names exactly.
- Use `filepath.Join` for any new filesystem paths in integration helpers.
- Keep all Postgres proxy runtime files Linux-only unless a touched file is already platform-neutral.
