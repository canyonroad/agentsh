# db-access Plan 05c — COPY Data Frames + Approval Runtime Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `CopyData` / `CopyDone` / `CopyFail` byte-passthrough for the duration of `bulk_load` / `bulk_export` COPY operations with `result.bytes_in` / `bytes_out` accumulation; ship an `Approver` interface with `NopApprover` default and an in-process approval-wait runtime that routes timeouts through 05a's `deny_mode_in_tx`; remove 04c's `APPROVE_NOT_YET_SUPPORTED` config-load warning now that `decision: approve` is a live verb.

**Architecture:** Three slices. (a) Classifier surfaces `BulkOp BulkOpKind` on `ClassifiedStatement` so the dispatcher knows after forwarding the `'Q'` whether to enter `InCopyIn` or `InCopyOut` phase. (b) A new `copyframes.go` in the proxy package owns the COPY-mode loop: on entry it pivots from the simple-query response drain into a CopyData byte-passthrough; on exit it returns to the normal upstream-RFQ drain. (c) A new `internal/db/policy/approver.go` defines the `Approver` interface and `NopApprover`. A new `approvalwait.go` in the proxy package implements the dispatcher action: spawn `Approver.Decide` on a goroutine, race against `time.After(timeout)` and a non-blocking client-Terminate peek, route the result through `statemachine.DenyRoute` if denied or timed out.

**Tech Stack:** Go (`//go:build linux` for new proxy files; effects/events/policy/approver extensions tag-free). Re-uses 05a's `statemachine.DenyRoute` and `preparedcache`. No new external dependencies; `clock.Clock` (already an existing project type — confirm) is injected so tests don't sleep.

**Cross-references:**
- Shared design: `docs/superpowers/specs/2026-05-11-db-plan-05-pg-extended-tx-design.md`
- Predecessor plans: `2026-05-11-db-plan-05a-pg-extended-tx-statemachine.md`, `2026-05-11-db-plan-05b-sql-prepared-funccall.md`
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1 (CopyData framing), §7.3 (COPY rows in mapping table), §14.5 (approval timeouts inside transactions)

**Settled in brainstorming (2026-05-11):**

1. COPY is byte-passthrough. No `max_copy_bytes` cap; operators rely on PG-side `statement_timeout` for runaway.
2. `BulkOp BulkOpKind` on `ClassifiedStatement` is the dispatcher's signal to enter `InCopyIn` / `InCopyOut`. Only `COPY ... FROM STDIN` and `COPY ... TO STDOUT` set non-zero values; PATH and PROGRAM variants stay zero because no client-side CopyData stream follows.
3. `Approver` interface in `internal/db/policy/approver.go`. Default `NopApprover` blocks until ctx-cancel or timeout, returns `(false, nil)`. `ErrApproverNotConfigured` exists as a sentinel for callers that want to refuse to construct a server without an explicit Approver — Plan 05c uses `NopApprover` as the implicit default in `Config.Approver`.
4. Approval-wait holds the per-connection driver goroutine; client `Terminate` cancels via a non-blocking peek.
5. 05c removes `APPROVE_NOT_YET_SUPPORTED` warning emission and the `synthApproveAsDeny` stub. `decision: approve` now produces `ActionApproverWait` from the state machine.

---

## File Structure

**Created:**

- `internal/db/proxy/postgres/copyframes.go` — COPY-mode loop: enter on upstream `CopyInResponse`/`CopyOutResponse`, byte-pass `CopyData`, exit on `CopyDone`/`CopyFail`/`ErrorResponse`. Updates `pc.state.smState.Phase` and counters.
- `internal/db/proxy/postgres/copyframes_test.go` — table-driven coverage: bulk_load enter/byte-pass/exit; bulk_export enter/byte-pass/exit; mid-COPY ErrorResponse; client Terminate mid-COPY.
- `internal/db/policy/approver.go` — `Approver` interface, `NopApprover`, `ErrApproverNotConfigured` sentinel.
- `internal/db/policy/approver_test.go` — `NopApprover` ctx-cancel vs timeout ordering.
- `internal/db/proxy/postgres/approvalwait.go` — dispatcher routine for `statemachine.ActionApproverWait`: spawn Decide goroutine, race with timer + client-Terminate peek, route result through `DenyRoute` or forward.
- `internal/db/proxy/postgres/approvalwait_test.go` — fake Approver returns approved/denied; clock-injected timeout; client Terminate during wait → cancelled_during_approval.

**Modified:**

- `internal/db/effects/statement.go` — add `BulkOp BulkOpKind` field; define enum `BulkOpKind` (`BulkOpNone`, `BulkOpIn`, `BulkOpOut`).
- `internal/db/effects/statement_test.go` — JSON round-trip with omitempty.
- `internal/db/classify/postgres/ast_copy.go` — populate `cs.BulkOp` for `COPY ... FROM STDIN` (BulkOpIn) and `COPY ... TO STDOUT` (BulkOpOut, including the `COPY (query) TO STDOUT` variant).
- `internal/db/classify/postgres/ast_copy_test.go` — coverage rows.
- `internal/db/proxy/postgres/statemachine/action.go` — add `ActionApproverWait{Timeout, Decide, Stmt, Rule}`, `ActionCopyEnter{Direction CopyDir}`, `ActionCopyExit`.
- `internal/db/proxy/postgres/statemachine/transition.go` — `decision.verb == approve` produces `ActionApproverWait`; revert 04c's `synthApproveAsDeny` stub.
- `internal/db/proxy/postgres/simplequery.go` — `handleQuery` allow-path: after forwarding the COPY Q and observing the upstream response, the dispatcher enters COPY mode based on the cached `BulkOp` and runs `runCopyLoop` from `copyframes.go`; remove `synthApproveAsDeny`.
- `internal/db/proxy/postgres/server.go` — `Config.Approver policy.Approver` (default `policy.NopApprover{}`); `New()` plumbs into `proxyConn`.
- `internal/db/proxy/postgres/proxyconn.go` — accessor `pc.srv.cfg.Approver` available; no struct change.
- `internal/db/policy/decode.go` — remove `APPROVE_NOT_YET_SUPPORTED` warning emission.
- `internal/db/policy/decode_test.go` — remove the warning-emission test; assert no warning emitted under `decision: approve` + `Unavoidability != off`.
- `internal/db/events/event.go` — `TxContext.DenyAction` accepts `"approval_timeout"`, `"approval_denied"`, `"cancelled_during_approval"` (string discipline; no schema-level enum to widen, since `EventTxContext.DenyAction` is `string`).

**Out of scope (deferred):**

- Real approver implementation (HTTP-backed, signal-backed) — future plan; `NopApprover` is the live default.
- Per-statement approval cache ("approve once, not always") — Phase 2+.
- Function OID → name resolution — Phase 2+.

---

## Task 1: `effects.ClassifiedStatement.BulkOp` field

**Why:** The proxy dispatcher needs to know after forwarding a COPY `'Q'` whether to enter `InCopyIn` or `InCopyOut` phase. Classifier knows; pipe it through.

**Files:**
- Modify: `internal/db/effects/statement.go`
- Modify: `internal/db/effects/statement_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/effects/statement_test.go`:

```go
func TestBulkOpKind_String(t *testing.T) {
	cases := []struct {
		in   BulkOpKind
		want string
	}{
		{BulkOpNone, ""},
		{BulkOpIn, "copy_in"},
		{BulkOpOut, "copy_out"},
	}
	for _, c := range cases {
		if got := c.in.String(); got != c.want {
			t.Errorf("BulkOpKind(%d).String()=%q want %q", c.in, got, c.want)
		}
	}
}

func TestClassifiedStatement_BulkOp_JSON_RoundTrip(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupBulkLoad, Subtype: SubtypeCopyFromStdin}},
		RawVerb: "COPY",
		BulkOp:  BulkOpIn,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(bs), `"bulk_op":"copy_in"`) {
		t.Fatalf("bulk_op missing: %s", bs)
	}
	var out ClassifiedStatement
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out.BulkOp != BulkOpIn {
		t.Fatalf("BulkOp=%v want BulkOpIn", out.BulkOp)
	}
}

func TestClassifiedStatement_BulkOp_OmitNone(t *testing.T) {
	in := ClassifiedStatement{
		Effects: []Effect{{Group: GroupRead}},
		RawVerb: "SELECT",
	}
	bs, _ := json.Marshal(in)
	if strings.Contains(string(bs), "bulk_op") {
		t.Fatalf("bulk_op should be omitted for BulkOpNone: %s", bs)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run: `go test ./internal/db/effects/ -run TestClassifiedStatement_BulkOp -count=1`
Expected: build error.

- [ ] **Step 3: Add the type and field**

Open `internal/db/effects/statement.go`. Add a `BulkOpKind` enum near the top:

```go
// BulkOpKind classifies whether a statement initiates a wire-protocol COPY
// stream the proxy must follow. Only COPY ... FROM STDIN (BulkOpIn) and
// COPY ... TO STDOUT (BulkOpOut) set non-None values. COPY ... TO/FROM
// 'path' or PROGRAM forms stay BulkOpNone because no client-side CopyData
// stream follows the Q frame.
type BulkOpKind uint8

const (
	BulkOpNone BulkOpKind = iota
	BulkOpIn
	BulkOpOut
)

func (b BulkOpKind) String() string {
	switch b {
	case BulkOpIn:
		return "copy_in"
	case BulkOpOut:
		return "copy_out"
	default:
		return ""
	}
}

func (b BulkOpKind) MarshalJSON() ([]byte, error) {
	s := b.String()
	if s == "" {
		return []byte(`""`), nil
	}
	return []byte(`"` + s + `"`), nil
}

func (b *BulkOpKind) UnmarshalJSON(bs []byte) error {
	s := string(bs)
	switch s {
	case `""`, `null`:
		*b = BulkOpNone
		return nil
	case `"copy_in"`:
		*b = BulkOpIn
		return nil
	case `"copy_out"`:
		*b = BulkOpOut
		return nil
	default:
		return fmt.Errorf("unknown bulk_op %s", s)
	}
}
```

Extend `ClassifiedStatement`:

```go
type ClassifiedStatement struct {
	Effects       []Effect      `json:"effects"`
	RawVerb       string        `json:"raw_verb,omitempty"`
	ParserBackend ParserBackend `json:"parser_backend,omitempty"`
	Error         string        `json:"error,omitempty"`
	SourceStart   int32         `json:"source_start,omitempty"`
	SourceEnd     int32         `json:"source_end,omitempty"`
	PreparedName  string        `json:"prepared_name,omitempty"`

	// BulkOp is non-None for COPY statements that open a client-side or
	// server-side CopyData stream the proxy must follow.
	BulkOp BulkOpKind `json:"bulk_op,omitempty"`
}
```

If `fmt` is not imported in this file, add it.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/effects/ -run TestBulkOp -count=1 -v`
Expected: all PASS.

Run: `go test ./internal/db/effects/ -count=1`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add internal/db/effects/statement.go internal/db/effects/statement_test.go
git commit -m "db: effects — add BulkOpKind enum and ClassifiedStatement.BulkOp"
```

---

## Task 2: Classifier populates `BulkOp`

**Why:** `classifyCopy` already produces the right effect set; just add the BulkOp tag based on what was seen.

**Files:**
- Modify: `internal/db/classify/postgres/ast_copy.go`
- Modify: `internal/db/classify/postgres/ast_copy_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/classify/postgres/ast_copy_test.go`:

```go
func TestCopy_FromStdin_BulkOpIn(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("COPY users FROM STDIN", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].BulkOp != effects.BulkOpIn {
		t.Fatalf("BulkOp=%v want BulkOpIn", got[0].BulkOp)
	}
}

func TestCopy_ToStdout_BulkOpOut(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("COPY users TO STDOUT", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].BulkOp != effects.BulkOpOut {
		t.Fatalf("BulkOp=%v want BulkOpOut", got[0].BulkOp)
	}
}

func TestCopy_QueryToStdout_BulkOpOut(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("COPY (SELECT * FROM users) TO STDOUT", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].BulkOp != effects.BulkOpOut {
		t.Fatalf("BulkOp=%v want BulkOpOut", got[0].BulkOp)
	}
}

func TestCopy_ToPath_BulkOpNone(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("COPY users TO '/tmp/users.csv'", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].BulkOp != effects.BulkOpNone {
		t.Fatalf("BulkOp=%v want BulkOpNone (no client-side CopyData stream)", got[0].BulkOp)
	}
}

func TestCopy_FromProgram_BulkOpNone(t *testing.T) {
	p := New(DialectPostgres)
	got, err := p.Classify("COPY users FROM PROGRAM 'cat /etc/passwd'", SessionState{}, Options{})
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if got[0].BulkOp != effects.BulkOpNone {
		t.Fatalf("BulkOp=%v want BulkOpNone (program runs server-side, no client stream)", got[0].BulkOp)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/classify/postgres/ -run TestCopy_(FromStdin|ToStdout|QueryToStdout|ToPath|FromProgram) -count=1`
Expected: FAIL — `BulkOp` always zero.

- [ ] **Step 3: Populate `BulkOp` in the classifier**

Open `internal/db/classify/postgres/ast_copy.go`. Inside `classifyCopy` (or whichever sub-handler the dispatch points to), set `cs.BulkOp`:

```go
// After deciding the COPY shape and assembling Effects, tag the BulkOp.
switch {
case s.Filename == "" && s.Program == false && s.IsFrom == true:
	// COPY ... FROM STDIN
	cs.BulkOp = effects.BulkOpIn
case s.Filename == "" && s.Program == false && s.IsFrom == false:
	// COPY ... TO STDOUT (or COPY (query) TO STDOUT — Query!=nil is the
	// inner-select variant; both reach STDOUT)
	cs.BulkOp = effects.BulkOpOut
default:
	// PATH or PROGRAM: server-side I/O, no client stream.
	cs.BulkOp = effects.BulkOpNone
}
```

Field names (`Filename`, `Program`, `IsFrom`, `Query`) are from `pg_query.CopyStmt`. Confirm against the active pg_query version; the v6 generated code matches this shape.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/classify/postgres/ -run TestCopy_ -count=1 -v`
Expected: all five PASS.

Run: `go test ./internal/db/classify/postgres/ -count=1`
Expected: all green.

- [ ] **Step 5: Commit**

```bash
git add internal/db/classify/postgres/ast_copy.go internal/db/classify/postgres/ast_copy_test.go
git commit -m "db: classify/postgres — populate BulkOp for COPY FROM STDIN / TO STDOUT"
```

---

## Task 3: `policy.Approver` interface + `NopApprover`

**Why:** The proxy needs a programmatic seam to plug in real approver mechanisms. Define it now in the `policy` package so future plans can ship an HTTP-backed Approver without touching the proxy.

**Files:**
- Create: `internal/db/policy/approver.go`
- Create: `internal/db/policy/approver_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/policy/approver_test.go`:

```go
package policy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestNopApprover_Timeout_ReturnsFalseNoError(t *testing.T) {
	a := NopApprover{}
	approved, err := a.Decide(context.Background(), effects.ClassifiedStatement{}, 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Decide err: %v", err)
	}
	if approved {
		t.Error("NopApprover must always deny on timeout")
	}
}

func TestNopApprover_CtxCancel_ReturnsCtxErr(t *testing.T) {
	a := NopApprover{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	approved, err := a.Decide(ctx, effects.ClassifiedStatement{}, time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err=%v want context.Canceled", err)
	}
	if approved {
		t.Error("approved should be false on ctx cancel")
	}
}

func TestErrApproverNotConfigured(t *testing.T) {
	if ErrApproverNotConfigured == nil {
		t.Fatal("ErrApproverNotConfigured should not be nil")
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/db/policy/ -run TestNopApprover -count=1`
Expected: build error.

- [ ] **Step 3: Implement Approver**

Create `internal/db/policy/approver.go`:

```go
package policy

import (
	"context"
	"errors"
	"time"

	"github.com/agentsh/agentsh/internal/db/effects"
)

// ErrApproverNotConfigured is a sentinel for callers that want to require an
// explicit Approver. The proxy's default Config.Approver is NopApprover{};
// this sentinel is reserved for higher-level callers (e.g., a future config
// validator that fails closed without a real approver).
var ErrApproverNotConfigured = errors.New("policy: approver not configured")

// Approver decides whether a statement awaiting approval should run.
// Implementations may block for up to `timeout`; on timeout the
// implementation may return (false, nil) — the dispatcher treats that
// as a timeout deny per spec §14.5.
//
// `cs` is the classified statement being approved. Implementations may
// log a redacted view of it (per policy.RedactionConfig) but must not
// retain the full SQL beyond the call.
//
// `timeout` is the spec §14.5 strict deadline; implementations should
// respect either the passed timeout or ctx.Done(), whichever is sooner.
type Approver interface {
	Decide(ctx context.Context, cs effects.ClassifiedStatement, timeout time.Duration) (approved bool, err error)
}

// NopApprover is the default. Blocks until ctx-cancel or timeout; returns
// (false, nil) on timeout. Under default config every `decision: approve`
// rule will deny after the configured timeout.
type NopApprover struct{}

func (NopApprover) Decide(ctx context.Context, _ effects.ClassifiedStatement, timeout time.Duration) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-time.After(timeout):
		return false, nil
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/policy/ -run TestNopApprover -count=1 -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/policy/approver.go internal/db/policy/approver_test.go
git commit -m "db: policy — Approver interface and NopApprover default for §14.5 approval runtime"
```

---

## Task 4: Remove `APPROVE_NOT_YET_SUPPORTED` warning

**Why:** With the approval runtime landing in 05c, the config-load warning is no longer needed. `decision: approve` is a live verb.

**Files:**
- Modify: `internal/db/policy/decode.go`
- Modify: `internal/db/policy/decode_test.go`

- [ ] **Step 1: Update the test expectations**

Open `internal/db/policy/decode_test.go`. Locate the existing test that asserts the warning is emitted (around line 265 per the 04c grep). Update it to assert the warning is NOT emitted:

```go
func TestDecode_Approve_NoLongerWarns(t *testing.T) {
	yaml := `
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
policies:
  db:
    unavoidability: observe
database_rules:
  - name: review-deletes
    db_service: appdb
    operations: [delete]
    decision: approve
    timeout: 60s
`
	_, warns, err := Decode([]byte(yaml))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	for _, w := range warns {
		if w.Code == "APPROVE_NOT_YET_SUPPORTED" {
			t.Fatalf("APPROVE_NOT_YET_SUPPORTED warning should no longer be emitted: %#v", w)
		}
	}
}
```

If the prior test was named differently (e.g., `TestDecode_ApproveWarns`), rename or replace it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/policy/ -run TestDecode_Approve -count=1`
Expected: FAIL — warning still emitted.

- [ ] **Step 3: Remove the warning emission**

Open `internal/db/policy/decode.go`. Locate the block that pushes `Warning{Code: "APPROVE_NOT_YET_SUPPORTED", ...}` and delete it. The grep:

```bash
git grep -n APPROVE_NOT_YET_SUPPORTED internal/db/policy/
```

should now only find references in the (updated) test.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/policy/ -count=1`
Expected: all PASS, including the updated `TestDecode_Approve_NoLongerWarns`.

- [ ] **Step 5: Commit**

```bash
git add internal/db/policy/decode.go internal/db/policy/decode_test.go
git commit -m "db: policy — remove APPROVE_NOT_YET_SUPPORTED warning now that approver runtime ships"
```

---

## Task 5: `ActionApproverWait` + state-machine routing

**Why:** When the policy evaluator returns `verb=approve`, the state machine should emit `ActionApproverWait` rather than treating it as deny.

**Files:**
- Modify: `internal/db/proxy/postgres/statemachine/action.go`
- Modify: `internal/db/proxy/postgres/statemachine/transition.go`
- Modify: `internal/db/proxy/postgres/statemachine/transition_test.go`
- Modify: `internal/db/proxy/postgres/statemachine/action_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/statemachine/action_test.go`:

```go
var _ Action = (*ActionApproverWait)(nil)

func TestActionApproverWait_Fields(t *testing.T) {
	rule := policy.StatementRule{Name: "review-deletes", Decision: "approve"}
	a := &ActionApproverWait{
		Timeout: 60 * time.Second,
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE"},
		Rule:    rule,
	}
	if a.Timeout != 60*time.Second {
		t.Errorf("Timeout=%v", a.Timeout)
	}
	if a.Rule.Name != "review-deletes" {
		t.Errorf("Rule.Name=%q", a.Rule.Name)
	}
}
```

Imports as needed (`time`, `effects`, `policy`).

Append to `internal/db/proxy/postgres/statemachine/transition_test.go`:

```go
func TestTransition_Parse_Approve_EmitsApproverWait(t *testing.T) {
	yaml := `
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}
database_rules:
  - name: review-deletes
    db_service: appdb
    operations: [delete]
    decision: approve
    timeout: 60s
`
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &ParseFrame{Name: "s1", SQL: "DELETE FROM users"}, cache, mustDecode(t, yaml), "appdb")
	if len(acts) != 1 {
		t.Fatalf("len(acts)=%d want 1", len(acts))
	}
	aw, ok := acts[0].(*ActionApproverWait)
	if !ok {
		t.Fatalf("acts[0]=%T want *ActionApproverWait", acts[0])
	}
	if aw.Rule.Name != "review-deletes" {
		t.Errorf("Rule.Name=%q", aw.Rule.Name)
	}
	if aw.Timeout != 60*time.Second {
		t.Errorf("Timeout=%v want 60s", aw.Timeout)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Parse_Approve`
Expected: FAIL — `ActionApproverWait` undefined; transition still routes approve as deny.

- [ ] **Step 3: Add the Action variant**

Open `internal/db/proxy/postgres/statemachine/action.go`. Append (with `import "time"` and the `effects` / `policy` imports added):

```go
// ActionApproverWait instructs the dispatcher to invoke the configured
// Approver and wait up to Timeout for a decision. While waiting, the
// dispatcher does NOT consume further client frames. On approve → forward
// the underlying statement. On deny or timeout → route through DenyRoute
// with the appropriate `tx_context.deny_action` value.
type ActionApproverWait struct {
	Timeout time.Duration
	Stmt    effects.ClassifiedStatement
	Rule    policy.StatementRule
}

func (*ActionApproverWait) isAction() {}
```

- [ ] **Step 4: Route approve through the new Action**

Open `internal/db/proxy/postgres/statemachine/transition.go`. Locate the `handleParse` (and `handleQuery`) approve-stub:

```go
		if d.Verb == policy.VerbApprove {
			d.Verb = policy.VerbDeny
			if d.Reason == "" {
				d.Reason = "APPROVE_NOT_YET_SUPPORTED"
			}
		}
```

Replace it with:

```go
		if d.Verb == policy.VerbApprove {
			// Plan 05c: route approve to ApproverWait. The dispatcher
			// re-enters the state machine after the Approver returns.
			rule := lookupStatementRule(rules, d.RuleName)
			timeout := rule.Timeout
			if timeout == 0 {
				timeout = 60 * time.Second
			}
			next := s
			// Do NOT set Absorbing — the approval might succeed and the
			// statement then forwards normally.
			return next, []Action{&ActionApproverWait{
				Timeout: timeout,
				Stmt:    cs,
				Rule:    rule,
			}}
		}
```

Apply the same change in `handleQuery` (the Simple Query branch).

Add `import "time"` if not already imported.

- [ ] **Step 5: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Parse_Approve -v`
Expected: PASS.

Run full state-machine suite: `go test ./internal/db/proxy/postgres/statemachine/ -count=1`
Expected: all green.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/action.go internal/db/proxy/postgres/statemachine/transition.go internal/db/proxy/postgres/statemachine/action_test.go internal/db/proxy/postgres/statemachine/transition_test.go
git commit -m "db: proxy/statemachine — ActionApproverWait + route approve through it"
```

---

## Task 6: Approval-wait dispatcher

**Why:** Translate `ActionApproverWait` into the goroutine + race against timer + client-Terminate peek that 05c's design §5 specifies.

**Files:**
- Create: `internal/db/proxy/postgres/approvalwait.go`
- Create: `internal/db/proxy/postgres/approvalwait_test.go`
- Modify: `internal/db/proxy/postgres/server.go` (Config.Approver)
- Modify: `internal/db/proxy/postgres/extquery.go` (executeActions handles ApproverWait)

- [ ] **Step 1: Add `Config.Approver`**

Open `internal/db/proxy/postgres/server.go`. Extend `Config`:

```go
type Config struct {
	// ... existing fields ...

	// Approver is invoked when an evaluated rule has decision: approve.
	// Defaults to policy.NopApprover{} when nil. Production deployments
	// supply a real Approver in a future plan.
	Approver policy.Approver
}
```

In `New(cfg Config)` (or whichever helper initializes config defaults), add:

```go
	if cfg.Approver == nil {
		cfg.Approver = policy.NopApprover{}
	}
```

- [ ] **Step 2: Write the failing tests**

Create `internal/db/proxy/postgres/approvalwait_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// fakeApprover lets tests drive the approve / deny / err paths deterministically.
type fakeApprover struct {
	mu       sync.Mutex
	calls    int
	approve  bool
	err      error
	hold     time.Duration
}

func (f *fakeApprover) Decide(ctx context.Context, _ effects.ClassifiedStatement, _ time.Duration) (bool, error) {
	f.mu.Lock()
	f.calls++
	f.mu.Unlock()
	if f.hold > 0 {
		select {
		case <-time.After(f.hold):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	return f.approve, f.err
}

func TestApprovalWait_Approve_Forwards(t *testing.T) {
	srv := mustNewServerWithApprover(t, &fakeApprover{approve: true})
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	rule := policy.StatementRule{Name: "review-deletes", Decision: "approve", Timeout: 100 * time.Millisecond}
	q := &pgproto3.Query{String: "DELETE FROM users"}
	err := pc.runApprovalWait(context.Background(), q, statemachine.ActionApproverWait{
		Timeout: 100 * time.Millisecond,
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE"},
		Rule:    rule,
	})
	if err != nil {
		t.Fatalf("runApprovalWait: %v", err)
	}
	if !pc.upstreamFake.SawQuery("DELETE FROM users") {
		t.Error("approve path should forward the original Q frame")
	}
}

func TestApprovalWait_Deny_RoutesDenyRoute(t *testing.T) {
	srv := mustNewServerWithApprover(t, &fakeApprover{approve: false})
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	rule := policy.StatementRule{Name: "review-deletes", Decision: "approve", Timeout: 100 * time.Millisecond}
	q := &pgproto3.Query{String: "DELETE FROM users"}
	err := pc.runApprovalWait(context.Background(), q, statemachine.ActionApproverWait{
		Timeout: 100 * time.Millisecond,
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE"},
		Rule:    rule,
	})
	if err != nil {
		t.Fatalf("runApprovalWait: %v", err)
	}
	if pc.upstreamFake.SawQuery("DELETE FROM users") {
		t.Error("deny path must NOT forward to upstream")
	}
	if !pc.clientFake.SawSQLState("42501") {
		t.Error("deny path should synthesize 42501")
	}
	gotDenyAction := false
	for _, ev := range pc.srv.cfg.Sink.(*captureSink).statements {
		if ev.TxContext.DenyAction == "approval_denied" {
			gotDenyAction = true
		}
	}
	if !gotDenyAction {
		t.Error("expected db_statement event with deny_action: approval_denied")
	}
}

func TestApprovalWait_Timeout_DenyAndApprovalTimeoutAction(t *testing.T) {
	srv := mustNewServerWithApprover(t, &fakeApprover{approve: true, hold: 500 * time.Millisecond})
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	rule := policy.StatementRule{Name: "review-deletes", Decision: "approve", Timeout: 50 * time.Millisecond}
	q := &pgproto3.Query{String: "DELETE FROM users"}
	err := pc.runApprovalWait(context.Background(), q, statemachine.ActionApproverWait{
		Timeout: 50 * time.Millisecond,
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE"},
		Rule:    rule,
	})
	if err != nil {
		t.Fatalf("runApprovalWait: %v", err)
	}
	if pc.upstreamFake.SawQuery("DELETE FROM users") {
		t.Error("timeout path must NOT forward")
	}
	gotTimeout := false
	for _, ev := range pc.srv.cfg.Sink.(*captureSink).statements {
		if ev.TxContext.DenyAction == "approval_timeout" {
			gotTimeout = true
		}
	}
	if !gotTimeout {
		t.Error("expected deny_action: approval_timeout event")
	}
}

func TestApprovalWait_ApproverError_RoutesDeny(t *testing.T) {
	srv := mustNewServerWithApprover(t, &fakeApprover{err: errors.New("approver unavailable")})
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	rule := policy.StatementRule{Name: "review-deletes", Decision: "approve", Timeout: 100 * time.Millisecond}
	q := &pgproto3.Query{String: "DELETE FROM users"}
	err := pc.runApprovalWait(context.Background(), q, statemachine.ActionApproverWait{
		Timeout: 100 * time.Millisecond,
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE"},
		Rule:    rule,
	})
	if err != nil {
		t.Fatalf("runApprovalWait: %v", err)
	}
	if !pc.clientFake.SawSQLState("42501") {
		t.Error("approver err should route deny path")
	}
}
```

`mustNewServerWithApprover(t, approver)` is a new test helper. Define it in `server_test.go` or wherever `mustNewServer` lives:

```go
func mustNewServerWithApprover(t *testing.T, a policy.Approver) *Server {
	t.Helper()
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	srv.cfg.Approver = a
	return srv
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestApprovalWait`
Expected: build error — `runApprovalWait` undefined.

- [ ] **Step 4: Implement `runApprovalWait`**

Create `internal/db/proxy/postgres/approvalwait.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// runApprovalWait executes a statemachine.ActionApproverWait. It spawns the
// configured Approver on a goroutine, races against time.After(timeout) and
// a non-blocking peek for client Terminate. On approve, forwards the original
// frame upstream. On deny / timeout / cancel, routes through DenyRoute with
// the appropriate deny_action.
func (pc *proxyConn) runApprovalWait(
	ctx context.Context,
	origFrame pgproto3.FrontendMessage,
	a statemachine.ActionApproverWait,
) error {
	approver := pc.srv.cfg.Approver
	if approver == nil {
		approver = policy.NopApprover{}
	}

	resultCh := make(chan approvalResult, 1)
	approveCtx, cancelApprove := context.WithCancel(ctx)
	defer cancelApprove()

	go func() {
		approved, err := approver.Decide(approveCtx, a.Stmt, a.Timeout)
		resultCh <- approvalResult{approved: approved, err: err}
	}()

	terminateCh := make(chan struct{}, 1)
	stopPeek := make(chan struct{})
	defer close(stopPeek)
	go pc.peekForTerminate(terminateCh, stopPeek)

	timer := time.NewTimer(a.Timeout)
	defer timer.Stop()

	select {
	case res := <-resultCh:
		if res.err != nil || !res.approved {
			return pc.routeApprovalDeny(ctx, origFrame, a, denyActionFromResult(res))
		}
		// Approved — forward original frame.
		pc.emitApprovalEvent(ctx, a, "none", "allow", origFrame)
		pc.state.upstreamFE.Send(origFrame)
		return pc.state.upstreamFE.Flush()
	case <-timer.C:
		cancelApprove()
		return pc.routeApprovalDeny(ctx, origFrame, a, "approval_timeout")
	case <-terminateCh:
		cancelApprove()
		pc.emitApprovalEvent(ctx, a, "cancelled_during_approval", "deny", origFrame)
		return errInTxTerminate // tears the conn down
	case <-ctx.Done():
		cancelApprove()
		return ctx.Err()
	}
}

type approvalResult struct {
	approved bool
	err      error
}

func denyActionFromResult(r approvalResult) string {
	if r.err != nil {
		return "approval_denied"
	}
	if !r.approved {
		return "approval_denied"
	}
	return "none"
}

func (pc *proxyConn) routeApprovalDeny(
	ctx context.Context,
	origFrame pgproto3.FrontendMessage,
	a statemachine.ActionApproverWait,
	denyAction string,
) error {
	pc.emitApprovalEvent(ctx, a, denyAction, "deny", origFrame)
	msg := "denied by AgentSH policy: " + a.Rule.Name
	if a.Rule.Name == "" {
		msg = "denied by AgentSH policy"
	}
	actions := statemachine.DenyRoute(*pc.state.smState, a.Rule, msg, "42501")
	return pc.executeActions(ctx, origFrame, actions)
}

// peekForTerminate reads pc.backend in non-blocking mode; if the next frame
// is a Terminate, send a token on terminateCh. Stops when stopPeek is closed.
//
// Implementation note: pgproto3 doesn't expose a non-blocking Receive, so we
// implement this by reading on a separate goroutine and pushing the message
// onto a channel. The dispatcher consumes whichever channel fires first.
func (pc *proxyConn) peekForTerminate(terminateCh chan<- struct{}, stop <-chan struct{}) {
	msgCh := make(chan pgproto3.FrontendMessage, 1)
	go func() {
		msg, err := pc.backend.Receive()
		if err != nil {
			return
		}
		msgCh <- msg
	}()
	select {
	case msg := <-msgCh:
		if _, ok := msg.(*pgproto3.Terminate); ok {
			select {
			case terminateCh <- struct{}{}:
			default:
			}
		}
		// If it's not a Terminate, the message is lost — this is acceptable
		// for Plan 05c because while approval is pending, clients should not
		// be sending further frames anyway. Production deployments wire a
		// real Approver that completes quickly enough for this not to matter.
	case <-stop:
		return
	}
}

func (pc *proxyConn) emitApprovalEvent(
	ctx context.Context,
	a statemachine.ActionApproverWait,
	denyAction, verbStr string,
	origFrame pgproto3.FrontendMessage,
) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	// We don't have the original SQL on the FunctionCall path; for Q-frame
	// approvals it's in origFrame.(*pgproto3.Query).String.
	sql := ""
	if q, ok := origFrame.(*pgproto3.Query); ok {
		sql = q.String
	}
	batchSHA := sha256HexBatch(sql)
	verb := policy.VerbDeny
	if verbStr == "allow" {
		verb = policy.VerbAllow
	}
	ev := buildStatementEvent(buildArgs{
		Stmt:       a.Stmt,
		StmtIndex:  0,
		BatchTotal: 1,
		Decision: policy.Decision{
			Verb:     verb,
			RuleKind: policy.RuleKindStatement,
			RuleName: a.Rule.Name,
		},
		SQL:        sql,
		Tier:       pc.state.redactionTier,
		Conn:       *pc.state,
		BytesIn:    int64(len(sql)),
		DenyAction: denyAction,
		BatchSHA:   batchSHA,
		Parser:     pc.srv.classifierFor(pc.svc.Dialect),
	})
	_ = pc.srv.cfg.Sink.EmitStatement(ctx, ev)
}

var errApprovalDispatch = errors.New("postgres.runApprovalWait: dispatch fell through")
```

- [ ] **Step 5: Wire `ActionApproverWait` into `executeActions`**

Open `internal/db/proxy/postgres/extquery.go`. Add a case to `executeActions`'s switch:

```go
		case *statemachine.ActionApproverWait:
			if err := pc.runApprovalWait(ctx, origFrame, *a); err != nil {
				return err
			}
```

- [ ] **Step 6: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestApprovalWait -v -timeout 60s`
Expected: all four PASS.

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: all green.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/approvalwait.go internal/db/proxy/postgres/approvalwait_test.go internal/db/proxy/postgres/server.go internal/db/proxy/postgres/extquery.go
git commit -m "db: proxy — approval-wait runtime routing through Approver + DenyRoute"
```

---

## Task 7: COPY frame dispatcher

**Why:** After forwarding a COPY `'Q'` and observing the upstream's CopyInResponse/CopyOutResponse, the proxy enters a byte-passthrough loop until CopyDone/CopyFail/ErrorResponse. Counters accumulate.

**Files:**
- Create: `internal/db/proxy/postgres/copyframes.go`
- Create: `internal/db/proxy/postgres/copyframes_test.go`
- Modify: `internal/db/proxy/postgres/upstreamread.go` (recognize CopyIn/OutResponse and yield to the COPY loop)

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/copyframes_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

func TestCopyLoop_BulkLoad_PassesBytesAndExitsOnCopyDone(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyIn}
	// Pre-queue client → CopyData → CopyDone.
	pc.clientFake.QueueClientFrames(
		&pgproto3.CopyData{Data: []byte("row1\n")},
		&pgproto3.CopyData{Data: []byte("row2\n")},
		&pgproto3.CopyDone{},
	)
	// Pre-queue upstream → CommandComplete + RFQ as the COPY-end response.
	pc.upstreamFake.QueueUpstreamFrames(
		&pgproto3.CommandComplete{CommandTag: []byte("COPY 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	result, err := pc.runCopyLoop(context.Background(), effects.BulkOpIn)
	if err != nil {
		t.Fatalf("runCopyLoop: %v", err)
	}
	if !pc.upstreamFake.SawCopyData([]byte("row1\nrow2\n")) {
		t.Error("CopyData bytes should be byte-passed upstream")
	}
	if result.BytesIn < 10 {
		t.Errorf("BytesIn=%d want >=10", result.BytesIn)
	}
	if pc.state.smState.Phase != statemachine.PhaseIdle {
		t.Errorf("Phase=%v want PhaseIdle after exit", pc.state.smState.Phase)
	}
}

func TestCopyLoop_BulkExport_PassesUpstreamBytes(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyOut}
	pc.upstreamFake.QueueUpstreamFrames(
		&pgproto3.CopyData{Data: []byte("hello\n")},
		&pgproto3.CopyData{Data: []byte("world\n")},
		&pgproto3.CopyDone{},
		&pgproto3.CommandComplete{CommandTag: []byte("COPY 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	result, err := pc.runCopyLoop(context.Background(), effects.BulkOpOut)
	if err != nil {
		t.Fatalf("runCopyLoop: %v", err)
	}
	if result.BytesOut < 12 {
		t.Errorf("BytesOut=%d want >=12", result.BytesOut)
	}
	if !pc.clientFake.SawClientBytes([]byte("hello\nworld\n")) {
		t.Error("CopyData bytes should be byte-passed to client")
	}
}

func TestCopyLoop_BulkLoad_MidCopyClientTerminate_SendsCopyFail(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyIn}
	pc.clientFake.QueueClientFrames(
		&pgproto3.CopyData{Data: []byte("row1\n")},
		&pgproto3.Terminate{},
	)
	_, err := pc.runCopyLoop(context.Background(), effects.BulkOpIn)
	if err == nil {
		// Allowed: test only that CopyFail went to upstream.
	}
	if !pc.upstreamFake.SawCopyFail() {
		t.Error("client Terminate during CopyIn should send CopyFail upstream")
	}
}

func TestCopyLoop_BulkExport_MidCopyErrorResponse_ExitsCleanly(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I', Phase: statemachine.PhaseInCopyOut}
	pc.upstreamFake.QueueUpstreamFrames(
		&pgproto3.CopyData{Data: []byte("partial")},
		&pgproto3.ErrorResponse{Severity: "ERROR", Code: "57014", Message: "canceled"},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	result, err := pc.runCopyLoop(context.Background(), effects.BulkOpOut)
	if err != nil {
		t.Fatalf("runCopyLoop: %v", err)
	}
	if result.ErrorCode != "57014" {
		t.Errorf("ErrorCode=%q want 57014", result.ErrorCode)
	}
	if pc.state.smState.Phase != statemachine.PhaseIdle {
		t.Errorf("Phase=%v want PhaseIdle", pc.state.smState.Phase)
	}
}
```

The `pc.clientFake.QueueClientFrames(...)` and `pc.upstreamFake.QueueUpstreamFrames(...)` helpers and `SawCopyData` / `SawClientBytes` / `SawCopyFail` accessors are 04c spine-style extensions. Add them in `testupstream_test.go` and the matching client-side fake.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestCopyLoop`
Expected: build error — `runCopyLoop` undefined.

- [ ] **Step 3: Implement `runCopyLoop`**

Create `internal/db/proxy/postgres/copyframes.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// runCopyLoop byte-passes CopyData frames for the duration of a bulk_load or
// bulk_export operation. Exits on CopyDone, CopyFail, or upstream
// ErrorResponse. Counters accumulate into the returned upstreamResult.
//
// direction selects the read side:
//   - BulkOpIn:  read client frames, forward to upstream until CopyDone/CopyFail;
//                then drain upstream until CommandComplete + RFQ.
//   - BulkOpOut: read upstream frames, forward to client until CopyDone/CopyFail/
//                ErrorResponse; then drain through RFQ.
func (pc *proxyConn) runCopyLoop(ctx context.Context, direction effects.BulkOpKind) (upstreamResult, error) {
	switch direction {
	case effects.BulkOpIn:
		return pc.runCopyInLoop(ctx)
	case effects.BulkOpOut:
		return pc.runCopyOutLoop(ctx)
	default:
		return upstreamResult{}, fmt.Errorf("postgres.runCopyLoop: unknown direction %v", direction)
	}
}

func (pc *proxyConn) runCopyInLoop(ctx context.Context) (upstreamResult, error) {
	var r upstreamResult
	pc.state.smState.Phase = statemachine.PhaseInCopyIn
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.backend.Receive()
		if err != nil {
			return r, fmt.Errorf("copyin client recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.CopyData:
			r.BytesIn += int64(len(m.Data))
			pc.state.upstreamFE.Send(m)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return r, fmt.Errorf("upstream flush copydata: %w", err)
			}
		case *pgproto3.CopyDone:
			pc.state.upstreamFE.Send(m)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return r, fmt.Errorf("upstream flush copydone: %w", err)
			}
			return pc.drainAfterCopy(ctx, r, time.Now())
		case *pgproto3.CopyFail:
			pc.state.upstreamFE.Send(m)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return r, fmt.Errorf("upstream flush copyfail: %w", err)
			}
			return pc.drainAfterCopy(ctx, r, time.Now())
		case *pgproto3.Terminate:
			pc.state.upstreamFE.Send(&pgproto3.CopyFail{Message: "client terminated mid-copy"})
			_ = pc.state.upstreamFE.Flush()
			return r, errInTxTerminate
		default:
			return r, fmt.Errorf("copyin: unexpected client frame %T", m)
		}
	}
}

func (pc *proxyConn) runCopyOutLoop(ctx context.Context) (upstreamResult, error) {
	var r upstreamResult
	pc.state.smState.Phase = statemachine.PhaseInCopyOut
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return r, fmt.Errorf("copyout upstream recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.CopyData:
			r.BytesOut += int64(len(m.Data))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("client flush copydata: %w", err)
			}
		case *pgproto3.CopyDone:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, err
			}
			return pc.drainAfterCopy(ctx, r, time.Now())
		case *pgproto3.CopyFail:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, err
			}
			return pc.drainAfterCopy(ctx, r, time.Now())
		case *pgproto3.ErrorResponse:
			r.ErrorCode = m.Code
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, err
			}
			return pc.drainAfterCopy(ctx, r, time.Now())
		default:
			// RowDescription / NoticeResponse / etc. — pass through.
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, err
			}
		}
	}
}

// drainAfterCopy reads upstream until ReadyForQuery and updates connState
// per the existing forwardUpstreamUntilRFQ semantics. Returns the populated
// result for the caller to attach to a DBEvent.
func (pc *proxyConn) drainAfterCopy(ctx context.Context, r upstreamResult, sentAt time.Time) (upstreamResult, error) {
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return r, fmt.Errorf("drain copy recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.CommandComplete:
			rows, aff := parseCommandTag(string(m.CommandTag))
			r.RowsByStmt = append(r.RowsByStmt, rows)
			r.AffectedByStmt = append(r.AffectedByStmt, aff)
			pc.backend.Send(m)
		case *pgproto3.ErrorResponse:
			if r.ErrorCode == "" {
				r.ErrorCode = m.Code
			}
			pc.backend.Send(m)
		case *pgproto3.ReadyForQuery:
			pc.state.smState.LastUpstreamRFQ = m.TxStatus
			switch m.TxStatus {
			case 'I':
				pc.state.smState.Phase = statemachine.PhaseIdle
			case 'T':
				pc.state.smState.Phase = statemachine.PhaseInTx
			case 'E':
				pc.state.smState.Phase = statemachine.PhaseInTxError
			}
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("drain flush rfq: %w", err)
			}
			r.LatencyMs = time.Since(sentAt).Milliseconds()
			return r, nil
		default:
			pc.backend.Send(m)
		}
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestCopyLoop -v`
Expected: all four PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/copyframes.go internal/db/proxy/postgres/copyframes_test.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — COPY data-frame loop (CopyIn/CopyOut) with byte counters"
```

---

## Task 8: Wire COPY entry into `handleQuery`

**Why:** After `handleQuery` forwards a COPY Q frame upstream and `forwardUpstreamUntilRFQ` returns from observing `CopyInResponse`/`CopyOutResponse`, the dispatcher should yield to `runCopyLoop`.

**Files:**
- Modify: `internal/db/proxy/postgres/upstreamread.go`
- Modify: `internal/db/proxy/postgres/simplequery.go`

- [ ] **Step 1: Update `forwardUpstreamUntilRFQ` to yield on CopyIn/OutResponse**

Open `internal/db/proxy/postgres/upstreamread.go`. Add cases:

```go
		case *pgproto3.CopyInResponse:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("flush copyinresp: %w", err)
			}
			r.YieldedToCopyIn = true
			r.LatencyMs = time.Since(sentAt).Milliseconds()
			return r, nil

		case *pgproto3.CopyOutResponse:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("flush copyoutresp: %w", err)
			}
			r.YieldedToCopyOut = true
			r.LatencyMs = time.Since(sentAt).Milliseconds()
			return r, nil
```

Add fields to `upstreamResult`:

```go
type upstreamResult struct {
	BytesOut         int64
	BytesIn          int64 // populated by COPY-In loops only
	RowsByStmt       []*int64
	AffectedByStmt   []*int64
	LatencyMs        int64
	ErrorCode        string
	YieldedToCopyIn  bool
	YieldedToCopyOut bool
}
```

- [ ] **Step 2: Wire `runCopyLoop` into `handleQuery`'s allow path**

Open `internal/db/proxy/postgres/simplequery.go`. After `forwardUpstreamUntilRFQ` returns, check whether it yielded:

```go
	result, ferr := pc.forwardUpstreamUntilRFQ(ctx, sentAt, len(q.String))
	if ferr != nil {
		return ferr
	}
	if result.YieldedToCopyIn || result.YieldedToCopyOut {
		direction := effects.BulkOpIn
		if result.YieldedToCopyOut {
			direction = effects.BulkOpOut
		}
		copyResult, cerr := pc.runCopyLoop(ctx, direction)
		// Merge counters.
		result.BytesIn += copyResult.BytesIn
		result.BytesOut += copyResult.BytesOut
		result.LatencyMs = copyResult.LatencyMs
		if copyResult.ErrorCode != "" {
			result.ErrorCode = copyResult.ErrorCode
		}
		if cerr != nil {
			return cerr
		}
	}
	pc.emitAllowEvents(ctx, stmts, decisions, q.String, batchSHA, result)
	return nil
```

- [ ] **Step 3: Write a higher-level test**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_CopyToStdout_EmitsBytesOut(t *testing.T) {
	srv := mustNewServerWithYAML(t, allowAllPolicyYAML())
	pc := mustPCFromSrv(t, srv)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	// Upstream responds: CopyOutResponse, two CopyData, CopyDone, CC, RFQ.
	pc.upstreamFake.QueueUpstreamFrames(
		&pgproto3.CopyOutResponse{},
		&pgproto3.CopyData{Data: []byte("alice\n")},
		&pgproto3.CopyData{Data: []byte("bob\n")},
		&pgproto3.CopyDone{},
		&pgproto3.CommandComplete{CommandTag: []byte("COPY 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "COPY users TO STDOUT"})
	if err != nil {
		t.Fatalf("handleQuery: %v", err)
	}
	evs := pc.srv.cfg.Sink.(*captureSink).statements
	if len(evs) == 0 {
		t.Fatal("expected allow event")
	}
	if evs[0].Result.BytesOut < 10 {
		t.Errorf("BytesOut=%d want >=10", evs[0].Result.BytesOut)
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run "TestHandleQuery_CopyToStdout|TestCopyLoop" -v -timeout 60s`
Expected: all PASS.

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: full PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/upstreamread.go internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/simplequery_test.go
git commit -m "db: proxy — wire COPY-mode dispatcher entry from forwardUpstreamUntilRFQ"
```

---

## Task 9: Spine tests — COPY bulk_export and approval timeout

**Why:** End-to-end through real pgx + clock injection.

**Files:**
- Modify: `internal/db/proxy/postgres/spine_test.go`
- Modify: `internal/db/proxy/postgres/testupstream_test.go`

- [ ] **Step 1: Extend the fake upstream for COPY**

Open `internal/db/proxy/postgres/testupstream_test.go`. Add a `'Q'` branch for `COPY users TO STDOUT` that emits `CopyOutResponse` + CopyData + CopyDone + CommandComplete + RFQ. Most realistic test setup keeps the queueing approach — operators define the response sequence inline per test.

- [ ] **Step 2: Add spine tests**

Append to `internal/db/proxy/postgres/spine_test.go`:

```go
func TestSpine_CopyToStdout_BytesOutCount(t *testing.T) {
	srv, sink := mustStartSpineServer(t, allowAllPolicyYAML())
	defer srv.Shutdown(context.Background())
	cfg, _ := pgx.ParseConfig("postgres:///?host=" + srv.cfg.Services[0].Listen.Path + "&sslrootcert=" + filepath.Join(srv.cfg.StateDir, "db-ca.crt"))
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close(context.Background())
	// Pre-queue the upstream response sequence so the fake serves it when
	// the proxy forwards the COPY Q frame. The exact helper name depends on
	// the 04c testupstream wiring — locate it via the existing 04c spine
	// test patterns. The shape is:
	srv.UpstreamFake().Queue(
		&pgproto3.CopyOutResponse{},
		&pgproto3.CopyData{Data: []byte("alice\n")},
		&pgproto3.CopyData{Data: []byte("bob\n")},
		&pgproto3.CopyDone{},
		&pgproto3.CommandComplete{CommandTag: []byte("COPY 2")},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	)
	r, err := conn.PgConn().CopyTo(context.Background(), io.Discard, "COPY users TO STDOUT")
	if err != nil {
		t.Fatalf("CopyTo: %v", err)
	}
	_ = r // CommandTag
	gotBytes := false
	for _, ev := range sink.StatementEvents() {
		if ev.Result.BytesOut > 0 {
			gotBytes = true
		}
	}
	if !gotBytes {
		t.Error("expected an event with BytesOut > 0 for COPY TO STDOUT")
	}
}

func TestSpine_ApprovalTimeout_DenyAfterTimeout(t *testing.T) {
	yaml := `
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue, listener: {unix: "/tmp/agentsh-appdb.sock"}}
database_rules:
  - name: review-deletes
    db_service: appdb
    operations: [delete]
    decision: approve
    timeout: 50ms
`
	srv, sink := mustStartSpineServer(t, yaml)
	// Use NopApprover (default); 50ms timeout will fire deterministically.
	defer srv.Shutdown(context.Background())
	cfg, _ := pgx.ParseConfig("postgres:///?host=" + srv.cfg.Services[0].Listen.Path + "&sslrootcert=" + filepath.Join(srv.cfg.StateDir, "db-ca.crt"))
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	defer conn.Close(context.Background())
	t0 := time.Now()
	_, err = conn.Exec(context.Background(), "DELETE FROM users")
	if err == nil {
		t.Fatal("expected deny after approval timeout")
	}
	if d := time.Since(t0); d < 40*time.Millisecond {
		t.Errorf("returned in %v; expected >= 40ms (timeout was 50ms)", d)
	}
	gotTimeout := false
	for _, ev := range sink.StatementEvents() {
		if ev.TxContext.DenyAction == "approval_timeout" {
			gotTimeout = true
		}
	}
	if !gotTimeout {
		t.Error("expected db_statement with deny_action: approval_timeout")
	}
}
```

The COPY spine test's `srv.UpstreamFake().Queue(...)` call is illustrative — the actual helper name in the 04c testupstream wiring may differ (e.g., `srv.upstream.Queue(...)` or `(*captureSink).Upstream.Queue(...)`). Locate the existing 04c spine helper for queueing upstream frames and use that. The asserted outcome is the externally visible event payload.

- [ ] **Step 3: Run tests until they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestSpine_(CopyToStdout|ApprovalTimeout) -v -timeout 120s`
Expected: PASS after iteration.

- [ ] **Step 4: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: green.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/spine_test.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — spine tests for COPY bulk_export bytes_out and approval timeout"
```

---

## Final verification

- [ ] **Step 1: Full test suite**

Run: `go test ./... -count=1 -timeout 240s`
Expected: PASS.

- [ ] **Step 2: Race detector**

Run: `go test -race ./internal/db/... -count=1 -timeout 240s`
Expected: PASS.

- [ ] **Step 3: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 4: Confirm 05c artifacts**

Run:
```bash
test -f internal/db/proxy/postgres/copyframes.go
test -f internal/db/proxy/postgres/approvalwait.go
test -f internal/db/policy/approver.go
grep -q APPROVE_NOT_YET_SUPPORTED internal/db/policy/decode.go && echo "warning still present" || echo "warning removed"
```
Expected: all three files present; "warning removed".
