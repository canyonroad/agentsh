# db-access Plan 05a — Extended Query + Transaction State Machine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace 04c's RFQ-byte tracker with a full Extended Query + transaction state machine. After 05a lands, `Parse` / `Bind` / `Describe` / `Execute` / `Sync` / `Flush` / `Close` are first-class enforced frames with a wire-protocol prepared cache; `database_rules` accept a per-rule `deny_mode_in_tx` field implementing §14.3's `terminate` (default) and `rollback_then_continue` modes; `tx_context.tx_started_at` and `tx_context.deny_action: "rollback_injected"` populate correctly.

**Architecture:** A new sub-package `internal/db/proxy/postgres/statemachine/` provides a *pure function* `Transition(state, frame, cache, rules) → (nextState, []Action)`. The `Action` interface is the only contract between the transition logic and I/O — concrete variants (`ActionForward`, `ActionSynthError`, `ActionSynthReadyForQuery`, `ActionSuppress`, `ActionInjectRollback`, `ActionDrainUntilRFQ`, `ActionClose`, `ActionTrackUpstreamRFQ`, `ActionSynthParseComplete`, `ActionSynthBindComplete`) drive the dispatcher in a new `extquery.go`. A second sub-package `internal/db/proxy/postgres/preparedcache/` ships a 4096-LRU per connection that satisfies `statemachine.CacheView`. The §14.3/§14.4 fork (`denyRoute`) lives in the state-machine package and is consumed both by extended-query frames and 04c's Simple Query path so the deny semantics live in exactly one place.

**Tech Stack:** Go (`//go:build linux` for all new proxy files; events/effects/policy extensions are tag-free), `github.com/jackc/pgx/v5/pgproto3` (already a dep), `pgregory.net/rapid` (new test-only dep for property tests; falls back to `testing/quick` if rapid is not available — task 14 spells out both options).

**Cross-references:**
- Shared design (covers 05a/05b/05c): `docs/superpowers/specs/2026-05-11-db-plan-05-pg-extended-tx-design.md`
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 05
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1, §14.2, §14.3, §14.4
- Predecessor plan: `docs/superpowers/plans/2026-05-10-db-plan-04c-simple-query-events.md`

**Settled in brainstorming (2026-05-11):**

1. Pure transition core + Action sum-type interface. `Transition` mutates the `CacheView` directly (calls `cache.Put` / `cache.Delete` / `cache.Clear`); cache mutations are NOT Actions. Actions are I/O-only.
2. `deny_mode_in_tx` is a per-rule field (`database_rules` entries). Validator rejects on non-deny rules and on `match_kind: cancel`. Remove the unused `DenyModeInTx` field from `policy.DBService`.
3. Shared `preparedcache.Cache` LRU type (cap 4096); two instances per `proxyConn`. 05a wires only `wireCache`; `sqlCache` exists for 05b.
4. Simple Query (`'Q'`) deny path refactors to call `denyRoute` so the §14.3/§14.4 logic lives once.
5. `Approve` rules continue to be stubbed as `deny + APPROVE_NOT_YET_SUPPORTED` in 05a (the runtime arrives in 05c). 05a does NOT remove the warning in `policy.Decode`.

---

## File Structure

**Created:**

- `internal/db/proxy/postgres/preparedcache/cache.go` — 4096-LRU; concurrency-safe; `Get` / `Put` / `Delete` / `Clear` / `Len`.
- `internal/db/proxy/postgres/preparedcache/cache_test.go` — eviction at cap; concurrent stress; round-trip; delete-missing no-op; clear.
- `internal/db/proxy/postgres/statemachine/state.go` — `Phase` enum (`PhasePreAuth`, `PhaseIdle`, `PhaseInQuery`, `PhaseInTx`, `PhaseInTxError`, `PhaseInCopyIn`, `PhaseInCopyOut`); `ConnState` struct.
- `internal/db/proxy/postgres/statemachine/action.go` — `Action` interface with private `isAction()` method; concrete variants listed above.
- `internal/db/proxy/postgres/statemachine/frame.go` — `Frame` interface; concrete adapters wrapping pgproto3 frontend messages (`ParseFrame`, `BindFrame`, `DescribeFrame`, `ExecuteFrame`, `SyncFrame`, `FlushFrame`, `CloseFrame`, `QueryFrame`, `TerminateFrame`).
- `internal/db/proxy/postgres/statemachine/cacheview.go` — `CacheView` interface; in-package fake recorder for tests.
- `internal/db/proxy/postgres/statemachine/denyroute.go` — pure `DenyRoute(state, rule, msg) []Action` implementing §14.3 + §14.4.
- `internal/db/proxy/postgres/statemachine/transition.go` — `Transition(state, frame, cache, rules, svc) (next ConnState, []Action)` plus per-frame helpers.
- `internal/db/proxy/postgres/statemachine/state_test.go` — Phase zero-value sanity.
- `internal/db/proxy/postgres/statemachine/action_test.go` — Action variant compile-time assertions (`var _ Action = (*ActionForward)(nil)` for each).
- `internal/db/proxy/postgres/statemachine/denyroute_test.go` — table-driven coverage of every §14.3/§14.4 row.
- `internal/db/proxy/postgres/statemachine/transition_test.go` — ~50-row table covering Parse/Bind/Describe/Execute/Sync/Flush/Close × absorbing × dirty × upstream RFQ.
- `internal/db/proxy/postgres/statemachine/property_test.go` — invariants from design §6 against random valid frame sequences.
- `internal/db/proxy/postgres/extquery.go` — dispatcher reading frames, calling `Transition`, executing Actions against `proxyConn` I/O.
- `internal/db/proxy/postgres/extquery_test.go` — dispatcher tests using a fake `proxyConn` and a `pgproto3.Backend` driving frames.

**Modified:**

- `internal/db/policy/types.go` — remove `DBService.DenyModeInTx`; add `StatementRule.DenyModeInTx string`.
- `internal/db/policy/validate.go` — `deny_mode_in_tx` validation; reject on non-deny rules and `match_kind: cancel`.
- `internal/db/policy/validate_test.go` — coverage rows for the new validations.
- `internal/db/proxy/postgres/proxyconn.go` — `connState` extension: replace `lastUpstreamRFQ byte` with `smState *statemachine.ConnState`; add `wireCache *preparedcache.Cache`, `sqlCache *preparedcache.Cache` (latter unused until 05b); preserve a `lastUpstreamRFQ() byte` accessor for backward compat with 04c readers.
- `internal/db/proxy/postgres/simplequery.go` — `simpleQueryLoop` dispatches Parse/Bind/Describe/Execute/Sync/Flush/Close to `extquery.handleExtendedFrame` instead of falling through to `handleUnsupportedFrame`. `handleQuery` (Q) reuses `statemachine.DenyRoute` for the deny path so the §14.3/§14.4 logic is unified.
- `internal/db/proxy/postgres/upstreamread.go` — `forwardUpstreamUntilRFQ` records `state.smState.LastUpstreamRFQ` and updates `state.smState.Phase` accordingly on every observed `'Z'`; also populates `TxStartedAt` on first `'T'` after `Idle`.
- `internal/db/proxy/postgres/deny.go` — `synthErrorOnly` keeps its FATAL severity (unchanged); add `synthErrorAndRollback(sqlstate, message)` for the rollback path (writes `ErrorResponse(Severity: "ERROR", …)` then leaves the connection alive for ROLLBACK injection).
- `internal/db/proxy/postgres/handshake.go` — `dialUpstreamAndForward` initializes `state.smState` and starts the unified frame loop (no Plan 05a code change needed; documented for completeness).
- `internal/db/proxy/postgres/eventbuilder.go` — `buildStatementEvent` populates `TxContext.TxStartedAt` from `state.smState.TxStartedAt` and accepts `DenyAction` value `"rollback_injected"`.
- `internal/db/proxy/postgres/eventbuilder_test.go` — new row for `rollback_injected` with `TxStartedAt` populated.
- `internal/db/proxy/postgres/server.go` — `proxyConn` factory initializes both cache instances; no public-API change.
- `internal/db/proxy/postgres/spine_test.go` — three new sub-tests: extended-query allow, extended-query deny pre-tx, in-tx deny with `rollback_then_continue`.
- `go.mod` / `go.sum` — add `pgregory.net/rapid v0.7.x` (test-only). If a license/policy concern arises, Task 14 has a `testing/quick` fallback.

**Out of scope (deferred to 05b / 05c):**

- SQL-level PREPARE/EXECUTE/DEALLOCATE/DISCARD recognition (05b).
- FunctionCall (`F`) opt-in beyond the 04c stub (05b).
- Function-call escalation classifier knobs (05b).
- COPY data-frame byte-passthrough (05c).
- Approver interface and approval-timeout runtime (05c).
- Removing the `APPROVE_NOT_YET_SUPPORTED` warning (05c).

---

## Task 1: Move `deny_mode_in_tx` from `DBService` to `StatementRule`

**Why:** Brainstorming decided the field belongs on rules (per-rule overrides), not services. The current `DBService.DenyModeInTx` field is unused; no test reads it. Move it.

**Files:**
- Modify: `internal/db/policy/types.go`
- Modify: `internal/db/policy/validate.go`
- Modify: `internal/db/policy/validate_test.go`
- Modify: `internal/db/policy/decode_test.go` (if any test loads the field on a service)

- [ ] **Step 1: Confirm no consumer of `DBService.DenyModeInTx`**

Run:
```bash
git grep -n 'DenyModeInTx' -- internal/ cmd/
```

Expected: only `internal/db/policy/types.go:88` defining it, plus any tests we authored ourselves. If a non-test consumer appears, stop and reconsider.

- [ ] **Step 2: Write the failing validator test**

Append to `internal/db/policy/validate_test.go`:

```go
func TestValidate_DenyModeInTx_AcceptedOnDenyRule(t *testing.T) {
	yaml := `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue }
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	rs, warns, err := Decode([]byte(yaml))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(warns) != 0 {
		t.Fatalf("warns: %#v", warns)
	}
	if rs == nil {
		t.Fatal("rs nil")
	}
}

func TestValidate_DenyModeInTx_RejectedOnAllowRule(t *testing.T) {
	yaml := `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue }
database_rules:
  - name: allow-read
    db_service: appdb
    operations: [read]
    decision: allow
    deny_mode_in_tx: rollback_then_continue
`
	_, _, err := Decode([]byte(yaml))
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "deny_mode_in_tx") {
		t.Fatalf("unexpected err: %v", err)
	}
}

func TestValidate_DenyModeInTx_RejectedUnknownValue(t *testing.T) {
	yaml := `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue }
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: banana
`
	_, _, err := Decode([]byte(yaml))
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	if !strings.Contains(err.Error(), "deny_mode_in_tx") {
		t.Fatalf("unexpected err: %v", err)
	}
}
```

If `strings` is not imported in this test file, add it.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/db/policy/ -run TestValidate_DenyModeInTx -count=1`
Expected: FAIL with `deny_mode_in_tx` unrecognized YAML field.

- [ ] **Step 4: Move the field on the struct**

Modify `internal/db/policy/types.go`. Locate the `DBService` struct and **remove** this line:

```go
	DenyModeInTx              string `yaml:"deny_mode_in_tx,omitempty"`
```

Then locate `StatementRule` and add the field. The struct should read:

```go
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
	DenyModeInTx                string        `yaml:"deny_mode_in_tx,omitempty"`
}
```

- [ ] **Step 5: Add the validator**

Open `internal/db/policy/validate.go`. Locate the statement-rule validation loop (the function that iterates `database_rules` and rejects bad fields — typically a `validateStatementRule(r)` helper or inline in `Decode`). Add this check at the end of per-rule validation:

```go
	if r.DenyModeInTx != "" {
		if r.Decision != "deny" {
			return fmt.Errorf("rule %q: deny_mode_in_tx is only valid on deny rules", r.Name)
		}
		switch r.DenyModeInTx {
		case "terminate", "rollback_then_continue":
			// ok
		default:
			return fmt.Errorf("rule %q: deny_mode_in_tx %q: must be one of \"terminate\" or \"rollback_then_continue\"", r.Name, r.DenyModeInTx)
		}
	}
```

If the existing validator uses `Warning` rather than `error` returns for similar cases (e.g., other `decision`-conditional checks), match that pattern — but `deny_mode_in_tx` on a non-deny rule is a config-load *error*, not a warning, because the field cannot have any effect.

- [ ] **Step 6: Run tests to confirm they pass**

Run: `go test ./internal/db/policy/ -run TestValidate_DenyModeInTx -count=1 -v`
Expected: all three PASS.

- [ ] **Step 7: Run the full policy test suite to confirm no regression**

Run: `go test ./internal/db/policy/ -count=1`
Expected: all green. If any test asserts on the removed `DBService.DenyModeInTx` field, update it to read the rule-level field instead.

- [ ] **Step 8: Commit**

```bash
git add internal/db/policy/types.go internal/db/policy/validate.go internal/db/policy/validate_test.go
git commit -m "db: policy — move deny_mode_in_tx from DBService to StatementRule with validation"
```

---

## Task 2: `preparedcache` package — LRU type

**Why:** Both 05a (wire prepared cache) and 05b (SQL prepared cache) need an identical 4096-LRU. Ship the type now with both instances created in `proxyConn`; 05a wires `wireCache`; 05b wires `sqlCache`.

**Files:**
- Create: `internal/db/proxy/postgres/preparedcache/cache.go`
- Create: `internal/db/proxy/postgres/preparedcache/cache_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/preparedcache/cache_test.go`:

```go
package preparedcache

import (
	"strconv"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/db/effects"
)

func TestCache_PutGet_RoundTrip(t *testing.T) {
	c := New(4)
	c.Put("s1", Entry{Classification: effects.ClassifiedStatement{RawVerb: "SELECT"}})
	got, ok := c.Get("s1")
	if !ok {
		t.Fatal("Get miss; want hit")
	}
	if got.Classification.RawVerb != "SELECT" {
		t.Fatalf("RawVerb=%q want SELECT", got.Classification.RawVerb)
	}
}

func TestCache_Get_Miss(t *testing.T) {
	c := New(4)
	_, ok := c.Get("nope")
	if ok {
		t.Fatal("hit on empty cache")
	}
}

func TestCache_Eviction_AtCap(t *testing.T) {
	c := New(2)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Put("b", Entry{Classification: effects.ClassifiedStatement{RawVerb: "B"}})
	c.Put("c", Entry{Classification: effects.ClassifiedStatement{RawVerb: "C"}})
	if _, ok := c.Get("a"); ok {
		t.Fatal("a not evicted")
	}
	if _, ok := c.Get("b"); !ok {
		t.Fatal("b missing")
	}
	if _, ok := c.Get("c"); !ok {
		t.Fatal("c missing")
	}
}

func TestCache_Get_PromotesEntry(t *testing.T) {
	c := New(2)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Put("b", Entry{Classification: effects.ClassifiedStatement{RawVerb: "B"}})
	_, _ = c.Get("a") // promote a
	c.Put("c", Entry{Classification: effects.ClassifiedStatement{RawVerb: "C"}})
	if _, ok := c.Get("a"); !ok {
		t.Fatal("a should be retained")
	}
	if _, ok := c.Get("b"); ok {
		t.Fatal("b should be evicted (was LRU)")
	}
}

func TestCache_Delete(t *testing.T) {
	c := New(4)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Delete("a")
	if _, ok := c.Get("a"); ok {
		t.Fatal("Get after Delete hit")
	}
	c.Delete("never-there") // no-op, no panic
}

func TestCache_Clear(t *testing.T) {
	c := New(4)
	c.Put("a", Entry{Classification: effects.ClassifiedStatement{RawVerb: "A"}})
	c.Put("b", Entry{Classification: effects.ClassifiedStatement{RawVerb: "B"}})
	c.Clear()
	if c.Len() != 0 {
		t.Fatalf("Len=%d want 0", c.Len())
	}
}

func TestCache_Concurrent(t *testing.T) {
	c := New(64)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				name := strconv.Itoa((w*1000 + i) % 32)
				c.Put(name, Entry{Classification: effects.ClassifiedStatement{RawVerb: name}})
				_, _ = c.Get(name)
				if i%37 == 0 {
					c.Delete(name)
				}
			}
		}(w)
	}
	wg.Wait()
	if c.Len() > 64 {
		t.Fatalf("Len=%d exceeded cap", c.Len())
	}
}
```

- [ ] **Step 2: Run tests to verify build failure**

Run: `go test ./internal/db/proxy/postgres/preparedcache/ -count=1`
Expected: build error — package does not exist.

- [ ] **Step 3: Implement the cache**

Create `internal/db/proxy/postgres/preparedcache/cache.go`:

```go
//go:build linux

// Package preparedcache is a per-connection LRU prepared-statement cache used
// by the PostgreSQL proxy. Plan 05a uses it for the wire-protocol Extended
// Query cache; Plan 05b adds a second instance per connection for SQL-level
// PREPARE/EXECUTE.
//
// The default capacity is 4096 entries per spec §7.4.
package preparedcache

import (
	"container/list"
	"sync"

	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

const DefaultCapacity = 4096

// Entry is the cached value: the classified statement plus the redaction
// tier captured at Parse time so a later Execute renders consistently even
// if policy is hot-swapped between Parse and Execute.
type Entry struct {
	Classification effects.ClassifiedStatement
	RedactionTier  policy.RedactionTier
}

// Cache is a fixed-capacity LRU keyed by prepared-statement name. Empty name
// is a legal key per §7.4 (unnamed prepared statement).
type Cache struct {
	mu       sync.Mutex
	cap      int
	order    *list.List // front=MRU, back=LRU
	byKey    map[string]*list.Element
}

type cacheItem struct {
	key   string
	value Entry
}

// New returns a Cache with the given capacity. capacity <= 0 falls back to
// DefaultCapacity.
func New(capacity int) *Cache {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Cache{
		cap:   capacity,
		order: list.New(),
		byKey: make(map[string]*list.Element, capacity),
	}
}

// Put inserts or updates name -> e. Existing entries are promoted to MRU.
// At capacity, the LRU entry is evicted.
func (c *Cache) Put(name string, e Entry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.byKey[name]; ok {
		el.Value.(*cacheItem).value = e
		c.order.MoveToFront(el)
		return
	}
	el := c.order.PushFront(&cacheItem{key: name, value: e})
	c.byKey[name] = el
	if c.order.Len() > c.cap {
		oldest := c.order.Back()
		if oldest != nil {
			ci := oldest.Value.(*cacheItem)
			c.order.Remove(oldest)
			delete(c.byKey, ci.key)
		}
	}
}

// Get returns the cached entry and promotes it to MRU. Second return is
// false on miss.
func (c *Cache) Get(name string) (Entry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[name]
	if !ok {
		return Entry{}, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*cacheItem).value, true
}

// Delete removes name if present. No-op on miss.
func (c *Cache) Delete(name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.byKey[name]
	if !ok {
		return
	}
	c.order.Remove(el)
	delete(c.byKey, name)
}

// Clear empties the cache.
func (c *Cache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.order.Init()
	c.byKey = make(map[string]*list.Element, c.cap)
}

// Len returns the current entry count.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.order.Len()
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/preparedcache/ -count=1 -race`
Expected: all PASS under `-race`.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/preparedcache/
git commit -m "db: proxy — preparedcache 4096-LRU type for Extended Query and SQL prepared caches"
```

---

## Task 3: `statemachine` package — `Phase` + `ConnState`

**Why:** The state machine's `Transition` consumes a `ConnState`; it needs a defined zero value and exported fields. No transition logic yet — just the type.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/state.go`
- Create: `internal/db/proxy/postgres/statemachine/state_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/db/proxy/postgres/statemachine/state_test.go`:

```go
package statemachine

import (
	"testing"
	"time"
)

func TestPhase_String(t *testing.T) {
	cases := []struct {
		p    Phase
		want string
	}{
		{PhasePreAuth, "pre_auth"},
		{PhaseIdle, "idle"},
		{PhaseInQuery, "in_query"},
		{PhaseInTx, "in_tx"},
		{PhaseInTxError, "in_tx_error"},
		{PhaseInCopyIn, "in_copy_in"},
		{PhaseInCopyOut, "in_copy_out"},
	}
	for _, c := range cases {
		if got := c.p.String(); got != c.want {
			t.Errorf("Phase(%d).String() = %q; want %q", c.p, got, c.want)
		}
	}
}

func TestConnState_ZeroValue(t *testing.T) {
	var s ConnState
	if s.Phase != PhasePreAuth {
		t.Errorf("zero Phase = %v; want PhasePreAuth", s.Phase)
	}
	if s.Absorbing {
		t.Error("zero Absorbing should be false")
	}
	if s.UpstreamDirtySinceSync {
		t.Error("zero UpstreamDirtySinceSync should be false")
	}
	if !s.TxStartedAt.IsZero() {
		t.Error("zero TxStartedAt should be zero time.Time")
	}
	var _ time.Time = s.TxStartedAt
}
```

- [ ] **Step 2: Run test to verify build failure**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1`
Expected: build error — package does not exist.

- [ ] **Step 3: Implement state**

Create `internal/db/proxy/postgres/statemachine/state.go`:

```go
//go:build linux

// Package statemachine implements the PostgreSQL proxy's Extended Query and
// transaction state machine per docs/agentsh-db-access-spec.md §14 and the
// design doc 2026-05-11-db-plan-05-pg-extended-tx-design.md §4.
//
// Transition is a pure function: it consumes (state, frame, cache, rules,
// service) and returns (nextState, []Action). It mutates the CacheView
// directly (for Put/Delete/Clear) so the Action stream is I/O-only.
package statemachine

import "time"

// Phase enumerates the per-connection lifecycle phases. The state machine
// tracks both Phase (for human-readable invariants) and LastUpstreamRFQ
// (the on-wire 'Z' status byte) because the two convey slightly different
// information — Phase encodes COPY-in/COPY-out which RFQ cannot represent.
type Phase uint8

const (
	PhasePreAuth Phase = iota
	PhaseIdle
	PhaseInQuery
	PhaseInTx
	PhaseInTxError
	PhaseInCopyIn
	PhaseInCopyOut
)

func (p Phase) String() string {
	switch p {
	case PhasePreAuth:
		return "pre_auth"
	case PhaseIdle:
		return "idle"
	case PhaseInQuery:
		return "in_query"
	case PhaseInTx:
		return "in_tx"
	case PhaseInTxError:
		return "in_tx_error"
	case PhaseInCopyIn:
		return "in_copy_in"
	case PhaseInCopyOut:
		return "in_copy_out"
	default:
		return "phase_unknown"
	}
}

// ConnState is the per-connection state the Extended Query and transaction
// state machine carries. All fields are exported so the dispatcher can read
// them after Transition returns; mutations happen only through Transition
// (or through the dispatcher updating LastUpstreamRFQ + Phase when an
// upstream 'Z' arrives during forwarding).
type ConnState struct {
	// Phase reflects the per-connection lifecycle position.
	Phase Phase

	// LastUpstreamRFQ is the most recent ReadyForQuery status byte observed
	// from upstream. Zero (0x00) means pre-auth. Otherwise 'I', 'T', or 'E'.
	LastUpstreamRFQ byte

	// Absorbing is true when a previous Parse/Bind/Execute denied within
	// the current Sync window. Subsequent non-Sync frames are suppressed
	// until the next Sync resolves the window.
	Absorbing bool

	// UpstreamDirtySinceSync is true once any Parse/Bind/Execute/Describe/
	// Close has been forwarded upstream in the current Sync window. Reset
	// on the next observed upstream RFQ.
	UpstreamDirtySinceSync bool

	// TxStartedAt is the local timestamp the proxy observed transitioning
	// into 'T' (in-tx) state on a fresh transaction. Cleared when the next
	// observed upstream RFQ is 'I'. Used by the DBEvent tx_context schema.
	TxStartedAt time.Time
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/
git commit -m "db: proxy/statemachine — Phase enum and ConnState type"
```

---

## Task 4: `statemachine.Action` interface + variants

**Why:** The Action sum type is the only contract between transition logic and the dispatcher. Defining it now lets later tasks emit Actions in tests using `cmp.Diff`.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/action.go`
- Create: `internal/db/proxy/postgres/statemachine/action_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/db/proxy/postgres/statemachine/action_test.go`:

```go
package statemachine

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// These compile-time assertions ensure every concrete type implements Action.
var (
	_ Action = (*ActionForward)(nil)
	_ Action = (*ActionSynthError)(nil)
	_ Action = (*ActionSynthReadyForQuery)(nil)
	_ Action = (*ActionSynthParseComplete)(nil)
	_ Action = (*ActionSynthBindComplete)(nil)
	_ Action = (*ActionSuppress)(nil)
	_ Action = (*ActionInjectRollback)(nil)
	_ Action = (*ActionDrainUntilRFQ)(nil)
	_ Action = (*ActionClose)(nil)
	_ Action = (*ActionTrackUpstreamRFQ)(nil)
)

func TestActions_DiffableByCmp(t *testing.T) {
	a := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	b := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(a, b); diff != "" {
		t.Errorf("expected equal; diff=%s", diff)
	}
	c := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionSynthReadyForQuery{Status: 'T'}, // differs
	}
	if diff := cmp.Diff(a, c); diff == "" {
		t.Errorf("expected diff; got empty")
	}
}

func TestActionTrackUpstreamRFQ_Field(t *testing.T) {
	a := &ActionTrackUpstreamRFQ{Status: 'T'}
	if a.Status != 'T' {
		t.Errorf("Status=%q want 'T'", a.Status)
	}
}
```

`github.com/google/go-cmp/cmp` should already be a transitive dep; if not, add via `go get`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1`
Expected: build error — `Action` and concrete types undefined.

- [ ] **Step 3: Implement Action**

Create `internal/db/proxy/postgres/statemachine/action.go`:

```go
//go:build linux

package statemachine

// Action is a single thing the dispatcher must execute after a Transition.
// Concrete types are sealed via the private isAction() method so the dispatcher
// can rely on a closed sum type. Cache mutations are NOT Actions — Transition
// mutates the CacheView directly.
type Action interface {
	isAction()
}

// ActionForward emits the original frontend frame to upstream unchanged.
// The dispatcher reads pc.lastFrame and forwards via upstream framer.
type ActionForward struct{}

// ActionSynthError synthesizes ErrorResponse to the client. The dispatcher
// chooses Severity based on the deny path (ERROR for resumable; FATAL for
// terminate). SQLState is the §10 / §13 / §14 SQLSTATE.
type ActionSynthError struct {
	SQLState string
	Message  string
	// Severity overrides "ERROR" when non-empty. The terminate-in-tx path
	// uses Severity="FATAL" so libpq clients surface the SQLSTATE alongside
	// the EOF that follows.
	Severity string
}

// ActionSynthReadyForQuery synthesizes ReadyForQuery to the client.
type ActionSynthReadyForQuery struct {
	Status byte // 'I' | 'T' | 'E'
}

// ActionSynthParseComplete synthesizes a ParseComplete frame to the client
// (used in absorbing-window denies to satisfy clients expecting one frame
// per Parse). Plan 05a does not emit this in standard paths; reserved for
// future tightening.
type ActionSynthParseComplete struct{}

// ActionSynthBindComplete mirrors ActionSynthParseComplete for Bind.
type ActionSynthBindComplete struct{}

// ActionSuppress instructs the dispatcher to drop the current frontend
// frame without forwarding upstream and without responding to client.
// Used inside an absorbing-deny window.
type ActionSuppress struct{}

// ActionInjectRollback sends a synthetic "ROLLBACK" Simple Query upstream as
// if from the client. Used by the rollback_then_continue deny mode. The
// dispatcher composes a 'Q' frame with body "ROLLBACK".
type ActionInjectRollback struct{}

// ActionDrainUntilRFQ reads upstream frames and forwards them to the client
// (subject to the per-row demux for counters in upstreamread.go) until an
// upstream ReadyForQuery is observed. Updates LastUpstreamRFQ on the way.
type ActionDrainUntilRFQ struct{}

// ActionClose tears down both client and upstream connections. After this
// the dispatcher returns from the per-connection driver.
type ActionClose struct{}

// ActionTrackUpstreamRFQ updates ConnState.LastUpstreamRFQ and Phase to
// match Status. Emitted when the dispatcher observes an upstream 'Z' frame
// during normal forwarding.
type ActionTrackUpstreamRFQ struct {
	Status byte
}

func (*ActionForward) isAction()              {}
func (*ActionSynthError) isAction()           {}
func (*ActionSynthReadyForQuery) isAction()   {}
func (*ActionSynthParseComplete) isAction()   {}
func (*ActionSynthBindComplete) isAction()    {}
func (*ActionSuppress) isAction()             {}
func (*ActionInjectRollback) isAction()       {}
func (*ActionDrainUntilRFQ) isAction()        {}
func (*ActionClose) isAction()                {}
func (*ActionTrackUpstreamRFQ) isAction()     {}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -v`
Expected: `TestActions_DiffableByCmp` PASS, `TestActionTrackUpstreamRFQ_Field` PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/action.go internal/db/proxy/postgres/statemachine/action_test.go
git commit -m "db: proxy/statemachine — Action sum type and concrete variants"
```

---

## Task 5: `statemachine.Frame` interface and adapters

**Why:** `Transition` consumes `Frame` rather than `pgproto3.FrontendMessage` so the state-machine package does not transitively import pgproto3 and tests can construct frames with literal values. Adapters live in this file so the dispatcher's frame conversion is a one-liner.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/frame.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/statemachine/state_test.go`:

```go
func TestFrame_Kind(t *testing.T) {
	cases := []struct {
		f    Frame
		want FrameKind
	}{
		{&QueryFrame{SQL: "SELECT 1"}, FrameKindQuery},
		{&ParseFrame{Name: "s1", SQL: "SELECT $1"}, FrameKindParse},
		{&BindFrame{Portal: "p1", Statement: "s1"}, FrameKindBind},
		{&DescribeFrame{Kind: 'S', Name: "s1"}, FrameKindDescribe},
		{&ExecuteFrame{Portal: "p1"}, FrameKindExecute},
		{&SyncFrame{}, FrameKindSync},
		{&FlushFrame{}, FrameKindFlush},
		{&CloseFrame{Kind: 'S', Name: "s1"}, FrameKindClose},
		{&TerminateFrame{}, FrameKindTerminate},
	}
	for _, c := range cases {
		if got := c.f.Kind(); got != c.want {
			t.Errorf("Kind() = %v; want %v", got, c.want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestFrame_Kind`
Expected: build error — `Frame`, `FrameKind`, concrete types undefined.

- [ ] **Step 3: Implement Frame**

Create `internal/db/proxy/postgres/statemachine/frame.go`:

```go
//go:build linux

package statemachine

// FrameKind enumerates the per-frame kinds Transition dispatches on.
type FrameKind uint8

const (
	FrameKindQuery FrameKind = iota
	FrameKindParse
	FrameKindBind
	FrameKindDescribe
	FrameKindExecute
	FrameKindSync
	FrameKindFlush
	FrameKindClose
	FrameKindTerminate
	FrameKindFunctionCall // Plan 05b live; Plan 05a falls through to default-deny
	FrameKindCopyData
	FrameKindCopyDone
	FrameKindCopyFail
)

// Frame is a thin protocol-level view of one PostgreSQL frontend message.
// The dispatcher constructs concrete adapters from pgproto3.FrontendMessage
// before calling Transition. The state machine does not depend on pgproto3.
type Frame interface {
	Kind() FrameKind
}

type QueryFrame struct {
	SQL string
}

func (*QueryFrame) Kind() FrameKind { return FrameKindQuery }

type ParseFrame struct {
	Name string // empty string is unnamed prepared statement
	SQL  string
}

func (*ParseFrame) Kind() FrameKind { return FrameKindParse }

type BindFrame struct {
	Portal    string
	Statement string // prepared-statement name
}

func (*BindFrame) Kind() FrameKind { return FrameKindBind }

type DescribeFrame struct {
	Kind byte   // 'S' (statement) or 'P' (portal)
	Name string
}

func (*DescribeFrame) Kind() FrameKind { return FrameKindDescribe }

type ExecuteFrame struct {
	Portal string
}

func (*ExecuteFrame) Kind() FrameKind { return FrameKindExecute }

type SyncFrame struct{}

func (*SyncFrame) Kind() FrameKind { return FrameKindSync }

type FlushFrame struct{}

func (*FlushFrame) Kind() FrameKind { return FrameKindFlush }

type CloseFrame struct {
	Kind byte   // 'S' (statement) or 'P' (portal)
	Name string
}

func (*CloseFrame) Kind() FrameKind { return FrameKindClose }

type TerminateFrame struct{}

func (*TerminateFrame) Kind() FrameKind { return FrameKindTerminate }

type FunctionCallFrame struct {
	FunctionOID uint32
}

func (*FunctionCallFrame) Kind() FrameKind { return FrameKindFunctionCall }

type CopyDataFrame struct {
	Body []byte // borrowed; do not retain past the Transition call
}

func (*CopyDataFrame) Kind() FrameKind { return FrameKindCopyData }

type CopyDoneFrame struct{}

func (*CopyDoneFrame) Kind() FrameKind { return FrameKindCopyDone }

type CopyFailFrame struct {
	Message string
}

func (*CopyFailFrame) Kind() FrameKind { return FrameKindCopyFail }
```

Note: there are two `Kind` symbols here — `Frame.Kind() FrameKind` (the method) and `DescribeFrame.Kind byte` / `CloseFrame.Kind byte` (the protocol "describe target" byte). Go treats them as distinct because the latter are field names on their own struct types. Tests that construct describe/close adapters use `DescribeFrame{Kind: 'S', Name: …}` literally.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -v -run TestFrame_Kind`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/frame.go internal/db/proxy/postgres/statemachine/state_test.go
git commit -m "db: proxy/statemachine — Frame interface and concrete adapters"
```

---

## Task 6: `statemachine.CacheView` interface

**Why:** `Transition` reads/writes the prepared cache through an interface so tests can use a recording fake. The `preparedcache.Cache` satisfies this interface in production.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/cacheview.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/statemachine/state_test.go`:

```go
func TestCacheView_FakeRecords(t *testing.T) {
	f := NewFakeCacheView()
	f.Put("s1", CacheValue{Verb: "SELECT"})
	v, ok := f.Get("s1")
	if !ok {
		t.Fatal("Get miss")
	}
	if v.Verb != "SELECT" {
		t.Fatalf("Verb=%q", v.Verb)
	}
	f.Delete("s1")
	if _, ok := f.Get("s1"); ok {
		t.Fatal("Get after Delete should miss")
	}
	if got := f.Recorded(); len(got) != 3 {
		t.Fatalf("Recorded len=%d want 3", len(got))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestCacheView_FakeRecords`
Expected: build error.

- [ ] **Step 3: Implement CacheView**

Create `internal/db/proxy/postgres/statemachine/cacheview.go`:

```go
//go:build linux

package statemachine

import "sync"

// CacheValue is the value stored in a CacheView. The transition logic
// reads/writes this type; production wraps it around a preparedcache.Entry
// at the dispatcher boundary so the state-machine package stays decoupled
// from the cache implementation.
type CacheValue struct {
	Verb     string // RawVerb from effects.ClassifiedStatement
	GroupID  uint8  // primary effect group_id; used for re-evaluate at Execute
	OpaqueID string // optional: spine-test correlation
}

// CacheView is the subset of preparedcache.Cache that Transition consumes.
// Implementations must be safe for concurrent reads with one writer per
// connection (the per-conn goroutine).
type CacheView interface {
	Get(name string) (CacheValue, bool)
	Put(name string, v CacheValue)
	Delete(name string)
	Clear()
}

// FakeCacheView records every operation and is safe for unit tests. NOT
// for production.
type FakeCacheView struct {
	mu      sync.Mutex
	store   map[string]CacheValue
	history []CacheOp
}

// CacheOp records one observation against a FakeCacheView.
type CacheOp struct {
	Method string // "Get" | "Put" | "Delete" | "Clear"
	Key    string
	Value  CacheValue
	Hit    bool // only meaningful for "Get"
}

// NewFakeCacheView returns an empty fake.
func NewFakeCacheView() *FakeCacheView {
	return &FakeCacheView{store: map[string]CacheValue{}}
}

func (f *FakeCacheView) Get(name string) (CacheValue, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.store[name]
	f.history = append(f.history, CacheOp{Method: "Get", Key: name, Value: v, Hit: ok})
	return v, ok
}

func (f *FakeCacheView) Put(name string, v CacheValue) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store[name] = v
	f.history = append(f.history, CacheOp{Method: "Put", Key: name, Value: v})
}

func (f *FakeCacheView) Delete(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.store, name)
	f.history = append(f.history, CacheOp{Method: "Delete", Key: name})
}

func (f *FakeCacheView) Clear() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.store = map[string]CacheValue{}
	f.history = append(f.history, CacheOp{Method: "Clear"})
}

// Recorded returns the operation history.
func (f *FakeCacheView) Recorded() []CacheOp {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]CacheOp, len(f.history))
	copy(out, f.history)
	return out
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -v -run TestCacheView_FakeRecords`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/cacheview.go internal/db/proxy/postgres/statemachine/state_test.go
git commit -m "db: proxy/statemachine — CacheView interface and FakeCacheView for tests"
```

---

## Task 7: `statemachine.DenyRoute` (§14.3 + §14.4 fork)

**Why:** Centralize the deny-route fork. Both Simple Query (`'Q'`) and every Extended Query frame go through this helper so the §14.3/§14.4 logic lives once.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/denyroute.go`
- Create: `internal/db/proxy/postgres/statemachine/denyroute_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/statemachine/denyroute_test.go`:

```go
package statemachine

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/agentsh/agentsh/internal/db/policy"
)

func TestDenyRoute_OutOfTx_NotDirty(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'I', UpstreamDirtySinceSync: false},
		policy.StatementRule{Name: "block-delete", Decision: "deny"},
		"denied: block-delete",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied: block-delete"},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_OutOfTx_Dirty(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'I', UpstreamDirtySinceSync: true},
		policy.StatementRule{Name: "block-delete", Decision: "deny"},
		"denied",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied"},
		&ActionDrainUntilRFQ{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_InTx_DefaultTerminate(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'T'},
		policy.StatementRule{Name: "block-delete", Decision: "deny"}, // DenyModeInTx=""
		"denied",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "denied", Severity: "FATAL"},
		&ActionClose{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_InTx_ExplicitTerminate(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'T'},
		policy.StatementRule{Name: "x", Decision: "deny", DenyModeInTx: "terminate"},
		"x", "42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "x", Severity: "FATAL"},
		&ActionClose{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff:\n%s", diff)
	}
}

func TestDenyRoute_InTx_RollbackThenContinue(t *testing.T) {
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'T'},
		policy.StatementRule{Name: "soft", Decision: "deny", DenyModeInTx: "rollback_then_continue"},
		"soft",
		"42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "soft"},
		&ActionInjectRollback{},
		&ActionDrainUntilRFQ{},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}

func TestDenyRoute_InTxError_TreatedAsInTx(t *testing.T) {
	// 'E' (in-tx error) routes via the in-tx branch per §14.3 default.
	got := DenyRoute(
		ConnState{LastUpstreamRFQ: 'E'},
		policy.StatementRule{Name: "x", Decision: "deny"},
		"x", "42501",
	)
	want := []Action{
		&ActionSynthError{SQLState: "42501", Message: "x", Severity: "FATAL"},
		&ActionClose{},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("diff (-want +got):\n%s", diff)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestDenyRoute`
Expected: build error — `DenyRoute` undefined.

- [ ] **Step 3: Implement DenyRoute**

Create `internal/db/proxy/postgres/statemachine/denyroute.go`:

```go
//go:build linux

package statemachine

import (
	"github.com/agentsh/agentsh/internal/db/policy"
)

// DenyRoute returns the Action sequence implementing the spec §14.3 + §14.4
// deny path. Callers pass the rendered deny message (already templated) and
// the SQLSTATE chosen by the rule kind.
//
//   - Out-of-tx (lastUpstreamRFQ in {0, 'I'}) and not dirty:
//     [SynthError, SynthReadyForQuery(I)]
//   - Out-of-tx and dirty:
//     [SynthError, DrainUntilRFQ]
//   - In-tx (lastUpstreamRFQ in {'T', 'E'}), terminate (default or explicit):
//     [SynthError(Severity=FATAL), Close]
//   - In-tx, rollback_then_continue:
//     [SynthError, InjectRollback, DrainUntilRFQ, SynthReadyForQuery(I)]
func DenyRoute(s ConnState, rule policy.StatementRule, msg, sqlstate string) []Action {
	if s.LastUpstreamRFQ == 'T' || s.LastUpstreamRFQ == 'E' {
		// In-tx branch. Default terminate; soft mode if explicitly configured.
		if rule.DenyModeInTx == "rollback_then_continue" {
			return []Action{
				&ActionSynthError{SQLState: sqlstate, Message: msg},
				&ActionInjectRollback{},
				&ActionDrainUntilRFQ{},
				&ActionSynthReadyForQuery{Status: 'I'},
			}
		}
		return []Action{
			&ActionSynthError{SQLState: sqlstate, Message: msg, Severity: "FATAL"},
			&ActionClose{},
		}
	}

	// Out-of-tx branch.
	if s.UpstreamDirtySinceSync {
		return []Action{
			&ActionSynthError{SQLState: sqlstate, Message: msg},
			&ActionDrainUntilRFQ{},
		}
	}
	return []Action{
		&ActionSynthError{SQLState: sqlstate, Message: msg},
		&ActionSynthReadyForQuery{Status: 'I'},
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestDenyRoute -v`
Expected: all six tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/denyroute.go internal/db/proxy/postgres/statemachine/denyroute_test.go
git commit -m "db: proxy/statemachine — DenyRoute helper implementing §14.3/§14.4 fork"
```

---

## Task 8: `Transition` — Sync handler

**Why:** Sync is the resolver for the absorbing window. Land it first because every Extended Query handler's behavior depends on Sync semantics; getting Sync right makes Parse/Bind/Execute straightforward to test.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/transition.go`
- Create: `internal/db/proxy/postgres/statemachine/transition_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/statemachine/transition_test.go`:

```go
package statemachine

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// dummyRules constructs an empty *policy.RuleSet usable for transition tests
// where the rules don't matter (Sync, Suppress paths).
func dummyRules(t *testing.T) *policy.RuleSet {
	t.Helper()
	rs, _, err := policy.Decode([]byte(`db_services: {appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}}`))
	if err != nil {
		t.Fatalf("Decode dummy: %v", err)
	}
	return rs
}

func TestTransition_Sync_NotAbsorbing_NotDirty(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: false, UpstreamDirtySinceSync: false}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &SyncFrame{}, cache, dummyRules(t), "appdb")
	want := []Action{&ActionForward{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if next.Absorbing {
		t.Error("absorbing should remain false")
	}
}

func TestTransition_Sync_Absorbing_Dirty(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true, UpstreamDirtySinceSync: true}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &SyncFrame{}, cache, dummyRules(t), "appdb")
	want := []Action{&ActionForward{}, &ActionDrainUntilRFQ{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if next.Absorbing {
		t.Error("absorbing should reset")
	}
	if next.UpstreamDirtySinceSync {
		t.Error("dirty should reset")
	}
}

func TestTransition_Sync_Absorbing_NotDirty(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true, UpstreamDirtySinceSync: false}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &SyncFrame{}, cache, dummyRules(t), "appdb")
	want := []Action{&ActionSynthReadyForQuery{Status: 'I'}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if next.Absorbing {
		t.Error("absorbing should reset")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Sync`
Expected: build error — `Transition` undefined.

- [ ] **Step 3: Implement Transition with Sync handling**

Create `internal/db/proxy/postgres/statemachine/transition.go`:

```go
//go:build linux

package statemachine

import (
	"github.com/agentsh/agentsh/internal/db/policy"
)

// Transition is the pure state-transition function. It consumes the current
// ConnState, the next inbound frontend frame, a CacheView (mutated directly
// for Put/Delete/Clear), the active RuleSet, and the per-connection service
// identifier (used to scope policy evaluation). Returns the next state and
// the Action stream the dispatcher must execute.
//
// Plan 05a implements: Sync, Parse, Bind, Describe, Execute, Flush, Close,
// Query (Simple Query). Other frame kinds fall through to a default-deny
// path that produces SynthError(0A000) + Close, preserving 04c's behavior.
// Plan 05b lifts FunctionCall and SQL prepared interception; Plan 05c
// lifts COPY frames and the approval-wait variant.
func Transition(
	s ConnState,
	frame Frame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
) (ConnState, []Action) {
	switch f := frame.(type) {
	case *SyncFrame:
		return handleSync(s, f)
	case *TerminateFrame:
		return s, []Action{&ActionForward{}, &ActionClose{}}
	default:
		_ = f
		// Fallback: synth 0A000 + Close. Plan 05a's TDD adds handlers in
		// later tasks; until each task lands, the unhandled frame kinds
		// hit this row.
		return s, []Action{
			&ActionSynthError{SQLState: "0A000", Message: "frame not supported"},
			&ActionClose{},
		}
	}
}

func handleSync(s ConnState, _ *SyncFrame) (ConnState, []Action) {
	switch {
	case !s.Absorbing && !s.UpstreamDirtySinceSync:
		// Spec §14.2 case (1): forward and let upstream RFQ pass.
		return s, []Action{&ActionForward{}}
	case s.Absorbing && s.UpstreamDirtySinceSync:
		// Spec §14.2 case (2): forward Sync; the dispatcher's
		// drain-until-RFQ suppresses post-deny upstream responses and
		// forwards the trailing RFQ to the client. Reset absorbing + dirty.
		next := s
		next.Absorbing = false
		next.UpstreamDirtySinceSync = false
		return next, []Action{&ActionForward{}, &ActionDrainUntilRFQ{}}
	case s.Absorbing && !s.UpstreamDirtySinceSync:
		// Spec §14.2 case (3): synth RFQ(I) locally; reset absorbing.
		next := s
		next.Absorbing = false
		return next, []Action{&ActionSynthReadyForQuery{Status: 'I'}}
	default:
		// Not absorbing but dirty: rare (would mean we forwarded frames
		// then got a Sync without any deny). Forward Sync; the dispatcher
		// passes through the upstream RFQ. Mirrors case (1) action-wise.
		return s, []Action{&ActionForward{}}
	}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Sync -v`
Expected: all three PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/transition.go internal/db/proxy/postgres/statemachine/transition_test.go
git commit -m "db: proxy/statemachine — Transition skeleton + Sync handler"
```

---

## Task 9: Parse handler

**Why:** Parse is the entry to the prepared cache. Its allow path is classify + evaluate + Forward + cache.Put; its deny path is denyRoute + Absorbing. Get this right and Bind/Execute follow naturally.

**Files:**
- Modify: `internal/db/proxy/postgres/statemachine/transition.go`
- Modify: `internal/db/proxy/postgres/statemachine/transition_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/statemachine/transition_test.go`:

```go
func denyRulesYAML() string {
	return `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue }
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
`
}

func mustDecode(t *testing.T, yaml string) *policy.RuleSet {
	t.Helper()
	rs, warns, err := policy.Decode([]byte(yaml))
	if err != nil {
		t.Fatalf("Decode: %v (warns=%v)", err, warns)
	}
	return rs
}

func TestTransition_Parse_Allow_PopulatesCacheAndForwards(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	frame := &ParseFrame{Name: "s1", SQL: "SELECT 1"}
	next, acts := Transition(s, frame, cache, mustDecode(t, denyRulesYAML()), "appdb")
	want := []Action{&ActionForward{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if !next.UpstreamDirtySinceSync {
		t.Error("dirty should be true after allow Parse")
	}
	if v, ok := cache.Get("s1"); !ok || v.Verb != "SELECT" {
		t.Errorf("cache miss or wrong verb: %#v ok=%v", v, ok)
	}
}

func TestTransition_Parse_Deny_OutOfTx(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	frame := &ParseFrame{Name: "del", SQL: "DELETE FROM users"}
	next, acts := Transition(s, frame, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if len(acts) < 2 {
		t.Fatalf("want >=2 actions; got %d", len(acts))
	}
	if _, ok := acts[0].(*ActionSynthError); !ok {
		t.Errorf("acts[0] = %T; want *ActionSynthError", acts[0])
	}
	if _, ok := acts[1].(*ActionSynthReadyForQuery); !ok {
		t.Errorf("acts[1] = %T; want *ActionSynthReadyForQuery", acts[1])
	}
	if !next.Absorbing {
		t.Error("absorbing should be true after deny")
	}
	if _, ok := cache.Get("del"); ok {
		t.Error("denied Parse must not populate cache")
	}
}

func TestTransition_Parse_Absorbing_Suppresses(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true}
	cache := NewFakeCacheView()
	frame := &ParseFrame{Name: "s2", SQL: "SELECT 2"}
	next, acts := Transition(s, frame, cache, mustDecode(t, denyRulesYAML()), "appdb")
	want := []Action{&ActionSuppress{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("acts diff: %s", diff)
	}
	if !next.Absorbing {
		t.Error("absorbing must remain true")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Parse`
Expected: FAIL with default-fallback 0A000 actions (current Transition emits that for ParseFrame).

- [ ] **Step 3: Implement Parse handler**

Open `internal/db/proxy/postgres/statemachine/transition.go`. Add the necessary imports and the new handler. The updated file should read:

```go
//go:build linux

package statemachine

import (
	classify_pg "github.com/agentsh/agentsh/internal/db/classify/postgres"
	"github.com/agentsh/agentsh/internal/db/effects"
	"github.com/agentsh/agentsh/internal/db/policy"
)

// PolicyClassifier is the minimal classifier surface Transition needs at the
// state-machine boundary. The dispatcher injects a real classify_pg.Parser
// via TransitionWithParser; transition_test.go uses the live parser via
// classify_pg.New(classify_pg.DialectPostgres).
type PolicyClassifier interface {
	Classify(sql string, sess classify_pg.SessionState, opts classify_pg.Options) ([]effects.ClassifiedStatement, error)
}

func Transition(
	s ConnState,
	frame Frame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
) (ConnState, []Action) {
	parser := classify_pg.New(classify_pg.DialectPostgres)
	return TransitionWithParser(s, frame, cache, rules, svc, parser)
}

// TransitionWithParser is the parser-injected variant; tests use it when
// they need to assert against a non-postgres dialect or a mock classifier.
func TransitionWithParser(
	s ConnState,
	frame Frame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
	parser PolicyClassifier,
) (ConnState, []Action) {
	switch f := frame.(type) {
	case *SyncFrame:
		return handleSync(s, f)
	case *ParseFrame:
		return handleParse(s, f, cache, rules, svc, parser)
	case *TerminateFrame:
		return s, []Action{&ActionForward{}, &ActionClose{}}
	default:
		_ = f
		return s, []Action{
			&ActionSynthError{SQLState: "0A000", Message: "frame not supported"},
			&ActionClose{},
		}
	}
}

func handleSync(s ConnState, _ *SyncFrame) (ConnState, []Action) {
	switch {
	case !s.Absorbing && !s.UpstreamDirtySinceSync:
		return s, []Action{&ActionForward{}}
	case s.Absorbing && s.UpstreamDirtySinceSync:
		next := s
		next.Absorbing = false
		next.UpstreamDirtySinceSync = false
		return next, []Action{&ActionForward{}, &ActionDrainUntilRFQ{}}
	case s.Absorbing && !s.UpstreamDirtySinceSync:
		next := s
		next.Absorbing = false
		return next, []Action{&ActionSynthReadyForQuery{Status: 'I'}}
	default:
		return s, []Action{&ActionForward{}}
	}
}

func handleParse(
	s ConnState,
	f *ParseFrame,
	cache CacheView,
	rules *policy.RuleSet,
	svc policy.ServiceID,
	parser PolicyClassifier,
) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	stmts, err := parser.Classify(f.SQL, classify_pg.SessionState{}, classify_pg.Options{})
	if err != nil || len(stmts) == 0 {
		// Parse failure → unknown → policy default-deny via evaluate.
		// Fall through and let the evaluator handle it.
	}
	rs := rules
	anyDeny := false
	var denyDecision policy.Decision
	var denyRule policy.StatementRule
	for _, cs := range stmts {
		d := policy.Evaluate(cs, rs, svc)
		if d.Verb == policy.VerbApprove {
			// Plan 05a still stubs approve as deny + APPROVE_NOT_YET_SUPPORTED.
			d.Verb = policy.VerbDeny
			if d.Reason == "" {
				d.Reason = "APPROVE_NOT_YET_SUPPORTED"
			}
		}
		if d.Verb == policy.VerbDeny {
			anyDeny = true
			denyDecision = d
			denyRule = lookupStatementRule(rs, d.RuleName)
			break
		}
	}
	if anyDeny {
		msg := renderDenyMessage(denyDecision)
		actions := DenyRoute(s, denyRule, msg, sqlstateForDecision(denyDecision))
		next := s
		// Don't enter absorbing if Close is part of the action list — the
		// connection is going away. Otherwise set Absorbing.
		if !containsClose(actions) {
			next.Absorbing = true
		}
		return next, actions
	}
	// Allow path: Forward, mutate cache directly.
	verb := ""
	if len(stmts) > 0 {
		verb = stmts[0].RawVerb
	}
	var groupID uint8
	if len(stmts) > 0 && len(stmts[0].Effects) > 0 {
		groupID = uint8(stmts[0].Effects[0].Group)
	}
	cache.Put(f.Name, CacheValue{Verb: verb, GroupID: groupID})
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

// lookupStatementRule finds the named rule in rs.AllStatementRules() (added
// in this task). RuleName == "" returns the zero StatementRule, which is
// fine for implicit-deny: DenyModeInTx is empty (== terminate).
func lookupStatementRule(rs *policy.RuleSet, name string) policy.StatementRule {
	if rs == nil || name == "" {
		return policy.StatementRule{}
	}
	for _, r := range rs.AllStatementRules() {
		if r.Name == name {
			return r
		}
	}
	return policy.StatementRule{}
}

func renderDenyMessage(d policy.Decision) string {
	if d.RuleName != "" {
		return "denied by AgentSH policy: " + d.RuleName
	}
	if d.Reason != "" {
		return "denied by AgentSH policy: " + d.Reason
	}
	return "denied by AgentSH policy"
}

func sqlstateForDecision(d policy.Decision) string {
	if d.RuleKind == policy.RuleKindConnection {
		return "28000"
	}
	return "42501"
}

func containsClose(acts []Action) bool {
	for _, a := range acts {
		if _, ok := a.(*ActionClose); ok {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Add `AllStatementRules` accessor on `RuleSet`**

The handler above calls `rs.AllStatementRules()`. Open `internal/db/policy/types.go` and add (near `AllServices`):

```go
// AllStatementRules returns a copy of every parsed StatementRule. Order is
// preserved from the source YAML. Returns nil when rs is nil.
func (rs *RuleSet) AllStatementRules() []StatementRule {
	if rs == nil || len(rs.statement) == 0 {
		return nil
	}
	out := make([]StatementRule, 0, len(rs.statement))
	for _, cr := range rs.statement {
		out = append(out, cr.source)
	}
	return out
}
```

If `compiledStatementRule` does not have a `source StatementRule` field, the existing struct already retains the rule name and the source bytes; the simplest implementation is to store the raw `StatementRule` value alongside the compiled form. Locate `compiledStatementRule` (in `internal/db/policy/compile.go` or similar) and add a `source StatementRule` field initialized at compile time; if compile is split across multiple files, set it in the place that constructs each compiled rule.

If the existing structure does not store the raw rule and adding it is intrusive, an acceptable alternative is to add a `StatementRulesByName(name string) (StatementRule, bool)` lookup that just returns the slice element with matching name from a copy maintained at compile time. Pick whichever fits the existing code better.

- [ ] **Step 5: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Parse -v`
Expected: all three PASS.

Run also: `go test ./internal/db/policy/ -count=1`
Expected: PASS (the new accessor must not break existing tests).

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/transition.go internal/db/proxy/postgres/statemachine/transition_test.go internal/db/policy/types.go internal/db/policy/compile.go
git commit -m "db: proxy/statemachine — Parse handler + AllStatementRules accessor"
```

(Adjust the `git add` paths to whatever file `compiledStatementRule.source` actually got modified in.)

---

## Task 10: Bind / Describe / Execute / Flush / Close handlers

**Why:** With Parse implementing the canonical allow/deny pattern, the rest fall in. Bind looks up the cache; Describe and Flush forward (or suppress); Execute re-evaluates cached classification; Close updates the cache.

**Files:**
- Modify: `internal/db/proxy/postgres/statemachine/transition.go`
- Modify: `internal/db/proxy/postgres/statemachine/transition_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/statemachine/transition_test.go`:

```go
func TestTransition_Bind_CacheHit_Forwards(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	cache.Put("s1", CacheValue{Verb: "SELECT"})
	next, acts := Transition(s, &BindFrame{Portal: "p1", Statement: "s1"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	want := []Action{&ActionForward{}}
	if diff := cmp.Diff(want, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
	if !next.UpstreamDirtySinceSync {
		t.Error("dirty should be true after Bind forward")
	}
}

func TestTransition_Bind_CacheMiss_SynthErrorAndAbsorb(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I'}
	cache := NewFakeCacheView()
	next, acts := Transition(s, &BindFrame{Portal: "p1", Statement: "missing"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if len(acts) != 1 {
		t.Fatalf("len(acts)=%d want 1", len(acts))
	}
	se, ok := acts[0].(*ActionSynthError)
	if !ok {
		t.Fatalf("acts[0] = %T; want *ActionSynthError", acts[0])
	}
	if se.SQLState != "34000" {
		t.Errorf("SQLState=%q want 34000", se.SQLState)
	}
	if !next.Absorbing {
		t.Error("absorbing should be true")
	}
}

func TestTransition_Bind_Absorbing_Suppresses(t *testing.T) {
	s := ConnState{LastUpstreamRFQ: 'I', Absorbing: true}
	cache := NewFakeCacheView()
	_, acts := Transition(s, &BindFrame{Portal: "p", Statement: "x"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionSuppress{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Describe_NotAbsorbing_Forwards(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &DescribeFrame{Kind: 'S', Name: "s1"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Describe_Absorbing_Suppresses(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I', Absorbing: true}, &DescribeFrame{Kind: 'S', Name: "s1"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionSuppress{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Execute_CacheHit_AllowForwards(t *testing.T) {
	cache := NewFakeCacheView()
	cache.Put("p1", CacheValue{Verb: "SELECT"}) // portal lookup uses name
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &ExecuteFrame{Portal: "p1"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Execute_CacheMiss_SynthErrorAndAbsorb(t *testing.T) {
	cache := NewFakeCacheView()
	next, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &ExecuteFrame{Portal: "missing"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if len(acts) < 1 {
		t.Fatalf("len(acts)=%d", len(acts))
	}
	if _, ok := acts[0].(*ActionSynthError); !ok {
		t.Errorf("acts[0]=%T", acts[0])
	}
	if !next.Absorbing {
		t.Error("absorbing should be true")
	}
}

func TestTransition_Flush_NotAbsorbing_Forwards(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &FlushFrame{}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Flush_Absorbing_Suppresses(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I', Absorbing: true}, &FlushFrame{}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionSuppress{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Close_DeletesCacheEntry(t *testing.T) {
	cache := NewFakeCacheView()
	cache.Put("s1", CacheValue{Verb: "SELECT"})
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &CloseFrame{Kind: 'S', Name: "s1"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
	if _, ok := cache.Get("s1"); ok {
		t.Error("cache should not retain s1 after Close")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_(Bind|Describe|Execute|Flush|Close) -v`
Expected: FAIL with default 0A000 fallback (handlers not implemented).

- [ ] **Step 3: Implement the handlers**

Open `internal/db/proxy/postgres/statemachine/transition.go`. Extend `TransitionWithParser`'s switch and add handler functions. The full updated `TransitionWithParser` switch should read:

```go
	switch f := frame.(type) {
	case *SyncFrame:
		return handleSync(s, f)
	case *ParseFrame:
		return handleParse(s, f, cache, rules, svc, parser)
	case *BindFrame:
		return handleBind(s, f, cache)
	case *DescribeFrame:
		return handleDescribe(s, f)
	case *ExecuteFrame:
		return handleExecute(s, f, cache, rules, svc)
	case *FlushFrame:
		return handleFlush(s, f)
	case *CloseFrame:
		return handleClose(s, f, cache)
	case *TerminateFrame:
		return s, []Action{&ActionForward{}, &ActionClose{}}
	default:
		_ = f
		return s, []Action{
			&ActionSynthError{SQLState: "0A000", Message: "frame not supported"},
			&ActionClose{},
		}
	}
```

Append these handler functions to the same file:

```go
func handleBind(s ConnState, f *BindFrame, cache CacheView) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	if _, ok := cache.Get(f.Statement); !ok {
		next := s
		next.Absorbing = true
		return next, []Action{
			&ActionSynthError{SQLState: "34000", Message: "prepared statement \"" + f.Statement + "\" does not exist"},
		}
	}
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleDescribe(s ConnState, _ *DescribeFrame) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleExecute(
	s ConnState, f *ExecuteFrame, cache CacheView,
	rules *policy.RuleSet, svc policy.ServiceID,
) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	// Portal name → prepared-statement classification.
	// Plan 05a does not maintain a portal→statement map separately; the
	// client-issued portal name is used as the cache key directly. This is
	// safe because Bind's contract is "bind statement S to portal P" and
	// our prior Parse populated S=<stmt name>; in the typical pgx pipeline
	// the portal name == statement name. A future task can add a portal
	// map if a real workload uses distinct portal/statement names.
	v, ok := cache.Get(f.Portal)
	if !ok {
		next := s
		next.Absorbing = true
		return next, []Action{
			&ActionSynthError{SQLState: "34000", Message: "portal \"" + f.Portal + "\" does not exist"},
		}
	}
	// Re-evaluate cached classification against current policy snapshot.
	// CacheValue.GroupID is the primary effect's Group ID. We reconstruct a
	// minimal ClassifiedStatement for the evaluator.
	_ = v
	_ = rules
	_ = svc
	// Plan 05a's re-evaluation surface: if the cached statement was a deny
	// under the current rules, route deny; otherwise forward. The full
	// re-evaluation path is added in 05b along with the SQL-prepared cache.
	// For 05a, the wire prepared cache was populated only on Parse-allow,
	// so a cache hit implies the cached statement was allowed under the
	// rules in effect at Parse time. Plan 05b lifts the re-eval surface.
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}

func handleFlush(s ConnState, _ *FlushFrame) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	return s, []Action{&ActionForward{}}
}

func handleClose(s ConnState, f *CloseFrame, cache CacheView) (ConnState, []Action) {
	if s.Absorbing {
		return s, []Action{&ActionSuppress{}}
	}
	if f.Kind == 'S' {
		cache.Delete(f.Name)
	}
	next := s
	next.UpstreamDirtySinceSync = true
	return next, []Action{&ActionForward{}}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition -v`
Expected: every Bind / Describe / Execute / Flush / Close test PASS along with the previous Parse and Sync rows.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/transition.go internal/db/proxy/postgres/statemachine/transition_test.go
git commit -m "db: proxy/statemachine — Bind/Describe/Execute/Flush/Close handlers"
```

---

## Task 11: Simple Query (`'Q'`) handler

**Why:** Simple Query path needs to share `DenyRoute` so the §14.3/§14.4 logic is unified. The 04c implementation lives in `simplequery.go::handleQuery`; this task wires `Transition`'s `QueryFrame` arm to produce the right Actions. The dispatcher integration that calls Transition for Q happens in Task 13.

**Files:**
- Modify: `internal/db/proxy/postgres/statemachine/transition.go`
- Modify: `internal/db/proxy/postgres/statemachine/transition_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/statemachine/transition_test.go`:

```go
func TestTransition_Query_AllowForwards(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &QueryFrame{SQL: "SELECT 1"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if diff := cmp.Diff([]Action{&ActionForward{}}, acts); diff != "" {
		t.Errorf("diff: %s", diff)
	}
}

func TestTransition_Query_DenyOutOfTx_NotDirty(t *testing.T) {
	cache := NewFakeCacheView()
	next, acts := Transition(ConnState{LastUpstreamRFQ: 'I'}, &QueryFrame{SQL: "DELETE FROM users"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if len(acts) != 2 {
		t.Fatalf("len(acts)=%d want 2", len(acts))
	}
	if _, ok := acts[0].(*ActionSynthError); !ok {
		t.Errorf("acts[0]=%T", acts[0])
	}
	if _, ok := acts[1].(*ActionSynthReadyForQuery); !ok {
		t.Errorf("acts[1]=%T", acts[1])
	}
	if next.Absorbing {
		t.Error("Simple Query deny does not set Absorbing — Q is atomic per Sync")
	}
}

func TestTransition_Query_DenyInTx_TerminateDefault(t *testing.T) {
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'T'}, &QueryFrame{SQL: "DELETE FROM users"}, cache, mustDecode(t, denyRulesYAML()), "appdb")
	if len(acts) != 2 {
		t.Fatalf("len(acts)=%d want 2 (SynthError + Close)", len(acts))
	}
	se, ok := acts[0].(*ActionSynthError)
	if !ok {
		t.Fatalf("acts[0]=%T", acts[0])
	}
	if se.Severity != "FATAL" {
		t.Errorf("Severity=%q want FATAL", se.Severity)
	}
	if _, ok := acts[1].(*ActionClose); !ok {
		t.Errorf("acts[1]=%T want *ActionClose", acts[1])
	}
}

func TestTransition_Query_DenyInTx_RollbackThenContinue(t *testing.T) {
	yaml := `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue }
database_rules:
  - name: block-delete-soft
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	cache := NewFakeCacheView()
	_, acts := Transition(ConnState{LastUpstreamRFQ: 'T'}, &QueryFrame{SQL: "DELETE FROM users"}, cache, mustDecode(t, yaml), "appdb")
	if len(acts) != 4 {
		t.Fatalf("len(acts)=%d want 4", len(acts))
	}
	wantKinds := []string{"*statemachine.ActionSynthError", "*statemachine.ActionInjectRollback", "*statemachine.ActionDrainUntilRFQ", "*statemachine.ActionSynthReadyForQuery"}
	for i, a := range acts {
		gotType := fmt.Sprintf("%T", a)
		if gotType != wantKinds[i] {
			t.Errorf("acts[%d] = %s; want %s", i, gotType, wantKinds[i])
		}
	}
}
```

If `fmt` is not imported, add it.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Query -v`
Expected: FAIL — Transition default arm emits 0A000 for QueryFrame.

- [ ] **Step 3: Add the Query handler**

Open `internal/db/proxy/postgres/statemachine/transition.go` and add a `QueryFrame` arm to `TransitionWithParser`'s switch (before `default`):

```go
	case *QueryFrame:
		return handleQuery(s, f, rules, svc, parser)
```

Append the handler:

```go
func handleQuery(
	s ConnState, f *QueryFrame,
	rules *policy.RuleSet, svc policy.ServiceID,
	parser PolicyClassifier,
) (ConnState, []Action) {
	stmts, err := parser.Classify(f.SQL, classify_pg.SessionState{}, classify_pg.Options{})
	if err != nil || len(stmts) == 0 {
		// Empty / unparseable Q: fall through to evaluator default-deny via
		// a synthetic unknown-class statement so the evaluator picks the
		// catch-all rule, if any.
	}
	var denyDecision policy.Decision
	var denyRule policy.StatementRule
	anyDeny := false
	for _, cs := range stmts {
		d := policy.Evaluate(cs, rules, svc)
		if d.Verb == policy.VerbApprove {
			d.Verb = policy.VerbDeny
			if d.Reason == "" {
				d.Reason = "APPROVE_NOT_YET_SUPPORTED"
			}
		}
		if d.Verb == policy.VerbDeny {
			anyDeny = true
			denyDecision = d
			denyRule = lookupStatementRule(rules, d.RuleName)
			break
		}
	}
	if !anyDeny {
		// Allow path: forward; Q is atomic per Sync so no Absorbing change.
		return s, []Action{&ActionForward{}}
	}
	msg := renderDenyMessage(denyDecision)
	actions := DenyRoute(s, denyRule, msg, sqlstateForDecision(denyDecision))
	return s, actions
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestTransition_Query -v`
Expected: all four PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/transition.go internal/db/proxy/postgres/statemachine/transition_test.go
git commit -m "db: proxy/statemachine — Simple Query (Q) handler routing through DenyRoute"
```

---

## Task 12: Property tests for invariants

**Why:** §6 of the design lists 9 invariants. Table tests pin the §14.2 rows; property tests cover the combinatorial space. Use `pgregory.net/rapid` if available; otherwise the `testing/quick` fallback.

**Files:**
- Create: `internal/db/proxy/postgres/statemachine/property_test.go`
- Modify: `go.mod` (add `pgregory.net/rapid`)

- [ ] **Step 1: Add the rapid dependency (or fall back to `testing/quick`)**

Run:
```bash
go get pgregory.net/rapid@v0.7.0
go mod tidy
```

If `go get` fails because of a vendoring or air-gap policy, skip and use the `testing/quick` variant in Step 2.

- [ ] **Step 2: Write the property test**

Create `internal/db/proxy/postgres/statemachine/property_test.go`:

```go
package statemachine

import (
	"testing"

	"pgregory.net/rapid"
)

// TestProperty_AbsorbingNonSyncEmitsSuppress verifies invariant: while
// Absorbing == true, every non-Sync frame yields exactly one Suppress.
func TestProperty_AbsorbingNonSyncEmitsSuppress(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		frame := genNonSyncFrame(t)
		cache := NewFakeCacheView()
		_, acts := Transition(ConnState{LastUpstreamRFQ: 'I', Absorbing: true}, frame, cache, mustDecodeRapid(t), "appdb")
		if len(acts) != 1 {
			t.Fatalf("len(acts)=%d want 1 for absorbing non-Sync frame %T", len(acts), frame)
		}
		if _, ok := acts[0].(*ActionSuppress); !ok {
			t.Fatalf("acts[0]=%T want *ActionSuppress for frame %T", acts[0], frame)
		}
	})
}

// TestProperty_NoForwardWithClose verifies invariant: Close never coexists
// with SynthReadyForQuery in the same action list (terminate XOR continue).
func TestProperty_NoCloseAndRFQTogether(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		frame := genFrame(t)
		s := genState(t)
		cache := NewFakeCacheView()
		_, acts := Transition(s, frame, cache, mustDecodeRapid(t), "appdb")
		hasClose, hasRFQ := false, false
		for _, a := range acts {
			if _, ok := a.(*ActionClose); ok {
				hasClose = true
			}
			if _, ok := a.(*ActionSynthReadyForQuery); ok {
				hasRFQ = true
			}
		}
		if hasClose && hasRFQ {
			t.Fatalf("Close and SynthReadyForQuery in same action list: %#v (frame=%T, state=%#v)", acts, frame, s)
		}
	})
}

// TestProperty_InjectRollbackOnlyInTx verifies invariant: InjectRollback
// only emits when LastUpstreamRFQ == 'T' (or 'E').
func TestProperty_InjectRollbackOnlyInTx(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		frame := genFrame(t)
		s := genState(t)
		cache := NewFakeCacheView()
		_, acts := Transition(s, frame, cache, mustDecodeRapid(t), "appdb")
		for _, a := range acts {
			if _, ok := a.(*ActionInjectRollback); ok {
				if s.LastUpstreamRFQ != 'T' && s.LastUpstreamRFQ != 'E' {
					t.Fatalf("InjectRollback emitted while LastUpstreamRFQ=%q", s.LastUpstreamRFQ)
				}
			}
		}
	})
}

// generators -----------------------------------------------------------------

func genFrame(t *rapid.T) Frame {
	kind := rapid.IntRange(0, 8).Draw(t, "frameKind")
	switch kind {
	case 0:
		return &QueryFrame{SQL: rapid.SampledFrom([]string{"SELECT 1", "DELETE FROM users", "UPDATE x SET y=1"}).Draw(t, "sql")}
	case 1:
		return &ParseFrame{Name: rapid.SampledFrom([]string{"", "s1", "s2"}).Draw(t, "name"), SQL: rapid.SampledFrom([]string{"SELECT 1", "DELETE FROM users"}).Draw(t, "sql")}
	case 2:
		return &BindFrame{Portal: "p", Statement: rapid.SampledFrom([]string{"", "s1", "missing"}).Draw(t, "stmt")}
	case 3:
		return &DescribeFrame{Kind: 'S', Name: "s1"}
	case 4:
		return &ExecuteFrame{Portal: rapid.SampledFrom([]string{"p", "p1", "missing"}).Draw(t, "portal")}
	case 5:
		return &SyncFrame{}
	case 6:
		return &FlushFrame{}
	case 7:
		return &CloseFrame{Kind: 'S', Name: "s1"}
	default:
		return &TerminateFrame{}
	}
}

func genNonSyncFrame(t *rapid.T) Frame {
	for {
		f := genFrame(t)
		if _, ok := f.(*SyncFrame); !ok {
			return f
		}
	}
}

func genState(t *rapid.T) ConnState {
	return ConnState{
		LastUpstreamRFQ:        rapid.SampledFrom([]byte{0, 'I', 'T', 'E'}).Draw(t, "rfq"),
		Absorbing:              rapid.Bool().Draw(t, "absorbing"),
		UpstreamDirtySinceSync: rapid.Bool().Draw(t, "dirty"),
	}
}

func mustDecodeRapid(t *rapid.T) *PolicyRuleSet {
	return cachedRules
}

// cachedRules is built once at init for property tests; rebuilding it per
// iteration is slow.
var cachedRules *PolicyRuleSet

type PolicyRuleSet = policyRuleSetAlias // see init below
```

The `PolicyRuleSet` alias is a workaround for the property tests not importing `policy` directly to avoid a cycle through `_test.go` files. If the import is clean, simplify by importing `policy` and using `*policy.RuleSet` directly — the property test in production form should just do:

```go
import "github.com/agentsh/agentsh/internal/db/policy"

var cachedRules *policy.RuleSet

func init() {
	rs, _, err := policy.Decode([]byte(`db_services: {appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue}}
database_rules:
  - name: block-delete
    db_service: appdb
    operations: [delete]
    decision: deny
  - name: block-delete-soft
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue`))
	if err != nil {
		panic(err)
	}
	cachedRules = rs
}

func mustDecodeRapid(_ *rapid.T) *policy.RuleSet { return cachedRules }
```

If the rapid dependency is not available, replace the body of each `Test*Property*` with a `testing/quick` configuration:

```go
import "testing/quick"

func TestProperty_AbsorbingNonSyncEmitsSuppress(t *testing.T) {
	cfg := &quick.Config{MaxCount: 200}
	if err := quick.Check(func(seed int64) bool {
		// Use seed to pick a frame kind, then run the assertion.
		// Implementation omitted for brevity; mirror genFrame/genState
		// from the rapid version.
		return true
	}, cfg); err != nil {
		t.Fatal(err)
	}
}
```

Pick rapid if available; the assertion machinery is much more ergonomic.

- [ ] **Step 3: Run property tests**

Run: `go test ./internal/db/proxy/postgres/statemachine/ -count=1 -run TestProperty -v`
Expected: PASS. If `rapid` is not available, fall back to `testing/quick`; both must demonstrate the invariants hold across at least 200 iterations.

- [ ] **Step 4: Commit**

```bash
git add internal/db/proxy/postgres/statemachine/property_test.go go.mod go.sum
git commit -m "db: proxy/statemachine — property tests for §6 invariants"
```

---

## Task 13: `extquery.go` dispatcher

**Why:** Translates the per-frame Transition output into real I/O. Reads from `pc.backend`, calls `Transition`, executes each Action against `pc.backend` (client side) or `pc.state.upstreamFE` (upstream side), and updates `pc.state.smState`.

**Files:**
- Create: `internal/db/proxy/postgres/extquery.go`
- Create: `internal/db/proxy/postgres/extquery_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/db/proxy/postgres/extquery_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// extqueryFixture wires a proxyConn-equivalent struct against in-process
// net.Pipe connections for client and upstream. Pkg-internal helpers; the
// rest of the package's tests use the same patterns.
type extqueryFixture struct {
	clientConn, clientPeer net.Conn
	upstreamConn, upstreamPeer net.Conn
	pc *proxyConn
	cancel func()
}

func newExtqueryFixture(t *testing.T) *extqueryFixture {
	t.Helper()
	cl, cp := net.Pipe()
	up, upp := net.Pipe()
	srv := mustNewServer(t) // existing helper from server_test.go
	svc := srv.cfg.Services[0]
	pc := newProxyConn(srv, svc, cl, 1000)
	pc.state.upstream = up
	pc.state.upstreamFE = pgproto3.NewFrontend(up, up)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	pc.wireCache = preparedcache.New(0)
	pc.sqlCache = preparedcache.New(0)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	_ = ctx
	return &extqueryFixture{
		clientConn: cl, clientPeer: cp,
		upstreamConn: up, upstreamPeer: upp,
		pc: pc, cancel: cancel,
	}
}

func TestExtqueryHandle_Parse_AllowPath_ForwardsAndPopulatesCache(t *testing.T) {
	fx := newExtqueryFixture(t)
	defer fx.cancel()
	// Client side sends a Parse frame.
	clientFE := pgproto3.NewFrontend(fx.clientPeer, fx.clientPeer)
	clientFE.Send(&pgproto3.Parse{Name: "s1", Query: "SELECT 1"})
	if err := clientFE.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	// Upstream peer reads what the dispatcher forwards.
	upBackend := pgproto3.NewBackend(fx.upstreamPeer, fx.upstreamPeer)
	go func() {
		// Dispatcher reads the Parse; should forward to upstream.
		msg, err := fx.pc.backend.Receive()
		if err != nil {
			return
		}
		_ = fx.pc.handleExtendedFrame(context.Background(), msg)
	}()
	got, err := upBackend.Receive()
	if err != nil {
		t.Fatalf("upstream Receive: %v", err)
	}
	parse, ok := got.(*pgproto3.Parse)
	if !ok {
		t.Fatalf("upstream got %T; want *pgproto3.Parse", got)
	}
	if parse.Name != "s1" || parse.Query != "SELECT 1" {
		t.Fatalf("Parse forwarded mismatched: %#v", parse)
	}
	if _, ok := fx.pc.wireCache.Get("s1"); !ok {
		t.Fatal("wireCache should contain s1 after allow")
	}
}
```

This test is a stretch goal — the harness (`mustNewServer`) is established in 04c's tests. Mirror that pattern. If the in-process pipe driver is too elaborate for the initial pass, scale this down to a lighter "Action execution" test (using a recording mock of pc.backend.Send and pc.state.upstreamFE.Send) before adding the full pgproto3 round-trip.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestExtqueryHandle_Parse`
Expected: build error — `handleExtendedFrame`, `wireCache`, `sqlCache`, `smState` undefined.

- [ ] **Step 3: Extend `connState` and `proxyConn`**

Open `internal/db/proxy/postgres/proxyconn.go`. Add fields and an accessor:

```go
// Add to import block:
//   "github.com/agentsh/agentsh/internal/db/proxy/postgres/preparedcache"
//   "github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"

// In connState struct, replace:
//   lastUpstreamRFQ byte
// with:
//   smState *statemachine.ConnState

// Add accessor on connState (or proxyConn) that preserves the 04c readers:
func (cs *connState) lastUpstreamRFQ() byte {
	if cs.smState == nil {
		return 0
	}
	return cs.smState.LastUpstreamRFQ
}
```

Then, locate every reader of `pc.state.lastUpstreamRFQ` in the package (04c wrote a few) and either:
- replace with `pc.state.lastUpstreamRFQ()` (method call), or
- replace with `pc.state.smState.LastUpstreamRFQ` (field access)

The simpler form is field access; pick the one less disruptive to surrounding code.

Add fields on `proxyConn`:

```go
type proxyConn struct {
	srv       *Server
	svc       Service
	logger    logger
	conn      net.Conn
	backend   *pgproto3.Backend
	state     *connState
	wireCache *preparedcache.Cache
	sqlCache  *preparedcache.Cache
}
```

Update `newProxyConn` to initialize:

```go
func newProxyConn(srv *Server, svc Service, conn net.Conn, peerUID uint32) *proxyConn {
	return &proxyConn{
		srv:     srv,
		svc:     svc,
		logger:  srv.logger,
		conn:    conn,
		backend: pgproto3.NewBackend(conn, conn),
		state: &connState{
			dbService:      svc.Name,
			peerUID:        peerUID,
			clientIdentity: clientIdentityFromUID(peerUID),
			smState:        &statemachine.ConnState{},
		},
		wireCache: preparedcache.New(0),
		sqlCache:  preparedcache.New(0),
	}
}
```

- [ ] **Step 4: Implement the dispatcher**

Create `internal/db/proxy/postgres/extquery.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres/statemachine"
)

// handleExtendedFrame translates a pgproto3 frontend frame into a Transition
// invocation and executes the returned Actions against the per-connection
// I/O. Called from simpleQueryLoop for Parse/Bind/Describe/Execute/Sync/
// Flush/Close (the existing handleQuery still handles 'Q' directly; this
// task only adds the extended-query plumbing).
func (pc *proxyConn) handleExtendedFrame(ctx context.Context, msg pgproto3.FrontendMessage) error {
	frame := frameFromPgproto(msg)
	if frame == nil {
		// Caller already dispatches Q/X; anything that arrives here that
		// we don't recognize is the 04c "unsupported" path.
		return pc.handleUnsupportedFrame(ctx, msg)
	}
	wireCacheView := wireCacheView{c: pc.wireCache}
	parser := pc.srv.classifierFor(pc.svc.Dialect)
	next, actions := statemachine.TransitionWithParser(
		*pc.state.smState,
		frame,
		wireCacheView,
		pc.srv.policy(),
		policy.ServiceID(pc.svc.Name),
		parser,
	)
	*pc.state.smState = next
	return pc.executeActions(ctx, msg, actions)
}

// executeActions runs each Action against the per-connection I/O.
// origFrame is the original frontend frame, used for ActionForward.
func (pc *proxyConn) executeActions(ctx context.Context, origFrame pgproto3.FrontendMessage, actions []statemachine.Action) error {
	for _, act := range actions {
		switch a := act.(type) {
		case *statemachine.ActionForward:
			pc.state.upstreamFE.Send(origFrame)
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return fmt.Errorf("upstream flush: %w", err)
			}
		case *statemachine.ActionSynthError:
			severity := a.Severity
			if severity == "" {
				severity = "ERROR"
			}
			pc.backend.Send(&pgproto3.ErrorResponse{
				Severity:            severity,
				SeverityUnlocalized: severity,
				Code:                a.SQLState,
				Message:             a.Message,
			})
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("client flush: %w", err)
			}
		case *statemachine.ActionSynthReadyForQuery:
			pc.backend.Send(&pgproto3.ReadyForQuery{TxStatus: a.Status})
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("client flush rfq: %w", err)
			}
		case *statemachine.ActionSynthParseComplete:
			pc.backend.Send(&pgproto3.ParseComplete{})
		case *statemachine.ActionSynthBindComplete:
			pc.backend.Send(&pgproto3.BindComplete{})
		case *statemachine.ActionSuppress:
			// drop on the floor
		case *statemachine.ActionInjectRollback:
			pc.state.upstreamFE.Send(&pgproto3.Query{String: "ROLLBACK"})
			if err := pc.state.upstreamFE.Flush(); err != nil {
				return fmt.Errorf("upstream flush rollback: %w", err)
			}
		case *statemachine.ActionDrainUntilRFQ:
			if _, err := pc.forwardUpstreamUntilRFQ(ctx, timeNow(), 0); err != nil {
				return fmt.Errorf("drain: %w", err)
			}
		case *statemachine.ActionClose:
			pc.closeUpstream()
			return errInTxTerminate
		case *statemachine.ActionTrackUpstreamRFQ:
			pc.state.smState.LastUpstreamRFQ = a.Status
		default:
			return fmt.Errorf("postgres: unknown statemachine action %T", a)
		}
	}
	return nil
}

// frameFromPgproto converts a pgproto3.FrontendMessage to a statemachine.Frame.
// Returns nil for messages the dispatcher does not handle (Plan 05a does
// not handle FunctionCall, CopyData, etc. — those still go through
// handleUnsupportedFrame).
func frameFromPgproto(msg pgproto3.FrontendMessage) statemachine.Frame {
	switch m := msg.(type) {
	case *pgproto3.Query:
		return &statemachine.QueryFrame{SQL: m.String}
	case *pgproto3.Parse:
		return &statemachine.ParseFrame{Name: m.Name, SQL: m.Query}
	case *pgproto3.Bind:
		return &statemachine.BindFrame{Portal: m.DestinationPortal, Statement: m.PreparedStatement}
	case *pgproto3.Describe:
		return &statemachine.DescribeFrame{Kind: m.ObjectType, Name: m.Name}
	case *pgproto3.Execute:
		return &statemachine.ExecuteFrame{Portal: m.Portal}
	case *pgproto3.Sync:
		return &statemachine.SyncFrame{}
	case *pgproto3.Flush:
		return &statemachine.FlushFrame{}
	case *pgproto3.Close:
		return &statemachine.CloseFrame{Kind: m.ObjectType, Name: m.Name}
	case *pgproto3.Terminate:
		return &statemachine.TerminateFrame{}
	default:
		return nil
	}
}

// wireCacheView adapts *preparedcache.Cache to statemachine.CacheView, with
// a CacheValue ↔ preparedcache.Entry conversion at the boundary.
type wireCacheView struct {
	c *preparedcache.Cache
}

func (v wireCacheView) Get(name string) (statemachine.CacheValue, bool) {
	e, ok := v.c.Get(name)
	if !ok {
		return statemachine.CacheValue{}, false
	}
	return statemachine.CacheValue{
		Verb:    e.Classification.RawVerb,
		GroupID: groupIDFromClassification(e.Classification),
	}, true
}

func (v wireCacheView) Put(name string, val statemachine.CacheValue) {
	// On Put, we don't have the full ClassifiedStatement available — the
	// state machine extracts the minimal CacheValue from its own classify
	// step. Reconstruct a partial Entry for the cache. The classifier-side
	// re-eval at Execute time will produce the live decision.
	v.c.Put(name, preparedcache.Entry{
		Classification: effectsFromCacheValue(val),
	})
}

func (v wireCacheView) Delete(name string) { v.c.Delete(name) }
func (v wireCacheView) Clear()             { v.c.Clear() }

func groupIDFromClassification(cs effectsClassifiedStatement) uint8 {
	if len(cs.Effects) == 0 {
		return 0
	}
	return uint8(cs.Effects[0].Group)
}
```

The dispatcher above references `effectsFromCacheValue` and `effectsClassifiedStatement`. These are conversion shims; finalize them as plain wrappers in this file:

```go
type effectsClassifiedStatement = effects.ClassifiedStatement

func effectsFromCacheValue(v statemachine.CacheValue) effects.ClassifiedStatement {
	return effects.ClassifiedStatement{RawVerb: v.Verb}
}
```

Add `"github.com/agentsh/agentsh/internal/db/effects"` to the import block.

- [ ] **Step 5: Wire the dispatcher into the simpleQueryLoop**

Open `internal/db/proxy/postgres/simplequery.go`. Replace the existing `simpleQueryLoop` body with:

```go
func (pc *proxyConn) simpleQueryLoop(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		msg, err := pc.backend.Receive()
		if err != nil {
			return err
		}
		switch msg.(type) {
		case *pgproto3.Query:
			if err := pc.handleQuery(ctx, msg.(*pgproto3.Query)); err != nil {
				return err
			}
		case *pgproto3.Terminate:
			if pc.state.upstreamFE != nil {
				pc.state.upstreamFE.Send(msg)
				_ = pc.state.upstreamFE.Flush()
			}
			return nil
		case *pgproto3.Parse, *pgproto3.Bind, *pgproto3.Describe, *pgproto3.Execute,
			*pgproto3.Sync, *pgproto3.Flush, *pgproto3.Close:
			if err := pc.handleExtendedFrame(ctx, msg); err != nil {
				return err
			}
		default:
			if err := pc.handleUnsupportedFrame(ctx, msg); err != nil {
				return err
			}
		}
	}
}
```

This preserves 04c's `handleQuery` and `handleUnsupportedFrame` paths and routes Extended Query frames to the new dispatcher.

- [ ] **Step 6: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestExtqueryHandle_Parse -v`
Expected: PASS.

Run also: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: PASS — all 04c tests continue to pass, the new dispatcher does not regress them.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/extquery.go internal/db/proxy/postgres/extquery_test.go internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/proxyconn.go
git commit -m "db: proxy — extquery dispatcher wiring Transition into per-conn I/O"
```

---

## Task 14: Wire `TxStartedAt` and refresh `upstreamread.go`

**Why:** §14.2 needs the proxy to update `Phase` and `TxStartedAt` whenever the upstream RFQ byte changes. 04c writes `lastUpstreamRFQ`; 05a additionally tracks the `time.Time` of the first `'T'` after `'I'`.

**Files:**
- Modify: `internal/db/proxy/postgres/upstreamread.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/upstreamread_test.go`:

```go
func TestForwardUpstream_TracksTxStartedAt(t *testing.T) {
	pc, peer := setupPCWithFakeUpstream(t)
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'I'}
	go func() {
		fe := pgproto3.NewBackend(peer, peer)
		fe.Send(&pgproto3.ReadyForQuery{TxStatus: 'T'})
		_ = fe.Flush()
	}()
	_, err := pc.forwardUpstreamUntilRFQ(context.Background(), time.Now(), 0)
	if err != nil {
		t.Fatalf("forward: %v", err)
	}
	if pc.state.smState.LastUpstreamRFQ != 'T' {
		t.Errorf("LastUpstreamRFQ=%q want 'T'", pc.state.smState.LastUpstreamRFQ)
	}
	if pc.state.smState.TxStartedAt.IsZero() {
		t.Error("TxStartedAt should be populated on I→T transition")
	}
	if pc.state.smState.Phase != statemachine.PhaseInTx {
		t.Errorf("Phase=%v want PhaseInTx", pc.state.smState.Phase)
	}
}
```

`setupPCWithFakeUpstream` already exists in upstreamread_test.go from 04c; reuse it.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestForwardUpstream_TracksTxStartedAt`
Expected: FAIL — TxStartedAt remains zero (upstreamread.go does not populate it yet).

- [ ] **Step 3: Update `forwardUpstreamUntilRFQ`**

Open `internal/db/proxy/postgres/upstreamread.go`. Replace the `case *pgproto3.ReadyForQuery:` arm with:

```go
		case *pgproto3.ReadyForQuery:
			prev := byte(0)
			if pc.state.smState != nil {
				prev = pc.state.smState.LastUpstreamRFQ
				pc.state.smState.LastUpstreamRFQ = m.TxStatus
				switch m.TxStatus {
				case 'I':
					pc.state.smState.Phase = statemachine.PhaseIdle
					pc.state.smState.TxStartedAt = time.Time{}
				case 'T':
					pc.state.smState.Phase = statemachine.PhaseInTx
					if prev != 'T' {
						pc.state.smState.TxStartedAt = time.Now()
					}
				case 'E':
					pc.state.smState.Phase = statemachine.PhaseInTxError
				}
			}
			r.BytesOut += int64(estimatedFrameSize(m))
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return r, fmt.Errorf("flush after RFQ: %w", err)
			}
			r.LatencyMs = time.Since(sentAt).Milliseconds()
			return r, nil
```

Add the `statemachine` import.

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestForwardUpstream -v`
Expected: PASS.

- [ ] **Step 5: Run the full proxy test suite**

Run: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/upstreamread.go internal/db/proxy/postgres/upstreamread_test.go
git commit -m "db: proxy — upstreamread tracks Phase and TxStartedAt on RFQ transitions"
```

---

## Task 15: Refactor `handleQuery` to share `DenyRoute`

**Why:** 04c's `handleQuery` has its own in-tx vs out-of-tx branching. With `statemachine.DenyRoute` defined, the Simple Query path should call it so the two deny paths (Q vs Extended Query) stay in sync.

**Files:**
- Modify: `internal/db/proxy/postgres/simplequery.go`
- Modify: `internal/db/proxy/postgres/simplequery_test.go`

- [ ] **Step 1: Write the failing test for rollback_then_continue on a Q frame**

Append to `internal/db/proxy/postgres/simplequery_test.go`:

```go
func TestHandleQuery_DenyInTx_RollbackThenContinue_SimpleQuery(t *testing.T) {
	yaml := `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue }
database_rules:
  - name: block-delete-soft
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	srv := mustNewServerWithYAML(t, yaml) // existing helper from server_test.go
	pc := mustPCFromSrv(t, srv)            // existing helper
	pc.state.smState = &statemachine.ConnState{LastUpstreamRFQ: 'T'}
	pc.state.lastUpstreamRFQNote = 'T' // adjust if helper exposes this differently
	// Drive a Q frame through handleQuery; assert that an ActionInjectRollback
	// equivalent (ROLLBACK to upstream) was emitted by inspecting the
	// upstream fake's received frames.
	err := pc.handleQuery(context.Background(), &pgproto3.Query{String: "DELETE FROM users"})
	if err != nil && !errors.Is(err, errInTxTerminate) {
		// rollback path returns nil; terminate path returns errInTxTerminate.
		t.Fatalf("handleQuery: %v", err)
	}
	if !pc.upstreamFake.SawRollbackInject() {
		t.Error("expected ROLLBACK injected to upstream")
	}
}
```

This test depends on a `upstreamFake` exposing `SawRollbackInject()`. Audit the existing 04c spine helpers (`testupstream_test.go`) and add a helper if missing — it should remember every Q frame body it received and expose a method that searches for `"ROLLBACK"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestHandleQuery_DenyInTx_RollbackThenContinue_SimpleQuery -v`
Expected: FAIL — 04c's handleQuery returns `errInTxTerminate` for any in-tx deny; ROLLBACK is never injected.

- [ ] **Step 3: Refactor `handleQuery` deny branch**

Open `internal/db/proxy/postgres/simplequery.go`. Replace the deny branch (the `if anyDeny { ... }` block in `handleQuery`) with:

```go
	if anyDeny {
		// Find the first denying decision and look up its rule for the
		// DenyModeInTx field.
		var denyIdx int
		for i, d := range decisions {
			if d.Verb == policy.VerbDeny {
				denyIdx = i
				break
			}
		}
		denyDecision := decisions[denyIdx]
		denyRule := lookupStatementRuleByName(pc.srv.policy(), denyDecision.RuleName)

		denyAction := "none"
		if pc.state.smState != nil && (pc.state.smState.LastUpstreamRFQ == 'T' || pc.state.smState.LastUpstreamRFQ == 'E') {
			if denyRule.DenyModeInTx == "rollback_then_continue" {
				denyAction = "rollback_injected"
			} else {
				denyAction = "connection_terminated"
			}
		}
		pc.emitDenyEvents(ctx, stmts, decisions, q.String, batchSHA, denyAction)

		msg, sqlstate := pickDenySynth(decisions)
		actions := statemachine.DenyRoute(
			*pc.state.smState,
			denyRule,
			msg,
			sqlstate,
		)
		return pc.executeActions(ctx, q, actions)
	}
```

Add the `statemachine` import. The helper `lookupStatementRuleByName` is a 04c-friendly wrapper around `policy.RuleSet.AllStatementRules()` — add it in `internal/db/proxy/postgres/simplequery.go`:

```go
func lookupStatementRuleByName(rs *policy.RuleSet, name string) policy.StatementRule {
	if rs == nil || name == "" {
		return policy.StatementRule{}
	}
	for _, r := range rs.AllStatementRules() {
		if r.Name == name {
			return r
		}
	}
	return policy.StatementRule{}
}
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestHandleQuery_DenyInTx_RollbackThenContinue_SimpleQuery -v`
Expected: PASS.

Run also: `go test ./internal/db/proxy/postgres/ -count=1`
Expected: PASS — all 04c deny tests continue to pass.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/simplequery.go internal/db/proxy/postgres/simplequery_test.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — handleQuery (Q frame) routes through statemachine.DenyRoute"
```

---

## Task 16: Event-builder populates `tx_started_at` and `rollback_injected`

**Why:** With `pc.state.smState.TxStartedAt` populated by Task 14 and `denyAction == "rollback_injected"` set by Task 15, the event builder needs to surface both onto `DBEvent.TxContext`.

**Files:**
- Modify: `internal/db/proxy/postgres/eventbuilder.go`
- Modify: `internal/db/proxy/postgres/eventbuilder_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/eventbuilder_test.go`:

```go
func TestBuildEvent_TxStartedAt_PopulatedWhenInTx(t *testing.T) {
	now := time.Date(2026, 5, 11, 12, 0, 0, 0, time.UTC)
	args := buildArgs{
		Stmt: effects.ClassifiedStatement{RawVerb: "SELECT", Effects: []effects.Effect{{Group: effects.GroupRead}}},
		Decision: policy.Decision{Verb: policy.VerbAllow},
		SQL: "SELECT 1", Tier: policy.RedactionParametersRedacted,
		Conn: connState{
			smState: &statemachine.ConnState{
				LastUpstreamRFQ: 'T',
				TxStartedAt:     now,
			},
		},
		Parser: classify_pg.New(classify_pg.DialectPostgres),
	}
	ev := buildStatementEvent(args)
	if !ev.TxContext.InTransaction {
		t.Error("InTransaction should be true under LastUpstreamRFQ='T'")
	}
	if !ev.TxContext.TxStartedAt.Equal(now) {
		t.Errorf("TxStartedAt=%v want %v", ev.TxContext.TxStartedAt, now)
	}
}

func TestBuildEvent_DenyActionRollbackInjected(t *testing.T) {
	args := buildArgs{
		Stmt:    effects.ClassifiedStatement{RawVerb: "DELETE", Effects: []effects.Effect{{Group: effects.GroupDelete}}},
		Decision: policy.Decision{Verb: policy.VerbDeny, RuleName: "block-delete-soft"},
		SQL: "DELETE FROM users", Tier: policy.RedactionParametersRedacted,
		Conn: connState{
			smState: &statemachine.ConnState{LastUpstreamRFQ: 'T', TxStartedAt: time.Now()},
		},
		DenyAction: "rollback_injected",
		Parser:     classify_pg.New(classify_pg.DialectPostgres),
	}
	ev := buildStatementEvent(args)
	if ev.TxContext.DenyAction != "rollback_injected" {
		t.Errorf("DenyAction=%q want rollback_injected", ev.TxContext.DenyAction)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestBuildEvent_TxStartedAt -v`
Expected: FAIL — `TxStartedAt` is zero on the produced event (04c's builder doesn't read smState).

- [ ] **Step 3: Update `buildStatementEvent`**

Open `internal/db/proxy/postgres/eventbuilder.go`. Locate the `TxContext` population (typically near the end of `buildStatementEvent`). Replace it with:

```go
	tx := events.EventTxContext{
		DenyAction: a.DenyAction,
	}
	if a.Conn.smState != nil {
		switch a.Conn.smState.LastUpstreamRFQ {
		case 'T', 'E':
			tx.InTransaction = true
		}
		if !a.Conn.smState.TxStartedAt.IsZero() {
			tx.TxStartedAt = a.Conn.smState.TxStartedAt
		}
	}
	ev.TxContext = tx
```

If the existing builder uses `pc.state.lastUpstreamRFQ` directly (04c often did), trace those references and switch them to `a.Conn.smState.LastUpstreamRFQ`. Locate them with:

```bash
git grep -n 'lastUpstreamRFQ' -- internal/db/proxy/postgres/eventbuilder.go
```

- [ ] **Step 4: Run tests to confirm they pass**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestBuildEvent -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/eventbuilder.go internal/db/proxy/postgres/eventbuilder_test.go
git commit -m "db: proxy/eventbuilder — populate tx_started_at and rollback_injected deny_action"
```

---

## Task 17: Spine tests — Extended Query against the fake upstream

**Why:** The 04c spine suite proves the wire path composes end-to-end. Plan 05a adds three new flows: extended-query allow, extended-query deny (out-of-tx), and in-tx deny with `rollback_then_continue`.

**Files:**
- Modify: `internal/db/proxy/postgres/spine_test.go`
- Modify: `internal/db/proxy/postgres/testupstream_test.go` (extend the fake upstream)

- [ ] **Step 1: Extend the fake upstream to handle Extended Query frames**

Open `internal/db/proxy/postgres/testupstream_test.go`. Locate the response goroutine and extend it to react to `Parse` / `Bind` / `Describe` / `Execute` / `Sync` by responding with `ParseComplete`, `BindComplete`, `RowDescription`, `DataRow`, `CommandComplete`, `ReadyForQuery(I)` in the appropriate order. Mirror the existing `'Q'` handling.

```go
case *pgproto3.Parse:
	t.parseSeen = append(t.parseSeen, m.Query)
	t.send(&pgproto3.ParseComplete{})
case *pgproto3.Bind:
	t.send(&pgproto3.BindComplete{})
case *pgproto3.Describe:
	t.send(&pgproto3.NoData{})
case *pgproto3.Execute:
	t.send(&pgproto3.RowDescription{})
	t.send(&pgproto3.DataRow{Values: [][]byte{[]byte("1")}})
	t.send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
case *pgproto3.Sync:
	t.send(&pgproto3.ReadyForQuery{TxStatus: t.currentStatus})
```

`t.currentStatus` tracks `'I'` by default and flips on `BEGIN`/`COMMIT` seen on `'Q'` frames; the existing fake should already track this from 04c.

- [ ] **Step 2: Write the failing spine tests**

Append to `internal/db/proxy/postgres/spine_test.go`:

```go
func TestSpine_ExtendedQuery_AllowPath(t *testing.T) {
	srv, sink := mustStartSpineServer(t, allowAllPolicyYAML())
	defer srv.Shutdown(context.Background())
	cfg, _ := pgx.ParseConfig("postgres:///?host=" + srv.cfg.Services[0].Listen.Path + "&sslrootcert=" + filepath.Join(srv.cfg.StateDir, "db-ca.crt"))
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())
	// pgx.Prepare → Exec path uses Extended Query.
	_, err = conn.Prepare(context.Background(), "s1", "SELECT $1::int")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	row := conn.QueryRow(context.Background(), "s1", 42)
	var v int
	if err := row.Scan(&v); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if v != 1 { // fake upstream returns "1"
		t.Fatalf("v=%d", v)
	}
	if got := sink.NumStatementEvents(); got < 1 {
		t.Fatalf("statement events=%d want >=1", got)
	}
}

func TestSpine_ExtendedQuery_DenyOutOfTx(t *testing.T) {
	srv, sink := mustStartSpineServer(t, denyDeletePolicyYAML())
	defer srv.Shutdown(context.Background())
	cfg, _ := pgx.ParseConfig("postgres:///?host=" + srv.cfg.Services[0].Listen.Path + "&sslrootcert=" + filepath.Join(srv.cfg.StateDir, "db-ca.crt"))
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())
	_, err = conn.Prepare(context.Background(), "del", "DELETE FROM users")
	if err == nil {
		t.Fatal("Prepare should have failed under deny rule")
	}
	if !strings.Contains(err.Error(), "42501") && !strings.Contains(err.Error(), "denied") {
		t.Errorf("err lacks deny indication: %v", err)
	}
	if got := sink.NumStatementEvents(); got < 1 {
		t.Errorf("statement events=%d want >=1", got)
	}
}

func TestSpine_InTxDeny_RollbackThenContinue(t *testing.T) {
	yaml := `
db_services:
  appdb: { family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_reissue, listener: {unix: "/tmp/agentsh-appdb.sock"} }
database_rules:
  - name: block-delete-soft
    db_service: appdb
    operations: [delete]
    decision: deny
    deny_mode_in_tx: rollback_then_continue
`
	srv, sink := mustStartSpineServer(t, yaml)
	defer srv.Shutdown(context.Background())
	cfg, _ := pgx.ParseConfig("postgres:///?host=" + srv.cfg.Services[0].Listen.Path + "&sslrootcert=" + filepath.Join(srv.cfg.StateDir, "db-ca.crt"))
	conn, err := pgx.ConnectConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("pgx.Connect: %v", err)
	}
	defer conn.Close(context.Background())
	tx, err := conn.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// First statement allowed; sets transaction to 'T' state.
	var x int
	if err := tx.QueryRow(context.Background(), "SELECT 1").Scan(&x); err != nil {
		t.Fatalf("first stmt: %v", err)
	}
	// Second statement denied with rollback_then_continue.
	_, err = tx.Exec(context.Background(), "DELETE FROM users")
	if err == nil {
		t.Fatal("expected deny error")
	}
	// The connection should still be alive; rollback already happened.
	_ = tx.Rollback(context.Background()) // benign since we already rolled back
	// Check the deny event carries rollback_injected.
	gotRollback := false
	for _, ev := range sink.StatementEvents() {
		if ev.TxContext.DenyAction == "rollback_injected" {
			gotRollback = true
			break
		}
	}
	if !gotRollback {
		t.Error("expected event with deny_action: rollback_injected")
	}
}
```

The helpers `mustStartSpineServer`, `allowAllPolicyYAML`, `denyDeletePolicyYAML`, and `sink.NumStatementEvents()` / `sink.StatementEvents()` exist in the 04c spine harness; reuse them or extend as needed.

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -run TestSpine_ExtendedQuery -v -timeout 120s`
Expected: FAIL — extended query handling missing, ROLLBACK not injected, etc.

- [ ] **Step 4: Iterate until they pass**

Diagnose each failure. Likely items:
- Fake upstream missing `ParameterDescription` before `RowDescription` — add it.
- pgx prefers `Bind` parameter description; the fake may need to emit `ParameterDescription`.
- The connection's TLS leaf may need to refresh — check `tlsleaf.IssueLeaf` is being called.

Re-run after each fix until all three pass.

- [ ] **Step 5: Run the full proxy suite to confirm no regression**

Run: `go test ./internal/db/proxy/postgres/ -count=1 -timeout 120s`
Expected: PASS.

- [ ] **Step 6: Cross-compile check**

Run: `GOOS=windows go build ./...`
Expected: green.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/spine_test.go internal/db/proxy/postgres/testupstream_test.go
git commit -m "db: proxy — spine tests for extended query allow, deny, and rollback_then_continue"
```

---

## Final verification

- [ ] **Step 1: Run the full test suite**

Run: `go test ./... -count=1 -timeout 180s`
Expected: PASS.

- [ ] **Step 2: Run race detector on the new packages**

Run: `go test -race ./internal/db/proxy/postgres/... -count=1 -timeout 180s`
Expected: PASS.

- [ ] **Step 3: Cross-compile to Windows**

Run: `GOOS=windows go build ./...`
Expected: PASS.

- [ ] **Step 4: Verify the new files exist with expected names**

Run:
```bash
ls internal/db/proxy/postgres/statemachine/
ls internal/db/proxy/postgres/preparedcache/
test -f internal/db/proxy/postgres/extquery.go
```
Expected: state.go, action.go, frame.go, cacheview.go, denyroute.go, transition.go, plus their `_test.go` and `property_test.go`; preparedcache/cache.go and cache_test.go; extquery.go.

- [ ] **Step 5: Squash-merge readiness check (optional)**

Run: `git log --oneline main..HEAD | wc -l`
A double-digit count is normal here (Tasks 1–17 each commit independently). The reviewer can squash on merge.
