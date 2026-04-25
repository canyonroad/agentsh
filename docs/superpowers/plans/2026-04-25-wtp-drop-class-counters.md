# WTP Drop-Class Counters Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the five `wtp_dropped_invalid_*_total` counters at the existing reject sites in `internal/store/watchtower/AppendEvent`, plus structured WARN logs on every drop.

**Architecture:** Three private methods on `*Store` — `recordSequenceOverflow`, `recordCompactEncodeFailure`, `recordCanonicalFailure` — each owning one reject class. Helpers increment the right counter on `*WTPMetrics` (nil-safe) and emit a structured WARN with reason/event_seq/event_gen/session_id/agent_id. Each `AppendEvent` reject site calls one helper before its existing `return fmt.Errorf(...)`, so error semantics are preserved exactly.

**Tech Stack:** Go, `log/slog`, `errors.Is`, existing `internal/metrics.WTPMetrics`.

**Spec:** `docs/superpowers/specs/2026-04-25-wtp-drop-class-counters-design.md`

---

## File Structure

| File | Purpose |
|---|---|
| `internal/store/watchtower/append.go` (modify) | Houses `AppendEvent` and the three new private helpers. Existing reject-site code calls the helpers; existing error returns stay byte-identical. |
| `internal/store/watchtower/append_drop_internal_test.go` (NEW, package `watchtower`) | Direct helper invocations for all 5 drop classes. Internal because it touches unexported helpers AND because two classes (`ErrInvalidMapper`, `ErrInvalidUTF8`) are unreachable through `watchtower.New` due to construction-time validation. |
| `internal/store/watchtower/append_drop_test.go` (NEW, package `watchtower_test`) | End-to-end `watchtower.New` + `AppendEvent` integration for the three reachable drop classes (timestamp, mapper-failure, sequence-overflow) plus a happy-path negative test. |
| `internal/metrics/wtp.go` (modify) | Update the "NOT YET WIRED — emits zero" doc comments at lines 463-467 to point at `AppendEvent` as the live producer. No code changes. |

The helpers stay in `append.go` (alongside the call sites) rather than a separate file because there are only three of them, they are tightly coupled to `AppendEvent`'s error handling, and splitting them would force a reader to context-switch when reasoning about each reject site.

---

## Task 1: Add `recordSequenceOverflow` helper (TDD)

**Files:**
- Modify: `internal/store/watchtower/append.go`
- Test: `internal/store/watchtower/append_drop_internal_test.go` (NEW)

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/append_drop_internal_test.go`:

```go
package watchtower

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/pkg/types"
)

// newDropTestStore builds a minimal Store wired with a counter-asserting
// *WTPMetrics and a buffered JSON slog handler so the recordX helpers
// can be unit-tested without standing up a WAL / transport / chain.
// Returns the Store, the metrics handle, and the log buffer.
func newDropTestStore(t *testing.T) (*Store, *metrics.WTPMetrics, *bytes.Buffer) {
	t.Helper()
	col := metrics.New()
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	s := &Store{
		opts: Options{
			Logger:    logger,
			SessionID: "s-test",
			AgentID:   "a-test",
		},
		metrics: col.WTP(),
	}
	return s, col.WTP(), &buf
}

// findWarnEntry returns the single decoded WARN log entry from buf, or
// fails the test if zero or more than one entry is present.
func findWarnEntry(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 1 || lines[0] == "" {
		t.Fatalf("expected exactly 1 WARN log entry, got %d: %q", len(lines), buf.String())
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("parse log entry: %v", err)
	}
	return entry
}

func TestRecordSequenceOverflow_IncrementsCounterAndEmitsWarn(t *testing.T) {
	s, m, buf := newDropTestStore(t)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 99, Generation: 7},
	}
	s.recordSequenceOverflow(ev)

	if got := m.DroppedSequenceOverflow(); got != 1 {
		t.Fatalf("DroppedSequenceOverflow() = %d, want 1", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "sequence_overflow" {
		t.Fatalf("reason = %v, want sequence_overflow", got)
	}
	if got := entry["event_seq"]; got != float64(99) {
		t.Fatalf("event_seq = %v, want 99", got)
	}
	if got := entry["event_gen"]; got != float64(7) {
		t.Fatalf("event_gen = %v, want 7", got)
	}
	if got := entry["session_id"]; got != "s-test" {
		t.Fatalf("session_id = %v, want s-test", got)
	}
	if got := entry["agent_id"]; got != "a-test" {
		t.Fatalf("agent_id = %v, want a-test", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -run TestRecordSequenceOverflow_IncrementsCounterAndEmitsWarn ./internal/store/watchtower/
```

Expected: FAIL with `s.recordSequenceOverflow undefined` (compile error).

- [ ] **Step 3: Implement `recordSequenceOverflow`**

Add to `internal/store/watchtower/append.go` (just below the `AppendEvent` function, after `latchFatal`):

```go
// recordSequenceOverflow increments wtp_dropped_sequence_overflow_total
// and emits a structured WARN. Called from AppendEvent's
// ev.Chain.Sequence > math.MaxInt64 branch BEFORE the existing error
// return so the counter increments exactly once per drop and the WARN
// gives operators triage context (which (gen, seq) was rejected).
//
// No underlying err is logged because this is our own range check, not
// a wrapped sentinel — the message is deterministic from event_seq.
func (s *Store) recordSequenceOverflow(ev types.Event) {
	s.metrics.IncDroppedSequenceOverflow(1)
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", "sequence_overflow"),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
}
```

Add `"log/slog"` to the import block at the top of `append.go` if not already present.

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test -run TestRecordSequenceOverflow_IncrementsCounterAndEmitsWarn ./internal/store/watchtower/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "feat(wtp/store): add recordSequenceOverflow helper

Increments wtp_dropped_sequence_overflow_total and emits a structured
WARN with reason/event_seq/event_gen/session_id/agent_id. Helper called
from AppendEvent's Chain.Sequence range check (wired in a later task)."
```

---

## Task 2: Add `recordCompactEncodeFailure` helper with 3-way classification (TDD)

**Files:**
- Modify: `internal/store/watchtower/append.go`
- Test: `internal/store/watchtower/append_drop_internal_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `internal/store/watchtower/append_drop_internal_test.go`:

```go
import (
	// ... existing imports ...
	"errors"
	"fmt"

	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
)

func TestRecordCompactEncodeFailure_ClassifiesInvalidMapper(t *testing.T) {
	s, m, buf := newDropTestStore(t)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	s.recordCompactEncodeFailure(compact.ErrInvalidMapper, ev)

	if got := m.DroppedInvalidMapper(); got != 1 {
		t.Fatalf("DroppedInvalidMapper() = %d, want 1", got)
	}
	if got := m.DroppedInvalidTimestamp(); got != 0 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 0 (wrong branch fired)", got)
	}
	if got := m.DroppedMapperFailure(); got != 0 {
		t.Fatalf("DroppedMapperFailure() = %d, want 0 (wrong branch fired)", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "invalid_mapper" {
		t.Fatalf("reason = %v, want invalid_mapper", got)
	}
	if got := entry["err"]; got == nil || !strings.Contains(got.(string), "mapper is required") {
		t.Fatalf("err attr = %v, want non-empty containing %q", got, "mapper is required")
	}
}

func TestRecordCompactEncodeFailure_ClassifiesInvalidTimestamp(t *testing.T) {
	s, m, buf := newDropTestStore(t)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 2, Generation: 1},
	}
	wrapped := fmt.Errorf("compact.Encode: %w", compact.ErrInvalidTimestamp)
	s.recordCompactEncodeFailure(wrapped, ev)

	if got := m.DroppedInvalidTimestamp(); got != 1 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 1", got)
	}
	if got := m.DroppedInvalidMapper(); got != 0 {
		t.Fatalf("DroppedInvalidMapper() = %d, want 0 (wrong branch fired)", got)
	}
	if got := m.DroppedMapperFailure(); got != 0 {
		t.Fatalf("DroppedMapperFailure() = %d, want 0 (wrong branch fired)", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "invalid_timestamp" {
		t.Fatalf("reason = %v, want invalid_timestamp", got)
	}
}

func TestRecordCompactEncodeFailure_ClassifiesMapperFailureCatchAll(t *testing.T) {
	s, m, buf := newDropTestStore(t)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 3, Generation: 1},
	}
	// A mapper-side error wrapped exactly like compact/encoder.go:71 does.
	wrapped := fmt.Errorf("compact mapper: %w", errors.New("synthetic mapper failure"))
	s.recordCompactEncodeFailure(wrapped, ev)

	if got := m.DroppedMapperFailure(); got != 1 {
		t.Fatalf("DroppedMapperFailure() = %d, want 1", got)
	}
	if got := m.DroppedInvalidMapper(); got != 0 {
		t.Fatalf("DroppedInvalidMapper() = %d, want 0 (wrong branch fired)", got)
	}
	if got := m.DroppedInvalidTimestamp(); got != 0 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 0 (wrong branch fired)", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "mapper_failure" {
		t.Fatalf("reason = %v, want mapper_failure", got)
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

```bash
go test -run TestRecordCompactEncodeFailure ./internal/store/watchtower/
```

Expected: FAIL with `s.recordCompactEncodeFailure undefined` (compile error).

- [ ] **Step 3: Implement `recordCompactEncodeFailure`**

Add to `internal/store/watchtower/append.go` immediately below `recordSequenceOverflow`:

```go
// recordCompactEncodeFailure inspects err for the compact.Encode
// sentinels and routes the drop to the matching counter + WARN.
// Called from AppendEvent's compact.Encode error branch BEFORE the
// existing error return.
//
// Classification priority (errors.Is order):
//   - compact.ErrInvalidMapper    → IncDroppedInvalidMapper / "invalid_mapper"
//   - compact.ErrInvalidTimestamp → IncDroppedInvalidTimestamp / "invalid_timestamp"
//   - (fallthrough)               → IncDroppedMapperFailure / "mapper_failure"
//
// The fallthrough catches the mapper-wrapped error returned by
// compact/encoder.go:71 (`fmt.Errorf("compact mapper: %w", err)`),
// which intentionally does not preserve a typed sentinel. The
// compact.ErrMissingChain sentinel is unreachable from AppendEvent
// because the ev.Chain == nil check earlier in the function bails
// before compact.Encode runs; if a future change makes it reachable,
// it falls into the mapper_failure catch-all and surfaces in logs.
func (s *Store) recordCompactEncodeFailure(err error, ev types.Event) {
	var reason string
	switch {
	case errors.Is(err, compact.ErrInvalidMapper):
		s.metrics.IncDroppedInvalidMapper(1)
		reason = "invalid_mapper"
	case errors.Is(err, compact.ErrInvalidTimestamp):
		s.metrics.IncDroppedInvalidTimestamp(1)
		reason = "invalid_timestamp"
	default:
		s.metrics.IncDroppedMapperFailure(1)
		reason = "mapper_failure"
	}
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", reason),
		slog.String("err", err.Error()),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
}
```

- [ ] **Step 4: Run the tests to verify they pass**

```bash
go test -run TestRecordCompactEncodeFailure ./internal/store/watchtower/
```

Expected: PASS (3 sub-tests).

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "feat(wtp/store): add recordCompactEncodeFailure with 3-way classification

errors.Is checks against compact.ErrInvalidMapper / ErrInvalidTimestamp
route to their respective counters; everything else is the mapper-side
catch-all (mirrors the wrapping at compact/encoder.go:71). All three
branches emit the same WARN shape with a class-specific reason label."
```

---

## Task 3: Add `recordCanonicalFailure` helper (TDD)

**Files:**
- Modify: `internal/store/watchtower/append.go`
- Test: `internal/store/watchtower/append_drop_internal_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/store/watchtower/append_drop_internal_test.go`:

```go
import (
	// ... existing imports ...
	"github.com/agentsh/agentsh/internal/store/watchtower/chain"
)

func TestRecordCanonicalFailure_ClassifiesInvalidUTF8(t *testing.T) {
	s, m, buf := newDropTestStore(t)

	ev := types.Event{
		Timestamp: time.Unix(1700000000, 0),
		Chain:     &types.ChainState{Sequence: 4, Generation: 2},
	}
	wrapped := fmt.Errorf("chain.EncodeCanonical: %w", chain.ErrInvalidUTF8)
	s.recordCanonicalFailure(wrapped, ev)

	if got := m.DroppedInvalidUTF8(); got != 1 {
		t.Fatalf("DroppedInvalidUTF8() = %d, want 1", got)
	}

	entry := findWarnEntry(t, buf)
	if got := entry["reason"]; got != "invalid_utf8" {
		t.Fatalf("reason = %v, want invalid_utf8", got)
	}
	if got := entry["event_seq"]; got != float64(4) {
		t.Fatalf("event_seq = %v, want 4", got)
	}
	if got := entry["event_gen"]; got != float64(2) {
		t.Fatalf("event_gen = %v, want 2", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

```bash
go test -run TestRecordCanonicalFailure_ClassifiesInvalidUTF8 ./internal/store/watchtower/
```

Expected: FAIL with `s.recordCanonicalFailure undefined`.

- [ ] **Step 3: Implement `recordCanonicalFailure`**

Add to `internal/store/watchtower/append.go` immediately below `recordCompactEncodeFailure`:

```go
// recordCanonicalFailure increments wtp_dropped_invalid_utf8_total
// and emits a structured WARN. Called from AppendEvent's
// chain.EncodeCanonical error branch BEFORE the existing error
// return.
//
// chain.EncodeCanonical's only error sentinel today is
// chain.ErrInvalidUTF8 — the function returns that or nil. This
// helper unconditionally classifies as invalid_utf8 rather than
// errors.Is-checking, so a future expansion of EncodeCanonical's
// error surface will fall through here and surface as invalid_utf8
// until the helper is updated. That posture is deliberate: it keeps
// the call site one line and matches the today-only contract; if a
// new sentinel is added, the helper grows a switch like
// recordCompactEncodeFailure.
func (s *Store) recordCanonicalFailure(err error, ev types.Event) {
	s.metrics.IncDroppedInvalidUTF8(1)
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", "invalid_utf8"),
		slog.String("err", err.Error()),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
}
```

Add `"github.com/agentsh/agentsh/internal/store/watchtower/chain"` to the imports if not already present (it likely already is).

- [ ] **Step 4: Run the test to verify it passes**

```bash
go test -run TestRecordCanonicalFailure_ClassifiesInvalidUTF8 ./internal/store/watchtower/
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "feat(wtp/store): add recordCanonicalFailure helper

Increments wtp_dropped_invalid_utf8_total and emits a structured WARN.
chain.EncodeCanonical's only sentinel today is ErrInvalidUTF8; the
helper unconditionally classifies as invalid_utf8 to match that
contract. Future sentinels would extend the helper into a switch."
```

---

## Task 4: Wire helpers into `AppendEvent` reject sites

**Files:**
- Modify: `internal/store/watchtower/append.go` (3 reject sites)

This task adds NO new tests — the helpers are already covered by Task 1-3 internal tests; the wiring is verified end-to-end by Task 5's external tests.

- [ ] **Step 1: Wire `recordSequenceOverflow` at the sequence range check**

In `internal/store/watchtower/append.go`, find the existing block:

```go
	if ev.Chain.Sequence > math.MaxInt64 {
		return fmt.Errorf("watchtower: ev.Chain.Sequence %d overflows int64", ev.Chain.Sequence)
	}
```

Replace with:

```go
	if ev.Chain.Sequence > math.MaxInt64 {
		s.recordSequenceOverflow(ev)
		return fmt.Errorf("watchtower: ev.Chain.Sequence %d overflows int64", ev.Chain.Sequence)
	}
```

- [ ] **Step 2: Wire `recordCompactEncodeFailure` at the compact.Encode call**

Find:

```go
	ce, err := compact.Encode(s.opts.Mapper, ev)
	if err != nil {
		return fmt.Errorf("compact.Encode: %w", err)
	}
```

Replace with:

```go
	ce, err := compact.Encode(s.opts.Mapper, ev)
	if err != nil {
		s.recordCompactEncodeFailure(err, ev)
		return fmt.Errorf("compact.Encode: %w", err)
	}
```

- [ ] **Step 3: Wire `recordCanonicalFailure` at the chain.EncodeCanonical call**

Find:

```go
	canonicalIntegrity, err := chain.EncodeCanonical(integrityRec)
	if err != nil {
		// chain.ErrInvalidUTF8 propagates here for any peer-derived
		// field that slipped through upstream validation. Task 23
		// follow-up wires this into wtp_dropped_invalid_utf8_total;
		// today it surfaces to the caller.
		return fmt.Errorf("chain.EncodeCanonical: %w", err)
	}
```

Replace with:

```go
	canonicalIntegrity, err := chain.EncodeCanonical(integrityRec)
	if err != nil {
		s.recordCanonicalFailure(err, ev)
		return fmt.Errorf("chain.EncodeCanonical: %w", err)
	}
```

(The stale "Task 23 follow-up" comment is removed because this commit IS that follow-up.)

- [ ] **Step 4: Update the `AppendEvent` SCOPE NOTE**

Find the comment block at the top of `AppendEvent` ending with:

```go
// SCOPE NOTE: this is Task 23's core transactional path. The full
// spec additionally routes compact.ErrInvalidMapper /
// ErrInvalidTimestamp / mapper-wrapped / sequence-overflow /
// chain.ErrInvalidUTF8 through per-class drop counters
// (wtp_dropped_invalid_*_total) with structured WARN logs. That
// counter-wiring layer is follow-up work alongside the Task 22a
// sink-failure counter surface; today those errors propagate to the
// caller as wrapped errors.
```

Replace the SCOPE NOTE block with:

```go
// Per-class drop counters: every reject path (sequence overflow,
// compact.Encode classification, chain.EncodeCanonical) increments
// the matching wtp_dropped_invalid_*_total counter and emits a
// structured WARN with reason/event_seq/event_gen/session_id/agent_id
// before the wrapped error is returned. See recordSequenceOverflow,
// recordCompactEncodeFailure, recordCanonicalFailure below.
```

- [ ] **Step 5: Run the existing AppendEvent tests to verify no regression**

```bash
go test ./internal/store/watchtower/...
```

Expected: PASS — all existing AppendEvent tests should still pass because the helpers are pure side-effects (counter + WARN); the returned error is unchanged byte-for-byte.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/append.go
git commit -m "feat(wtp/store): wire drop-class helpers at AppendEvent reject sites

Three call sites: sequence-overflow check, compact.Encode error,
chain.EncodeCanonical error. Each calls the matching record* helper
before returning the existing wrapped error — error semantics are
preserved exactly. Updates the AppendEvent SCOPE NOTE to reflect that
the per-class counter wiring is now live (this commit closes the
Task 23 follow-up gap)."
```

---

## Task 5: Add external integration tests (3 reachable drop classes + happy path)

**Files:**
- Test: `internal/store/watchtower/append_drop_test.go` (NEW, package `watchtower_test`)

- [ ] **Step 1: Write the failing tests**

Create `internal/store/watchtower/append_drop_test.go`:

```go
package watchtower_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
)

// failingMapper is a Mapper that always returns the configured error.
// Used to drive AppendEvent into the mapper_failure catch-all branch
// without depending on a particular OCSF mapper's failure modes.
type failingMapper struct{ err error }

func (f failingMapper) Map(_ types.Event) (compact.MappedEvent, error) {
	return compact.MappedEvent{}, f.err
}

// dropTestFixture wires a Store with a counter-asserting collector and
// a captured logger so each test can assert the precise observability
// emitted on a drop. The Store is constructed via watchtower.New so
// the test exercises the real reject-site wiring, not the helpers
// directly. A testserver is started so Options.Dialer is satisfied;
// the transport never actually delivers anything in these tests
// because every test path errors before WAL append.
type dropTestFixture struct {
	store     *watchtower.Store
	collector *metrics.Collector
	logBuf    *bytes.Buffer
}

func newDropFixture(t *testing.T, optsMutator func(*watchtower.Options)) *dropTestFixture {
	t.Helper()
	col := metrics.New()
	var logBuf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelWarn}))

	srv := testserver.New(testserver.Options{})
	t.Cleanup(srv.Close)

	opts := watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a-test",
		SessionID:       "s-test",
		KeyFingerprint:  "sha256:drop-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		BatchMaxRecords: 8,
		BatchMaxBytes:   8 * 1024,
		BatchMaxAge:     50 * time.Millisecond,
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Metrics:         col,
		Logger:          logger,
	}
	if optsMutator != nil {
		optsMutator(&opts)
	}

	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	return &dropTestFixture{store: s, collector: col, logBuf: &logBuf}
}

// findWarnEntry parses the captured log buffer and returns the single
// drop WARN entry. Fails the test if zero or multiple entries match.
func (f *dropTestFixture) findDropWarn(t *testing.T) map[string]any {
	t.Helper()
	var matches []map[string]any
	for _, line := range strings.Split(strings.TrimRight(f.logBuf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			t.Fatalf("parse log line %q: %v", line, err)
		}
		if entry["msg"] == "wtp: dropping event before WAL append" {
			matches = append(matches, entry)
		}
	}
	if len(matches) != 1 {
		t.Fatalf("expected 1 drop WARN, got %d (full buf: %q)", len(matches), f.logBuf.String())
	}
	return matches[0]
}

func TestAppendEvent_DropsOnInvalidTimestamp(t *testing.T) {
	f := newDropFixture(t, nil)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Time{}, // zero value trips compact.ErrInvalidTimestamp
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	err := f.store.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent: expected error, got nil")
	}
	if !errors.Is(err, compact.ErrInvalidTimestamp) {
		t.Fatalf("error = %v, want errors.Is(_, ErrInvalidTimestamp)", err)
	}

	if got := f.collector.WTP().DroppedInvalidTimestamp(); got != 1 {
		t.Fatalf("DroppedInvalidTimestamp() = %d, want 1", got)
	}

	entry := f.findDropWarn(t)
	if got := entry["reason"]; got != "invalid_timestamp" {
		t.Fatalf("reason = %v, want invalid_timestamp", got)
	}
	if got := entry["event_seq"]; got != float64(1) {
		t.Fatalf("event_seq = %v, want 1", got)
	}
	if got := entry["event_gen"]; got != float64(1) {
		t.Fatalf("event_gen = %v, want 1", got)
	}
	if got := entry["session_id"]; got != "s-test" {
		t.Fatalf("session_id = %v, want s-test", got)
	}
	if got := entry["agent_id"]; got != "a-test" {
		t.Fatalf("agent_id = %v, want a-test", got)
	}
}

func TestAppendEvent_DropsOnMapperFailure(t *testing.T) {
	mapperErr := errors.New("synthetic mapper failure")
	f := newDropFixture(t, func(opts *watchtower.Options) {
		opts.Mapper = failingMapper{err: mapperErr}
		opts.AllowStubMapper = false
	})

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	err := f.store.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent: expected error, got nil")
	}
	if !errors.Is(err, mapperErr) {
		t.Fatalf("error = %v, want errors.Is(_, mapperErr)", err)
	}

	if got := f.collector.WTP().DroppedMapperFailure(); got != 1 {
		t.Fatalf("DroppedMapperFailure() = %d, want 1", got)
	}

	entry := f.findDropWarn(t)
	if got := entry["reason"]; got != "mapper_failure" {
		t.Fatalf("reason = %v, want mapper_failure", got)
	}
	if got := entry["err"]; got == nil || !strings.Contains(got.(string), "synthetic mapper failure") {
		t.Fatalf("err attr = %v, want non-empty containing %q", got, "synthetic mapper failure")
	}
}

func TestAppendEvent_DropsOnSequenceOverflow(t *testing.T) {
	f := newDropFixture(t, nil)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: math.MaxInt64 + 1, Generation: 1},
	}
	err := f.store.AppendEvent(context.Background(), ev)
	if err == nil {
		t.Fatal("AppendEvent: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "overflows int64") {
		t.Fatalf("error = %v, want message containing %q", err, "overflows int64")
	}

	if got := f.collector.WTP().DroppedSequenceOverflow(); got != 1 {
		t.Fatalf("DroppedSequenceOverflow() = %d, want 1", got)
	}

	entry := f.findDropWarn(t)
	if got := entry["reason"]; got != "sequence_overflow" {
		t.Fatalf("reason = %v, want sequence_overflow", got)
	}
	// No "err" attr expected — sequence_overflow is our own range check, not a wrapped sentinel.
	if _, present := entry["err"]; present {
		t.Fatalf("err attr present in sequence_overflow WARN; want absent")
	}
}

func TestAppendEvent_HappyPath_NoDrops(t *testing.T) {
	// Explicit no-op mutator so we go through the same fixture path as
	// the failing tests; the contract under test is "valid input bumps
	// no drop counter and emits no drop WARN."
	f := newDropFixture(t, nil)

	ev := types.Event{
		Type:      "exec",
		SessionID: "s-test",
		Timestamp: time.Now(),
		Chain:     &types.ChainState{Sequence: 1, Generation: 1},
	}
	if err := f.store.AppendEvent(context.Background(), ev); err != nil {
		t.Fatalf("AppendEvent (happy path): %v", err)
	}

	wtp := f.collector.WTP()
	if got := wtp.DroppedSequenceOverflow(); got != 0 {
		t.Errorf("DroppedSequenceOverflow() = %d, want 0", got)
	}
	if got := wtp.DroppedInvalidMapper(); got != 0 {
		t.Errorf("DroppedInvalidMapper() = %d, want 0", got)
	}
	if got := wtp.DroppedInvalidTimestamp(); got != 0 {
		t.Errorf("DroppedInvalidTimestamp() = %d, want 0", got)
	}
	if got := wtp.DroppedMapperFailure(); got != 0 {
		t.Errorf("DroppedMapperFailure() = %d, want 0", got)
	}
	if got := wtp.DroppedInvalidUTF8(); got != 0 {
		t.Errorf("DroppedInvalidUTF8() = %d, want 0", got)
	}

	// No drop WARN should have fired.
	for _, line := range strings.Split(strings.TrimRight(f.logBuf.String(), "\n"), "\n") {
		if line == "" {
			continue
		}
		var entry map[string]any
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}
		if entry["msg"] == "wtp: dropping event before WAL append" {
			t.Fatalf("happy-path append emitted a drop WARN: %v", entry)
		}
	}
}
```

- [ ] **Step 2: Run the new tests to verify they pass**

```bash
go test -run "TestAppendEvent_DropsOn|TestAppendEvent_HappyPath_NoDrops" -v ./internal/store/watchtower/
```

Expected: PASS for all four tests (`TestAppendEvent_DropsOnInvalidTimestamp`, `TestAppendEvent_DropsOnMapperFailure`, `TestAppendEvent_DropsOnSequenceOverflow`, `TestAppendEvent_HappyPath_NoDrops`).

- [ ] **Step 3: Run the full watchtower suite to confirm no regression**

```bash
go test ./internal/store/watchtower/...
```

Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add internal/store/watchtower/append_drop_test.go
git commit -m "test(wtp/store): add end-to-end drop-class tests via AppendEvent

Three reachable drop classes (invalid_timestamp, mapper_failure,
sequence_overflow) plus a happy-path negative test. Each failing case
asserts the wrapped error is preserved (errors.Is for sentinels,
substring match for the home-grown sequence-overflow message), the
matching counter increments exactly once, and the drop WARN carries
reason/event_seq/event_gen/session_id/agent_id.

The happy-path test catches a regression where every successful append
accidentally bumps a drop counter."
```

---

## Task 6: Update metrics doc comments

**Files:**
- Modify: `internal/metrics/wtp.go` (lines 463-467)

- [ ] **Step 1: Update the "NOT YET WIRED" status comments**

In `internal/metrics/wtp.go`, find this block (around line 463):

```go
//	wtp_dropped_invalid_utf8_total              AppendEvent (Task 23)                    NOT YET WIRED — emits zero
//	wtp_dropped_sequence_overflow_total         AppendEvent (Task 23)                    NOT YET WIRED — emits zero
//	wtp_dropped_invalid_mapper_total            AppendEvent (Task 23)                    NOT YET WIRED — emits zero
//	wtp_dropped_invalid_timestamp_total         AppendEvent (Task 23)                    NOT YET WIRED — emits zero
//	wtp_dropped_mapper_failure_total            AppendEvent (Task 23)                    NOT YET WIRED — emits zero
```

Replace with:

```go
//	wtp_dropped_invalid_utf8_total              AppendEvent (Task 23 follow-up)          WIRED — recordCanonicalFailure
//	wtp_dropped_sequence_overflow_total         AppendEvent (Task 23 follow-up)          WIRED — recordSequenceOverflow
//	wtp_dropped_invalid_mapper_total            AppendEvent (Task 23 follow-up)          WIRED — recordCompactEncodeFailure (defense-in-depth)
//	wtp_dropped_invalid_timestamp_total         AppendEvent (Task 23 follow-up)          WIRED — recordCompactEncodeFailure
//	wtp_dropped_mapper_failure_total            AppendEvent (Task 23 follow-up)          WIRED — recordCompactEncodeFailure (catch-all)
```

(`(defense-in-depth)` notes which counters can only increment if construction-time validation is bypassed.)

- [ ] **Step 2: Confirm the file still compiles and the metrics tests still pass**

```bash
go build ./internal/metrics/...
go test ./internal/metrics/...
```

Expected: PASS for both.

- [ ] **Step 3: Commit**

```bash
git add internal/metrics/wtp.go
git commit -m "docs(metrics): mark wtp_dropped_invalid_*_total as WIRED

Updates the producer-status table at internal/metrics/wtp.go:463-467
now that AppendEvent emits all five counters via recordSequenceOverflow,
recordCompactEncodeFailure, and recordCanonicalFailure. Notes which
counters are defense-in-depth (unreachable through normal construction
because Options.validate / chain.ComputeContextDigest catch them at
watchtower.New time)."
```

---

## Task 7: Verification

**Files:** none

- [ ] **Step 1: Full test suite**

```bash
go test ./...
```

Expected: PASS, no FAIL anywhere.

- [ ] **Step 2: Cross-compile to Windows**

```bash
GOOS=windows go build ./...
```

Expected: exit 0, no output.

- [ ] **Step 3: Roborev**

```bash
roborev review --wait
```

Expected: clean, or findings at Low severity only. Findings above Low must be fixed (per the project's between-tasks rule) before this task is considered complete.

- [ ] **Step 4: Final commit (only if roborev requested fixes; otherwise skip)**

If roborev surfaces fixable findings, address them in additional commits following the same `fix(wtp/store): roborev #NNNN — <summary>` pattern used in PR #243.

---

## Acceptance Recap

When all tasks are complete:

- All five `wtp_dropped_invalid_*_total` counters increment exactly once at their reject sites in `AppendEvent`.
- Each drop emits one structured WARN with `reason` (matching the metric suffix), `err` (where applicable), `event_seq`, `event_gen`, `session_id`, `agent_id`.
- Existing `AppendEvent` error returns are preserved verbatim — no caller-visible change to error semantics.
- 3 internal helper unit tests (one per helper, covering all 5 classification branches) + 4 external integration tests (3 reachable drops + happy path).
- `go test ./...` and `GOOS=windows go build ./...` both clean.
- `roborev review` clean (no findings above Low).
