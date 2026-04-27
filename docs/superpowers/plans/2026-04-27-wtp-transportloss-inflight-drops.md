# WTP TransportLoss In-Flight Drops + Carrier Wiring — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the in-WAL `wal.LossRecord` to on-the-wire `wtpv1.TransportLoss` (replacing today's `ErrRecordLossEncountered` fail-closed), and add six new wire reason values so in-flight client-side drops are observable as gaps server-side.

**Architecture:** The encoder splits a record stream around loss markers into a sequence of `[]*wtpv1.ClientMessage`; the inflight tracker treats `EventBatch` and `TransportLoss` symmetrically (both keyed by `to_sequence`); five drop sites in `append.go` route through a shared `Store.emitInFlightLoss` helper that calls `wal.AppendLoss` (gated by `EmitExtendedLossReasons`). OVERFLOW and CRC_CORRUPTION emit unconditionally; the six new reasons (`MAPPER_FAILURE`, `INVALID_MAPPER`, `INVALID_TIMESTAMP`, `INVALID_UTF8`, `SEQUENCE_OVERFLOW`, `ACK_REGRESSION_AFTER_GC`) are gated behind a config flag for staged rollout.

**Tech Stack:** Go 1.x, protobuf (`canyonroad/wtp/v1`), gRPC streaming, `bufconn` testserver. Cross-platform (linux/macos/windows); no OS-specific code.

**Spec:** `docs/superpowers/specs/2026-04-27-wtp-transportloss-inflight-drops-design.md`

---

## File map

**Create:**
- `internal/store/watchtower/wal/loss_reasons.go` — exported reason constants
- `internal/store/watchtower/transport/loss_reason.go` — `ToWireReason` mapper
- `internal/store/watchtower/transport/loss_reason_test.go` — mapper unit tests
- `internal/store/watchtower/transport/loss_reason_exhaustiveness_test.go` — AST walker
- `internal/store/watchtower/component_loss_carrier_test.go` — carrier component tests
- `internal/store/watchtower/component_inflight_loss_test.go` — in-flight reason tests
- `internal/store/watchtower/component_ack_regression_loss_test.go` — ack-regression test
- `proto/canyonroad/wtp/v1/testdata/transport_loss_*.bin` — wire goldens (one per reason)

**Modify:**
- `proto/canyonroad/wtp/v1/wtp.proto` — six new enum values
- `proto/canyonroad/wtp/v1/wtp.pb.go` — regenerated
- `internal/store/watchtower/wal/wal.go` — switch reason literals to constants
- `internal/store/watchtower/wal/reader.go` — switch CRC reason literal to constant
- `internal/store/watchtower/transport/transport.go` — switch ack-regression reason literal to constant
- `internal/store/watchtower/transport/state_live.go` — `encodeBatchMessage` returns slice; remove `ErrRecordLossEncountered`; iterate slice in `runLive`
- `internal/store/watchtower/transport/state_replaying.go` — iterate slice in `runReplaying`
- `internal/store/watchtower/transport/inflight.go` — docstring updates (no structural change)
- `internal/store/watchtower/append.go` — add `emitInFlightLoss`; route from each drop site
- `internal/store/watchtower/options.go` — add `EmitExtendedLossReasons`
- `internal/store/watchtower/store.go` — propagate Options field
- `internal/server/wtp.go` — propagate from config to Options
- `internal/config/config.go` — add `EmitExtendedLossReasons` field
- `internal/metrics/wtp.go` — add `wtp_loss_unknown_reason_total` counter
- `docs/superpowers/operator/wtp-monitoring-migration.md` — flag rollout doc

---

## Phase 1 — Foundation

### Task 1: Add six new wire enum values to `TransportLossReason`

**Files:**
- Modify: `proto/canyonroad/wtp/v1/wtp.proto:155-159`
- Regenerate: `proto/canyonroad/wtp/v1/wtp.pb.go`

- [ ] **Step 1: Update the proto file**

Edit `proto/canyonroad/wtp/v1/wtp.proto` lines 155-159, replacing the existing `TransportLossReason` enum with:

```proto
enum TransportLossReason {
  TRANSPORT_LOSS_REASON_UNSPECIFIED       = 0;   // wire-incompatible — receivers MUST reject.
  TRANSPORT_LOSS_REASON_OVERFLOW          = 1;   // WAL hit max_total_bytes; oldest segments dropped.
  TRANSPORT_LOSS_REASON_CRC_CORRUPTION    = 2;   // CRC mismatch encountered during WAL replay.

  // Extended (2026-04-27 spec) — gated by client-side
  // output.wtp.emit_extended_loss_reasons. Strict-enum receivers reject
  // unknown values per the UNSPECIFIED contract.
  TRANSPORT_LOSS_REASON_MAPPER_FAILURE          = 3;  // compact.Encode wrapped a mapper-side error.
  TRANSPORT_LOSS_REASON_INVALID_MAPPER          = 4;  // defense-in-depth: typed-nil mapper escaped validation.
  TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP       = 5;  // ev.Timestamp zero or pre-epoch.
  TRANSPORT_LOSS_REASON_INVALID_UTF8            = 6;  // chain.EncodeCanonical reported invalid UTF-8.
  TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW       = 7;  // ev.Chain.Sequence > math.MaxInt64.
  TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC = 8;  // computeReplayStart synthesized prefix gap.
}
```

- [ ] **Step 2: Regenerate Go bindings**

Run: `cd proto/canyonroad/wtp/v1 && go generate ./...`

If a `go:generate` directive isn't already wired, run the project's standard regeneration command (check `proto/canyonroad/wtp/v1/gen.go` or `Makefile` for the protoc invocation).

Expected: `wtp.pb.go` updated; the new `TransportLossReason_*` constants appear in the generated `var (...)` block.

- [ ] **Step 3: Verify the build still compiles**

Run: `go build ./...`
Expected: success.

- [ ] **Step 4: Commit**

```bash
git add proto/canyonroad/wtp/v1/wtp.proto proto/canyonroad/wtp/v1/wtp.pb.go
git commit -m "wtp/proto: add 6 TransportLossReason values for in-flight drops + ack regression

MAPPER_FAILURE, INVALID_MAPPER, INVALID_TIMESTAMP, INVALID_UTF8,
SEQUENCE_OVERFLOW, ACK_REGRESSION_AFTER_GC. Wire-additive (existing
strict-enum receivers will Goaway on unknown until upgraded).

Spec: docs/superpowers/specs/2026-04-27-wtp-transportloss-inflight-drops-design.md"
```

---

### Task 2: Add `wal.LossReason*` exported constants

**Files:**
- Create: `internal/store/watchtower/wal/loss_reasons.go`
- Test: `internal/store/watchtower/wal/loss_reasons_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/wal/loss_reasons_test.go`:

```go
package wal

import "testing"

func TestLossReasonConstants_StableValues(t *testing.T) {
	cases := []struct {
		name     string
		got      string
		expected string
	}{
		{"Overflow", LossReasonOverflow, "overflow"},
		{"CRCCorruption", LossReasonCRCCorruption, "crc_corruption"},
		{"AckRegressionAfterGC", LossReasonAckRegressionAfterGC, "ack_regression_after_gc"},
		{"MapperFailure", LossReasonMapperFailure, "mapper_failure"},
		{"InvalidMapper", LossReasonInvalidMapper, "invalid_mapper"},
		{"InvalidTimestamp", LossReasonInvalidTimestamp, "invalid_timestamp"},
		{"InvalidUTF8", LossReasonInvalidUTF8, "invalid_utf8"},
		{"SequenceOverflow", LossReasonSequenceOverflow, "sequence_overflow"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.got != tc.expected {
				t.Fatalf("%s = %q, want %q (on-disk-stable; do NOT change)", tc.name, tc.got, tc.expected)
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/wal/ -run TestLossReasonConstants -v`
Expected: build error — `LossReasonOverflow` etc. undefined.

- [ ] **Step 3: Create the constants file**

Create `internal/store/watchtower/wal/loss_reasons.go`:

```go
package wal

// LossRecord.Reason strings. These are written byte-for-byte to disk
// inside the loss-marker payload (encodeLossPayload), so changing any
// value is an on-disk-format break. New reasons are additive.
//
// Wire-side mapping lives in
// internal/store/watchtower/transport/loss_reason.go (ToWireReason).
const (
	LossReasonOverflow             = "overflow"
	LossReasonCRCCorruption        = "crc_corruption"
	LossReasonAckRegressionAfterGC = "ack_regression_after_gc"

	// Extended (2026-04-27 spec) — emitted only when
	// EmitExtendedLossReasons is on at the producer site.
	LossReasonMapperFailure    = "mapper_failure"
	LossReasonInvalidMapper    = "invalid_mapper"
	LossReasonInvalidTimestamp = "invalid_timestamp"
	LossReasonInvalidUTF8      = "invalid_utf8"
	LossReasonSequenceOverflow = "sequence_overflow"
)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/watchtower/wal/ -run TestLossReasonConstants -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/wal/loss_reasons.go internal/store/watchtower/wal/loss_reasons_test.go
git commit -m "wtp/wal: add LossReason* exported constants (on-disk-stable)"
```

---

### Task 3: Add `wtp_loss_unknown_reason_total` counter

**Files:**
- Modify: `internal/metrics/wtp.go` (add field + accessor + exposition)
- Modify: `internal/metrics/wtp_test.go` (extend Prometheus exposition test)

- [ ] **Step 1: Read existing metric pattern**

Read `internal/metrics/wtp.go` lines 374-405 to understand the existing `wtp_dropped_*` exposition format. Identify the atomic field declaration site (search for `wtpDroppedInvalidUTF8` field) and the helper accessor pattern (search for `IncDroppedInvalidUTF8`).

- [ ] **Step 2: Write the failing test**

In `internal/metrics/wtp_test.go`, add:

```go
func TestWTPMetrics_LossUnknownReasonExposed(t *testing.T) {
	c := metrics.NewCollector()
	c.IncWTPLossUnknownReason(3)

	var buf bytes.Buffer
	c.WriteWTPMetrics(&buf)

	out := buf.String()
	if !strings.Contains(out, "# HELP wtp_loss_unknown_reason_total") {
		t.Fatalf("HELP missing for wtp_loss_unknown_reason_total:\n%s", out)
	}
	if !strings.Contains(out, "# TYPE wtp_loss_unknown_reason_total counter") {
		t.Fatalf("TYPE missing for wtp_loss_unknown_reason_total:\n%s", out)
	}
	if !strings.Contains(out, "wtp_loss_unknown_reason_total 3") {
		t.Fatalf("counter line wrong:\n%s", out)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestWTPMetrics_LossUnknownReasonExposed -v`
Expected: build error — `IncWTPLossUnknownReason` undefined.

- [ ] **Step 4: Add the field**

In `internal/metrics/wtp.go`, find the `Collector` struct's atomic field block (where `wtpDroppedInvalidUTF8 atomic.Uint64` lives). Add:

```go
wtpLossUnknownReason atomic.Uint64
```

- [ ] **Step 5: Add the accessor**

In `internal/metrics/wtp.go`, near the existing `IncDroppedInvalidUTF8` definition, add:

```go
// IncWTPLossUnknownReason increments wtp_loss_unknown_reason_total by n.
// Called by transport.encodeBatchMessage when ToWireReason returns
// ok=false — i.e., a producer added a new wal.LossReason* string without
// updating ToWireReason. The marker is dropped (not emitted as
// UNSPECIFIED) to preserve wire-format conformance.
func (c *Collector) IncWTPLossUnknownReason(n uint64) {
	c.wtpLossUnknownReason.Add(n)
}
```

- [ ] **Step 6: Add exposition**

In `internal/metrics/wtp.go::WriteWTPMetrics`, after the existing `wtp_dropped_*` exposition block (around line 392), add:

```go
fmt.Fprint(w, "# HELP wtp_loss_unknown_reason_total Loss markers dropped because the in-WAL Reason string had no wire enum mapping. Non-zero indicates a producer added a new reason without updating ToWireReason — programming bug.\n")
fmt.Fprint(w, "# TYPE wtp_loss_unknown_reason_total counter\n")
fmt.Fprintf(w, "wtp_loss_unknown_reason_total %d\n", c.wtpLossUnknownReason.Load())
```

- [ ] **Step 7: Run test to verify it passes**

Run: `go test ./internal/metrics/ -run TestWTPMetrics_LossUnknownReasonExposed -v`
Expected: PASS.

- [ ] **Step 8: Verify no other tests broken**

Run: `go test ./internal/metrics/...`
Expected: ALL PASS.

- [ ] **Step 9: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_test.go
git commit -m "wtp/metrics: add wtp_loss_unknown_reason_total counter"
```

---

### Task 4: Add `EmitExtendedLossReasons` config field

**Files:**
- Modify: `internal/config/config.go:842-883` (add field to `AuditWatchtowerConfig`)
- Test: `internal/config/config_test.go` (add YAML round-trip case)

- [ ] **Step 1: Read existing field pattern**

Read `internal/config/config.go:842-883`. Note the `LogGoawayMessage *bool` precedent for an opt-in flag with comprehensive docs. Our flag is plain `bool` because there is no future default-flip concern — operators explicitly turn it on.

- [ ] **Step 2: Write the failing test**

In `internal/config/config_test.go`, add (place near the existing `LogGoawayMessage` round-trip tests):

```go
func TestAuditWatchtowerConfig_EmitExtendedLossReasons_DefaultsFalse(t *testing.T) {
	yamlIn := `
audit:
  watchtower:
    enabled: true
    endpoint: "host:1234"
`
	cfg, err := loadFromYAMLString(t, yamlIn)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if cfg.Audit.Watchtower.EmitExtendedLossReasons {
		t.Fatalf("EmitExtendedLossReasons default should be false; got true")
	}
}

func TestAuditWatchtowerConfig_EmitExtendedLossReasons_ExplicitTrue(t *testing.T) {
	yamlIn := `
audit:
  watchtower:
    enabled: true
    endpoint: "host:1234"
    emit_extended_loss_reasons: true
`
	cfg, err := loadFromYAMLString(t, yamlIn)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !cfg.Audit.Watchtower.EmitExtendedLossReasons {
		t.Fatalf("EmitExtendedLossReasons should be true after explicit set")
	}
}
```

If `loadFromYAMLString` does not exist, mirror the pattern used by the closest existing config round-trip test (search `loadFromYAMLString\|yaml.Unmarshal` in `internal/config/`).

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/config/ -run EmitExtendedLossReasons -v`
Expected: build error — `EmitExtendedLossReasons` undefined.

- [ ] **Step 4: Add the field**

In `internal/config/config.go`, in the `AuditWatchtowerConfig` struct, add (after the `Filter WatchtowerFilterConfig` line at 882):

```go
	// EmitExtendedLossReasons controls whether the WTP client emits
	// TransportLoss frames with the six reason values added in the
	// 2026-04-27 spec: MAPPER_FAILURE, INVALID_MAPPER, INVALID_TIMESTAMP,
	// INVALID_UTF8, SEQUENCE_OVERFLOW, ACK_REGRESSION_AFTER_GC.
	//
	// Default false. Strict-enum receivers reject unknown enum values
	// per the TRANSPORT_LOSS_REASON_UNSPECIFIED contract (Goaway on
	// unknown). Operators flip this to true once their receiving
	// Watchtower instance has been upgraded.
	//
	// OVERFLOW and CRC_CORRUPTION are always emitted (they predate this
	// spec and are part of the original wire schema) — those reasons
	// are not gated by this flag.
	EmitExtendedLossReasons bool `yaml:"emit_extended_loss_reasons"`
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/config/ -run EmitExtendedLossReasons -v`
Expected: PASS.

Run: `go test ./internal/config/...`
Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "config: add audit.watchtower.emit_extended_loss_reasons (default false)"
```

---

## Phase 2 — Reason → wire mapping

### Task 5: `transport.ToWireReason` mapper

**Files:**
- Create: `internal/store/watchtower/transport/loss_reason.go`
- Test: `internal/store/watchtower/transport/loss_reason_test.go`

- [ ] **Step 1: Write the failing test**

Create `internal/store/watchtower/transport/loss_reason_test.go`:

```go
package transport

import (
	"testing"

	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func TestToWireReason_MapsKnownConstants(t *testing.T) {
	cases := []struct {
		in   string
		want wtpv1.TransportLossReason
	}{
		{wal.LossReasonOverflow, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW},
		{wal.LossReasonCRCCorruption, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION},
		{wal.LossReasonAckRegressionAfterGC, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC},
		{wal.LossReasonMapperFailure, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE},
		{wal.LossReasonInvalidMapper, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER},
		{wal.LossReasonInvalidTimestamp, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP},
		{wal.LossReasonInvalidUTF8, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8},
		{wal.LossReasonSequenceOverflow, wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, ok := ToWireReason(tc.in)
			if !ok {
				t.Fatalf("ToWireReason(%q) ok=false; want true", tc.in)
			}
			if got != tc.want {
				t.Fatalf("ToWireReason(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestToWireReason_UnknownReturnsFalseAndUnspecified(t *testing.T) {
	got, ok := ToWireReason("not-a-known-reason")
	if ok {
		t.Fatalf("ToWireReason(unknown) ok=true; want false")
	}
	if got != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED {
		t.Fatalf("ToWireReason(unknown) = %v, want UNSPECIFIED", got)
	}
}

func TestToWireReason_NeverReturnsUnspecifiedForKnownConstants(t *testing.T) {
	known := []string{
		wal.LossReasonOverflow,
		wal.LossReasonCRCCorruption,
		wal.LossReasonAckRegressionAfterGC,
		wal.LossReasonMapperFailure,
		wal.LossReasonInvalidMapper,
		wal.LossReasonInvalidTimestamp,
		wal.LossReasonInvalidUTF8,
		wal.LossReasonSequenceOverflow,
	}
	for _, r := range known {
		got, ok := ToWireReason(r)
		if !ok {
			t.Errorf("ToWireReason(%q) ok=false", r)
			continue
		}
		if got == wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED {
			t.Errorf("ToWireReason(%q) returned UNSPECIFIED — would emit wire-incompatible frame", r)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/ -run ToWireReason -v`
Expected: build error — `ToWireReason` undefined.

- [ ] **Step 3: Create the mapper**

Create `internal/store/watchtower/transport/loss_reason.go`:

```go
package transport

import (
	"github.com/agentsh/agentsh/internal/store/watchtower/wal"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// ToWireReason maps an in-WAL wal.LossRecord.Reason string to its wire
// enum value. Returns (UNSPECIFIED, false) for unknown strings — the
// caller MUST treat false as a programming error: log ERROR, increment
// metrics.IncWTPLossUnknownReason, drop the marker. Never send
// UNSPECIFIED on the wire (it is wire-incompatible per the proto's
// TRANSPORT_LOSS_REASON_UNSPECIFIED contract).
//
// CI test (loss_reason_exhaustiveness_test.go) verifies one entry here
// per wal.LossReason* constant, AST-walking the wal package source.
func ToWireReason(s string) (wtpv1.TransportLossReason, bool) {
	switch s {
	case wal.LossReasonOverflow:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW, true
	case wal.LossReasonCRCCorruption:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION, true
	case wal.LossReasonAckRegressionAfterGC:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC, true
	case wal.LossReasonMapperFailure:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE, true
	case wal.LossReasonInvalidMapper:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER, true
	case wal.LossReasonInvalidTimestamp:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP, true
	case wal.LossReasonInvalidUTF8:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8, true
	case wal.LossReasonSequenceOverflow:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW, true
	default:
		return wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_UNSPECIFIED, false
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/watchtower/transport/ -run ToWireReason -v`
Expected: PASS (all three tests).

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/loss_reason.go internal/store/watchtower/transport/loss_reason_test.go
git commit -m "wtp/transport: add ToWireReason mapping for LossRecord.Reason"
```

---

### Task 6: AST exhaustiveness CI test for `ToWireReason`

**Files:**
- Create: `internal/store/watchtower/transport/loss_reason_exhaustiveness_test.go`

This guards against the failure mode where someone adds a new `wal.LossReason*` constant without adding a `case` to `ToWireReason` — it would silently fall through to the `default` branch and the marker would be dropped at the carrier instead of emitted on the wire. The AST walker enumerates `wal.LossReason*` constants and asserts each appears verbatim as a `case` clause in `ToWireReason`'s body.

- [ ] **Step 1: Check existing AST pattern**

Read `internal/ocsf/exhaustiveness_test.go` (referenced in the spec) to see the project's pattern for AST-driven exhaustiveness tests. Mirror its style.

- [ ] **Step 2: Write the failing test**

Create `internal/store/watchtower/transport/loss_reason_exhaustiveness_test.go`:

```go
package transport

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestToWireReason_Exhaustive enforces that every wal.LossReason*
// constant has a matching `case wal.LossReason*` clause in
// ToWireReason. Adding a new constant without updating ToWireReason
// would fall through to the UNSPECIFIED default, dropping the marker
// at the carrier — silent integrity gap. This AST walker fails CI in
// that scenario.
func TestToWireReason_Exhaustive(t *testing.T) {
	thisFile := callerFile(t)
	transportDir := filepath.Dir(thisFile)
	walDir := filepath.Join(transportDir, "..", "wal")

	walConsts := collectLossReasonConstants(t, filepath.Join(walDir, "loss_reasons.go"))
	cases := collectToWireReasonCases(t, filepath.Join(transportDir, "loss_reason.go"))

	for _, name := range walConsts {
		want := "wal." + name
		found := false
		for _, c := range cases {
			if c == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("ToWireReason missing case for %s — would silently drop loss markers with that reason", want)
		}
	}
}

func collectLossReasonConstants(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for _, ident := range vs.Names {
				if strings.HasPrefix(ident.Name, "LossReason") {
					names = append(names, ident.Name)
				}
			}
		}
		return true
	})
	if len(names) == 0 {
		t.Fatalf("no LossReason* constants found in %s", path)
	}
	return names
}

func collectToWireReasonCases(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var cases []string
	ast.Inspect(f, func(n ast.Node) bool {
		fn, ok := n.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ToWireReason" {
			return true
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range cc.List {
				sel, ok := expr.(*ast.SelectorExpr)
				if !ok {
					continue
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok {
					continue
				}
				cases = append(cases, pkg.Name+"."+sel.Sel.Name)
			}
			return true
		})
		return false
	})
	return cases
}

func callerFile(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatalf("runtime.Caller failed")
	}
	return file
}
```

- [ ] **Step 3: Run the test**

Run: `go test ./internal/store/watchtower/transport/ -run TestToWireReason_Exhaustive -v`
Expected: PASS (all 8 constants matched).

- [ ] **Step 4: Verify the test actually catches missing cases**

Temporarily comment out the `case wal.LossReasonOverflow:` line in `loss_reason.go` and re-run:

Run: `go test ./internal/store/watchtower/transport/ -run TestToWireReason_Exhaustive -v`
Expected: FAIL with "ToWireReason missing case for wal.LossReasonOverflow".

Restore the `case` line.

- [ ] **Step 5: Re-verify pass**

Run: `go test ./internal/store/watchtower/transport/ -run TestToWireReason_Exhaustive -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/loss_reason_exhaustiveness_test.go
git commit -m "wtp/transport: AST exhaustiveness test for ToWireReason"
```

---

## Phase 3 — Migrate existing reason literals to constants

### Task 7: Switch existing `wal.LossRecord.Reason` literals to constants

**Files:**
- Modify: `internal/store/watchtower/wal/wal.go:1824` (`"overflow"` literal in `dropOldestLocked`)
- Modify: `internal/store/watchtower/wal/reader.go:472-ish` (`"crc_corruption"` literal in CRC path)
- Modify: `internal/store/watchtower/transport/transport.go:799,811` (`"ack_regression_after_gc"` literals)

This is a no-behavior-change refactor — just switches string literals to the exported constants so the AST exhaustiveness test (Task 6) has a single source of truth. Catches typos and gives operators one place to find every reason string.

- [ ] **Step 1: Switch the overflow literal**

In `internal/store/watchtower/wal/wal.go`, find the line:

```go
return LossRecord{FromSequence: fromSeq, ToSequence: toSeq, Generation: hdr.Generation, Reason: "overflow"}, true, hasUserRange, nil
```

Replace `"overflow"` with `LossReasonOverflow`.

- [ ] **Step 2: Switch the crc_corruption literal**

In `internal/store/watchtower/wal/reader.go`, find the `Loss: LossRecord{...Reason: "crc_corruption"}` block (around line 472). Replace `"crc_corruption"` with `LossReasonCRCCorruption`.

- [ ] **Step 3: Switch the ack_regression literals**

In `internal/store/watchtower/transport/transport.go`, find the two occurrences of `Reason: "ack_regression_after_gc"` (lines 799 and 811 per the snapshot). Replace both with `Reason: wal.LossReasonAckRegressionAfterGC`.

- [ ] **Step 4: Verify no other literals remain**

Run: `git grep -nE '"overflow"|"crc_corruption"|"ack_regression_after_gc"' internal/store/watchtower/`
Expected: no output (every occurrence converted).

- [ ] **Step 5: Run all watchtower tests**

Run: `go test ./internal/store/watchtower/...`
Expected: ALL PASS — this is a string-equivalence refactor.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/wal/wal.go internal/store/watchtower/wal/reader.go internal/store/watchtower/transport/transport.go
git commit -m "wtp/{wal,transport}: switch LossRecord.Reason literals to wal.LossReason* consts"
```

---

## Phase 4 — Carrier (encoder + send loops)

### Task 8: Change `encodeBatchMessage` to return `[]*wtpv1.ClientMessage`

**Files:**
- Modify: `internal/store/watchtower/transport/state_live.go:270-333` (encoder + sentinel docstring)
- Test: `internal/store/watchtower/transport/state_live_internal_test.go` (encoder unit tests)

This is the single largest behavioral change in the plan. The encoder now splits a record stream around `RecordLoss` boundaries, emitting one `EventBatch` per data run and one `TransportLoss` per loss marker, in input order.

- [ ] **Step 1: Write the failing tests**

In `internal/store/watchtower/transport/state_live_internal_test.go`, add (search for the existing `encodeBatchMessage` tests; place new tests adjacent):

```go
func TestEncodeBatchMessage_DataOnly_OneFrame(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 10, Generation: 1, Payload: marshalCompactEvent(t, 10)},
		{Kind: wal.RecordData, Sequence: 11, Generation: 1, Payload: marshalCompactEvent(t, 11)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("len(msgs) = %d; want 1", len(msgs))
	}
	eb, ok := msgs[0].Msg.(*wtpv1.ClientMessage_EventBatch)
	if !ok {
		t.Fatalf("msg[0] not EventBatch: %T", msgs[0].Msg)
	}
	if eb.EventBatch.FromSequence != 10 || eb.EventBatch.ToSequence != 11 {
		t.Fatalf("from/to = %d/%d; want 10/11", eb.EventBatch.FromSequence, eb.EventBatch.ToSequence)
	}
}

func TestEncodeBatchMessage_LossOnly_OneFrame(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 5, ToSequence: 5, Generation: 1, Reason: wal.LossReasonOverflow,
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 1 {
		t.Fatalf("len(msgs) = %d; want 1", len(msgs))
	}
	tl, ok := msgs[0].Msg.(*wtpv1.ClientMessage_TransportLoss)
	if !ok {
		t.Fatalf("msg[0] not TransportLoss: %T", msgs[0].Msg)
	}
	if tl.TransportLoss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW {
		t.Fatalf("reason = %v; want OVERFLOW", tl.TransportLoss.Reason)
	}
	if tl.TransportLoss.FromSequence != 5 || tl.TransportLoss.ToSequence != 5 {
		t.Fatalf("from/to = %d/%d; want 5/5", tl.TransportLoss.FromSequence, tl.TransportLoss.ToSequence)
	}
	if tl.TransportLoss.Generation != 1 {
		t.Fatalf("generation = %d; want 1", tl.TransportLoss.Generation)
	}
}

func TestEncodeBatchMessage_DataLossData_ThreeFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 10, Generation: 1, Payload: marshalCompactEvent(t, 10)},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 11, ToSequence: 11, Generation: 1, Reason: wal.LossReasonInvalidUTF8,
		}},
		{Kind: wal.RecordData, Sequence: 12, Generation: 1, Payload: marshalCompactEvent(t, 12)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 3 {
		t.Fatalf("len(msgs) = %d; want 3", len(msgs))
	}
	if _, ok := msgs[0].Msg.(*wtpv1.ClientMessage_EventBatch); !ok {
		t.Fatalf("msg[0] not EventBatch: %T", msgs[0].Msg)
	}
	if _, ok := msgs[1].Msg.(*wtpv1.ClientMessage_TransportLoss); !ok {
		t.Fatalf("msg[1] not TransportLoss: %T", msgs[1].Msg)
	}
	if _, ok := msgs[2].Msg.(*wtpv1.ClientMessage_EventBatch); !ok {
		t.Fatalf("msg[2] not EventBatch: %T", msgs[2].Msg)
	}
	loss := msgs[1].Msg.(*wtpv1.ClientMessage_TransportLoss).TransportLoss
	if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8 {
		t.Fatalf("loss reason = %v; want INVALID_UTF8", loss.Reason)
	}
}

func TestEncodeBatchMessage_LeadingLoss_TwoFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 5, ToSequence: 5, Generation: 1, Reason: wal.LossReasonMapperFailure,
		}},
		{Kind: wal.RecordData, Sequence: 6, Generation: 1, Payload: marshalCompactEvent(t, 6)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d; want 2", len(msgs))
	}
	if _, ok := msgs[0].Msg.(*wtpv1.ClientMessage_TransportLoss); !ok {
		t.Fatalf("msg[0] not TransportLoss: %T", msgs[0].Msg)
	}
	if _, ok := msgs[1].Msg.(*wtpv1.ClientMessage_EventBatch); !ok {
		t.Fatalf("msg[1] not EventBatch: %T", msgs[1].Msg)
	}
}

func TestEncodeBatchMessage_TrailingLoss_TwoFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 6, Generation: 1, Payload: marshalCompactEvent(t, 6)},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 7, ToSequence: 7, Generation: 1, Reason: wal.LossReasonSequenceOverflow,
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d; want 2", len(msgs))
	}
	if _, ok := msgs[0].Msg.(*wtpv1.ClientMessage_EventBatch); !ok {
		t.Fatalf("msg[0] not EventBatch: %T", msgs[0].Msg)
	}
	if _, ok := msgs[1].Msg.(*wtpv1.ClientMessage_TransportLoss); !ok {
		t.Fatalf("msg[1] not TransportLoss: %T", msgs[1].Msg)
	}
}

func TestEncodeBatchMessage_ConsecutiveLosses_SeparateFrames(t *testing.T) {
	records := []wal.Record{
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 5, ToSequence: 5, Generation: 1, Reason: wal.LossReasonOverflow,
		}},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 6, ToSequence: 6, Generation: 1, Reason: wal.LossReasonInvalidUTF8,
		}},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d; want 2 (no coalescing)", len(msgs))
	}
	for i, msg := range msgs {
		if _, ok := msg.Msg.(*wtpv1.ClientMessage_TransportLoss); !ok {
			t.Fatalf("msg[%d] not TransportLoss: %T", i, msg.Msg)
		}
	}
}

func TestEncodeBatchMessage_UnknownReason_DropsMarkerIncrementsCounter(t *testing.T) {
	c := metrics.NewCollector()
	prev := encoderMetrics
	encoderMetrics = c
	t.Cleanup(func() { encoderMetrics = prev })

	records := []wal.Record{
		{Kind: wal.RecordData, Sequence: 5, Generation: 1, Payload: marshalCompactEvent(t, 5)},
		{Kind: wal.RecordLoss, Loss: wal.LossRecord{
			FromSequence: 6, ToSequence: 6, Generation: 1, Reason: "garbage-not-a-real-reason",
		}},
		{Kind: wal.RecordData, Sequence: 7, Generation: 1, Payload: marshalCompactEvent(t, 7)},
	}
	msgs, err := encodeBatchMessage(records)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	// Loss marker is dropped → only the two data EventBatch frames remain.
	if len(msgs) != 2 {
		t.Fatalf("len(msgs) = %d; want 2 (loss dropped)", len(msgs))
	}
	for i, msg := range msgs {
		if _, ok := msg.Msg.(*wtpv1.ClientMessage_EventBatch); !ok {
			t.Fatalf("msg[%d] not EventBatch: %T", i, msg.Msg)
		}
	}
	if got := c.SnapshotForTest().WTPLossUnknownReason; got != 1 {
		t.Fatalf("wtp_loss_unknown_reason_total = %d; want 1", got)
	}
}

// marshalCompactEvent helper — creates a minimal valid CompactEvent
// payload for encoder tests.
func marshalCompactEvent(t *testing.T, seq uint64) []byte {
	t.Helper()
	ce := &wtpv1.CompactEvent{
		Sequence:           seq,
		Generation:         1,
		TimestampUnixNanos: 1_700_000_000_000_000_000,
	}
	b, err := proto.Marshal(ce)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}
```

If `metrics.Collector` does not have a `SnapshotForTest()` returning a struct with the counter, mirror the existing test pattern in `internal/store/watchtower/transport/`. If a simpler pattern exists, use it (e.g., reading the counter via a getter).

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/transport/ -run TestEncodeBatchMessage -v`
Expected: build error — `encoderMetrics` undefined; the unknown-reason test fails because the encoder still returns `ErrRecordLossEncountered`.

- [ ] **Step 3: Add the metrics seam**

Open `internal/store/watchtower/transport/state_live.go`. Above `encodeBatchMessageFn` (around line 275), add:

```go
// encoderMetrics is the metrics collector the encoder increments for
// loss-marker bookkeeping. Test seam — production wiring sets this from
// transport.New via SetEncoderMetricsForTest's production sibling
// (Task 8 follow-up).
var encoderMetrics *metrics.Collector
```

Add the import: `"github.com/agentsh/agentsh/internal/metrics"`.

- [ ] **Step 4: Rewrite the encoder**

Replace the entire `encodeBatchMessage` function in `state_live.go:294-333` with:

```go
// encodeBatchMessage is the production EventBatch + TransportLoss
// encoder. It walks `records` linearly, packing consecutive RecordData
// into EventBatch ClientMessages and emitting one TransportLoss
// ClientMessage per RecordLoss. Total wire order is preserved: a
// records list of [data, data, loss, data] produces three frames in
// order: EventBatch, TransportLoss, EventBatch.
//
// On encountering a RecordLoss whose Reason has no wire enum mapping
// (ToWireReason returns ok=false): the marker is DROPPED, an ERROR is
// logged, and wtp_loss_unknown_reason_total is incremented. UNSPECIFIED
// is never emitted on the wire (it is wire-incompatible per the
// proto's TRANSPORT_LOSS_REASON_UNSPECIFIED contract). The exhaustiveness
// CI test (loss_reason_exhaustiveness_test.go) prevents this from
// happening for known wal.LossReason* constants; this branch exists for
// defense in depth.
//
// Compression is COMPRESSION_NONE on every EventBatch (zstd/gzip is
// post-MVP). TransportLoss has no body; just the (from, to, gen, reason)
// quadruple.
func encodeBatchMessage(records []wal.Record) ([]*wtpv1.ClientMessage, error) {
	var msgs []*wtpv1.ClientMessage

	// Accumulator for the current data run.
	var (
		curEvents  []*wtpv1.CompactEvent
		curFromSeq uint64
		curToSeq   uint64
		curGen     uint32
		curSeen    bool
	)

	flushData := func() {
		if !curSeen {
			return
		}
		batch := &wtpv1.EventBatch{
			FromSequence: curFromSeq,
			ToSequence:   curToSeq,
			Generation:   curGen,
			Compression:  wtpv1.Compression_COMPRESSION_NONE,
			Body: &wtpv1.EventBatch_Uncompressed{
				Uncompressed: &wtpv1.UncompressedEvents{Events: curEvents},
			},
		}
		msgs = append(msgs, &wtpv1.ClientMessage{
			Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: batch},
		})
		curEvents = nil
		curSeen = false
	}

	for _, rec := range records {
		switch rec.Kind {
		case wal.RecordLoss:
			flushData()
			wireReason, ok := ToWireReason(rec.Loss.Reason)
			if !ok {
				if encoderMetrics != nil {
					encoderMetrics.IncWTPLossUnknownReason(1)
				}
				// Continue without emitting the marker — UNSPECIFIED on
				// wire is wire-incompatible.
				continue
			}
			tl := &wtpv1.TransportLoss{
				FromSequence: rec.Loss.FromSequence,
				ToSequence:   rec.Loss.ToSequence,
				Generation:   rec.Loss.Generation,
				Reason:       wireReason,
			}
			msgs = append(msgs, &wtpv1.ClientMessage{
				Msg: &wtpv1.ClientMessage_TransportLoss{TransportLoss: tl},
			})
		case wal.RecordData:
			ce := &wtpv1.CompactEvent{}
			if err := proto.Unmarshal(rec.Payload, ce); err != nil {
				return nil, fmt.Errorf("encodeBatchMessage: unmarshal record seq=%d: %w", rec.Sequence, err)
			}
			curEvents = append(curEvents, ce)
			if !curSeen {
				curFromSeq = rec.Sequence
				curGen = rec.Generation
				curSeen = true
			}
			curToSeq = rec.Sequence
		default:
			// Skip unknown record kinds (forward compat).
		}
	}
	flushData()
	return msgs, nil
}
```

- [ ] **Step 5: Run encoder tests**

Run: `go test ./internal/store/watchtower/transport/ -run TestEncodeBatchMessage -v`
Expected: PASS for all subtests.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/state_live.go internal/store/watchtower/transport/state_live_internal_test.go
git commit -m "wtp/transport: encodeBatchMessage returns []*ClientMessage; splits around RecordLoss

Replaces ErrRecordLossEncountered fail-closed with structured emission.
Each RecordLoss becomes a TransportLoss ClientMessage; the data accumulator
flushes around it. Unknown reasons are dropped + counted (never UNSPECIFIED
on wire).

Spec: docs/superpowers/specs/2026-04-27-wtp-transportloss-inflight-drops-design.md"
```

---

### Task 9: Update `runLive` to iterate the encoder's slice

**Files:**
- Modify: `internal/store/watchtower/transport/state_live.go:74-265` (Send loop in `runLive`)

The `runLive` function calls `encodeBatchMessageFn` at four sites (lines 81, 205, 245 per the snapshot) and uses the result with `t.conn.Send(msg)`. Each call must now iterate the returned slice.

- [ ] **Step 1: Read the existing send sites**

Read `internal/store/watchtower/transport/state_live.go:74-265`. Identify all `encodeBatchMessageFn(...)` callers. There are typically four: initial replay flush, drain on ctx, drain on stream error, and the inflight-gated tick handler.

- [ ] **Step 2: Update each caller to iterate**

For each caller of the form:

```go
msg, err := encodeBatchMessageFn(batch.Records)
if err != nil {
    // existing error handling
    return ...
}
if err := t.conn.Send(msg); err != nil {
    // existing error handling
    return ...
}
inflight.Push(last.Generation, last.Sequence)
```

Replace with:

```go
msgs, err := encodeBatchMessageFn(batch.Records)
if err != nil {
    // existing error handling
    return ...
}
for _, msg := range msgs {
    if err := t.conn.Send(msg); err != nil {
        // existing error handling
        return ...
    }
    inflight.Push(extractWireHighWatermark(msg))
}
```

Where `extractWireHighWatermark(msg)` is a small helper (added in this task) that returns the `(generation, to_sequence)` of either an `EventBatch` or a `TransportLoss`:

```go
// extractWireHighWatermark returns the (generation, to_sequence) for a
// ClientMessage carrying either an EventBatch or a TransportLoss. The
// inflight tracker keys both frame types by this tuple — a BatchAck
// retiring entries up to (gen, ack_high) covers both kinds uniformly.
func extractWireHighWatermark(msg *wtpv1.ClientMessage) (uint32, uint64) {
	switch m := msg.Msg.(type) {
	case *wtpv1.ClientMessage_EventBatch:
		return m.EventBatch.Generation, m.EventBatch.ToSequence
	case *wtpv1.ClientMessage_TransportLoss:
		return m.TransportLoss.Generation, m.TransportLoss.ToSequence
	default:
		return 0, 0
	}
}
```

Add `extractWireHighWatermark` near the top of `state_live.go` (alongside the other helpers).

Update the four `inflight.Push(last.Generation, last.Sequence)` callers in `runLive` to use the per-message high-watermark instead of the per-batch `last`:

```go
gen, seq := extractWireHighWatermark(msg)
inflight.Push(gen, seq)
```

- [ ] **Step 3: Write a regression test**

In `internal/store/watchtower/transport/state_live_internal_test.go`, add (search for existing `runLive` test scaffolding to mirror its setup):

```go
func TestRunLive_TransportLossPushedToInflight(t *testing.T) {
	// Scenario: encoder returns [EventBatch{to=10}, TransportLoss{to=11}].
	// Both must be sent via conn.Send AND tracked by the inflight
	// tracker so a subsequent BatchAck{ack_high=11} retires both.
	//
	// Test the low-level invariant: extractWireHighWatermark returns
	// (gen, to) for both types.
	ebMsg := &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: &wtpv1.EventBatch{
			Generation: 1, FromSequence: 9, ToSequence: 10,
		}},
	}
	gen, seq := extractWireHighWatermark(ebMsg)
	if gen != 1 || seq != 10 {
		t.Fatalf("EventBatch high watermark = (%d, %d); want (1, 10)", gen, seq)
	}

	tlMsg := &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_TransportLoss{TransportLoss: &wtpv1.TransportLoss{
			Generation: 1, FromSequence: 11, ToSequence: 11,
			Reason: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW,
		}},
	}
	gen, seq = extractWireHighWatermark(tlMsg)
	if gen != 1 || seq != 11 {
		t.Fatalf("TransportLoss high watermark = (%d, %d); want (1, 11)", gen, seq)
	}
}
```

- [ ] **Step 4: Run unit tests**

Run: `go test ./internal/store/watchtower/transport/ -run TestRunLive_TransportLossPushedToInflight -v`
Expected: PASS.

Run: `go test ./internal/store/watchtower/transport/...`
Expected: ALL PASS — existing `runLive` tests should continue to pass (the slice iteration is functionally equivalent for data-only inputs).

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/state_live.go internal/store/watchtower/transport/state_live_internal_test.go
git commit -m "wtp/transport: runLive iterates encoder slice; tracks per-message high watermark"
```

---

### Task 10: Update `runReplaying` and `buildEventBatchFn` alias

**Files:**
- Modify: `internal/store/watchtower/transport/state_replaying.go:108-128` (Send loop, `buildEventBatchFn` callsite)
- Modify: `internal/store/watchtower/transport/state_replaying.go:156` (`buildEventBatchFn` alias type)

`state_replaying.go` calls `buildEventBatchFn` (an alias of `encodeBatchMessage`) at line 108. After Task 8 changed the encoder's return type, this alias's effective signature changed too — every caller must iterate.

- [ ] **Step 1: Verify the alias declaration**

Read `internal/store/watchtower/transport/state_replaying.go:131-156`. Confirm `var buildEventBatchFn = encodeBatchMessage`. The alias takes the new return type automatically — no explicit type change needed.

- [ ] **Step 2: Update the call site**

In `state_replaying.go`, replace lines 108-124 (the `if len(batch.Records) > 0` block):

```go
if len(batch.Records) > 0 {
    msgs, err := buildEventBatchFn(batch.Records)
    if err != nil {
        _ = t.conn.Close()
        t.teardownRecv()
        t.conn = nil
        return StateConnecting, fmt.Errorf("build EventBatch: %w", err)
    }
    for _, msg := range msgs {
        if err := t.conn.Send(msg); err != nil {
            _ = t.conn.Close()
            t.teardownRecv()
            t.conn = nil
            return StateConnecting, fmt.Errorf("send EventBatch: %w", err)
        }
    }
}
```

Note the removal of the `if errors.Is(err, ErrRecordLossEncountered) { return StateShutdown, err }` branch — that error no longer occurs.

- [ ] **Step 3: Update existing replaying tests**

Run: `go test ./internal/store/watchtower/transport/ -run TestRunReplaying -v`
Expected: any test that asserted `ErrRecordLossEncountered` propagation must be updated to assert TransportLoss emission instead. Update those tests.

- [ ] **Step 4: Verify all replaying tests pass**

Run: `go test ./internal/store/watchtower/transport/ -run TestRunReplaying -v`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/state_replaying.go internal/store/watchtower/transport/state_replaying_internal_test.go internal/store/watchtower/transport/state_replaying_test.go
git commit -m "wtp/transport: runReplaying iterates buildEventBatchFn slice; drop fail-closed branch"
```

---

### Task 10b: Update `runShutdown` to iterate the encoder's slice

**Files:**
- Modify: `internal/store/watchtower/transport/state_shutdown.go:50-99` (drain + final-flush sites)

`runShutdown` calls `encodeBatchMessageFn` at two sites (drain loop line 64, final flush line 87) and tracks `lossErr` to skip the post-loss flush per roborev #6143. With the carrier wired, encountering a loss is no longer integrity-violating — the TransportLoss frame is the integrity record. The `lossErr` tracking and skip-final-send logic become dead.

- [ ] **Step 1: Read the existing structure**

Read `internal/store/watchtower/transport/state_shutdown.go:50-99`. Note the `lossErr` accumulator and the comment block referencing roborev #6143.

- [ ] **Step 2: Rewrite the drain block**

Replace the `drainLoop:` block (lines ~46-76) with:

```go
drainLoop:
for {
    if ctx.Err() != nil {
        break
    }
    rec, ok, err := rdr.TryNext()
    if err != nil {
        break
    }
    if !ok {
        break
    }
    if outBatch := b.Add(rec); outBatch != nil {
        msgs, err := encodeBatchMessageFn(outBatch.Records)
        if err != nil {
            break drainLoop
        }
        for _, msg := range msgs {
            if err := t.conn.Send(msg); err != nil {
                break drainLoop
            }
        }
    }
}
```

- [ ] **Step 3: Rewrite the final-flush block**

Replace the post-drain `if final := b.Drain(); final != nil { ... }` block (lines ~77-96) with:

```go
if final := b.Drain(); final != nil {
    msgs, err := encodeBatchMessageFn(final.Records)
    if err == nil {
        for _, msg := range msgs {
            _ = t.conn.Send(msg)
        }
    }
}
_ = t.conn.CloseSend()
return nil
```

The function previously returned `lossErr`; now it returns `nil` because the loss-as-error path is gone. If the caller relies on a non-nil return for ANY purpose, refactor accordingly.

- [ ] **Step 4: Update existing shutdown tests**

Run: `go test ./internal/store/watchtower/transport/ -run TestRunShutdown -v`
Expected: any test asserting `ErrRecordLossEncountered` or `lossErr` propagation must be updated to assert TransportLoss emission. Update those tests.

- [ ] **Step 5: Verify**

Run: `go test ./internal/store/watchtower/transport/ -run Shutdown -v`
Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/state_shutdown.go internal/store/watchtower/transport/shutdown_test.go
git commit -m "wtp/transport: runShutdown iterates encoder slice; drop lossErr fail-closed accumulator

Pre-spec, encountering a loss marker mid-shutdown caused us to skip
the final flush to avoid roborev #6143's integrity-leak scenario. Post-
spec, the TransportLoss frame IS the integrity record — sending it +
subsequent data is safe."
```

---

### Task 11: Remove `ErrRecordLossEncountered` and dead branches

**Files:**
- Modify: `internal/store/watchtower/transport/state_live.go:14-31` (delete sentinel)
- Modify: `internal/store/watchtower/transport/state_live.go` (remove `errors.Is(err, ErrRecordLossEncountered)` branches at lines 127, 210, 250 per snapshot)
- Modify: `internal/store/watchtower/transport/state_replaying.go` (remove same branches)
- Modify: `internal/store/watchtower/transport/replayer.go` (and any other callers)

After Tasks 8–10 the encoder no longer returns `ErrRecordLossEncountered`. Every `errors.Is(err, ErrRecordLossEncountered)` branch is dead code. Remove the sentinel and every reference.

- [ ] **Step 1: Find all references**

Run: `git grep -nE 'ErrRecordLossEncountered'`
Expected: a list of all locations that need changes.

- [ ] **Step 2: Delete the sentinel declaration**

Open `internal/store/watchtower/transport/state_live.go`. Delete the entire `ErrRecordLossEncountered` block (lines 14-31 per the snapshot — adjust to current line numbers). The block starts with the comment `// ErrRecordLossEncountered is the sentinel...` and ends with the `var ErrRecordLossEncountered = errors.New(...)` line.

- [ ] **Step 3: Remove dead branches**

For each remaining reference (callers of `encodeBatchMessageFn`), remove the `if errors.Is(err, ErrRecordLossEncountered) { ... return StateShutdown ... }` blocks. Only the catch-all `return StateConnecting` (or whatever the existing non-loss-error path was) remains.

- [ ] **Step 4: Verify no references remain**

Run: `git grep -nE 'ErrRecordLossEncountered'`
Expected: no output.

- [ ] **Step 5: Run all transport tests**

Run: `go test ./internal/store/watchtower/transport/...`
Expected: ALL PASS — including any tests that previously asserted `ErrRecordLossEncountered` behavior MUST be UPDATED in this same task to assert the new fail-open behavior.

If any test still references `ErrRecordLossEncountered`, update it: assert that an EventBatch + TransportLoss are sent in order instead of asserting the sentinel error.

- [ ] **Step 6: Verify build still compiles**

Run: `go build ./...`
Expected: success.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/
git commit -m "wtp/transport: remove ErrRecordLossEncountered sentinel and fail-closed branches

Now that encodeBatchMessage emits TransportLoss ClientMessages on the
wire, the fail-closed sentinel and its Shutdown-state propagation are
dead code."
```

---

## Phase 5 — Inflight tracker symmetry + emit logging

### Task 12: Document inflight tracker symmetry; verify no structural change needed

**Files:**
- Modify: `internal/store/watchtower/transport/inflight.go:1-19` (docstring update)
- Test: `internal/store/watchtower/transport/inflight_test.go` (add cross-frame-kind retirement test)

The inflight tracker keys on `(generation, sequence)`. Both `EventBatch.ToSequence` and `TransportLoss.ToSequence` advance into the same monotonic sequence space, so no structural change is needed. Update the docstring to reflect symmetric tracking.

- [ ] **Step 1: Write the failing test**

In `internal/store/watchtower/transport/inflight_test.go`, add:

```go
func TestInflightTracker_TransportLossAndEventBatchRetiredTogether(t *testing.T) {
	// Mixed sequence: EventBatch{to=10}, TransportLoss{to=11}, EventBatch{to=15}.
	// A BatchAck{ack_high=11, gen=1} should retire the first two.
	var it inflightTracker
	it.Push(1, 10)  // EventBatch
	it.Push(1, 11)  // TransportLoss
	it.Push(1, 15)  // EventBatch
	if it.Len() != 3 {
		t.Fatalf("Len = %d; want 3", it.Len())
	}
	released := it.Release(1, 11)
	if released != 2 {
		t.Fatalf("Release = %d; want 2 (first two retired)", released)
	}
	if it.Len() != 1 {
		t.Fatalf("Len after Release = %d; want 1", it.Len())
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/store/watchtower/transport/ -run TestInflightTracker_TransportLossAndEventBatchRetiredTogether -v`
Expected: PASS — the existing tracker already supports this case (sequence-based keying is type-agnostic).

- [ ] **Step 3: Update docstring**

In `internal/store/watchtower/transport/inflight.go`, replace lines 3-15 (the `// inflightTracker tracks the (generation, sequence)...` block) with:

```go
// inflightTracker tracks the (generation, sequence) high-watermarks of
// frames that have been Sent but not yet covered by an
// AckOutcomeAdopted BatchAck. Both EventBatch and TransportLoss frames
// are tracked symmetrically — the high-watermark is the frame's
// to_sequence, regardless of frame type. A BatchAck whose
// ack_high_watermark_seq retires entries up to that sequence covers
// both kinds uniformly (the WTP server treats TransportLoss as a
// metadata frame that advances the watermark, just like a data batch).
//
// The WTP protocol allows a single BatchAck to coalesce
// acknowledgements for multiple frames via its AckHighWatermarkSeq +
// Generation tuple, so a counter that decrements by one per ack would
// under-release the inflight window against any conforming server that
// batches acknowledgements (roborev Medium round-3). Release pops every
// pending entry whose high-watermark is at or below the adopted ack's
// (gen, seq) tuple.
//
// Pending entries are appended in send order; the protocol guarantees
// (gen, seq) is monotonically non-decreasing across successive Sends
// on the same connection, so a prefix-pop is correct.
```

- [ ] **Step 4: Run all inflight tests**

Run: `go test ./internal/store/watchtower/transport/ -run Inflight -v`
Expected: ALL PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/inflight.go internal/store/watchtower/transport/inflight_test.go
git commit -m "wtp/transport: document inflight tracker symmetry across EventBatch + TransportLoss"
```

---

### Task 12b: Add per-emission INFO log for TransportLoss frames

**Files:**
- Modify: `internal/store/watchtower/transport/transport.go` (add `logEmittedLossIfApplicable` helper on `*Transport`)
- Modify: `internal/store/watchtower/transport/state_live.go` (call helper from each iteration site)
- Modify: `internal/store/watchtower/transport/state_replaying.go` (call helper)
- Modify: `internal/store/watchtower/transport/state_shutdown.go` (call helper)

The spec §"Operator-facing logs" requires a single INFO log per emitted TransportLoss, carrying reason/from/to/generation/session_id/agent_id so operators can confirm carrier-path activity end-to-end without grepping the wire.

- [ ] **Step 1: Add the helper on Transport**

In `internal/store/watchtower/transport/transport.go`, near other Transport methods, add:

```go
// logEmittedLossIfApplicable emits an INFO log when msg is a
// TransportLoss ClientMessage. No-op for other frame types. Called
// after each successful conn.Send in the runLive / runReplaying /
// runShutdown send loops so the carrier path is observable end-to-end.
func (t *Transport) logEmittedLossIfApplicable(ctx context.Context, msg *wtpv1.ClientMessage) {
	tl, ok := msg.Msg.(*wtpv1.ClientMessage_TransportLoss)
	if !ok {
		return
	}
	t.logger.LogAttrs(ctx, slog.LevelInfo,
		"wtp: emitted TransportLoss frame",
		slog.String("reason", tl.TransportLoss.Reason.String()),
		slog.Uint64("from_seq", tl.TransportLoss.FromSequence),
		slog.Uint64("to_seq", tl.TransportLoss.ToSequence),
		slog.Uint64("generation", uint64(tl.TransportLoss.Generation)),
		slog.String("session_id", t.sessionID),
		slog.String("agent_id", t.agentID))
}
```

If `t.logger` / `t.sessionID` / `t.agentID` field names differ in the codebase, search Transport struct fields and adapt.

- [ ] **Step 2: Wire helper into runLive iteration sites**

In `internal/store/watchtower/transport/state_live.go`, in each of the three iteration loops added in Task 9, add the helper call after `t.conn.Send(msg)`:

```go
for _, msg := range msgs {
    if err := t.conn.Send(msg); err != nil {
        // existing error handling
        return ...
    }
    t.logEmittedLossIfApplicable(ctx, msg)
    gen, seq := extractWireHighWatermark(msg)
    inflight.Push(gen, seq)
}
```

- [ ] **Step 3: Wire helper into runReplaying iteration**

In `state_replaying.go`, in the iteration loop added in Task 10:

```go
for _, msg := range msgs {
    if err := t.conn.Send(msg); err != nil {
        // existing error handling
        return ...
    }
    t.logEmittedLossIfApplicable(ctx, msg)
}
```

- [ ] **Step 4: Wire helper into runShutdown iteration**

In `state_shutdown.go`, in BOTH iteration loops added in Task 10b:

```go
for _, msg := range msgs {
    if err := t.conn.Send(msg); err != nil {
        break drainLoop
    }
    t.logEmittedLossIfApplicable(ctx, msg)
}
```

(For the final-flush loop, `_ = t.conn.Send(msg)` then `t.logEmittedLossIfApplicable(ctx, msg)`.)

- [ ] **Step 5: Write a test asserting the INFO log appears**

In `internal/store/watchtower/transport/state_live_internal_test.go`, add:

```go
func TestRunLive_LogsInfoOnTransportLossEmission(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tr := &Transport{logger: logger, sessionID: "sess-1", agentID: "agent-1"}

	tlMsg := &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_TransportLoss{TransportLoss: &wtpv1.TransportLoss{
			FromSequence: 5, ToSequence: 5, Generation: 1,
			Reason: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW,
		}},
	}
	tr.logEmittedLossIfApplicable(context.Background(), tlMsg)

	out := buf.String()
	if !strings.Contains(out, `"msg":"wtp: emitted TransportLoss frame"`) {
		t.Fatalf("expected INFO log; got %s", out)
	}
	if !strings.Contains(out, `"reason":"TRANSPORT_LOSS_REASON_OVERFLOW"`) {
		t.Fatalf("missing reason attr: %s", out)
	}
	if !strings.Contains(out, `"session_id":"sess-1"`) {
		t.Fatalf("missing session_id: %s", out)
	}
}

func TestRunLive_NoLogForEventBatch(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))
	tr := &Transport{logger: logger, sessionID: "sess-1", agentID: "agent-1"}

	ebMsg := &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_EventBatch{EventBatch: &wtpv1.EventBatch{
			FromSequence: 1, ToSequence: 1, Generation: 1,
		}},
	}
	tr.logEmittedLossIfApplicable(context.Background(), ebMsg)

	if buf.Len() > 0 {
		t.Fatalf("expected no log for EventBatch; got %s", buf.String())
	}
}
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/store/watchtower/transport/ -run "LogsInfoOnTransportLossEmission|NoLogForEventBatch" -v`
Expected: PASS.

Run: `go test ./internal/store/watchtower/transport/...`
Expected: ALL PASS.

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/transport/transport.go internal/store/watchtower/transport/state_live.go internal/store/watchtower/transport/state_replaying.go internal/store/watchtower/transport/state_shutdown.go internal/store/watchtower/transport/state_live_internal_test.go
git commit -m "wtp/transport: INFO log per emitted TransportLoss frame (carrier observability)"
```

---

## Phase 6 — Drop-site wiring

### Task 13: Plumb `EmitExtendedLossReasons` through Options → Store

**Files:**
- Modify: `internal/store/watchtower/options.go:38-150` (add `EmitExtendedLossReasons bool`)
- Modify: `internal/store/watchtower/store.go:140` and following (`Store` struct field)
- Modify: `internal/server/wtp.go` (build path: read config → set Options field)

- [ ] **Step 1: Add field to Options**

In `internal/store/watchtower/options.go`, find the field block near `LogGoawayMessage bool` (line 102 per snapshot). Add adjacent:

```go
	// EmitExtendedLossReasons toggles wire emission of the six
	// TransportLossReason values added in the 2026-04-27 spec
	// (MAPPER_FAILURE, INVALID_MAPPER, INVALID_TIMESTAMP, INVALID_UTF8,
	// SEQUENCE_OVERFLOW, ACK_REGRESSION_AFTER_GC). When false:
	//   - in-flight drop sites (recordSequenceOverflow, etc.) skip
	//     wal.AppendLoss entirely; the drop is counter-only.
	//   - the encoder drops ACK_REGRESSION_AFTER_GC PrefixLoss markers
	//     instead of emitting them.
	// OVERFLOW and CRC_CORRUPTION are unaffected — they're part of the
	// original wire schema.
	EmitExtendedLossReasons bool
```

- [ ] **Step 2: Plumb into Store**

In `internal/store/watchtower/store.go`, find the `Store` struct around line 140. Find where existing `opts.*` fields are stored (search `s.opts =` or check the constructor). The Store typically retains the entire `Options` value (`s.opts Options`); no new field is needed if so.

If a new field on `Store` is required (e.g., the codebase prefers narrowed struct fields over storing whole `Options`), add:

```go
emitExtendedLossReasons bool
```

and initialize from `opts.EmitExtendedLossReasons` in `New(...)`.

- [ ] **Step 3: Plumb into Encoder**

The encoder needs to know the flag for `ack_regression_after_gc` gating. In `internal/store/watchtower/transport/state_live.go`, near `encoderMetrics`, add:

```go
// encoderEmitExtendedReasons controls whether the encoder emits
// TransportLoss frames for the six extended reasons. When false:
//   - ACK_REGRESSION_AFTER_GC markers are silently dropped (logged INFO).
//   - In-flight reasons (mapper_failure, invalid_utf8, sequence_overflow,
//     invalid_mapper, invalid_timestamp) cannot reach the encoder
//     because the drop sites skip wal.AppendLoss when the flag is off.
//   - OVERFLOW and CRC_CORRUPTION emit unconditionally.
var encoderEmitExtendedReasons bool
```

In the encoder body (Task 8), after `wireReason, ok := ToWireReason(rec.Loss.Reason)` and before constructing the TransportLoss, add a flag check that gates *only* extended reasons:

```go
if !encoderEmitExtendedReasons && isExtendedReason(wireReason) {
    // Spec §"Configuration": ACK_REGRESSION_AFTER_GC is dropped when
    // flag is off. In-flight reasons can't reach this branch in
    // practice (drop sites skip AppendLoss when flag is off), but we
    // gate them defensively.
    continue
}
```

Add the helper near `encoderEmitExtendedReasons`:

```go
// isExtendedReason reports whether the wire enum is one of the six
// reasons added in the 2026-04-27 spec. OVERFLOW and CRC_CORRUPTION
// return false — they're always emitted regardless of the flag.
func isExtendedReason(r wtpv1.TransportLossReason) bool {
    switch r {
    case wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE,
        wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER,
        wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP,
        wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8,
        wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW,
        wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC:
        return true
    default:
        return false
    }
}
```

- [ ] **Step 4: Wire from config in `internal/server/wtp.go`**

In `internal/server/wtp.go`, find where `watchtower.Options` is constructed (`buildWatchtowerStore` or similar). Add:

```go
opts.EmitExtendedLossReasons = cfg.Audit.Watchtower.EmitExtendedLossReasons
```

Then, where the transport is constructed, also set the encoder package-level flag:

```go
transport.SetEncoderEmitExtendedReasonsForTest(opts.EmitExtendedLossReasons)
```

If a non-test setter does not yet exist, create it in `state_live.go`:

```go
// SetEncoderEmitExtendedReasons sets the package-level flag controlling
// emission of extended TransportLoss reasons. Called from
// watchtower.Store construction; the package-level shape mirrors
// encoderMetrics.
func SetEncoderEmitExtendedReasons(b bool) {
    encoderEmitExtendedReasons = b
}
```

- [ ] **Step 5: Add wire-through test**

In `internal/store/watchtower/options_test.go`, add:

```go
func TestOptions_EmitExtendedLossReasons_DefaultsFalse(t *testing.T) {
	opts := watchtower.Options{}
	if opts.EmitExtendedLossReasons {
		t.Fatalf("zero-value Options.EmitExtendedLossReasons should be false")
	}
}
```

- [ ] **Step 6: Run tests**

Run: `go test ./internal/store/watchtower/...`
Expected: ALL PASS.

Run: `go test ./internal/server/...`
Expected: ALL PASS (or no breakage from this change).

- [ ] **Step 7: Commit**

```bash
git add internal/store/watchtower/options.go internal/store/watchtower/options_test.go internal/store/watchtower/transport/state_live.go internal/server/wtp.go
git commit -m "wtp: plumb EmitExtendedLossReasons from config through Options + encoder"
```

---

### Task 14: Add `Store.emitInFlightLoss` helper

**Files:**
- Modify: `internal/store/watchtower/append.go` (add helper near the existing `record*` family)

The helper centralizes the AppendLoss + flag-gate + ambiguous-fatal-latch logic. All five drop sites (Tasks 15–17) call it.

- [ ] **Step 1: Write the failing test**

In `internal/store/watchtower/append_drop_internal_test.go`, add:

```go
func TestEmitInFlightLoss_FlagOff_NoAppendLossCall(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, false /* EmitExtendedLossReasons */)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)

	if walSpy.AppendLossCalls != 0 {
		t.Fatalf("AppendLoss called %d times; want 0 (flag off)", walSpy.AppendLossCalls)
	}
}

func TestEmitInFlightLoss_FlagOn_CallsAppendLoss(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true /* EmitExtendedLossReasons */)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)

	if walSpy.AppendLossCalls != 1 {
		t.Fatalf("AppendLoss called %d times; want 1", walSpy.AppendLossCalls)
	}
	loss := walSpy.LastLoss
	if loss.FromSequence != 100 || loss.ToSequence != 100 {
		t.Fatalf("from/to = %d/%d; want 100/100", loss.FromSequence, loss.ToSequence)
	}
	if loss.Generation != 1 {
		t.Fatalf("generation = %d; want 1", loss.Generation)
	}
	if loss.Reason != wal.LossReasonInvalidUTF8 {
		t.Fatalf("reason = %q; want %q", loss.Reason, wal.LossReasonInvalidUTF8)
	}
}

func TestEmitInFlightLoss_AmbiguousFailure_LatchesFatal(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	walSpy.AppendLossErr = wal.NewAmbiguousErrorForTest("simulated I/O failure")
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)

	if !s.isFatal() {
		t.Fatalf("Store should be fatal-latched after ambiguous AppendLoss")
	}
}

func TestEmitInFlightLoss_CleanFailure_NoFatalLatch(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	walSpy.AppendLossErr = wal.NewCleanErrorForTest("WAL closed")
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 100, Generation: 1}}
	s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)

	if s.isFatal() {
		t.Fatalf("Store should NOT be fatal-latched after clean AppendLoss failure")
	}
}
```

`newStoreWithWALSpy` is a test helper this task adds to `append_drop_internal_test.go` if missing. It constructs a Store with a fake WAL that records AppendLoss calls. Use the existing test helper pattern (see `internal/store/watchtower/append_drop_internal_test.go` for examples of how the existing tests fake the WAL — search for the spy types and reuse them).

`wal.NewAmbiguousErrorForTest` / `NewCleanErrorForTest` are existing helpers (or add minimal wrappers around `wal.AppendError`). Check `internal/store/watchtower/wal/wal.go` for the `AppendError` constructor; reuse the existing `wal.IsAmbiguous` predicate.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/store/watchtower/ -run TestEmitInFlightLoss -v`
Expected: build error — `emitInFlightLoss` undefined.

- [ ] **Step 3: Add the helper**

In `internal/store/watchtower/append.go`, after `recordCanonicalFailure` (around line 316), add:

```go
// emitInFlightLoss writes a single-record TransportLoss marker into the
// WAL so the carrier surfaces the gap on the wire. Called from each
// in-flight drop site after the counter increment + WARN log, gated by
// s.opts.EmitExtendedLossReasons.
//
// Failure handling:
//   - flag off: skip AppendLoss entirely; the drop is counter-only.
//   - flag on, AppendLoss clean error (closed/fatal): ERROR log, no
//     fatal latch. The event is already lost; the marker is also lost.
//     No worse than the pre-spec behavior.
//   - flag on, AppendLoss ambiguous error: latch BOTH the audit chain
//     and the Store fatal (mirrors regular Append ambiguous handling).
func (s *Store) emitInFlightLoss(ev types.Event, reason string) {
	if !s.opts.EmitExtendedLossReasons {
		return
	}
	loss := wal.LossRecord{
		FromSequence: ev.Chain.Sequence,
		ToSequence:   ev.Chain.Sequence,
		Generation:   ev.Chain.Generation,
		Reason:       reason,
	}
	if err := s.w.AppendLoss(loss); err != nil {
		if wal.IsAmbiguous(err) {
			s.sink.Fatal(err)
			s.latchFatal(err)
			return
		}
		s.opts.Logger.LogAttrs(context.Background(), slog.LevelError,
			"wtp: in-flight loss marker not persisted; counter-only",
			slog.String("reason", reason),
			slog.String("err", err.Error()),
			slog.Uint64("event_seq", ev.Chain.Sequence),
			slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
			slog.String("session_id", s.opts.SessionID),
			slog.String("agent_id", s.opts.AgentID))
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/watchtower/ -run TestEmitInFlightLoss -v`
Expected: PASS for all four subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "wtp: add Store.emitInFlightLoss helper"
```

---

### Task 15: Wire `emitInFlightLoss` into `recordSequenceOverflow`

**Files:**
- Modify: `internal/store/watchtower/append.go:232-241` (`recordSequenceOverflow`)
- Modify: `internal/store/watchtower/append_drop_internal_test.go` (add wire-through test)

- [ ] **Step 1: Write the failing test**

In `internal/store/watchtower/append_drop_internal_test.go`, add:

```go
func TestRecordSequenceOverflow_EmitsInFlightLoss_WhenFlagOn(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true /* flag */)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: math.MaxUint64, Generation: 5}}
	s.recordSequenceOverflow(ev)

	if walSpy.AppendLossCalls != 1 {
		t.Fatalf("AppendLoss calls = %d; want 1", walSpy.AppendLossCalls)
	}
	if walSpy.LastLoss.Reason != wal.LossReasonSequenceOverflow {
		t.Fatalf("reason = %q; want %q", walSpy.LastLoss.Reason, wal.LossReasonSequenceOverflow)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/ -run TestRecordSequenceOverflow_EmitsInFlightLoss -v`
Expected: FAIL — AppendLoss not called.

- [ ] **Step 3: Wire emitInFlightLoss**

In `internal/store/watchtower/append.go::recordSequenceOverflow`, append a call after the existing slog statement:

```go
func (s *Store) recordSequenceOverflow(ev types.Event) {
	s.metrics.IncDroppedSequenceOverflow(1)
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", "sequence_overflow"),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
	s.emitInFlightLoss(ev, wal.LossReasonSequenceOverflow)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/store/watchtower/ -run TestRecordSequenceOverflow_EmitsInFlightLoss -v`
Expected: PASS.

- [ ] **Step 5: Run all watchtower tests**

Run: `go test ./internal/store/watchtower/...`
Expected: ALL PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "wtp: recordSequenceOverflow emits in-flight loss marker"
```

---

### Task 16: Wire `emitInFlightLoss` into `recordCanonicalFailure`

**Files:**
- Modify: `internal/store/watchtower/append.go:306-316` (`recordCanonicalFailure`)
- Modify: `internal/store/watchtower/append_drop_internal_test.go` (add test)

- [ ] **Step 1: Write the failing test**

In `internal/store/watchtower/append_drop_internal_test.go`, add:

```go
func TestRecordCanonicalFailure_EmitsInFlightLoss_WhenFlagOn(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 200, Generation: 3}}
	s.recordCanonicalFailure(chain.ErrInvalidUTF8, ev)

	if walSpy.AppendLossCalls != 1 {
		t.Fatalf("AppendLoss calls = %d; want 1", walSpy.AppendLossCalls)
	}
	if walSpy.LastLoss.Reason != wal.LossReasonInvalidUTF8 {
		t.Fatalf("reason = %q; want %q", walSpy.LastLoss.Reason, wal.LossReasonInvalidUTF8)
	}
}
```

- [ ] **Step 2: Run test**

Run: `go test ./internal/store/watchtower/ -run TestRecordCanonicalFailure_EmitsInFlightLoss -v`
Expected: FAIL.

- [ ] **Step 3: Wire helper**

In `recordCanonicalFailure` (line 306), append:

```go
s.emitInFlightLoss(ev, wal.LossReasonInvalidUTF8)
```

- [ ] **Step 4: Run test**

Run: `go test ./internal/store/watchtower/ -run TestRecordCanonicalFailure_EmitsInFlightLoss -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "wtp: recordCanonicalFailure emits in-flight loss marker"
```

---

### Task 17: Wire `emitInFlightLoss` into `recordCompactEncodeFailure` (3 branches)

**Files:**
- Modify: `internal/store/watchtower/append.go:266-290` (`recordCompactEncodeFailure`)
- Modify: `internal/store/watchtower/append_drop_internal_test.go` (add test per branch)

- [ ] **Step 1: Write the failing tests**

Add three subtests:

```go
func TestRecordCompactEncodeFailure_MapperFailure_EmitsInFlightLoss(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 50, Generation: 1}}
	err := fmt.Errorf("compact.Encode: %w", compact.ErrMapperFailure)
	s.recordCompactEncodeFailure(err, ev)

	if walSpy.AppendLossCalls != 1 {
		t.Fatalf("AppendLoss calls = %d; want 1", walSpy.AppendLossCalls)
	}
	if walSpy.LastLoss.Reason != wal.LossReasonMapperFailure {
		t.Fatalf("reason = %q; want %q", walSpy.LastLoss.Reason, wal.LossReasonMapperFailure)
	}
}

func TestRecordCompactEncodeFailure_InvalidMapper_EmitsInFlightLoss(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 51, Generation: 1}}
	err := fmt.Errorf("compact.Encode: %w", compact.ErrInvalidMapper)
	s.recordCompactEncodeFailure(err, ev)

	if walSpy.LastLoss.Reason != wal.LossReasonInvalidMapper {
		t.Fatalf("reason = %q; want %q", walSpy.LastLoss.Reason, wal.LossReasonInvalidMapper)
	}
}

func TestRecordCompactEncodeFailure_InvalidTimestamp_EmitsInFlightLoss(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 52, Generation: 1}}
	err := fmt.Errorf("compact.Encode: %w", compact.ErrInvalidTimestamp)
	s.recordCompactEncodeFailure(err, ev)

	if walSpy.LastLoss.Reason != wal.LossReasonInvalidTimestamp {
		t.Fatalf("reason = %q; want %q", walSpy.LastLoss.Reason, wal.LossReasonInvalidTimestamp)
	}
}

func TestRecordCompactEncodeFailure_FallthroughClassifiedAsMapperFailure(t *testing.T) {
	s, walSpy := newStoreWithWALSpy(t, true)
	defer s.Close()

	ev := types.Event{Chain: &types.ChainState{Sequence: 53, Generation: 1}}
	// An error not matching any sentinel — falls into the catch-all.
	err := errors.New("some unrelated error")
	s.recordCompactEncodeFailure(err, ev)

	if walSpy.LastLoss.Reason != wal.LossReasonMapperFailure {
		t.Fatalf("reason = %q; want %q (fallthrough)", walSpy.LastLoss.Reason, wal.LossReasonMapperFailure)
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run: `go test ./internal/store/watchtower/ -run TestRecordCompactEncodeFailure -v`
Expected: FAIL.

- [ ] **Step 3: Wire helper into each classification branch**

In `recordCompactEncodeFailure` (line 266), modify the switch to set both `reason` (string for log) AND a `lossReason` (constant for emit). Restructure as:

```go
func (s *Store) recordCompactEncodeFailure(err error, ev types.Event) {
	var reason, lossReason string
	switch {
	case errors.Is(err, compact.ErrMapperFailure):
		s.metrics.IncDroppedMapperFailure(1)
		reason = "mapper_failure"
		lossReason = wal.LossReasonMapperFailure
	case errors.Is(err, compact.ErrInvalidMapper):
		s.metrics.IncDroppedInvalidMapper(1)
		reason = "invalid_mapper"
		lossReason = wal.LossReasonInvalidMapper
	case errors.Is(err, compact.ErrInvalidTimestamp):
		s.metrics.IncDroppedInvalidTimestamp(1)
		reason = "invalid_timestamp"
		lossReason = wal.LossReasonInvalidTimestamp
	default:
		s.metrics.IncDroppedMapperFailure(1)
		reason = "mapper_failure"
		lossReason = wal.LossReasonMapperFailure
	}
	s.opts.Logger.LogAttrs(context.Background(), slog.LevelWarn,
		"wtp: dropping event before WAL append",
		slog.String("reason", reason),
		slog.String("err", err.Error()),
		slog.Uint64("event_seq", ev.Chain.Sequence),
		slog.Uint64("event_gen", uint64(ev.Chain.Generation)),
		slog.String("session_id", s.opts.SessionID),
		slog.String("agent_id", s.opts.AgentID))
	s.emitInFlightLoss(ev, lossReason)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/store/watchtower/ -run TestRecordCompactEncodeFailure -v`
Expected: PASS for all four subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/append.go internal/store/watchtower/append_drop_internal_test.go
git commit -m "wtp: recordCompactEncodeFailure emits in-flight loss marker per branch"
```

---

## Phase 7 — Component tests (testserver-driven)

### Task 18: Component test — overflow emits TransportLoss; session does NOT restart

**Files:**
- Create: `internal/store/watchtower/component_loss_carrier_test.go`

This is the headline regression test for the carrier. Pre-spec, an overflow caused `ErrRecordLossEncountered` → session shutdown. Post-spec, the session continues and the testserver receives a `TransportLoss{reason: OVERFLOW}`.

- [ ] **Step 1: Read existing testserver patterns**

Read `internal/store/watchtower/component_drop_test.go` and `internal/store/watchtower/component_restart_test.go` to understand the established testserver scaffolding (RoutingDialer, scenarios, assertion helpers).

- [ ] **Step 2: Write the test**

Create `internal/store/watchtower/component_loss_carrier_test.go`:

```go
package watchtower_test

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestStore_OverflowEmitsTransportLossOnWire — exercise WAL overflow,
// assert the testserver receives a ClientMessage{TransportLoss{reason:
// OVERFLOW}} AND the session continues normally (no restart).
func TestStore_OverflowEmitsTransportLossOnWire(t *testing.T) {
	srv := testserver.New(t, testserver.Scenario{})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Construct a Store with a TINY WAL so a few appends overflow.
	s := watchtower.NewForTest(t, watchtower.Options{
		// ... set walMaxTotalSize very small ...
	}, srv.Dialer())
	defer s.Close()

	// Append more events than the WAL can hold to trigger overflow.
	for i := 0; i < 100; i++ {
		appendEventForTest(t, ctx, s, uint64(i+1), 1)
	}

	// Wait for the testserver to observe a TransportLoss frame.
	select {
	case loss := <-srv.TransportLossCh():
		if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW {
			t.Fatalf("loss.Reason = %v; want OVERFLOW", loss.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for TransportLoss frame")
	}

	// Session continues — assert no Goaway and no SessionInit retry.
	if srv.SessionInits() != 1 {
		t.Fatalf("SessionInits = %d; want 1 (no session restart)", srv.SessionInits())
	}
}
```

If the testserver doesn't yet expose `TransportLossCh()`, add it: search `internal/store/watchtower/testserver/*.go` for the existing `EventBatchCh()` pattern and mirror it for `TransportLoss`. Likewise `SessionInits() int` to count session-init handshakes.

If `appendEventForTest` doesn't exist, mirror the helper used in `component_drop_test.go` or `component_restart_test.go`.

If `watchtower.NewForTest` doesn't exist, use `watchtower.New(ctx, opts)` directly with the routing dialer; check `component_restart_test.go` for the pattern.

- [ ] **Step 3: Add the missing testserver hooks**

If `TransportLossCh()` and `SessionInits()` don't exist on testserver, add them. In `internal/store/watchtower/testserver/server.go` (or whichever file owns the bufconn server):

```go
// TransportLossCh delivers every ClientMessage_TransportLoss the server
// observes. Channel buffer is 64; tests should drain or risk deadlock.
func (s *Server) TransportLossCh() <-chan *wtpv1.TransportLoss {
	return s.transportLossCh
}

// SessionInits returns the count of SessionInit handshakes the server
// has accepted since New(). Useful to assert "no reconnect happened
// during the test."
func (s *Server) SessionInits() int {
	return int(atomic.LoadInt64(&s.sessionInits))
}
```

In the server's recv loop, when a `ClientMessage_TransportLoss` arrives:

```go
case *wtpv1.ClientMessage_TransportLoss:
    select {
    case s.transportLossCh <- msg.TransportLoss:
    default:
        // drop on full channel
    }
```

Initialize `s.transportLossCh = make(chan *wtpv1.TransportLoss, 64)` in `New(...)` and `atomic.AddInt64(&s.sessionInits, 1)` on every accepted SessionInit.

- [ ] **Step 4: Run the test**

Run: `go test ./internal/store/watchtower/ -run TestStore_OverflowEmitsTransportLossOnWire -v`
Expected: PASS.

- [ ] **Step 5: Verify cross-platform**

Run: `GOOS=windows go build ./...`
Expected: success.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/component_loss_carrier_test.go internal/store/watchtower/testserver/
git commit -m "wtp: component test — overflow emits TransportLoss; session does not restart"
```

---

### Task 19: Component test — CRC corruption emits TransportLoss; session does NOT restart

**Files:**
- Modify: `internal/store/watchtower/component_loss_carrier_test.go` (add test)

- [ ] **Step 1: Write the test**

Add to `component_loss_carrier_test.go`:

```go
// TestStore_CRCCorruptionEmitsTransportLossOnWire — manufacture CRC
// corruption mid-WAL via the existing CRC test helpers, restart the
// store (so replay walks the corrupted segment), assert a
// TransportLoss{reason: CRC_CORRUPTION} reaches the wire AND the
// session does not fail-closed.
func TestStore_CRCCorruptionEmitsTransportLossOnWire(t *testing.T) {
	srv := testserver.New(t, testserver.Scenario{})
	defer srv.Close()

	walDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Step A: write some records, close the store cleanly.
	s1 := watchtower.NewForTest(t, watchtower.Options{WALDir: walDir}, srv.Dialer())
	for i := 0; i < 5; i++ {
		appendEventForTest(t, ctx, s1, uint64(i+1), 1)
	}
	s1.Close()

	// Step B: corrupt one record's CRC in the WAL on disk.
	corruptCRCForTest(t, walDir)

	// Step C: open a new store on the same WAL; replay walks the
	// corrupted segment.
	s2 := watchtower.NewForTest(t, watchtower.Options{WALDir: walDir}, srv.Dialer())
	defer s2.Close()

	select {
	case loss := <-srv.TransportLossCh():
		if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION {
			t.Fatalf("loss.Reason = %v; want CRC_CORRUPTION", loss.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for CRC TransportLoss")
	}

	// No second SessionInit — the session continued.
	if srv.SessionInits() != 2 {
		t.Fatalf("SessionInits = %d; want 2 (one per Store)", srv.SessionInits())
	}
}
```

`corruptCRCForTest` is a helper this task adds (or already exists in `internal/store/watchtower/wal/crc_test.go`). If absent, mirror the pattern from `crc_test.go` — open a segment, seek into the data region, flip a byte.

- [ ] **Step 2: Run the test**

Run: `go test ./internal/store/watchtower/ -run TestStore_CRCCorruptionEmitsTransportLossOnWire -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/store/watchtower/component_loss_carrier_test.go
git commit -m "wtp: component test — CRC corruption emits TransportLoss; session does not restart"
```

---

### Task 20: Component test — five in-flight reasons emit on wire when flag is on

**Files:**
- Create: `internal/store/watchtower/component_inflight_loss_test.go`

- [ ] **Step 1: Write the test**

Create `internal/store/watchtower/component_inflight_loss_test.go`:

```go
package watchtower_test

import (
	"context"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/pkg/types"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func TestStore_InFlightDrop_EmitsTransportLossOnWire(t *testing.T) {
	cases := []struct {
		name      string
		setup     func(*testing.T, *watchtower.Store) types.Event
		wantWire  wtpv1.TransportLossReason
	}{
		{
			name: "sequence_overflow",
			setup: func(t *testing.T, _ *watchtower.Store) types.Event {
				return types.Event{
					Chain:     &types.ChainState{Sequence: math.MaxUint64, Generation: 1},
					Timestamp: time.Now(),
					Type:      "test",
				}
			},
			wantWire: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW,
		},
		{
			name: "invalid_utf8",
			setup: func(t *testing.T, _ *watchtower.Store) types.Event {
				return types.Event{
					Chain:     &types.ChainState{Sequence: 1, Generation: 1},
					Timestamp: time.Now(),
					Type:      "test",
					Path:      "\xff\xfeinvalid",
				}
			},
			wantWire: wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8,
		},
		// ... three more entries: mapper_failure, invalid_mapper, invalid_timestamp
		// each setting up a condition that triggers the matching drop path.
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := testserver.New(t, testserver.Scenario{})
			defer srv.Close()

			s := watchtower.NewForTest(t, watchtower.Options{
				EmitExtendedLossReasons: true,
			}, srv.Dialer())
			defer s.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			ev := tc.setup(t, s)
			err := s.AppendEvent(ctx, ev)
			if err == nil {
				t.Fatal("AppendEvent succeeded; expected drop")
			}

			select {
			case loss := <-srv.TransportLossCh():
				if loss.Reason != tc.wantWire {
					t.Fatalf("reason = %v; want %v", loss.Reason, tc.wantWire)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("timeout waiting for in-flight TransportLoss")
			}
		})
	}
}
```

For the three remaining subtests:

- `mapper_failure` — construct the Store with a Mapper that returns a runtime error from `Map(types.Event)`.
- `invalid_mapper` — pass a typed-nil mapper that escaped validation (use `compact.ErrInvalidMapper` semantics; check `internal/store/watchtower/compact/encoder.go` for how this is normally triggered).
- `invalid_timestamp` — `types.Event{Timestamp: time.Time{}}` (zero) or pre-epoch.

- [ ] **Step 2: Run the test**

Run: `go test ./internal/store/watchtower/ -run TestStore_InFlightDrop_EmitsTransportLossOnWire -v`
Expected: PASS for all five subtests.

- [ ] **Step 3: Add a flag-off counter-only test**

Append:

```go
func TestStore_InFlightDrop_NoTransportLoss_WhenFlagOff(t *testing.T) {
	srv := testserver.New(t, testserver.Scenario{})
	defer srv.Close()

	s := watchtower.NewForTest(t, watchtower.Options{
		EmitExtendedLossReasons: false, // FLAG OFF
	}, srv.Dialer())
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ev := types.Event{
		Chain:     &types.ChainState{Sequence: math.MaxUint64, Generation: 1},
		Timestamp: time.Now(),
		Type:      "test",
	}
	_ = s.AppendEvent(ctx, ev) // expected drop

	select {
	case got := <-srv.TransportLossCh():
		t.Fatalf("got TransportLoss when flag off: reason=%v", got.Reason)
	case <-time.After(2 * time.Second):
		// expected — no wire emission
	}
}
```

- [ ] **Step 4: Run all tests**

Run: `go test ./internal/store/watchtower/ -run TestStore_InFlightDrop -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/component_inflight_loss_test.go
git commit -m "wtp: component tests — in-flight drops emit TransportLoss per reason; flag gates wire emission"
```

---

### Task 21: Component test — `ack_regression_after_gc` emits TransportLoss when flag is on

**Files:**
- Create: `internal/store/watchtower/component_ack_regression_loss_test.go`

The setup is delicate: requires manufacturing an ack-regression scenario that triggers `computeReplayStart` to construct a PrefixLoss. Mirror the pattern from existing transport tests that test `computeReplayStart`.

- [ ] **Step 1: Read existing ack-regression tests**

Search: `git grep -l 'ack_regression\|computeReplayStart' internal/store/watchtower/`

Read the closest existing test that exercises `computeReplayStart` to find the testserver scenario (probably involves a `RestoreSessionAckSeq` or similar testserver knob to claim a higher ack than the WAL has).

- [ ] **Step 2: Write the test**

Create `internal/store/watchtower/component_ack_regression_loss_test.go`:

```go
package watchtower_test

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func TestStore_AckRegressionAfterGC_EmitsTransportLoss_WhenFlagOn(t *testing.T) {
	// Scenario: server claims ack at seq=N+10, WAL only has seq=N.
	// computeReplayStart constructs a PrefixLoss with reason
	// "ack_regression_after_gc". Encoder maps to wire and emits.
	srv := testserver.New(t, testserver.Scenario{
		// ... claim higher ack than client has produced ...
		RestoreSessionAckSeq: 20,
		RestoreSessionAckGen: 1,
	})
	defer srv.Close()

	s := watchtower.NewForTest(t, watchtower.Options{
		EmitExtendedLossReasons: true,
	}, srv.Dialer())
	defer s.Close()

	// Trigger SessionInit handshake with mismatched ack.
	// (Implementation depends on existing test helpers; see e.g.
	// state_replaying_test.go for ack-regression test fixtures.)
	triggerSessionInitForTest(t, s)

	select {
	case loss := <-srv.TransportLossCh():
		if loss.Reason != wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC {
			t.Fatalf("reason = %v; want ACK_REGRESSION_AFTER_GC", loss.Reason)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for ack-regression TransportLoss")
	}
}
```

If the testserver scenario doesn't have the `RestoreSessionAckSeq` / `RestoreSessionAckGen` knobs (or equivalent), add them by following the existing `Scenario` struct pattern in `internal/store/watchtower/testserver/scenarios.go`.

- [ ] **Step 3: Run the test**

Run: `go test ./internal/store/watchtower/ -run TestStore_AckRegressionAfterGC -v`
Expected: PASS.

- [ ] **Step 4: Add a flag-off counterpart test**

```go
func TestStore_AckRegressionAfterGC_NoTransportLoss_WhenFlagOff(t *testing.T) {
	srv := testserver.New(t, testserver.Scenario{
		RestoreSessionAckSeq: 20,
		RestoreSessionAckGen: 1,
	})
	defer srv.Close()

	s := watchtower.NewForTest(t, watchtower.Options{
		EmitExtendedLossReasons: false, // FLAG OFF
	}, srv.Dialer())
	defer s.Close()

	triggerSessionInitForTest(t, s)

	select {
	case got := <-srv.TransportLossCh():
		t.Fatalf("got TransportLoss when flag off: reason=%v", got.Reason)
	case <-time.After(3 * time.Second):
		// expected
	}
}
```

- [ ] **Step 5: Run both tests**

Run: `go test ./internal/store/watchtower/ -run TestStore_AckRegressionAfterGC -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/component_ack_regression_loss_test.go internal/store/watchtower/testserver/
git commit -m "wtp: component test — ack_regression_after_gc emits TransportLoss; flag gates"
```

---

### Task 22: Component test — TransportLoss inflight slot retired by `BatchAck`

**Files:**
- Modify: `internal/store/watchtower/component_loss_carrier_test.go` (add test)

- [ ] **Step 1: Write the test**

Add to `component_loss_carrier_test.go`:

```go
func TestStore_TransportLossInflightSlot_RetiredByBatchAck(t *testing.T) {
	// Scenario: server holds back BatchAck for the loss frame's
	// to_sequence. Inflight tracker shows the slot occupied; the next
	// AppendEvent blocks at MaxInflight=1. Server then sends a BatchAck
	// for the loss seq; tracker retires; AppendEvent unblocks.
	srv := testserver.New(t, testserver.Scenario{
		BatchAckDelay: 5 * time.Second, // hold acks
	})
	defer srv.Close()

	s := watchtower.NewForTest(t, watchtower.Options{
		EmitExtendedLossReasons: true,
		// MaxInflight = 1 to force back-pressure on the second send.
		// (Plumb via Options if not already; check options.go for
		// existing knob name.)
	}, srv.Dialer())
	defer s.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// First append triggers an in-flight drop → loss marker → wire frame.
	bad := types.Event{Chain: &types.ChainState{Sequence: math.MaxUint64, Generation: 1}, Timestamp: time.Now(), Type: "t"}
	_ = s.AppendEvent(ctx, bad)

	// Wait for the server to receive the loss frame.
	select {
	case <-srv.TransportLossCh():
	case <-time.After(5 * time.Second):
		t.Fatal("loss frame not received")
	}

	// Now release the held ack — tracker should retire and subsequent
	// appends complete normally.
	srv.ReleaseAcks()

	good := types.Event{Chain: &types.ChainState{Sequence: 1, Generation: 1}, Timestamp: time.Now(), Type: "t"}
	if err := s.AppendEvent(ctx, good); err != nil {
		t.Fatalf("AppendEvent unblocked too slowly or failed: %v", err)
	}
}
```

If `BatchAckDelay` doesn't exist on the testserver scenario yet (it was added in Task 26 of the WTP client plan; check the scenario struct), use it. Otherwise add it.

If `srv.ReleaseAcks()` doesn't exist, add it:

```go
// ReleaseAcks releases any held BatchAcks (from BatchAckDelay) so the
// client can drain them.
func (s *Server) ReleaseAcks() {
    close(s.holdAcksCh)
}
```

- [ ] **Step 2: Run**

Run: `go test ./internal/store/watchtower/ -run TestStore_TransportLossInflightSlot -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/store/watchtower/component_loss_carrier_test.go internal/store/watchtower/testserver/
git commit -m "wtp: component test — TransportLoss inflight slot retired by BatchAck"
```

---

## Phase 8 — Wire goldens

### Task 23: Wire goldens for new TransportLoss reasons

**Files:**
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_overflow.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_crc_corruption.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_mapper_failure.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_invalid_mapper.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_invalid_timestamp.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_invalid_utf8.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_sequence_overflow.bin`
- Create: `proto/canyonroad/wtp/v1/testdata/transport_loss_ack_regression_after_gc.bin`
- Modify: `cmd/gen-wire-goldens/main.go` (add TransportLoss generation)
- Modify: `proto/canyonroad/wtp/v1/wire_goldens_test.go` (round-trip test)

- [ ] **Step 1: Read existing golden generator**

Read `cmd/gen-wire-goldens/main.go`. Identify how existing goldens are produced (likely `proto.Marshal` on a constructed message → write to file). Mirror for TransportLoss.

- [ ] **Step 2: Add TransportLoss generation**

In `cmd/gen-wire-goldens/main.go`, after the existing EventBatch / SessionInit golden generation, add:

```go
// TransportLoss goldens — one per reason value.
type tlSpec struct {
	name   string
	reason wtpv1.TransportLossReason
}
tls := []tlSpec{
	{"overflow", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_OVERFLOW},
	{"crc_corruption", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_CRC_CORRUPTION},
	{"mapper_failure", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_MAPPER_FAILURE},
	{"invalid_mapper", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_MAPPER},
	{"invalid_timestamp", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_TIMESTAMP},
	{"invalid_utf8", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_INVALID_UTF8},
	{"sequence_overflow", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_SEQUENCE_OVERFLOW},
	{"ack_regression_after_gc", wtpv1.TransportLossReason_TRANSPORT_LOSS_REASON_ACK_REGRESSION_AFTER_GC},
}
for _, tl := range tls {
	msg := &wtpv1.ClientMessage{
		Msg: &wtpv1.ClientMessage_TransportLoss{
			TransportLoss: &wtpv1.TransportLoss{
				FromSequence: 100,
				ToSequence:   100,
				Generation:   1,
				Reason:       tl.reason,
			},
		},
	}
	b, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "transport_loss_"+tl.name+".bin"), b, 0644); err != nil {
		log.Fatal(err)
	}
}
```

- [ ] **Step 3: Generate the goldens**

Run: `go run ./cmd/gen-wire-goldens -dir proto/canyonroad/wtp/v1/testdata`
Expected: eight `transport_loss_*.bin` files appear.

- [ ] **Step 4: Update round-trip test**

In `proto/canyonroad/wtp/v1/wire_goldens_test.go`, find the existing golden enumeration. Add the eight new files to the round-trip cases. Use the existing pattern (probably a `for _, golden := range filenames` loop).

- [ ] **Step 5: Run round-trip test**

Run: `go test ./proto/canyonroad/wtp/v1/ -run TestWireGoldens -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add proto/canyonroad/wtp/v1/testdata/transport_loss_*.bin cmd/gen-wire-goldens/main.go proto/canyonroad/wtp/v1/wire_goldens_test.go
git commit -m "wtp/proto: wire goldens for TransportLoss with all 8 reason values"
```

---

## Phase 9 — Operator doc

### Task 24: Update `wtp-monitoring-migration.md` with the new flag

**Files:**
- Modify: `docs/superpowers/operator/wtp-monitoring-migration.md`

- [ ] **Step 1: Read existing operator doc structure**

Read `docs/superpowers/operator/wtp-monitoring-migration.md` to find the existing `LogGoawayMessage` section. Mirror its structure.

- [ ] **Step 2: Add the section**

Append a new section to the operator doc:

```markdown
## `output.wtp.emit_extended_loss_reasons` (added 2026-04-27)

Controls whether the WTP client emits TransportLoss frames with the six
extended reason values: `MAPPER_FAILURE`, `INVALID_MAPPER`,
`INVALID_TIMESTAMP`, `INVALID_UTF8`, `SEQUENCE_OVERFLOW`,
`ACK_REGRESSION_AFTER_GC`.

**Default: false.** Strict-enum receivers (per the
`TRANSPORT_LOSS_REASON_UNSPECIFIED` contract) reject unknown values with
a Goaway. Flip this to `true` only after your receiving Watchtower
instance has been upgraded to support the new reason values.

OVERFLOW and CRC_CORRUPTION are always emitted — they are part of the
original wire schema and are unaffected by this flag.

### Migration order

1. **Client lands the carrier change** (no operator action; ships with
   client upgrade). Today's fail-closed behavior on overflow / CRC
   becomes fail-open: TransportLoss frames replace session restarts.
2. **Watchtower server ships support for new reason values.** Confirm
   with your server operator that the receiving instance has been
   upgraded.
3. **Operator flips `audit.watchtower.emit_extended_loss_reasons:
   true`** in the agent's YAML config. Restart the agent. Verify
   `wtp_loss_unknown_reason_total` stays at zero (non-zero indicates a
   client-side programming bug — file an issue).

### Rollback

If the server-side upgrade misbehaves and the agent enters a Goaway
loop, set `audit.watchtower.emit_extended_loss_reasons: false` and
restart the agent. The agent reverts to counter-only drops for the six
extended reasons; OVERFLOW and CRC_CORRUPTION continue to emit on the
wire.

### Threat model

The new reason values carry no PII or secrets — they are bounded enum
values plus the `(from_sequence, to_sequence, generation)` triple of
the dropped event. The agent does not include the original event
contents in the TransportLoss frame.
```

- [ ] **Step 3: Verify rendering**

Run: `git diff docs/superpowers/operator/wtp-monitoring-migration.md`
Expected: clean diff with the new section appended.

- [ ] **Step 4: Commit**

```bash
git add docs/superpowers/operator/wtp-monitoring-migration.md
git commit -m "docs(operator): add emit_extended_loss_reasons flag rollout guide"
```

---

## Phase 10 — Final verification

### Task 25: Full test sweep + cross-compile

- [ ] **Step 1: Run the full test suite**

Run: `go test ./...`
Expected: ALL PASS.

- [ ] **Step 2: Verify Windows cross-compilation**

Run: `GOOS=windows go build ./...`
Expected: success.

- [ ] **Step 3: Verify Darwin cross-compilation**

Run: `GOOS=darwin go build ./...`
Expected: success.

- [ ] **Step 4: Verify race detector clean**

Run: `go test -race ./internal/store/watchtower/...`
Expected: ALL PASS, no race warnings.

- [ ] **Step 5: Run roborev**

Per CLAUDE.md / project memory, run `/roborev-review` between major phases. After this final task, run a full-branch review:

```bash
roborev review --wait
```

Address any findings above LOW per the standing instruction.

- [ ] **Step 6: Final commit (only if any roborev fixes needed)**

If roborev landed fixes:

```bash
git add .
git commit -m "wtp: address roborev findings on TransportLoss in-flight drops bundle"
```

Otherwise no commit; the previous commits already cover the work.

---

## Acceptance gates (cross-task)

The following must hold at the end of Task 25:

1. `proto/canyonroad/wtp/v1/wtp.proto` carries six new enum values; `wtp.pb.go` regenerated.
2. `wal.LossReason*` exported constants exist; existing producers reference them (no string literals in production code).
3. `transport.ToWireReason` exists with full coverage; AST exhaustiveness CI test passes.
4. `encodeBatchMessage` returns `[]*wtpv1.ClientMessage`; `ErrRecordLossEncountered` removed; all callers iterate.
5. `inflight.go` retires both EventBatch and TransportLoss frames symmetrically.
6. Five drop sites in `append.go` route through `Store.emitInFlightLoss` (flag-gated).
7. `EmitExtendedLossReasons` is wired through config → Options → Store and encoder; default false.
8. All unit, internal, component, and integration tests pass on linux + macos + windows.
9. `TestStore_OverflowEmitsTransportLossOnWire` passes — overflow emits a wire frame and the session does NOT restart.
10. `TestStore_CRCCorruptionEmitsTransportLossOnWire` passes — same regression guard for CRC.
11. Eight TransportLoss wire goldens exist; round-trip test passes.
12. `docs/superpowers/operator/wtp-monitoring-migration.md` documents the new flag with rollout + rollback guidance.
13. `wtp_dropped_*` counters continue to increment at the source — no regression in existing observability.
