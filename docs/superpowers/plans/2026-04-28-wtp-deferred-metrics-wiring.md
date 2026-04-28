# WTP Deferred Failure-Metric Wiring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire `wtp_session_init_failures_total{reason}` (Project A — handshake failures in `state_connecting.go`) and `wtp_dropped_invalid_frame_total{reason}` for inbound `ServerMessage` validation (Project B — proto validators + `recv_multiplexer.go`). `wtp_session_rotation_failures_total` remains deferred to Project C (rotation feature).

**Architecture:** Project A is pure metrics wiring: expand `WTPSessionFailureReason` from 2 to 6 values; emit one at each of the 5 distinct handshake-failure paths in `state_connecting.go`. Project B adds 5 new `Validate*` functions (`SessionAck`, `BatchAck`, `ServerHeartbeat`, `Goaway`, `SessionUpdate`) plus 2 new `ValidationReason` constants (`goaway_code_unspecified`, `session_update_generation_invalid`); validators are routed through the existing `ClassifyAndIncInvalidFrame` helper in each `recv_multiplexer.go` dispatch arm. The cross-package parity test (`wtp_parity_test.go`) auto-fails until matching `WTPInvalidFrameReason` constants land — that's the existing safety net.

**Tech Stack:** Go 1.x, `internal/metrics` Collector, `proto/canyonroad/wtp/v1` validators, `internal/store/watchtower/transport` state machine, existing `ClassifyAndIncInvalidFrame` helper.

**Spec:** `docs/superpowers/specs/2026-04-28-wtp-deferred-metrics-wiring-design.md`

---

## File Structure

**Modify (Project A):**
- `internal/metrics/wtp.go` — expand `WTPSessionFailureReason` constants, `wtpSessionFailureReasonsValid` map, `wtpSessionFailureReasonsEmitOrder` slice
- `internal/metrics/wtp_test.go` — update `TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons`, `TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons`, `TestWTPMetrics_SessionFailureReasonValidationAndEscape`; add `TestWTPMetrics_SessionInitFailures_PerReasonInc`
- `internal/store/watchtower/transport/state_connecting.go` — emit `IncSessionInitFailures(reason)` at the 5 failure sites

**Modify (Project B):**
- `proto/canyonroad/wtp/v1/validate.go` — add 2 new `ValidationReason` constants; add `allValidationReasons` entries; add 5 new `Validate*` functions
- `proto/canyonroad/wtp/v1/validate_test.go` — add per-validator tests
- `proto/canyonroad/wtp/v1/validate_reason_test.go` — extend the reason-completeness test
- `internal/metrics/wtp.go` — add 2 new `WTPInvalidFrameReason` constants; add to `wtpInvalidFrameReasonsValid` map; add to `wtpInvalidFrameReasonsEmitOrder` slice; add to `validationReasonsShared` slice
- `internal/metrics/wtp_test.go` — update `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons` (the always-emit test) to expect the 2 new labels at zero
- `internal/store/watchtower/transport/recv_multiplexer.go` — call validator at the top of each `ServerMessage` variant arm; route failures through `ClassifyAndIncInvalidFrame`
- `docs/superpowers/operator/wtp-monitoring-migration.md` — append two sections documenting the new reason sets

**Create:**
- `internal/store/watchtower/component_session_init_failure_test.go` — component tests for each of the 5 SessionInit failure paths
- `internal/store/watchtower/component_invalid_frame_test.go` — component tests for inbound malformed frames

---

## Task 1: Expand WTPSessionFailureReason enum (4 new values)

**Files:**
- Modify: `internal/metrics/wtp.go`
- Modify: `internal/metrics/wtp_test.go`

- [ ] **Step 1: Write failing always-emit test extension**

In `internal/metrics/wtp_test.go`, find `TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons` (around line 332). Update its expected reason set to all 6 values:

```go
func TestWTPMetrics_SessionInitFailuresAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	body := scrape(t, c)
	for _, want := range []string{
		`wtp_session_init_failures_total{reason="invalid_utf8"} 0`,
		`wtp_session_init_failures_total{reason="recv_failed"} 0`,
		`wtp_session_init_failures_total{reason="rejected"} 0`,
		`wtp_session_init_failures_total{reason="send_failed"} 0`,
		`wtp_session_init_failures_total{reason="unexpected_message"} 0`,
		`wtp_session_init_failures_total{reason="unknown"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing always-emit line %q\nbody:\n%s", want, body)
		}
	}
}
```

Same shape for `TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons` — the same enum is shared with the rotation metric, so it ALSO must emit all 6 reasons at zero. Update if the test exists; if it does not yet exist with that name, add a new test:

```go
func TestWTPMetrics_SessionRotationFailuresAlwaysEmittedAllReasons(t *testing.T) {
	c := New()
	body := scrape(t, c)
	for _, want := range []string{
		`wtp_session_rotation_failures_total{reason="invalid_utf8"} 0`,
		`wtp_session_rotation_failures_total{reason="recv_failed"} 0`,
		`wtp_session_rotation_failures_total{reason="rejected"} 0`,
		`wtp_session_rotation_failures_total{reason="send_failed"} 0`,
		`wtp_session_rotation_failures_total{reason="unexpected_message"} 0`,
		`wtp_session_rotation_failures_total{reason="unknown"} 0`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing always-emit line %q\nbody:\n%s", want, body)
		}
	}
}
```

(If a similar test already exists under a slightly different name, update IT in place rather than adding a duplicate. Search the file for `wtp_session_rotation_failures_total` first.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test -run TestWTPMetrics_SessionInitFailuresAlwaysEmitted -v ./internal/metrics/...`
Expected: FAIL — only 2 of the 6 reason labels currently emit.

- [ ] **Step 3: Add the 4 new constants**

In `internal/metrics/wtp.go`, find the `WTPSessionFailureReason` constant block (around line 513). Replace with:

```go
const (
	WTPSessionFailureReasonInvalidUTF8         WTPSessionFailureReason = "invalid_utf8"
	WTPSessionFailureReasonSendFailed          WTPSessionFailureReason = "send_failed"
	WTPSessionFailureReasonRecvFailed          WTPSessionFailureReason = "recv_failed"
	WTPSessionFailureReasonUnexpectedMessage   WTPSessionFailureReason = "unexpected_message"
	WTPSessionFailureReasonRejected            WTPSessionFailureReason = "rejected"
	WTPSessionFailureReasonUnknown             WTPSessionFailureReason = "unknown"
)
```

Update `wtpSessionFailureReasonsValid` (around line 518) to include all 6:

```go
var wtpSessionFailureReasonsValid = map[WTPSessionFailureReason]struct{}{
	WTPSessionFailureReasonInvalidUTF8:       {},
	WTPSessionFailureReasonSendFailed:        {},
	WTPSessionFailureReasonRecvFailed:        {},
	WTPSessionFailureReasonUnexpectedMessage: {},
	WTPSessionFailureReasonRejected:          {},
	WTPSessionFailureReasonUnknown:           {},
}
```

Update `wtpSessionFailureReasonsEmitOrder` (around line 527) to include all 6 in alphabetical order:

```go
var wtpSessionFailureReasonsEmitOrder = []WTPSessionFailureReason{
	WTPSessionFailureReasonInvalidUTF8,
	WTPSessionFailureReasonRecvFailed,
	WTPSessionFailureReasonRejected,
	WTPSessionFailureReasonSendFailed,
	WTPSessionFailureReasonUnexpectedMessage,
	WTPSessionFailureReasonUnknown,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test -run "TestWTPMetrics_SessionInitFailures|TestWTPMetrics_SessionRotationFailures|TestWTPMetrics_SessionFailureReason" -v ./internal/metrics/...`
Expected: PASS — all 6 reasons emit at zero on first scrape.

Run: `go test -count=1 ./internal/metrics/...`
Expected: PASS — full metrics suite clean (no other tests broken by the enum expansion).

- [ ] **Step 5: Build sanity**

```bash
go build ./...
GOOS=windows go build ./...
```
Expected: clean.

- [ ] **Step 6: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_test.go
git commit -m "metrics(wtp): expand WTPSessionFailureReason enum from 2 to 6 values"
```

---

## Task 2: Add per-reason increment test for IncSessionInitFailures

**Files:**
- Modify: `internal/metrics/wtp_test.go`

- [ ] **Step 1: Write the failing test**

Append to `internal/metrics/wtp_test.go`:

```go
func TestWTPMetrics_SessionInitFailures_PerReasonInc(t *testing.T) {
	c := New()
	w := c.WTP()

	// Increment each of the 6 reasons a unique number of times so the
	// emit ordering is observable from the Prom output.
	w.IncSessionInitFailures(WTPSessionFailureReasonInvalidUTF8)
	w.IncSessionInitFailures(WTPSessionFailureReasonSendFailed)
	w.IncSessionInitFailures(WTPSessionFailureReasonSendFailed)
	w.IncSessionInitFailures(WTPSessionFailureReasonRecvFailed)
	w.IncSessionInitFailures(WTPSessionFailureReasonRecvFailed)
	w.IncSessionInitFailures(WTPSessionFailureReasonRecvFailed)
	w.IncSessionInitFailures(WTPSessionFailureReasonUnexpectedMessage)
	w.IncSessionInitFailures(WTPSessionFailureReasonRejected)
	w.IncSessionInitFailures(WTPSessionFailureReasonRejected)
	w.IncSessionInitFailures(WTPSessionFailureReasonRejected)
	w.IncSessionInitFailures(WTPSessionFailureReasonRejected)
	w.IncSessionInitFailures(WTPSessionFailureReasonUnknown)

	body := scrape(t, c)
	for _, want := range []string{
		`wtp_session_init_failures_total{reason="invalid_utf8"} 1`,
		`wtp_session_init_failures_total{reason="recv_failed"} 3`,
		`wtp_session_init_failures_total{reason="rejected"} 4`,
		`wtp_session_init_failures_total{reason="send_failed"} 2`,
		`wtp_session_init_failures_total{reason="unexpected_message"} 1`,
		`wtp_session_init_failures_total{reason="unknown"} 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing line %q\nbody:\n%s", want, body)
		}
	}
}
```

(`scrape` is the existing test helper added in PR #256 — search for `func scrape(` in the same test file to confirm the signature is `scrape(t *testing.T, c *Collector) string`.)

- [ ] **Step 2: Run test to verify it passes (no production change needed)**

Run: `go test -run TestWTPMetrics_SessionInitFailures_PerReasonInc -v ./internal/metrics/...`
Expected: PASS — `IncSessionInitFailures` already exists; the test exercises every value in the expanded enum.

- [ ] **Step 3: Commit**

```bash
git add internal/metrics/wtp_test.go
git commit -m "metrics(wtp): per-reason increment test for IncSessionInitFailures"
```

---

## Task 3: Wire IncSessionInitFailures at the 5 handshake-failure sites

**Files:**
- Modify: `internal/store/watchtower/transport/state_connecting.go`

- [ ] **Step 1: Read the existing sites**

Open `internal/store/watchtower/transport/state_connecting.go` and confirm the 5 failure-return paths are at:
- line ~23 (after `wtpv1.ValidateSessionInit(...)` returns error)
- line ~42 (after `conn.Send(init)` returns error)
- line ~48 (after `conn.Recv()` returns error)
- line ~56 (when `msg.GetSessionAck()` returns nil — wrong message type)
- line ~62 (when `ack.GetAccepted() == false`)

Each path returns either `StateConnecting` or `StateShutdown` plus a wrapped error. We add ONE line — `t.metrics.IncSessionInitFailures(<reason>)` — immediately before each return. No other behavior change.

- [ ] **Step 2: Apply the increments**

Edit `runConnecting` so each failure path increments the matching counter:

```go
func (t *Transport) runConnecting(ctx context.Context) (State, error) {
	init := t.sessionInit()
	if err := wtpv1.ValidateSessionInit(init.GetSessionInit()); err != nil {
		// Outbound self-check: this is a local construction bug
		// (Options misconfig, bookkeeping drift) — NOT a dropped
		// peer frame, so it does NOT increment
		// wtp_dropped_invalid_frame_total. The validator only returns
		// ReasonSessionInitAlgorithmUnspecified today; a future
		// surface gain (e.g. invalid-UTF-8 from chain rotation in
		// Project C) would add an errors.Is branch here that emits
		// invalid_utf8.
		t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonUnknown)
		return StateShutdown, fmt.Errorf("invalid SessionInit: %w", err)
	}

	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn

	if err := conn.Send(init); err != nil {
		_ = conn.Close()
		t.conn = nil
		t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonSendFailed)
		return StateConnecting, fmt.Errorf("send SessionInit: %w", err)
	}

	msg, err := conn.Recv()
	if err != nil {
		_ = conn.Close()
		t.conn = nil
		t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonRecvFailed)
		return StateConnecting, fmt.Errorf("recv SessionAck: %w", err)
	}

	ack := msg.GetSessionAck()
	if ack == nil {
		_ = conn.Close()
		t.conn = nil
		t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonUnexpectedMessage)
		return StateConnecting, fmt.Errorf("expected SessionAck, got %T", msg.Msg)
	}

	if !ack.GetAccepted() {
		t.rejectReason = ack.GetRejectReason()
		_ = conn.Close()
		t.conn = nil
		t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonRejected)
		return StateShutdown, fmt.Errorf("session rejected: %s", ack.GetRejectReason())
	}

	t.ackSessionAck(ack)
	return StateReplaying, nil
}
```

Note: `dial: %w` does NOT increment — the dial-failure path bumps `wtp_reconnects_total{reason=dial_failed}` upstream and is a connection-level event distinct from "the SessionInit handshake failed."

The `metrics` import is already present in this file as `"github.com/agentsh/agentsh/internal/metrics"` (the existing `wtp_loss_unknown_reason_total` references confirm). No new import needed.

- [ ] **Step 3: Build and run targeted tests**

```bash
go build ./...
go test -count=1 ./internal/store/watchtower/transport/...
```
Expected: PASS — existing tests unchanged because the metric increments are observation-only.

- [ ] **Step 4: Cross-compile sanity**

```bash
GOOS=windows go build ./...
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/state_connecting.go
git commit -m "wtp/transport: emit wtp_session_init_failures_total at 5 handshake-failure sites"
```

---

## Task 4: Add ValidationReason constants for inbound validators

**Files:**
- Modify: `proto/canyonroad/wtp/v1/validate.go`
- Modify: `proto/canyonroad/wtp/v1/validate_reason_test.go`

- [ ] **Step 1: Write the failing reason-completeness test extension**

Open `proto/canyonroad/wtp/v1/validate_reason_test.go` and find the test that walks every constant in `allValidationReasons`. Extend its expected set to include the 2 new constants:

```go
// Inside the existing reason-completeness test (likely named
// TestValidationReasons_AllListed or similar), append the 2 new
// expected reasons:
expected := []ValidationReason{
	ReasonEventBatchBodyUnset,
	ReasonEventBatchCompressionUnspecified,
	ReasonEventBatchCompressionMismatch,
	ReasonSessionInitAlgorithmUnspecified,
	ReasonPayloadTooLarge,
	ReasonGoawayCodeUnspecified,
	ReasonSessionUpdateGenerationInvalid,
	ReasonUnknown,
}
```

(If the existing test uses a different exact name or shape, locate the slice it asserts against and add the 2 new constants alongside the existing ones; do not delete or rearrange existing constants beyond alphabetization if the test sorts them.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run ValidationReasons`
Expected: FAIL — `ReasonGoawayCodeUnspecified` / `ReasonSessionUpdateGenerationInvalid` undefined.

- [ ] **Step 3: Add the 2 new constants**

In `proto/canyonroad/wtp/v1/validate.go`, find the existing `ValidationReason` constant block. Append:

```go
// ReasonGoawayCodeUnspecified is returned by ValidateGoaway when the
// inbound Goaway has code == GOAWAY_CODE_UNSPECIFIED — that value is
// wire-incompatible per the proto's UNSPECIFIED contract.
ReasonGoawayCodeUnspecified ValidationReason = "goaway_code_unspecified"

// ReasonSessionUpdateGenerationInvalid is returned by
// ValidateSessionUpdate when the inbound SessionUpdate has
// generation == 0. Rotation MUST monotonically advance to a positive
// generation per the WTP client design.
ReasonSessionUpdateGenerationInvalid ValidationReason = "session_update_generation_invalid"
```

Update `allValidationReasons` (around line 136) to include the 2 new constants in alphabetical order:

```go
var allValidationReasons = []ValidationReason{
	ReasonEventBatchBodyUnset,
	ReasonEventBatchCompressionMismatch,
	ReasonEventBatchCompressionUnspecified,
	ReasonGoawayCodeUnspecified,
	ReasonPayloadTooLarge,
	ReasonSessionInitAlgorithmUnspecified,
	ReasonSessionUpdateGenerationInvalid,
	ReasonUnknown,
}
```

(Confirm exact location and current ordering by reading lines 131–145 first; preserve the existing convention.)

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run ValidationReasons`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_reason_test.go
git commit -m "wtp/proto: add ReasonGoawayCodeUnspecified, ReasonSessionUpdateGenerationInvalid"
```

---

## Task 5: Add matching WTPInvalidFrameReason constants (cross-package parity)

**Files:**
- Modify: `internal/metrics/wtp.go`
- Modify: `internal/metrics/wtp_test.go`

- [ ] **Step 1: Run the parity test to confirm it fails**

Run: `go test ./internal/metrics/... -v -run TestWTPInvalidFrameReason_ParityWithValidator`
Expected: FAIL — proto package has 2 new reasons that the metrics package does not yet mirror.

- [ ] **Step 2: Add matching constants in metrics package**

In `internal/metrics/wtp.go`, find the `WTPInvalidFrameReason` constant block (around line 622). Append:

```go
WTPInvalidFrameReasonGoawayCodeUnspecified         WTPInvalidFrameReason = "goaway_code_unspecified"
WTPInvalidFrameReasonSessionUpdateGenerationInvalid WTPInvalidFrameReason = "session_update_generation_invalid"
```

Update `wtpInvalidFrameReasonsValid` (search for that map name) to include both:

```go
WTPInvalidFrameReasonGoawayCodeUnspecified:         {},
WTPInvalidFrameReasonSessionUpdateGenerationInvalid: {},
```

Update `wtpInvalidFrameReasonsEmitOrder` to include both alphabetically. The current slice (around line 583) ends with `WTPInvalidFrameReasonUnknown`; insert the 2 new entries in alphabetical position:

```go
var wtpInvalidFrameReasonsEmitOrder = []WTPInvalidFrameReason{
	WTPInvalidFrameReasonClassifierBypass,
	WTPInvalidFrameReasonDecompressError,
	WTPInvalidFrameReasonEventBatchBodyUnset,
	WTPInvalidFrameReasonEventBatchCompressionMismatch,
	WTPInvalidFrameReasonEventBatchCompressionUnspecified,
	WTPInvalidFrameReasonGoawayCodeUnspecified,        // new
	WTPInvalidFrameReasonPayloadTooLarge,
	WTPInvalidFrameReasonSessionInitAlgorithmUnspecified,
	WTPInvalidFrameReasonSessionUpdateGenerationInvalid, // new
	WTPInvalidFrameReasonUnknown,
}
```

Update `validationReasonsShared` (the slice that the proto-vs-metrics parity test uses to confirm shared reasons). Search for the slice declaration and add the 2 new constants alongside the existing shared reasons.

- [ ] **Step 3: Update the always-emit test**

In `internal/metrics/wtp_test.go`, find `TestWTPMetrics_DroppedInvalidFrameAlwaysEmittedAllReasons`. Add expectations for the 2 new labels at zero:

```go
// In addition to existing reason expectations, append:
`wtp_dropped_invalid_frame_total{reason="goaway_code_unspecified"} 0`,
`wtp_dropped_invalid_frame_total{reason="session_update_generation_invalid"} 0`,
```

- [ ] **Step 4: Run all metrics tests**

Run: `go test -count=1 ./internal/metrics/...`
Expected: PASS — including the parity test and the always-emit test.

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_test.go
git commit -m "metrics(wtp): mirror new WTPInvalidFrameReason constants for parity with proto"
```

---

## Task 6: ValidateGoaway

**Files:**
- Modify: `proto/canyonroad/wtp/v1/validate.go`
- Modify: `proto/canyonroad/wtp/v1/validate_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `proto/canyonroad/wtp/v1/validate_test.go`:

```go
func TestValidateGoaway_Nil(t *testing.T) {
	err := ValidateGoaway(nil)
	if err == nil {
		t.Fatal("ValidateGoaway(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("ValidateGoaway(nil) err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonUnknown {
		t.Errorf("ValidateGoaway(nil) reason = %q; want %q", ve.Reason, ReasonUnknown)
	}
}

func TestValidateGoaway_CodeUnspecified(t *testing.T) {
	err := ValidateGoaway(&Goaway{Code: GoawayCode_GOAWAY_CODE_UNSPECIFIED})
	if err == nil {
		t.Fatal("ValidateGoaway(code=UNSPECIFIED): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonGoawayCodeUnspecified {
		t.Errorf("reason = %q; want %q", ve.Reason, ReasonGoawayCodeUnspecified)
	}
}

func TestValidateGoaway_HappyPath(t *testing.T) {
	cases := []GoawayCode{
		GoawayCode_GOAWAY_CODE_DRAINING,
		GoawayCode_GOAWAY_CODE_OVERLOAD,
		GoawayCode_GOAWAY_CODE_UPGRADE,
		GoawayCode_GOAWAY_CODE_AUTH,
	}
	for _, c := range cases {
		t.Run(c.String(), func(t *testing.T) {
			if err := ValidateGoaway(&Goaway{Code: c}); err != nil {
				t.Errorf("ValidateGoaway(code=%v): %v", c, err)
			}
		})
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run TestValidateGoaway`
Expected: FAIL — `ValidateGoaway` undefined.

- [ ] **Step 3: Add the validator**

Append to `proto/canyonroad/wtp/v1/validate.go`:

```go
// ValidateGoaway returns ReasonGoawayCodeUnspecified when the inbound
// Goaway has code == GOAWAY_CODE_UNSPECIFIED — wire-incompatible per
// the proto's UNSPECIFIED contract. Returns ReasonUnknown for nil
// messages (a structural failure).
//
// Other Goaway fields (message, retry_immediately) have no MUST-be-set
// invariants the validator can enforce statelessly.
func ValidateGoaway(g *Goaway) error {
	if g == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: goaway is nil", ErrInvalidFrame),
		}
	}
	if g.Code == GoawayCode_GOAWAY_CODE_UNSPECIFIED {
		return &ValidationError{
			Reason: ReasonGoawayCodeUnspecified,
			Inner:  fmt.Errorf("%w: goaway code unspecified", ErrInvalidFrame),
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run TestValidateGoaway`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_test.go
git commit -m "wtp/proto: add ValidateGoaway"
```

---

## Task 7: ValidateSessionUpdate

**Files:**
- Modify: `proto/canyonroad/wtp/v1/validate.go`
- Modify: `proto/canyonroad/wtp/v1/validate_test.go`

- [ ] **Step 1: Write the failing tests**

Append to `proto/canyonroad/wtp/v1/validate_test.go`:

```go
func TestValidateSessionUpdate_Nil(t *testing.T) {
	err := ValidateSessionUpdate(nil)
	if err == nil {
		t.Fatal("ValidateSessionUpdate(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonUnknown {
		t.Errorf("reason = %q; want %q", ve.Reason, ReasonUnknown)
	}
}

func TestValidateSessionUpdate_GenerationZero(t *testing.T) {
	err := ValidateSessionUpdate(&SessionUpdate{Generation: 0, NewKeyFingerprint: "k", NewContextDigest: "d"})
	if err == nil {
		t.Fatal("ValidateSessionUpdate(gen=0): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err type = %T; want *ValidationError", err)
	}
	if ve.Reason != ReasonSessionUpdateGenerationInvalid {
		t.Errorf("reason = %q; want %q", ve.Reason, ReasonSessionUpdateGenerationInvalid)
	}
}

func TestValidateSessionUpdate_HappyPath(t *testing.T) {
	if err := ValidateSessionUpdate(&SessionUpdate{
		Generation:        1,
		NewKeyFingerprint: "k",
		NewContextDigest:  "d",
		BoundarySequence:  42,
	}); err != nil {
		t.Errorf("ValidateSessionUpdate: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run TestValidateSessionUpdate`
Expected: FAIL — `ValidateSessionUpdate` undefined.

- [ ] **Step 3: Add the validator**

Append to `proto/canyonroad/wtp/v1/validate.go`:

```go
// ValidateSessionUpdate returns ReasonSessionUpdateGenerationInvalid
// when SessionUpdate.generation == 0 — rotation MUST monotonically
// advance to a positive generation per the WTP client design (see
// 2026-04-18-wtp-client-design.md). Returns ReasonUnknown for nil.
//
// State-dependent invariants ("new generation must be strictly higher
// than current") are not the validator's concern; the rotation
// handler enforces those (when Project C lands).
func ValidateSessionUpdate(u *SessionUpdate) error {
	if u == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: session_update is nil", ErrInvalidFrame),
		}
	}
	if u.Generation == 0 {
		return &ValidationError{
			Reason: ReasonSessionUpdateGenerationInvalid,
			Inner:  fmt.Errorf("%w: session_update generation == 0", ErrInvalidFrame),
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run TestValidateSessionUpdate`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_test.go
git commit -m "wtp/proto: add ValidateSessionUpdate"
```

---

## Task 8: ValidateSessionAck, ValidateBatchAck, ValidateServerHeartbeat

**Files:**
- Modify: `proto/canyonroad/wtp/v1/validate.go`
- Modify: `proto/canyonroad/wtp/v1/validate_test.go`

These three validators are simple structural-failure checks. Group into one task because each is 5 lines of production code + 2 tests.

- [ ] **Step 1: Write the failing tests**

Append to `proto/canyonroad/wtp/v1/validate_test.go`:

```go
func TestValidateSessionAck_Nil(t *testing.T) {
	err := ValidateSessionAck(nil)
	if err == nil {
		t.Fatal("ValidateSessionAck(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonUnknown {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonUnknown)
	}
}

func TestValidateSessionAck_AcceptedHappyPath(t *testing.T) {
	if err := ValidateSessionAck(&SessionAck{Accepted: true, Generation: 1, AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateSessionAck(accepted): %v", err)
	}
}

func TestValidateSessionAck_RejectedHappyPath(t *testing.T) {
	if err := ValidateSessionAck(&SessionAck{Accepted: false, RejectReason: "auth failed"}); err != nil {
		t.Errorf("ValidateSessionAck(rejected w/ reason): %v", err)
	}
}

func TestValidateBatchAck_Nil(t *testing.T) {
	err := ValidateBatchAck(nil)
	if err == nil {
		t.Fatal("ValidateBatchAck(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonUnknown {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonUnknown)
	}
}

func TestValidateBatchAck_HappyPath(t *testing.T) {
	if err := ValidateBatchAck(&BatchAck{Generation: 1, AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateBatchAck: %v", err)
	}
}

func TestValidateServerHeartbeat_Nil(t *testing.T) {
	err := ValidateServerHeartbeat(nil)
	if err == nil {
		t.Fatal("ValidateServerHeartbeat(nil): want error, got nil")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.Reason != ReasonUnknown {
		t.Fatalf("err = %v; want *ValidationError with Reason=%q", err, ReasonUnknown)
	}
}

func TestValidateServerHeartbeat_HappyPath(t *testing.T) {
	if err := ValidateServerHeartbeat(&ServerHeartbeat{AckHighWatermarkSeq: 42}); err != nil {
		t.Errorf("ValidateServerHeartbeat: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run "TestValidateSessionAck|TestValidateBatchAck|TestValidateServerHeartbeat"`
Expected: FAIL — three new validators undefined.

- [ ] **Step 3: Add the three validators**

Append to `proto/canyonroad/wtp/v1/validate.go`:

```go
// ValidateSessionAck rejects a structurally invalid inbound
// SessionAck. Today the only structural failure the validator can
// detect statelessly is a nil message — the SessionAck schema has no
// MUST-be-set field invariants beyond presence (the accepted/
// reject_reason coherence is a server contract that this validator
// does not police). State-dependent invariants are enforced by the
// transport's apply layer (applyServerAckTuple).
func ValidateSessionAck(ack *SessionAck) error {
	if ack == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: session_ack is nil", ErrInvalidFrame),
		}
	}
	return nil
}

// ValidateBatchAck rejects a nil BatchAck. Like SessionAck, the schema
// has no MUST-be-set field invariants beyond presence;
// state-dependent invariants are enforced by applyServerAckTuple.
func ValidateBatchAck(ack *BatchAck) error {
	if ack == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: batch_ack is nil", ErrInvalidFrame),
		}
	}
	return nil
}

// ValidateServerHeartbeat rejects a nil ServerHeartbeat. No other
// stateless invariants apply.
func ValidateServerHeartbeat(hb *ServerHeartbeat) error {
	if hb == nil {
		return &ValidationError{
			Reason: ReasonUnknown,
			Inner:  fmt.Errorf("%w: server_heartbeat is nil", ErrInvalidFrame),
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./proto/canyonroad/wtp/v1/... -v -run "TestValidateSessionAck|TestValidateBatchAck|TestValidateServerHeartbeat"`
Expected: PASS — all 7 new sub-tests.

Run the full proto package test suite to make sure nothing else broke:
`go test -count=1 ./proto/canyonroad/wtp/v1/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add proto/canyonroad/wtp/v1/validate.go proto/canyonroad/wtp/v1/validate_test.go
git commit -m "wtp/proto: add ValidateSessionAck, ValidateBatchAck, ValidateServerHeartbeat"
```

---

## Task 9: Wire validators in recv_multiplexer.go

**Files:**
- Modify: `internal/store/watchtower/transport/recv_multiplexer.go`

- [ ] **Step 1: Read the existing dispatch switch**

Open `internal/store/watchtower/transport/recv_multiplexer.go` and locate the `m := msg.Msg.(type)` switch. Each variant arm currently does protocol-level work (apply ack, log heartbeat, fail closed on Goaway, etc.). The change inserts a validation step at the TOP of each arm, BEFORE the existing handler.

- [ ] **Step 2: Add validation calls in each arm**

For each of these 5 arms — `*wtpv1.ServerMessage_SessionAck`, `*wtpv1.ServerMessage_BatchAck`, `*wtpv1.ServerMessage_ServerHeartbeat`, `*wtpv1.ServerMessage_Goaway`, `*wtpv1.ServerMessage_ServerUpdate` — insert at the top of the case body:

```go
case *wtpv1.ServerMessage_SessionAck:
    if err := wtpv1.ValidateSessionAck(m.SessionAck); err != nil {
        ClassifyAndIncInvalidFrame(t.opts.Logger, t.metrics, err)
        select {
        case rs.errCh <- fmt.Errorf("recv: invalid SessionAck: %w", err):
        default:
        }
        return
    }
    // ... existing SessionAck handler unchanged ...
```

The same shape applies to:
- `BatchAck` → `ValidateBatchAck(m.BatchAck)` + `"recv: invalid BatchAck: %w"`
- `ServerHeartbeat` → `ValidateServerHeartbeat(m.ServerHeartbeat)` + `"recv: invalid ServerHeartbeat: %w"`
- `Goaway` → `ValidateGoaway(m.Goaway)` + `"recv: invalid Goaway: %w"`
- `ServerUpdate` → `ValidateSessionUpdate(m.ServerUpdate)` + `"recv: invalid ServerUpdate: %w"`

For the `ServerUpdate` arm specifically: the validation step runs FIRST. If validation passes, the existing fail-closed branch runs unchanged (the agent still fail-closes because Phase 4 has no rotation handler — Project C territory). If validation fails, `ClassifyAndIncInvalidFrame` increments the matching reason BEFORE the fail-close path.

The `ClassifyAndIncInvalidFrame` helper is already imported into this package (it's defined in `internal/store/watchtower/transport/invalid_frame.go`); no new import needed.

`fmt.Errorf` and `errors.New` are already in use; check the file's import block to confirm.

- [ ] **Step 3: Build and run targeted tests**

```bash
go build ./...
go test -count=1 ./internal/store/watchtower/transport/...
```
Expected: PASS — existing tests still pass because well-formed inbound frames bypass the new validation step (validators return nil on happy paths).

- [ ] **Step 4: Cross-compile sanity**

```bash
GOOS=windows go build ./...
```
Expected: clean.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/recv_multiplexer.go
git commit -m "wtp/transport: validate inbound ServerMessage variants in recv_multiplexer"
```

---

## Task 10: Component test — SessionInit failure paths

**Files:**
- Create: `internal/store/watchtower/component_session_init_failure_test.go`

This task drives a real `watchtower.Store` against a `testserver.Server` configured to trigger each of the 5 SessionInit failure modes, and asserts the matching counter increments.

- [ ] **Step 1: Audit existing testserver hooks**

Before writing the test, confirm the testserver supports:
- `RejectSessionInit bool` (or similar) — server returns `accepted=false`
- A way to close the connection during recv (induces `recv_failed`)
- A way to inject a wrong message in response to SessionInit (induces `unexpected_message`)
- A dialer that returns a usable conn for a happy-path subtest

Run: `grep -E "RejectSessionInit|CloseAfterSessionInit|InjectWrongMessage" internal/store/watchtower/testserver/server.go internal/store/watchtower/testserver/scenarios.go | head -20`

If a needed hook does not exist, add it as part of this task. The test outline below assumes hooks named conservatively (e.g. `Options.RejectSessionInit`); adjust the names to match what the testserver actually exposes.

- [ ] **Step 2: Write the test file**

Create `internal/store/watchtower/component_session_init_failure_test.go`:

```go
package watchtower_test

import (
	"bytes"
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
)

// scrapeMetricsFor renders the Collector's Prom output as a string.
// Mirrors the scrape() helper in internal/metrics/wtp_test.go but
// reachable from this _test package.
func scrapeMetricsFor(t *testing.T, c *metrics.Collector) string {
	t.Helper()
	rr := httptest.NewRecorder()
	c.Handler(metrics.HandlerOptions{}).ServeHTTP(rr, httptest.NewRequest("GET", "/", nil))
	return rr.Body.String()
}

// waitForCounter polls scrapeMetricsFor until the named line appears or
// the deadline elapses. Returns the final body for diagnostics.
func waitForCounter(t *testing.T, c *metrics.Collector, want string, deadline time.Duration) string {
	t.Helper()
	end := time.Now().Add(deadline)
	var body string
	for time.Now().Before(end) {
		body = scrapeMetricsFor(t, c)
		if strings.Contains(body, want) {
			return body
		}
		time.Sleep(50 * time.Millisecond)
	}
	return body
}

// baseSessionInitOpts returns watchtower.Options sufficient to drive the
// agent through SessionInit. Each subtest customizes one or two fields
// to trigger a specific failure path.
func baseSessionInitOpts(t *testing.T, srv *testserver.Server, c *metrics.Collector) watchtower.Options {
	t.Helper()
	return watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:session-init-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Metrics:         c,
	}
}

// TestStore_SessionInit_Rejected drives the agent against a testserver
// that returns SessionAck.accepted=false; asserts the rejected counter
// ticks.
func TestStore_SessionInit_Rejected(t *testing.T) {
	srv := testserver.New(testserver.Options{
		RejectSessionInit: true,
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	want := `wtp_session_init_failures_total{reason="rejected"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected reason=rejected within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_RecvFailed drives the agent against a testserver
// that closes the conn after accepting SessionInit but before sending
// SessionAck; asserts the recv_failed counter ticks.
func TestStore_SessionInit_RecvFailed(t *testing.T) {
	srv := testserver.New(testserver.Options{
		CloseAfterSessionInitRecv: true,
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	want := `wtp_session_init_failures_total{reason="recv_failed"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected reason=recv_failed within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_UnexpectedMessage drives the agent against a
// testserver that responds to SessionInit with a BatchAck instead of a
// SessionAck; asserts the unexpected_message counter ticks.
func TestStore_SessionInit_UnexpectedMessage(t *testing.T) {
	srv := testserver.New(testserver.Options{
		RespondToSessionInitWithBatchAck: true,
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	want := `wtp_session_init_failures_total{reason="unexpected_message"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected reason=unexpected_message within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_SendFailed configures the testserver dialer to
// return a conn whose Send returns an error; asserts the send_failed
// counter ticks.
func TestStore_SessionInit_SendFailed(t *testing.T) {
	srv := testserver.New(testserver.Options{
		FailFirstSend: true,
	})
	defer srv.Close()
	c := metrics.New()

	s, err := watchtower.New(context.Background(), baseSessionInitOpts(t, srv, c))
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	defer s.Close()

	want := `wtp_session_init_failures_total{reason="send_failed"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected reason=send_failed within 30s\nbody:\n%s", body)
	}
}

// TestStore_SessionInit_ValidatorFailed constructs Options with an
// invalid Algorithm so ValidateSessionInit fails locally; asserts the
// unknown counter ticks (today's validator only returns
// ReasonSessionInitAlgorithmUnspecified, which the producer maps to
// "unknown").
func TestStore_SessionInit_ValidatorFailed(t *testing.T) {
	srv := testserver.New(testserver.Options{})
	defer srv.Close()
	c := metrics.New()

	opts := baseSessionInitOpts(t, srv, c)
	// Algorithm omitted (zero value == HASH_ALGORITHM_UNSPECIFIED) so
	// ValidateSessionInit fails before dial.
	opts.HMACAlgorithm = ""

	s, err := watchtower.New(context.Background(), opts)
	if err != nil {
		// watchtower.New may reject up-front depending on internal
		// validation order. If so, the metric DOES NOT increment via
		// state_connecting.go (the run loop never started). Adjust
		// this test if construction-time rejection is the actual
		// behavior — in that case the metric site is not reached and
		// this test should target a different validator failure mode
		// (e.g. an Algorithm string that passes Options.validate but
		// fails wtpv1.ValidateSessionInit).
		t.Skipf("watchtower.New rejected construction; investigate: %v", err)
	}
	defer s.Close()

	want := `wtp_session_init_failures_total{reason="unknown"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected reason=unknown within 30s\nbody:\n%s", body)
	}
}
```

The 5 subtests target the 5 emit sites in `state_connecting.go`. Each uses a different `testserver.Options` field to trigger one path. The validator-failed subtest constructs an invalid `Options` directly; the other four rely on testserver hooks.

- [ ] **Step 3: Resolve testserver API gaps**

If Step 1 found that the testserver lacks a hook for one of the failure modes, add the hook in `internal/store/watchtower/testserver/server.go` and the scenarios driver. Examples:

- For `send_failed`: testserver shutting down its `Listen` so the agent's `conn.Send` fails. Or a dialer that returns a conn whose `Send` returns an error after the dial completed.
- For `recv_failed`: testserver's stream closing after accepting SessionInit but before sending SessionAck.
- For `unexpected_message`: testserver injecting a `BatchAck` instead of `SessionAck` in response to SessionInit.
- For validator-failure: construct `watchtower.Options` with `Algorithm: ""` (or another invalid value) so `ValidateSessionInit` fails locally before even dialing.

Add ONE hook per uncovered failure mode. Keep each hook narrow and well-doc-commented.

- [ ] **Step 4: Run the new tests**

Run: `go test -count=1 -timeout 120s -run TestStore_SessionInit_ -v ./internal/store/watchtower/...`
Expected: PASS — each subtest exercises one path and asserts one counter increment.

- [ ] **Step 5: Cross-compile sanity**

```bash
GOOS=windows go build ./...
```

Some tests may need `runtime.GOOS == "windows"` skips if the testserver hooks rely on Linux-specific timing. Mirror the pattern from `compress_integration_test.go` if needed.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/component_session_init_failure_test.go internal/store/watchtower/testserver/
git commit -m "wtp: component tests for the 5 SessionInit failure paths"
```

---

## Task 11: Component test — inbound malformed frames

**Files:**
- Create: `internal/store/watchtower/component_invalid_frame_test.go`

- [ ] **Step 1: Audit testserver injection hooks**

Confirm the testserver can inject a server-side message of arbitrary shape in response to a connected agent. Look for hooks like:
- `Options.InjectGoaway *wtpv1.Goaway` or similar
- `Options.InjectServerMessage func() *wtpv1.ServerMessage` for arbitrary frames

Run: `grep -E "Inject|server.*Send|stream.*Send" internal/store/watchtower/testserver/*.go | head -20`

If injection hooks don't exist, add a minimal one — `Options.InjectFirstServerMessage *wtpv1.ServerMessage` that the testserver sends BEFORE its normal SessionAck. This gives the test full control over the first inbound frame.

- [ ] **Step 2: Write the test file**

Create `internal/store/watchtower/component_invalid_frame_test.go`:

```go
package watchtower_test

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	"github.com/agentsh/agentsh/internal/metrics"
	"github.com/agentsh/agentsh/internal/store/watchtower"
	"github.com/agentsh/agentsh/internal/store/watchtower/compact"
	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func newStoreForInvalidFrame(t *testing.T, srv *testserver.Server, c *metrics.Collector) *watchtower.Store {
	t.Helper()
	s, err := watchtower.New(context.Background(), watchtower.Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.StubMapper{},
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "a",
		SessionID:       "s",
		KeyFingerprint:  "sha256:invalid-frame-test",
		HMACKeyID:       "k1",
		HMACSecret:      bytes.Repeat([]byte("a"), 32),
		HMACAlgorithm:   "hmac-sha256",
		AllowStubMapper: true,
		Dialer:          srv.DialerFor(),
		Metrics:         c,
	})
	if err != nil {
		t.Fatalf("watchtower.New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore_InboundGoaway_CodeUnspecified(t *testing.T) {
	srv := testserver.New(testserver.Options{
		InjectFirstServerMessage: &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_Goaway{
				Goaway: &wtpv1.Goaway{
					Code: wtpv1.GoawayCode_GOAWAY_CODE_UNSPECIFIED,
				},
			},
		},
	})
	defer srv.Close()

	c := metrics.New()
	_ = newStoreForInvalidFrame(t, srv, c)

	want := `wtp_dropped_invalid_frame_total{reason="goaway_code_unspecified"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected goaway_code_unspecified counter to tick within 30s\nbody:\n%s", body)
	}
}

func TestStore_InboundSessionUpdate_GenerationZero(t *testing.T) {
	srv := testserver.New(testserver.Options{
		InjectFirstServerMessage: &wtpv1.ServerMessage{
			Msg: &wtpv1.ServerMessage_ServerUpdate{
				ServerUpdate: &wtpv1.SessionUpdate{
					Generation:        0,
					NewKeyFingerprint: "k",
					NewContextDigest:  "d",
				},
			},
		},
	})
	defer srv.Close()

	c := metrics.New()
	_ = newStoreForInvalidFrame(t, srv, c)

	want := `wtp_dropped_invalid_frame_total{reason="session_update_generation_invalid"} 1`
	body := waitForCounter(t, c, want, 30*time.Second)
	if !strings.Contains(body, want) {
		t.Fatalf("expected session_update_generation_invalid counter to tick within 30s\nbody:\n%s", body)
	}
}

func TestStore_InboundNilBatchAck(t *testing.T) {
	// A nil BatchAck inside the oneof is the only structural failure
	// the validator can catch for BatchAck — and it's hard to construct
	// in proto without going through a hand-marshaled wire frame. If
	// the testserver injection path requires a non-nil pointer, this
	// subtest can be skipped or implemented via a wire-bytes hook.
	t.Skip("nil BatchAck injection requires wire-bytes hook; covered indirectly by ValidateBatchAck unit test")
}
```

`waitForCounter` and `scrapeMetricsFor` are reused from the SessionInit failure test file (Task 10) — refactor into a shared `_test.go` helper file if both tasks land. For TDD purposes, copy them into this file initially; consolidate in a follow-up step if the linter complains about duplicate symbols.

- [ ] **Step 3: Run the tests**

Run: `go test -count=1 -timeout 120s -run TestStore_Inbound -v ./internal/store/watchtower/...`
Expected: PASS — `goaway_code_unspecified` and `session_update_generation_invalid` counters each tick once.

- [ ] **Step 4: Cross-compile sanity**

```bash
GOOS=windows go build ./...
```

Apply Windows skip via `runtime.GOOS == "windows"` if these tests join the slow-CI flake-class observed in the WTP integration tests.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/component_invalid_frame_test.go internal/store/watchtower/testserver/
git commit -m "wtp: component tests for inbound malformed Goaway and SessionUpdate"
```

---

## Task 12: Operator documentation

**Files:**
- Modify: `docs/superpowers/operator/wtp-monitoring-migration.md`

- [ ] **Step 1: Append the SessionInit-failures section**

Find the end of the existing operator doc. Append:

```markdown
## `wtp_session_init_failures_total{reason}`

**Status:** Live as of PR (this branch). Previously emitted at zero with no producers wired.

The agent increments this counter at every SessionInit handshake failure path in `state_connecting.go`. The reason enum is shared with `wtp_session_rotation_failures_total` (Project C), so all 6 reason labels emit at zero on every scrape regardless of which producer is active.

| Reason | Fires when (SessionInit producer) |
|---|---|
| `invalid_utf8` | Reserved for chain-rotation invalid-UTF-8 (Project C). The SessionInit producer does not currently emit this reason. |
| `send_failed` | `conn.Send(SessionInit)` returns an error. Indicates network egress problems or server unreachability. |
| `recv_failed` | `conn.Recv()` returns an error before SessionAck arrives. Indicates server liveness or network return-path problems. |
| `unexpected_message` | The first inbound `ServerMessage` after SessionInit is not a `SessionAck`. Typically a server protocol bug or version mismatch. |
| `rejected` | Server returned `SessionAck.accepted=false`. The structured WARN log carries the server-supplied `reject_reason` text; the counter only carries the count. Operator response: check server-side authorization / agent identity configuration. |
| `unknown` | Validator (`ValidateSessionInit`) returned an error. Today this is `ReasonSessionInitAlgorithmUnspecified`; future validator surface gains add `errors.Is` branches at the emit site. Operator response: check Options misconfiguration (typically `Algorithm` left zero); structured ERR log carries the field-level cause. |

**Operator alert recommendations.**

- Notify-only on `rate(wtp_session_init_failures_total[10m]) > 0` — a single transient handshake failure during a normal reconnect cycle is not a problem.
- Page on sustained `rejected` rate: `rate(wtp_session_init_failures_total{reason="rejected"}[5m]) > 0.01` indicates persistent server-side authorization failure.
- Page on sustained `unknown` rate: indicates a misconfigured agent that cannot construct a valid SessionInit.

**Reload model.** Read at handshake time on every reconnect; changes to `Options.Algorithm` etc. take effect on the next reconnect (no daemon restart needed for metric-side observation).

## `wtp_dropped_invalid_frame_total{reason=goaway_code_unspecified|session_update_generation_invalid}`

**Status:** Live as of PR (this branch). Two new reason labels added.

These two reasons fire on inbound frames that fail the new structural validators in `recv_multiplexer.go`:

- `goaway_code_unspecified`: Server sent a `Goaway` with `code: GOAWAY_CODE_UNSPECIFIED`. Wire-incompatible per the proto's UNSPECIFIED contract — receivers MUST reject. Operator response: investigate server protocol-version mismatch.
- `session_update_generation_invalid`: Server sent a `SessionUpdate` with `generation: 0`. Rotation MUST monotonically advance to a positive generation. Operator response: investigate server bug.

In both cases the agent ALSO ticks `wtp_reconnects_total{reason="recv_unknown_frame"}` because the validator failure causes the recv goroutine to fail-close and the run loop reconnects. The two metrics answer different questions:
- `wtp_dropped_invalid_frame_total{reason}` — frame-level diagnostic ("why was the frame rejected").
- `wtp_reconnects_total{reason="recv_unknown_frame"}` — connection-level event ("why did we reconnect").

A single malformed frame legitimately fires both.

**Operator alert recommendations.**

- Notify-only on any non-zero rate for these two new labels — server-side protocol drift is rare and worth investigation when it appears.
- Page on `rate(...) > 0.01/s` sustained: server is consistently misbehaving and the agent is reconnect-looping.
```

- [ ] **Step 2: Confirm rendering**

Optionally view the markdown rendered. The doc is checked into git as plain text; no build step needed.

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/operator/wtp-monitoring-migration.md
git commit -m "docs(operator): document wtp_session_init_failures_total + 2 new invalid-frame reasons"
```

---

## Task 13: Final verification

- [ ] **Step 1: Full build**

```bash
go build ./...
```
Expected: clean.

- [ ] **Step 2: Cross-compile to Windows**

```bash
GOOS=windows go build ./...
```
Expected: clean.

- [ ] **Step 3: Full test suite**

```bash
go test -count=1 -timeout 300s ./...
```
Expected: clean. The 2 pre-existing Windows-only flakes (`TestStore_OverflowEmitsTransportLossOnWire`, `TestStore_CRCCorruptionEmitsTransportLossOnWire`) may flake under parallel-test load; rerun affected jobs if they fire on CI.

- [ ] **Step 4: Vet**

```bash
go vet ./...
```
Expected: clean (the testserver vet warnings were fixed in PR #257).

- [ ] **Step 5: Targeted compression-and-this-PR coverage**

```bash
go test -v -count=1 \
  -run "TestValidateGoaway|TestValidateSessionUpdate|TestValidateSessionAck|TestValidateBatchAck|TestValidateServerHeartbeat|TestWTPMetrics_SessionInitFailures|TestWTPMetrics_DroppedInvalidFrame|TestStore_SessionInit|TestStore_Inbound" \
  ./...
```

Each of the 30+ sub-tests should report PASS.

- [ ] **Step 6: Wiring chain smoke check**

Confirm the wiring chain is intact by reading these files for the expected strings:
- `internal/metrics/wtp.go` contains `WTPSessionFailureReasonSendFailed`, `WTPSessionFailureReasonRecvFailed`, `WTPSessionFailureReasonUnexpectedMessage`, `WTPSessionFailureReasonRejected`, `WTPInvalidFrameReasonGoawayCodeUnspecified`, `WTPInvalidFrameReasonSessionUpdateGenerationInvalid`
- `proto/canyonroad/wtp/v1/validate.go` contains `ReasonGoawayCodeUnspecified`, `ReasonSessionUpdateGenerationInvalid`, `func ValidateGoaway`, `func ValidateSessionUpdate`, `func ValidateSessionAck`, `func ValidateBatchAck`, `func ValidateServerHeartbeat`
- `internal/store/watchtower/transport/state_connecting.go` contains exactly 5 occurrences of `t.metrics.IncSessionInitFailures(`
- `internal/store/watchtower/transport/recv_multiplexer.go` contains exactly 5 calls to `ClassifyAndIncInvalidFrame` (one per `ServerMessage` variant arm)

Any missing string is a regression — surface and fix.

- [ ] **Step 7: Final commit (if any pending fixups)**

```bash
git status
```
If clean, no extra commit needed.

---

## Self-Review Checklist

After implementing, before claiming done:

- [ ] All 6 `WTPSessionFailureReason` values defined and emit at zero in always-emit tests for BOTH `wtp_session_init_failures_total` AND `wtp_session_rotation_failures_total` (shared enum).
- [ ] `state_connecting.go` increments at all 5 failure paths — no path missed.
- [ ] All 5 new `Validate*` functions exist with the documented behavior.
- [ ] All 5 inbound validators are wired in `recv_multiplexer.go` ahead of their existing handlers; well-formed frames bypass the new step.
- [ ] 2 new `ValidationReason` constants land in BOTH `proto/canyonroad/wtp/v1/validate.go` AND the metrics package — parity test passes.
- [ ] `wtp_dropped_invalid_frame_total{reason}` always-emit cross product covers the 2 new labels at zero.
- [ ] Component tests cover the 5 SessionInit failure paths and at least 2 inbound malformed frame paths.
- [ ] Operator doc has new sections for `wtp_session_init_failures_total` and the 2 new `wtp_dropped_invalid_frame_total` reasons.
- [ ] `go vet ./...` clean.
- [ ] `GOOS=windows go build ./...` clean.
- [ ] No production behavior change for happy paths — all new code is observation-only or pre-handler validation.
- [ ] No new `TransportLossReason` (per spec — this PR doesn't touch the transport-loss surface).
- [ ] Project C (rotation handling + `wtp_session_rotation_failures_total` wiring) explicitly NOT done — `recv_multiplexer.go`'s ServerUpdate arm still fail-closes after passing or failing validation.
