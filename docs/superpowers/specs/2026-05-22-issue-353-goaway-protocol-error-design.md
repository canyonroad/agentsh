# Issue #353 — GoawayCode.PROTOCOL_ERROR cross-repo design

**Date:** 2026-05-22
**Status:** Design — pending implementation (Stage 1 in this repo; Stage 2 by user in watchtower)
**Tracking issue:** [#353](https://github.com/canyonroad/agentsh/issues/353)
**Related repos:** [canyonroad/agentsh](https://github.com/canyonroad/agentsh) (this design's Stage 1), [canyonroad/watchtower](https://github.com/canyonroad/watchtower) (Stage 2)

## Problem

WTP's `GoawayCode` enum is missing a dedicated code for protocol-invariant violations. As a result, watchtower currently emits `Goaway{UNSPECIFIED, "<reason>"}` for 45 distinct fatal-rejection sites — envelope inconsistencies, unexpected gaps, dedup invariant violations, chain verification failures, session-init wire-contract violations, and others. The agent receives all of them as the same generic `UNSPECIFIED` code and must rely on the human-readable `Message` field for triage. The issue (#353) was filed during Watchtower v0.3.6 spec review on 2026-05-17.

The literal proto in the issue proposed `PROTOCOL_ERROR = 5`, but slot 5 was subsequently allocated to `GOAWAY_CODE_POLICY` (policy snapshot rejection, separate concept). The new code lands at `= 6`.

## Goals

- Add `GOAWAY_CODE_PROTOCOL_ERROR = 6` to the `GoawayCode` enum on both wire-schema repos.
- Migrate watchtower's 45 `RejectFatal(..., UNSPECIFIED)` call sites for protocol invariants to `PROTOCOL_ERROR`.
- Refresh comments and docstrings that were written when `UNSPECIFIED` was the only available encoding.
- Surface the new code in the agent's existing structured log line (`goaway_code` field) so operators can triage from a single grep.
- Preserve full v0.4 backward compatibility: v0.5 agents continue accepting `UNSPECIFIED` from v0.4 servers; v0.4 agents continue receiving Goaway frames from v0.5 servers (numeric unknown code, but agent's behavior unchanged because it doesn't classify codes for retry semantics).

## Non-goals

- Adding "halt on PROTOCOL_ERROR" agent semantics. The issue's "fatal-don't-retry" recommendation is reframed as a documentation invariant, not a code enforcement; agent reconnects with existing backoff on every Goaway regardless of code.
- Adding a received-Goaway-by-code metric. No current operator demand; existing log line already carries the code label.
- Tightening `ValidateGoaway` to reject `UNSPECIFIED`. Would break v0.4 compat without a corresponding benefit; v0.4-legacy is documented in the docstring instead.
- Cross-repo golden-frame wire-compat test. Protobuf wire format for the same enum number is identical by construction.
- Bumping any other proto field. This is a scoped one-enum-value addition.

## Architecture

Wire schema gets one new enum value, mirrored across both repos:

```
enum GoawayCode {
  GOAWAY_CODE_UNSPECIFIED    = 0;  // v0.4-legacy; clients reconnect (unchanged)
  GOAWAY_CODE_DRAINING       = 1;
  GOAWAY_CODE_OVERLOAD       = 2;
  GOAWAY_CODE_UPGRADE        = 3;
  GOAWAY_CODE_AUTH           = 4;
  GOAWAY_CODE_POLICY         = 5;
  GOAWAY_CODE_PROTOCOL_ERROR = 6;  // NEW: protocol invariant violations
}
```

Watchtower flips its 45 protocol-invariant `RejectFatal` call sites from `UNSPECIFIED` to `PROTOCOL_ERROR`. Agentsh's validator and recv multiplexer require no behavior change — the recv-side log already prints `code.String()`, which will surface `GOAWAY_CODE_PROTOCOL_ERROR` automatically once the enum value is defined.

Three invariants:

1. **Wire compatibility both directions.** v0.5 agent ↔ v0.4 watchtower: agent accepts legacy UNSPECIFIED. v0.4 agent ↔ v0.5 watchtower (theoretical mixed fleet): agent treats code 6 as an unknown enum value, surfaces it through the existing log path, reconnects as today.
2. **Retry semantics unchanged.** Watchtower's `RetryImmediately = (code == DRAINING)` rule means `PROTOCOL_ERROR` automatically receives `retry_immediately=false`, which is the correct posture for a server-detected invariant violation.
3. **No agent halt on PROTOCOL_ERROR.** Agent disconnects and reconnects with backoff. Operator value is realized purely through the more specific code label in logs and through the spec-doc clarity.

## Detailed design

### 1. Proto enum addition (both repos, same change)

`proto/canyonroad/wtp/v1/wtp.proto` (agentsh) and `api/proto/wtp/v1/wtp.proto` (watchtower):

```proto
enum GoawayCode {
  GOAWAY_CODE_UNSPECIFIED = 0;   // v0.4-legacy catch-all; clients MUST treat
                                 // as transient and reconnect. v0.5+ servers
                                 // SHOULD emit GOAWAY_CODE_PROTOCOL_ERROR for
                                 // protocol-invariant violations instead.
  GOAWAY_CODE_DRAINING    = 1;   // graceful shutdown; reconnect to a different instance.
  GOAWAY_CODE_OVERLOAD    = 2;   // server overloaded; reconnect with backoff.
  GOAWAY_CODE_UPGRADE     = 3;   // server upgrade in progress; reconnect after delay.
  GOAWAY_CODE_AUTH        = 4;   // authentication/authorization failed; do not auto-retry.
  GOAWAY_CODE_POLICY      = 5;   // policy snapshot in SessionInit was rejected.
  GOAWAY_CODE_PROTOCOL_ERROR = 6; // server-detected protocol invariant violation
                                  // (envelope inconsistent, unexpected gap,
                                  // dedup mismatch, chain verification failure,
                                  // session-update boundary mismatch, etc.).
                                  // Agent reconnects with backoff; operators
                                  // SHOULD investigate (server-side or
                                  // agent-side bug).
}
```

Both `wtp.pb.go` files are regenerated via the repo's existing buf/protoc pipeline.

### 2. agentsh validator docstring rewrite

`proto/canyonroad/wtp/v1/validate.go:297-309` — replace the v0.4-era rationale (which explains why UNSPECIFIED is accepted "because every Fatal-with-generic-reason Goaway watchtower sends" defaults to it) with:

```go
// ValidateGoaway returns ReasonUnknown for nil messages (a structural
// failure). Any non-nil Goaway is accepted regardless of code:
//
//   - GOAWAY_CODE_PROTOCOL_ERROR (v0.5+) is the canonical code for
//     server-detected protocol-invariant violations (envelope
//     inconsistent, unexpected gap, dedup mismatch, chain verification
//     failed, etc.). Operators triage from the code label.
//
//   - GOAWAY_CODE_UNSPECIFIED is preserved as a v0.4-legacy code for
//     wire compatibility with older servers that pre-date
//     PROTOCOL_ERROR. The validator MUST NOT reject it; doing so
//     would silently drop every Goaway from a v0.4 watchtower and
//     cause a tight reconnect loop where the client never observes
//     the server's stated reason.
//
// Other Goaway fields (message, retry_immediately) have no
// MUST-be-set invariants the validator can enforce statelessly.
func ValidateGoaway(g *Goaway) error {
    if g == nil { ... }   // unchanged
    return nil
}
```

No logic changes. Only the leading comment block is touched.

### 3. Watchtower call-site migration (45 sites)

All 45 sites flip `GoawayCode_GOAWAY_CODE_UNSPECIFIED` → `GoawayCode_GOAWAY_CODE_PROTOCOL_ERROR`. The categorization is uniform: every site is a `RejectFatal` invocation paired with a protocol-invariant `Reason*` constant.

| Reason constant | Sites | Issue-353 keyword |
|---|---|---|
| `ReasonProtocolStateViolation` | 12 | `stale_stream`-adjacent / state-machine |
| `ReasonEventBatchEnvelopeInconsistent` | 4 | `envelope_inconsistent` |
| `ReasonStaleStream` | 4 | `stale_stream` |
| `ReasonSessionUpdateBoundaryMismatch` | 3 | `boundary_mismatch` |
| `ReasonTransportLossOutOfRange` | 3 | (extends `unexpected_gap`) |
| `ReasonDedupInvariantViolation` | 2 | `dedup_invariant_violation` |
| `ReasonLossMarkerInvariantViolation` | 2 | (analog of dedup invariant) |
| `ReasonDedupHashMismatch` | 1 | `dedup_hash_mismatch` |
| `ReasonChainVerificationFailed` | 1 | `chain_verification_failed` |
| `ReasonHeartbeatGenerationMismatch` | 1 | (analog of `unexpected_gap` for HB) |
| `ReasonEventBatchUnexpectedGap` | 1 | `unexpected_gap` |
| `ReasonEventBatchPartialReplayOverlap` | 1 | `partial_replay_overlap` |
| `ReasonEventBatchGenerationMismatch` | 1 | (extends `unexpected_gap`) |
| `ReasonTransportLossUnspecified` | 1 | wire-incompatible loss reason |
| `ReasonTransportLossSequenceOverflow` | 1 | (extends `unexpected_gap`) |
| `ReasonTransportLossPartialOverlap` | 1 | `partial_replay_overlap`-equivalent |
| `ReasonSessionInit{Key,Context,AgentID,SessionID}Empty` | 4 | `body_unset` family |
| `ReasonSessionInitBackwardsGeneration` | 1 | `session_update_unknown_generation`-adjacent |
| `ReasonSessionUpdateBackwardsGeneration` | 1 | extends `session_update_unknown_generation` |

Files containing the 45 sites:
- `internal/edge/wtp/state/state.go` — 14 sites
- `internal/edge/wtp/state/event_batch.go` — 11 sites
- `internal/edge/wtp/state/transport_loss.go` — 8 sites
- `internal/edge/wtp/admission/admit.go` — 6 sites
- `internal/edge/wtp/state/heartbeat.go` — 4 sites
- `internal/edge/wtp/state/client_shutdown.go` — 2 sites
- `internal/edge/wtp/server/convert.go` — passes the code through `actionToGoawayMessage`; no change needed, referenced for completeness.

No `RejectTransient` site is touched. No existing `AUTH` / `DRAINING` / `OVERLOAD` / `UPGRADE` / `POLICY` site is touched (none exist in watchtower today — verified by grep).

### 4. Watchtower spec doc updates

`docs/specs/watchtower.md` — 11 sites flip `UNSPECIFIED` → `PROTOCOL_ERROR`:

```
line 173:  RejectFatal(session_update_unknown_generation, UNSPECIFIED)
line 205:  RejectFatal(event_batch_envelope_inconsistent, UNSPECIFIED)
line 221:  Goaway{UNSPECIFIED, "chain_verification_failed"}
line 229:  RejectFatal(dedup_invariant_violation, UNSPECIFIED)
line 257:  RejectFatal(dedup_hash_mismatch, UNSPECIFIED)
           RejectFatal(dedup_invariant_violation, UNSPECIFIED)
line 260:  RejectFatal(event_batch_unexpected_gap, UNSPECIFIED)
line 305:  table row label "UNSPECIFIED | Protocol invariant or storage invariant violation"
line 664:  Goaway{UNSPECIFIED, "chain_verification_failed"}
line 677:  Goaway{UNSPECIFIED}, close
line 691:  RejectFatal(session_update_unknown_generation, UNSPECIFIED)
line 1202: Strict-mode block — "Goaway{UNSPECIFIED, ...}" (×3 within the block)
```

The §3.1.3 table (around line 305) gets two changes:
- The existing "Protocol invariant or storage invariant violation" row label switches from `UNSPECIFIED` to `PROTOCOL_ERROR`.
- A new row is added for `UNSPECIFIED`, describing it as v0.4-legacy and noting that v0.5+ servers SHOULD NOT emit it.

`docs/specs/WTP-v0.5-candidates.md` — line 40 (the candidate entry naming this exact change) is removed.

## Performance

No runtime impact. The change is wire schema + documentation. Protobuf enum encoding is a single varint; adding one value does not change the encoding of existing values.

## Testing

### agentsh-side (Stage 1)

1. **`proto/canyonroad/wtp/v1/validate_test.go`** — extend the accepted-code table in `TestValidateGoaway` to include `GoawayCode_GOAWAY_CODE_PROTOCOL_ERROR`. One new table entry.

2. **`proto/canyonroad/wtp/v1/validate_reason_test.go`** — parity test (validator reasons ↔ metric labels). No new `ValidationReason` is added. The existing parity assertion must continue to pass; if it fails, the model is wrong and the design needs revisiting.

3. **`internal/store/watchtower/transport/recv_multiplexer_failclosed_test.go`** — add a sub-test that constructs `Goaway{Code: PROTOCOL_ERROR, Message: "..."}`, runs it through the recv multiplexer, and asserts the structured log line contains `goaway_code=GOAWAY_CODE_PROTOCOL_ERROR` and `goaway_retry_immediately=false`. This is the core operator-visible-improvement smoke test.

4. **`internal/metrics/wtp.go` parity assertion** — verify no new invalid-frame reason is needed (PROTOCOL_ERROR is a *valid* code, not an invalid-frame reason). The metric parity test should continue to pass with no metric additions.

### watchtower-side (Stage 2 — detailed for completeness; out of scope for this PR)

1. **`internal/edge/wtp/action_test.go`** — assert `RejectFatal(r, PROTOCOL_ERROR)` produces an Action with `GoawayCode == 6`. One new assertion.

2. **State-machine tests across `event_batch_test.go`, `heartbeat_test.go`, `transport_loss_test.go`, `client_shutdown_test.go`, `state_test.go`, `admit_test.go`** — every test asserting `GoawayCode == UNSPECIFIED` updates to assert `GoawayCode == PROTOCOL_ERROR`. Mechanical refactor at the test-assertion level. Approximately 45 assertions touched.

3. **`internal/edge/wtp/server/convert_test.go`** — assert `actionToGoawayMessage` for a `RejectFatal(PROTOCOL_ERROR)` Action produces a wire frame with `Code = 6` and `RetryImmediately = false`. One new test.

4. **End-to-end integration test (if one exists for full session lifecycle)** — verify a simulated protocol-invariant violation produces `Goaway{PROTOCOL_ERROR, "<reason>"}`. Probably an existing test that just needs assertion updates.

### Tests explicitly NOT added

- No cross-repo golden-frame wire-compat test. Protobuf wire format for the same enum number is identical by construction.
- No new metric (Approach B explicitly does not add metrics).
- No "agent halts on PROTOCOL_ERROR" test. We chose label-only semantics; no halt path exists.

## Rollout

Two-stage, sequenced agentsh-first:

**Stage 1 — agentsh PR (this design's scope):**

1. Edit `proto/canyonroad/wtp/v1/wtp.proto`: add `PROTOCOL_ERROR = 6`, refresh `UNSPECIFIED` comment.
2. Regenerate `proto/canyonroad/wtp/v1/wtp.pb.go`.
3. Rewrite `proto/canyonroad/wtp/v1/validate.go` docstring on `ValidateGoaway`.
4. Extend `validate_test.go` accepted-code table.
5. Add `recv_multiplexer_failclosed_test.go` log-format sub-test.
6. Verify reason↔metric parity test stays green.
7. `go build ./... && GOOS=windows go build ./... && go test ./...`.
8. PR, CI, merge.

Production effect after Stage 1: none observable. Enum label is defined; no server emits it.

**Stage 2 — watchtower PR (separate, user-handled):**

1. Mirror proto enum + comments to `api/proto/wtp/v1/wtp.proto`.
2. Regenerate `api/proto/wtp/v1/wtp.pb.go`.
3. Migrate 45 `RejectFatal` call sites: `UNSPECIFIED` → `PROTOCOL_ERROR`.
4. Update `docs/specs/watchtower.md` (11 sites + table-row addition).
5. Remove `docs/specs/WTP-v0.5-candidates.md` line 40 entry.
6. Update state-machine + convert tests (~45 assertions).
7. `go build && go test`.
8. PR, CI, merge.

Production effect after Stage 2: agent logs surface `goaway_code=GOAWAY_CODE_PROTOCOL_ERROR` for protocol invariants instead of `GOAWAY_CODE_UNSPECIFIED`. No behavior change beyond log-line content.

### Compatibility matrix between stages

| Server | Agent (after Stage 1) | Outcome |
|---|---|---|
| v0.4 watchtower (pre-Stage-2) | v0.5 agent | Emits UNSPECIFIED → agent accepts → reconnects (unchanged) |
| v0.5 watchtower (post-Stage-2) | v0.5 agent | Emits PROTOCOL_ERROR → agent accepts → reconnects → logs new label |
| v0.4 watchtower | v0.4 agent (theoretical) | Unchanged |
| v0.5 watchtower (post-Stage-2) | v0.4 agent (theoretical mixed fleet) | Code 6 unknown in v0.4 protoc; `code.String()` returns numeric form, agent reconnects. Not catastrophic; visible only in log cosmetics. |

The Stage 1 → Stage 2 ordering is safety-driven, not correctness-driven: any ordering works, but agentsh-first eliminates the "unknown code 6" cosmetic regression window.

## Open questions / follow-ups

- **Configurable halt semantics (Option 4 from brainstorming).** Not in this design. If production telemetry shows operators wanting an explicit "stop reconnecting" signal on PROTOCOL_ERROR, add a `wtp.protocol_error_action: "reconnect" | "halt"` agent config knob in a follow-up.
- **Received-Goaway-by-code metric.** Not in this design. Add if operator dashboards need to count PROTOCOL_ERROR events without log scraping.
- **Tightening `ValidateGoaway` to reject UNSPECIFIED in a future major (e.g., WTP v1.0).** Not in this design. The current docstring records UNSPECIFIED as v0.4-legacy; a future major version could tighten the validator without ceremony.
- **Stage 2 timing.** Owned by the watchtower repo; no fixed deadline tied to this design.
