# WTP Phase 1: OCSF Mapper

**Date:** 2026-04-25
**Status:** Draft (design specification; implementation tracked separately)
**Scope:** Defines the OCSF v1.8.0 schema mapper that projects an `events.Event` into the `(ocsf_class_uid, ocsf_activity_id, payload []byte)` shape consumed by `wtpv1.CompactEvent`. Implements the `compact.Mapper` interface that the WTP client (Phase 2) already depends on. Closes the production-blocker that `Store.validate()` currently enforces by rejecting `compact.StubMapper`.

**Related:**
- `docs/superpowers/specs/2026-04-18-phase-0-shared-sequence-contract.md` — shared sequence/generation allocator + sink-local chain contract.
- `docs/superpowers/specs/2026-04-18-wtp-client-design.md` — WTP client; consumes this mapper via `watchtower.WithMapper(...)`.
- `internal/store/watchtower/compact/mapper.go` — existing `Mapper` interface and `StubMapper`.
- `pkg/types/events.go` — `Event` shape this mapper consumes.
- `proto/canyonroad/wtp/v1/wtp.proto` — `CompactEvent` shape this mapper feeds.

## Why

Phase 0 (shared sequence + sink chains) and Phase 2 (WTP client) are both designed against an injected `compact.Mapper`. The `StubMapper` shipped today emits `class=0/activity=0` with the raw `events.Event` JSON as payload; `Store.validate()` rejects it in production. Until a real mapper exists, the WTP sink cannot be enabled. Phase 1 fills that gap.

The mapper has three jobs:

1. **Classify** each `events.Event` into an OCSF v1.8.0 class and activity.
2. **Project** the event's structured columns and (allowlisted subset of) `Fields` into a typed proto3 message that mirrors the OCSF class schema.
3. **Encode** the message deterministically so the same logical event always produces byte-identical payload — load-bearing for the Phase 0 chain hash.

It is a pure function: same input → same output bytes. No I/O, no goroutines, no globals beyond a process-init registry.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| **Payload encoding** | Proto3 per-class messages with `proto.MarshalOptions{Deterministic: true}.Marshal(...)` | Wire is already proto3 end-to-end; OCSF doesn't publish official protos; deterministic marshal is straightforward and gives byte-stable output for chain hashing; ~5× smaller than canonical OCSF JSON for our event mix. |
| **Event-catalog scope** | Full production catalog → 8 OCSF classes (one PR series, no Phase 1.5) | Avoids long-tail "unmapped" debt; bounded authoring (~10 proto messages, ~40 registry entries). |
| **Unmapped-type handling** | Compile-time exhaustiveness check + runtime drop with counter | Allowlist-style: a forgotten registration breaks the build, not production. CI walks every `Type:` literal in `internal/`, `pkg/`, `cmd/` and asserts it is registered or skiplisted. |
| **Package home** | `internal/ocsf/` (standalone) | Mapping logic is independent of WTP transport mechanics; mirrors the proto layout at `proto/canyonroad/wtp/v1/ocsf/`; one extra package is the only cost. |
| **Infra/operational events** | Mapped to Application Activity (6005) with `agent_internal=true` flag and activity IDs ≥ 100 | No data loss; server-side filters can split SOC vs. fleet-health views without a wire schema change; matches "WTP is the agent's outbound telemetry channel" framing. |
| **Fields handling** | Per-class allowlist + transforms; no global denylist | Fail-closed: attacker-controlled values in `ev.Fields` (LLM-supplied tool args, outbound headers) cannot leak through unregistered keys. Sensitive keys are simply absent from any allowlist. |
| **Mapping-table structure** | Single declarative `registry map[string]Mapping` + per-class `Projector` functions | Registry is the spec; exhaustiveness check is mechanical (`for t := range knownTypes { _, ok := registry[t]; require ok }`); per-event work is real Go for type safety. |
| **OCSF version** | Pin to `"1.8.0"` (build-time constant `ocsf.SchemaVersion`); negotiation deferred | Matches WTP `SessionInit`; the wire field exists, so a future negotiation phase needs no schema change. |
| **Determinism violations** | Caught by `TestMapDeterministic` (1000× identical payload) and by Phase 0 chain at runtime (`ErrStaleResult` on replay) | Cheap unit test prevents the expensive runtime failure mode. |

## Architecture

### Package layout

```
proto/canyonroad/wtp/v1/ocsf/
├── common.proto                // Actor, Process, File, Endpoint, Metadata, User
├── process_activity.proto      // class_uid 1007
├── file_activity.proto         // class_uid 1001
├── network_activity.proto      // class_uid 4001
├── http_activity.proto         // class_uid 4002
├── dns_activity.proto          // class_uid 4003
├── detection_finding.proto     // class_uid 2004
└── application_activity.proto  // class_uid 6005

internal/ocsf/
├── mapper.go                  // type Mapper, New(), Map(ev) → MappedEvent
├── registry.go                // var registry = map[string]Mapping{ ... }
├── mapping.go                 // type Mapping, type Projector, FieldRule
├── activity.go                // OCSF activity_id constants + agentsh-internal extensions
├── version.go                 // const SchemaVersion = "1.8.0"
├── project_process.go
├── project_file.go
├── project_network.go
├── project_http.go
├── project_dns.go
├── project_finding.go
├── project_app.go             // class 6005, including infra events
├── skiplist.go                // test-only Type values excluded from exhaustiveness
├── exhaustiveness_test.go
├── redaction_test.go
├── mapper_test.go
└── testdata/
    └── golden/
        ├── execve.json
        ├── file_open.json
        └── …                  // one per registered Type
```

### Imports and boundaries

- `internal/ocsf` imports `pkg/types`, `proto/canyonroad/wtp/v1/ocsf` (generated `ocsfpb`), and `internal/store/watchtower/compact` (for the `MappedEvent` shape and `Mapper` interface).
- `internal/ocsf` does **not** import any other `internal/store/*` package — no reverse imports.
- `internal/store/watchtower/compact.Mapper` is the interface; `internal/ocsf.Mapper` implements it.

### Concurrency

`Mapper` is read-only after `New()`. Concurrent `Map` calls are safe. No locks. The `registry` is populated at package-init and never mutated.

### Out-of-scope

- Chain hashing (Phase 0).
- Batching, transport, WAL (Phase 2).
- Mutation of `types.Event`.
- OCSF version negotiation.
- A `TransportLoss` marker for mapper-side drops (deferred to Phase 8 per the WTP design).
- OCSF classes other than the eight listed below (Authentication 3002, Authorization 3003, Vulnerability Finding 2002, etc.).

## OCSF Class Set

Eight classes cover the full event catalog. The full per-event registry lives in `internal/ocsf/registry.go`; this section is the contract for which classes the proto authoring covers.

| Class | UID | agentsh Types |
|---|---|---|
| **Process Activity** | 1007 | `execve`, `exec`, `exec_intercept`, `exec.start`, `ptrace_execve`, `command_started`, `command_executed`, `command_finished`, `command_killed`, `command_redirected`, `command_redirect`, `process_start`, `exit` |
| **File System Activity** | 1001 | `file_open`, `file_read`, `file_write`, `file_create`, `file_created`, `file_delete`, `file_deleted`, `file_chmod`, `file_mkdir`, `file_rmdir`, `file_rename`, `file_renamed`, `file_modified`, `file_soft_deleted`, `ptrace_file`, `registry_write`, `registry_error` |
| **Network Activity** | 4001 | `net_connect`, `connection_allowed`, `connect_redirect`, `ptrace_network`, `unix_socket_op`, `transparent_net_failed`, `transparent_net_ready`, `transparent_net_setup`, `mcp_network_connection` |
| **HTTP Activity** | 4002 | `http`, `net_http_request`, `http_service_denied_direct` |
| **DNS Activity** | 4003 | `dns_query`, `dns_redirect` |
| **Detection Finding** | 2004 | `command_policy`, `seccomp_blocked`, `agent_detected`, `taint_created`, `taint_propagated`, `taint_removed`, `mcp_cross_server_blocked`, `mcp_tool_call_intercepted` |
| **Application Activity** | 6005 | MCP family (`mcp_tool_called`, `mcp_tool_seen`, `mcp_tool_changed`, `mcp_tools_list_changed`, `mcp_sampling_request`, `mcp_tool_result_inspected`), proxies (`llm_proxy_started`, `llm_proxy_failed`, `net_proxy_started`, `net_proxy_failed`), `secret_access`, **plus all infra events** (`cgroup_*`, `fuse_*`, `ebpf_*`, `wrap_init`, `fsevents_error`, `integrity_chain_rotated`, `policy_created/updated/deleted`, `session_created/destroyed/expired/updated`) tagged with `agent_internal=true` |

Activity IDs follow OCSF's class-specific enums for the standard classes. For `Application Activity 6005`, agentsh-internal activities use values ≥ 100 (e.g., `EBPF_ATTACHED=100`, `FUSE_MOUNTED=101`, `CGROUP_APPLIED=102`, `INTEGRITY_CHAIN_ROTATED=110`, `POLICY_CREATED=120`, `SESSION_CREATED=130`) to stay clear of OCSF-reserved ranges.

A small set of test-only Type values appearing only in test files (`a`, `b`, `x`, `y`, `test`, `test_event`, `demo`, `hello`, `phone`, `license`, `ok`, `none`, `live`, `email`, `external`, `self`, `invalid`, `invalid_type`, `pid_range`, `signal`, `resize`, `rotate`, `after_rotate`, `start`, `big_event`, `command`, `fatal_sidecar`, `file`, `malware`, `network`, `process`, `session`, `sse`, `stream`, `unix`, `vulnerability`) is explicitly listed in `internal/ocsf/skiplist.go` and excluded from the exhaustiveness check. Each entry carries a `// reason:` comment justifying inclusion. The `skiplist_test.go` asserts the comment is non-empty for every entry. The skiplist must not contain any value listed in the OCSF Class Set table above; a `TestSkiplistDoesNotShadowRegistry` sub-test asserts the disjointness.

## Components

### `Mapping` shape

```go
package ocsf

import (
    "github.com/agentsh/agentsh/internal/store/watchtower/compact"
    "github.com/agentsh/agentsh/pkg/types"
    "google.golang.org/protobuf/proto"
)

type Mapping struct {
    ClassUID        uint32          // OCSF class_uid
    ActivityID      uint32          // OCSF activity_id (or agentsh-extended for infra)
    AgentInternal   bool            // true for class 6005 infra events
    FieldsAllowlist []FieldRule     // per-key projection rules for ev.Fields
    Project         Projector       // builds the per-class proto payload
}

type Projector func(ev types.Event, allowed map[string]any) (proto.Message, error)

type FieldRule struct {
    Key       string                       // ev.Fields[Key]
    Required  bool                         // if true, mapping fails when absent
    Transform func(any) (any, error)       // identity, ToString, ToInt64, redact, …
    DestPath  string                       // documentation only, e.g., "request.headers.host"
}
```

The `Projector` receives only allowlisted-and-transformed Field values plus `ev`'s structured columns (`Filename`, `Argv`, `Path`, `Domain`, `Policy`, …). It cannot reach `ev.Fields` directly — that is enforced by the function signature.

A `Transform` returning `(nil, nil)` omits the key from `allowed`. There is no global denylist; sensitive keys are absent from every allowlist by construction.

### `Map()` flow

```go
func (m *Mapper) Map(ev types.Event) (compact.MappedEvent, error) {
    rule, ok := m.registry[ev.Type]
    if !ok {
        return compact.MappedEvent{}, &UnmappedTypeError{Type: ev.Type}
    }

    allowed, err := projectFields(ev.Fields, rule.FieldsAllowlist)
    if err != nil {
        return compact.MappedEvent{}, err
    }

    msg, err := safeProject(rule.Project, ev, allowed) // recover() wrapper
    if err != nil {
        return compact.MappedEvent{}, err
    }

    payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
    if err != nil {
        return compact.MappedEvent{}, fmt.Errorf("ocsf: marshal: %w", err)
    }

    return compact.MappedEvent{
        OCSFClassUID:   rule.ClassUID,
        OCSFActivityID: rule.ActivityID,
        Payload:        payload,
    }, nil
}
```

### Determinism contract

`Map(ev)` MUST be deterministic — for any two calls with logically equal `ev`, the returned `Payload []byte` is byte-identical. Implementation:

1. **Per-class proto marshal** uses `proto.MarshalOptions{Deterministic: true}.Marshal(msg)` — sorts proto map keys, fixes wire-tag ordering, drops zero-value fields predictably.
2. **`projectFields` iteration order** is the order of `Mapping.FieldsAllowlist` (a Go slice — deterministic by declaration). The mapper does **not** range over `ev.Fields` directly anywhere in the projection path.
3. **`activity_id`** is a static value in the registry. No `time.Now()`, no random IDs, no per-call counters.
4. **Timestamp** is normalized to UTC (`ev.Timestamp.UTC().UnixNano()`) so `MarshalBinary` of an equivalent timestamp produces identical bytes regardless of source location.
5. **No hidden state** in `Mapper`. Two calls with identical inputs return identical outputs — proven by `TestMapDeterministic`.

A determinism violation is caught at runtime by Phase 0's `SinkChain.Commit` (rejecting replay verification with `ErrStaleResult`) and at test time by `TestMapDeterministic` (1000 calls per event, 100 events, byte-equality assertion).

## Data Flow

```
Composite store
    ↓ (allocates seq/gen, stamps ev.Chain — Phase 0)
WTP Store.AppendEvent(ev)
    ↓
compact.Encode(ev, mapper, sinkChain, ctx)
    ↓
mapper.Map(ev)               ← internal/ocsf
    ├─ registry[ev.Type] lookup
    ├─ projectFields(ev.Fields, allowlist)
    ├─ rule.Project(ev, allowed) → typed *ocsfpb.X message
    └─ proto.Marshal(deterministic) → []byte
    ↓ MappedEvent{class, activity, payload}
compact.Encode builds CompactEvent{seq, gen, ts, class, activity, payload, integrity}
    ↓
sinkChain.Compute(formatVersion, seq, gen, canonicalRecord)  ← Phase 0 contract
    ↓
WTP WAL → batch → gRPC
```

Mapper input is read-only. `Map(ev)` does not mutate `ev`, `ev.Fields`, or `ev.Chain`. Projectors must not mutate `allowed` either.

A mapping that produces a payload exceeding the per-event cap is rejected at the WTP boundary (Task 23 territory; the WTP design already specifies the counters). Invalid UTF-8 inside a string field surfaces as `chain.ErrInvalidUTF8` from the chain encoder; the mapper does not pre-validate UTF-8. Sequence-overflow handling is the composite/WTP boundary's job, not the mapper's.

## Proto Schemas

Layout under `proto/canyonroad/wtp/v1/ocsf/` — one `.proto` file per class plus `common.proto` for shared types. All messages use:

- `package canyonroad.wtp.v1.ocsf;`
- `option go_package = "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1/ocsf;ocsfpb";`
- snake_case field names matching OCSF v1.8.0 JSON keys verbatim
- proto3 explicit-presence (`optional`) on every field so absence is distinguishable from zero-value

Modelling rules:

1. **Direct OCSF subset.** Each message models only the fields agentsh actually populates today. Adding a field later is an additive proto change.
2. **Shared types in `common.proto`.** Reused objects (`Process`, `File`, `Actor`, `Endpoint`, `Metadata`, `User`) are defined once. `Metadata` carries `version: "1.8.0"` and `product.name: "agentsh"`.
3. **Enum subsets.** Class-specific activity enums declare only the values agentsh uses, plus the OCSF-mandated `UNKNOWN = 0`.
4. **Agent-internal extension activities.** `application_activity.proto` declares an extended activity enum with values ≥ 100 for agentsh-internal activities. Each `ApplicationActivity` message also declares `bool agent_internal = 50;` so server-side filtering does not depend on the activity range.
5. **No inheritance.** OCSF's "object" model is JSON-flavored; we flatten where needed and accept that some `*Info` fields (e.g., `ConnectionInfo`) are redeclared per class rather than extending a base message.
6. **Versioning.** OCSF additive minor (1.8 → 1.9) = new optional fields; existing wire bytes stay valid. OCSF major (1.x → 2.0) = new sibling package `proto/canyonroad/wtp/v2/ocsf/` with a corresponding `internal/ocsf/v2/`. The `ocsf_version` string in `SessionInit` is the source of truth for which version a stream uses.

Authoring scope: ~10 message types in 8 files, 5–15 fields each, ~600–800 lines of `.proto` total. The OCSF schema browser (schema.ocsf.io) is the reference; field names are copied verbatim for the subset used.

## Failure Modes

The mapper has three error categories, all surfaced as typed errors:

```go
package ocsf

var (
    // Type isn't registered. Should never happen in production because the
    // exhaustiveness CI catches new Types pre-merge. If it does happen
    // (skiplist drift, plugin emitting a new Type), the WTP store drops the
    // event and bumps wtp_dropped_invalid_mapper_total{reason="unmapped_type"}.
    ErrUnmappedType = errors.New("ocsf: event Type not registered")

    // A FieldRule with Required=true was missing or transform-rejected.
    // Indicates an event-emit site bug.
    ErrMissingRequiredField = errors.New("ocsf: required allowlisted field absent or rejected")

    // Projector returned nil message, panicked, or proto.Marshal failed.
    ErrProjectFailed = errors.New("ocsf: projector failed to build OCSF message")
)

// UnmappedTypeError wraps ErrUnmappedType with the offending Type for logging.
type UnmappedTypeError struct{ Type string }

func (e *UnmappedTypeError) Error() string { … }
func (e *UnmappedTypeError) Unwrap() error { return ErrUnmappedType }
```

### Routing

All three errors propagate up through `compact.Encode` to `watchtower.Store.AppendEvent`. The WTP design already specifies the drop counters; this section nails down the `errors.Is(...)` → label mapping:

| Error | Counter | Label |
|---|---|---|
| `ErrUnmappedType` | `wtp_dropped_invalid_mapper_total` | `reason="unmapped_type"` |
| `ErrMissingRequiredField` | `wtp_dropped_mapper_failure_total` | `reason="missing_required_field"` |
| `ErrProjectFailed` | `wtp_dropped_mapper_failure_total` | `reason="project_failed"` |
| any other error | `wtp_dropped_mapper_failure_total` | `reason="unknown"` |

Each drop emits a structured WARN log with `event_type`, `error`, and a stable `reason` field matching the counter label. No PII from `ev.Fields` is logged — log cardinality is bounded by the number of distinct event types times the four reasons.

### Sequence accounting

A mapper-side drop happens *after* the composite has allocated the shared sequence and stamped `ev.Chain`. JSONL/OTEL sinks have committed seq=N for this event; WTP has not. Per the WTP/Phase 0 contract this manifests as a one-record gap that other sinks fill. Surfacing the gap as a `TransportLoss` marker in WTP's WAL stream is deferred to Phase 8 (the WTP design already documents this deferral). For Phase 1 the gap is observable via counters and structured logs; no `TransportLoss` is emitted.

### Panics

Projectors must not panic. A `recover()` wrapper inside `Map()` (`safeProject`) converts any panic into `ErrProjectFailed` with the panic value attached. This is a belt-and-braces guard: a panicking projector should be caught in tests, but malformed `ev.Fields` (unexpected concrete type behind an `any`) must not take down the daemon.

### No retry, no partial output

Mapping is pure and deterministic — retrying a failed `Map()` produces the same error. The store drops on first failure. If `Map()` returns an error, the returned `MappedEvent` is the zero value; callers must check the error before reading the result.

## Testing

Five test layers:

### 1. Per-event golden tests (`mapper_test.go` + `testdata/golden/<event_type>.json`)

For each registered Type, a fixture `Event` is mapped, the resulting proto payload decoded, projected to JSON via `protojson.Marshal` with stable options, and compared against a checked-in golden. Goldens are regenerated via `go test -update`. ~40 files (one per registered Type). Catches:

- Wrong class/activity assignment.
- Wrong field projection (`Domain` mapped to `process.cmd_line` instead of `connection_info.domain`).
- Allowlist regression (a Field that used to be projected silently disappeared).

### 2. Determinism property test (`mapper_test.go`)

`TestMapDeterministic` runs `Map(ev)` 1000× on a single event and asserts every payload is byte-identical. Then runs it on 100 different events and asserts each event's 1000 outputs are all identical. Catches accidental map-iteration leaks, time-based contamination, or non-deterministic proto marshal regressions.

### 3. Exhaustiveness CI (`exhaustiveness_test.go`)

- **Type exhaustiveness:** walks `internal/`, `pkg/`, `cmd/` with `go/parser`. Collects every `types.Event{Type: "..."}` literal and `ev.Type = "..."` assignment. Asserts each is in `registry` or `skiplist`. Reports unregistered Types with the file:line of the first occurrence.
- **Fields-key exhaustiveness:** walks the same tree for `ev.Fields["..."]` writes. For each key, asserts at least one Mapping registering an emitter of that key has the key in its `FieldsAllowlist`. Catches "we added a new Field key but forgot to allowlist it for the OCSF projection."
- **Skiplist hygiene:** every entry in `skiplist.go` carries a non-empty `// reason:` comment.

### 4. Redaction / sensitive-key guard (`redaction_test.go`)

A negative test: a hand-curated list of sensitive key names (`authorization`, `cookie`, `set-cookie`, `proxy-authorization`, `api_key`, `api-key`, `apikey`, `secret`, `password`, `token`, `bearer`, `x-auth-token`) is asserted to NOT appear in any allowlist across the full registry. Catches accidental allowlisting of a sensitive key. The sensitive-key list is the test's own fixture, separate from any production code (we do not have a global denylist).

### 5. Round-trip with WTP (extension to `internal/store/watchtower/encoder_e2e_test.go`)

The existing E2E test uses `compact.StubMapper`. Phase 1 adds a parallel test wiring the real `ocsf.Mapper` and asserting a sample of events flows end-to-end: `Event → Map → CompactEvent → SinkChain.Compute → WAL → wire`. Verifies the chain accepts the deterministic payload and that an off-by-one byte in the payload latches `ErrStaleResult` on commit.

### Out of scope for Phase 1 tests

- Fuzzing the proto decoder (server-side concern).
- Conformance against an official OCSF test vector (none published in proto form for v1.8.0; we'd need to author them).
- Cross-version compat (no v2 yet).
- Performance benchmarks (deferred until WTP throughput regression testing lands; mapper is in the hot path but proto encoding is well-understood ns-scale work).

## Migration & Wiring

Phase 1 lands as a single PR series that toggles the WTP store from `StubMapper` (rejected by `validate()`) to the real `ocsf.Mapper`.

### Order of merge

1. **Proto authoring.** `proto/canyonroad/wtp/v1/ocsf/*.proto` plus regenerated `.pb.go`. No Go code uses the new types yet. Compiles green; ships zero behavior change.
2. **Skeleton mapper.** `internal/ocsf/{mapper,mapping,registry,activity,version,skiplist}.go` with an empty registry. `Mapper.Map()` works but returns `ErrUnmappedType` for every event. The exhaustiveness check has an internal `pendingTypes` allowlist (initialized to every production Type) that suppresses failures for Types not yet registered; entries are removed PR-by-PR as classes land. Goldens directory is empty. Ships zero behavior change because nothing wires this in.
3. **Per-class projectors land in topological order**, one PR each, each self-contained. Each PR:
   - Adds `project_<class>.go` with the projector function(s) for that class.
   - Adds `registry` entries for every Type in that class (from §"OCSF Class Set").
   - Adds the goldens under `testdata/golden/`.
   - Removes the corresponding Types from `pendingTypes` so the exhaustiveness check enforces them.
   - When the last class lands, `pendingTypes` is empty and the check enforces the entire production catalog.

   Recommended order: Process → File → Network → DNS → HTTP → Detection Finding → Application Activity (largest, includes infra). Each PR is reviewable in isolation; each is independently reverable.
4. **Wiring switch.** Single small PR in `cmd/agentshd` (or wherever `watchtower.New` is called):
   ```go
   wtp, err := watchtower.New(
       watchtower.WithMapper(ocsf.New()),  // ← was: compact.StubMapper{}
       // … existing options …
   )
   ```
   `Store.validate()` already rejects the stub in production; this PR is the moment that production wiring becomes possible. Until this PR lands, the daemon fails fast at config when WTP is enabled — the intended behavior.
5. **Stub remains** in `internal/store/watchtower/compact/mapper.go` strictly as a unit-test helper. Production rejection is unchanged.

### Backwards compatibility

None required. The mapper is new; it has no callers before step 4. The OCSF protos are new; no client decodes them yet (server-side decode is in the Watchtower server, out of scope here). JSONL, OTEL, SQLite, webhook sinks: unchanged.

### Rollout & feature gating

WTP is already gated by config (`output.wtp.enabled`). Phase 1 does not change the gate. Operators turning WTP on for the first time get OCSF-mapped events from the first event onward; there is no "shadow" mode where WTP runs with `StubMapper` in production (rejected by `validate()`).

### Rollback

If the production wiring (step 4) needs reverting, the revert is one commit and the daemon falls back to refusing to start with WTP enabled. Operators who can't revert that fast disable WTP in config; that path is well-tested.

### What this phase does NOT do

- Doesn't change Phase 0 chain semantics.
- Doesn't change WTP transport/WAL/batching.
- Doesn't add OCSF version negotiation (still hard-coded `1.8.0`).
- Doesn't add a `TransportLoss` marker for mapper-drops (deferred to Phase 8 per WTP design).
- Doesn't author Authentication 3002 / Authorization 3003 / other OCSF classes outside the eight listed above.

## Verification

Acceptance criteria for declaring Phase 1 done:

1. All eight class projectors implemented; `registry` covers every production-emitted `Type` value; exhaustiveness test passes with `pendingTypes` empty.
2. `TestMapDeterministic` passes — 1000× call equality on 100 sample events.
3. `redaction_test.go` passes — no sensitive key name appears in any allowlist.
4. The WTP E2E round-trip test (with the real mapper) passes; an injected payload-byte mutation latches `ErrStaleResult` on chain replay.
5. `Store.validate()` accepts `ocsf.New()` and rejects `compact.StubMapper{}` (already implemented; this verifies it still holds after wiring).
6. `cmd/agentshd` boots green with `output.wtp.enabled=true`; first emitted event arrives at the in-tree testserver with the expected `(class_uid, activity_id, payload)` triple.
