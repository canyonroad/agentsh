# Issue #365 — Phase 1 Watchtower wiring fixes (design)

Date: 2026-05-20
Issue: [#365](https://github.com/agentsh/agentsh/issues/365)

## Background

A smoke test of the Watchtower demo against agentsh `main` surfaced an
empty live feed despite a healthy gRPC stream and successful auth. The
issue ascribed this to "Phase 1 incomplete" — specifically, an
incomplete OCSF projector backlog (Tasks 16–22) plus a hardcoded
`agent_id`.

Investigation against runtime state (not the source declaration) found
that the projector backlog the issue describes is **already shipped**:

- `internal/ocsf/registry` contains **96 registered event types** after
  package init.
- The runtime `pendingTypes` set contains exactly one entry:
  `db_statement` — pending a dedicated OCSF database projection.
- Every exec-lifecycle and file/network/HTTP/DNS event named in the
  issue is registered and would map cleanly.

The static `pendingTypes` map declared at `internal/ocsf/registry.go:26`
is an archaeological record of the original Task 16–22 plan; each
`register()` call deletes the corresponding entry during the relevant
`project_*.go` package init. The issue's report mistook the static
declaration for the runtime state.

Two real defects remain from the smoke test, plus one CI gap that let
the first one slip through:

1. **`cgroup_mode` drops at every daemon start.** The event is emitted
   from `internal/server/server.go:492` as
   `Type: string(events.EventCgroupMode)`. It has no projector, no
   skiplist entry, and no `pendingTypes` entry — so `Mapper.Map`
   returns `UnmappedTypeError`, the WTP store records a
   `mapper_failure`, and the event is silently dropped before WAL.
2. **`agent_id` is hardcoded to `os.Hostname()`.** Operators provisioning
   Watchtower agents must either rename their host or mint a fresh
   token per host. The TODO is already flagged in source
   (`internal/server/wtp.go:90`).
3. **The OCSF exhaustiveness AST scanner is blind to the
   `Type: string(events.EventX)` form.** It only recognises string
   literals. This is why `cgroup_mode` reached production without
   tripping `TestExhaustiveness_AllEventTypesRegistered`.

The "exec events not visible on the Watchtower live feed" symptom
reported in the issue is **not** caused by the mapper (subsequent
events log no further `mapper_failure` lines). It is almost certainly a
separate concern — batching, filter `min_risk_level`, or a
render/query layer issue on the Watchtower side — and is explicitly
deferred from this work.

## Goal

Close the three real defects with a single, tight PR that unblocks the
demo:

- Register an OCSF projector for `cgroup_mode`.
- Harden the exhaustiveness AST scanner to catch
  `Type: string(events.EventX)` form so this class of gap is detected
  by CI in the future.
- Add an `audit.watchtower.agent_id` config field with override-only
  semantics and hostname fallback.

## Non-goals

- **`db_statement` projector.** Pending dedicated OCSF database
  projection. Out of scope; will be its own follow-up.
- **"Exec events missing on Watchtower" investigation.** Symptom in
  issue #365 but not caused by the OCSF mapper. Separate bug.
- **AST scanner: helper-emitter walker upgrade.** The TODO at
  `internal/ocsf/exhaustiveness_test.go:36` (catching emit sites like
  `n.emitFileEvent(ctx, "dir_list", ...)`) is a larger go/types-based
  change. All seven helper-emitted types listed in the TODO
  (`net_close`, `dir_list`, `file_stat`, `dir_create`, `dir_delete`,
  `symlink_create`, `symlink_read`) are already manually registered in
  `project_file.go` / `project_network.go`, so this defect is dormant
  and out of scope here.
- **CLI / proto / migration changes.** None of the three items touches
  them.

## Acceptance criteria

- A fresh daemon start with `audit.watchtower.enabled: true` logs no
  `wtp: dropping event before WAL append reason=mapper_failure
  err="...: \"cgroup_mode\""` line.
- Setting `audit.watchtower.agent_id: agent-edge-001` overrides
  hostname on the Watchtower wire. Omitting or leaving it empty falls
  back to `os.Hostname()`. Whitespace-only values are treated as empty.
  Daemon does not panic when `os.Hostname()` itself errors.
- Removing the new `cgroup_mode` projector locally causes
  `TestExhaustiveness_AllEventTypesRegistered` to fail, demonstrating
  the AST scanner now catches the `string(events.EventX)` form.

## Architecture and file-level changes

### 1. `cgroup_mode` projector

Slot the event into the existing app-activity projector alongside the
sibling `cgroup_*` events. The `agent_internal=true` flag matches the
"fleet-health" classification used for `cgroup_applied`,
`cgroup_apply_failed`, and `cgroup_cleanup_failed`.

**`internal/ocsf/activity.go`** — add one constant in the
agentsh-internal range (`100–155`). Slot `151` is currently unused.

```go
AppActivityCgroupMode uint32 = 151
```

**`internal/ocsf/project_app.go`** — in `init()`:

- Add `"cgroup_mode": AppActivityCgroupMode` to the existing
  `infraMappings` map.
- Extend `infraAllow` with the fields emitted at
  `internal/server/server.go:492`. (`reason` is already allowlisted.)

```go
{Key: "mode",         Transform: AsString, DestPath: "enrichments.mode"},
{Key: "own_cgroup",   Transform: AsString, DestPath: "enrichments.own_cgroup"},
{Key: "slice_dir",    Transform: AsString, DestPath: "enrichments.slice_dir"},
{Key: "io_available", Transform: AsBool,   DestPath: "enrichments.io_available"},
{Key: "leaf_moved",   Transform: AsBool,   DestPath: "enrichments.leaf_moved"},
```

`infraAllow` is shared across all 22 infra events. Keyed lookups mean
events without these fields simply don't populate them — no
cross-pollution risk.

### 2. AST scanner harden

**File:** `internal/ocsf/exhaustiveness_test.go`.

The current `scanTypeLiterals` walks `Type:` key-value exprs and
`ev.Type =` assignments, but only matches the value when it is an
`*ast.BasicLit` of kind `STRING`. It misses the
`string(events.EventCgroupMode)` form, which is an `*ast.CallExpr`
(the built-in `string` conversion).

Approach is pure AST — no `go/types`, no `go/packages`.

1. **Pre-pass: `loadEventConstants(t, rootDir) map[string]string`.**
   Parses `internal/events/types.go` and walks `*ast.GenDecl` (`tok ==
   token.CONST`). For each `*ast.ValueSpec` whose declared type is
   `EventType` and whose first value is a `*ast.BasicLit` of kind
   `STRING`, record `name → unquoted-value` (e.g.
   `"EventCgroupMode" → "cgroup_mode"`). Other constants are skipped.

2. **Walker extension.** In `scanTypeLiterals`, when the `Type:` or
   `ev.Type =` value is an `*ast.CallExpr`:
   - The call's `Fun` must be `*ast.Ident{Name: "string"}` (the
     built-in conversion).
   - The single argument must be one of:
     - `*ast.SelectorExpr` with `X` an `*ast.Ident{Name: "events"}`
       and `Sel.Name` matching a key in the constants map — i.e.
       `string(events.EventX)`, the qualified form used from outside
       `internal/events`.
     - `*ast.Ident` whose `Name` matches a key in the constants map —
       i.e. `string(EventX)`, the bare form used within the package
       itself.
   - On a match, the resolved string value is added to the discovered
     set with the call's source position.

3. **New negative test
   `TestExhaustiveness_DetectsStringConversionForm`.** Table-driven
   over the two forms (qualified, bare). Each case parses an in-memory
   Go source snippet that constructs a `types.Event` literal using
   `Type: string(events.EventCgroupMode)` (or the bare variant) and
   asserts the resolved value (`"cgroup_mode"`) appears in the
   walker's output. A control case asserts that an unrelated constant
   reference is **not** included.

**Limitation acknowledged.** If a future emit site references
`events.EventX` directly (without the `string(...)` conversion, relying
on `EventType`'s underlying string kind), the walker still won't catch
it. No such site exists today; extension is deferred until needed.

The pre-existing helper-emitter TODO at line 36 of the test file is
unrelated and untouched.

### 3. `audit.watchtower.agent_id` config field

**`internal/config/config.go`** — add one struct field to
`AuditWatchtowerConfig`, positioned immediately after `SessionID` so
the two identifier fields are grouped.

```go
// AgentID is the operator-visible identifier for this agent on the
// Watchtower wire. When empty (the default), buildWatchtowerStore
// falls back to os.Hostname() — preserving pre-existing behaviour.
//
// Mirrors SessionID: optional in YAML, resolved at store-construction
// time, NOT in applyDefaults — non-daemon CLI subcommands like
// `agentsh config show` must not trigger hostname lookup.
AgentID string `yaml:"agent_id"`
```

No `applyDefaults` change. No `validate` change. The empty string is a
legitimate sentinel for "use hostname".

**`internal/server/wtp.go`** — replace the resolution block at lines
89–93:

```go
agentID := strings.TrimSpace(cfg.AgentID)
if agentID == "" {
    h, err := os.Hostname()
    if err != nil {
        h = "unknown"
    }
    agentID = h
}
```

Update the doc comment of `buildWatchtowerStore` to describe the new
three-rung resolution order (config → hostname → `"unknown"`) and to
remove the stale "Phase 1 gap" note.

## Error handling

No new error types or sentinels. Each item composes with existing
classification paths:

- Projector errors continue to flow through
  `compact.ErrMapperFailure` in
  `internal/store/watchtower/append.go:269`. The new field
  allowlist entries are best-effort enrichments — none are marked
  `Required`, so a missing or wrong-type field produces no error.
- The AST scanner is test code; failures surface as `t.Fatalf` exactly
  as today.
- AgentID resolution has three explicit fallback rungs and propagates
  no new errors.

## Edge cases

| Case | Behaviour |
|---|---|
| `cfg.AgentID = ""` | Falls back to `os.Hostname()`. |
| `cfg.AgentID = "   "` (whitespace) | `TrimSpace` → empty → hostname fallback. |
| `cfg.AgentID` set + `os.Hostname()` would error | Override takes effect; hostname never consulted. |
| `cfg.AgentID = ""` + `os.Hostname()` errors | Resolves to `"unknown"` (existing behaviour). |
| `cgroup_mode` event omits one of the new fields | Allowlist transform silently drops it; `enrichments` map omits the key. No error. |
| `cgroup_mode` event has a wrong-typed field (e.g. `io_available: "yes"`) | `AsBool` rejects the cast; key omitted. No error. |
| Scanner sees `string(events.EventX)` where `EventX` is not in `events/types.go` | Lookup miss → call is skipped silently. If the typo also appears as a bare literal elsewhere, the exhaustiveness test still fails on that path. |
| Scanner pre-pass: const declared in `events/types.go` but not of type `EventType` | Filtered out by the typed-spec check; ignored. |
| Scanner pre-pass: const declared but never referenced in any emit site | Harmless; lookup entry never consulted. |

## Test plan

### Unit

- **`internal/ocsf/project_app_test.go`** (or wherever existing
  app-projector tests live):
  - `TestCgroupMode_Registered` — registry contains `cgroup_mode`
    after `init()`.
  - `TestCgroupMode_Projects` — feed a `types.Event` with all six
    fields populated through `Mapper.Map`; assert
    `ClassUid=6005`, `ActivityId=151`, `AgentInternal=true`, and the
    enrichments map contains `mode`, `reason`, `own_cgroup`,
    `slice_dir`, `io_available`, `leaf_moved` with the right typed
    values.
  - `TestCgroupMode_OmittedFields_NoError` — event with only `mode`
    set; projection succeeds; only `mode` appears in `enrichments`.

- **`internal/ocsf/exhaustiveness_test.go`**:
  - `TestExhaustiveness_DetectsStringConversionForm` — two table
    rows (qualified, bare) plus a control row asserting non-detection
    of unrelated references.
  - `TestExhaustiveness_AllEventTypesRegistered` (existing) — must
    continue to pass with both the scanner change and the new
    projector landed. Local verification: temporarily remove the
    `cgroup_mode` mapping in `project_app.go` and confirm this test
    fails with a message naming `cgroup_mode` and the
    `server.go:492` position.

- **`internal/server/wtp_test.go`** — three new cases against
  `BuildWatchtowerStoreForTest`:
  - `TestBuildWatchtowerStore_AgentIDExplicit` —
    `cfg.AgentID="agent-edge-001"`, store records that value.
  - `TestBuildWatchtowerStore_AgentIDFallsBackToHostname` — empty
    `cfg.AgentID`, store records `os.Hostname()`.
  - `TestBuildWatchtowerStore_AgentIDTrimmed` —
    `cfg.AgentID="  agent-x  "`, store records `"agent-x"`.

- **`internal/config/config_test.go`** — extend an existing
  `TestAuditWatchtowerConfig_*` round-trip case to populate
  `agent_id: agent-edge-001` and confirm it survives YAML load.

### Manual smoke

Rebuild `bin/agentsh`. Run the demo with the issue's config plus
`audit.watchtower.agent_id: agent-edge-001`. Daemon startup logs must
contain zero `mapper_failure` lines for `cgroup_mode`, and the
Watchtower side must see Hello with `agent_id=agent-edge-001`.

### Cross-compile

- `GOOS=windows go build ./...` — `os.Hostname()` is cross-platform;
  no new OS-specific code introduced.

## Risk

- **Item 3 (config field):** pure-additive. Empty `AgentID` behaves
  exactly as before this change.
- **Item 2 (scanner):** the only failure mode is a false positive
  flagged by `TestExhaustiveness_AllEventTypesRegistered` — easy to
  diagnose because the failure names the offending string.
- **Item 1 (projector):** mechanical; the existing
  `cgroup_applied`/`cgroup_apply_failed`/`cgroup_cleanup_failed`
  registrations are the template.

No deprecations, migrations, proto changes, or public API changes.

## Out-of-scope follow-ups

- `db_statement` OCSF database projection.
- "Exec events not visible on Watchtower" investigation (filter /
  batch / render).
- AST scanner helper-emitter walker upgrade (TODO at
  `internal/ocsf/exhaustiveness_test.go:36`).
