# db-access Plan 04a — Listener Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship a Linux-only PostgreSQL proxy *listener* that binds Unix-socket listeners per declared `db_service`, authenticates peers by UID via SO_PEERCRED, and accepts/closes connections cleanly. No protocol semantics — Plan 04b adds handshake/TLS, Plan 04c adds Simple Query.

**Architecture:** New package `internal/db/proxy/postgres/` (`//go:build linux`; non-Linux stub returns `errors.ErrUnsupported`). Server lifecycle (`New` / `Start` / `Shutdown`) bound by an internal `errgroup`. Connection handler is a no-op that closes the conn after peercred check. The `policies.db.unavoidability` flag (default `off`) gates listener bind; with `off` the package is a no-op. DBEvent emission via a new `events.Sink` interface (in-memory `SyncSink` for tests; real sink wiring deferred to a later plan).

**Tech Stack:** Go (`//go:build linux` for the active code), `golang.org/x/sys/unix` (already a dep) for SO_PEERCRED, `golang.org/x/sync/errgroup` (already a dep), stdlib `net`, `slog`. Existing packages: `internal/db/service`, `internal/db/policy`, `internal/db/events`, `internal/policy`. Macro design: `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md`.

---

## File Structure

**Created:**

- `internal/db/service/flag.go` — `Unavoidability` enum (`UnavoidabilityOff | UnavoidabilityObserve | UnavoidabilityEnforce`), `String`, `ParseUnavoidability`.
- `internal/db/service/flag_test.go` — table-driven tests for `ParseUnavoidability` + `String`.
- `internal/db/events/sink.go` — `Sink` interface, `NopSink`, `SyncSink`.
- `internal/db/events/sink_test.go` — tests for `NopSink` + `SyncSink`.
- `internal/db/events/lifecycle.go` — `LifecycleEvent` value type for non-statement events (listener-auth failures, handshake failures, degraded-visibility warnings).
- `internal/db/events/lifecycle_test.go` — round-trip JSON test for `LifecycleEvent`.
- `internal/db/proxy/postgres/stub_other.go` — `//go:build !linux`; `New` returns a sentinel server whose `Start` returns `errors.ErrUnsupported`.
- `internal/db/proxy/postgres/server.go` — `//go:build linux`; `Config`, `Server`, `New`, `Start`, `Shutdown`. Sentinel-server short-circuit when `Unavoidability == off`.
- `internal/db/proxy/postgres/server_test.go` — server lifecycle tests on Linux.
- `internal/db/proxy/postgres/peercred_linux.go` — `//go:build linux`; SO_PEERCRED + UID-equality check.
- `internal/db/proxy/postgres/peercred_linux_test.go` — `socketpair`-based round-trip test for SO_PEERCRED.

**Modified:**

- `internal/db/policy/decode.go` — extend `dbPoliciesWrapper` to include `Unavoidability string`; add `decodeUnavoidability`; surface it on `RuleSet`.
- `internal/db/policy/types.go` — extend `RuleSet` with `unavoidability service.Unavoidability` field + `Unavoidability()` accessor.
- `internal/db/policy/decode_test.go` — add cases covering the new field.
- `internal/db/policy/validate.go` — reject connection rules under `tls_mode: passthrough` that match passthrough-invisible fields (`db_user`, `database`, `application_name`).
- `internal/db/policy/validate_test.go` — add cases covering the new validation.
- `internal/api/db_proxy.go` — proxy boot helper (NEW) wrapping `postgres.New` + `postgres.Server.Start`/`Shutdown`.
- `internal/api/db_proxy_test.go` — tests for the helper.
- `internal/server/server.go` — call `startDBProxy` next to the existing `app := api.NewApp(...)` site (around line 507) and chain its `Shutdown` into the existing `appCloser` defer.

**Sentinel server contract:** `Server.New` always returns a non-nil `*Server`. When `cfg.Unavoidability == UnavoidabilityOff`, `Start` is a no-op (logs once at info, returns nil immediately) and `Shutdown` is a no-op. Callers do not have to special-case the `off` flag.

**Listener path contract:** `Server.Start` binds each declared `db_service` whose `Listen.Kind == "unix"`. Listen kinds other than `unix` are accepted but not bound in 04a (they will bind in 04b once TCP framing exists for tests). For each Unix listener: parent dir must exist and be owned by current uid; existing socket file at the path is removed before bind (this is intentional — a stale socket from a prior crash should not block startup); after `bind` we call `chmod(0700)` on the socket file; `listen` with backlog 64. On `Shutdown` the socket file is unlinked.

---

## Task 1: Preflight — `Unavoidability` enum and `policies.db.unavoidability` decode

**Why:** The proxy `Server` needs to know which mode the operator selected. The flag rides on the existing `policies.db` YAML block (already parsed by `internal/db/policy/decode.go` for redaction). Adding it here means the proxy package only needs to call `ruleSet.Unavoidability()`.

**Files:**
- Create: `internal/db/service/flag.go`
- Create: `internal/db/service/flag_test.go`
- Modify: `internal/db/policy/decode.go`
- Modify: `internal/db/policy/types.go`
- Modify: `internal/db/policy/decode_test.go`

- [ ] **Step 1: Write the failing test for `ParseUnavoidability` and `String`**

Create `internal/db/service/flag_test.go`:

```go
package service

import "testing"

func TestUnavoidability_StringAndParse(t *testing.T) {
	tests := []struct {
		s    string
		want Unavoidability
		ok   bool
	}{
		{"off", UnavoidabilityOff, true},
		{"observe", UnavoidabilityObserve, true},
		{"enforce", UnavoidabilityEnforce, true},
		{"", UnavoidabilityOff, false},
		{"OFF", UnavoidabilityOff, false},        // case-sensitive
		{"unknown", UnavoidabilityOff, false},
	}
	for _, tc := range tests {
		got, ok := ParseUnavoidability(tc.s)
		if ok != tc.ok || got != tc.want {
			t.Errorf("ParseUnavoidability(%q) = (%v,%v), want (%v,%v)", tc.s, got, ok, tc.want, tc.ok)
		}
		if ok && got.String() != tc.s {
			t.Errorf("Unavoidability(%v).String() = %q, want %q", got, got.String(), tc.s)
		}
	}
}

func TestUnavoidability_ZeroValueIsOff(t *testing.T) {
	var u Unavoidability
	if u != UnavoidabilityOff {
		t.Fatalf("zero-value Unavoidability is %v, want UnavoidabilityOff", u)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/service/ -run TestUnavoidability -v`
Expected: FAIL with "undefined: Unavoidability" / "undefined: ParseUnavoidability".

- [ ] **Step 3: Implement `internal/db/service/flag.go`**

```go
package service

// Unavoidability is the policies.db.unavoidability flag per
// docs/agentsh-db-access-spec.md §11.1. Operators select one of three modes:
//
//   off     (default): proxy is inert; no listeners are bound.
//   observe: listeners bind; declared services are intercepted; events emit.
//   enforce: same as observe in Plan 04a (and through Plan 04c). Plan 07
//            generates the unavoidability bundle (egress denial, SessionID-
//            keyed proxy identity) and makes enforce the high-assurance default.
//
// The zero value is UnavoidabilityOff, which is the safe default for any
// caller holding a not-yet-decoded RuleSet.
type Unavoidability uint8

const (
	UnavoidabilityOff Unavoidability = iota
	UnavoidabilityObserve
	UnavoidabilityEnforce
)

func (u Unavoidability) String() string {
	switch u {
	case UnavoidabilityOff:
		return "off"
	case UnavoidabilityObserve:
		return "observe"
	case UnavoidabilityEnforce:
		return "enforce"
	default:
		return ""
	}
}

// ParseUnavoidability accepts the canonical lowercase mode names. Empty input
// returns ok=false (callers may want to apply a default at a higher level).
func ParseUnavoidability(s string) (Unavoidability, bool) {
	switch s {
	case "off":
		return UnavoidabilityOff, true
	case "observe":
		return UnavoidabilityObserve, true
	case "enforce":
		return UnavoidabilityEnforce, true
	default:
		return UnavoidabilityOff, false
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/db/service/ -run TestUnavoidability -v`
Expected: PASS for both subtests.

- [ ] **Step 5: Write the failing test for `RuleSet.Unavoidability()` decode**

Add to `internal/db/policy/decode_test.go`:

```go
func TestDecode_PoliciesDB_Unavoidability(t *testing.T) {
	tests := []struct {
		name string
		yaml string
		want service.Unavoidability
	}{
		{
			name: "missing block defaults to off",
			yaml: `version: 1
name: test
`,
			want: service.UnavoidabilityOff,
		},
		{
			name: "explicit off",
			yaml: `version: 1
name: test
policies:
  db:
    unavoidability: off
`,
			want: service.UnavoidabilityOff,
		},
		{
			name: "observe",
			yaml: `version: 1
name: test
policies:
  db:
    unavoidability: observe
`,
			want: service.UnavoidabilityObserve,
		},
		{
			name: "enforce",
			yaml: `version: 1
name: test
policies:
  db:
    unavoidability: enforce
`,
			want: service.UnavoidabilityEnforce,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rp, err := rootpolicy.LoadFromBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			rs, _, err := Decode(rp)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if got := rs.Unavoidability(); got != tc.want {
				t.Errorf("Unavoidability() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDecode_PoliciesDB_Unavoidability_Unknown(t *testing.T) {
	yaml := `version: 1
name: test
policies:
  db:
    unavoidability: bogus
`
	rp, err := rootpolicy.LoadFromBytes([]byte(yaml))
	if err != nil {
		t.Fatalf("LoadFromBytes: %v", err)
	}
	if _, _, err := Decode(rp); err == nil {
		t.Fatal("Decode: expected error for unknown unavoidability value, got nil")
	}
}
```

The `service` import is `"github.com/agentsh/agentsh/internal/db/service"`. The test file already imports `rootpolicy "github.com/agentsh/agentsh/internal/policy"` from earlier tests (verify before adding).

- [ ] **Step 6: Run test to verify it fails**

Run: `go test ./internal/db/policy/ -run TestDecode_PoliciesDB_Unavoidability -v`
Expected: FAIL with "rs.Unavoidability undefined" / "Decode unknown field unavoidability".

- [ ] **Step 7: Extend `internal/db/policy/decode.go` to decode the field**

Find the `redactionYAML` struct (around line 111) and extend it:

```go
type redactionYAML struct {
	LogStatements                 string `yaml:"log_statements,omitempty"`
	ApprovalStatementPreview      string `yaml:"approval_statement_preview,omitempty"`
	ApprovalStatementPreviewChars int    `yaml:"approval_statement_preview_chars,omitempty"`
	Unavoidability                string `yaml:"unavoidability,omitempty"`
}
```

Add a new helper just below `decodeRedaction`:

```go
// decodeUnavoidability reads policies.db.unavoidability. Default: UnavoidabilityOff.
// Unknown values are an error.
func decodeUnavoidability(p *rootpolicy.Policy) (service.Unavoidability, error) {
	if p.Policies.IsZero() {
		return service.UnavoidabilityOff, nil
	}
	var w dbPoliciesWrapper
	if err := strictDecode(p.Policies, &w); err != nil {
		return service.UnavoidabilityOff, fmt.Errorf("decode policies.db: %w", err)
	}
	if w.DB.Unavoidability == "" {
		return service.UnavoidabilityOff, nil
	}
	u, ok := service.ParseUnavoidability(w.DB.Unavoidability)
	if !ok {
		return service.UnavoidabilityOff, fmt.Errorf("unknown policies.db.unavoidability: %q", w.DB.Unavoidability)
	}
	return u, nil
}
```

Add the import:

```go
"github.com/agentsh/agentsh/internal/db/service"
```

Find `Decode` in the same file. Locate the call to `decodeRedaction` and add a sibling call to `decodeUnavoidability`. Wire its result into the `RuleSet` value being constructed (next step).

- [ ] **Step 8: Add `Unavoidability` field + accessor to `RuleSet`**

In `internal/db/policy/types.go`, extend the `RuleSet` struct. After the existing `redaction RedactionConfig` field add:

```go
unavoidability service.Unavoidability
```

Add the import:

```go
"github.com/agentsh/agentsh/internal/db/service"
```

Add the accessor below the existing `Service(...)` method:

```go
// Unavoidability returns the policies.db.unavoidability mode. Returns
// UnavoidabilityOff when rs is nil so startup code holding a not-yet-loaded
// *RuleSet does not panic.
func (rs *RuleSet) Unavoidability() service.Unavoidability {
	if rs == nil {
		return service.UnavoidabilityOff
	}
	return rs.unavoidability
}
```

Then in `internal/db/policy/decode.go`'s `Decode` function, plumb `decodeUnavoidability`'s result into the `RuleSet` being returned. The construction site (search for `redaction:` in the file) should now also set `unavoidability:`.

- [ ] **Step 9: Run all `internal/db/policy` tests**

Run: `go test ./internal/db/policy/... -v`
Expected: all pass, including the new ones.

- [ ] **Step 10: Commit**

```bash
git add internal/db/service/flag.go internal/db/service/flag_test.go \
        internal/db/policy/decode.go internal/db/policy/types.go \
        internal/db/policy/decode_test.go
git commit -m "$(cat <<'EOF'
db: add Unavoidability flag and policies.db.unavoidability decode

Plan 04a preflight. Adds internal/db/service.Unavoidability enum
(off/observe/enforce; default off) and decodes policies.db.unavoidability
into RuleSet.Unavoidability() so the proxy can gate listener bind.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 2: Validate.go extension — passthrough-invisible-fields rejection

**Why:** Spec §13.2 states `db_user`, `database`, `application_name` are not visible under `tls_mode: passthrough`. A connection rule under a passthrough service that matches one of those fields can never fire. We catch that at config-load with a clear error rather than silently misbehaving at runtime.

**Files:**
- Modify: `internal/db/policy/validate.go`
- Modify: `internal/db/policy/validate_test.go`

- [ ] **Step 1: Read the existing `validate.go` to find the connection-rule validator**

Run: `grep -n "ConnectionRule\|connection_rule\|validateConn" internal/db/policy/validate.go | head -20`
Identify the per-rule validation function (likely `validateConnectionRule` or similar).

- [ ] **Step 2: Write the failing test**

Add to `internal/db/policy/validate_test.go` a new test:

```go
func TestValidate_PassthroughInvisibleFieldRule(t *testing.T) {
	tests := []struct {
		name      string
		yaml      string
		wantError bool
	}{
		{
			name: "db_user under passthrough rejected",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    db_user: ["admin"]
    decision: deny
`,
			wantError: true,
		},
		{
			name: "database under passthrough rejected",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    database: prod
    decision: deny
`,
			wantError: true,
		},
		{
			name: "application_name under passthrough rejected",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    application_name: psql
    decision: deny
`,
			wantError: true,
		},
		{
			name: "client_identity under passthrough is allowed (visible pre-handshake)",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: passthrough
database_connection_rules:
  - name: r1
    db_service: appdb
    client_identity: agent
    decision: deny
`,
			wantError: false,
		},
		{
			name: "db_user under terminate_reissue is allowed",
			yaml: `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: r1
    db_service: appdb
    db_user: ["admin"]
    decision: deny
`,
			wantError: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rp, err := rootpolicy.LoadFromBytes([]byte(tc.yaml))
			if err != nil {
				t.Fatalf("LoadFromBytes: %v", err)
			}
			_, _, err = Decode(rp)
			gotErr := err != nil
			if gotErr != tc.wantError {
				t.Fatalf("Decode error = %v, wantError = %v", err, tc.wantError)
			}
		})
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/db/policy/ -run TestValidate_PassthroughInvisibleFieldRule -v`
Expected: FAIL — first three subtests pass without error currently.

- [ ] **Step 4: Implement the validation in `internal/db/policy/validate.go`**

Locate the connection-rule validator and add a service-aware check. Sketch (adapt to the file's existing style):

```go
// validateConnectionRuleVsService returns a non-nil error if the rule
// matches a field that is invisible under the service's tls_mode.
// Per spec §13.2: db_user, database, application_name are invisible under
// tls_mode: passthrough. client_identity and SNI are visible.
func validateConnectionRuleVsService(rule ConnectionRule, svc DBService) error {
	if svc.TLSMode != "passthrough" {
		return nil
	}
	if len(rule.DBUser) > 0 {
		return fmt.Errorf("connection_rule %q: db_user match is invisible under tls_mode: passthrough", rule.Name)
	}
	if rule.Database != "" {
		return fmt.Errorf("connection_rule %q: database match is invisible under tls_mode: passthrough", rule.Name)
	}
	if rule.ApplicationName != "" {
		return fmt.Errorf("connection_rule %q: application_name match is invisible under tls_mode: passthrough", rule.Name)
	}
	return nil
}
```

Wire this into the existing connection-rule validation loop (find where each `ConnectionRule` is validated and a `DBService` is in scope; if it is not, plumb the service map through). The error should bubble up through `Decode` so the test passes.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/policy/ -run TestValidate_PassthroughInvisibleFieldRule -v`
Expected: PASS for all five subtests.

- [ ] **Step 6: Run all policy tests to verify no regressions**

Run: `go test ./internal/db/policy/... -v`
Expected: all pass.

- [ ] **Step 7: Commit**

```bash
git add internal/db/policy/validate.go internal/db/policy/validate_test.go
git commit -m "$(cat <<'EOF'
db: reject passthrough-invisible-field rules under tls_mode: passthrough

Spec §13.2: db_user, database, application_name are not visible under
tls_mode: passthrough. Connection rules referencing them under passthrough
services can never fire; reject at config-load with a clear error.
client_identity remains valid (visible pre-handshake).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 3: `events.Sink` interface, `NopSink`, `SyncSink`, and `LifecycleEvent`

**Why:** Plan 04a's listener-auth path needs to emit `db_listener_auth_fail` events. We declare the proxy's emission interface here so 04a/04b/04c all consume the same surface. The test fake `SyncSink` is the in-memory event store unit tests assert against. `LifecycleEvent` carries connection-lifecycle events (listener-auth-fail, handshake-fail in 04b, degraded-visibility in 04b, etc.) — separate from the per-statement `DBEvent` because the schema is much smaller.

**Files:**
- Create: `internal/db/events/sink.go`
- Create: `internal/db/events/sink_test.go`
- Create: `internal/db/events/lifecycle.go`
- Create: `internal/db/events/lifecycle_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/events/sink_test.go`:

```go
package events

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

func TestNopSink_EmitNeverFails(t *testing.T) {
	s := NopSink{}
	if err := s.EmitStatement(context.Background(), DBEvent{}); err != nil {
		t.Fatalf("EmitStatement: %v", err)
	}
	if err := s.EmitLifecycle(context.Background(), LifecycleEvent{}); err != nil {
		t.Fatalf("EmitLifecycle: %v", err)
	}
}

func TestSyncSink_DrainReturnsEventsInOrder(t *testing.T) {
	s := &SyncSink{}
	for i := 0; i < 3; i++ {
		if err := s.EmitStatement(context.Background(), DBEvent{EventID: string(rune('A' + i))}); err != nil {
			t.Fatalf("EmitStatement: %v", err)
		}
	}
	if err := s.EmitLifecycle(context.Background(), LifecycleEvent{Kind: "db_listener_auth_fail"}); err != nil {
		t.Fatalf("EmitLifecycle: %v", err)
	}
	stmts := s.DrainStatements()
	if len(stmts) != 3 || stmts[0].EventID != "A" || stmts[2].EventID != "C" {
		t.Fatalf("DrainStatements = %+v", stmts)
	}
	if got := s.DrainStatements(); len(got) != 0 {
		t.Fatalf("DrainStatements after drain = %+v, want empty", got)
	}
	lcs := s.DrainLifecycle()
	if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
		t.Fatalf("DrainLifecycle = %+v", lcs)
	}
}

func TestSyncSink_ConcurrentEmitIsSafe(t *testing.T) {
	s := &SyncSink{}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = s.EmitStatement(context.Background(), DBEvent{Timestamp: time.Now()})
		}()
	}
	wg.Wait()
	if got := len(s.DrainStatements()); got != 100 {
		t.Fatalf("DrainStatements len = %d, want 100", got)
	}
}

func TestSyncSink_ContextCancelled_ReturnsError(t *testing.T) {
	s := &SyncSink{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := s.EmitStatement(ctx, DBEvent{})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("EmitStatement err = %v, want context.Canceled", err)
	}
}
```

Create `internal/db/events/lifecycle_test.go`:

```go
package events

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLifecycleEvent_JSONRoundTrip(t *testing.T) {
	in := LifecycleEvent{
		EventID:        "01HJ...",
		SessionID:      "sess-1",
		Timestamp:      time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService:      "appdb",
		ClientIdentity: "uid:1000",
		Kind:           "db_listener_auth_fail",
		Reason:         "uid_mismatch",
		PeerUID:        2000,
		PeerPID:        12345,
	}
	bs, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var out LifecycleEvent
	if err := json.Unmarshal(bs, &out); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if out != in {
		t.Fatalf("round-trip mismatch:\n got %+v\nwant %+v", out, in)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/events/ -run "TestNopSink|TestSyncSink|TestLifecycleEvent" -v`
Expected: FAIL with "undefined: NopSink" / "undefined: SyncSink" / "undefined: LifecycleEvent".

- [ ] **Step 3: Implement `internal/db/events/sink.go`**

```go
package events

import (
	"context"
	"sync"
)

// Sink is the event emission surface for the DB proxy. Implementations may
// fan out to a real audit pipeline (production), to nothing (tests that do
// not care about events), or to an in-memory buffer (unit tests asserting
// emission). Sinks must be safe for concurrent use.
//
// Errors from Emit* are advisory: the proxy logs them at warn but does not
// fail the connection. Spec §8 is silent on emission durability; Plan 04a
// adopts best-effort semantics, leaving durability concerns to the audit-
// pipeline implementation a later plan provides.
type Sink interface {
	EmitStatement(ctx context.Context, ev DBEvent) error
	EmitLifecycle(ctx context.Context, ev LifecycleEvent) error
}

// NopSink discards every event. Useful when the proxy is wired into a
// runtime that does not care about audit (tests of unrelated code).
type NopSink struct{}

func (NopSink) EmitStatement(context.Context, DBEvent) error      { return nil }
func (NopSink) EmitLifecycle(context.Context, LifecycleEvent) error { return nil }

// SyncSink buffers every emitted event in memory. Tests call DrainStatements
// or DrainLifecycle to inspect what was emitted. Concurrent use is safe.
//
// Drain* returns the buffered events in emission order and resets the buffer.
type SyncSink struct {
	mu        sync.Mutex
	stmt      []DBEvent
	lifecycle []LifecycleEvent
}

func (s *SyncSink) EmitStatement(ctx context.Context, ev DBEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.stmt = append(s.stmt, ev)
	s.mu.Unlock()
	return nil
}

func (s *SyncSink) EmitLifecycle(ctx context.Context, ev LifecycleEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.mu.Lock()
	s.lifecycle = append(s.lifecycle, ev)
	s.mu.Unlock()
	return nil
}

func (s *SyncSink) DrainStatements() []DBEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.stmt
	s.stmt = nil
	return out
}

func (s *SyncSink) DrainLifecycle() []LifecycleEvent {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.lifecycle
	s.lifecycle = nil
	return out
}
```

- [ ] **Step 4: Implement `internal/db/events/lifecycle.go`**

```go
package events

import "time"

// LifecycleEvent is a non-statement DB-proxy event: listener-auth failures,
// handshake failures (Plan 04b), degraded-visibility warnings (Plan 04b).
// Carries less data than DBEvent because there is no statement to redact.
//
// Kind is a small enumerated string ("db_listener_auth_fail",
// "db_handshake_fail", "degraded_visibility_warning"); each plan that emits
// a new kind is responsible for documenting the value in plan release notes.
type LifecycleEvent struct {
	EventID        string    `json:"event_id"`
	SessionID      string    `json:"session_id,omitempty"`
	Timestamp      time.Time `json:"ts"`
	DBService      string    `json:"db_service,omitempty"`
	ClientIdentity string    `json:"client_identity,omitempty"`

	Kind   string `json:"kind"`
	Reason string `json:"reason,omitempty"`

	// Listener-auth specific (Plan 04a). Zero when not applicable.
	PeerUID uint32 `json:"peer_uid,omitempty"`
	PeerPID int32  `json:"peer_pid,omitempty"`

	// Handshake/error specific (Plan 04b). Zero when not applicable.
	ErrorCode string `json:"error_code,omitempty"`
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/db/events/ -v`
Expected: PASS for all (including any pre-existing `event_test.go` tests).

- [ ] **Step 6: Commit**

```bash
git add internal/db/events/sink.go internal/db/events/sink_test.go \
        internal/db/events/lifecycle.go internal/db/events/lifecycle_test.go
git commit -m "$(cat <<'EOF'
db/events: add Sink interface, NopSink, SyncSink, LifecycleEvent

Plan 04a's listener-auth path needs to emit db_listener_auth_fail events.
Declare the proxy's emission interface here so 04a/04b/04c all consume
the same surface. SyncSink is the in-memory test fake. LifecycleEvent
carries connection-lifecycle events (listener-auth, handshake fail,
degraded-visibility); separate from per-statement DBEvent.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 4: Package skeleton — `Server` type, sentinel short-circuit, non-Linux stub

**Why:** Establishes the `internal/db/proxy/postgres` package surface (`Config`, `Server`, `New`, `Start`, `Shutdown`) without any protocol code. The sentinel short-circuit (when `Unavoidability == off`) means callers never special-case the flag. The non-Linux stub keeps `GOOS=windows go build ./...` green per CLAUDE.md.

**Files:**
- Create: `internal/db/proxy/postgres/server.go` (`//go:build linux`)
- Create: `internal/db/proxy/postgres/stub_other.go` (`//go:build !linux`)
- Create: `internal/db/proxy/postgres/server_test.go` (`//go:build linux`)

- [ ] **Step 1: Write the failing test for the public surface and sentinel**

Create `internal/db/proxy/postgres/server_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestServer_New_ZeroConfigRejected(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New(Config{}): want error, got nil")
	}
}

func TestServer_OffMode_StartIsNoop(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityOff,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil server")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start (off mode): %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown (off mode): %v", err)
	}
}

func TestServer_ObserveMode_RequiresAtLeastOneService(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (observe, no services): want error, got nil")
	}
}

func TestServer_New_MissingSink(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Services:       []policy.DBService{{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "db.internal:5432", TLSMode: "terminate_reissue"}},
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (no sink): want error, got nil")
	}
}

// testWriter wires slog output into t.Log so tests preserve context on failure.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }
```

Note: `policy.DBService` is the type already shipped in Plan 02. The `Listener` shape is owned by `internal/db/service.Service`, but for Plan 04a the proxy receives services + listen paths via a flatter shape. Settle the exact `Config.Services` element type in the implementation step.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: FAIL with "no Go files in ..." or "undefined: New".

- [ ] **Step 3: Implement `internal/db/proxy/postgres/server.go`**

```go
//go:build linux

// Package postgres implements the AgentSH PostgreSQL proxy per
// docs/agentsh-db-access-spec.md §11–§14 and the macro design at
// docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md.
//
// Plan 04a ships only the listener skeleton: bind Unix sockets per declared
// db_service, peer-authenticate via SO_PEERCRED + UID-equality, accept and
// immediately close. Plan 04b adds the handshake / TLS layer; Plan 04c adds
// Simple Query classification and DBEvent emission.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// Service is the proxy-internal flattened view of one db_service. The proxy
// needs the listener path (from internal/db/service.Listener) and the
// upstream + tls_mode metadata (from internal/db/policy.DBService). Callers
// in internal/api are responsible for joining them.
type Service struct {
	Name     string                  // matches policy.DBService.Name
	Family   string                  // "postgres"
	Dialect  string                  // postgres / aurora_postgres / cockroachdb / redshift
	Upstream string                  // host:port
	TLSMode  string                  // terminate_reissue / passthrough / terminate_plaintext_upstream
	Listen   ServiceListener         // unix-socket path or tcp host:port
	Service  policy.DBService        // full DBService for downstream evaluation
}

// ServiceListener mirrors internal/db/service.Listener but is the package-
// local concrete type the proxy operates on. Plan 04a only binds Kind=="unix".
type ServiceListener struct {
	Kind string // "unix" or "tcp"
	Path string // when Kind == "unix"
	Host string // when Kind == "tcp"
	Port int    // when Kind == "tcp"
}

// Config captures the supervisor-supplied parameters for a Server. All
// fields are required when Unavoidability != UnavoidabilityOff except
// Logger (defaults to slog.Default) and the Plan 04b/04c-only fields
// (Classifier, Policy) which Plan 04a accepts but does not use.
type Config struct {
	Unavoidability service.Unavoidability
	Services       []Service
	StateDir       string
	Sink           events.Sink
	Logger         *slog.Logger
}

// Server runs the AgentSH PostgreSQL proxy listeners.
type Server struct {
	cfg       Config
	logger    *slog.Logger
	sentinel  bool // true when Unavoidability == off; Start/Shutdown are no-ops
	mu        sync.Mutex
	started   bool
	shutdown  bool
}

// New validates cfg and returns a *Server. When cfg.Unavoidability ==
// UnavoidabilityOff, returns a sentinel server whose Start/Shutdown are
// no-ops. Returns an error when required fields are missing.
func New(cfg Config) (*Server, error) {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Unavoidability == service.UnavoidabilityOff {
		return &Server{cfg: cfg, logger: cfg.Logger, sentinel: true}, nil
	}
	if cfg.StateDir == "" {
		return nil, errors.New("postgres.New: StateDir is required when Unavoidability != off")
	}
	if cfg.Sink == nil {
		return nil, errors.New("postgres.New: Sink is required when Unavoidability != off")
	}
	if len(cfg.Services) == 0 {
		return nil, errors.New("postgres.New: at least one Service is required when Unavoidability != off")
	}
	for i, svc := range cfg.Services {
		if svc.Name == "" {
			return nil, fmt.Errorf("postgres.New: services[%d].Name is empty", i)
		}
		if svc.Listen.Kind != "unix" && svc.Listen.Kind != "tcp" {
			return nil, fmt.Errorf("postgres.New: services[%d].Listen.Kind = %q; want unix or tcp", i, svc.Listen.Kind)
		}
		if svc.Listen.Kind == "unix" && svc.Listen.Path == "" {
			return nil, fmt.Errorf("postgres.New: services[%d].Listen.Path is empty for unix listener", i)
		}
	}
	return &Server{cfg: cfg, logger: cfg.Logger}, nil
}

// Start binds listeners and runs accept loops until ctx is cancelled.
// Returns nil for sentinel servers. Returns the first listener-bind error;
// subsequent listeners are torn down.
//
// Plan 04a: connection handler is a no-op that closes the conn after the
// peercred check. Plan 04b plugs in the real handshake handler.
func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("postgres.Server: Start called twice")
	}
	s.started = true
	s.mu.Unlock()

	if s.sentinel {
		s.logger.Info("postgres.Server: sentinel mode (Unavoidability == off); not binding listeners")
		return nil
	}

	// Listener bind + accept loop is implemented in Task 5.
	return errors.New("postgres.Server.Start: listener bind not yet implemented (Plan 04a Task 5)")
}

// Shutdown stops accept loops, waits for in-flight conns to close, and
// unlinks Unix sockets. Returns nil for sentinel servers.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		return nil
	}
	s.shutdown = true
	if s.sentinel {
		return nil
	}
	// Implemented in Task 5.
	return nil
}
```

- [ ] **Step 4: Implement `internal/db/proxy/postgres/stub_other.go`**

```go
//go:build !linux

// Package postgres provides a non-Linux stub so cross-compilation
// (GOOS=windows go build ./...) stays green. The proxy is Linux-only;
// callers on other platforms get errors.ErrUnsupported when starting it.
package postgres

import (
	"context"
	"errors"
	"log/slog"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

type Service struct {
	Name     string
	Family   string
	Dialect  string
	Upstream string
	TLSMode  string
	Listen   ServiceListener
	Service  policy.DBService
}

type ServiceListener struct {
	Kind string
	Path string
	Host string
	Port int
}

type Config struct {
	Unavoidability service.Unavoidability
	Services       []Service
	StateDir       string
	Sink           events.Sink
	Logger         *slog.Logger
}

type Server struct {
	sentinel bool
}

// New on non-Linux always succeeds and returns a sentinel that refuses to
// start unless Unavoidability == off (in which case Start is a no-op too).
func New(cfg Config) (*Server, error) {
	return &Server{sentinel: cfg.Unavoidability == service.UnavoidabilityOff}, nil
}

func (s *Server) Start(ctx context.Context) error {
	if s.sentinel {
		return nil
	}
	return errors.ErrUnsupported
}

func (s *Server) Shutdown(ctx context.Context) error { return nil }
```

- [ ] **Step 5: Run tests to verify only the unimplemented-bind test path fails for the right reason**

Run: `go test ./internal/db/proxy/postgres/ -run "TestServer_New|TestServer_OffMode" -v`
Expected: PASS for `TestServer_New_ZeroConfigRejected`, `TestServer_OffMode_StartIsNoop`, `TestServer_ObserveMode_RequiresAtLeastOneService`, `TestServer_New_MissingSink`. (The full Start/Shutdown test arrives in Task 5.)

- [ ] **Step 6: Verify cross-compile**

Run: `GOOS=windows go build ./internal/db/proxy/postgres/...`
Expected: build success.

Run: `GOOS=darwin go build ./internal/db/proxy/postgres/...`
Expected: build success.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/server.go \
        internal/db/proxy/postgres/stub_other.go \
        internal/db/proxy/postgres/server_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: package skeleton with sentinel short-circuit

Plan 04a Task 4. Establishes Config / Server / New / Start / Shutdown
public surface plus a non-Linux stub for cross-compilation. Sentinel
mode (Unavoidability == off) is a no-op so callers do not special-case
the flag. Listener bind arrives in Task 5.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 5: Server lifecycle — bind, accept loop, Shutdown drain

**Why:** Implements `Start` / `Shutdown` for the non-sentinel case. Listener bind, accept loop in its own goroutine per service, graceful drain on cancel, Unix-socket unlink on close. The connection handler is still a no-op that closes the conn — Task 6 plugs in peercred auth, Plan 04b plugs in handshake.

**Files:**
- Modify: `internal/db/proxy/postgres/server.go`
- Modify: `internal/db/proxy/postgres/server_test.go`
- Create: `internal/db/proxy/postgres/listener_unix.go` (`//go:build linux`)

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/server_test.go`:

```go
func TestServer_StartShutdown_BindsAndUnlinksUnixSocket(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
		}},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startErr := make(chan error, 1)
	go func() { startErr <- s.Start(ctx) }()

	// Wait until the socket exists. Start spawns goroutines synchronously
	// after bind, so a short poll loop is sufficient.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(sockPath); err == nil && fi.Mode()&os.ModeSocket != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if fi, err := os.Stat(sockPath); err != nil || fi.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket %q not bound: stat=%v, err=%v", sockPath, fi, err)
	}
	if fi, _ := os.Stat(sockPath); fi.Mode()&0777 != 0700 {
		t.Errorf("socket %q perms = %#o, want 0700", sockPath, fi.Mode()&0777)
	}

	// A Unix-socket dial should succeed and immediately see EOF (handler is no-op).
	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	buf := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Read(buf); err == nil || (err.Error() != "EOF" && !errors.Is(err, io.EOF) && !os.IsTimeout(err)) {
		t.Fatalf("Read after dial: err=%v, want EOF or close", err)
	}
	conn.Close()

	// Cancel context and assert Shutdown completes and unlinks the socket.
	cancel()
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	if err := <-startErr; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Start returned: %v", err)
	}
	if _, err := os.Stat(sockPath); !os.IsNotExist(err) {
		t.Fatalf("socket %q still present after Shutdown: stat err=%v", sockPath, err)
	}
}

func TestServer_StartTwice_ReturnsError(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Services: []Service{{
			Name:     "appdb",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb"},
			TLSMode:  "terminate_reissue",
		}},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	time.Sleep(50 * time.Millisecond)
	if err := s.Start(ctx); err == nil {
		t.Fatal("second Start: want error, got nil")
	}
}
```

Add the necessary imports:

```go
"errors"
"io"
"net"
"os"
"path/filepath"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run "TestServer_StartShutdown|TestServer_StartTwice" -v`
Expected: FAIL — `Start` returns the "not yet implemented" sentinel error.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/listener_unix.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
)

// unixListener wraps a net.UnixListener with the Plan 04a setup contract:
// remove stale socket → bind → chmod 0700. On Close, unlinks the socket.
type unixListener struct {
	path string
	ln   *net.UnixListener
}

func bindUnixListener(path string) (*unixListener, error) {
	parent := filepath.Dir(path)
	fi, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat listener parent dir %q: %w", parent, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("listener parent %q is not a directory", parent)
	}
	// Remove stale socket from a prior crash. Existing non-socket file is a
	// hard error to avoid clobbering operator data.
	if existing, err := os.Stat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("listener path %q exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat listener path %q: %w", path, err)
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, fmt.Errorf("chmod 0700 %q: %w", path, err)
	}
	return &unixListener{path: path, ln: ln}, nil
}

func (l *unixListener) Accept(ctx context.Context) (net.Conn, error) {
	// Plumb ctx cancel into Accept by setting a deadline that is bumped
	// forward periodically. Simpler than juggling a goroutine + close.
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		// 250ms cancellation latency is fine for shutdown.
		_ = l.ln.SetDeadline(timeNow().Add(250 * time.Millisecond))
		conn, err := l.ln.AcceptUnix()
		if err == nil {
			return conn, nil
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		return nil, err
	}
}

func (l *unixListener) Close() error {
	err := l.ln.Close()
	if rmErr := os.Remove(l.path); rmErr != nil && !os.IsNotExist(rmErr) {
		if err == nil {
			err = fmt.Errorf("remove %q: %w", l.path, rmErr)
		}
	}
	return err
}

// activeConns is a small concurrent set of in-flight conns the Server cancels
// at Shutdown. The set is keyed by conn pointer; conn handlers Add themselves
// at start and Remove themselves on return.
type activeConns struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func newActiveConns() *activeConns { return &activeConns{m: make(map[net.Conn]struct{})} }

func (a *activeConns) Add(c net.Conn) {
	a.mu.Lock()
	a.m[c] = struct{}{}
	a.mu.Unlock()
}

func (a *activeConns) Remove(c net.Conn) {
	a.mu.Lock()
	delete(a.m, c)
	a.mu.Unlock()
}

func (a *activeConns) CloseAll() {
	a.mu.Lock()
	for c := range a.m {
		_ = c.Close()
	}
	a.mu.Unlock()
}

func (a *activeConns) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.m)
}
```

Add the `time` import and a small `timeNow` shim at the top of the file:

```go
import (
	"time"
)

var timeNow = time.Now // overridable in tests if needed
```

- [ ] **Step 4: Replace `Server.Start` and `Server.Shutdown` in `server.go`**

Replace the Plan-04a-Task-4 stubs with full implementations:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// (Service, ServiceListener, Config types unchanged from Task 4.)

type Server struct {
	cfg      Config
	logger   *slog.Logger
	sentinel bool

	mu       sync.Mutex
	started  bool
	shutdown bool

	// Populated on Start. Owned by the goroutine that called Start.
	cancel    context.CancelFunc
	eg        *errgroup.Group
	listeners []*unixListener
	conns     *activeConns
}

func (s *Server) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errors.New("postgres.Server: Start called twice")
	}
	s.started = true
	s.mu.Unlock()

	if s.sentinel {
		s.logger.Info("postgres.Server: sentinel mode (Unavoidability == off); not binding listeners")
		<-ctx.Done()
		return ctx.Err()
	}

	// Bind all listeners up-front so a partial failure tears the rest down.
	var bound []*unixListener
	for _, svc := range s.cfg.Services {
		if svc.Listen.Kind != "unix" {
			s.logger.Warn("postgres.Server: skipping non-unix listener (Plan 04a binds unix only)",
				"service", svc.Name, "kind", svc.Listen.Kind)
			continue
		}
		ln, err := bindUnixListener(svc.Listen.Path)
		if err != nil {
			for _, b := range bound {
				_ = b.Close()
			}
			return fmt.Errorf("bind listener for service %q: %w", svc.Name, err)
		}
		bound = append(bound, ln)
		s.logger.Info("postgres.Server: bound listener", "service", svc.Name, "path", svc.Listen.Path)
	}

	runCtx, cancel := context.WithCancel(ctx)
	s.mu.Lock()
	s.cancel = cancel
	s.listeners = bound
	s.conns = newActiveConns()
	s.eg, _ = errgroup.WithContext(runCtx)
	s.mu.Unlock()

	for i, svc := range s.cfg.Services {
		if svc.Listen.Kind != "unix" {
			continue
		}
		ln := bound[i] // index alignment: only unix listeners go into bound
		svcCopy := svc
		s.eg.Go(func() error {
			return s.acceptLoop(runCtx, svcCopy, ln)
		})
	}

	err := s.eg.Wait()
	if errors.Is(err, context.Canceled) {
		err = nil
	}
	return err
}

// Bound listeners are aligned with cfg.Services entries that have Kind=="unix".
// The index map above is wrong — replace with: keep a per-service ln pointer.
// (See Step 5: refactor the bound slice into a per-service map.)
```

The index-alignment shortcut above is **wrong** when some services have non-unix listeners. Replace `bound []*unixListener` with `bound map[string]*unixListener` keyed by service name; index the per-service goroutine by name. Update the code accordingly.

```go
type Server struct {
	// ... same as above except:
	listeners map[string]*unixListener
}

// In Start:
bound := make(map[string]*unixListener, len(s.cfg.Services))
for _, svc := range s.cfg.Services {
	if svc.Listen.Kind != "unix" {
		s.logger.Warn(...)
		continue
	}
	ln, err := bindUnixListener(svc.Listen.Path)
	if err != nil {
		for _, b := range bound { _ = b.Close() }
		return fmt.Errorf("bind listener for service %q: %w", svc.Name, err)
	}
	bound[svc.Name] = ln
}
// ...
s.listeners = bound
// ...
for _, svc := range s.cfg.Services {
	ln, ok := bound[svc.Name]
	if !ok { continue }
	svcCopy, lnCopy := svc, ln
	s.eg.Go(func() error {
		return s.acceptLoop(runCtx, svcCopy, lnCopy)
	})
}
```

- [ ] **Step 5: Implement `acceptLoop` and the no-op handler in `server.go`**

```go
func (s *Server) acceptLoop(ctx context.Context, svc Service, ln *unixListener) error {
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.logger.Warn("postgres.Server: accept error", "service", svc.Name, "err", err)
			return err
		}
		s.conns.Add(conn)
		go func() {
			defer s.conns.Remove(conn)
			defer conn.Close()
			s.handleConn(ctx, svc, conn)
		}()
	}
}

// handleConn is the per-connection handler. Plan 04a: peercred check (Task 6),
// then close. Plan 04b plugs in the real handshake.
func (s *Server) handleConn(ctx context.Context, svc Service, conn net.Conn) {
	// Task 6 inserts the peercred check here; for Task 5 the body is empty
	// (and the conn is closed by the deferred Close in acceptLoop).
}
```

- [ ] **Step 6: Implement `Server.Shutdown`**

```go
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.shutdown {
		s.mu.Unlock()
		return nil
	}
	s.shutdown = true
	cancel := s.cancel
	listeners := s.listeners
	conns := s.conns
	eg := s.eg
	s.mu.Unlock()

	if s.sentinel || cancel == nil {
		return nil
	}
	cancel()
	for _, ln := range listeners {
		_ = ln.Close()
	}
	if conns != nil {
		conns.CloseAll()
	}
	if eg != nil {
		// eg.Wait already happens in Start; here we just respect the caller's ctx.
		done := make(chan error, 1)
		go func() { done <- eg.Wait() }()
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS for all tests including the new bind/unbind and double-Start cases.

- [ ] **Step 8: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 9: Commit**

```bash
git add internal/db/proxy/postgres/server.go \
        internal/db/proxy/postgres/listener_unix.go \
        internal/db/proxy/postgres/server_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: bind, accept loop, graceful Shutdown

Plan 04a Task 5. Server.Start binds Unix listeners per declared service
(0700 perms; stale socket removed before bind), runs an accept loop per
listener under errgroup, and tracks in-flight conns. Connection handler
is still a no-op that closes the conn (Task 6 adds peercred auth).
Shutdown cancels accept, closes listeners (unlinking socket files),
and closes in-flight conns within the caller's deadline.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 6: SO_PEERCRED + UID-equality listener auth

**Why:** Spec §12.5 requires the listener to verify peer identity. Plan 04a uses the simplest correct check: `getsockopt(SO_PEERCRED)` plus equality with the proxy's own uid. Plan 07 tightens this to SO_PEERCRED → SessionID via the ptrace registry. On mismatch the connection is closed silently and a `db_listener_auth_fail` lifecycle event is emitted.

**Files:**
- Create: `internal/db/proxy/postgres/peercred_linux.go` (`//go:build linux`)
- Create: `internal/db/proxy/postgres/peercred_linux_test.go` (`//go:build linux`)
- Modify: `internal/db/proxy/postgres/server.go` (wire peercred into `handleConn`)

- [ ] **Step 1: Write the failing test**

Create `internal/db/proxy/postgres/peercred_linux_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestReadPeerCredUID_FromSocketpair(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		t.Fatalf("Socketpair: %v", err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])

	// Wrap fd[0] as a net.UnixConn so we can call our helper on it.
	f := os.NewFile(uintptr(fds[0]), "peer")
	conn, err := net.FileConn(f)
	if err != nil {
		t.Fatalf("FileConn: %v", err)
	}
	f.Close() // FileConn dup'd the fd
	defer conn.Close()

	uc, ok := conn.(*net.UnixConn)
	if !ok {
		t.Fatalf("conn is %T, want *net.UnixConn", conn)
	}

	gotUID, gotPID, err := readPeerCred(uc)
	if err != nil {
		t.Fatalf("readPeerCred: %v", err)
	}
	if gotUID != uint32(os.Getuid()) {
		t.Errorf("readPeerCred uid = %d, want %d", gotUID, os.Getuid())
	}
	if gotPID != int32(os.Getpid()) {
		t.Errorf("readPeerCred pid = %d, want %d", gotPID, os.Getpid())
	}
}

func TestReadPeerCredUID_OnNonUnixConn_Errors(t *testing.T) {
	r, w := net.Pipe()
	defer r.Close()
	defer w.Close()
	if _, _, err := readPeerCred(r); err == nil {
		t.Fatal("readPeerCred(net.Pipe): want error, got nil")
	}
}

func TestServer_PeercredMismatch_ClosesAndEmitsLifecycle(t *testing.T) {
	// We cannot easily impersonate a different uid in unit tests; instead,
	// inject a checkUID function that always returns false. This exercises
	// the failure branch end-to-end.
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	sink := &events.SyncSink{}
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb"},
		}},
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Override the equality check for this test only.
	s.uidAllowed = func(uint32) bool { return false }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Start(ctx)
	waitForSocket(t, sockPath)

	conn, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer conn.Close()

	// Server should close the conn silently after peercred check.
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); !errors.Is(err, io.EOF) && !isClosedConnError(err) {
		t.Errorf("Read after peercred mismatch: err=%v, want EOF or closed-conn", err)
	}

	// Allow a brief moment for the lifecycle event to land.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if len(sink.DrainLifecycle()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Drain again to inspect (the prior loop may have drained on a hit).
	// Re-emit by triggering once more is overkill; instead, capture the
	// lifecycle slice on first non-empty Drain.
}

// helper: wait until socket file exists and is a socket
func waitForSocket(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if fi, err := os.Stat(path); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("socket %q never bound", path)
}

func isClosedConnError(err error) bool {
	return err != nil && (errors.Is(err, net.ErrClosed) || strings.Contains(err.Error(), "use of closed"))
}
```

The test shape above has a small issue (the second drain after the deadline loop is unsound). Replace the post-loop assertion with a single drained slice captured inside the loop:

```go
var lcs []events.LifecycleEvent
deadline := time.Now().Add(500 * time.Millisecond)
for time.Now().Before(deadline) {
    if got := sink.DrainLifecycle(); len(got) > 0 {
        lcs = got
        break
    }
    time.Sleep(10 * time.Millisecond)
}
if len(lcs) != 1 || lcs[0].Kind != "db_listener_auth_fail" {
    t.Fatalf("DrainLifecycle = %+v, want one db_listener_auth_fail", lcs)
}
if lcs[0].DBService != "appdb" {
    t.Errorf("DBService = %q, want appdb", lcs[0].DBService)
}
if lcs[0].PeerUID != uint32(os.Getuid()) {
    t.Errorf("PeerUID = %d, want %d", lcs[0].PeerUID, os.Getuid())
}
```

Also add the new `time`, `strings`, `io` imports if missing.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run "TestReadPeerCred|TestServer_Peercred" -v`
Expected: FAIL with "undefined: readPeerCred" / "s.uidAllowed undefined".

- [ ] **Step 3: Implement `internal/db/proxy/postgres/peercred_linux.go`**

```go
//go:build linux

package postgres

import (
	"errors"
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// readPeerCred returns the peer's uid and pid via SO_PEERCRED on a Unix
// socket connection. Returns an error if conn is not a *net.UnixConn or the
// getsockopt call fails.
//
// Spec §12.5: SO_PEERCRED is the listener-auth primitive in Plan 04a.
// Plan 07 hardens this to a SessionID resolution via the ptrace registry.
func readPeerCred(conn net.Conn) (uid uint32, pid int32, err error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, 0, fmt.Errorf("readPeerCred: conn is %T, want *net.UnixConn", conn)
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, 0, fmt.Errorf("readPeerCred: SyscallConn: %w", err)
	}
	var ucred *unix.Ucred
	var sysErr error
	ctrlErr := raw.Control(func(fd uintptr) {
		ucred, sysErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctrlErr != nil {
		return 0, 0, fmt.Errorf("readPeerCred: Control: %w", ctrlErr)
	}
	if sysErr != nil {
		return 0, 0, fmt.Errorf("readPeerCred: SO_PEERCRED: %w", sysErr)
	}
	if ucred == nil {
		return 0, 0, errors.New("readPeerCred: ucred is nil")
	}
	return ucred.Uid, ucred.Pid, nil
}
```

- [ ] **Step 4: Wire peercred into `handleConn`**

Modify `internal/db/proxy/postgres/server.go`:

Add `uidAllowed` to the `Server` struct (overrideable in tests):

```go
type Server struct {
	// ... existing fields ...
	uidAllowed func(uint32) bool // default: equality with os.Getuid()
}
```

In `New`, initialize `uidAllowed`:

```go
me := uint32(os.Getuid())
srv := &Server{
	cfg:        cfg,
	logger:     cfg.Logger,
	sentinel:   cfg.Unavoidability == service.UnavoidabilityOff,
	uidAllowed: func(u uint32) bool { return u == me },
}
return srv, nil
```

(Adjust the existing `New` body to use `srv` and the sentinel-short-circuit appropriately. Imports: add `os`.)

Replace `handleConn` with:

```go
func (s *Server) handleConn(ctx context.Context, svc Service, conn net.Conn) {
	uid, pid, err := readPeerCred(conn)
	if err != nil {
		s.logger.Warn("postgres.Server: peercred read failed; closing", "service", svc.Name, "err", err)
		s.emitListenerAuthFail(ctx, svc, 0, 0, "peercred_read_failed")
		return
	}
	if !s.uidAllowed(uid) {
		s.emitListenerAuthFail(ctx, svc, uid, pid, "uid_mismatch")
		return
	}
	// Plan 04a: peercred passed; close the conn (handshake lands in 04b).
	// The deferred Close in acceptLoop handles the actual close.
}

func (s *Server) emitListenerAuthFail(ctx context.Context, svc Service, uid uint32, pid int32, reason string) {
	if s.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:   newEventID(),
		Timestamp: timeNow(),
		DBService: svc.Name,
		Kind:      "db_listener_auth_fail",
		Reason:    reason,
		PeerUID:   uid,
		PeerPID:   pid,
	}
	if err := s.cfg.Sink.EmitLifecycle(ctx, ev); err != nil {
		s.logger.Warn("postgres.Server: sink emit failed", "kind", ev.Kind, "err", err)
	}
}
```

Add a small `newEventID` helper in a new `internal/db/proxy/postgres/eventid.go`:

```go
//go:build linux

package postgres

import "github.com/google/uuid"

// newEventID returns a UUIDv7 string for event correlation.
// Plan 04 spec §8: event_id is uuid-v7. uuid v1.6.0 ships v7 support.
func newEventID() string {
	id, err := uuid.NewV7()
	if err != nil {
		// NewV7 only fails if the random source fails; fall back to V4.
		return uuid.NewString()
	}
	return id.String()
}
```

(Verify `github.com/google/uuid` is already a direct dep — `go.mod` line 34 confirms `github.com/google/uuid v1.6.0`.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS for all tests.

- [ ] **Step 6: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/peercred_linux.go \
        internal/db/proxy/postgres/peercred_linux_test.go \
        internal/db/proxy/postgres/server.go \
        internal/db/proxy/postgres/eventid.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: SO_PEERCRED + UID-equality listener auth

Plan 04a Task 6. handleConn now reads SO_PEERCRED and compares the peer
uid to the proxy's own uid. Mismatch silently closes the conn and emits
a db_listener_auth_fail lifecycle event. uidAllowed is overrideable in
tests so the failure branch is exercised end-to-end without changing
process credentials.

Spec §12.5: this is the Plan 04a listener-auth primitive. Plan 07
hardens it to SessionID resolution via the ptrace registry.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 7: `internal/api` wiring — instantiate the proxy at startup

**Why:** The proxy is useless without something starting it. `internal/api` already owns subsystem boot and shutdown for the supervisor process; we add a small block that constructs the proxy `Server` from the loaded `RuleSet` + `db_services` and attaches `Shutdown` to the supervisor's lifecycle.

**Files:**
- Create: `internal/api/db_proxy.go` — proxy boot helper.
- Create: `internal/api/db_proxy_test.go` — exercises boot + shutdown wiring.
- Modify: `internal/server/server.go` — call `startDBProxy` after `api.NewApp` and register `Shutdown` into the existing `appCloser` defer chain (around line 507).

The boot site is `internal/server/server.go` (a `grep -n "api.NewApp" internal/server/server.go` confirms one hit). The DB proxy is process-global (not per-session), so it lives next to `app := api.NewApp(...)` rather than inside `internal/api/app.go`'s per-session paths.

- [ ] **Step 1: Read the existing supervisor boot site**

Run: `grep -n "api.NewApp\|appCloser" internal/server/server.go`
Identify line ~507 where `app := api.NewApp(...)` is called and the `appCloser` defer chain is established. The DB proxy boot block lands immediately after `app := api.NewApp(...)`. Read the surrounding 30 lines to confirm the policyLoader / engine / store names available in scope.

- [ ] **Step 2: Write the failing test**

Create `internal/api/db_proxy_test.go`:

```go
package api

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
)

func TestStartDBProxy_Off_NoListener(t *testing.T) {
	dir := t.TempDir()
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityOff,
		Services:       nil,
		StateDir:       dir,
		Sink:           &events.SyncSink{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDBProxy(ctx, deps)
	if err != nil {
		t.Fatalf("startDBProxy: %v", err)
	}
	if srv == nil {
		t.Fatal("startDBProxy returned nil")
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestStartDBProxy_Observe_BindsListener(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "appdb.sock")
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityObserve,
		Services: []dbProxyService{{
			Name:       "appdb",
			DBService:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
			ListenKind: "unix",
			ListenPath: sockPath,
		}},
		StateDir: dir,
		Sink:     &events.SyncSink{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDBProxy(ctx, deps)
	if err != nil {
		t.Fatalf("startDBProxy: %v", err)
	}
	defer srv.Shutdown(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener never bound at %q", sockPath)
}

func TestStartDBProxy_Observe_NoServices_Errors(t *testing.T) {
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityObserve,
		Services:       nil,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := startDBProxy(ctx, deps); err == nil {
		t.Fatal("startDBProxy (observe, no services): want error, got nil")
	}
}
```

(Add `os` import.)

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/api/ -run TestStartDBProxy -v`
Expected: FAIL with "undefined: dbProxyDeps" / "undefined: startDBProxy".

- [ ] **Step 4: Implement `internal/api/db_proxy.go`**

```go
package api

import (
	"context"
	"fmt"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/proxy/postgres"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
)

// dbProxyService is the per-service input to startDBProxy. The api layer
// joins the listener config (from internal/db/service) with the policy-side
// DBService (from internal/db/policy) into this flat shape so the proxy
// package never has to import internal/db/service's listener types.
type dbProxyService struct {
	Name       string
	DBService  policy.DBService
	ListenKind string // "unix" or "tcp"
	ListenPath string // when ListenKind == "unix"
	ListenHost string // when ListenKind == "tcp"
	ListenPort int    // when ListenKind == "tcp"
}

type dbProxyDeps struct {
	Unavoidability dbservice.Unavoidability
	Services       []dbProxyService
	StateDir       string
	Sink           events.Sink
}

// startDBProxy constructs and starts the AgentSH PostgreSQL proxy. Returns
// the *Server so the caller can wire Shutdown into supervisor lifecycle.
//
// Plan 04a: under Unavoidability == off, returns a sentinel server that
// does nothing. Under observe/enforce, binds Unix-socket listeners.
func startDBProxy(ctx context.Context, deps dbProxyDeps) (*postgres.Server, error) {
	cfg := postgres.Config{
		Unavoidability: deps.Unavoidability,
		StateDir:       deps.StateDir,
		Sink:           deps.Sink,
	}
	for _, s := range deps.Services {
		cfg.Services = append(cfg.Services, postgres.Service{
			Name:     s.Name,
			Family:   s.DBService.Family,
			Dialect:  s.DBService.Dialect,
			Upstream: s.DBService.Upstream,
			TLSMode:  s.DBService.TLSMode,
			Listen: postgres.ServiceListener{
				Kind: s.ListenKind,
				Path: s.ListenPath,
				Host: s.ListenHost,
				Port: s.ListenPort,
			},
			Service: s.DBService,
		})
	}
	srv, err := postgres.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("startDBProxy: new server: %w", err)
	}
	go func() {
		if err := srv.Start(ctx); err != nil {
			// Log via the supervisor's logger; not propagated here because
			// Start runs for the lifetime of ctx. Shutdown is the merge point.
			_ = err
		}
	}()
	return srv, nil
}
```

- [ ] **Step 5: Wire `startDBProxy` into the supervisor boot site**

In `internal/server/server.go`, just after the `app := api.NewApp(...)` call (line ~507) and the `appCloser` defer block, add:

```go
// DB proxy (Phase 1, Plan 04a). Bound only when policies.db.unavoidability != off.
// The DB rule set is loaded lazily by policyLoader.Engine() — read it once at
// boot. If the operator changes the unavoidability flag at runtime, a SIGHUP
// reload will rewire the proxy in a later plan.
{
	rs := loadDBRuleSet(policyLoader) // helper added below; returns *dbpolicy.RuleSet or nil
	deps := dbProxyDeps{
		Unavoidability: dbRuleSetUnavoidability(rs),
		StateDir:       cfg.StateDir, // verify the field name in cfg; fall back to filepath.Join(cfg.Sessions.BaseDir, "state") if absent
		Sink:           dbevents.NopSink{},
		Services:       collectDBProxyServices(policyLoader), // helper joins listener + DBService entries
	}
	dbSrv, err := startDBProxy(ctx, deps)
	if err != nil {
		return nil, fmt.Errorf("start db proxy: %w", err)
	}
	prevAppCloser := appCloser
	appCloser = func() {
		_ = dbSrv.Shutdown(context.Background())
		if prevAppCloser != nil {
			prevAppCloser()
		}
	}
}
```

Define the two helpers `loadDBRuleSet` and `collectDBProxyServices` and `dbRuleSetUnavoidability` in `internal/api/db_proxy.go`. They wrap `policyLoader.Engine()` (or whichever method exposes the loaded `*internal/policy.Policy`), call `dbpolicy.Decode(p)` to get a `*dbpolicy.RuleSet`, and assemble the `[]dbProxyService` slice from the parsed `db_services` listener entries.

If the supervisor boot site uses an early-return pattern instead of `appCloser`, mirror its style — the goal is "Shutdown is called once on supervisor teardown."

The exact `cfg` field for state dir: confirm against `internal/config/config.go`. If neither `cfg.StateDir` nor `cfg.Sessions.BaseDir` is the right place to persist the (still-Plan-04b) CA, use `filepath.Join(os.UserConfigDir(), "agentsh", "state")` as a Plan 04a placeholder; Plan 04b will revisit when the CA actually persists.

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/api/ -run TestStartDBProxy -v`
Expected: PASS for all three subtests.

Run: `go test ./internal/api/...`
Expected: no regressions.

- [ ] **Step 7: Commit**

```bash
git add internal/api/db_proxy.go internal/api/db_proxy_test.go internal/server/server.go
git commit -m "$(cat <<'EOF'
api: wire AgentSH PostgreSQL proxy into supervisor boot

Plan 04a Task 7. startDBProxy joins the policy-side DBService with the
listener-side config and constructs a postgres.Server, starting it under
the supervisor's ctx and registering Shutdown into the supervisor's
shutdown chain. Bound only when policies.db.unavoidability != off and at
least one db_service is declared.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Task 8: Final verification

**Why:** Belt-and-suspenders pass before declaring 04a done.

**Files:** None (verification only).

- [ ] **Step 1: Run the full repo test suite**

Run: `go test ./...`
Expected: all pass on Linux. Pre-existing flakes documented in `MEMORY.md` (e.g. `TestFlushLoop_PeriodicSync`) are not regressions; rerun once if they trip.

- [ ] **Step 2: Run cross-compile for Windows and macOS**

Run: `GOOS=windows go build ./...`
Expected: build success.

Run: `GOOS=darwin go build ./...`
Expected: build success.

- [ ] **Step 3: Manual `nc -U` smoke test (informational)**

Build a tiny driver under `cmd/dbproxy-smoke/main.go` (do **not** commit) that constructs a `postgres.Server` with one Unix-socket service, starts it, prints the socket path, and waits for SIGINT. Run it and connect with `nc -U <path>`; observe the connection accepting and immediately closing. Verify a `db_listener_auth_fail` event lands when running `nc -U` from a different user (skip if no second user is available).

- [ ] **Step 4: Confirm roborev between-tasks per project memory**

Per `feedback_roborev_between_tasks.md`: run roborev review after each major step before proceeding. Run `roborev-review-branch` on the current branch and address any findings above `low` severity before merging.

- [ ] **Step 5: Update plan checkboxes**

Confirm every checkbox above this section is checked. Open follow-up tasks for any defect found during verification.

- [ ] **Step 6: Final commit (only if any verification fixes were needed)**

```bash
git status
# If clean, nothing to commit. Otherwise:
git add <files>
git commit -m "db: Plan 04a verification fixes

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Out-of-scope reminders (do NOT do in Plan 04a)

- pgproto3 framing or any startup-packet handling — Plan 04b.
- `internal/db/tlsleaf` package, CA generation, leaf reissue — Plan 04b.
- TLS modes (`terminate_reissue`, `passthrough`, `terminate_plaintext_upstream`) — Plan 04b.
- SSLRequest / GSSENCRequest / CancelRequest / StartupMessage dispatch — Plan 04b.
- Replication detection and degraded_visibility_warning emission — Plan 04b.
- Connect-kind connection-rule evaluation — Plan 04b (just consume Plan 02's `EvaluateConnection`).
- Upstream TCP connect, auth-byte forwarding, SCRAM-SHA-256-PLUS detection — Plan 04b.
- `'Q'` frame classify + evaluate, RFQ tracker, deny synthesis, eventbuilder, redaction tiers, `statement_digest`, `MaxQueryBytes` — Plan 04c.
- `approve` runtime, `db_handshake_fail`, `degraded_visibility_warning` (these are 04b/04c kinds reserved on `LifecycleEvent` but emitted later).
- Out-of-process proxy under distinct SessionID, SO_PEERCRED → SessionID resolution, unavoidability bundle (network/file rules) generation, real-PG integration tests — Plan 07.

The `LifecycleEvent.Kind` values reserved here for later plans (`db_handshake_fail`, `degraded_visibility_warning`) are documented in this plan but only `db_listener_auth_fail` is emitted in 04a.
