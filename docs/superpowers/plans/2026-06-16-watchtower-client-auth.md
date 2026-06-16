# Watchtower Client Auth (v1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make agentsh/Beacon present a per-instance API key (`<kid>.<secret>`) to Watchtower over the existing bearer-in-metadata WTP path, with a per-Dial credential seam, secret redaction, a warn-only TLS coupling, and an auth-reject backoff clamp so a bad/revoked key cannot reconnect-storm Watchtower.

**Architecture:** The credential is fetched per-Dial through a new `CredentialSource` (v1 = a static source built from the already-resolved `token_env`/`token_file` value) and attached as `authorization: Bearer <kid>.<secret>` gRPC metadata by the production dialer. The transport classifies a gRPC `Unauthenticated`/`PermissionDenied` at stream open/handshake as a distinct `ErrAuthRejected`, increments a new `auth_rejected` session-init-failure metric, and clamps reconnect backoff to its max instead of fast-retrying. All Watchtower-side validation (key registry, principal→policy binding, DecisionContext narrowing) is out of scope — separate WT-repo spec.

**Tech Stack:** Go, gRPC (`google.golang.org/grpc/status` + `codes`), `log/slog`, the existing `internal/store/watchtower` transport/store, `internal/metrics` WTP series.

**Spec:** `docs/superpowers/specs/2026-06-16-watchtower-client-auth-design.md`

## Global Constraints

- `go test ./...` must pass (full suite — catches OCSF exhaustiveness and cross-package gates). One line, copied from CLAUDE.md/AGENTS.md.
- `GOOS=windows go build ./...` must pass (cross-compile gate).
- **No `wtp-protos` / proto changes** — auth rides gRPC metadata + status codes only.
- The bearer credential (`CredentialSource`) and mTLS client cert (`TLSCertFile`) remain **mutually exclusive** (existing rule in `options.go:324`).
- **The secret is never logged.** Logs carry only the `kid` (substring before the first `.`) or, for legacy dot-less tokens, a short `sha256:` prefix.
- **TLS coupling is warn-only** — credential configured together with `tls.insecure: true` logs a loud startup WARN; it never hard-fails. Resolved open item: warn **unconditionally** when a credential is present and the transport is insecure (no loopback-endpoint carve-out — simpler, and a warn on a loopback test server is harmless).
- Credential format is `<kid>.<secret>`; a value with **no `.`** is accepted verbatim as a legacy opaque bearer (back-compat with today's plain tokens).
- TDD: write the failing test first, watch it fail, implement minimally, watch it pass, commit. Frequent commits.

---

### Task 1: `CredentialSource` + `credLogID` (watchtower package)

**Files:**
- Create: `internal/store/watchtower/credsource.go`
- Test: `internal/store/watchtower/credsource_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `type CredentialSource interface { Bearer(ctx context.Context) (string, error) }`
  - `func NewStaticCredentialSource(token string) CredentialSource` — returns `nil` when `token == ""`.
  - `func credLogID(token string) string` — non-sensitive log id (`kid` before first `.`, else `sha256:` + 8 hex chars). Never returns the secret.

- [ ] **Step 1: Write the failing test**

```go
package watchtower

import (
	"context"
	"strings"
	"testing"
)

func TestCredLogID(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, token, want string
		wantPrefix        bool
	}{
		{name: "kid.secret returns kid", token: "inst-abc.SUPERSECRETVALUE", want: "inst-abc"},
		{name: "multi-dot splits on first", token: "kid1.a.b.c", want: "kid1"},
		{name: "legacy no-dot hashes", token: "plainlegacytoken", want: "sha256:", wantPrefix: true},
		{name: "leading dot hashes", token: ".secret", want: "sha256:", wantPrefix: true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := credLogID(tc.token)
			if strings.Contains(got, "SECRET") || got == tc.token && tc.wantPrefix {
				t.Fatalf("credLogID leaked the secret: %q", got)
			}
			if tc.wantPrefix {
				if !strings.HasPrefix(got, tc.want) {
					t.Fatalf("got %q, want prefix %q", got, tc.want)
				}
				return
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestNewStaticCredentialSource(t *testing.T) {
	t.Parallel()
	if NewStaticCredentialSource("") != nil {
		t.Fatal("empty token must yield a nil CredentialSource")
	}
	src := NewStaticCredentialSource("kid.secret")
	if src == nil {
		t.Fatal("non-empty token must yield a source")
	}
	got, err := src.Bearer(context.Background())
	if err != nil {
		t.Fatalf("Bearer: %v", err)
	}
	if got != "kid.secret" {
		t.Fatalf("Bearer: got %q, want %q", got, "kid.secret")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/ -run 'TestCredLogID|TestNewStaticCredentialSource' -v`
Expected: FAIL — `undefined: credLogID` / `undefined: NewStaticCredentialSource`.

- [ ] **Step 3: Write the implementation**

```go
package watchtower

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// CredentialSource yields the bearer credential agentsh presents on each
// WTP Dial. Returning "" means "present no credential" (anonymous; for
// local/test servers). It is called once per Dial so a future rotating or
// attested source (Phase 2) can return fresh values on reconnect with no
// change to the transport.
type CredentialSource interface {
	Bearer(ctx context.Context) (string, error)
}

// staticCredentialSource always yields the same token. Used for v1
// env/file credentials resolved once at startup.
type staticCredentialSource struct{ token string }

func (s staticCredentialSource) Bearer(context.Context) (string, error) { return s.token, nil }

// NewStaticCredentialSource returns a CredentialSource that always yields
// token, or nil when token is empty (nothing to present).
func NewStaticCredentialSource(token string) CredentialSource {
	if token == "" {
		return nil
	}
	return staticCredentialSource{token: token}
}

// credLogID returns a non-sensitive identifier for logging a presented
// credential: the key ID (the substring before the first '.') when the
// credential is in "<kid>.<secret>" form, or a short sha256 prefix for a
// legacy dot-less token. The secret is never returned.
func credLogID(token string) string {
	if i := strings.IndexByte(token, '.'); i > 0 {
		return token[:i]
	}
	sum := sha256.Sum256([]byte("agentsh-wt-cred\x00" + token))
	return "sha256:" + hex.EncodeToString(sum[:4])
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/ -run 'TestCredLogID|TestNewStaticCredentialSource' -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/credsource.go internal/store/watchtower/credsource_test.go
git commit -m "feat(wt): add CredentialSource + credLogID redaction helper"
```

---

### Task 2: Swap `Options.AuthBearer` → `CredentialSource` (keep build green)

**Files:**
- Modify: `internal/store/watchtower/options.go` (field at `:83`, validate at `:324`)
- Modify: `internal/store/watchtower/dialer.go` (`:62-66`)
- Modify: `internal/server/wtp.go` (`:215`)
- Test: `internal/store/watchtower/options_validate_test.go` (create)

**Interfaces:**
- Consumes: `CredentialSource`, `NewStaticCredentialSource` (Task 1).
- Produces: `Options.CredentialSource CredentialSource` (replaces `Options.AuthBearer string`). The mutual-exclusion rule now reads: `TLSCertFile != "" && CredentialSource != nil` is invalid.

- [ ] **Step 1: Write the failing test**

```go
package watchtower

import (
	"strings"
	"testing"
)

func TestValidate_CredentialSourceAndClientCertMutuallyExclusive(t *testing.T) {
	t.Parallel()
	o := baseValidOptionsForAuthTest(t)
	o.CredentialSource = NewStaticCredentialSource("kid.secret")
	o.TLSCertFile = "/tmp/cert.pem"
	o.TLSKeyFile = "/tmp/key.pem"
	err := o.validate()
	if err == nil {
		t.Fatal("expected validate() to reject CredentialSource + client cert together")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("err = %v, want mention of mutual exclusion", err)
	}
}

func TestValidate_CredentialSourceOnlyOK(t *testing.T) {
	t.Parallel()
	o := baseValidOptionsForAuthTest(t)
	o.CredentialSource = NewStaticCredentialSource("kid.secret")
	if err := o.validate(); err != nil {
		t.Fatalf("validate() with only a credential source: %v", err)
	}
}
```

Add this helper at the bottom of the same test file (a minimal `Options` that passes every other `validate()` branch — mirror the required fields from `options.go:validate`):

```go
func baseValidOptionsForAuthTest(t *testing.T) Options {
	t.Helper()
	o := Options{
		WALDir:          t.TempDir(),
		Mapper:          compact.NewStubMapper(),
		AllowStubMapper: true,
		Allocator:       audit.NewSequenceAllocator(),
		AgentID:         "agent-1",
		SessionID:       "sess-1",
		HMACKeyID:       "k1",
		HMACSecret:      make([]byte, audit.MinKeyLength),
	}
	o.applyDefaults()
	return o
}
```

Add the imports the helper needs to the test file: `"github.com/agentsh/agentsh/internal/audit"` and `"github.com/agentsh/agentsh/internal/store/watchtower/compact"`.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/ -run TestValidate_CredentialSource -v`
Expected: FAIL — `o.CredentialSource undefined` (field not added yet).

- [ ] **Step 3: Implement the field swap**

In `internal/store/watchtower/options.go`, replace the `AuthBearer string` line (`:83`) with:

```go
	// CredentialSource yields the bearer credential presented to
	// Watchtower on each Dial (authorization: Bearer <kid>.<secret>).
	// Nil means "no bearer credential" (anonymous, or mTLS via
	// TLSCertFile). Mutually exclusive with TLSCertFile. Fetched
	// per-Dial so a Phase-2 rotating/attested source drops in with no
	// transport change.
	CredentialSource CredentialSource
```

In the same file, replace the mutual-exclusion branch (`:324`):

```go
	if o.TLSCertFile != "" && o.CredentialSource != nil {
		return errors.New("watchtower: TLS client cert and bearer auth are mutually exclusive")
	}
```

In `internal/store/watchtower/dialer.go`, replace the bearer block (`:62-66`) with a per-Dial fetch (richer logging/classification comes in Task 7 — keep it minimal here so the build stays green):

```go
	streamCtx := ctx
	if d.opts.CredentialSource != nil {
		bearer, err := d.opts.CredentialSource.Bearer(ctx)
		if err != nil {
			_ = cc.Close()
			return nil, fmt.Errorf("watchtower: resolve credential: %w", err)
		}
		if bearer != "" {
			streamCtx = metadata.AppendToOutgoingContext(streamCtx,
				"authorization", "Bearer "+bearer)
		}
	}
```

In `internal/server/wtp.go`, replace `AuthBearer: authBearer,` (`:215`) with:

```go
		CredentialSource:        watchtower.NewStaticCredentialSource(authBearer),
```

- [ ] **Step 4: Run tests + build to verify**

Run: `go test ./internal/store/watchtower/ -run TestValidate_CredentialSource -v && go build ./...`
Expected: PASS, build succeeds.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/options.go internal/store/watchtower/dialer.go internal/server/wtp.go internal/store/watchtower/options_validate_test.go
git commit -m "refactor(wt): replace Options.AuthBearer with per-Dial CredentialSource"
```

---

### Task 3: Transport auth-reject primitives (`ErrAuthRejected`, `IsAuthReject`, `Backoff.ClampToMax`, `backoffAfterConnectError`)

**Files:**
- Create: `internal/store/watchtower/transport/auth_reject.go`
- Modify: `internal/store/watchtower/transport/backoff.go`
- Modify: `internal/store/watchtower/transport/transport.go` (add the `backoffAfterConnectError` method near the Run loop)
- Test: `internal/store/watchtower/transport/auth_reject_internal_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces (all in package `transport`):
  - `var ErrAuthRejected error`
  - `func IsAuthReject(err error) bool`
  - `func (b *Backoff) ClampToMax()`
  - `func (t *Transport) backoffAfterConnectError(bo *Backoff, err error) time.Duration`

- [ ] **Step 1: Write the failing test**

```go
package transport

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestIsAuthReject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"unauthenticated", status.Error(codes.Unauthenticated, "bad key"), true},
		{"permission denied", status.Error(codes.PermissionDenied, "revoked"), true},
		{"wrapped sentinel", fmt.Errorf("dial (%w): x", ErrAuthRejected), true},
		{"unavailable is transient", status.Error(codes.Unavailable, "down"), false},
		{"plain error", errors.New("connection reset"), false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := IsAuthReject(tc.err); got != tc.want {
				t.Fatalf("IsAuthReject(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestBackoffClampToMax(t *testing.T) {
	t.Parallel()
	bo := NewBackoff(BackoffOptions{Initial: time.Millisecond, Max: 10 * time.Second, Factor: 2})
	bo.ClampToMax()
	d := bo.Next()
	// Next applies [0.5,1.5) jitter to current (== Max after clamp).
	if d < 5*time.Second || d >= 15*time.Second {
		t.Fatalf("after ClampToMax, Next() = %v, want ~10s ±jitter", d)
	}
}

func TestBackoffAfterConnectError(t *testing.T) {
	t.Parallel()
	tr := &Transport{}

	boAuth := NewBackoff(BackoffOptions{Initial: time.Millisecond, Max: 10 * time.Second, Factor: 2})
	dAuth := tr.backoffAfterConnectError(boAuth, fmt.Errorf("dial (%w): x", ErrAuthRejected))
	if dAuth < 5*time.Second || dAuth >= 15*time.Second {
		t.Fatalf("auth-reject backoff = %v, want clamped ~10s", dAuth)
	}

	boTransient := NewBackoff(BackoffOptions{Initial: 100 * time.Millisecond, Max: 10 * time.Second, Factor: 2})
	dTransient := tr.backoffAfterConnectError(boTransient, errors.New("connection reset"))
	if dTransient < 50*time.Millisecond || dTransient >= 150*time.Millisecond {
		t.Fatalf("transient backoff = %v, want ~Initial 100ms ±jitter", dTransient)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/ -run 'TestIsAuthReject|TestBackoffClampToMax|TestBackoffAfterConnectError' -v`
Expected: FAIL — `undefined: ErrAuthRejected` / `IsAuthReject` / `ClampToMax` / `backoffAfterConnectError`.

- [ ] **Step 3: Implement**

Create `internal/store/watchtower/transport/auth_reject.go`:

```go
package transport

import (
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ErrAuthRejected marks a WTP connection failure caused by the server
// rejecting the presented credential (gRPC Unauthenticated /
// PermissionDenied) at stream open or handshake. The Run loop treats it
// specially: it is recoverable (a rotated file credential, or a Phase-2
// refreshing source, can succeed on a later Dial) but must NOT fast-retry,
// so reconnect backoff is clamped to its max for this case.
var ErrAuthRejected = errors.New("wtp: authentication rejected by Watchtower")

// IsAuthReject reports whether err is (or wraps) an authentication
// rejection — either the ErrAuthRejected sentinel or a raw gRPC status
// with code Unauthenticated/PermissionDenied (which is how the reject
// first surfaces from Dial/Recv before it is wrapped).
func IsAuthReject(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrAuthRejected) {
		return true
	}
	switch status.Code(err) {
	case codes.Unauthenticated, codes.PermissionDenied:
		return true
	default:
		return false
	}
}
```

Append to `internal/store/watchtower/transport/backoff.go`:

```go
// ClampToMax forces the next Next() to return the max interval (with
// jitter), short-circuiting the exponential ramp. Used by the reconnect
// loop on an authentication rejection so a bad/revoked credential retries
// no faster than once per BackoffMax instead of storming the server.
func (b *Backoff) ClampToMax() { b.current = b.opts.Max }
```

Add the seam method to `internal/store/watchtower/transport/transport.go` (place it just above the `Run` method, near line 1200). `errors` and `time` are already imported there:

```go
// backoffAfterConnectError computes the sleep before the next reconnect
// attempt after a StateConnecting error. An authentication rejection
// clamps the backoff to its max (no fast ramp); all other errors use the
// normal exponential progression.
func (t *Transport) backoffAfterConnectError(bo *Backoff, err error) time.Duration {
	if errors.Is(err, ErrAuthRejected) {
		bo.ClampToMax()
	}
	return bo.Next()
}
```

- [ ] **Step 4: Run tests + cross-compile**

Run: `go test ./internal/store/watchtower/transport/ -run 'TestIsAuthReject|TestBackoffClampToMax|TestBackoffAfterConnectError' -v && GOOS=windows go build ./...`
Expected: PASS, build succeeds.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/auth_reject.go internal/store/watchtower/transport/backoff.go internal/store/watchtower/transport/transport.go internal/store/watchtower/transport/auth_reject_internal_test.go
git commit -m "feat(wt): add ErrAuthRejected, IsAuthReject, backoff clamp seam"
```

---

### Task 4: Metrics — `auth_rejected` session-init-failure reason

**Files:**
- Modify: `internal/metrics/wtp.go` (const block `:584`, valid map `:592`, emit order `:605`)
- Test: `internal/metrics/wtp_auth_reason_test.go` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `metrics.WTPSessionFailureReasonAuthRejected WTPSessionFailureReason = "auth_rejected"`, present in `wtpSessionFailureReasonsValid` and `wtpSessionFailureReasonsEmitOrder`.

- [ ] **Step 1: Write the failing test**

```go
package metrics

import "testing"

func TestSessionFailureReason_AuthRejectedIsValid(t *testing.T) {
	if _, ok := wtpSessionFailureReasonsValid[WTPSessionFailureReasonAuthRejected]; !ok {
		t.Fatal("auth_rejected must be in wtpSessionFailureReasonsValid")
	}
	if WTPSessionFailureReasonAuthRejected != "auth_rejected" {
		t.Fatalf("value = %q, want %q", WTPSessionFailureReasonAuthRejected, "auth_rejected")
	}
	found := false
	for _, r := range wtpSessionFailureReasonsEmitOrder {
		if r == WTPSessionFailureReasonAuthRejected {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("auth_rejected must be in wtpSessionFailureReasonsEmitOrder")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/metrics/ -run TestSessionFailureReason_AuthRejectedIsValid -v`
Expected: FAIL — `undefined: WTPSessionFailureReasonAuthRejected`.

- [ ] **Step 3: Implement**

In `internal/metrics/wtp.go`, add the const to the `WTPSessionFailureReason` block (after `:588`):

```go
	WTPSessionFailureReasonAuthRejected      WTPSessionFailureReason = "auth_rejected"
```

Add it to `wtpSessionFailureReasonsValid` (`:592`):

```go
	WTPSessionFailureReasonAuthRejected:      {},
```

Add it to `wtpSessionFailureReasonsEmitOrder` (`:605`), keeping the existing alphabetical-ish ordering — insert before `WTPSessionFailureReasonInvalidUTF8`:

```go
	WTPSessionFailureReasonAuthRejected,
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/metrics/ -run TestSessionFailureReason_AuthRejectedIsValid -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/metrics/wtp.go internal/metrics/wtp_auth_reason_test.go
git commit -m "feat(metrics): add auth_rejected WTP session-init-failure reason"
```

---

### Task 5: Classify auth-reject in `runConnecting` (Dial + Recv branches)

**Files:**
- Modify: `internal/store/watchtower/transport/state_connecting.go` (`:38-41` Dial branch, `:51-57` Recv branch)
- Test: `internal/store/watchtower/transport/auth_reject_connecting_internal_test.go` (create)

**Interfaces:**
- Consumes: `IsAuthReject`, `ErrAuthRejected` (Task 3); `metrics.WTPSessionFailureReasonAuthRejected` (Task 4); the existing `internalFakeConn` (in `state_connecting_internal_test.go`) and `fakeMetrics` (in `state_connecting_clamp_internal_test.go`) test fakes.
- Produces: on an auth-reject from Dial or Recv, `runConnecting` returns `StateConnecting` with an error satisfying `errors.Is(err, ErrAuthRejected)` and increments `IncSessionInitFailures(auth_rejected)`.

- [ ] **Step 1: Write the failing test**

```go
package transport

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRunConnecting_AuthRejectFromRecv(t *testing.T) {
	t.Parallel()
	fm := &fakeMetrics{}
	fc := &internalFakeConn{recvErr: status.Error(codes.Unauthenticated, "bad key")}
	tr, err := New(Options{
		Dialer:    DialerFunc(func(context.Context) (Conn, error) { return fc, nil }),
		AgentID:   "a",
		SessionID: "s",
		Metrics:   fm,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	st, err := tr.RunOnce(ctx, StateConnecting)
	if st != StateConnecting {
		t.Fatalf("state = %s, want StateConnecting", st)
	}
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want errors.Is ErrAuthRejected", err)
	}
	if !containsReason(fm.sessionInitFailureReasons, "auth_rejected") {
		t.Fatalf("session-init-failure reasons = %v, want auth_rejected", fm.sessionInitFailureReasons)
	}
}

func TestRunConnecting_AuthRejectFromDial(t *testing.T) {
	t.Parallel()
	fm := &fakeMetrics{}
	tr, err := New(Options{
		Dialer: DialerFunc(func(context.Context) (Conn, error) {
			return nil, status.Error(codes.PermissionDenied, "revoked")
		}),
		AgentID:   "a",
		SessionID: "s",
		Metrics:   fm,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	st, err := tr.RunOnce(ctx, StateConnecting)
	if st != StateConnecting {
		t.Fatalf("state = %s, want StateConnecting", st)
	}
	if !errors.Is(err, ErrAuthRejected) {
		t.Fatalf("err = %v, want errors.Is ErrAuthRejected", err)
	}
	if !containsReason(fm.sessionInitFailureReasons, "auth_rejected") {
		t.Fatalf("reasons = %v, want auth_rejected", fm.sessionInitFailureReasons)
	}
}

func containsReason(rs []metricsReason, want string) bool {
	for _, r := range rs {
		if string(r) == want {
			return true
		}
	}
	return false
}
```

Note: `fakeMetrics.sessionInitFailureReasons` is `[]metrics.WTPSessionFailureReason`. Replace `metricsReason` with that type and add the import `"github.com/agentsh/agentsh/internal/metrics"` — written here as `metricsReason` only to keep the helper readable; use the real type:

```go
func containsReason(rs []metrics.WTPSessionFailureReason, want string) bool {
	for _, r := range rs {
		if string(r) == want {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/ -run 'TestRunConnecting_AuthReject' -v`
Expected: FAIL — error does not satisfy `errors.Is ErrAuthRejected` and reason `auth_rejected` not recorded.

- [ ] **Step 3: Implement**

In `internal/store/watchtower/transport/state_connecting.go`, replace the Dial-error branch (`:38-41`):

```go
	conn, err := t.opts.Dialer.Dial(ctx)
	if err != nil {
		if IsAuthReject(err) {
			t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonAuthRejected)
			return StateConnecting, fmt.Errorf("dial (%w): %v", ErrAuthRejected, err)
		}
		return StateConnecting, fmt.Errorf("dial: %w", err)
	}
	t.conn = conn
```

Replace the Recv-error branch (`:51-57`):

```go
	msg, err := conn.Recv()
	if err != nil {
		_ = conn.Close()
		t.conn = nil
		if IsAuthReject(err) {
			t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonAuthRejected)
			return StateConnecting, fmt.Errorf("recv SessionAck (%w): %v", ErrAuthRejected, err)
		}
		t.metrics.IncSessionInitFailures(metrics.WTPSessionFailureReasonRecvFailed)
		return StateConnecting, fmt.Errorf("recv SessionAck: %w", err)
	}
```

(`metrics` and `fmt` are already imported in `state_connecting.go`.)

- [ ] **Step 4: Run tests + cross-compile**

Run: `go test ./internal/store/watchtower/transport/ -run 'TestRunConnecting' -v && GOOS=windows go build ./...`
Expected: PASS (both new tests and the existing `TestRunConnecting_DiscardsConnOnError`), build succeeds.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/transport/state_connecting.go internal/store/watchtower/transport/auth_reject_connecting_internal_test.go
git commit -m "feat(wt): classify Unauthenticated/PermissionDenied as ErrAuthRejected in runConnecting"
```

---

### Task 6: Run loop clamps backoff on auth-reject

**Files:**
- Modify: `internal/store/watchtower/transport/transport.go` (StateConnecting error sleep arm, `:1259`)
- Test: `internal/store/watchtower/transport/auth_reject_runloop_internal_test.go` (create)

**Interfaces:**
- Consumes: `backoffAfterConnectError` (Task 3), `ErrAuthRejected` (Task 3), the auth-reject classification in `runConnecting` (Task 5), `internalFakeConn` test fake.
- Produces: the Run loop sleeps for the clamped (max) interval after an auth-reject, so repeated rejects do not fast-retry.

- [ ] **Step 1: Write the failing test**

This test drives `Run` against a dialer that always auth-rejects, with `BackoffInitial` tiny and `BackoffMax` large, and asserts the SECOND dial does not happen within a short window (it would, with the un-clamped fast ramp). It cancels promptly to keep the test fast.

```go
package transport

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRunLoop_AuthRejectClampsBackoff(t *testing.T) {
	t.Parallel()
	var dials atomic.Int32
	tr, err := New(Options{
		Dialer: DialerFunc(func(context.Context) (Conn, error) {
			dials.Add(1)
			return nil, status.Error(codes.Unauthenticated, "bad key")
		}),
		AgentID:        "a",
		SessionID:      "s",
		BackoffInitial: time.Millisecond, // would fast-retry many times if NOT clamped
		BackoffMax:     30 * time.Second, // clamp target — no 2nd dial in our window
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = tr.Run(ctx); close(done) }()

	// With clamping, the first dial fires immediately, then the loop
	// sleeps ~BackoffMax (30s). Within 300ms there must be exactly one
	// dial. Without clamping, the 1ms initial backoff would produce many.
	time.Sleep(300 * time.Millisecond)
	got := dials.Load()
	cancel()
	<-done

	if got != 1 {
		t.Fatalf("dials in 300ms = %d, want 1 (backoff should be clamped to max)", got)
	}
}
```

If `Run`'s exact signature differs (e.g. it takes a stop channel rather than ctx-cancel for teardown), adapt the goroutine/cancel to the existing `Run`/`Stop` pattern used in `transport_run_test.go`; the assertion (exactly one dial in 300ms) is the invariant.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/transport/ -run TestRunLoop_AuthRejectClampsBackoff -v`
Expected: FAIL — many dials within 300ms (fast 1ms ramp), `got` > 1.

- [ ] **Step 3: Implement**

In `internal/store/watchtower/transport/transport.go`, in the `StateConnecting` error block, replace the backoff sleep arm (`:1259`):

```go
				case <-time.After(t.backoffAfterConnectError(bo, err)):
```

(Leave the surrounding `select` — the `ctx.Done()` and `stopCh` arms — unchanged.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/store/watchtower/transport/ -run TestRunLoop_AuthRejectClampsBackoff -v`
Expected: PASS — exactly one dial in 300ms.

- [ ] **Step 5: Run the full transport package + cross-compile (regression gate)**

Run: `go test ./internal/store/watchtower/transport/ && GOOS=windows go build ./...`
Expected: PASS — the backoff change must not regress existing reconnect tests.

- [ ] **Step 6: Commit**

```bash
git add internal/store/watchtower/transport/transport.go internal/store/watchtower/transport/auth_reject_runloop_internal_test.go
git commit -m "feat(wt): clamp reconnect backoff to max on auth rejection"
```

---

### Task 7: Dialer — per-Dial kid log + classify Stream() auth-reject

**Files:**
- Modify: `internal/store/watchtower/dialer.go`
- Test: `internal/store/watchtower/dialer_cred_test.go` (create)

**Interfaces:**
- Consumes: `credLogID` (Task 1), `Options.CredentialSource` (Task 2), `transport.ErrAuthRejected` + `transport.IsAuthReject` (Task 3).
- Produces: on a credential-resolution error the dialer returns `watchtower: resolve credential: …`; on a gRPC auth-reject at `Stream()` it logs ERROR with `kid` and returns an error satisfying `errors.Is(err, transport.ErrAuthRejected)`; on each Dial with a credential it logs the `kid` at DEBUG. The secret is never logged.

- [ ] **Step 1: Write the failing test**

The credential-resolution-error path is unit-testable without a server because `Bearer(ctx)` is called before any network use:

```go
package watchtower

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type erroringCredentialSource struct{}

func (erroringCredentialSource) Bearer(context.Context) (string, error) {
	return "", errors.New("kms unavailable")
}

func TestDial_CredentialResolutionErrorIsSurfaced(t *testing.T) {
	t.Parallel()
	d := &productionDialer{opts: Options{
		Endpoint:         "127.0.0.1:0", // never actually dialed; Bearer() fails first
		CredentialSource: erroringCredentialSource{},
	}}
	_, err := d.Dial(context.Background())
	if err == nil {
		t.Fatal("expected Dial to fail when CredentialSource errors")
	}
	if !strings.Contains(err.Error(), "resolve credential") {
		t.Fatalf("err = %v, want 'resolve credential'", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/ -run TestDial_CredentialResolutionErrorIsSurfaced -v`
Expected: FAIL — current dialer resolves the credential AFTER `grpc.DialContext`, so a bogus endpoint may not surface the credential error first (or the ordering differs). Implement Step 3 to make it deterministic.

- [ ] **Step 3: Implement**

Rewrite `internal/store/watchtower/dialer.go`'s `Dial` so the credential is fetched FIRST (fail fast, no socket on a credential error), kid is logged at DEBUG, and a `Stream()` auth-reject is classified. Add imports `"log/slog"` and `"google.golang.org/grpc/status"`.

```go
func (d *productionDialer) Dial(ctx context.Context) (transport.Conn, error) {
	// Resolve the credential first so a credential error fails fast
	// without opening a socket.
	var bearer string
	if d.opts.CredentialSource != nil {
		b, err := d.opts.CredentialSource.Bearer(ctx)
		if err != nil {
			return nil, fmt.Errorf("watchtower: resolve credential: %w", err)
		}
		bearer = b
	}

	var dialOpts []grpc.DialOption
	if d.opts.TLSEnabled {
		tlsCfg := &tls.Config{InsecureSkipVerify: d.opts.TLSInsecure} //nolint:gosec
		if d.opts.TLSCACertFile != "" {
			pem, err := os.ReadFile(d.opts.TLSCACertFile)
			if err != nil {
				return nil, fmt.Errorf("read TLS CA cert: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("parse TLS CA cert: no certificates found in %q", d.opts.TLSCACertFile)
			}
			tlsCfg.RootCAs = pool
		}
		if d.opts.TLSCertFile != "" && d.opts.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(d.opts.TLSCertFile, d.opts.TLSKeyFile)
			if err != nil {
				return nil, fmt.Errorf("load TLS client cert: %w", err)
			}
			tlsCfg.Certificates = []tls.Certificate{cert}
		}
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	} else {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	//nolint:staticcheck // grpc.DialContext is the established pattern in this codebase.
	cc, err := grpc.DialContext(ctx, d.opts.Endpoint, dialOpts...)
	if err != nil {
		return nil, err
	}

	streamCtx := ctx
	if bearer != "" {
		d.logger().Debug("wtp: presenting credential",
			"kid", credLogID(bearer), "endpoint", d.opts.Endpoint)
		streamCtx = metadata.AppendToOutgoingContext(streamCtx,
			"authorization", "Bearer "+bearer)
	}

	stream, err := wtpv1.NewWatchtowerClient(cc).Stream(streamCtx)
	if err != nil {
		_ = cc.Close()
		if transport.IsAuthReject(err) {
			d.logger().Error("wtp: authentication rejected by Watchtower at stream open",
				"kid", credLogID(bearer), "code", status.Code(err).String())
			return nil, fmt.Errorf("%w: %v", transport.ErrAuthRejected, err)
		}
		return nil, err
	}
	return &grpcStreamConn{stream: stream, cc: cc}, nil
}

// logger returns the configured slog handle or the default.
func (d *productionDialer) logger() *slog.Logger {
	if d.opts.Logger != nil {
		return d.opts.Logger
	}
	return slog.Default()
}
```

- [ ] **Step 4: Run tests + cross-compile**

Run: `go test ./internal/store/watchtower/ -run TestDial_CredentialResolutionErrorIsSurfaced -v && GOOS=windows go build ./...`
Expected: PASS, build succeeds.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/dialer.go internal/store/watchtower/dialer_cred_test.go
git commit -m "feat(wt): dialer logs kid and classifies stream-open auth rejection"
```

---

### Task 8: `wtp.go` — warn when a credential is configured over plaintext

**Files:**
- Modify: `internal/server/wtp.go` (add helper + call near the `tlsEnabled` block at `:165-168`)
- Test: `internal/server/wtp_auth_warn_test.go` (create)

**Interfaces:**
- Consumes: the resolved `authBearer` string (`wtp.go:126`) and `cfg.TLS.Insecure`.
- Produces: `func warnIfCredentialOverPlaintext(logger *slog.Logger, token string, insecure bool)` — logs a WARN iff `token != "" && insecure`. Never errors.

- [ ] **Step 1: Write the failing test**

```go
package server

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestWarnIfCredentialOverPlaintext(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		token    string
		insecure bool
		wantWarn bool
	}{
		{"cred + insecure warns", "kid.secret", true, true},
		{"cred + secure silent", "kid.secret", false, false},
		{"no cred + insecure silent", "", true, false},
		{"no cred + secure silent", "", false, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
			warnIfCredentialOverPlaintext(logger, tc.token, tc.insecure)
			got := strings.Contains(buf.String(), "plaintext")
			if got != tc.wantWarn {
				t.Fatalf("warn emitted = %v, want %v (log=%q)", got, tc.wantWarn, buf.String())
			}
			if strings.Contains(buf.String(), tc.token) && tc.token != "" {
				t.Fatalf("WARN leaked the credential: %q", buf.String())
			}
		})
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/server/ -run TestWarnIfCredentialOverPlaintext -v`
Expected: FAIL — `undefined: warnIfCredentialOverPlaintext`.

- [ ] **Step 3: Implement**

Add the helper to `internal/server/wtp.go` (near `resolveAuthBearer`):

```go
// warnIfCredentialOverPlaintext logs a loud startup WARN when a bearer
// credential is configured together with a plaintext transport
// (tls.insecure=true). It is warn-only by design — the credential still
// traverses the network unencrypted, but operators may legitimately run
// plaintext against a local/dev Watchtower. The credential value is never
// logged.
func warnIfCredentialOverPlaintext(logger *slog.Logger, token string, insecure bool) {
	if token != "" && insecure {
		logger.Warn("watchtower: bearer credential configured over plaintext transport (tls.insecure=true); the credential will traverse the network unencrypted")
	}
}
```

Call it in `buildWatchtowerStore`, right after the existing `tls.insecure` WARN block (`:165-168`), using the already-resolved `authBearer`:

```go
	warnIfCredentialOverPlaintext(slog.Default(), authBearer, cfg.TLS.Insecure)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/server/ -run TestWarnIfCredentialOverPlaintext -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/server/wtp.go internal/server/wtp_auth_warn_test.go
git commit -m "feat(wt): warn when a bearer credential is configured over plaintext"
```

---

### Task 9: testserver metadata capture + integration tests

**Files:**
- Modify: `internal/store/watchtower/testserver/server.go` (Stream handler `:342`, struct `:33`, add accessor)
- Test: `internal/store/watchtower/auth_integration_test.go` (create)

**Interfaces:**
- Consumes: `srv.DialerFor()` (existing), `watchtower.NewStaticCredentialSource` (Task 1), the production dialer behavior (Task 7).
- Produces: `func (s *Server) FirstAuthorizationMetadata() string` — the `authorization` metadata value captured from the first accepted stream (empty if none/absent).

- [ ] **Step 1: Write the failing test**

Drive a real WTP handshake through the production gRPC path against the testserver's bufconn, presenting a credential, and assert the server saw the `Bearer` header. Use `transport.New` directly (the existing integration pattern) with the testserver dialer wrapped so it carries the credential — but the simplest correct path is to exercise the production dialer through the testserver's real gRPC stream. Since `DialerFor()` bypasses the production dialer, this test instead asserts the metadata-capture mechanism end-to-end via a small custom dialer that appends the header the same way the production dialer does:

```go
package watchtower_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	"github.com/agentsh/agentsh/internal/store/watchtower/testserver"
	"github.com/agentsh/agentsh/internal/store/watchtower/transport"
)

func TestServer_CapturesAuthorizationMetadata(t *testing.T) {
	t.Parallel()
	srv := testserver.New(testserver.Options{})
	defer srv.Close()

	base := srv.DialerFor()
	authed := transport.DialerFunc(func(ctx context.Context) (transport.Conn, error) {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer inst-7.SECRET")
		return base.Dial(ctx)
	})

	tr, err := transport.New(transport.Options{
		Dialer:    authed,
		AgentID:   "agent-1",
		SessionID: "sess-1",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := tr.RunOnce(ctx, transport.StateConnecting); err != nil {
		t.Fatalf("RunOnce: %v", err)
	}

	if _, err := srv.WaitForFirstSessionInit(time.Second); err != nil {
		t.Fatalf("WaitForFirstSessionInit: %v", err)
	}
	if got := srv.FirstAuthorizationMetadata(); got != "Bearer inst-7.SECRET" {
		t.Fatalf("captured authorization = %q, want %q", got, "Bearer inst-7.SECRET")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/store/watchtower/ -run TestServer_CapturesAuthorizationMetadata -v`
Expected: FAIL — `srv.FirstAuthorizationMetadata undefined`.

- [ ] **Step 3: Implement the capture**

In `internal/store/watchtower/testserver/server.go`, add a field to the `Server` struct (near `:38`):

```go
	// firstAuthMetadata captures the "authorization" metadata value from
	// the first accepted stream's context, for auth handshake tests.
	firstAuthMetadata string
```

In the `Stream` handler (`:342`), capture the metadata once, right where `firstSessionInit` is captured (inside the `h.s.mu.Lock()` block, after the `firstSessionInit == nil` guard fires). Add the import `"google.golang.org/grpc/metadata"` to the file:

```go
				if md, ok := metadata.FromIncomingContext(stream.Context()); ok {
					if vals := md.Get("authorization"); len(vals) > 0 {
						h.s.firstAuthMetadata = vals[0]
					}
				}
```

Add the accessor (near `WaitForFirstSessionInit`):

```go
// FirstAuthorizationMetadata returns the "authorization" metadata value
// captured from the first accepted stream, or "" if none was present.
func (s *Server) FirstAuthorizationMetadata() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firstAuthMetadata
}
```

- [ ] **Step 4: Run tests + full suite + cross-compile**

Run: `go test ./internal/store/watchtower/... -run TestServer_CapturesAuthorizationMetadata -v`
Then the cross-cutting gates:
`go test ./... && GOOS=windows go build ./...`
Expected: PASS across the board.

- [ ] **Step 5: Commit**

```bash
git add internal/store/watchtower/testserver/server.go internal/store/watchtower/auth_integration_test.go
git commit -m "test(wt): capture and assert authorization metadata in testserver"
```

---

## Self-Review

**1. Spec coverage:**
- Credential format `<kid>.<secret>` + legacy fallback → Task 1 (`credLogID`).
- Acquisition via `token_env`/`token_file` (reuses existing `resolveAuthBearer`) → unchanged; wired through `NewStaticCredentialSource` in Task 2.
- Per-Dial `CredentialSource` seam → Tasks 1, 2, 7.
- TLS warn-only coupling → Task 8.
- Auth-reject: fast-fail classification + long backoff (no storm) → Tasks 3, 5, 6.
- Reason-labeled metric (resolved open item: use the already-wired `IncSessionInitFailures` series with a new `auth_rejected` reason rather than the unwired reconnect series) → Task 4.
- Secret redaction invariant → Tasks 1, 7, 8 (log kid/hash only; assertions in tests).
- No `wtp-protos`/proto change → honored (metadata + gRPC status only).
- Bearer vs mTLS mutual exclusion preserved → Task 2.
- Integration: server receives `authorization` metadata → Task 9.
- WT-side registry / DecisionContext narrowing → correctly **out of scope** (deferred to WT-repo spec), matching the spec's Non-goals.

**2. Placeholder scan:** No "TBD"/"handle errors"/"similar to Task N". The one readability shortcut (`metricsReason` in Task 5's first draft) is immediately corrected inline to the real `metrics.WTPSessionFailureReason` type with the needed import. Task 6 notes a `Run`-signature adaptation fallback but states the concrete invariant (exactly one dial in 300ms).

**3. Type consistency:** `CredentialSource.Bearer(ctx) (string, error)`, `NewStaticCredentialSource(string) CredentialSource`, `credLogID(string) string`, `ErrAuthRejected`, `IsAuthReject(error) bool`, `(*Backoff).ClampToMax()`, `(*Transport).backoffAfterConnectError(*Backoff, error) time.Duration`, `WTPSessionFailureReasonAuthRejected = "auth_rejected"`, `(*Server).FirstAuthorizationMetadata() string` are used consistently across producing and consuming tasks. `Options.AuthBearer` is removed in Task 2 and never referenced afterward.
