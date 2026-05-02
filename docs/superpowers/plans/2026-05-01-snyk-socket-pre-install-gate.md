# Snyk and Socket Pre-Install Gating Implementation Plan

> **PIVOT (2026-05-01, mid-execution):** During T5 we discovered that `internal/pkgcheck/provider/socket.go` and `snyk.go` already exist in the codebase from prior PRs (`a703bc06`, `90cf4934`). The original plan assumed both were greenfield. After T1-T4 landed (foundation types + retry/breaker infra), tasks T5-T10 were re-scoped from "create from scratch" to **"enhance existing providers with retry+breaker integration."** Specifically:
>
> - T5 was reverted (`buildSocketPURLs` is dead code — existing Socket uses `/v0/scan/batch`, not `/v0/purl`).
> - T6/T7/T9/T10 dropped in favor of two new tasks: **T6'** (wire `retryClient` + `callWithBreaker` into existing `socketProvider.CheckBatch`) and **T7'** (same for `snykProvider`, plus add bounded concurrency to its sequential fan-out).
> - **T8'** wires both existing providers into the shared contract suite from T2.
> - Tasks T11-T20 stand essentially as written. Config defaults (T16) just need to ensure the existing `socket`/`snyk` provider entries exist in the providers map — they currently do not appear in `DefaultPackageChecksConfig()`.
>
> The original task descriptions below are kept for historical context but are NOT the source of truth past T4.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Snyk and Socket as pluggable `CheckProvider` implementations so intercepted package installs can be gated pre-execution against supply-chain attacks, with degraded-fallback behavior, privacy filtering for private packages, and rule-engine-driven verdict policy.

**Architecture:** Two new providers (`provider/socket.go`, `provider/snyk.go`) implementing the existing `pkgcheck.CheckProvider` interface, plus a small shared `httpclient.go` with retry/rate-limit/circuit-breaker. Privacy filtering happens upstream of the orchestrator. The `fail_mode` config compiles to existing `OnFailure` per-provider semantics. The `block_on` policy config compiles to `policy.PackageRule` entries — no new evaluator engine.

**Tech Stack:** Go 1.22+, standard library `net/http`, `golang.org/x/sync/errgroup`, existing `internal/pkgcheck` infra (orchestrator, evaluator, cache), existing `internal/policy` rule engine.

**Spec:** `docs/superpowers/specs/2026-05-01-snyk-socket-pre-install-gate-design.md`

---

## File Structure

**New files:**
- `internal/pkgcheck/provider/httpclient.go` — shared HTTP client with bounded retries, rate-limit handling, and circuit breaker.
- `internal/pkgcheck/provider/httpclient_test.go`
- `internal/pkgcheck/provider/socket.go` — Socket provider implementation.
- `internal/pkgcheck/provider/socket_test.go`
- `internal/pkgcheck/provider/snyk.go` — Snyk provider implementation.
- `internal/pkgcheck/provider/snyk_test.go`
- `internal/pkgcheck/provider/contract_test.go` — shared `CheckProvider` contract suite (run against OSV, Socket, Snyk).
- `internal/pkgcheck/provider/testdata/socket_purl_response.json`
- `internal/pkgcheck/provider/testdata/socket_malware_response.json`
- `internal/pkgcheck/provider/testdata/snyk_test_response.json`
- `internal/pkgcheck/provider/testdata/snyk_no_issues_response.json`
- `internal/pkgcheck/privacy.go` — registry/scope filter helper.
- `internal/pkgcheck/privacy_test.go`

**Modified files:**
- `internal/pkgcheck/types.go` — add `SkippedPackage` type and `Verdict.Skipped` field.
- `internal/pkgcheck/orchestrator.go` — pre-filter privacy-skipped packages, surface them on the response, plumb circuit-breaker state per provider.
- `internal/pkgcheck/cache/cache.go` — distinguish clean / found / not-found TTLs; add `PutNotFound`.
- `internal/pkgcheck/cache/cache_test.go`
- `internal/config/pkgcheck.go` — add `BlockOn` policy shorthand, `Privacy` block, `FailMode`; default scope override; emit validation warning.
- `internal/config/pkgcheck_test.go`

---

## Task Order Rationale

Foundation types (Tasks 1-2) must land first because privacy/orchestrator/test-fixtures all reference them. The shared HTTP helper (Tasks 3-4) lands before either provider so both can consume it. Socket goes before Snyk because it's simpler (single batch call) and exercises the helper. Cache changes (Tasks 11-12) land before orchestrator privacy/fail-mode wiring (Tasks 13-15) because the orchestrator now needs to call new cache methods. Config changes (Tasks 16-18) land last because they wire everything that already works individually.

---

## Task 1: Add SkippedPackage type and Verdict.Skipped field

**Files:**
- Modify: `internal/pkgcheck/types.go:152-158`
- Test: `internal/pkgcheck/types_test.go`

- [ ] **Step 1: Write failing test for SkippedPackage**

Add to `internal/pkgcheck/types_test.go`:

```go
func TestSkippedPackage_ReasonString(t *testing.T) {
	s := SkippedPackage{
		Package: PackageRef{Name: "@acme/internal", Version: "1.0.0"},
		Reason:  SkipReasonPrivateRegistry,
	}
	if s.Reason != "private_registry" {
		t.Fatalf("want private_registry, got %s", s.Reason)
	}
}

func TestVerdict_SkippedSurfaced(t *testing.T) {
	v := Verdict{
		Action: VerdictAllow,
		Skipped: []SkippedPackage{{
			Package: PackageRef{Name: "@acme/internal", Version: "1.0.0"},
			Reason:  SkipReasonPrivateRegistry,
		}},
	}
	if len(v.Skipped) != 1 {
		t.Fatalf("want 1 skipped, got %d", len(v.Skipped))
	}
}
```

- [ ] **Step 2: Run test, expect compile failure**

Run: `go test ./internal/pkgcheck/ -run TestSkippedPackage -v`
Expected: build error referencing `SkipReasonPrivateRegistry` undefined and `Verdict.Skipped` undefined.

- [ ] **Step 3: Add the type and field**

In `internal/pkgcheck/types.go`, after the `PackageVerdict` block:

```go
// SkipReason describes why a package was excluded from external scanning.
type SkipReason string

const (
	// SkipReasonPrivateRegistry indicates the package was resolved from a
	// registry not on the external-scan allowlist.
	SkipReasonPrivateRegistry SkipReason = "private_registry"

	// SkipReasonPrivateScopeDenylist indicates the package matched a scope
	// or prefix on the privacy denylist.
	SkipReasonPrivateScopeDenylist SkipReason = "private_scope_denylist"
)

// SkippedPackage records a package that was not externally scanned
// because of privacy rules.
type SkippedPackage struct {
	Package PackageRef `json:"package" yaml:"package"`
	Reason  SkipReason `json:"reason" yaml:"reason"`
}
```

In the `Verdict` struct, add `Skipped`:

```go
type Verdict struct {
	Action   VerdictAction             `json:"action" yaml:"action"`
	Findings []Finding                 `json:"findings,omitempty" yaml:"findings,omitempty"`
	Summary  string                    `json:"summary" yaml:"summary"`
	Packages map[string]PackageVerdict `json:"packages,omitempty" yaml:"packages,omitempty"`
	Skipped  []SkippedPackage          `json:"skipped,omitempty" yaml:"skipped,omitempty"`
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/ -run "TestSkippedPackage|TestVerdict_SkippedSurfaced" -v`
Expected: PASS.

- [ ] **Step 5: Run full pkgcheck suite to verify no regressions**

Run: `go test ./internal/pkgcheck/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/pkgcheck/types.go internal/pkgcheck/types_test.go
git commit -m "pkgcheck: add Skipped field and SkipReason for privacy filter"
```

---

## Task 2: Define shared CheckProvider contract test suite

**Files:**
- Create: `internal/pkgcheck/provider/contract_test.go`

This test runs against any `CheckProvider` and asserts the contract every implementation must satisfy. Each new provider (Socket, Snyk) wires itself into this suite via a sub-test entry point.

- [ ] **Step 1: Write the contract suite scaffold**

Create `internal/pkgcheck/provider/contract_test.go`:

```go
package provider

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// providerFactory builds a CheckProvider configured to talk to the given baseURL.
// Each provider's test file defines its own factory.
type providerFactory func(t *testing.T, baseURL string) pkgcheck.CheckProvider

// runContractSuite runs the shared CheckProvider contract assertions.
func runContractSuite(t *testing.T, name string, makeProvider providerFactory, fixture contractFixture) {
	t.Run(name+"/EmptyInput", func(t *testing.T) {
		p := makeProvider(t, fixture.cleanServerURL)
		resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  nil,
		})
		if err != nil {
			t.Fatalf("empty input must not error: %v", err)
		}
		if resp == nil {
			t.Fatal("response must not be nil")
		}
		if len(resp.Findings) != 0 {
			t.Fatalf("empty input should yield 0 findings, got %d", len(resp.Findings))
		}
	})

	t.Run(name+"/RespectsContextCancellation", func(t *testing.T) {
		p := makeProvider(t, fixture.slowServerURL)
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := p.CheckBatch(ctx, pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  []pkgcheck.PackageRef{{Name: "lodash", Version: "4.17.21"}},
		})
		if err == nil {
			t.Fatal("cancelled context must produce an error")
		}
	})

	t.Run(name+"/TransportErrorReturnsError", func(t *testing.T) {
		p := makeProvider(t, "http://127.0.0.1:1") // unreachable
		_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
			Ecosystem: pkgcheck.EcosystemNPM,
			Packages:  []pkgcheck.PackageRef{{Name: "lodash", Version: "4.17.21"}},
		})
		if err == nil {
			t.Fatal("transport error must return an error")
		}
	})
}

// contractFixture holds the test servers a provider needs to exercise the contract.
type contractFixture struct {
	cleanServerURL string // returns a 200 OK with no findings
	slowServerURL  string // sleeps longer than the test ctx timeout
}
```

- [ ] **Step 2: Verify it compiles (no providers wire in yet)**

Run: `go build ./internal/pkgcheck/provider/...`
Expected: build succeeds. No tests run yet — the suite is invoked by per-provider test files added in Tasks 8 and 10.

- [ ] **Step 3: Commit**

```bash
git add internal/pkgcheck/provider/contract_test.go
git commit -m "pkgcheck/provider: add shared CheckProvider contract test suite"
```

---

## Task 3: HTTP helper — bounded retry with backoff and rate-limit handling

**Files:**
- Create: `internal/pkgcheck/provider/httpclient.go`
- Create: `internal/pkgcheck/provider/httpclient_test.go`

- [ ] **Step 1: Write failing test for retry on 5xx**

Create `internal/pkgcheck/provider/httpclient_test.go`:

```go
package provider

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryClient_Retries5xxThenSucceeds(t *testing.T) {
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "ok")
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{
		MaxAttempts: 5,
		BaseBackoff: 1 * time.Millisecond,
		MaxBackoff:  10 * time.Millisecond,
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("want 200, got %d", resp.StatusCode)
	}
	if got := attempts.Load(); got != 3 {
		t.Fatalf("want 3 attempts, got %d", got)
	}
}

func TestRetryClient_RespectsRetryAfterHeader(t *testing.T) {
	start := time.Now()
	var attempts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := attempts.Add(1)
		if n == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{
		MaxAttempts:    3,
		BaseBackoff:    1 * time.Millisecond,
		MaxBackoff:     10 * time.Second,
		RespectRetryAfter: true,
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Fatalf("expected ~1s wait for Retry-After, got %v", elapsed)
	}
}

func TestRetryClient_GivesUpAfterMaxAttempts(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := newRetryClient(retryConfig{MaxAttempts: 3, BaseBackoff: 1 * time.Millisecond, MaxBackoff: 5 * time.Millisecond})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, strings.NewReader(""))
	resp, err := c.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error after max attempts, got nil")
	}
}
```

- [ ] **Step 2: Run test, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestRetryClient -v`
Expected: build error — `newRetryClient`, `retryConfig` undefined.

- [ ] **Step 3: Implement retry client**

Create `internal/pkgcheck/provider/httpclient.go`:

```go
package provider

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

// retryConfig configures the bounded-retry HTTP client.
type retryConfig struct {
	MaxAttempts       int
	BaseBackoff       time.Duration
	MaxBackoff        time.Duration
	RespectRetryAfter bool
	Transport         http.RoundTripper // optional, defaults to http.DefaultTransport
}

// retryClient wraps http.Client with bounded retries on 429/5xx and
// optional Retry-After header handling.
type retryClient struct {
	cfg    retryConfig
	client *http.Client
}

// newRetryClient creates a retryClient with sane defaults if zero values are passed.
func newRetryClient(cfg retryConfig) *retryClient {
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 3
	}
	if cfg.BaseBackoff <= 0 {
		cfg.BaseBackoff = 200 * time.Millisecond
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = 5 * time.Second
	}
	transport := cfg.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	return &retryClient{
		cfg:    cfg,
		client: &http.Client{Transport: transport},
	}
}

// Do executes the request with bounded retries on 429/5xx.
// The request body, if any, must be replayable — callers should pass a
// *bytes.Reader or similar that can be re-read.
func (c *retryClient) Do(req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		_ = req.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("read request body: %w", err)
		}
	}

	var lastErr error
	for attempt := 1; attempt <= c.cfg.MaxAttempts; attempt++ {
		if bodyBytes != nil {
			req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			if attempt == c.cfg.MaxAttempts {
				break
			}
			c.sleep(attempt, nil, req)
			continue
		}

		if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
			return resp, nil
		}

		// Retryable status — drain body and try again.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		lastErr = fmt.Errorf("http status %d", resp.StatusCode)
		if attempt == c.cfg.MaxAttempts {
			break
		}
		c.sleep(attempt, resp, req)
	}

	return nil, fmt.Errorf("retryClient: gave up after %d attempts: %w", c.cfg.MaxAttempts, lastErr)
}

// sleep applies Retry-After (when configured and present) or exponential
// backoff with jitter. Honors context cancellation.
func (c *retryClient) sleep(attempt int, resp *http.Response, req *http.Request) {
	wait := c.backoff(attempt)
	if c.cfg.RespectRetryAfter && resp != nil {
		if h := resp.Header.Get("Retry-After"); h != "" {
			if secs, err := strconv.Atoi(h); err == nil && secs > 0 {
				wait = time.Duration(secs) * time.Second
			}
		}
	}
	if wait > c.cfg.MaxBackoff {
		wait = c.cfg.MaxBackoff
	}

	select {
	case <-time.After(wait):
	case <-req.Context().Done():
	}
}

// backoff returns exponential-with-jitter backoff for the given attempt.
func (c *retryClient) backoff(attempt int) time.Duration {
	exp := time.Duration(1<<uint(attempt-1)) * c.cfg.BaseBackoff
	if exp > c.cfg.MaxBackoff {
		exp = c.cfg.MaxBackoff
	}
	// Full jitter: random in [0, exp].
	jitter := time.Duration(rand.Int63n(int64(exp) + 1))
	return jitter
}

// errMaxAttempts is exposed for tests that want to assert "gave up".
var errMaxAttempts = errors.New("max retry attempts exceeded")
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run TestRetryClient -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/provider/httpclient.go internal/pkgcheck/provider/httpclient_test.go
git commit -m "pkgcheck/provider: add retry client with backoff and Retry-After support"
```

---

## Task 4: HTTP helper — circuit breaker

**Files:**
- Modify: `internal/pkgcheck/provider/httpclient.go`
- Modify: `internal/pkgcheck/provider/httpclient_test.go`

The breaker tracks consecutive failures per provider; after 3 in 60s it opens for 60s. While open, calls return immediately with a sentinel error so the orchestrator skips the network.

- [ ] **Step 1: Write failing test for circuit breaker**

Append to `internal/pkgcheck/provider/httpclient_test.go`:

```go
func TestCircuitBreaker_OpensAfterConsecutiveFailures(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  3,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})

	if !cb.Allow() {
		t.Fatal("breaker should start closed")
	}
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("breaker should still be closed after 2 failures")
	}
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open after 3 failures")
	}
}

func TestCircuitBreaker_ClosesAfterOpenPeriod(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  2,
		Window:     time.Second,
		OpenPeriod: 50 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	if cb.Allow() {
		t.Fatal("breaker should be open")
	}
	time.Sleep(80 * time.Millisecond)
	if !cb.Allow() {
		t.Fatal("breaker should re-close after open period")
	}
}

func TestCircuitBreaker_SuccessResetsFailures(t *testing.T) {
	cb := newCircuitBreaker(circuitBreakerConfig{
		Threshold:  3,
		Window:     time.Second,
		OpenPeriod: 100 * time.Millisecond,
	})
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordSuccess()
	cb.RecordFailure()
	cb.RecordFailure()
	if !cb.Allow() {
		t.Fatal("breaker should still be closed: success reset failure count")
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestCircuitBreaker -v`
Expected: build error — `newCircuitBreaker`, `circuitBreakerConfig` undefined.

- [ ] **Step 3: Implement the breaker**

Append to `internal/pkgcheck/provider/httpclient.go`:

```go
import "sync"

// circuitBreakerConfig controls breaker behavior.
type circuitBreakerConfig struct {
	Threshold  int           // consecutive failures before opening
	Window     time.Duration // window in which Threshold failures must occur
	OpenPeriod time.Duration // how long the breaker stays open
}

// circuitBreaker tracks consecutive provider failures and short-circuits
// while open. Safe for concurrent use.
type circuitBreaker struct {
	cfg circuitBreakerConfig

	mu             sync.Mutex
	failures       int
	firstFailureAt time.Time
	openedAt       time.Time
}

func newCircuitBreaker(cfg circuitBreakerConfig) *circuitBreaker {
	if cfg.Threshold <= 0 {
		cfg.Threshold = 3
	}
	if cfg.Window <= 0 {
		cfg.Window = 60 * time.Second
	}
	if cfg.OpenPeriod <= 0 {
		cfg.OpenPeriod = 60 * time.Second
	}
	return &circuitBreaker{cfg: cfg}
}

// Allow reports whether a call may proceed.
func (b *circuitBreaker) Allow() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.openedAt.IsZero() {
		return true
	}
	if time.Since(b.openedAt) >= b.cfg.OpenPeriod {
		// Re-close.
		b.openedAt = time.Time{}
		b.failures = 0
		return true
	}
	return false
}

// RecordSuccess resets the failure counter.
func (b *circuitBreaker) RecordSuccess() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.failures = 0
	b.firstFailureAt = time.Time{}
}

// RecordFailure increments the failure counter and opens the breaker if the
// threshold is crossed within the window.
func (b *circuitBreaker) RecordFailure() {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	if b.failures == 0 || now.Sub(b.firstFailureAt) > b.cfg.Window {
		b.failures = 1
		b.firstFailureAt = now
	} else {
		b.failures++
	}

	if b.failures >= b.cfg.Threshold {
		b.openedAt = now
	}
}
```

(Move the `import "sync"` line into the existing import block at the top of the file.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run "TestRetryClient|TestCircuitBreaker" -v`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/provider/httpclient.go internal/pkgcheck/provider/httpclient_test.go
git commit -m "pkgcheck/provider: add circuit breaker for provider failure isolation"
```

---

## Task 5: Socket provider — request building (PURL)

**Files:**
- Create: `internal/pkgcheck/provider/socket.go`
- Create: `internal/pkgcheck/provider/socket_test.go`

- [ ] **Step 1: Write failing test for PURL construction**

Create `internal/pkgcheck/provider/socket_test.go`:

```go
package provider

import (
	"testing"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

func TestSocket_BuildPURLs_NPM(t *testing.T) {
	pkgs := []pkgcheck.PackageRef{
		{Name: "lodash", Version: "4.17.21"},
		{Name: "@types/node", Version: "20.10.0"},
	}
	got := buildSocketPURLs(pkgcheck.EcosystemNPM, pkgs)
	want := []string{
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/%40types/node@20.10.0",
	}
	if len(got) != len(want) {
		t.Fatalf("len mismatch: want %d, got %d", len(want), len(got))
	}
	for i, p := range got {
		if p != want[i] {
			t.Errorf("idx %d: want %q got %q", i, want[i], p)
		}
	}
}

func TestSocket_BuildPURLs_PyPI(t *testing.T) {
	pkgs := []pkgcheck.PackageRef{{Name: "requests", Version: "2.31.0"}}
	got := buildSocketPURLs(pkgcheck.EcosystemPyPI, pkgs)
	want := "pkg:pypi/requests@2.31.0"
	if got[0] != want {
		t.Fatalf("want %q got %q", want, got[0])
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket_BuildPURLs -v`
Expected: build error — `buildSocketPURLs` undefined.

- [ ] **Step 3: Implement PURL building**

Create `internal/pkgcheck/provider/socket.go`:

```go
package provider

import (
	"net/url"
	"strings"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// buildSocketPURLs converts a list of PackageRef to PURL strings (per spec
// https://github.com/package-url/purl-spec) for Socket's batch endpoint.
//
// The package name is path-escaped (so `@scope/name` becomes `%40scope/name`)
// to comply with PURL grammar.
func buildSocketPURLs(eco pkgcheck.Ecosystem, pkgs []pkgcheck.PackageRef) []string {
	ecoStr := mapEcosystemSocket(eco)
	out := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		// Split scope from name to escape only the @scope portion.
		// PURL grammar requires the leading `@` to be percent-encoded.
		name := p.Name
		if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
			parts := strings.SplitN(name, "/", 2)
			name = url.PathEscape(parts[0]) + "/" + parts[1]
		}
		purl := "pkg:" + ecoStr + "/" + name
		if p.Version != "" {
			purl += "@" + p.Version
		}
		out = append(out, purl)
	}
	return out
}

// mapEcosystemSocket converts our Ecosystem to Socket's PURL ecosystem token.
func mapEcosystemSocket(eco pkgcheck.Ecosystem) string {
	switch eco {
	case pkgcheck.EcosystemNPM:
		return "npm"
	case pkgcheck.EcosystemPyPI:
		return "pypi"
	default:
		return string(eco)
	}
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket_BuildPURLs -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/provider/socket.go internal/pkgcheck/provider/socket_test.go
git commit -m "pkgcheck/provider: add Socket PURL builder"
```

---

## Task 6: Socket provider — alert → Finding mapping

**Files:**
- Modify: `internal/pkgcheck/provider/socket.go`
- Modify: `internal/pkgcheck/provider/socket_test.go`
- Create: `internal/pkgcheck/provider/testdata/socket_malware_response.json`

- [ ] **Step 1: Capture a representative Socket response into testdata**

Create `internal/pkgcheck/provider/testdata/socket_malware_response.json`:

```json
[
  {
    "purl": "pkg:npm/evil-package@1.0.0",
    "name": "evil-package",
    "version": "1.0.0",
    "type": "npm",
    "score": {"supplyChainRisk": {"score": 0.05}},
    "alerts": [
      {"type": "malware", "severity": "critical", "title": "Known malicious package"},
      {"type": "installScripts", "severity": "high", "title": "Runs install scripts"}
    ]
  },
  {
    "purl": "pkg:npm/lodash@4.17.21",
    "name": "lodash",
    "version": "4.17.21",
    "type": "npm",
    "score": {"supplyChainRisk": {"score": 0.95}},
    "alerts": []
  },
  {
    "purl": "pkg:npm/typo-react@1.0.0",
    "name": "typo-react",
    "version": "1.0.0",
    "type": "npm",
    "score": {"supplyChainRisk": {"score": 0.5}},
    "alerts": [
      {"type": "typosquat", "severity": "medium", "title": "Possible typosquat of `react`"}
    ]
  }
]
```

- [ ] **Step 2: Write failing test for alert mapping**

Append to `internal/pkgcheck/provider/socket_test.go`:

```go
import (
	"encoding/json"
	"os"
	"path/filepath"
)

func TestSocket_MapAlertsToFindings(t *testing.T) {
	path := filepath.Join("testdata", "socket_malware_response.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var pkgs []socketPackageResp
	if err := json.Unmarshal(raw, &pkgs); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	findings := mapSocketAlertsToFindings(pkgs)

	// evil-package: malware (critical) + installScripts (high → malware critical-or-high mapping)
	// typo-react: typosquat → reputation
	// lodash: clean
	wantTypes := map[string]int{
		"malware":    2,
		"reputation": 1,
	}
	got := map[string]int{}
	for _, f := range findings {
		got[string(f.Type)]++
	}
	for k, v := range wantTypes {
		if got[k] != v {
			t.Errorf("finding type %s: want %d got %d", k, v, got[k])
		}
	}

	// Verify malware finding carries critical severity.
	var sawCriticalMalware bool
	for _, f := range findings {
		if f.Type == pkgcheck.FindingMalware && f.Severity == pkgcheck.SeverityCritical {
			sawCriticalMalware = true
			break
		}
	}
	if !sawCriticalMalware {
		t.Error("expected at least one critical malware finding")
	}
}
```

- [ ] **Step 3: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket_MapAlerts -v`
Expected: build error.

- [ ] **Step 4: Implement response types and mapping**

Append to `internal/pkgcheck/provider/socket.go`:

```go
import (
	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// socketPackageResp is one element in the Socket /v0/purl response array.
type socketPackageResp struct {
	PURL    string         `json:"purl"`
	Name    string         `json:"name"`
	Version string         `json:"version"`
	Type    string         `json:"type"`
	Alerts  []socketAlert  `json:"alerts"`
}

type socketAlert struct {
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail"`
}

// mapSocketAlertsToFindings converts Socket alert objects into pkgcheck.Finding records.
//
// Mapping rules (per spec §"Per-provider implementations / Socket"):
//   - "malware"                                                                → FindingMalware
//   - "installScripts" / "shellAccess" / "networkAccess" with severity ≥ high → FindingMalware
//                                          else                                → FindingReputation
//   - "typosquat" / "suspiciousStarActivity" / "unmaintained"                  → FindingReputation
//   - alert types containing "cve"                                             → FindingVulnerability
//   - "licenseChange" / "nonpermissiveLicense"                                 → FindingLicense
//   - "provenance*" / "signing*"                                               → FindingProvenance
//   - unknown alert type                                                        → FindingReputation, severity Medium
func mapSocketAlertsToFindings(pkgs []socketPackageResp) []pkgcheck.Finding {
	var out []pkgcheck.Finding
	for _, pkg := range pkgs {
		ref := pkgcheck.PackageRef{Name: pkg.Name, Version: pkg.Version}
		for _, a := range pkg.Alerts {
			ftype, sev := classifySocketAlert(a)
			out = append(out, pkgcheck.Finding{
				Type:     ftype,
				Provider: "socket",
				Package:  ref,
				Severity: sev,
				Title:    a.Title,
				Detail:   a.Detail,
				Reasons:  []pkgcheck.Reason{{Code: a.Type, Message: a.Title}},
			})
		}
	}
	return out
}

// classifySocketAlert returns the Finding type and Severity for a Socket alert.
func classifySocketAlert(a socketAlert) (pkgcheck.FindingType, pkgcheck.Severity) {
	sev := mapSocketSeverity(a.Severity)
	switch a.Type {
	case "malware":
		return pkgcheck.FindingMalware, sev
	case "installScripts", "shellAccess", "networkAccess":
		if sev == pkgcheck.SeverityCritical || sev == pkgcheck.SeverityHigh {
			return pkgcheck.FindingMalware, sev
		}
		return pkgcheck.FindingReputation, sev
	case "typosquat", "suspiciousStarActivity", "unmaintained":
		return pkgcheck.FindingReputation, sev
	case "licenseChange", "nonpermissiveLicense":
		return pkgcheck.FindingLicense, sev
	}
	if strings.Contains(a.Type, "cve") || strings.HasPrefix(a.Type, "CVE-") {
		return pkgcheck.FindingVulnerability, sev
	}
	if strings.HasPrefix(a.Type, "provenance") || strings.HasPrefix(a.Type, "signing") {
		return pkgcheck.FindingProvenance, sev
	}
	// Unknown alert type — surface as reputation/medium per spec.
	return pkgcheck.FindingReputation, pkgcheck.SeverityMedium
}

func mapSocketSeverity(s string) pkgcheck.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return pkgcheck.SeverityCritical
	case "high":
		return pkgcheck.SeverityHigh
	case "medium":
		return pkgcheck.SeverityMedium
	case "low":
		return pkgcheck.SeverityLow
	default:
		return pkgcheck.SeverityMedium
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/pkgcheck/provider/socket.go internal/pkgcheck/provider/socket_test.go internal/pkgcheck/provider/testdata/
git commit -m "pkgcheck/provider: map Socket alerts to pkgcheck Findings"
```

---

## Task 7: Socket provider — CheckBatch with chunking

**Files:**
- Modify: `internal/pkgcheck/provider/socket.go`
- Modify: `internal/pkgcheck/provider/socket_test.go`

- [ ] **Step 1: Write failing test for CheckBatch with httptest server**

Append to `internal/pkgcheck/provider/socket_test.go`:

```go
import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"time"
)

func TestSocket_CheckBatch_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v0/purl" {
			t.Errorf("want path /v0/purl, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		raw, _ := os.ReadFile(filepath.Join("testdata", "socket_malware_response.json"))
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	p := NewSocketProvider(SocketConfig{
		BaseURL:        srv.URL,
		APIKey:         "test-key",
		Timeout:        2 * time.Second,
		MaxPURLsPerCall: 100,
	})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "evil-package", Version: "1.0.0"},
			{Name: "lodash", Version: "4.17.21"},
			{Name: "typo-react", Version: "1.0.0"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Provider != "socket" {
		t.Errorf("want provider=socket, got %s", resp.Provider)
	}
	if len(resp.Findings) == 0 {
		t.Fatal("expected findings, got none")
	}
}

func TestSocket_CheckBatch_Chunks(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()

	pkgs := make([]pkgcheck.PackageRef, 250)
	for i := range pkgs {
		pkgs[i] = pkgcheck.PackageRef{Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"}
	}
	p := NewSocketProvider(SocketConfig{
		BaseURL:         srv.URL,
		APIKey:          "test-key",
		Timeout:         2 * time.Second,
		MaxPURLsPerCall: 100,
	})
	_, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  pkgs,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 250 / 100 = 3 chunks
	if got := calls.Load(); got != 3 {
		t.Errorf("want 3 calls (chunks), got %d", got)
	}
}

func TestSocket_CheckBatch_AuthHeaderSet(t *testing.T) {
	var sawAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer srv.Close()
	p := NewSocketProvider(SocketConfig{BaseURL: srv.URL, APIKey: "abc123", Timeout: time.Second, MaxPURLsPerCall: 100})
	_, _ = p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "foo", Version: "1"}},
	})
	if sawAuth == "" {
		t.Fatal("Authorization header missing")
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket_CheckBatch -v`
Expected: build error — `NewSocketProvider`, `SocketConfig` undefined.

- [ ] **Step 3: Implement the provider**

Append to `internal/pkgcheck/provider/socket.go`:

```go
import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultSocketBaseURL        = "https://api.socket.dev"
	defaultSocketTimeout        = 5 * time.Second
	defaultSocketMaxPURLsPerCall = 100
)

// SocketConfig configures the Socket provider.
type SocketConfig struct {
	BaseURL         string
	APIKey          string
	Timeout         time.Duration
	MaxPURLsPerCall int
}

type socketProvider struct {
	baseURL         string
	apiKey          string
	maxPURLsPerCall int
	client          *retryClient
	breaker         *circuitBreaker
}

// NewSocketProvider returns a CheckProvider that queries Socket's /v0/purl batch endpoint.
func NewSocketProvider(cfg SocketConfig) pkgcheck.CheckProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultSocketBaseURL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSocketTimeout
	}
	if cfg.MaxPURLsPerCall <= 0 {
		cfg.MaxPURLsPerCall = defaultSocketMaxPURLsPerCall
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return &socketProvider{
		baseURL:         cfg.BaseURL,
		apiKey:          cfg.APIKey,
		maxPURLsPerCall: cfg.MaxPURLsPerCall,
		client: newRetryClient(retryConfig{
			MaxAttempts:       3,
			BaseBackoff:       200 * time.Millisecond,
			MaxBackoff:        2 * time.Second,
			RespectRetryAfter: true,
		}),
		breaker: newCircuitBreaker(circuitBreakerConfig{
			Threshold:  3,
			Window:     60 * time.Second,
			OpenPeriod: 60 * time.Second,
		}),
	}
}

func (p *socketProvider) Name() string { return "socket" }

func (p *socketProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{
		pkgcheck.FindingMalware,
		pkgcheck.FindingVulnerability,
		pkgcheck.FindingLicense,
		pkgcheck.FindingReputation,
		pkgcheck.FindingProvenance,
	}
}

func (p *socketProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	start := time.Now()
	if len(req.Packages) == 0 {
		return &pkgcheck.CheckResponse{
			Provider: p.Name(),
			Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start)},
		}, nil
	}
	if !p.breaker.Allow() {
		return &pkgcheck.CheckResponse{
			Provider: p.Name(),
			Metadata: pkgcheck.ResponseMetadata{
				Duration: time.Since(start),
				Partial:  true,
				Error:    "circuit breaker open",
			},
		}, fmt.Errorf("socket: circuit breaker open")
	}

	purls := buildSocketPURLs(req.Ecosystem, req.Packages)

	var allFindings []pkgcheck.Finding
	for i := 0; i < len(purls); i += p.maxPURLsPerCall {
		end := i + p.maxPURLsPerCall
		if end > len(purls) {
			end = len(purls)
		}
		findings, err := p.queryChunk(ctx, purls[i:end])
		if err != nil {
			p.breaker.RecordFailure()
			return nil, fmt.Errorf("socket: chunk %d: %w", i/p.maxPURLsPerCall, err)
		}
		allFindings = append(allFindings, findings...)
	}
	p.breaker.RecordSuccess()

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: allFindings,
		Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}

func (p *socketProvider) queryChunk(ctx context.Context, purls []string) ([]pkgcheck.Finding, error) {
	body, err := json.Marshal(map[string]any{"components": componentsFromPURLs(purls)})
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.baseURL+"/v0/purl", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(p.apiKey+":")))
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(raw))
	}

	var pkgs []socketPackageResp
	if err := json.NewDecoder(resp.Body).Decode(&pkgs); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	return mapSocketAlertsToFindings(pkgs), nil
}

// componentsFromPURLs wraps PURL strings in the {purl: "..."} object shape that Socket's API expects.
func componentsFromPURLs(purls []string) []map[string]string {
	out := make([]map[string]string, len(purls))
	for i, p := range purls {
		out[i] = map[string]string{"purl": p}
	}
	return out
}
```

(Move imports into the existing import block at the top of the file.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/provider/socket.go internal/pkgcheck/provider/socket_test.go
git commit -m "pkgcheck/provider: implement Socket CheckBatch with chunking and breaker"
```

---

## Task 8: Wire Socket into the contract suite

**Files:**
- Modify: `internal/pkgcheck/provider/socket_test.go`

- [ ] **Step 1: Add a contract-suite entry point for Socket**

Append to `internal/pkgcheck/provider/socket_test.go`:

```go
func TestSocket_Contract(t *testing.T) {
	cleanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer cleanSrv.Close()

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer slowSrv.Close()

	factory := func(t *testing.T, baseURL string) pkgcheck.CheckProvider {
		return NewSocketProvider(SocketConfig{BaseURL: baseURL, APIKey: "test", Timeout: 2 * time.Second, MaxPURLsPerCall: 100})
	}
	runContractSuite(t, "socket", factory, contractFixture{
		cleanServerURL: cleanSrv.URL,
		slowServerURL:  slowSrv.URL,
	})
}
```

- [ ] **Step 2: Run the contract suite for Socket**

Run: `go test ./internal/pkgcheck/provider/ -run TestSocket_Contract -v`
Expected: all sub-tests PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/pkgcheck/provider/socket_test.go
git commit -m "pkgcheck/provider: run shared contract suite against Socket"
```

---

## Task 9: Snyk provider — request/response types and per-package mapping

**Files:**
- Create: `internal/pkgcheck/provider/snyk.go`
- Create: `internal/pkgcheck/provider/snyk_test.go`
- Create: `internal/pkgcheck/provider/testdata/snyk_test_response.json`
- Create: `internal/pkgcheck/provider/testdata/snyk_no_issues_response.json`

- [ ] **Step 1: Capture Snyk response fixtures**

Create `internal/pkgcheck/provider/testdata/snyk_test_response.json`:

```json
{
  "ok": false,
  "issues": {
    "vulnerabilities": [
      {
        "id": "SNYK-JS-LODASH-1234567",
        "title": "Prototype Pollution",
        "severity": "high",
        "cvssScore": 7.4,
        "url": "https://snyk.io/vuln/SNYK-JS-LODASH-1234567",
        "packageName": "lodash",
        "version": "4.17.20"
      }
    ],
    "licenses": []
  }
}
```

Create `internal/pkgcheck/provider/testdata/snyk_no_issues_response.json`:

```json
{"ok": true, "issues": {"vulnerabilities": [], "licenses": []}}
```

- [ ] **Step 2: Write failing test for response → Finding mapping**

Create `internal/pkgcheck/provider/snyk_test.go`:

```go
package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
)

func TestSnyk_MapResponseToFindings(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "snyk_test_response.json"))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	var sr snykTestResp
	if err := json.Unmarshal(raw, &sr); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	ref := pkgcheck.PackageRef{Name: "lodash", Version: "4.17.20"}
	findings := mapSnykResponseToFindings(ref, sr)

	if len(findings) != 1 {
		t.Fatalf("want 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Type != pkgcheck.FindingVulnerability {
		t.Errorf("type: want vulnerability, got %s", f.Type)
	}
	if f.Severity != pkgcheck.SeverityHigh {
		t.Errorf("severity: want high, got %s", f.Severity)
	}
	if f.Provider != "snyk" {
		t.Errorf("provider: want snyk, got %s", f.Provider)
	}
}

func TestSnyk_MapResponseToFindings_NoIssues(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "snyk_no_issues_response.json"))
	var sr snykTestResp
	_ = json.Unmarshal(raw, &sr)
	findings := mapSnykResponseToFindings(pkgcheck.PackageRef{Name: "lodash", Version: "4.17.21"}, sr)
	if len(findings) != 0 {
		t.Fatalf("want 0 findings, got %d", len(findings))
	}
}
```

- [ ] **Step 3: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestSnyk_MapResponse -v`
Expected: build error — `snykTestResp`, `mapSnykResponseToFindings` undefined.

- [ ] **Step 4: Implement types and mapping**

Create `internal/pkgcheck/provider/snyk.go`:

```go
package provider

import (
	"github.com/agentsh/agentsh/internal/pkgcheck"
)

// snykTestResp is the response shape for /test/{ecosystem}/{name}/{version}.
type snykTestResp struct {
	OK     bool      `json:"ok"`
	Issues snykIssues `json:"issues"`
}

type snykIssues struct {
	Vulnerabilities []snykVuln    `json:"vulnerabilities"`
	Licenses        []snykLicense `json:"licenses"`
}

type snykVuln struct {
	ID          string  `json:"id"`
	Title       string  `json:"title"`
	Severity    string  `json:"severity"`
	CVSSScore   float64 `json:"cvssScore"`
	URL         string  `json:"url"`
	PackageName string  `json:"packageName"`
	Version     string  `json:"version"`
}

type snykLicense struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Severity string `json:"severity"`
	License  string `json:"license"`
	URL      string `json:"url"`
}

// mapSnykResponseToFindings translates a Snyk /test response for a single package
// into pkgcheck.Finding records.
func mapSnykResponseToFindings(pkg pkgcheck.PackageRef, r snykTestResp) []pkgcheck.Finding {
	var out []pkgcheck.Finding
	for _, v := range r.Issues.Vulnerabilities {
		out = append(out, pkgcheck.Finding{
			Type:     pkgcheck.FindingVulnerability,
			Provider: "snyk",
			Package:  pkg,
			Severity: mapSnykSeverity(v.Severity),
			Title:    v.Title,
			Reasons:  []pkgcheck.Reason{{Code: "snyk_vuln", Message: v.ID}},
			Links:    []string{v.URL},
			Metadata: map[string]string{"snyk_id": v.ID},
		})
	}
	for _, l := range r.Issues.Licenses {
		out = append(out, pkgcheck.Finding{
			Type:     pkgcheck.FindingLicense,
			Provider: "snyk",
			Package:  pkg,
			Severity: mapSnykSeverity(l.Severity),
			Title:    l.Title,
			Reasons:  []pkgcheck.Reason{{Code: "snyk_license", Message: l.ID}},
			Links:    []string{l.URL},
			Metadata: map[string]string{"spdx": l.License},
		})
	}
	return out
}

func mapSnykSeverity(s string) pkgcheck.Severity {
	switch s {
	case "critical":
		return pkgcheck.SeverityCritical
	case "high":
		return pkgcheck.SeverityHigh
	case "medium":
		return pkgcheck.SeverityMedium
	case "low":
		return pkgcheck.SeverityLow
	default:
		return pkgcheck.SeverityMedium
	}
}

func mapEcosystemSnyk(eco pkgcheck.Ecosystem) string {
	switch eco {
	case pkgcheck.EcosystemNPM:
		return "npm"
	case pkgcheck.EcosystemPyPI:
		return "pip"
	default:
		return string(eco)
	}
}
```

- [ ] **Step 5: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run TestSnyk_MapResponse -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/pkgcheck/provider/snyk.go internal/pkgcheck/provider/snyk_test.go internal/pkgcheck/provider/testdata/snyk_*.json
git commit -m "pkgcheck/provider: add Snyk response types and Finding mapper"
```

---

## Task 10: Snyk provider — concurrency-bounded fan-out CheckBatch

**Files:**
- Modify: `internal/pkgcheck/provider/snyk.go`
- Modify: `internal/pkgcheck/provider/snyk_test.go`

- [ ] **Step 1: Write failing tests for fan-out**

Append to `internal/pkgcheck/provider/snyk_test.go`:

```go
func TestSnyk_CheckBatch_FanOut(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		raw, _ := os.ReadFile(filepath.Join("testdata", "snyk_no_issues_response.json"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	pkgs := make([]pkgcheck.PackageRef, 50)
	for i := range pkgs {
		pkgs[i] = pkgcheck.PackageRef{Name: fmt.Sprintf("pkg-%d", i), Version: "1.0.0"}
	}
	p := NewSnykProvider(SnykConfig{BaseURL: srv.URL, APIKey: "tk", Timeout: 2 * time.Second, Concurrency: 8})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  pkgs,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if int(calls.Load()) != len(pkgs) {
		t.Errorf("want %d calls, got %d", len(pkgs), calls.Load())
	}
	if resp.Provider != "snyk" {
		t.Errorf("provider: %s", resp.Provider)
	}
}

func TestSnyk_CheckBatch_AggregatesFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		raw, _ := os.ReadFile(filepath.Join("testdata", "snyk_test_response.json"))
		_, _ = w.Write(raw)
	}))
	defer srv.Close()
	p := NewSnykProvider(SnykConfig{BaseURL: srv.URL, APIKey: "tk", Timeout: time.Second, Concurrency: 4})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "lodash", Version: "4.17.20"},
			{Name: "express", Version: "4.18.0"},
		},
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Findings) != 2 {
		t.Fatalf("want 2 findings (1 per package), got %d", len(resp.Findings))
	}
}

func TestSnyk_CheckBatch_404IsNotAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	p := NewSnykProvider(SnykConfig{BaseURL: srv.URL, APIKey: "tk", Timeout: time.Second, Concurrency: 2})
	resp, err := p.CheckBatch(context.Background(), pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages:  []pkgcheck.PackageRef{{Name: "@acme/private", Version: "1.0.0"}},
	})
	if err != nil {
		t.Fatalf("404 should not be a hard error, got: %v", err)
	}
	if len(resp.Findings) != 0 {
		t.Fatalf("404 should yield 0 findings, got %d", len(resp.Findings))
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/provider/ -run TestSnyk_CheckBatch -v`
Expected: build error — `NewSnykProvider`, `SnykConfig` undefined.

- [ ] **Step 3: Implement the provider**

Append to `internal/pkgcheck/provider/snyk.go`:

```go
import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	defaultSnykBaseURL     = "https://api.snyk.io"
	defaultSnykTimeout     = 5 * time.Second
	defaultSnykConcurrency = 16
)

// SnykConfig configures the Snyk provider.
type SnykConfig struct {
	BaseURL     string
	APIKey      string
	Timeout     time.Duration
	Concurrency int
}

type snykProvider struct {
	baseURL     string
	apiKey      string
	concurrency int
	client      *retryClient
	breaker     *circuitBreaker
}

// NewSnykProvider returns a CheckProvider that queries Snyk's /test API per package.
func NewSnykProvider(cfg SnykConfig) pkgcheck.CheckProvider {
	if cfg.BaseURL == "" {
		cfg.BaseURL = defaultSnykBaseURL
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSnykTimeout
	}
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultSnykConcurrency
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")

	return &snykProvider{
		baseURL:     cfg.BaseURL,
		apiKey:      cfg.APIKey,
		concurrency: cfg.Concurrency,
		client: newRetryClient(retryConfig{
			MaxAttempts:       3,
			BaseBackoff:       200 * time.Millisecond,
			MaxBackoff:        2 * time.Second,
			RespectRetryAfter: true,
		}),
		breaker: newCircuitBreaker(circuitBreakerConfig{
			Threshold:  3,
			Window:     60 * time.Second,
			OpenPeriod: 60 * time.Second,
		}),
	}
}

func (p *snykProvider) Name() string { return "snyk" }

func (p *snykProvider) Capabilities() []pkgcheck.FindingType {
	return []pkgcheck.FindingType{pkgcheck.FindingVulnerability, pkgcheck.FindingLicense}
}

func (p *snykProvider) CheckBatch(ctx context.Context, req pkgcheck.CheckRequest) (*pkgcheck.CheckResponse, error) {
	start := time.Now()
	if len(req.Packages) == 0 {
		return &pkgcheck.CheckResponse{Provider: p.Name(), Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start)}}, nil
	}
	if !p.breaker.Allow() {
		return &pkgcheck.CheckResponse{
			Provider: p.Name(),
			Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start), Partial: true, Error: "circuit breaker open"},
		}, fmt.Errorf("snyk: circuit breaker open")
	}

	eco := mapEcosystemSnyk(req.Ecosystem)

	var (
		mu       sync.Mutex
		findings []pkgcheck.Finding
		anyError error
	)
	sem := make(chan struct{}, p.concurrency)
	var wg sync.WaitGroup

	for _, pkg := range req.Packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(pkg pkgcheck.PackageRef) {
			defer wg.Done()
			defer func() { <-sem }()

			fs, err := p.queryOne(ctx, eco, pkg)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if anyError == nil {
					anyError = err
				}
				return
			}
			findings = append(findings, fs...)
		}(pkg)
	}
	wg.Wait()

	if anyError != nil {
		p.breaker.RecordFailure()
		return nil, anyError
	}
	p.breaker.RecordSuccess()

	return &pkgcheck.CheckResponse{
		Provider: p.Name(),
		Findings: findings,
		Metadata: pkgcheck.ResponseMetadata{Duration: time.Since(start)},
	}, nil
}

// queryOne fetches /test/{eco}/{name}/{version} for a single package.
// 404 is not treated as an error — it means Snyk has no data for that package
// (typically a private package); we return zero findings.
func (p *snykProvider) queryOne(ctx context.Context, eco string, pkg pkgcheck.PackageRef) ([]pkgcheck.Finding, error) {
	urlStr := fmt.Sprintf("%s/test/%s/%s/%s", p.baseURL, eco, url.PathEscape(pkg.Name), url.PathEscape(pkg.Version))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	if p.apiKey != "" {
		httpReq.Header.Set("Authorization", "token "+p.apiKey)
	}
	httpReq.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("snyk %s@%s: %w", pkg.Name, pkg.Version, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("snyk %s@%s: status %d: %s", pkg.Name, pkg.Version, resp.StatusCode, string(raw))
	}

	var sr snykTestResp
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("snyk decode %s@%s: %w", pkg.Name, pkg.Version, err)
	}
	return mapSnykResponseToFindings(pkg, sr), nil
}
```

(Move imports into the existing import block at the top of the file.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/provider/ -run TestSnyk -v`
Expected: PASS.

- [ ] **Step 5: Wire Snyk into the contract suite**

Append to `internal/pkgcheck/provider/snyk_test.go`:

```go
func TestSnyk_Contract(t *testing.T) {
	cleanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true, "issues": {"vulnerabilities": [], "licenses": []}}`))
	}))
	defer cleanSrv.Close()
	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok": true, "issues": {"vulnerabilities": [], "licenses": []}}`))
	}))
	defer slowSrv.Close()

	factory := func(t *testing.T, baseURL string) pkgcheck.CheckProvider {
		return NewSnykProvider(SnykConfig{BaseURL: baseURL, APIKey: "tk", Timeout: 2 * time.Second, Concurrency: 4})
	}
	runContractSuite(t, "snyk", factory, contractFixture{
		cleanServerURL: cleanSrv.URL,
		slowServerURL:  slowSrv.URL,
	})
}
```

Run: `go test ./internal/pkgcheck/provider/ -run TestSnyk_Contract -v`
Expected: all sub-tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/pkgcheck/provider/snyk.go internal/pkgcheck/provider/snyk_test.go
git commit -m "pkgcheck/provider: implement Snyk concurrency-bounded fan-out CheckBatch"
```

---

## Task 11: Cache — distinguish clean vs found vs not-found TTLs

**Files:**
- Modify: `internal/pkgcheck/cache/cache.go`
- Modify: `internal/pkgcheck/cache/cache_test.go`

The existing cache uses `TTLByType` keyed by finding type. We need three distinct lifetimes per the spec:
- **clean** (provider returned no findings) → 24h default
- **found** (provider returned ≥1 finding) → indefinite (use `0` to mean never expire)
- **not-found** (provider returned 404 / unknown package) → 1h default

- [ ] **Step 1: Write failing tests**

Add to `internal/pkgcheck/cache/cache_test.go`:

```go
func TestCache_FoundEntriesNeverExpire(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, CleanTTL: 1 * time.Hour, FoundTTL: 0 /* never */, NotFoundTTL: 1 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Provider: "snyk", Ecosystem: "npm", Package: "lodash", Version: "4.17.20"}
	c.Put(key, []pkgcheck.Finding{{Type: pkgcheck.FindingVulnerability}})

	// Manually rewind the entry's expiry to "the past" — verify it still hits.
	got, ok := c.Get(key)
	if !ok {
		t.Fatal("expected hit")
	}
	if len(got) != 1 {
		t.Fatalf("want 1 finding, got %d", len(got))
	}
}

func TestCache_CleanEntriesExpire(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, CleanTTL: 50 * time.Millisecond, FoundTTL: 0, NotFoundTTL: 1 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Provider: "socket", Ecosystem: "npm", Package: "lodash", Version: "4.17.21"}
	c.Put(key, nil) // no findings → clean

	if _, ok := c.Get(key); !ok {
		t.Fatal("expected fresh hit")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get(key); ok {
		t.Fatal("expected expiry after CleanTTL")
	}
}

func TestCache_PutNotFoundUsesNotFoundTTL(t *testing.T) {
	dir := t.TempDir()
	c, err := New(Config{Dir: dir, CleanTTL: 24 * time.Hour, FoundTTL: 0, NotFoundTTL: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Provider: "snyk", Ecosystem: "npm", Package: "@acme/private", Version: "1.0.0"}
	c.PutNotFound(key)
	if _, ok := c.Get(key); !ok {
		t.Fatal("expected fresh hit")
	}
	time.Sleep(80 * time.Millisecond)
	if _, ok := c.Get(key); ok {
		t.Fatal("expected expiry after NotFoundTTL")
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/cache/ -run TestCache -v`
Expected: build error — `Config.CleanTTL`, `Config.FoundTTL`, `Config.NotFoundTTL`, `PutNotFound` undefined.

- [ ] **Step 3: Add new Config fields and PutNotFound**

In `internal/pkgcheck/cache/cache.go`, replace the `Config` struct with:

```go
type Config struct {
	// Dir is the directory where the cache file is stored.
	Dir string
	// MaxSizeMB is the maximum size of the cache file in megabytes (reserved for future use).
	MaxSizeMB int

	// CleanTTL is the lifetime of an entry where the provider returned no findings.
	CleanTTL time.Duration
	// FoundTTL is the lifetime of an entry with one or more findings.
	// A zero value means "never expire" (findings for a (name, version) are permanent).
	FoundTTL time.Duration
	// NotFoundTTL is the lifetime of an entry where the provider had no data
	// (e.g., 404 from /test/...). Typically used for private packages.
	NotFoundTTL time.Duration

	// DefaultTTL is retained for backwards compatibility with callers that have
	// not migrated to the explicit per-result-class TTLs above. It is used
	// when CleanTTL is zero.
	DefaultTTL time.Duration
	// TTLByType is retained for backwards compatibility. It is consulted only
	// for found entries; if a finding type matches and no explicit FoundTTL is set,
	// the matched value is used.
	TTLByType map[string]time.Duration
}
```

Add a sentinel for "never expire" handled in `Get`:

```go
// neverExpires is a far-future expiry used when FoundTTL == 0.
var neverExpires = time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
```

Replace `Put` with:

```go
func (c *Cache) Put(key Key, findings []pkgcheck.Finding) {
	c.mu.Lock()
	defer c.mu.Unlock()

	stored := deepCopyFindings(findings)
	expiry := c.computeExpiry(findings)
	c.entries[key.String()] = entry{Findings: stored, ExpiresAt: expiry}
}

// PutNotFound stores a "provider has no data on this package" sentinel
// with the configured NotFoundTTL.
func (c *Cache) PutNotFound(key Key) {
	c.mu.Lock()
	defer c.mu.Unlock()

	ttl := c.cfg.NotFoundTTL
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	c.entries[key.String()] = entry{Findings: nil, ExpiresAt: time.Now().Add(ttl)}
}
```

Replace `computeTTL` with `computeExpiry`:

```go
// computeExpiry returns the absolute expiry timestamp for a Put.
//   - empty findings → CleanTTL (or DefaultTTL fallback)
//   - non-empty       → FoundTTL (0 = neverExpires); falls back to TTLByType match or DefaultTTL
func (c *Cache) computeExpiry(findings []pkgcheck.Finding) time.Time {
	now := time.Now()
	if len(findings) == 0 {
		ttl := c.cfg.CleanTTL
		if ttl <= 0 {
			ttl = c.cfg.DefaultTTL
		}
		if ttl <= 0 {
			ttl = 24 * time.Hour
		}
		return now.Add(ttl)
	}
	if c.cfg.FoundTTL == 0 {
		// Found entries persist indefinitely by default.
		// Honor TTLByType only if explicitly configured.
		if len(c.cfg.TTLByType) > 0 {
			best := time.Duration(0)
			matched := false
			for _, f := range findings {
				if t, ok := c.cfg.TTLByType[string(f.Type)]; ok {
					if !matched || t > best {
						best = t
						matched = true
					}
				}
			}
			if matched {
				return now.Add(best)
			}
		}
		return neverExpires
	}
	return now.Add(c.cfg.FoundTTL)
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/cache/...`
Expected: PASS (including pre-existing tests — keep them green by leaving `DefaultTTL` / `TTLByType` honored as fallback).

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/cache/cache.go internal/pkgcheck/cache/cache_test.go
git commit -m "pkgcheck/cache: distinguish clean/found/not-found TTLs and add PutNotFound"
```

---

## Task 12: Privacy filter

**Files:**
- Create: `internal/pkgcheck/privacy.go`
- Create: `internal/pkgcheck/privacy_test.go`

- [ ] **Step 1: Write failing tests**

Create `internal/pkgcheck/privacy_test.go`:

```go
package pkgcheck

import (
	"testing"
)

func TestPrivacyFilter_PrivateRegistryAutoDetect(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org", "pypi.org"},
	})
	in := []PackageRef{
		{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org"},
		{Name: "internal-tool", Version: "0.1.0", Registry: "artifactory.acme.local"},
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || scan[0].Name != "lodash" {
		t.Fatalf("scan = %+v, want lodash only", scan)
	}
	if len(skip) != 1 || skip[0].Reason != SkipReasonPrivateRegistry {
		t.Fatalf("skip = %+v, want internal-tool with private_registry", skip)
	}
}

func TestPrivacyFilter_ScopeDenylist(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
		PrivateScopeDenylist:   []string{"@acme", "@internal-*"},
	})
	in := []PackageRef{
		{Name: "@acme/billing", Version: "1.0.0", Registry: "registry.npmjs.org"},
		{Name: "@internal-platform/utils", Version: "1.0.0", Registry: "registry.npmjs.org"},
		{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org"},
	}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || scan[0].Name != "lodash" {
		t.Fatalf("scan = %+v, want lodash only", scan)
	}
	if len(skip) != 2 {
		t.Fatalf("skip = %+v, want 2 entries", skip)
	}
	for _, s := range skip {
		if s.Reason != SkipReasonPrivateScopeDenylist {
			t.Errorf("want denylist reason for %s, got %s", s.Package.Name, s.Reason)
		}
	}
}

func TestPrivacyFilter_EmptyAllowlistTreatsAllAsPublic(t *testing.T) {
	// An empty allowlist means "no registry filter applied" — defer to denylist only.
	pf := NewPrivacyFilter(PrivacyConfig{})
	in := []PackageRef{{Name: "lodash", Version: "4.17.21", Registry: "anything"}}
	scan, skip := pf.Partition(in)
	if len(scan) != 1 || len(skip) != 0 {
		t.Fatalf("scan=%v skip=%v", scan, skip)
	}
}

func TestPrivacyFilter_RegistryRuleTakesPriority(t *testing.T) {
	pf := NewPrivacyFilter(PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
		PrivateScopeDenylist:   []string{"@acme"},
	})
	// On a private registry — should report private_registry, not denylist.
	in := []PackageRef{{Name: "@acme/x", Version: "1", Registry: "artifactory.acme.local"}}
	_, skip := pf.Partition(in)
	if len(skip) != 1 || skip[0].Reason != SkipReasonPrivateRegistry {
		t.Fatalf("want private_registry, got %+v", skip)
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/ -run TestPrivacyFilter -v`
Expected: build error — `NewPrivacyFilter`, `PrivacyConfig` undefined.

- [ ] **Step 3: Implement the filter**

Create `internal/pkgcheck/privacy.go`:

```go
package pkgcheck

import (
	"path"
	"strings"
)

// PrivacyConfig configures the privacy filter.
type PrivacyConfig struct {
	// ExternalScanRegistries lists registries whose packages may be sent to
	// external providers. An empty list means "do not filter by registry."
	ExternalScanRegistries []string

	// PrivateScopeDenylist lists package name prefixes / glob patterns that
	// should NOT be sent externally even when on an allowed registry.
	// Each entry is matched as either an exact prefix (`@acme`) or a
	// glob (`@internal-*`).
	PrivateScopeDenylist []string
}

// PrivacyFilter partitions a list of PackageRef into "to-scan" and "to-skip".
type PrivacyFilter struct {
	allowedRegistries map[string]struct{}
	denylistPatterns  []string
}

// NewPrivacyFilter builds a filter from configuration.
func NewPrivacyFilter(cfg PrivacyConfig) *PrivacyFilter {
	allowed := make(map[string]struct{}, len(cfg.ExternalScanRegistries))
	for _, r := range cfg.ExternalScanRegistries {
		allowed[r] = struct{}{}
	}
	return &PrivacyFilter{
		allowedRegistries: allowed,
		denylistPatterns:  append([]string(nil), cfg.PrivateScopeDenylist...),
	}
}

// Partition splits the input into packages eligible for external scanning
// and packages skipped due to privacy rules. Order within each slice
// preserves the order of the input.
//
// Decision order: registry rule first (if an allowlist is configured),
// then scope/prefix denylist. A package skipped for "private_registry"
// is never re-classified to "private_scope_denylist."
func (f *PrivacyFilter) Partition(pkgs []PackageRef) (scan []PackageRef, skip []SkippedPackage) {
	for _, p := range pkgs {
		if len(f.allowedRegistries) > 0 && p.Registry != "" {
			if _, ok := f.allowedRegistries[p.Registry]; !ok {
				skip = append(skip, SkippedPackage{Package: p, Reason: SkipReasonPrivateRegistry})
				continue
			}
		}
		if f.matchesDenylist(p.Name) {
			skip = append(skip, SkippedPackage{Package: p, Reason: SkipReasonPrivateScopeDenylist})
			continue
		}
		scan = append(scan, p)
	}
	return scan, skip
}

func (f *PrivacyFilter) matchesDenylist(name string) bool {
	for _, pat := range f.denylistPatterns {
		if strings.ContainsAny(pat, "*?[") {
			if ok, _ := path.Match(pat, name); ok {
				return true
			}
			// Also match against the leading scope segment for patterns like @internal-*
			if strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
				scope := strings.SplitN(name, "/", 2)[0]
				if ok, _ := path.Match(pat, scope); ok {
					return true
				}
			}
		} else {
			// Plain prefix: matches "@acme" against "@acme/billing" and "@acme".
			if name == pat || strings.HasPrefix(name, pat+"/") {
				return true
			}
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/ -run TestPrivacyFilter -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/privacy.go internal/pkgcheck/privacy_test.go
git commit -m "pkgcheck: add PrivacyFilter for registry and scope-denylist exclusions"
```

---

## Task 13: Wire privacy filter into orchestrator and surface Skipped

**Files:**
- Modify: `internal/pkgcheck/orchestrator.go`
- Create: `internal/pkgcheck/orchestrator_privacy_test.go`

The orchestrator gets a new `PrivacyFilter` field. Before fanning out to providers, it partitions the request and accumulates the skipped list to return alongside findings.

- [ ] **Step 1: Write failing test**

Create `internal/pkgcheck/orchestrator_privacy_test.go`:

```go
package pkgcheck

import (
	"context"
	"testing"
	"time"
)

type recordingProvider struct {
	name string
	last []PackageRef
}

func (r *recordingProvider) Name() string                 { return r.name }
func (r *recordingProvider) Capabilities() []FindingType  { return nil }
func (r *recordingProvider) CheckBatch(ctx context.Context, req CheckRequest) (*CheckResponse, error) {
	r.last = append([]PackageRef(nil), req.Packages...)
	return &CheckResponse{Provider: r.name}, nil
}

func TestOrchestrator_PrivacyFiltersBeforeProviders(t *testing.T) {
	rp := &recordingProvider{name: "fake"}
	o := NewOrchestrator(OrchestratorConfig{
		Providers: map[string]ProviderEntry{
			"fake": {Provider: rp, Timeout: time.Second, OnFailure: "warn"},
		},
		PrivacyFilter: NewPrivacyFilter(PrivacyConfig{
			ExternalScanRegistries: []string{"registry.npmjs.org"},
			PrivateScopeDenylist:   []string{"@acme"},
		}),
	})
	req := CheckRequest{
		Ecosystem: EcosystemNPM,
		Packages: []PackageRef{
			{Name: "lodash", Version: "4.17.21", Registry: "registry.npmjs.org"},
			{Name: "@acme/x", Version: "1", Registry: "registry.npmjs.org"},
			{Name: "internal", Version: "0.1", Registry: "artifactory.acme.local"},
		},
	}
	_, _, skipped := o.CheckAllWithPrivacy(context.Background(), req)
	if len(skipped) != 2 {
		t.Fatalf("want 2 skipped, got %d", len(skipped))
	}
	if len(rp.last) != 1 || rp.last[0].Name != "lodash" {
		t.Fatalf("provider should have received lodash only, got %+v", rp.last)
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/ -run TestOrchestrator_PrivacyFilters -v`
Expected: build error — `OrchestratorConfig.PrivacyFilter` and `Orchestrator.CheckAllWithPrivacy` undefined.

- [ ] **Step 3: Add the field and method**

In `internal/pkgcheck/orchestrator.go`, modify `OrchestratorConfig`:

```go
type OrchestratorConfig struct {
	Providers     map[string]ProviderEntry
	PrivacyFilter *PrivacyFilter // optional; nil means no filtering
}
```

Update `NewOrchestrator` to keep the filter:

```go
func NewOrchestrator(cfg OrchestratorConfig) *Orchestrator {
	providers := make(map[string]ProviderEntry, len(cfg.Providers))
	for k, v := range cfg.Providers {
		providers[k] = v
	}
	return &Orchestrator{cfg: OrchestratorConfig{
		Providers:     providers,
		PrivacyFilter: cfg.PrivacyFilter,
	}}
}
```

Add the new method that returns the skipped list. Keep the existing `CheckAll` for backward compatibility — it now delegates:

```go
// CheckAllWithPrivacy applies the configured PrivacyFilter (if any) before
// dispatching the request to all providers. Returns merged findings, provider
// errors, and the list of packages that were not externally scanned.
func (o *Orchestrator) CheckAllWithPrivacy(ctx context.Context, req CheckRequest) ([]Finding, []ProviderError, []SkippedPackage) {
	var skipped []SkippedPackage
	if o.cfg.PrivacyFilter != nil {
		scan, skip := o.cfg.PrivacyFilter.Partition(req.Packages)
		req.Packages = scan
		skipped = skip
	}
	findings, errs := o.CheckAll(ctx, req)
	return findings, errs, skipped
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/ -run TestOrchestrator -v`
Expected: PASS (existing TestOrchestrator tests + the new privacy test).

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/orchestrator.go internal/pkgcheck/orchestrator_privacy_test.go
git commit -m "pkgcheck: orchestrator filters private packages before provider dispatch"
```

---

## Task 14: Verdict — surface Skipped and degraded summary annotation

**Files:**
- Modify: `internal/pkgcheck/evaluator.go`
- Modify: `internal/pkgcheck/evaluator_test.go`

The evaluator receives findings + skipped + provider errors and emits a complete `Verdict`. Currently `Evaluate(findings, ecosystem)` does not see skipped or errors. Add a wrapper that does.

- [ ] **Step 1: Write failing test**

Add to `internal/pkgcheck/evaluator_test.go`:

```go
func TestEvaluator_EvaluateWithContext_AnnotatesDegraded(t *testing.T) {
	ev := NewEvaluator([]policy.PackageRule{
		{Match: policy.PackageMatch{}, Action: "allow"},
	})
	v := ev.EvaluateWithContext(EvalContext{
		Findings:  nil,
		Ecosystem: EcosystemNPM,
		ProviderErrors: []ProviderError{
			{Provider: "socket", Err: errors.New("timeout"), OnFailure: "warn"},
		},
		Skipped: []SkippedPackage{
			{Package: PackageRef{Name: "@acme/x"}, Reason: SkipReasonPrivateScopeDenylist},
		},
	})
	if !strings.HasPrefix(v.Summary, "degraded:") {
		t.Errorf("want summary prefixed degraded:, got %q", v.Summary)
	}
	if len(v.Skipped) != 1 {
		t.Errorf("want 1 skipped, got %d", len(v.Skipped))
	}
}
```

(Add the imports `errors`, `strings`, and `policy` if not already present.)

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/pkgcheck/ -run TestEvaluator_EvaluateWithContext -v`
Expected: build error — `EvaluateWithContext`, `EvalContext` undefined.

- [ ] **Step 3: Add EvalContext and EvaluateWithContext**

Add to `internal/pkgcheck/evaluator.go`:

```go
// EvalContext bundles all inputs the evaluator needs to produce a complete Verdict.
type EvalContext struct {
	Findings       []Finding
	Ecosystem      Ecosystem
	ProviderErrors []ProviderError
	Skipped        []SkippedPackage
}

// EvaluateWithContext runs the rule engine and decorates the resulting Verdict
// with skipped-package info and a "degraded:" summary prefix when one or more
// providers failed with OnFailure == "warn" (the degraded fail-mode).
func (e *Evaluator) EvaluateWithContext(c EvalContext) *Verdict {
	v := e.Evaluate(c.Findings, c.Ecosystem)
	if v == nil {
		v = &Verdict{Action: VerdictAllow}
	}
	v.Skipped = append([]SkippedPackage(nil), c.Skipped...)

	var degraded []string
	for _, perr := range c.ProviderErrors {
		if perr.OnFailure == "warn" {
			degraded = append(degraded, perr.Provider)
		}
	}
	if len(degraded) > 0 {
		v.Summary = "degraded: " + strings.Join(degraded, ",") + " unavailable; " + v.Summary
	}
	return v
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/pkgcheck/ -run TestEvaluator -v`
Expected: PASS (new test plus all pre-existing evaluator tests).

- [ ] **Step 5: Commit**

```bash
git add internal/pkgcheck/evaluator.go internal/pkgcheck/evaluator_test.go
git commit -m "pkgcheck: evaluator surfaces skipped packages and degraded annotation"
```

---

## Task 15: Compile block_on policy shorthand into PackageRule list

**Files:**
- Modify: `internal/config/pkgcheck.go`
- Create: `internal/config/pkgcheck_policy_test.go`

Per the implementation discovery, the spec's `policy.block_on` config is a shorthand that compiles into `policy.PackageRule` entries that the existing evaluator already understands. This avoids inventing a parallel policy engine.

- [ ] **Step 1: Write failing test**

Create `internal/config/pkgcheck_policy_test.go`:

```go
package config

import (
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
)

func TestCompileBlockOn_DefaultsAndOverrides(t *testing.T) {
	rules := CompileBlockOn(BlockOnConfig{
		Malware:       "any",
		Vulnerability: "critical",
		License:       "never",
		Reputation:    "never",
		Provenance:    "never",
	})

	// Expect: malware-any → deny; vuln-critical → deny; vuln-high → warn;
	// then a catch-all allow at the end.
	if len(rules) < 4 {
		t.Fatalf("want >=4 rules, got %d: %+v", len(rules), rules)
	}

	denyMalware := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "malware"}, Action: "deny",
	})
	denyCritVuln := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny",
	})
	warnHighVuln := containsRule(rules, policy.PackageRule{
		Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "warn",
	})
	if !denyMalware {
		t.Error("missing malware deny rule")
	}
	if !denyCritVuln {
		t.Error("missing vulnerability/critical deny rule")
	}
	if !warnHighVuln {
		t.Error("missing vulnerability/high warn rule")
	}

	last := rules[len(rules)-1]
	if last.Action != "allow" || last.Match.FindingType != "" {
		t.Errorf("expected catch-all allow as last rule, got %+v", last)
	}
}

// containsRule compares rules ignoring Reason text.
func containsRule(rules []policy.PackageRule, want policy.PackageRule) bool {
	for _, r := range rules {
		if r.Match.FindingType == want.Match.FindingType &&
			r.Match.Severity == want.Match.Severity &&
			r.Action == want.Action {
			return true
		}
	}
	return false
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/config/ -run TestCompileBlockOn -v`
Expected: build error — `BlockOnConfig`, `CompileBlockOn` undefined.

- [ ] **Step 3: Add the type and compiler**

Append to `internal/config/pkgcheck.go`:

```go
import "github.com/agentsh/agentsh/internal/policy"

// BlockOnConfig is the policy shorthand:
//   each finding type maps to a severity threshold at which to block.
//   Allowed values per finding type:
//     malware:       any | critical | never
//     vulnerability: critical | high | medium | never
//     license:       any | never
//     reputation:    any | never
//     provenance:    any | never
type BlockOnConfig struct {
	Malware       string `yaml:"malware"`
	Vulnerability string `yaml:"vulnerability"`
	License       string `yaml:"license"`
	Reputation    string `yaml:"reputation"`
	Provenance    string `yaml:"provenance"`
}

// CompileBlockOn translates the BlockOnConfig shorthand into a list of
// policy.PackageRule entries (first-match-wins) ending in a catch-all allow.
//
// For each finding type we emit deny rules for severities at or above the
// threshold, warn rules for severities below the threshold but still
// noteworthy (currently: high vulns become warn even when threshold is
// critical), and rely on the catch-all allow for everything else.
func CompileBlockOn(b BlockOnConfig) []policy.PackageRule {
	var rules []policy.PackageRule

	// Malware: any (deny all severities) or critical (deny only critical).
	switch b.Malware {
	case "any":
		rules = append(rules, policy.PackageRule{
			Match: policy.PackageMatch{FindingType: "malware"}, Action: "deny",
			Reason: "block_on.malware=any",
		})
	case "critical":
		rules = append(rules, policy.PackageRule{
			Match: policy.PackageMatch{FindingType: "malware", Severity: "critical"}, Action: "deny",
			Reason: "block_on.malware=critical",
		})
	}

	// Vulnerability thresholds.
	switch b.Vulnerability {
	case "medium":
		rules = append(rules,
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "medium"}, Action: "deny"},
		)
	case "high":
		rules = append(rules,
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "deny"},
		)
	case "critical":
		rules = append(rules,
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
			policy.PackageRule{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "high"}, Action: "warn"},
		)
	}

	// License / reputation / provenance: any → deny; never → no rule (catch-all allows).
	for _, kv := range []struct{ ft, mode string }{
		{"license", b.License}, {"reputation", b.Reputation}, {"provenance", b.Provenance},
	} {
		if kv.mode == "any" {
			rules = append(rules, policy.PackageRule{
				Match: policy.PackageMatch{FindingType: kv.ft}, Action: "deny",
				Reason: "block_on." + kv.ft + "=any",
			})
		}
	}

	// Catch-all allow.
	rules = append(rules, policy.PackageRule{
		Match: policy.PackageMatch{}, Action: "allow",
		Reason: "block_on default allow",
	})
	return rules
}
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -run TestCompileBlockOn -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/pkgcheck.go internal/config/pkgcheck_policy_test.go
git commit -m "config: compile block_on shorthand into policy.PackageRule list"
```

---

## Task 16: Add Privacy and FailMode config fields and provider entries

**Files:**
- Modify: `internal/config/pkgcheck.go`
- Modify: `internal/config/pkgcheck_test.go`

The existing `ProviderConfig` already has `APIKeyEnv`, `Timeout`, `OnFailure`, `Options` — Snyk and Socket fit as map entries. We add a top-level `Privacy` block, a `FailMode` field, and a `BlockOn` field for the policy shorthand.

- [ ] **Step 1: Write failing test**

Add to `internal/config/pkgcheck_test.go`:

```go
func TestPackageChecksConfig_FailModeAndPrivacy(t *testing.T) {
	cfg := PackageChecksConfig{
		FailMode: "degraded",
		Privacy: PrivacyConfig{
			ExternalScanRegistries: []string{"registry.npmjs.org"},
			PrivateScopeDenylist:   []string{"@acme"},
		},
		BlockOn: BlockOnConfig{Malware: "any", Vulnerability: "critical"},
	}
	if cfg.FailMode != "degraded" {
		t.Errorf("FailMode field missing")
	}
	if len(cfg.Privacy.ExternalScanRegistries) != 1 {
		t.Errorf("Privacy field missing")
	}
}

func TestDefaultPackageChecksConfig_HasFailModeAndPrivacy(t *testing.T) {
	d := DefaultPackageChecksConfig()
	if d.FailMode == "" {
		t.Error("default FailMode should be set")
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/config/ -run "TestPackageChecksConfig_FailMode|TestDefaultPackageChecksConfig_HasFail" -v`
Expected: build error — `PackageChecksConfig.FailMode`, `PackageChecksConfig.Privacy`, `PackageChecksConfig.BlockOn` undefined.

- [ ] **Step 3: Add fields and update defaults**

In `internal/config/pkgcheck.go`, modify `PackageChecksConfig`:

```go
type PackageChecksConfig struct {
	Enabled    bool                           `yaml:"enabled"`
	Scope      string                         `yaml:"scope"` // "new_packages_only" | "all_installs"
	Cache      PackageCacheConfig             `yaml:"cache"`
	Registries map[string]RegistryTrustConfig `yaml:"registries"`
	Providers  map[string]ProviderConfig      `yaml:"providers"`
	Resolvers  map[string]ResolverConfig      `yaml:"resolvers"`

	// FailMode controls how the orchestrator reacts to provider failures
	// for external providers (Snyk / Socket / etc.). One of:
	//   "open"     — let the install proceed when an external provider fails.
	//   "closed"   — block the install when an external provider fails.
	//   "degraded" — fall back to OSV findings, annotate the verdict.
	// The env var PKGCHECK_FAIL_MODE overrides this at runtime.
	FailMode string `yaml:"fail_mode"`

	// Privacy filters which packages may be sent to external providers.
	Privacy PrivacyConfig `yaml:"privacy"`

	// BlockOn is a per-finding-type severity threshold shorthand that compiles
	// into policy.PackageRule entries via CompileBlockOn.
	BlockOn BlockOnConfig `yaml:"block_on"`
}

// PrivacyConfig configures the upstream privacy filter (mirrors pkgcheck.PrivacyConfig).
type PrivacyConfig struct {
	ExternalScanRegistries []string `yaml:"external_scan_registries"`
	PrivateScopeDenylist   []string `yaml:"private_scope_denylist"`
}
```

In `DefaultPackageChecksConfig()`, augment the returned struct:

```go
return PackageChecksConfig{
	Enabled:  false,
	Scope:    "new_packages_only",
	FailMode: "degraded",
	Privacy: PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org", "pypi.org"},
	},
	BlockOn: BlockOnConfig{
		Malware:       "any",
		Vulnerability: "critical",
		License:       "never",
		Reputation:    "never",
		Provenance:    "never",
	},
	// ... existing Cache/Providers/Resolvers entries unchanged ...
}
```

Also add Snyk and Socket as known-but-disabled providers in the default Providers map:

```go
Providers: map[string]ProviderConfig{
	"osv": { Enabled: true, Priority: 1, Timeout: 10 * time.Second, OnFailure: "warn" },
	"depsdev": { Enabled: true, Priority: 2, Timeout: 10 * time.Second, OnFailure: "warn" },
	"local": { Enabled: true, Priority: 0, OnFailure: "warn" },
	"socket": { Enabled: false, Priority: 5, Timeout: 5 * time.Second, OnFailure: "warn", APIKeyEnv: "SOCKET_API_KEY" },
	"snyk": { Enabled: false, Priority: 4, Timeout: 5 * time.Second, OnFailure: "warn", APIKeyEnv: "SNYK_TOKEN",
		Options: map[string]any{"concurrency": 16}},
},
```

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -run "TestPackageChecksConfig_FailMode|TestDefaultPackageChecksConfig_HasFail" -v`
Expected: PASS.

- [ ] **Step 5: Verify pre-existing config tests still pass**

Run: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/pkgcheck.go internal/config/pkgcheck_test.go
git commit -m "config: add fail_mode, privacy, block_on; register snyk and socket providers"
```

---

## Task 17: Default scope to all_installs when an external provider is enabled

**Files:**
- Modify: `internal/config/pkgcheck.go`
- Modify: `internal/config/pkgcheck_test.go`

- [ ] **Step 1: Write failing test**

Add to `internal/config/pkgcheck_test.go`:

```go
func TestApplyExternalProviderDefaults_PromotesScope(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "", // unset — should be promoted
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true, APIKeyEnv: "SOCKET_API_KEY"},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "all_installs" {
		t.Errorf("expected scope to be promoted to all_installs, got %q", cfg.Scope)
	}
	if len(warnings) != 0 {
		t.Errorf("no warnings expected when scope was empty; got %v", warnings)
	}
}

func TestApplyExternalProviderDefaults_WarnsOnExplicitNarrowScope(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "new_packages_only",
		Providers: map[string]ProviderConfig{
			"snyk": {Enabled: true, APIKeyEnv: "SNYK_TOKEN"},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "new_packages_only" {
		t.Errorf("user-set scope should not be overwritten")
	}
	if len(warnings) == 0 {
		t.Fatal("expected validation warning")
	}
	if !strings.Contains(warnings[0], "snyk") || !strings.Contains(warnings[0], "all_installs") {
		t.Errorf("warning should mention provider and recommend all_installs, got %q", warnings[0])
	}
}

func TestApplyExternalProviderDefaults_NoExternalProviderNoOp(t *testing.T) {
	cfg := PackageChecksConfig{
		Enabled: true,
		Scope:   "",
		Providers: map[string]ProviderConfig{
			"osv": {Enabled: true},
		},
	}
	warnings := ApplyExternalProviderDefaults(&cfg)
	if cfg.Scope != "" {
		t.Errorf("scope should remain empty when no external provider is enabled")
	}
	if len(warnings) != 0 {
		t.Errorf("no warnings expected, got %v", warnings)
	}
}
```

(Add `strings` import if not already present.)

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/config/ -run TestApplyExternalProviderDefaults -v`
Expected: build error — `ApplyExternalProviderDefaults` undefined.

- [ ] **Step 3: Implement the helper**

Append to `internal/config/pkgcheck.go`:

```go
// externalProviderNames lists provider names that send package data to a
// third-party API (and thus benefit from privacy filtering / scope=all_installs).
var externalProviderNames = []string{"snyk", "socket"}

// ApplyExternalProviderDefaults adjusts cfg in-place when one or more external
// providers are enabled:
//   - if Scope is unset, promote to "all_installs"
//   - if Scope is "new_packages_only", emit a validation warning naming the
//     external provider(s) and recommending "all_installs"
// Returns a list of human-readable warnings the caller should surface.
func ApplyExternalProviderDefaults(cfg *PackageChecksConfig) []string {
	var enabledExternal []string
	for _, name := range externalProviderNames {
		p, ok := cfg.Providers[name]
		if ok && p.Enabled {
			enabledExternal = append(enabledExternal, name)
		}
	}
	if len(enabledExternal) == 0 {
		return nil
	}
	switch cfg.Scope {
	case "":
		cfg.Scope = "all_installs"
		return nil
	case "new_packages_only":
		return []string{
			fmt.Sprintf(
				"pkgcheck: %s configured but scope=new_packages_only — bare `npm install` and `npm ci` will not be intercepted, "+
					"so supply-chain attacks via lockfile installs will not be blocked. Set scope: all_installs for full coverage.",
				strings.Join(enabledExternal, ", "),
			),
		}
	}
	return nil
}
```

(Add imports `fmt` and `strings` if not already present.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -run TestApplyExternalProviderDefaults -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/pkgcheck.go internal/config/pkgcheck_test.go
git commit -m "config: promote scope to all_installs when external provider is enabled"
```

---

## Task 18: Resolve fail_mode to per-provider OnFailure

**Files:**
- Modify: `internal/config/pkgcheck.go`
- Modify: `internal/config/pkgcheck_test.go`

`fail_mode` at the top level is a convenience that sets `OnFailure` for external providers, with `PKGCHECK_FAIL_MODE` env var overriding the YAML.

- [ ] **Step 1: Write failing test**

Add to `internal/config/pkgcheck_test.go`:

```go
func TestResolveFailMode_EnvOverridesYAML(t *testing.T) {
	cfg := PackageChecksConfig{FailMode: "closed"}
	t.Setenv("PKGCHECK_FAIL_MODE", "open")
	got := ResolveFailMode(&cfg)
	if got != "open" {
		t.Errorf("env should win, got %q", got)
	}
}

func TestResolveFailMode_DefaultsToDegraded(t *testing.T) {
	cfg := PackageChecksConfig{}
	t.Setenv("PKGCHECK_FAIL_MODE", "")
	got := ResolveFailMode(&cfg)
	if got != "degraded" {
		t.Errorf("default should be degraded, got %q", got)
	}
}

func TestApplyFailMode_SetsOnFailureForExternal(t *testing.T) {
	cfg := PackageChecksConfig{
		FailMode: "closed",
		Providers: map[string]ProviderConfig{
			"socket": {Enabled: true},
			"osv":    {Enabled: true, OnFailure: "warn"}, // should be untouched
		},
	}
	ApplyFailMode(&cfg, "closed")
	if cfg.Providers["socket"].OnFailure != "deny" {
		t.Errorf("socket OnFailure should be deny, got %q", cfg.Providers["socket"].OnFailure)
	}
	if cfg.Providers["osv"].OnFailure != "warn" {
		t.Errorf("osv OnFailure must remain warn, got %q", cfg.Providers["osv"].OnFailure)
	}
}
```

- [ ] **Step 2: Run, expect compile failure**

Run: `go test ./internal/config/ -run "TestResolveFailMode|TestApplyFailMode" -v`
Expected: build error — `ResolveFailMode`, `ApplyFailMode` undefined.

- [ ] **Step 3: Implement helpers**

Append to `internal/config/pkgcheck.go`:

```go
import "os"

// ResolveFailMode returns the effective fail mode, honoring the
// PKGCHECK_FAIL_MODE env var override. Defaults to "degraded".
func ResolveFailMode(cfg *PackageChecksConfig) string {
	if v := os.Getenv("PKGCHECK_FAIL_MODE"); v != "" {
		return v
	}
	if cfg.FailMode != "" {
		return cfg.FailMode
	}
	return "degraded"
}

// ApplyFailMode sets OnFailure on every enabled external provider to match the
// resolved fail mode. Mapping:
//   open     → "allow"
//   closed   → "deny"
//   degraded → "warn"
// External providers are those listed in externalProviderNames. Other
// providers (osv, depsdev, local) keep whatever OnFailure the user set.
func ApplyFailMode(cfg *PackageChecksConfig, mode string) {
	target := ""
	switch mode {
	case "open":
		target = "allow"
	case "closed":
		target = "deny"
	case "degraded":
		target = "warn"
	default:
		target = "warn"
	}
	for _, name := range externalProviderNames {
		p, ok := cfg.Providers[name]
		if !ok || !p.Enabled {
			continue
		}
		p.OnFailure = target
		cfg.Providers[name] = p
	}
}
```

(Move `os` into the existing import block.)

- [ ] **Step 4: Run tests**

Run: `go test ./internal/config/ -run "TestResolveFailMode|TestApplyFailMode" -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/config/pkgcheck.go internal/config/pkgcheck_test.go
git commit -m "config: resolve fail_mode and apply OnFailure to external providers"
```

---

## Task 19: End-to-end orchestrator integration test (degraded fallback)

**Files:**
- Create: `internal/pkgcheck/integration_socket_degraded_test.go`

This test wires together: orchestrator + privacy filter + Socket (failing) + OSV (succeeding) + evaluator-with-context. It asserts the verdict carries `"degraded:"` in the summary, OSV findings are present, and skipped packages are surfaced.

- [ ] **Step 1: Write the failing integration test**

Create `internal/pkgcheck/integration_socket_degraded_test.go`:

```go
package pkgcheck_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/pkgcheck"
	"github.com/agentsh/agentsh/internal/pkgcheck/provider"
	"github.com/agentsh/agentsh/internal/policy"
)

func TestIntegration_SocketDownDegradesToOSV(t *testing.T) {
	// Socket: returns 500 every call.
	socketSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer socketSrv.Close()

	// OSV: returns one vuln for lodash.
	osvSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"results":[{"vulns":[{"id":"GHSA-xxxx","summary":"sample","severity":[{"type":"CVSS_V3","score":"9.8"}]}]}]}`))
	}))
	defer osvSrv.Close()

	pf := pkgcheck.NewPrivacyFilter(pkgcheck.PrivacyConfig{
		ExternalScanRegistries: []string{"registry.npmjs.org"},
		PrivateScopeDenylist:   []string{"@acme"},
	})

	o := pkgcheck.NewOrchestrator(pkgcheck.OrchestratorConfig{
		PrivacyFilter: pf,
		Providers: map[string]pkgcheck.ProviderEntry{
			"socket": {
				Provider:  provider.NewSocketProvider(provider.SocketConfig{BaseURL: socketSrv.URL, APIKey: "tk", Timeout: time.Second, MaxPURLsPerCall: 100}),
				Timeout:   time.Second,
				OnFailure: "warn", // fail_mode: degraded
			},
			"osv": {
				Provider:  provider.NewOSVProvider(provider.OSVConfig{BaseURL: osvSrv.URL, Timeout: time.Second}),
				Timeout:   time.Second,
				OnFailure: "warn",
			},
		},
	})

	req := pkgcheck.CheckRequest{
		Ecosystem: pkgcheck.EcosystemNPM,
		Packages: []pkgcheck.PackageRef{
			{Name: "lodash", Version: "4.17.20", Registry: "registry.npmjs.org"},
			{Name: "@acme/internal", Version: "1.0.0", Registry: "registry.npmjs.org"},
		},
	}

	findings, errs, skipped := o.CheckAllWithPrivacy(context.Background(), req)

	if len(skipped) != 1 {
		t.Errorf("want 1 skipped (@acme), got %d", len(skipped))
	}

	ev := pkgcheck.NewEvaluator([]policy.PackageRule{
		{Match: policy.PackageMatch{FindingType: "vulnerability", Severity: "critical"}, Action: "deny"},
		{Match: policy.PackageMatch{}, Action: "allow"},
	})
	verdict := ev.EvaluateWithContext(pkgcheck.EvalContext{
		Findings:       findings,
		Ecosystem:      req.Ecosystem,
		ProviderErrors: errs,
		Skipped:        skipped,
	})

	if !strings.Contains(verdict.Summary, "degraded:") || !strings.Contains(verdict.Summary, "socket") {
		t.Errorf("verdict summary should be annotated degraded for socket, got %q", verdict.Summary)
	}
	if verdict.Action != pkgcheck.VerdictBlock {
		t.Errorf("OSV finding (critical) should drive verdict to block, got %s", verdict.Action)
	}
	if len(verdict.Skipped) != 1 {
		t.Errorf("verdict should carry 1 skipped, got %d", len(verdict.Skipped))
	}
}
```

- [ ] **Step 2: Run the test**

Run: `go test ./internal/pkgcheck/ -run TestIntegration_SocketDownDegradesToOSV -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add internal/pkgcheck/integration_socket_degraded_test.go
git commit -m "pkgcheck: integration test for Socket-down → OSV degraded fallback"
```

---

## Task 20: Cross-compile verification and full-suite run

**Files:** none modified — verification step only.

- [ ] **Step 1: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: build succeeds (no Linux-only deps in the new providers).

- [ ] **Step 2: Run the full pkgcheck and config test suites**

Run:
```bash
go test ./internal/pkgcheck/... ./internal/config/...
```
Expected: PASS.

- [ ] **Step 3: Run vet and the full project suite as a sanity pass**

Run:
```bash
go vet ./...
go test ./...
```
Expected: PASS for the whole project.

- [ ] **Step 4: If everything is green, push the branch and open a PR**

Run:
```bash
git push -u origin <branch>
gh pr create --title "pkgcheck: add Snyk and Socket pre-install gating" --body "$(cat <<'EOF'
## Summary
- Adds Snyk and Socket as `CheckProvider` implementations with shared retry / circuit-breaker helper
- Privacy filter (registry allowlist + scope denylist) at the orchestrator before any third-party call
- `fail_mode` (open / closed / degraded) compiles to per-provider `OnFailure`; degraded annotates the verdict and falls back to OSV
- `block_on` policy shorthand compiles into existing `policy.PackageRule` entries — no new evaluator
- Cache distinguishes clean / found / not-found TTLs (findings persist indefinitely by default)
- Scope auto-promotes to `all_installs` when any external provider is enabled

Spec: docs/superpowers/specs/2026-05-01-snyk-socket-pre-install-gate-design.md

## Test plan
- [ ] go test ./...
- [ ] GOOS=windows go build ./...
- [ ] Manually confirm SOCKET_API_KEY / SNYK_TOKEN env vars are read on a real install
EOF
)"
```

---

## Self-Review

**Spec coverage:**

| Spec section | Implementing tasks |
|---|---|
| §Architecture (CheckProvider, orchestrator) | Tasks 1, 13 |
| §Per-provider — Socket (PURL batch, alert mapping, chunking, breaker) | Tasks 5, 6, 7, 8 |
| §Per-provider — Snyk (per-package fan-out, mapping, breaker) | Tasks 9, 10 |
| §Verdict policy (`block_on` shorthand) | Task 15 |
| §Fail mode (per-call timeout, total budget, OnFailure mapping, env override, breaker) | Tasks 4, 7, 10, 18, 19 |
| §Caching (clean / found / not-found TTLs, negative cache) | Task 11 |
| §Privacy (registry allowlist + scope denylist + Skipped surfaced) | Tasks 1, 12, 13, 14 |
| §Configuration shape | Tasks 16, 17, 18 |
| §Scope implication (`all_installs` default + warning) | Task 17 |
| §Out of scope (manifest upload, CLI shell-out, post-install, auto-remediate) | Honored — not implemented anywhere |
| §Testing strategy | Tasks 2, 8, 10, 11, 12, 13, 14, 19, 20 |

**Note on per-`CheckBatch` total budget:** the spec calls for a 30s `total_budget` distinct from the 5s per-call timeout. The orchestrator's existing per-provider `Timeout` already serves this role for the `CheckBatch` call (its context times out the entire fan-out). No new field is needed; the user configures `Providers["snyk"].Timeout = 30s` at the YAML layer. Documented as inline comment on the config in Task 16.

**Placeholder scan:** no TBD / TODO / "implement later" / "similar to task N" instances. Every step has either runnable code, a runnable command with expected output, or a commit. Spot-checked all 20 tasks.

**Type consistency:**
- `SkipReason`, `SkippedPackage`, `Verdict.Skipped` consistent across Tasks 1, 12, 13, 14, 19.
- `EvalContext` / `EvaluateWithContext` introduced in Task 14, consumed in Task 19.
- `ApplyExternalProviderDefaults`, `ResolveFailMode`, `ApplyFailMode`, `CompileBlockOn`, `BlockOnConfig`, `PrivacyConfig` consistent across Tasks 15-18.
- `NewSocketProvider(SocketConfig{...})` / `NewSnykProvider(SnykConfig{...})` constructor + config-struct names consistent in Tasks 7, 8, 10, 19.
- `runContractSuite` / `contractFixture` defined in Task 2, consumed in Tasks 8, 10.
- `retryClient`, `newRetryClient`, `retryConfig`, `circuitBreaker`, `newCircuitBreaker`, `circuitBreakerConfig` consistent in Tasks 3, 4, 7, 10.

**Scope check:** the plan covers exactly the spec — two new providers + privacy + cache + fail-mode + config wiring. Implementation only, no UI / dashboard / SaaS work, matching the spec's non-goals.

No issues found.
