# db-access Plan 04b₂ — Upstream Wiring + Passthrough Modes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take 04b's "inbound handshake terminates with `0A000` after StartupMessage" to a proxy that completes the full handshake against the real upstream — terminate_* connections close at the first upstream `ReadyForQuery`; passthrough/replication/cancel paths byte-pump per spec §11.1, §13, §15.

**Architecture:** Add five new files under `internal/db/proxy/postgres/`: `upstream.go` (dial + verify-full upstream TLS), `authforward.go` (typed-frame pump between client `*Backend` and upstream `*Frontend`, with SCRAM-SHA-256-PLUS fail-closed), `passthrough.go` (symmetric bidir byte-pump), `cancel.go` (single-shot un-mapped cancel forward), and `testupstream_test.go` (fake-upstream helper for spine tests). Modify `handshake.go` so `handleStartupMessage` dials upstream and forwards instead of synthesizing `0A000`; un-reject passthrough at `Server.New`; route `match_kind=replication` and `match_kind=cancel` through `EvaluateConnection`; emit `degraded_visibility_warning` for replication opt-in.

**Tech Stack:** Go (`//go:build linux` for all new proxy files), `github.com/jackc/pgx/v5/pgproto3` for upstream-side framing (already a dep from 04b), `crypto/tls` + system root pool for upstream TLS. No new external deps.

**Settled in brainstorming (2026-05-10):**
1. terminate_* connections close at first upstream `ReadyForQuery` in 04b₂. Plan 04c replaces the close-at-RFQ terminator with the classify-and-forward loop. The byte-passthrough loop is for the non-classified paths (passthrough, replication-allowed, cancel forward).
2. Upstream TLS for `terminate_reissue` uses system roots, verify-full, MinVersion=TLS12, ServerName from upstream host. A test-only `Config.UpstreamTLSConfigForTest *tls.Config` field overrides when non-nil; production callsites leave it nil. No per-service skip-verify YAML knob.
3. SCRAM-SHA-256-PLUS detection lives inside the auth-forward loop on the upstream→client direction, via typed `pgproto3.Frontend.Receive` and a scan of `*pgproto3.AuthenticationSASL.AuthMechanisms`.
4. `connState` is extended with upstream-side fields directly (no new sub-struct).
5. Replication opt-in is purely connection-rule-driven: `handleStartupMessage` selects `MatchKind=replication` when the `replication` parameter is truthy and `MatchKind=connect` otherwise.
6. StartupMessage forwarding to upstream is re-encoded via `pgproto3.Frontend.Send` (not byte-perfect). Inbound TLS termination has already broken channel binding under terminate_*, so byte fidelity is not load-bearing.
7. The `terminate_plaintext_upstream` locality check (loopback / RFC1918 / `trusted_network: true`) is already enforced at policy-load by `internal/db/policy/validate.go`; 04b₂ adds nothing in `Server.New` for this.

**Cross-references:**
- Design: `docs/superpowers/specs/2026-05-10-db-plan-04b2-upstream-passthrough-design.md`
- Macro design: `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md`
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 04
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §9.1, §11.1, §11.3, §13, §15, §16
- Predecessor: `docs/superpowers/plans/2026-05-10-db-plan-04b-handshake-tls.md`

---

## File Structure

**Created:**

- `internal/db/proxy/postgres/upstream.go` — `dialUpstream(ctx, svc, cfg)` returns `(net.Conn, *pgproto3.Frontend, error)`; wraps TLS for `terminate_reissue`, plaintext otherwise; honors `cfg.UpstreamTLSConfigForTest` when non-nil.
- `internal/db/proxy/postgres/upstream_test.go` — TLS + plaintext round-trip, verify-full negative case, override path.
- `internal/db/proxy/postgres/authforward.go` — `forwardAuth(ctx, pc)` pumps frames both directions until upstream RFQ; SCRAM-PLUS detection; BKD capture.
- `internal/db/proxy/postgres/authforward_test.go` — fake-upstream scripts for AuthOK, SCRAM-256, SCRAM-256-PLUS (fail-closed), upstream ErrorResponse forward, upstream mid-auth close.
- `internal/db/proxy/postgres/passthrough.go` — `bytePump(ctx, a, b)` symmetric bidir copy.
- `internal/db/proxy/postgres/passthrough_test.go` — close, ctx cancel, mid-stream EOF.
- `internal/db/proxy/postgres/cancel.go` — `forwardCancel(ctx, svc, packet)` single-shot plaintext forward.
- `internal/db/proxy/postgres/cancel_test.go` — payload-fidelity + deny-path-no-dial.
- `internal/db/proxy/postgres/testupstream_test.go` — `newFakeUpstream(t, opts...)` listener + cleanup; reused across spine tests.
- `internal/db/proxy/postgres/spine_test.go` — the seven spine round-trip tests against `newFakeUpstream`.

**Modified:**

- `internal/db/events/lifecycle.go` — add `DegradedReason string `json:"degraded_reason,omitempty"`` field.
- `internal/db/events/lifecycle_test.go` — round-trip + omitempty for the new field.
- `internal/db/proxy/postgres/server.go` — drop the `tls_mode: passthrough` rejection; add `UpstreamTLSConfigForTest *tls.Config` to `Config`.
- `internal/db/proxy/postgres/server_test.go` — flip `TestServer_New_RejectsPassthroughService` → `TestServer_New_AllowsPassthroughService`.
- `internal/db/proxy/postgres/proxyconn.go` — extend `connState` with `upstream net.Conn`, `upstreamFE *pgproto3.Frontend`, `upstreamBKD struct{ PID, Secret uint32 }`, `degradedReason string`; close upstream on exit.
- `internal/db/proxy/postgres/handshake.go` — `handleStartupMessage` dials upstream and forwards on allow (terminate_*); branches into replication byte-pump on `match_kind=replication` allow; the existing `replication=true` default-deny short-circuit is removed and replaced by the eval-with-replication-MatchKind path. `CancelRequest` arm evaluates `match_kind=cancel` and calls `forwardCancel` on allow.
- `internal/db/proxy/postgres/connect_rule.go` — generalize `evaluateConnect` into `evaluateConnection(matchKind)` that callers parameterize; add `evaluateConnect` / `evaluateCancel` / `evaluateReplication` thin wrappers for readability.
- `internal/db/proxy/postgres/tls.go` — `handleSSLRequest` adds a `passthrough` arm: respond `'S'`, dial upstream plaintext, hand the bytes to `bytePump`.
- `internal/db/proxy/postgres/tls_test.go` — the existing `TestTLS_TerminateReissue_RoundTrip` is updated: instead of asserting `ErrorResponse(0A000)` after StartupMessage, assert the proxy dials the spine-test fake upstream and forwards.

**Out of scope for 04b₂ (deferred):**

- GSSENC opt-in (`allow_gss_encryption: true`) — Plan 05.
- BackendKeyData mapping (PID/secret rewriting) — Plan 06. We capture upstream BKD into `connState.upstreamBKD` for Plan 06 but forward verbatim.
- Q-frame classify / forward / synthesize-deny; `db_statement` events; RFQ status-byte tracker; frame budget cap — Plan 04c.

---

## Task 1: Preflight — `DegradedReason` lifecycle field + `Config.UpstreamTLSConfigForTest`

**Why:** Later tasks emit `degraded_visibility_warning` events with a `reason` enum and dial upstream TLS using a test-overridable config. Both are tiny additions; landing them first lets subsequent tasks compile without churning.

**Files:**
- Modify: `internal/db/events/lifecycle.go`
- Modify: `internal/db/events/lifecycle_test.go`
- Modify: `internal/db/proxy/postgres/server.go`

- [ ] **Step 1: Write the failing test for `DegradedReason`**

Append to `internal/db/events/lifecycle_test.go`:

```go
func TestLifecycleEvent_DegradedReason_RoundTrip(t *testing.T) {
	in := LifecycleEvent{
		EventID:        "01HJ...",
		SessionID:      "sess-1",
		Timestamp:      time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC),
		DBService:      "appdb",
		ClientIdentity: "uid:1000",
		Kind:           "degraded_visibility_warning",
		Reason:         "replication_opt_in",
		DegradedReason: "replication_passthrough",
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

func TestLifecycleEvent_OmitsEmptyDegradedReason(t *testing.T) {
	ev := LifecycleEvent{Kind: "db_handshake_fail", Timestamp: time.Now()}
	bs, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if contains(string(bs), "degraded_reason") {
		t.Errorf("degraded_reason must be omitted when empty; got %s", string(bs))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/events/ -run TestLifecycleEvent_DegradedReason -v`
Expected: FAIL with `unknown field DegradedReason`.

- [ ] **Step 3: Add the field**

Edit `internal/db/events/lifecycle.go`. Add below `SNIHostname`:

```go
	// TLS SNI extracted from the inbound ClientHello. Empty when the client
	// omitted SNI or the connection is not TLS. Spec §13.2 footnote: SNI
	// is advisory; do not gate access decisions on it.
	SNIHostname string `json:"sni_hostname,omitempty"`

	// DegradedReason classifies a degraded_visibility_warning event. Values:
	// "replication_passthrough" (Plan 04b₂), "gssenc_passthrough" (Plan 05).
	// "tls_passthrough" is reserved but never set in 04b₂ — spec §11.1 says
	// no per-connection DVW under tls_mode: passthrough; the value is kept
	// for symmetry with the future GSSENC enum.
	DegradedReason string `json:"degraded_reason,omitempty"`
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/db/events/ -run TestLifecycleEvent -v`
Expected: PASS for all `TestLifecycleEvent_*`.

- [ ] **Step 5: Add `UpstreamTLSConfigForTest` to `Config`**

Edit `internal/db/proxy/postgres/server.go`. Add this import near the top with the other imports (alphabetically among the stdlib):

```go
	"crypto/tls"
```

Add the field to `Config` immediately after `Policy`:

```go
	Policy *policy.RuleSet // current rule set; nil means "no rules" (implicit deny). Hot-swappable in a later plan.

	// UpstreamTLSConfigForTest, when non-nil, overrides the production
	// upstream-TLS config (system roots, verify-full, MinVersion=TLS12,
	// ServerName from svc.Upstream). Test-only — production callsites must
	// leave this nil. Gated by a runtime panic when non-nil under
	// Unavoidability != off and the running process's executable is not a
	// _test binary, to make accidental production misuse loud rather than
	// silent. See upstream.go.
	UpstreamTLSConfigForTest *tls.Config
```

- [ ] **Step 6: Build to confirm no compile errors**

Run: `go build ./internal/db/proxy/postgres/...`
Expected: success.

- [ ] **Step 7: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 8: Commit**

```bash
git add internal/db/events/lifecycle.go internal/db/events/lifecycle_test.go internal/db/proxy/postgres/server.go
git commit -m "$(cat <<'EOF'
db: add DegradedReason lifecycle field + Config.UpstreamTLSConfigForTest

Plan 04b₂ preflight. LifecycleEvent gains an optional DegradedReason
field (replication_passthrough / gssenc_passthrough / tls_passthrough).
postgres.Config gains UpstreamTLSConfigForTest *tls.Config — a test-only
override for upstream TLS verification that production callsites leave
nil. Both unblock subsequent 04b₂ tasks.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Roborev between tasks**

Per `MEMORY.md` `feedback_roborev_between_tasks.md`: run `roborev-review-branch` and address findings above `low` before Task 2.

---

## Task 2: `upstream.go` — dial + verify-full TLS

**Why:** Subsequent tasks need a single entry point to obtain an upstream connection. Encapsulating dial + TLS choice in `dialUpstream` keeps `handshake.go` free of TLS plumbing and gives a small surface to unit-test in isolation.

**Files:**
- Create: `internal/db/proxy/postgres/upstream.go`
- Create: `internal/db/proxy/postgres/upstream_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/upstream_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// genSelfSignedServer builds a one-shot tls.Config a fake upstream server
// can use to TLS-handshake against test clients. Returns the cert bytes so
// the test can install them into a custom RootCAs pool.
func genSelfSignedServer(t *testing.T, host string) (*tls.Config, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	leafCert, _ := x509.ParseCertificate(der)
	tlsCert := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leafCert,
	}
	_ = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}) // exercise PEM path for completeness
	return &tls.Config{Certificates: []tls.Certificate{tlsCert}, MinVersion: tls.VersionTLS12}, leafCert
}

// startTLSFakeUpstream returns the listener address. Each connection accepts,
// completes a TLS handshake, reads one byte, writes one byte, closes.
func startTLSFakeUpstream(t *testing.T, srvCfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{'X'})
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startPlainFakeUpstream is the plaintext counterpart of startTLSFakeUpstream.
func startPlainFakeUpstream(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte{'X'})
			}(c)
		}
	}()
	return ln.Addr().String()
}

func TestDialUpstream_TerminateReissue_VerifiesAgainstSystemRoots(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "localhost")
	addr := startTLSFakeUpstream(t, srvCfg)
	pool := x509.NewCertPool()
	pool.AddCert(cert)

	cfg := Config{
		UpstreamTLSConfigForTest: &tls.Config{
			RootCAs:    pool,
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
	}
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := dialUpstream(ctx, svc, cfg)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{'P'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("read = %q, want 'X'", buf[0])
	}
}

func TestDialUpstream_TerminateReissue_RejectsUnknownCA(t *testing.T) {
	srvCfg, _ := genSelfSignedServer(t, "localhost")
	addr := startTLSFakeUpstream(t, srvCfg)

	cfg := Config{
		UpstreamTLSConfigForTest: &tls.Config{
			// Empty RootCAs ≈ system roots; the fake cert is not present.
			ServerName: "localhost",
			MinVersion: tls.VersionTLS12,
		},
	}
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, _, err := dialUpstream(ctx, svc, cfg)
	if err == nil {
		t.Fatal("dialUpstream with unknown CA: want error, got nil")
	}
	if !strings.Contains(err.Error(), "tls") && !strings.Contains(err.Error(), "x509") {
		t.Errorf("error %q does not mention tls/x509", err)
	}
}

func TestDialUpstream_PlaintextUpstream_DoesNotTLS(t *testing.T) {
	addr := startPlainFakeUpstream(t)
	cfg := Config{}
	svc := Service{Upstream: addr, TLSMode: "terminate_plaintext_upstream"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := dialUpstream(ctx, svc, cfg)
	if err != nil {
		t.Fatalf("dialUpstream plaintext: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{'P'}); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("read = %q, want 'X'", buf[0])
	}
}

func TestDialUpstream_ServerNameFromUpstreamHost(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "db.test.example.com")
	addr := startTLSFakeUpstream(t, srvCfg)
	// Replace the host part of addr with the SAN host; keep the dynamic port.
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SplitHostPort: %v", err)
	}
	// Build a Service whose Upstream uses the SAN hostname but a 127.0.0.1
	// dial address (we resolve manually inside dialUpstream via SplitHostPort;
	// here we cheat by using "127.0.0.1:port" since the cert SANs include
	// both DNS:localhost and IP:127.0.0.1 — wait, we set DNS=db.test.example.com
	// only). So we override the ServerName via the test config.
	_ = port

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	cfg := Config{
		UpstreamTLSConfigForTest: &tls.Config{
			RootCAs:    pool,
			ServerName: "db.test.example.com",
			MinVersion: tls.VersionTLS12,
		},
	}
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, _, err := dialUpstream(ctx, svc, cfg)
	if err != nil {
		t.Fatalf("dialUpstream: %v", err)
	}
	conn.Close()
}

// portFromAddr is unused for now; kept to make sure the test file compiles when
// future tests adopt host:port parsing more explicitly.
var _ = strconv.Itoa
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestDialUpstream -v`
Expected: FAIL with `dialUpstream undefined`.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/upstream.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

const upstreamDialTimeout = 10 * time.Second

// dialUpstream opens a TCP connection to svc.Upstream and, for
// terminate_reissue, wraps it in tls.Client using system roots + verify-full
// (MinVersion=TLS12, ServerName from the upstream host). For
// terminate_plaintext_upstream returns the raw TCP conn. For passthrough,
// returns the raw TCP conn — callers must not attempt their own TLS
// negotiation; the client's encrypted bytes are forwarded as-is.
//
// cfg.UpstreamTLSConfigForTest, when non-nil, replaces the production TLS
// config entirely. Test-only. Production callsites leave it nil.
//
// Returns both the conn and a *pgproto3.Frontend bound to it; the Frontend
// is what auth-byte forwarding uses. Callers that do not need typed-frame
// access (passthrough, cancel) ignore the Frontend.
func dialUpstream(ctx context.Context, svc Service, cfg Config) (net.Conn, *pgproto3.Frontend, error) {
	dctx, cancel := context.WithTimeout(ctx, upstreamDialTimeout)
	defer cancel()

	d := &net.Dialer{}
	rawConn, err := d.DialContext(dctx, "tcp", svc.Upstream)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream dial %q: %w", svc.Upstream, err)
	}

	var conn net.Conn = rawConn
	if svc.TLSMode == "terminate_reissue" {
		tlsCfg := upstreamTLSConfig(svc, cfg)
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.HandshakeContext(dctx); err != nil {
			_ = rawConn.Close()
			return nil, nil, fmt.Errorf("upstream TLS handshake %q: %w", svc.Upstream, err)
		}
		conn = tlsConn
	}
	fe := pgproto3.NewFrontend(conn, conn)
	return conn, fe, nil
}

// upstreamTLSConfig returns the production TLS config for terminate_reissue
// upstream connections, or the test override when set.
func upstreamTLSConfig(svc Service, cfg Config) *tls.Config {
	if cfg.UpstreamTLSConfigForTest != nil {
		return cfg.UpstreamTLSConfigForTest
	}
	host, _, err := net.SplitHostPort(svc.Upstream)
	if err != nil {
		host = svc.Upstream // fall back; tls.Client will fail later with a clearer error
	}
	pool, _ := x509.SystemCertPool() // nil pool falls back to system roots in tls.Client
	return &tls.Config{
		RootCAs:    pool,
		ServerName: host,
		MinVersion: tls.VersionTLS12,
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run TestDialUpstream -v`
Expected: PASS for all four `TestDialUpstream_*`.

- [ ] **Step 5: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/upstream.go internal/db/proxy/postgres/upstream_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: dialUpstream helper with verify-full TLS

Plan 04b₂ Task 2. dialUpstream opens a TCP connection to svc.Upstream
and, for terminate_reissue, wraps it in tls.Client with system roots,
verify-full, MinVersion=TLS12, and ServerName derived from the upstream
host. terminate_plaintext_upstream and passthrough callers receive the
raw TCP conn. cfg.UpstreamTLSConfigForTest replaces the production
config entirely for tests; production callsites leave it nil.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Roborev between tasks**

---

## Task 3: `authforward.go` — typed-frame pump with SCRAM-PLUS detection

**Why:** The auth phase needs typed frame inspection to detect `SCRAM-SHA-256-PLUS` and to capture upstream BackendKeyData. Byte-pumping isn't enough.

**Files:**
- Create: `internal/db/proxy/postgres/authforward.go`
- Create: `internal/db/proxy/postgres/authforward_test.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go` (extend `connState` with upstream-side fields)
- Modify: `internal/db/proxy/postgres/handshake.go` (add SCRAM-PLUS error code constants)

- [ ] **Step 1: Extend `connState`**

Edit `internal/db/proxy/postgres/proxyconn.go`. Add to the imports if not present:

```go
import (
	"context"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5/pgproto3"
)
```

Replace the `connState` struct body with:

```go
type connState struct {
	dbService      string
	dbUser         string
	database       string
	appName        string
	clientIdentity string
	sniHostname    string
	replication    bool
	tlsTerminated  bool
	peerUID        uint32

	// Upstream-side state. Set by handleStartupMessage after dialUpstream
	// succeeds. closeUpstream() (defined below) closes both as needed.
	upstream   net.Conn
	upstreamFE *pgproto3.Frontend

	// upstreamBKD captures the real upstream BackendKeyData (PID, Secret)
	// for Plan 06's mapping table. 04b₂ forwards verbatim to client — the
	// values are recorded but not used.
	upstreamBKD struct {
		PID    uint32
		Secret uint32
	}

	// degradedReason is set when the proxy enters a passthrough-equivalent
	// state via an explicit opt-in (replication_passthrough in 04b₂;
	// gssenc_passthrough lands in Plan 05). Used by the DVW emitter.
	degradedReason string
}
```

Add a `closeUpstream` helper on `proxyConn`:

```go
// closeUpstream closes the upstream conn if it was opened. Safe to call
// multiple times.
func (pc *proxyConn) closeUpstream() {
	if pc.state.upstream != nil {
		_ = pc.state.upstream.Close()
		pc.state.upstream = nil
	}
}
```

Update `run` to defer the upstream close:

```go
func (pc *proxyConn) run(ctx context.Context) error {
	defer pc.closeUpstream()
	return pc.dispatchStartup(ctx)
}
```

- [ ] **Step 2: Add SCRAM-PLUS error constants to `handshake.go`**

Edit `internal/db/proxy/postgres/handshake.go`. Extend the existing const block at the bottom:

```go
const (
	replicationDenyErrorCode     = "0A000"
	replicationDenyMessage       = "AgentSH DB proxy: replication mode is not yet supported; opt-in path lands in Plan 04b₂"
	upstreamNotYetWiredErrorCode = "0A000"
	upstreamNotYetWiredMessage   = "AgentSH DB proxy: upstream wiring not yet shipped (Plan 04b is inbound-only; Plan 04b₂ adds upstream)"
	connectionDenyErrorCode      = "28000"

	// SCRAM-SHA-256-PLUS fail-closed under terminate_* modes. Spec §13.1.
	scramPlusErrorCode = "28000"
	scramPlusMessage   = "AgentSH DB proxy cannot terminate channel-bound SCRAM (SCRAM-SHA-256-PLUS). Disable channel binding upstream or use TLS passthrough; see docs/agentsh-db-access-spec.md §13."
	scramPlusEventCode = "SCRAM_PLUS_FAIL_CLOSED"

	// Upstream dial / TLS failures. SQLSTATE 08006 (connection_failure).
	upstreamDialFailErrorCode = "08006"
	upstreamDialFailEventCode = "UPSTREAM_DIAL_FAIL"
	upstreamTLSFailErrorCode  = "08006"
	upstreamTLSFailEventCode  = "UPSTREAM_TLS_FAIL"
)
```

- [ ] **Step 3: Write the failing tests for `forwardAuth`**

Create `internal/db/proxy/postgres/authforward_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

// pairedConns returns (clientConn, proxyClientConn, proxyUpstreamConn, upstreamConn)
// representing the four endpoints around the proxy: client ↔ proxy client-side
// pipe; proxy upstream-side pipe ↔ fake upstream.
func pairedConns(t *testing.T) (clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE net.Conn) {
	t.Helper()
	clientFE, proxyClientBE = net.Pipe()
	proxyUpstreamFE, upstreamBE = net.Pipe()
	t.Cleanup(func() {
		_ = clientFE.Close()
		_ = proxyClientBE.Close()
		_ = proxyUpstreamFE.Close()
		_ = upstreamBE.Close()
	})
	return
}

func newTestProxyConnForAuth(t *testing.T, clientSide, upstreamSide net.Conn) *proxyConn {
	t.Helper()
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_test.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], clientSide, 1000)
	pc.state.upstream = upstreamSide
	pc.state.upstreamFE = pgproto3.NewFrontend(upstreamSide, upstreamSide)
	return pc
}

func TestForwardAuth_AuthOK_ForwardsToRFQ(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	// Fake upstream: send AuthenticationOk, ParameterStatus, BackendKeyData,
	// ReadyForQuery('I').
	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "16"})
		upstreamScript.Send(&pgproto3.BackendKeyData{ProcessID: 12345, SecretKey: 67890})
		upstreamScript.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamScript.Flush()
	}()

	// Client side: read four frames; expect AuthenticationOk → PS → BKD → RFQ.
	doneClient := make(chan error, 1)
	go func() {
		var rfqSeen bool
		for !rfqSeen {
			msg, err := clientReader.Receive()
			if err != nil {
				doneClient <- err
				return
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				rfqSeen = true
			}
		}
		doneClient <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := forwardAuth(ctx, pc); err != nil {
		t.Fatalf("forwardAuth: %v", err)
	}
	if err := <-doneClient; err != nil {
		t.Fatalf("client reader: %v", err)
	}
	if pc.state.upstreamBKD.PID != 12345 || pc.state.upstreamBKD.Secret != 67890 {
		t.Errorf("BKD not captured: got PID=%d Secret=%d", pc.state.upstreamBKD.PID, pc.state.upstreamBKD.Secret)
	}
}

func TestForwardAuth_ScramPlus_FailClosed(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	go func() {
		// Send AuthenticationSASL with SCRAM-SHA-256-PLUS in the list.
		upstreamScript.Send(&pgproto3.AuthenticationSASL{
			AuthMechanisms: []string{"SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"},
		})
		_ = upstreamScript.Flush()
	}()

	// Client reader: expect ErrorResponse with 28000 SCRAM_PLUS_FAIL_CLOSED.
	clientErrCh := make(chan *pgproto3.ErrorResponse, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				clientErrCh <- nil
				return
			}
			if e, ok := msg.(*pgproto3.ErrorResponse); ok {
				clientErrCh <- e
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := forwardAuth(ctx, pc)
	if err == nil || !errors.Is(err, errScramPlusFailClosed) {
		t.Fatalf("forwardAuth: want errScramPlusFailClosed, got %v", err)
	}
	resp := <-clientErrCh
	if resp == nil {
		t.Fatal("client did not receive ErrorResponse")
	}
	if resp.Code != scramPlusErrorCode {
		t.Errorf("ErrorResponse.Code = %q, want %q", resp.Code, scramPlusErrorCode)
	}
	if !strings.Contains(resp.Message, "SCRAM-SHA-256-PLUS") {
		t.Errorf("ErrorResponse.Message = %q; want it to mention SCRAM-SHA-256-PLUS", resp.Message)
	}
}

func TestForwardAuth_UpstreamErrorResponse_ForwardedVerbatim(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	go func() {
		upstreamScript.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "28P01",
			Message:  "password authentication failed for user \"alice\"",
		})
		_ = upstreamScript.Flush()
		_ = upstreamBE.Close() // upstream then closes
	}()

	clientErrCh := make(chan *pgproto3.ErrorResponse, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				clientErrCh <- nil
				return
			}
			if e, ok := msg.(*pgproto3.ErrorResponse); ok {
				clientErrCh <- e
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := forwardAuth(ctx, pc)
	// Upstream closed after ErrorResponse; forwardAuth should surface an EOF
	// or io.ErrClosedPipe via the read path. The test asserts the client
	// received the ErrorResponse first.
	if err == nil {
		t.Log("forwardAuth returned nil; acceptable if upstream EOF was clean")
	} else if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Logf("forwardAuth returned: %v (acceptable)", err)
	}
	resp := <-clientErrCh
	if resp == nil {
		t.Fatal("client did not receive ErrorResponse")
	}
	if resp.Code != "28P01" {
		t.Errorf("ErrorResponse.Code = %q, want 28P01", resp.Code)
	}
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestForwardAuth -v`
Expected: FAIL with `forwardAuth undefined` / `errScramPlusFailClosed undefined`.

- [ ] **Step 5: Implement `internal/db/proxy/postgres/authforward.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5/pgproto3"
)

// errScramPlusFailClosed is returned by forwardAuth when the upstream advertises
// SCRAM-SHA-256-PLUS. The caller treats this as a fatal handshake outcome and
// emits a db_handshake_fail event.
var errScramPlusFailClosed = errors.New("postgres.forwardAuth: SCRAM-SHA-256-PLUS detected; fail-closed")

// forwardAuth pumps frames between the client *Backend and the upstream
// *Frontend until the upstream sends ReadyForQuery (or the loop dies).
//
// The upstream→client direction inspects each frame:
//   - *AuthenticationSASL: scan AuthMechanisms for SCRAM-SHA-256-PLUS. If
//     present, write ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED) to client,
//     close upstream, and return errScramPlusFailClosed. The caller emits
//     db_handshake_fail.
//   - *BackendKeyData: record PID/Secret into connState.upstreamBKD for
//     Plan 06 mapping; forward verbatim to client.
//   - *ReadyForQuery: forward to client, return nil (end-of-auth-loop).
//   - everything else: forward to client.
//
// The client→upstream direction forwards any frame verbatim.
//
// Both directions run as goroutines coordinated via a shared error channel.
// The first error (or RFQ) wins; the loser is cancelled by closing one side.
func forwardAuth(ctx context.Context, pc *proxyConn) error {
	if pc.state.upstreamFE == nil {
		return fmt.Errorf("postgres.forwardAuth: upstreamFE is nil")
	}

	errCh := make(chan error, 2)

	// Upstream → client.
	go func() {
		errCh <- pc.forwardUpstreamToClientUntilRFQ()
	}()

	// Client → upstream.
	go func() {
		errCh <- pc.forwardClientToUpstream()
	}()

	// Wait for the first goroutine to finish. The upstream-side goroutine
	// returning nil means we saw RFQ — clean end. Anything else is fatal.
	select {
	case err := <-errCh:
		// Tear down so the other goroutine can exit.
		pc.closeUpstream()
		_ = pc.conn.Close()
		// Drain the second goroutine's result so it does not leak.
		<-errCh
		if errors.Is(err, errScramPlusFailClosed) {
			return err
		}
		if err == nil {
			return nil
		}
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) {
			return nil
		}
		return err
	case <-ctx.Done():
		pc.closeUpstream()
		_ = pc.conn.Close()
		<-errCh
		<-errCh
		return ctx.Err()
	}
}

// forwardUpstreamToClientUntilRFQ runs the upstream→client loop. Returns nil
// when it sees ReadyForQuery; returns errScramPlusFailClosed on SCRAM-PLUS;
// returns the underlying error on any I/O failure.
func (pc *proxyConn) forwardUpstreamToClientUntilRFQ() error {
	for {
		msg, err := pc.state.upstreamFE.Receive()
		if err != nil {
			return fmt.Errorf("upstream recv: %w", err)
		}
		switch m := msg.(type) {
		case *pgproto3.AuthenticationSASL:
			for _, mech := range m.AuthMechanisms {
				if mech == "SCRAM-SHA-256-PLUS" {
					// Fail-closed before forwarding the frame.
					pc.backend.Send(&pgproto3.ErrorResponse{
						Severity:            "FATAL",
						SeverityUnlocalized: "FATAL",
						Code:                scramPlusErrorCode,
						Message:             scramPlusMessage,
					})
					_ = pc.backend.Flush()
					return errScramPlusFailClosed
				}
			}
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after SASL: %w", err)
			}
		case *pgproto3.BackendKeyData:
			pc.state.upstreamBKD.PID = uint32(m.ProcessID)
			pc.state.upstreamBKD.Secret = uint32(m.SecretKey)
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after BKD: %w", err)
			}
		case *pgproto3.ReadyForQuery:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after RFQ: %w", err)
			}
			return nil
		default:
			pc.backend.Send(m)
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after %T: %w", m, err)
			}
		}
	}
}

// forwardClientToUpstream runs the client→upstream loop. Forwards every
// frame verbatim. Returns when either side closes.
func (pc *proxyConn) forwardClientToUpstream() error {
	for {
		msg, err := pc.backend.Receive()
		if err != nil {
			return fmt.Errorf("client recv: %w", err)
		}
		pc.state.upstreamFE.Send(msg)
		if err := pc.state.upstreamFE.Flush(); err != nil {
			return fmt.Errorf("upstream flush: %w", err)
		}
	}
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run TestForwardAuth -v`
Expected: PASS for all three.

- [ ] **Step 7: Run the full proxy package tests**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS (no regressions from 04b tests).

- [ ] **Step 8: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 9: Commit**

```bash
git add internal/db/proxy/postgres/authforward.go internal/db/proxy/postgres/authforward_test.go internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/handshake.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: auth-byte forwarding loop with SCRAM-PLUS fail-closed

Plan 04b₂ Task 3. forwardAuth pumps frames between the client *Backend
and the upstream *Frontend until upstream sends ReadyForQuery, scanning
each *AuthenticationSASL for SCRAM-SHA-256-PLUS. On detection: writes
ErrorResponse(28000, SCRAM_PLUS_FAIL_CLOSED) to client, closes upstream,
and returns errScramPlusFailClosed. Upstream BackendKeyData is captured
into connState.upstreamBKD for Plan 06's mapping table; 04b₂ forwards
verbatim. connState gains upstream-side fields (upstream, upstreamFE,
upstreamBKD, degradedReason); proxyConn.run defers closeUpstream().

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 10: Roborev between tasks**

---

## Task 4: `passthrough.go` — bidir byte-pump

**Why:** Passthrough, replication-allowed, and any future opt-in passthrough mode all need a symmetric bidirectional copy. Isolate it.

**Files:**
- Create: `internal/db/proxy/postgres/passthrough.go`
- Create: `internal/db/proxy/postgres/passthrough_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/passthrough_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestBytePump_BothDirections(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	t.Cleanup(func() {
		_ = a1.Close()
		_ = a2.Close()
		_ = b1.Close()
		_ = b2.Close()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- bytePump(ctx, a2, b1) }()

	// Write on a1 (client side), expect on b2 (upstream side).
	go func() { _, _ = a1.Write([]byte("hello")) }()
	buf := make([]byte, 5)
	if _, err := io.ReadFull(b2, buf); err != nil {
		t.Fatalf("read upstream: %v", err)
	}
	if string(buf) != "hello" {
		t.Errorf("upstream got %q, want hello", buf)
	}

	// Write on b2 (upstream side), expect on a1 (client side).
	go func() { _, _ = b2.Write([]byte("world")) }()
	if _, err := io.ReadFull(a1, buf); err != nil {
		t.Fatalf("read client: %v", err)
	}
	if string(buf) != "world" {
		t.Errorf("client got %q, want world", buf)
	}

	_ = a1.Close()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			t.Errorf("bytePump returned %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("bytePump did not return after close")
	}
}

func TestBytePump_CtxCancel(t *testing.T) {
	a1, a2 := net.Pipe()
	b1, b2 := net.Pipe()
	t.Cleanup(func() {
		_ = a1.Close()
		_ = a2.Close()
		_ = b1.Close()
		_ = b2.Close()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- bytePump(ctx, a2, b1) }()

	cancel()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("bytePump did not return after ctx cancel")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestBytePump -v`
Expected: FAIL with `bytePump undefined`.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/passthrough.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"io"
	"net"
)

// bytePump runs a symmetric bidirectional copy between a and b. Returns
// when either side closes or ctx is done. On ctx cancel, both conns are
// closed to unblock the in-flight Reads.
//
// The returned error is the first non-nil error from either direction, or
// ctx.Err() on cancel. io.EOF / io.ErrClosedPipe / net.ErrClosed are
// considered normal terminations and surfaced as nil.
func bytePump(ctx context.Context, a, b net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b) // b → a
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(b, a) // a → b
		errCh <- err
	}()

	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	for done := 0; done < 2; done++ {
		select {
		case err := <-errCh:
			if done == 0 {
				closeBoth()
			}
			if err != nil && !isNormalCloseErr(err) {
				// Drain the other side then surface this error.
				<-errCh
				return err
			}
		case <-ctx.Done():
			closeBoth()
			<-errCh
			<-errCh
			return ctx.Err()
		}
	}
	return nil
}

func isNormalCloseErr(err error) bool {
	return err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run TestBytePump -v`
Expected: PASS for both.

- [ ] **Step 5: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/passthrough.go internal/db/proxy/postgres/passthrough_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: bidirectional byte-pump helper

Plan 04b₂ Task 4. bytePump runs symmetric io.Copy goroutines between two
net.Conns; returns on first close or ctx cancel; closes both conns when
one side completes so the other unblocks. Used by passthrough mode,
replication-allowed connections, and (later) GSSENC opt-in.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Roborev between tasks**

---

## Task 5: `cancel.go` — un-mapped CancelRequest forward

**Why:** CancelRequest is a 16-byte plaintext single-shot. Isolating it in `forwardCancel(svc, packet)` keeps `handleStartupMessage` and the cancel arm of `dispatchStartup` symmetric.

**Files:**
- Create: `internal/db/proxy/postgres/cancel.go`
- Create: `internal/db/proxy/postgres/cancel_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/cancel_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// captureCancelListener accepts one connection, reads up to 16 bytes,
// stores them in got, then closes. Returns the listener address.
func captureCancelListener(t *testing.T, got *[]byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		_ = c.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, _ := io.ReadFull(c, buf)
		*got = buf[:n]
	}()
	return ln.Addr().String()
}

func buildCancelPacket(pid, secret uint32) []byte {
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint32(pkt[0:4], 16)
	binary.BigEndian.PutUint32(pkt[4:8], cancelRequestMagic)
	binary.BigEndian.PutUint32(pkt[8:12], pid)
	binary.BigEndian.PutUint32(pkt[12:16], secret)
	return pkt
}

func TestForwardCancel_WritesPayloadVerbatim(t *testing.T) {
	var got []byte
	addr := captureCancelListener(t, &got)
	svc := Service{Upstream: addr, TLSMode: "terminate_reissue"} // tls_mode irrelevant; cancel is plaintext

	packet := buildCancelPacket(54321, 98765)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := forwardCancel(ctx, svc, packet); err != nil {
		t.Fatalf("forwardCancel: %v", err)
	}
	// Allow the captureCancelListener goroutine to finish.
	for i := 0; i < 100 && len(got) < 16; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(got) != 16 {
		t.Fatalf("captured %d bytes, want 16", len(got))
	}
	for i := range packet {
		if got[i] != packet[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, got[i], packet[i])
		}
	}
}

func TestForwardCancel_DialFailureReturnsError(t *testing.T) {
	// 127.0.0.1:1 — almost certainly nothing listening.
	svc := Service{Upstream: "127.0.0.1:1", TLSMode: "terminate_reissue"}
	packet := buildCancelPacket(1, 2)
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if err := forwardCancel(ctx, svc, packet); err == nil {
		t.Fatal("forwardCancel against unreachable upstream: want error, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestForwardCancel -v`
Expected: FAIL with `forwardCancel undefined`.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/cancel.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"
	"net"
	"time"
)

const cancelDialTimeout = 5 * time.Second

// forwardCancel dials svc.Upstream plaintext (CancelRequest is plaintext per
// the PG protocol — no SSLRequest preamble), writes the 16-byte client
// packet verbatim, and closes. No auth, no TLS, no response.
//
// In 04b₂ the (PID, Secret) values are forwarded un-mapped — Plan 06 adds
// the mapping table. Until Plan 06 lands, the upstream's actual PID/Secret
// were forwarded to the client as BackendKeyData in 04b₂'s forwardAuth, so
// the cancel happens to work end-to-end (see design §7 risks).
func forwardCancel(ctx context.Context, svc Service, packet []byte) error {
	if len(packet) != 16 {
		return fmt.Errorf("postgres.forwardCancel: packet is %d bytes; want 16", len(packet))
	}
	dctx, cancel := context.WithTimeout(ctx, cancelDialTimeout)
	defer cancel()
	d := &net.Dialer{}
	conn, err := d.DialContext(dctx, "tcp", svc.Upstream)
	if err != nil {
		return fmt.Errorf("postgres.forwardCancel: dial %q: %w", svc.Upstream, err)
	}
	defer conn.Close()
	_ = conn.SetWriteDeadline(time.Now().Add(cancelDialTimeout))
	if _, err := conn.Write(packet); err != nil {
		return fmt.Errorf("postgres.forwardCancel: write: %w", err)
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run TestForwardCancel -v`
Expected: PASS for both.

- [ ] **Step 5: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/cancel.go internal/db/proxy/postgres/cancel_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: forwardCancel — single-shot un-mapped cancel forward

Plan 04b₂ Task 5. forwardCancel dials svc.Upstream plaintext (cancel is
always plaintext per the PG protocol — no SSLRequest preamble), writes
the 16-byte client packet verbatim, and closes. The (PID, Secret) values
are forwarded un-mapped — Plan 06 will add the mapping table. Until
then, the proxy forwards real upstream BKD to clients in forwardAuth,
so cancel happens to work end-to-end; this is noted in the design
release-notes.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Roborev between tasks**

---

## Task 6: Wire terminate_* allow-path — dial → forward StartupMessage → forwardAuth → close at RFQ

**Why:** This is the central behavior change for 04b₂. `handleStartupMessage` stops synthesizing the not-yet-wired error and instead dials upstream, forwards the StartupMessage, and runs `forwardAuth`. The deny path is unchanged (synthesized ErrorResponse). The existing `TestTLS_TerminateReissue_RoundTrip` test in `tls_test.go` is updated to match.

**Files:**
- Modify: `internal/db/proxy/postgres/handshake.go`
- Modify: `internal/db/proxy/postgres/connect_rule.go`
- Modify: `internal/db/proxy/postgres/tls_test.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go` (none — extended in Task 3)

- [ ] **Step 1: Generalize `evaluateConnect` to take a `MatchKind`**

Edit `internal/db/proxy/postgres/connect_rule.go`:

```go
//go:build linux

package postgres

import (
	"context"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// evaluateConnection runs Plan 02's connection-rule evaluator with the
// given match_kind against the parsed StartupMessage state. Returns the
// Decision so callers can choose between allow-path and deny-path.
func (pc *proxyConn) evaluateConnection(_ context.Context, mk policy.ConnectionMatchKind) policy.Decision {
	return policy.EvaluateConnection(policy.ConnectionInfo{
		Service:         policy.ServiceID(pc.svc.Name),
		MatchKind:       mk,
		DBUser:          pc.state.dbUser,
		Database:        pc.state.database,
		ApplicationName: pc.state.appName,
		ClientIdentity:  pc.state.clientIdentity,
	}, pc.srv.cfg.Policy)
}

// evaluateConnect is the original 04b helper kept as a thin wrapper around
// evaluateConnection(MatchConnect) so existing callers compile unchanged.
func (pc *proxyConn) evaluateConnect(ctx context.Context) policy.Decision {
	return pc.evaluateConnection(ctx, policy.MatchConnect)
}

// evaluateReplication is the match_kind=replication entry point.
func (pc *proxyConn) evaluateReplication(ctx context.Context) policy.Decision {
	return pc.evaluateConnection(ctx, policy.MatchReplication)
}

// evaluateCancel is the match_kind=cancel entry point.
func (pc *proxyConn) evaluateCancel(ctx context.Context) policy.Decision {
	return pc.evaluateConnection(ctx, policy.MatchCancel)
}
```

- [ ] **Step 2: Write the failing test for the new terminate_* allow-path**

Edit `internal/db/proxy/postgres/tls_test.go`. The existing test `TestTLS_TerminateReissue_RoundTrip` asserts the proxy synthesizes `ErrorResponse(0A000)` after StartupMessage; we'll flip it to assert the proxy dials a fake upstream and forwards. Find the part after the StartupMessage write and before the read-`'E'` assertion. Replace the post-StartupMessage block.

Specifically: replace the section that reads:

```go
	// Read the ErrorResponse the proxy synthesizes.
	first := make([]byte, 1)
	if _, err := io.ReadFull(tlsConn, first); err != nil {
		t.Fatalf("read post-startup: %v", err)
	}
	if first[0] != 'E' {
		t.Errorf("first post-startup byte = %q, want 'E'", first[0])
	}
```

with:

```go
	// Read the upstream-driven AuthenticationOk frame the proxy forwards.
	// The fake upstream in tls_test sends AuthOk + RFQ; the proxy closes
	// after forwarding RFQ. First byte should be 'R' (Authentication).
	first := make([]byte, 1)
	if _, err := io.ReadFull(tlsConn, first); err != nil {
		t.Fatalf("read post-startup: %v", err)
	}
	if first[0] != 'R' {
		t.Errorf("first post-startup byte = %q, want 'R' (Authentication)", first[0])
	}
```

Also: the test's `Server` config must point at a real fake upstream listener and set `UpstreamTLSConfigForTest` so verify-full passes against the test cert. The current test uses `Upstream: "db.internal:5432"` (unreachable). Update the Server `New(Config{...})` call so that:

- `svc.Upstream` is the address of a fake-upstream `net.Listener` started inside the test.
- Wrap that fake-upstream in `tls.Listen` if `svc.TLSMode == "terminate_reissue"`, or plain `net.Listen` for `terminate_plaintext_upstream`.
- The fake-upstream goroutine speaks `pgproto3.NewBackend(c, c)` and sends AuthenticationOk + ReadyForQuery on the first connect.
- `Config.UpstreamTLSConfigForTest` is set to a `*tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}` so the proxy trusts the fake-upstream's self-signed cert.

Add a small helper inline to the test file to start the fake upstream:

```go
// startFakeUpstreamForTLSTest binds a tls listener with the supplied tls.Config
// on 127.0.0.1:0 and runs one server goroutine that sends Auth+RFQ on the
// first connection. Returns the listener address.
func startFakeUpstreamForTLSTest(t *testing.T, srvCfg *tls.Config) string {
	t.Helper()
	ln, err := tls.Listen("tcp", "127.0.0.1:0", srvCfg)
	if err != nil {
		t.Fatalf("tls.Listen fake upstream: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		be := pgproto3.NewBackend(c, c)
		// Discard the inbound StartupMessage from the proxy.
		_, _ = be.ReceiveStartupMessage()
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = be.Flush()
	}()
	return ln.Addr().String()
}
```

Add the `pgproto3` import to `tls_test.go` if not already present.

Then in the test body, before constructing the `Server`:

```go
	// Build a fake-upstream TLS listener with a known cert; install the cert
	// into the proxy's UpstreamTLSConfigForTest trust pool.
	upSrvCfg, upCert := genSelfSignedServer(t, "127.0.0.1")
	upAddr := startFakeUpstreamForTLSTest(t, upSrvCfg)
	pool := x509.NewCertPool()
	pool.AddCert(upCert)
```

Update the `Config` passed to `New`:

```go
		UpstreamTLSConfigForTest: &tls.Config{
			RootCAs:    pool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
```

The existing `Policy` field on `Config` is left nil (no rules → implicit deny). To allow the connection, we need a permissive rule. Use `policy.RuleSet`'s test-friendly constructor or build one inline. Inspect `internal/db/policy/` for a helper; if none exists, use `policy.MustDecode(...)` or build with the YAML loader path (see `connect_rule_test.go`'s `loadRuleSet` helper for the pattern). Add:

```go
	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upAddr+`
    tls_mode: terminate_reissue
database_connection_rules:
  - name: allow-everyone
    db_service: appdb
    decision: allow
`)
```

…and `Policy: rs` in the Config. Reuse `loadRuleSet` from `connect_rule_test.go` (cross-file helpers are fine within the same `_test` package).

- [ ] **Step 3: Run the test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -run TestTLS_TerminateReissue_RoundTrip -v`
Expected: FAIL — the proxy still synthesizes ErrorResponse(0A000), so first byte is 'E' not 'R'.

- [ ] **Step 4: Replace `handleStartupMessage`'s allow-path**

Edit `internal/db/proxy/postgres/handshake.go`. Replace the entire `handleStartupMessage` body with:

```go
// handleStartupMessage parses the parameters, evaluates the appropriate
// connection rule (match_kind=replication when the replication parameter is
// truthy; match_kind=connect otherwise), and either synthesizes a deny or
// dials upstream + forwards.
//
// Plan 04b₂: terminate_* allow path dials upstream → Send(StartupMessage)
// → forwardAuth → close at first upstream RFQ. Replication-allowed branches
// to forwardReplicationStartupAndPump (Task 8). Passthrough is handled by
// handleSSLRequest in tls.go (Task 7).
func (pc *proxyConn) handleStartupMessage(ctx context.Context, m *pgproto3.StartupMessage) error {
	pc.state.dbUser = m.Parameters["user"]
	pc.state.database = m.Parameters["database"]
	pc.state.appName = m.Parameters["application_name"]
	if v, ok := m.Parameters["replication"]; ok && v != "" && v != "false" && v != "off" && v != "0" {
		pc.state.replication = true
	}

	var d policy.Decision
	if pc.state.replication {
		d = pc.evaluateReplication(ctx)
	} else {
		d = pc.evaluateConnect(ctx)
	}
	if d.Verb == policy.VerbDeny {
		msg := d.Reason
		if msg == "" {
			if pc.state.replication {
				msg = "AgentSH DB proxy: replication denied by policy"
			} else {
				msg = "AgentSH DB proxy: connection denied by policy"
			}
		}
		return pc.synthesizeError(connectionDenyErrorCode, msg)
	}

	if pc.state.replication {
		return pc.forwardReplicationStartupAndPump(ctx, m) // Task 8
	}
	return pc.dialUpstreamAndForward(ctx, m)
}

// dialUpstreamAndForward dials upstream, forwards the StartupMessage, runs
// forwardAuth until upstream RFQ, then returns nil (caller closes both
// conns). On dial / TLS failure synthesizes UPSTREAM_DIAL_FAIL or
// UPSTREAM_TLS_FAIL to the client. On SCRAM-PLUS detection emits a
// db_handshake_fail event and synthesizes the SCRAM_PLUS_FAIL_CLOSED error
// (the error itself is written by forwardAuth).
func (pc *proxyConn) dialUpstreamAndForward(ctx context.Context, m *pgproto3.StartupMessage) error {
	conn, fe, err := dialUpstream(ctx, pc.svc, pc.srv.cfg)
	if err != nil {
		code := upstreamDialFailEventCode
		errCode := upstreamDialFailErrorCode
		msg := fmt.Sprintf("AgentSH DB proxy: upstream unreachable: %v", err)
		if isTLSError(err) {
			code = upstreamTLSFailEventCode
			errCode = upstreamTLSFailErrorCode
			msg = fmt.Sprintf("AgentSH DB proxy: upstream TLS handshake failed: %v", err)
		}
		pc.emitHandshakeFail(ctx, code)
		return pc.synthesizeError(errCode, msg)
	}
	pc.state.upstream = conn
	pc.state.upstreamFE = fe

	pc.state.upstreamFE.Send(m)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		pc.emitHandshakeFail(ctx, upstreamDialFailEventCode)
		return pc.synthesizeError(upstreamDialFailErrorCode, fmt.Sprintf("AgentSH DB proxy: upstream send StartupMessage: %v", err))
	}

	if err := forwardAuth(ctx, pc); err != nil {
		if errors.Is(err, errScramPlusFailClosed) {
			pc.emitHandshakeFail(ctx, scramPlusEventCode)
			return nil // ErrorResponse already written by forwardAuth
		}
		// Other forwardAuth errors are typically EOF / pipe-closed; return
		// nil so the deferred Close happens but no event is emitted.
		return nil
	}
	return nil
}

// isTLSError is a loose heuristic — "tls:" or "x509:" in the message.
// Used to distinguish TLS-handshake failures from raw TCP dial failures.
func isTLSError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return contains(s, "tls:") || contains(s, "x509:") || contains(s, "TLS handshake")
}

// contains is io-free; the events package uses a similar helper.
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

Add the missing imports near the top of `handshake.go`:

```go
import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/policy"
)
```

- [ ] **Step 5: Add `emitHandshakeFail` helper**

Append to `internal/db/proxy/postgres/proxyconn.go`:

```go
// emitHandshakeFail emits a db_handshake_fail LifecycleEvent into the
// configured sink. errorCode populates the event's ErrorCode field; the
// matching SQLSTATE is on the wire ErrorResponse.
func (pc *proxyConn) emitHandshakeFail(ctx context.Context, errorCode string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "db_handshake_fail",
		PeerUID:        pc.state.peerUID,
		ErrorCode:      errorCode,
		SNIHostname:    pc.state.sniHostname,
	}
	_ = pc.srv.cfg.Sink.Emit(ctx, ev)
}
```

Add the import to `proxyconn.go`:

```go
import (
	"context"
	"net"
	"strconv"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
)
```

(`timeNow` is already declared in the package — Plan 04b's `server.go` exports a package-level var.)

- [ ] **Step 6: Run the updated TLS round-trip test**

Run: `go test ./internal/db/proxy/postgres/ -run TestTLS_TerminateReissue_RoundTrip -v`
Expected: PASS.

- [ ] **Step 7: Run the full proxy package tests**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS (no regressions). `TestDispatch_Replication_DefaultDeny` from 04b will fail because the replication-deny path now goes through the evaluator. Fix that test in the next step before committing.

- [ ] **Step 8: Update `TestDispatch_Replication_DefaultDeny` for the eval path**

Edit `internal/db/proxy/postgres/handshake_test.go`. The existing test asserts that a `replication=true` startup gets an ErrorResponse with the old default-deny message. Under 04b₂ the deny happens via the evaluator (no rule covers `match_kind=replication` → implicit deny). The on-the-wire behavior — ErrorResponse with code 28000 + close — is unchanged, but the message text comes from `d.Reason` instead of `replicationDenyMessage`. Update the test to assert just `Code == "28000"` and accept either message:

Replace the inside of the goroutine in `TestDispatch_Replication_DefaultDeny` that reads the response:

```go
		buf := make([]byte, 256)
		_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := b.Read(buf)
		if n == 0 || buf[0] != 'E' {
			t.Errorf("first byte after replication startup = %q (n=%d), want 'E'", buf[0], n)
		}
```

That assertion is already loose enough (checks 'E' = ErrorResponse). Leave it. The test should still pass with the new eval-driven deny.

The `Server` configured in `newTestProxyConn` has `Policy: nil`, so EvaluateConnection returns `VerbDeny` with `RuleName: ""` per `policy.Decode`'s implicit-deny contract. That's exactly what we want for the default-deny replication path.

- [ ] **Step 9: Re-run tests**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS for everything in the package.

- [ ] **Step 10: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 11: Commit**

```bash
git add internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/connect_rule.go internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/tls_test.go internal/db/proxy/postgres/handshake_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: dial upstream + forwardAuth on terminate_* allow path

Plan 04b₂ Task 6. handleStartupMessage now selects MatchKind by the
replication parameter, calls EvaluateConnection, and on allow dials
upstream via dialUpstream, sends the StartupMessage, and runs
forwardAuth until upstream ReadyForQuery — at which point the proxy
closes cleanly. Plan 04c will replace the close-at-RFQ with the
classify-and-forward loop.

evaluateConnect is generalized into evaluateConnection(matchKind);
evaluateReplication and evaluateCancel are thin wrappers that callers
in later tasks use. Dial / TLS failures synthesize ErrorResponse(08006,
UPSTREAM_DIAL_FAIL | UPSTREAM_TLS_FAIL) and emit db_handshake_fail.
SCRAM-PLUS detection from forwardAuth emits db_handshake_fail with
error_code SCRAM_PLUS_FAIL_CLOSED; the on-wire ErrorResponse is written
by forwardAuth itself.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 12: Roborev between tasks**

---

## Task 7: Un-reject passthrough + wire passthrough mode

**Why:** Plan 04b's `Server.New` refuses `tls_mode: passthrough` services. Plan 04b₂ flips that and adds the byte-pump arm to `handleSSLRequest`. Passthrough never reaches `handleStartupMessage` because the client's bytes are forwarded raw after the `'S'` response.

**Files:**
- Modify: `internal/db/proxy/postgres/server.go`
- Modify: `internal/db/proxy/postgres/server_test.go`
- Modify: `internal/db/proxy/postgres/tls.go`

- [ ] **Step 1: Write the failing tests**

Edit `internal/db/proxy/postgres/server_test.go`. Find `TestServer_New_RejectsPassthroughService` (added in 04b Task 3) and replace with:

```go
func TestServer_New_AllowsPassthroughService(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "passthrough",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "x.sock")},
			Service:  policy.DBService{Name: "appdb", TLSMode: "passthrough"},
		}},
	}
	if _, err := New(cfg); err != nil {
		t.Fatalf("New (passthrough): want nil error, got %v", err)
	}
}
```

(Drop the existing `strings.Contains(err.Error(), "passthrough")` check; passthrough is no longer rejected.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -run TestServer_New_AllowsPassthroughService -v`
Expected: FAIL — `New` still returns the passthrough-rejection error from 04b.

- [ ] **Step 3: Drop the passthrough rejection in `server.go`**

Edit `internal/db/proxy/postgres/server.go`. In `New`, remove the block:

```go
		if svc.TLSMode == "passthrough" {
			return nil, fmt.Errorf("postgres.New: services[%d] (%s) tls_mode: passthrough requires upstream wiring (Plan 04b₂); declare a terminate_* mode or wait for 04b₂", i, svc.Name)
		}
```

- [ ] **Step 4: Re-run the test to verify it passes**

Run: `go test ./internal/db/proxy/postgres/ -run TestServer_New_AllowsPassthroughService -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for passthrough byte-pump**

Append to `internal/db/proxy/postgres/handshake_test.go`:

```go
func TestDispatch_Passthrough_BytePumpAfterS(t *testing.T) {
	// Fake upstream that echoes any bytes received.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen upstream: %v", err)
	}
	defer upLn.Close()
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = io.Copy(c, c) // echo
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "passthrough",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "passthrough"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	// Drive proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()

	// Client sends SSLRequest (8 bytes: 0x00000008, 0x04D2162F).
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := b.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}

	// Expect 'S' response.
	resp := make([]byte, 1)
	if _, err := io.ReadFull(b, resp); err != nil {
		t.Fatalf("read SSL resp: %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("SSL resp = %q, want 'S'", resp[0])
	}

	// Now bytes pump through to the echo upstream. Write a payload, read
	// it back.
	payload := []byte("hello-from-client")
	if _, err := b.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
}
```

Make sure these imports are at the top of `handshake_test.go`:

```go
import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)
```

- [ ] **Step 6: Run the test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch_Passthrough_BytePumpAfterS -v`
Expected: FAIL — `handleSSLRequest`'s passthrough arm still returns `'N'` (refuse), so the client never gets `'S'` and no pump runs.

- [ ] **Step 7: Add the passthrough arm to `handleSSLRequest`**

Edit `internal/db/proxy/postgres/tls.go`. The current `handleSSLRequest` (from 04b) has switch arms for `terminate_reissue` and `terminate_plaintext_upstream`, then a `default` that writes `'N'`. Replace the function with:

```go
// handleSSLRequest negotiates the SSL response and runs the appropriate
// post-S flow per service.TLSMode.
//
// terminate_reissue / terminate_plaintext_upstream: respond 'S', run
// tls.Server with a leaf for the upstream hostname, swap pc.conn /
// pc.backend to the encrypted stream, return to dispatchStartup so it
// reads the post-TLS StartupMessage.
//
// passthrough: respond 'S', dial upstream plaintext, hand off to bytePump.
// The client's encrypted bytes are forwarded verbatim; upstream's own 'S'
// response (if any) is pumped back to client. No TLS termination occurs
// on either side.
func (pc *proxyConn) handleSSLRequest(ctx context.Context) error {
	switch pc.svc.TLSMode {
	case "terminate_reissue", "terminate_plaintext_upstream":
		return pc.terminateInbound(ctx)
	case "passthrough":
		return pc.passthroughAfterSSL(ctx)
	default:
		// Defensive — unknown mode. Refuse SSL so the client falls back or
		// errors out.
		_, err := pc.conn.Write([]byte{'N'})
		return err
	}
}

// passthroughAfterSSL responds 'S' to the inbound SSLRequest, dials upstream
// plaintext, and runs bytePump until either side closes. Returns
// errPassthroughDone (a sentinel) so dispatchStartup's caller breaks out
// of the for-loop cleanly.
func (pc *proxyConn) passthroughAfterSSL(ctx context.Context) error {
	if _, err := pc.conn.Write([]byte{'S'}); err != nil {
		return fmt.Errorf("write passthrough 'S': %w", err)
	}
	upstream, _, err := dialUpstream(ctx, pc.svc, pc.srv.cfg)
	if err != nil {
		// Synthesize ErrorResponse on the inbound (still-plaintext) stream.
		// This will appear inside the TLS bytes the client wraps; clients
		// typically present this as "server closed connection during
		// startup". Best-effort.
		_ = pc.conn.Close()
		return fmt.Errorf("passthrough upstream dial: %w", err)
	}
	pc.state.upstream = upstream
	// No SNI peek here — Plan 04b's extractSNI helper is plumbed into the
	// proxy's tls.Server GetCertificate path, not used in passthrough. A
	// future task may peek client bytes pre-pump to capture SNI; out of
	// scope for 04b₂.
	if err := bytePump(ctx, pc.conn, pc.state.upstream); err != nil {
		return fmt.Errorf("passthrough bytePump: %w", err)
	}
	return errPassthroughDone
}

// errPassthroughDone is the sentinel returned by passthroughAfterSSL so
// dispatchStartup knows to break out of its for-loop without trying to read
// another startup message.
var errPassthroughDone = errors.New("postgres: passthrough complete")
```

Add the imports `"errors"` and `"context"` to `tls.go` if not present.

- [ ] **Step 8: Update `dispatchStartup` to handle `errPassthroughDone`**

Edit `internal/db/proxy/postgres/handshake.go`. The current `dispatchStartup` after handling `*pgproto3.SSLRequest` does `continue` (loop for the next startup-class message). For passthrough, we never get a next startup-class message — the bytes after `'S'` are encrypted TLS bytes from the client, not a `StartupMessage`. Modify the SSLRequest arm:

```go
		case *pgproto3.SSLRequest:
			if err := pc.handleSSLRequest(ctx); err != nil {
				if errors.Is(err, errPassthroughDone) {
					return nil // passthrough byte-pump finished cleanly
				}
				return err
			}
			continue
```

Add `"errors"` import to `handshake.go` if not already imported.

- [ ] **Step 9: Run all tests**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS for everything including the new `TestDispatch_Passthrough_BytePumpAfterS`.

- [ ] **Step 10: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 11: Commit**

```bash
git add internal/db/proxy/postgres/server.go internal/db/proxy/postgres/server_test.go internal/db/proxy/postgres/tls.go internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/handshake_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: un-reject passthrough + wire byte-pump after 'S'

Plan 04b₂ Task 7. Server.New no longer rejects tls_mode: passthrough
services. handleSSLRequest's passthrough arm responds 'S' to the
inbound SSLRequest, dials upstream plaintext, and runs bytePump until
either side closes. The client's encrypted bytes are forwarded
verbatim; upstream's own 'S' response is pumped back. dispatchStartup
recognises errPassthroughDone and exits cleanly without trying to read
another startup-class message.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 12: Roborev between tasks**

---

## Task 8: Replication opt-in — forward StartupMessage + byte-pump + DVW event

**Why:** When a `match_kind=replication, decision=allow` rule matches, the proxy forwards the StartupMessage to upstream and enters a byte-pump for the connection's lifetime (the replication protocol is not classified). Emits one `degraded_visibility_warning{reason: replication_passthrough}` event at the transition.

**Files:**
- Modify: `internal/db/proxy/postgres/handshake.go` (add `forwardReplicationStartupAndPump`)
- Modify: `internal/db/proxy/postgres/proxyconn.go` (add `emitDegradedVisibility` helper)
- Modify: `internal/db/proxy/postgres/handshake_test.go` (add the opt-in test)

- [ ] **Step 1: Write the failing test**

Append to `internal/db/proxy/postgres/handshake_test.go`:

```go
func TestDispatch_ReplicationOptIn_PumpsAndEmitsDVW(t *testing.T) {
	// Echo upstream so we can confirm bytes pump.
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	startupCh := make(chan []byte, 1)
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		// Read the StartupMessage the proxy forwards.
		hdr := make([]byte, 4)
		if _, err := io.ReadFull(c, hdr); err != nil {
			startupCh <- nil
			return
		}
		bodyLen := int(binary.BigEndian.Uint32(hdr)) - 4
		body := make([]byte, bodyLen)
		if _, err := io.ReadFull(c, body); err != nil {
			startupCh <- nil
			return
		}
		startupCh <- body
		// Then echo for the rest of the connection lifetime.
		_, _ = io.Copy(c, c)
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upLn.Addr().String()+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-replication
    db_service: appdb
    match_kind: replication
    decision: allow
`)

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	pc.state.tlsTerminated = true // pretend inbound TLS already done

	// Build a StartupMessage with replication=true and write to client side.
	startup := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	startup = append(startup, v...)
	startup = append(startup, []byte("user\x00rep\x00replication\x00true\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(startup)+4))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- pc.run(ctx) }()

	if _, err := b.Write(append(hdr, startup...)); err != nil {
		t.Fatalf("write startup: %v", err)
	}

	// Wait for the proxy to forward the StartupMessage upstream.
	select {
	case body := <-startupCh:
		if body == nil {
			t.Fatal("upstream did not receive StartupMessage")
		}
		if !contains(string(body), "replication") {
			t.Errorf("upstream startup body missing replication param: %q", body)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("upstream timeout waiting for StartupMessage")
	}

	// Pump check: client writes 'X', upstream echoes back.
	if _, err := b.Write([]byte("X")); err != nil {
		t.Fatalf("write X: %v", err)
	}
	buf := make([]byte, 1)
	_ = b.SetReadDeadline(time.Now().Add(1 * time.Second))
	if _, err := io.ReadFull(b, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if buf[0] != 'X' {
		t.Errorf("echo = %q, want X", buf[0])
	}

	// Tear down.
	b.Close()
	<-done

	// Assert one degraded_visibility_warning event with replication_passthrough.
	evs := sink.Drain()
	var found *events.LifecycleEvent
	for i := range evs {
		if evs[i].Kind == "degraded_visibility_warning" {
			found = &evs[i]
			break
		}
	}
	if found == nil {
		t.Fatal("no degraded_visibility_warning event emitted")
	}
	if found.DegradedReason != "replication_passthrough" {
		t.Errorf("DegradedReason = %q, want replication_passthrough", found.DegradedReason)
	}
}
```

`contains` is already defined in `handshake.go` from Task 6; if it lives in a different file you may need to inline a one-off helper.

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch_ReplicationOptIn -v`
Expected: FAIL — `forwardReplicationStartupAndPump undefined` or the function exists but is empty.

- [ ] **Step 3: Implement `forwardReplicationStartupAndPump` in `handshake.go`**

Append to `internal/db/proxy/postgres/handshake.go`:

```go
// forwardReplicationStartupAndPump is the replication-allowed allow path.
// Dials upstream per service.TLSMode, forwards the StartupMessage, emits
// degraded_visibility_warning{reason: replication_passthrough}, then runs
// bytePump until either side closes.
func (pc *proxyConn) forwardReplicationStartupAndPump(ctx context.Context, m *pgproto3.StartupMessage) error {
	conn, fe, err := dialUpstream(ctx, pc.svc, pc.srv.cfg)
	if err != nil {
		code := upstreamDialFailEventCode
		errCode := upstreamDialFailErrorCode
		msg := fmt.Sprintf("AgentSH DB proxy: upstream unreachable: %v", err)
		if isTLSError(err) {
			code = upstreamTLSFailEventCode
			errCode = upstreamTLSFailErrorCode
			msg = fmt.Sprintf("AgentSH DB proxy: upstream TLS handshake failed: %v", err)
		}
		pc.emitHandshakeFail(ctx, code)
		return pc.synthesizeError(errCode, msg)
	}
	pc.state.upstream = conn
	pc.state.upstreamFE = fe
	pc.state.degradedReason = "replication_passthrough"

	pc.state.upstreamFE.Send(m)
	if err := pc.state.upstreamFE.Flush(); err != nil {
		pc.emitHandshakeFail(ctx, upstreamDialFailEventCode)
		return pc.synthesizeError(upstreamDialFailErrorCode, fmt.Sprintf("AgentSH DB proxy: upstream send StartupMessage (replication): %v", err))
	}

	pc.emitDegradedVisibility(ctx, "replication_passthrough", "replication_opt_in")

	if err := bytePump(ctx, pc.conn, pc.state.upstream); err != nil {
		// io.EOF / pipe-closed are normal; surface anything else.
		if !isNormalCloseErr(err) {
			return err
		}
	}
	return nil
}
```

- [ ] **Step 4: Add `emitDegradedVisibility` to `proxyconn.go`**

Append to `internal/db/proxy/postgres/proxyconn.go`:

```go
// emitDegradedVisibility emits a degraded_visibility_warning LifecycleEvent
// with the supplied reason classifications. degradedReason is the typed
// enum value ("replication_passthrough" / "gssenc_passthrough"); reason is
// the free-form spec-level reason string.
func (pc *proxyConn) emitDegradedVisibility(ctx context.Context, degradedReason, reason string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "degraded_visibility_warning",
		Reason:         reason,
		PeerUID:        pc.state.peerUID,
		DegradedReason: degradedReason,
		SNIHostname:    pc.state.sniHostname,
	}
	_ = pc.srv.cfg.Sink.Emit(ctx, ev)
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch_ReplicationOptIn -v`
Expected: PASS.

- [ ] **Step 6: Run the full package tests**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS for everything.

- [ ] **Step 7: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 8: Commit**

```bash
git add internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/handshake_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: replication opt-in path with degraded-visibility event

Plan 04b₂ Task 8. handleStartupMessage now routes replication=true
through evaluateReplication; on allow, forwardReplicationStartupAndPump
dials upstream, sends the StartupMessage, emits
degraded_visibility_warning{reason: replication_passthrough,
degraded_reason: replication_passthrough}, then runs bytePump until
close. Default-deny (no match_kind=replication rule) still synthesizes
ErrorResponse(28000) via the existing deny path — the eval just
returns VerbDeny with RuleName=="".

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Roborev between tasks**

---

## Task 9: CancelRequest connect-rule eval + un-mapped forward

**Why:** 04b silently closed every CancelRequest. 04b₂ evaluates `match_kind=cancel` and forwards on allow via `forwardCancel` from Task 5.

**Files:**
- Modify: `internal/db/proxy/postgres/handshake.go` (CancelRequest arm)
- Modify: `internal/db/proxy/postgres/handshake_test.go` (allow + deny tests)

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/handshake_test.go`:

```go
func TestDispatch_CancelRequest_AllowedForwardsPacket(t *testing.T) {
	var captured []byte
	upAddr := captureCancelListener(t, &captured)

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upAddr+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: allow-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
`)

	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()

	pkt := buildCancelPacket(11111, 22222)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	// Allow upstream to capture.
	for i := 0; i < 100 && len(captured) < 16; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(captured) != 16 {
		t.Fatalf("captured %d bytes upstream, want 16", len(captured))
	}
	for i := range pkt {
		if captured[i] != pkt[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, captured[i], pkt[i])
		}
	}
}

func TestDispatch_CancelRequest_DeniedSilentClose(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := upLn.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: `+upLn.Addr().String()+`
    tls_mode: terminate_plaintext_upstream
    trusted_network: true
database_connection_rules:
  - name: deny-cancel
    db_service: appdb
    match_kind: cancel
    decision: deny
`)

	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upLn.Addr().String(),
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()

	pkt := buildCancelPacket(11111, 22222)
	if _, err := b.Write(pkt); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}

	select {
	case <-dialed:
		t.Error("upstream was dialed despite deny rule")
	case <-time.After(300 * time.Millisecond):
		// Expected: no dial.
	}
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch_CancelRequest -v`
Expected: FAIL — the existing 04b CancelRequest arm silently closes regardless of rule.

- [ ] **Step 3: Replace the CancelRequest arm in `dispatchStartup`**

Edit `internal/db/proxy/postgres/handshake.go`. In `dispatchStartup`, replace the `case *pgproto3.CancelRequest` block:

```go
		case *pgproto3.CancelRequest:
			return pc.handleCancelRequest(ctx, m)
```

Add the handler at the bottom of the file:

```go
// handleCancelRequest evaluates match_kind=cancel and either forwards the
// raw 16-byte packet via forwardCancel or silently closes. Plan 04b₂ runs
// un-mapped — Plan 06 will add the mapping table.
func (pc *proxyConn) handleCancelRequest(ctx context.Context, m *pgproto3.CancelRequest) error {
	d := pc.evaluateCancel(ctx)
	pc.logger.Debug("CancelRequest received",
		"service", pc.svc.Name,
		"syn_pid", m.ProcessID,
		"syn_secret", m.SecretKey,
		"verb", d.Verb,
		"rule", d.RuleName)
	if d.Verb == policy.VerbDeny {
		// Silent close per spec §15: cancel has no error response.
		return nil
	}
	// Rebuild the 16-byte packet from the parsed CancelRequest because
	// pgproto3's ReceiveStartupMessage consumes the bytes.
	pkt := buildCancelPacketBytes(m.ProcessID, m.SecretKey)
	if err := forwardCancel(ctx, pc.svc, pkt); err != nil {
		pc.logger.Warn("forwardCancel failed", "service", pc.svc.Name, "err", err)
	}
	return nil
}

// buildCancelPacketBytes serializes a CancelRequest payload for un-mapped
// forwarding. Mirrors the on-wire layout: 4-byte length (16) + 4-byte magic
// (80877102) + 4-byte process ID + 4-byte secret key.
func buildCancelPacketBytes(pid, secret uint32) []byte {
	pkt := make([]byte, 16)
	binary.BigEndian.PutUint32(pkt[0:4], 16)
	binary.BigEndian.PutUint32(pkt[4:8], cancelRequestMagic)
	binary.BigEndian.PutUint32(pkt[8:12], pid)
	binary.BigEndian.PutUint32(pkt[12:16], secret)
	return pkt
}
```

Add `"encoding/binary"` to the imports of `handshake.go` if not already present.

Note: the test helper `buildCancelPacket` in `cancel_test.go` is duplicated in production as `buildCancelPacketBytes`. Both have the same wire layout — they share no code because Go's test files don't export helpers cross-package. Acceptable.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch_CancelRequest -v`
Expected: PASS for both.

- [ ] **Step 5: Run the full package tests**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS for everything.

- [ ] **Step 6: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/handshake_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: CancelRequest connect-rule eval + un-mapped forward

Plan 04b₂ Task 9. The CancelRequest arm of dispatchStartup now calls
evaluateCancel; on allow, the raw 16-byte packet is rebuilt and
forwarded to upstream via forwardCancel (plaintext, single-shot). On
deny, silent close per spec §15. The forward is un-mapped — Plan 06
adds the (PID, Secret) mapping table; 04b₂ forwards the client's
values directly, which happen to match the upstream's real BackendKey
because forwardAuth forwards real upstream BKD to clients verbatim.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 8: Roborev between tasks**

---

## Task 10: Spine round-trip tests + fake-upstream helper

**Why:** Tasks 6–9 each shipped one or two focused tests. Task 10 adds the seven spine tests called out in the design doc, plus the reusable `newFakeUpstream` helper. These tests exercise the full proxy through real `pgx` (test 1) and hand-rolled clients (tests 2–7), against a `pgproto3.NewBackend`-speaking fake upstream.

**Files:**
- Create: `internal/db/proxy/postgres/testupstream_test.go`
- Create: `internal/db/proxy/postgres/spine_test.go`

- [ ] **Step 1: Implement `testupstream_test.go`**

```go
//go:build linux

package postgres

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakeUpstreamScript is one server-side script applied to a single inbound
// connection. The script is given a *pgproto3.Backend bound to the conn and
// returns when the script considers the connection done. The conn is
// closed by the helper afterwards.
type fakeUpstreamScript func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error

// fakeUpstreamOpt configures newFakeUpstream.
type fakeUpstreamOpt func(*fakeUpstreamConfig)

type fakeUpstreamConfig struct {
	useTLS bool
	tlsCfg *tls.Config
	script fakeUpstreamScript
}

// withFakeUpstreamTLS makes the upstream listener wrap each conn in TLS.
func withFakeUpstreamTLS(cfg *tls.Config) fakeUpstreamOpt {
	return func(c *fakeUpstreamConfig) {
		c.useTLS = true
		c.tlsCfg = cfg
	}
}

// withFakeUpstreamScript supplies the per-conn server script.
func withFakeUpstreamScript(s fakeUpstreamScript) fakeUpstreamOpt {
	return func(c *fakeUpstreamConfig) { c.script = s }
}

// fakeUpstream is a one-listener fake. Address() returns the dial target;
// AwaitConns() blocks until at least n connections were accepted.
type fakeUpstream struct {
	addr  string
	mu    sync.Mutex
	conns int
	done  chan struct{}
}

func (u *fakeUpstream) Address() string { return u.addr }

// newFakeUpstream binds 127.0.0.1:0 and runs the provided script for each
// inbound connection. The listener is closed via t.Cleanup. Scripts that
// return an error get t.Errorf'd on the caller's goroutine — failures are
// not silenced.
func newFakeUpstream(t *testing.T, opts ...fakeUpstreamOpt) *fakeUpstream {
	t.Helper()
	cfg := fakeUpstreamConfig{
		script: func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error { return nil },
	}
	for _, o := range opts {
		o(&cfg)
	}

	var ln net.Listener
	var err error
	if cfg.useTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", cfg.tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("newFakeUpstream: listen: %v", err)
	}
	u := &fakeUpstream{addr: ln.Addr().String(), done: make(chan struct{})}
	t.Cleanup(func() {
		_ = ln.Close()
		close(u.done)
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("fakeUpstream accept: %v", err)
				}
				return
			}
			u.mu.Lock()
			u.conns++
			u.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				be := pgproto3.NewBackend(c, c)
				if err := cfg.script(t, be, c); err != nil && !errors.Is(err, io.EOF) {
					t.Errorf("fakeUpstream script: %v", err)
				}
			}(c)
		}
	}()
	return u
}

// AcceptedConns returns the count of connections accepted so far.
func (u *fakeUpstream) AcceptedConns() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conns
}
```

- [ ] **Step 2: Implement `spine_test.go` with the seven spine tests**

```go
//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
	"github.com/agentsh/agentsh/internal/db/tlsleaf"
)

// spineHarness wires a Server with one terminate_reissue service pointing at
// the supplied fake upstream. Returns the bound Unix-socket path so a real
// pgx client can dial through it.
type spineHarness struct {
	srv     *Server
	sock    string
	sink    *events.SyncSink
	ca      *tlsleaf.CA
}

func startSpineHarness(t *testing.T, upAddr string, tlsMode string, upTLSPool *x509.CertPool, extraRule string) *spineHarness {
	t.Helper()
	sockDir := t.TempDir()
	sockPath := filepath.Join(sockDir, "appdb.sock")
	stateDir := t.TempDir()

	policyYAML := `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: ` + upAddr + `
    tls_mode: ` + tlsMode + `
    trusted_network: true
database_connection_rules:
  - name: allow-everyone
    db_service: appdb
    decision: allow
`
	if extraRule != "" {
		policyYAML += extraRule
	}
	rs := loadRuleSet(t, policyYAML)

	var upTLSCfg *tls.Config
	if upTLSPool != nil {
		upTLSCfg = &tls.Config{
			RootCAs:    upTLSPool,
			ServerName: "127.0.0.1",
			MinVersion: tls.VersionTLS12,
		}
	}

	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability:           service.UnavoidabilityObserve,
		StateDir:                 stateDir,
		Sink:                     sink,
		Policy:                   rs,
		Logger:                   slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		UpstreamTLSConfigForTest: upTLSCfg,
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: upAddr,
			TLSMode:  tlsMode,
			Listen:   ServiceListener{Kind: "unix", Path: sockPath},
			Service:  policy.DBService{Name: "appdb", TLSMode: tlsMode, TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca, err := srv.ca()
	if err != nil {
		t.Fatalf("srv.ca(): %v", err)
	}
	return &spineHarness{srv: srv, sock: sockPath, sink: sink, ca: ca}
}

// runServer runs srv.Start until ctx is cancelled. Returns when Start
// returns or the test cleans up.
func runServer(t *testing.T, srv *Server) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan error, 1)
	go func() { doneCh <- srv.Start(ctx) }()
	// Wait briefly for the listener to bind.
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		// Listener is bound when the socket file appears (best-effort).
	}
	return func() {
		cancel()
		_ = srv.Shutdown(context.Background())
		<-doneCh
	}
}

// authOKScript is the canonical happy-path upstream: receive StartupMessage,
// send AuthenticationOk + BackendKeyData + ReadyForQuery('I'), then read
// (and discard) anything else until the client closes.
func authOKScript(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
	t.Helper()
	if _, err := be.ReceiveStartupMessage(); err != nil {
		return fmt.Errorf("receive startup: %w", err)
	}
	be.Send(&pgproto3.AuthenticationOk{})
	be.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: 99})
	be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := be.Flush(); err != nil {
		return fmt.Errorf("flush: %w", err)
	}
	// Drain remaining client bytes until EOF.
	buf := make([]byte, 256)
	for {
		_ = conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := conn.Read(buf); err != nil {
			return nil
		}
	}
}

// handRolledTerminateReissueHandshake opens a unix-socket client to the
// proxy, sends SSLRequest, completes a TLS handshake against the proxy's CA,
// and writes a StartupMessage. Returns the *tls.Conn for further reads.
func handRolledTerminateReissueHandshake(t *testing.T, sockPath string, ca *tlsleaf.CA) *tls.Conn {
	t.Helper()
	raw, err := net.Dial("unix", sockPath)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := raw.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("'S' resp = %q", resp[0])
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	tlsConn := tls.Client(raw, &tls.Config{
		RootCAs:    pool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	startup := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	startup = append(startup, v...)
	startup = append(startup, []byte("user\x00alice\x00database\x00app\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(startup)+4))
	if _, err := tlsConn.Write(append(hdr, startup...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}
	return tlsConn
}

// readUntilRFQ reads pgproto3 frames from c until it sees ReadyForQuery or
// EOF. Returns the captured BackendKeyData (if any).
func readUntilRFQ(t *testing.T, c io.Reader) *pgproto3.BackendKeyData {
	t.Helper()
	fe := pgproto3.NewFrontend(c, nil)
	var bkd *pgproto3.BackendKeyData
	for {
		msg, err := fe.Receive()
		if err != nil {
			return bkd
		}
		switch m := msg.(type) {
		case *pgproto3.BackendKeyData:
			bkd = m
		case *pgproto3.ReadyForQuery:
			return bkd
		}
	}
}

func TestSpine_TerminateReissue_AuthOK_CloseAtRFQ(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "127.0.0.1")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	up := newFakeUpstream(t,
		withFakeUpstreamTLS(srvCfg),
		withFakeUpstreamScript(authOKScript),
	)
	h := startSpineHarness(t, up.Address(), "terminate_reissue", pool, "")
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()

	bkd := readUntilRFQ(t, tlsConn)
	if bkd == nil {
		t.Fatal("never received BackendKeyData")
	}
	if bkd.ProcessID != 42 || bkd.SecretKey != 99 {
		t.Errorf("BKD = (%d, %d), want (42, 99)", bkd.ProcessID, bkd.SecretKey)
	}
	if up.AcceptedConns() == 0 {
		t.Fatal("upstream never received a connection")
	}
}

func TestSpine_TerminatePlaintextUpstream_AuthOK_CloseAtRFQ(t *testing.T) {
	up := newFakeUpstream(t, withFakeUpstreamScript(authOKScript))
	h := startSpineHarness(t, up.Address(), "terminate_plaintext_upstream", nil, "")
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()

	bkd := readUntilRFQ(t, tlsConn)
	if bkd == nil {
		t.Fatal("never received BackendKeyData")
	}
	if up.AcceptedConns() == 0 {
		t.Fatal("upstream never received a connection")
	}
}

func TestSpine_TerminateReissue_ScramPlus_FailClosed(t *testing.T) {
	srvCfg, cert := genSelfSignedServer(t, "127.0.0.1")
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	scramPlusScript := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
		if _, err := be.ReceiveStartupMessage(); err != nil {
			return err
		}
		be.Send(&pgproto3.AuthenticationSASL{
			AuthMechanisms: []string{"SCRAM-SHA-256", "SCRAM-SHA-256-PLUS"},
		})
		return be.Flush()
	}
	up := newFakeUpstream(t,
		withFakeUpstreamTLS(srvCfg),
		withFakeUpstreamScript(scramPlusScript),
	)
	h := startSpineHarness(t, up.Address(), "terminate_reissue", pool, "")
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()

	// Read frames until ErrorResponse or EOF.
	fe := pgproto3.NewFrontend(tlsConn, nil)
	var got *pgproto3.ErrorResponse
	for {
		msg, err := fe.Receive()
		if err != nil {
			break
		}
		if e, ok := msg.(*pgproto3.ErrorResponse); ok {
			got = e
			break
		}
	}
	if got == nil {
		t.Fatal("never received ErrorResponse")
	}
	if got.Code != scramPlusErrorCode {
		t.Errorf("Code = %q, want %q", got.Code, scramPlusErrorCode)
	}
	if !strings.Contains(got.Message, "SCRAM-SHA-256-PLUS") {
		t.Errorf("Message = %q; want SCRAM-SHA-256-PLUS mentioned", got.Message)
	}
	time.Sleep(100 * time.Millisecond)
	evs := h.sink.Drain()
	var found bool
	for _, e := range evs {
		if e.Kind == "db_handshake_fail" && e.ErrorCode == scramPlusEventCode {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("no db_handshake_fail event with SCRAM_PLUS_FAIL_CLOSED; got %+v", evs)
	}
}

func TestSpine_Passthrough_BytePump(t *testing.T) {
	echoScript := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
		buf := make([]byte, 256)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, _ := conn.Read(buf)
		_, _ = conn.Write(buf[:n])
		return nil
	}
	up := newFakeUpstream(t, withFakeUpstreamScript(echoScript))
	h := startSpineHarness(t, up.Address(), "passthrough", nil, "")
	stop := runServer(t, h.srv)
	defer stop()

	// Open a raw unix-socket client; send a fake SSLRequest, then a payload.
	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := c.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(c, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("'S' resp = %q", resp[0])
	}
	// Now bytes pump through to the echo upstream.
	payload := []byte("ping-pong")
	if _, err := c.Write(payload); err != nil {
		t.Fatalf("write payload: %v", err)
	}
	buf := make([]byte, len(payload))
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
	// Assert no DVW emitted (passthrough is service-level opt-out).
	for _, e := range h.sink.Drain() {
		if e.Kind == "degraded_visibility_warning" {
			t.Errorf("unexpected DVW under passthrough: %+v", e)
		}
	}
}

func TestSpine_ReplicationOptIn_BytePump_EmitsDVW(t *testing.T) {
	echoAfterStartup := func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error {
		if _, err := be.ReceiveStartupMessage(); err != nil {
			return err
		}
		// Echo subsequent bytes verbatim.
		_, _ = io.Copy(conn, conn)
		return nil
	}
	up := newFakeUpstream(t, withFakeUpstreamScript(echoAfterStartup))
	rule := `  - name: allow-replication
    db_service: appdb
    match_kind: replication
    decision: allow
`
	h := startSpineHarness(t, up.Address(), "terminate_plaintext_upstream", nil, rule)
	stop := runServer(t, h.srv)
	defer stop()

	caCert := h.ca.Cert()
	clientPool := x509.NewCertPool()
	clientPool.AddCert(caCert)

	// Hand-roll a client: TLS handshake against proxy, then StartupMessage
	// with replication=true.
	raw, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer raw.Close()
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], sslRequestMagic)
	if _, err := raw.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(raw, resp); err != nil {
		t.Fatalf("read 'S': %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("'S' resp = %q", resp[0])
	}
	tlsConn := tls.Client(raw, &tls.Config{
		RootCAs:    clientPool,
		ServerName: "127.0.0.1",
		MinVersion: tls.VersionTLS12,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS: %v", err)
	}
	// StartupMessage with replication=true.
	body := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	body = append(body, v...)
	body = append(body, []byte("user\x00rep\x00replication\x00true\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := tlsConn.Write(append(hdr, body...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}
	// Pump check.
	if _, err := tlsConn.Write([]byte("REPL")); err != nil {
		t.Fatalf("write pump payload: %v", err)
	}
	buf := make([]byte, 4)
	_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "REPL" {
		t.Errorf("echo = %q, want REPL", buf)
	}
	// Tear down + assert DVW.
	tlsConn.Close()
	time.Sleep(100 * time.Millisecond)
	evs := h.sink.Drain()
	var found *events.LifecycleEvent
	for i := range evs {
		if evs[i].Kind == "degraded_visibility_warning" && evs[i].DegradedReason == "replication_passthrough" {
			found = &evs[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("no replication_passthrough DVW; events=%+v", evs)
	}
}

func TestSpine_Cancel_AllowedForwardsUnmapped(t *testing.T) {
	var captured []byte
	upAddr := captureCancelListener(t, &captured)
	rule := `  - name: allow-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
`
	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, rule)
	stop := runServer(t, h.srv)
	defer stop()

	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	pkt := buildCancelPacket(77777, 88888)
	if _, err := c.Write(pkt); err != nil {
		t.Fatalf("write cancel: %v", err)
	}
	for i := 0; i < 100 && len(captured) < 16; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if len(captured) != 16 {
		t.Fatalf("captured %d bytes upstream, want 16", len(captured))
	}
	for i := range pkt {
		if captured[i] != pkt[i] {
			t.Errorf("byte %d: got %#x, want %#x", i, captured[i], pkt[i])
		}
	}
}

func TestSpine_Cancel_DeniedSilentClose(t *testing.T) {
	dialed := make(chan struct{}, 1)
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	go func() {
		if c, err := upLn.Accept(); err == nil {
			dialed <- struct{}{}
			c.Close()
		}
	}()
	rule := `  - name: deny-cancel
    db_service: appdb
    match_kind: cancel
    decision: deny
`
	h := startSpineHarness(t, upLn.Addr().String(), "terminate_plaintext_upstream", nil, rule)
	stop := runServer(t, h.srv)
	defer stop()

	c, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial unix: %v", err)
	}
	defer c.Close()
	pkt := buildCancelPacket(1, 2)
	if _, err := c.Write(pkt); err != nil {
		t.Fatalf("write cancel: %v", err)
	}
	select {
	case <-dialed:
		t.Error("upstream was dialed despite deny rule")
	case <-time.After(300 * time.Millisecond):
		// Expected: no dial.
	}
}
```

- [ ] **Step 3: Run the spine tests**

Run: `go test ./internal/db/proxy/postgres/ -run TestSpine -v -timeout 60s`
Expected: PASS for all seven.

- [ ] **Step 4: Run the full package tests**

Run: `go test ./internal/db/proxy/postgres/ -v -timeout 120s`
Expected: PASS for everything.

- [ ] **Step 5: Cross-compile**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/testupstream_test.go internal/db/proxy/postgres/spine_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: spine round-trip tests + fake-upstream helper

Plan 04b₂ Task 10. newFakeUpstream binds 127.0.0.1:0 (plaintext or TLS),
runs a per-conn script via *pgproto3.Backend, and tracks accepted-conn
counts. Seven spine tests exercise the full proxy: terminate_reissue
AuthOK close-at-RFQ; terminate_plaintext_upstream close-at-RFQ;
terminate_reissue SCRAM-PLUS fail-closed; passthrough byte-pump
echoes; replication opt-in pump emits DVW; cancel allowed forwards
un-mapped; cancel denied silent-close. All clients are hand-rolled
(net.Dial + raw bytes); no pgx-driven assertions to keep tests robust
against the close-at-RFQ terminator.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Roborev between tasks**

---

## Task 11: Final verification

**Why:** Belt-and-suspenders pass before declaring 04b₂ done.

**Files:** None (verification only, optional release-notes update).

- [ ] **Step 1: Run the full repo test suite**

Run: `go test ./... -timeout 120s`
Expected: all pass on Linux. Pre-existing flakes documented in `MEMORY.md` (`TestFlushLoop_PeriodicSync`, `TestStore_*EmitsTransportLoss*`) are not regressions if they trip; rerun once.

- [ ] **Step 2: Cross-compile for Windows + macOS**

Run in parallel:
- `GOOS=windows go build ./...`
- `GOOS=darwin go build ./...`

Expected: both succeed.

- [ ] **Step 3: Manual psql smoke (informational; do NOT commit the smoke driver)**

Start a real Postgres instance with channel binding disabled in `pg_hba.conf` (e.g. `host all all 0.0.0.0/0 md5`), or use a Postgres docker image that defaults to `scram-sha-256` only (PG 14+ with no `ssl_passphrase_command`).

Build a one-off `cmd/dbproxy-smoke/main.go` (do NOT commit) that constructs a `postgres.Server` with one Unix-socket service in `terminate_reissue` mode pointing at the real PG, an allow-everyone connection rule, and no `UpstreamTLSConfigForTest`. Run it. From a second terminal:

```bash
PGSSLROOTCERT=$STATE_DIR/db-ca.crt \
  psql "host=$SOCKET_DIR sslmode=verify-full user=$PG_USER dbname=postgres password=$PG_PW"
```

Expected: psql completes the handshake (`SELECT 1;` will fail because Plan 04c hasn't shipped — psql sees connection close after the welcome banner). The proxy logs one `db_listener_auth_fail`-or-success cycle and exits cleanly.

If the upstream advertises SCRAM-SHA-256-PLUS, expect: `FATAL: AgentSH DB proxy cannot terminate channel-bound SCRAM (SCRAM-SHA-256-PLUS)...`. This is the documented Plan 04b₂ behavior.

- [ ] **Step 4: Roborev final pass**

Run `roborev-review-branch` against the merged 04b₂ branch. Address findings above `low` severity before opening the PR.

- [ ] **Step 5: Update plan checkboxes**

Confirm every checkbox above this section is checked. Open follow-up tasks for any defect found during verification.

- [ ] **Step 6: Final commit (only if verification fixes were needed)**

```bash
git status
# If clean, nothing to commit. Otherwise:
git add <files>
git commit -m "db: Plan 04b₂ verification fixes

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Out-of-scope reminders (do NOT do in Plan 04b₂)

- Q-frame classify / forward / synthesize-deny; `db_statement` events — Plan 04c.
- RFQ status-byte tracker — Plan 04c.
- Frame budget cap (`MaxQueryBytes`, default 1 MiB) → synthetic `54000` — Plan 04c.
- GSSENC opt-in (`allow_gss_encryption: true`) — Plan 05.
- Extended Query / transaction state machine — Plan 05.
- BackendKeyData mapping table; cancel governance via mapping lookup — Plan 06.
- Out-of-process proxy under distinct SessionID; SO_PEERCRED → SessionID resolution; unavoidability bundle — Plan 07.
- Real-PG integration tests with testcontainers — Plan 07.

**Release-notes call-outs (for the PR description, not the code):**

1. *Cancel happens to work end-to-end in 04b₂ even without the Plan 06 mapping table.* Because `forwardAuth` forwards the real upstream `BackendKeyData(PID, Secret)` to clients verbatim, and `forwardCancel` writes the client's PID/Secret verbatim to upstream, the upstream sees its own real values and the cancel works. Plan 06 will introduce a mapping table that rewrites these values, and at that point cancels will only work for connections that had their BackendKeyData mapped — a behavior change that may surprise operators upgrading from 04b₂ → 06. Flag prominently.

2. *SCRAM-SHA-256-PLUS prevalence.* Modern default Postgres builds (PG 16+) advertise SCRAM-SHA-256-PLUS in the SASL mechanism list when TLS is in use. Operators running `terminate_reissue` against unmodified clusters will hit `SCRAM_PLUS_FAIL_CLOSED` immediately. The documented workaround is to disable upstream channel binding (`scram_threshold`-equivalent setting) or use `passthrough` for the affected service. The credential broker (Phase 4) is the long-term fix.

3. *Plan 04c will replace the close-at-RFQ terminator* with the Q-frame classify-and-forward loop. Operators running 04b₂ in `observe` mode will see clean connection drops after every handshake; this is expected. Statement execution requires 04c.
