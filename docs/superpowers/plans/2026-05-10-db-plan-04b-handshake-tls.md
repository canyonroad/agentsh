# db-access Plan 04b — Handshake + Inbound TLS Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Take the 04a listener skeleton from "accept and immediately close after peercred" to "client completes inbound Postgres handshake (SSL + StartupMessage), the proxy evaluates connect-kind connection rules, and either synthesizes a §13.3 deny or returns a clean *upstream-not-wired* error." No upstream socket exists yet — Plan 04b₂ adds upstream dial, auth forwarding, the byte-passthrough loop, replication opt-in, and CancelRequest dispatch.

**Architecture:** Add `internal/db/tlsleaf/` as a separate cross-platform package for the lazily-loaded self-signed CA + per-hostname leaf cache. Inside `internal/db/proxy/postgres/` (Linux-only), replace `handleConn`'s peercred-only body with a `proxyConn` driver that owns per-connection state, runs `pgproto3` framing, dispatches the four startup-packet types, terminates inbound TLS via tlsleaf, evaluates `match_kind=connect` (and rejects `replication=true` by default), and exits with a structured `ErrorResponse` when 04b's scope ends.

**Tech Stack:** Go (`//go:build linux` for proxy code), `github.com/jackc/pgx/v5/pgproto3` (NEW dep) for wire framing, `crypto/tls` + `crypto/x509` + `crypto/rsa` + `crypto/ecdsa` for the CA. Existing in-repo: `internal/db/policy.EvaluateConnection`, `internal/db/events.LifecycleEvent`, `internal/db/proxy/postgres.Server` (04a).

**Settled in brainstorming (2026-05-10):**
1. After StartupMessage is allowed by connection rules, the proxy synthesizes `ErrorResponse(SQLSTATE 0A000, code=UPSTREAM_NOT_YET_WIRED)` and closes. Plan 04b₂ replaces this with the upstream dial.
2. `passthrough` TLS-mode services are rejected at `Server.New` with a clear error referencing Plan 04b₂. Operators can declare them in config; the supervisor will error on startup until 04b₂ lands.
3. `replication=true` StartupMessages are denied by default in 04b (no opt-in yet). Plan 04b₂ adds the opt-in passthrough path.
4. `CancelRequest` startup packets are silently closed in 04b. Plan 04b₂ adds the connection-rule eval + un-mapped forward.
5. `tlsleaf` is its own package — Linux-agnostic, no build tags — so unit tests of CA + leaf issuance run on macOS dev boxes.

**Cross-references:**
- Macro design: `docs/superpowers/specs/2026-05-10-db-plan-04-pg-proxy-skeleton-design.md`
- Roadmap: `docs/superpowers/specs/2026-05-08-db-access-phase-1-roadmap-design.md` §3 Plan 04
- Spec: `docs/agentsh-db-access-spec.md` v0.8 §7.1, §11.1, §11.3 (steps 3–8), §13.1, §13.2, §13.3
- Predecessor: `docs/superpowers/plans/2026-05-10-db-plan-04a-listener-skeleton.md`

---

## File Structure

**Created:**

- `internal/db/tlsleaf/ca.go` — Lazy load-or-create AgentSH-DB CA persisted under `${StateDir}/db-ca.{key,crt}`.
- `internal/db/tlsleaf/ca_test.go` — Round-trip persistence + perms.
- `internal/db/tlsleaf/leaf.go` — Per-hostname leaf issuer with in-process LRU (cap 256).
- `internal/db/tlsleaf/leaf_test.go` — SAN content + cache-hit semantics.
- `internal/db/proxy/postgres/proxyconn.go` — `connState` + `proxyConn` driver replacing 04a's no-op body.
- `internal/db/proxy/postgres/proxyconn_test.go` — End-to-end driver tests using `net.Pipe()`.
- `internal/db/proxy/postgres/handshake.go` — Startup-packet dispatch (SSLRequest / GSSENCRequest / CancelRequest / StartupMessage).
- `internal/db/proxy/postgres/handshake_test.go` — Hand-rolled byte tests for each branch.
- `internal/db/proxy/postgres/tls.go` — Inbound TLS termination for `terminate_reissue` and `terminate_plaintext_upstream`.
- `internal/db/proxy/postgres/tls_test.go` — Per-mode handshake against `crypto/tls` client.
- `internal/db/proxy/postgres/sni.go` — Best-effort ClientHello SNI extractor (used by 04b₂'s passthrough; recorded into connState in 04b for completeness).
- `internal/db/proxy/postgres/sni_test.go` — Hand-rolled ClientHello bytes covering present / absent / fragmented SNI.
- `internal/db/proxy/postgres/connect_rule.go` — Connect-kind connection-rule eval + §13.3 deny synthesis helper.
- `internal/db/proxy/postgres/connect_rule_test.go` — Allow / deny / replication-default-deny cases.

**Modified:**

- `internal/db/events/lifecycle.go` — Add `SNIHostname` optional field for `db_handshake_fail` and (later) `degraded_visibility_warning` events.
- `internal/db/events/lifecycle_test.go` — Cover the new field.
- `internal/db/proxy/postgres/server.go` — Reject `passthrough`-mode services at `New` with `errors.ErrUnsupported + structured msg`; add `CA *tlsleaf.CA` field to `Config` (or lazy load); replace `handleConn` body to call `proxyConn`.
- `internal/db/proxy/postgres/server_test.go` — Add `passthrough`-rejection test; keep existing tests passing.
- `internal/db/proxy/postgres/stub_other.go` — Mirror new exported types (`Config.CA` is a private indirection; no stub change needed if CA stays internal).
- `go.mod` / `go.sum` — `github.com/jackc/pgx/v5` (only the `pgproto3` sub-package is imported).

**Out of scope for 04b (deferred to 04b₂):**

- Upstream TCP dial; upstream TLS; auth-byte forwarding; SCRAM-SHA-256-PLUS detection.
- `passthrough` TLS mode (requires upstream wiring).
- Post-handshake byte-passthrough loop.
- `replication=true` opt-in passthrough.
- `CancelRequest` connection-rule eval + un-mapped forward.
- `degraded_visibility_warning` event emission.
- pgx-based spine round-trip test (the in-process tests in 04b use `crypto/tls.Client` directly).

---

## Task 1: Preflight — pgproto3 dep + LifecycleEvent SNIHostname field

**Why:** All later tasks consume `pgproto3` framing and the `SNIHostname` lifecycle field. Land both first so subsequent tasks compile in isolation.

**Files:**
- Modify: `go.mod`, `go.sum`
- Modify: `internal/db/events/lifecycle.go`
- Modify: `internal/db/events/lifecycle_test.go`

- [ ] **Step 1: Add the pgproto3 dependency**

Run:
```bash
go get github.com/jackc/pgx/v5@v5.9.2
go mod tidy
```

Expected: `go.mod` gains `github.com/jackc/pgx/v5 v5.9.2`; `go.sum` updates.

- [ ] **Step 2: Verify pgproto3 imports cleanly**

Create a one-line scratch file at `/tmp/pgproto3-probe.go`:
```go
package main

import _ "github.com/jackc/pgx/v5/pgproto3"

func main() {}
```

Run: `go run /tmp/pgproto3-probe.go`
Expected: clean exit. Delete the file.

- [ ] **Step 3: Write the failing test for the SNIHostname field**

Replace the body of `TestLifecycleEvent_JSONRoundTrip` in `internal/db/events/lifecycle_test.go` with a version that includes `SNIHostname`:

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
		Kind:           "db_handshake_fail",
		Reason:         "scram_plus_fail_closed",
		PeerUID:        2000,
		PeerPID:        12345,
		ErrorCode:      "SCRAM_PLUS_FAIL_CLOSED",
		SNIHostname:    "db.internal",
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

func TestLifecycleEvent_OmitsEmptySNIHostname(t *testing.T) {
	ev := LifecycleEvent{Kind: "db_listener_auth_fail", Timestamp: time.Now()}
	bs, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if got := string(bs); contains(got, "sni_hostname") {
		t.Errorf("sni_hostname must be omitted when empty; got %s", got)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `go test ./internal/db/events/ -run TestLifecycleEvent -v`
Expected: FAIL with `unknown field SNIHostname`.

- [ ] **Step 5: Add the field**

Edit `internal/db/events/lifecycle.go`. Add the field below `ErrorCode`:

```go
	// Handshake/error specific (Plan 04b). Zero when not applicable.
	ErrorCode string `json:"error_code,omitempty"`

	// TLS SNI from inbound ClientHello (Plan 04b). Best-effort under
	// passthrough; recorded under terminate_* when the client sets it.
	// Spec §13.2 footnote: SNI is advisory.
	SNIHostname string `json:"sni_hostname,omitempty"`
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `go test ./internal/db/events/ -run TestLifecycleEvent -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum internal/db/events/lifecycle.go internal/db/events/lifecycle_test.go
git commit -m "$(cat <<'EOF'
db: add pgproto3 dep and LifecycleEvent.SNIHostname field

Plan 04b preflight. github.com/jackc/pgx/v5 added for the pgproto3
sub-package only; LifecycleEvent gains an optional SNIHostname field
that the handshake-fail and degraded-visibility events will populate
(spec §13.2 SNI is advisory; recorded for audit-trail completeness).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 8: Roborev between tasks**

Per `MEMORY.md` `feedback_roborev_between_tasks.md`: run `roborev-review-branch` before starting Task 2. Address findings above `low` severity inline.

---

## Task 2: `internal/db/tlsleaf` package — CA load-or-create + leaf issuer

**Why:** Inbound TLS termination requires a leaf certificate whose chain a client can trust. The proxy persists one self-signed CA under StateDir and issues a leaf per upstream hostname at connect time. Both pieces are pure crypto — easy to test in isolation, no build tags needed.

**Files:**
- Create: `internal/db/tlsleaf/ca.go`
- Create: `internal/db/tlsleaf/ca_test.go`
- Create: `internal/db/tlsleaf/leaf.go`
- Create: `internal/db/tlsleaf/leaf_test.go`

- [ ] **Step 1: Write the failing test for CA LoadOrCreate**

Create `internal/db/tlsleaf/ca_test.go`:

```go
package tlsleaf

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadOrCreate_FirstCallGenerates(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate (first): %v", err)
	}
	if ca == nil {
		t.Fatal("CA is nil")
	}
	keyPath := filepath.Join(dir, "db-ca.key")
	crtPath := filepath.Join(dir, "db-ca.crt")
	keyFI, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyFI.Mode()&0o777 != 0o600 {
		t.Errorf("key perms = %#o, want 0600", keyFI.Mode()&0o777)
	}
	crtFI, err := os.Stat(crtPath)
	if err != nil {
		t.Fatalf("stat crt: %v", err)
	}
	if crtFI.Mode()&0o777 != 0o644 {
		t.Errorf("crt perms = %#o, want 0644", crtFI.Mode()&0o777)
	}
	if ca.Cert().Subject.CommonName != "AgentSH DB Proxy CA" {
		t.Errorf("CN = %q, want \"AgentSH DB Proxy CA\"", ca.Cert().Subject.CommonName)
	}
	if !ca.Cert().IsCA {
		t.Error("CA cert IsCA = false; want true")
	}
}

func TestLoadOrCreate_SecondCallLoads(t *testing.T) {
	dir := t.TempDir()
	first, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate (first): %v", err)
	}
	second, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate (second): %v", err)
	}
	if !first.Cert().Equal(second.Cert()) {
		t.Fatal("second LoadOrCreate produced a different certificate; expected reuse")
	}
}

func TestLoadOrCreate_RejectsNonCAExistingCert(t *testing.T) {
	dir := t.TempDir()
	// Drop a non-CA-looking blob at the cert path.
	if err := os.WriteFile(filepath.Join(dir, "db-ca.crt"), []byte("not a cert"), 0o644); err != nil {
		t.Fatalf("write garbage cert: %v", err)
	}
	if _, err := LoadOrCreate(dir, time.Now); err == nil {
		t.Fatal("LoadOrCreate over corrupted cert: want error, got nil")
	}
}

func TestCA_VerifyOptions(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	if pool.Equal(x509.NewCertPool()) {
		t.Fatal("pool with CA equals empty pool; CertPool not exposing CA correctly")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/tlsleaf/ -run TestLoadOrCreate -v`
Expected: FAIL with `no Go files`.

- [ ] **Step 3: Implement `internal/db/tlsleaf/ca.go`**

```go
// Package tlsleaf provides a lazily-generated self-signed CA and per-hostname
// leaf issuer for the AgentSH DB proxy's TLS termination path. The CA is
// persisted under a caller-provided StateDir; leaves are issued on demand and
// cached in-process. Operators copy the CA cert into client trust stores
// (sslrootcert) so downstream PostgreSQL clients accept proxied connections.
//
// The package is platform-agnostic; tests run on every supported OS.
package tlsleaf

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	caKeyFile  = "db-ca.key"
	caCertFile = "db-ca.crt"
	caCN       = "AgentSH DB Proxy CA"
	caKeyBits  = 4096
	caValidFor = 10 * 365 * 24 * time.Hour
)

// CA is the AgentSH-DB self-signed certificate authority. Construct via
// LoadOrCreate. Methods are safe for concurrent use.
type CA struct {
	mu   sync.Mutex
	cert *x509.Certificate
	key  *rsa.PrivateKey
	clk  func() time.Time
}

// LoadOrCreate loads the CA from stateDir if both files are present, or
// generates a fresh CA on first call and persists it (key 0600, cert 0644).
// stateDir must already exist; the parent of any sub-path is not created.
//
// Failure modes:
//   - stateDir does not exist or is not a directory.
//   - One of the two files exists but cannot be parsed.
//   - The persisted cert exists but is not a CA (malformed/manual edit).
func LoadOrCreate(stateDir string, clock func() time.Time) (*CA, error) {
	if clock == nil {
		clock = time.Now
	}
	fi, err := os.Stat(stateDir)
	if err != nil {
		return nil, fmt.Errorf("tlsleaf: stat %q: %w", stateDir, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("tlsleaf: %q is not a directory", stateDir)
	}
	keyPath := filepath.Join(stateDir, caKeyFile)
	crtPath := filepath.Join(stateDir, caCertFile)

	keyBytes, keyErr := os.ReadFile(keyPath)
	crtBytes, crtErr := os.ReadFile(crtPath)
	keyExists := keyErr == nil
	crtExists := crtErr == nil

	if keyExists && crtExists {
		ca, err := loadCA(keyBytes, crtBytes)
		if err != nil {
			return nil, fmt.Errorf("tlsleaf: load existing CA: %w", err)
		}
		ca.clk = clock
		return ca, nil
	}
	if keyExists != crtExists {
		return nil, fmt.Errorf("tlsleaf: incomplete CA on disk (have key=%v, cert=%v); refusing to regenerate", keyExists, crtExists)
	}
	return generateAndPersist(stateDir, clock)
}

func loadCA(keyPEM, crtPEM []byte) (*CA, error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("malformed key PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	crtBlock, _ := pem.Decode(crtPEM)
	if crtBlock == nil || crtBlock.Type != "CERTIFICATE" {
		return nil, errors.New("malformed cert PEM")
	}
	cert, err := x509.ParseCertificate(crtBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("persisted cert is not a CA")
	}
	return &CA{cert: cert, key: key}, nil
}

func generateAndPersist(stateDir string, clock func() time.Time) (*CA, error) {
	key, err := rsa.GenerateKey(rand.Reader, caKeyBits)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	now := clock()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: caCN},
		NotBefore:    now.Add(-1 * time.Hour),
		NotAfter:     now.Add(caValidFor),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:         true,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("self-sign: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse self-signed: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	crtPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyPath := filepath.Join(stateDir, caKeyFile)
	crtPath := filepath.Join(stateDir, caCertFile)
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := os.WriteFile(crtPath, crtPEM, 0o644); err != nil {
		_ = os.Remove(keyPath)
		return nil, fmt.Errorf("write cert: %w", err)
	}
	return &CA{cert: cert, key: key, clk: clock}, nil
}

// Cert returns the CA certificate. Safe for concurrent use; callers must
// not mutate the returned value.
func (c *CA) Cert() *x509.Certificate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cert
}

// Key returns the CA private key. Test-internal use only; production code
// uses IssueLeaf instead. Safe for concurrent use.
func (c *CA) Key() *rsa.PrivateKey {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.key
}

// Now returns the configured clock's notion of "now". Used by leaf.go.
func (c *CA) Now() time.Time {
	c.mu.Lock()
	clk := c.clk
	c.mu.Unlock()
	if clk == nil {
		return time.Now()
	}
	return clk()
}

func serial() *big.Int {
	max := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		// The reader is crypto/rand; failure is catastrophic and we cannot
		// proceed. Panic mirrors stdlib behavior in similar paths.
		panic(fmt.Sprintf("tlsleaf: serial: %v", err))
	}
	return n
}
```

- [ ] **Step 4: Run CA tests to verify they pass**

Run: `go test ./internal/db/tlsleaf/ -run TestLoadOrCreate -v`
Expected: PASS.

- [ ] **Step 5: Write the failing test for the leaf issuer**

Create `internal/db/tlsleaf/leaf_test.go`:

```go
package tlsleaf

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestIssueLeaf_SignedByCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	leaf, err := ca.IssueLeaf("db.internal")
	if err != nil {
		t.Fatalf("IssueLeaf: %v", err)
	}
	if len(leaf.Certificate) == 0 {
		t.Fatal("leaf has empty certificate chain")
	}
	parsed, err := x509.ParseCertificate(leaf.Certificate[0])
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())
	if _, err := parsed.Verify(x509.VerifyOptions{Roots: pool, DNSName: "db.internal"}); err != nil {
		t.Fatalf("verify leaf against CA: %v", err)
	}
}

func TestIssueLeaf_SAN(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	leaf, _ := ca.IssueLeaf("db.example.com")
	parsed, _ := x509.ParseCertificate(leaf.Certificate[0])
	if len(parsed.DNSNames) != 1 || parsed.DNSNames[0] != "db.example.com" {
		t.Errorf("DNSNames = %v, want [db.example.com]", parsed.DNSNames)
	}
}

func TestIssueLeaf_CacheReturnsSameCert(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreate(dir, time.Now)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	a, _ := ca.IssueLeaf("host-a")
	b, _ := ca.IssueLeaf("host-a")
	if &a.Certificate[0][0] != &b.Certificate[0][0] {
		// Compare byte slices; a stricter check would assert identity.
		if string(a.Certificate[0]) != string(b.Certificate[0]) {
			t.Error("cache miss: different bytes for same hostname")
		}
	}
}

func TestIssueLeaf_DifferentHostsDifferentCerts(t *testing.T) {
	dir := t.TempDir()
	ca, _ := LoadOrCreate(dir, time.Now)
	a, _ := ca.IssueLeaf("host-a")
	b, _ := ca.IssueLeaf("host-b")
	if string(a.Certificate[0]) == string(b.Certificate[0]) {
		t.Error("different hostnames produced identical certificates")
	}
}
```

- [ ] **Step 6: Run leaf tests to verify they fail**

Run: `go test ./internal/db/tlsleaf/ -run TestIssueLeaf -v`
Expected: FAIL with `ca.IssueLeaf undefined`.

- [ ] **Step 7: Implement `internal/db/tlsleaf/leaf.go`**

```go
package tlsleaf

import (
	"container/list"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"sync"
	"time"
)

const (
	leafValidFor = 90 * 24 * time.Hour
	leafCacheCap = 256
)

// IssueLeaf returns a tls.Certificate whose leaf is signed by the CA and
// whose only SAN is hostname. Cached in-process under hostname; cache size
// is bounded at 256 entries (LRU). Repeated calls for the same hostname
// return the cached certificate (no re-issuance).
//
// The leaf's notBefore/notAfter use the CA's clock so tests with an
// injected clock get deterministic validity windows.
func (c *CA) IssueLeaf(hostname string) (*tls.Certificate, error) {
	if hostname == "" {
		return nil, fmt.Errorf("tlsleaf: IssueLeaf: hostname is empty")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = newLeafCache(leafCacheCap)
	}
	if cached, ok := c.cache.get(hostname); ok {
		return cached, nil
	}
	leaf, err := c.issueLeafLocked(hostname)
	if err != nil {
		return nil, err
	}
	c.cache.put(hostname, leaf)
	return leaf, nil
}

func (c *CA) issueLeafLocked(hostname string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	now := c.clk
	if now == nil {
		now = time.Now
	}
	t := now()
	tmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    t.Add(-1 * time.Hour),
		NotAfter:     t.Add(leafValidFor),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, fmt.Errorf("sign leaf: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der, c.cert.Raw},
		PrivateKey:  key,
	}, nil
}

// --- LRU cache (private; one instance per CA) ---

type leafCache struct {
	cap   int
	ll    *list.List
	items map[string]*list.Element
}

type leafEntry struct {
	host string
	leaf *tls.Certificate
}

func newLeafCache(cap int) *leafCache {
	return &leafCache{cap: cap, ll: list.New(), items: make(map[string]*list.Element, cap)}
}

func (c *leafCache) get(host string) (*tls.Certificate, bool) {
	el, ok := c.items[host]
	if !ok {
		return nil, false
	}
	c.ll.MoveToFront(el)
	return el.Value.(*leafEntry).leaf, true
}

func (c *leafCache) put(host string, leaf *tls.Certificate) {
	if el, ok := c.items[host]; ok {
		c.ll.MoveToFront(el)
		el.Value.(*leafEntry).leaf = leaf
		return
	}
	c.items[host] = c.ll.PushFront(&leafEntry{host: host, leaf: leaf})
	if c.ll.Len() > c.cap {
		oldest := c.ll.Back()
		if oldest != nil {
			c.ll.Remove(oldest)
			delete(c.items, oldest.Value.(*leafEntry).host)
		}
	}
}
```

Add the cache field to `CA` in `ca.go`:

```go
type CA struct {
	mu    sync.Mutex
	cert  *x509.Certificate
	key   *rsa.PrivateKey
	clk   func() time.Time
	cache *leafCache
}
```

(The `mu` already exists; just add the `cache` line.)

- [ ] **Step 8: Run leaf tests to verify they pass**

Run: `go test ./internal/db/tlsleaf/ -v`
Expected: PASS for both `TestLoadOrCreate*` and `TestIssueLeaf*`.

- [ ] **Step 9: Cross-compile**

Run: `GOOS=windows go build ./internal/db/tlsleaf/...`
Expected: build success.

Run: `GOOS=darwin go build ./internal/db/tlsleaf/...`
Expected: build success.

- [ ] **Step 10: Commit**

```bash
git add internal/db/tlsleaf/
git commit -m "$(cat <<'EOF'
db/tlsleaf: lazy self-signed CA + per-hostname leaf issuer

Plan 04b Task 2. internal/db/tlsleaf is the AgentSH DB proxy's TLS
termination primitive. LoadOrCreate persists the CA under StateDir
(key 0600 / cert 0644, CN "AgentSH DB Proxy CA", 10-year RSA-4096).
IssueLeaf returns a P-256 leaf for a given upstream hostname, signed
by the CA and cached LRU (cap 256) per process.

Spec §13.1 and design doc §5 govern; package is platform-agnostic so
unit tests run on every supported OS.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 11: Roborev between tasks**

Per `MEMORY.md` `feedback_roborev_between_tasks.md`. Address findings above `low`.

---

## Task 3: Wire `tlsleaf.CA` into `postgres.Config` (lazy load) + reject `passthrough` services

**Why:** The Server needs a CA available before any `terminate_*` connection completes. We add a `*tlsleaf.CA` field to `Config` (caller may pre-supply for tests) plus lazy load-on-first-need from `cfg.StateDir`. We also reject `passthrough` services at `New` because Plan 04b cannot satisfy them (no upstream wiring).

**Files:**
- Modify: `internal/db/proxy/postgres/server.go`
- Modify: `internal/db/proxy/postgres/server_test.go`
- Modify: `internal/db/proxy/postgres/stub_other.go` (no shape change; just verify still compiles)

- [ ] **Step 1: Write the failing tests**

Append to `internal/db/proxy/postgres/server_test.go`:

```go
func TestServer_New_RejectsPassthroughService(t *testing.T) {
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
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (passthrough): want error referencing Plan 04b₂, got nil")
	}
	if !strings.Contains(err.Error(), "passthrough") {
		t.Errorf("New error = %q; want it to mention passthrough", err)
	}
}

func TestServer_LazyCALoad(t *testing.T) {
	dir := t.TempDir()
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       dir,
		Sink:           &events.SyncSink{},
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "appdb.sock")},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ca, err := srv.ca()
	if err != nil {
		t.Fatalf("ca() first call: %v", err)
	}
	if ca == nil {
		t.Fatal("ca() returned nil")
	}
	// Files should now exist under StateDir.
	if _, err := os.Stat(filepath.Join(dir, "db-ca.crt")); err != nil {
		t.Errorf("db-ca.crt missing after lazy load: %v", err)
	}
	again, err := srv.ca()
	if err != nil {
		t.Fatalf("ca() second call: %v", err)
	}
	if again != ca {
		t.Error("ca() did not return cached pointer on second call")
	}
}
```

Add `"strings"` to the imports.

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run "TestServer_New_RejectsPassthrough|TestServer_LazyCA" -v`
Expected: FAIL — `srv.ca undefined`; passthrough not rejected.

- [ ] **Step 3: Modify `internal/db/proxy/postgres/server.go`**

Add the import:

```go
"github.com/agentsh/agentsh/internal/db/tlsleaf"
```

Add a CA field and accessor on `Server`:

```go
type Server struct {
	// ... existing fields ...

	caMu  sync.Mutex
	caRef *tlsleaf.CA
}
```

(The existing `mu` is for run-state; `caMu` keeps CA loading out of the lifecycle critical section.)

Inside `New`, just before the final `return &Server{...}, nil`, add a per-service passthrough check:

```go
	for i, svc := range cfg.Services {
		if svc.Name == "" {
			return nil, fmt.Errorf("postgres.New: services[%d].Name is empty", i)
		}
		if svc.TLSMode == "passthrough" {
			return nil, fmt.Errorf("postgres.New: services[%d] (%s) tls_mode: passthrough requires upstream wiring (Plan 04b₂); declare a terminate_* mode or wait for 04b₂", i, svc.Name)
		}
		if svc.Listen.Kind != "unix" && svc.Listen.Kind != "tcp" {
			return nil, fmt.Errorf("postgres.New: services[%d].Listen.Kind = %q; want unix or tcp", i, svc.Listen.Kind)
		}
		if svc.Listen.Kind == "unix" && svc.Listen.Path == "" {
			return nil, fmt.Errorf("postgres.New: services[%d].Listen.Path is empty for unix listener", i)
		}
	}
```

Add the `ca()` accessor at the bottom of the file:

```go
// ca returns the CA, loading or generating it on first call. Concurrent
// callers see the same instance.
func (s *Server) ca() (*tlsleaf.CA, error) {
	s.caMu.Lock()
	defer s.caMu.Unlock()
	if s.caRef != nil {
		return s.caRef, nil
	}
	ca, err := tlsleaf.LoadOrCreate(s.cfg.StateDir, timeNow)
	if err != nil {
		return nil, fmt.Errorf("postgres.Server: load CA: %w", err)
	}
	s.caRef = ca
	s.logger.Info("postgres.Server: CA loaded",
		"key", filepath.Join(s.cfg.StateDir, "db-ca.key"),
		"cert", filepath.Join(s.cfg.StateDir, "db-ca.crt"))
	return ca, nil
}
```

Add `"path/filepath"` to the imports if not already present.

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run "TestServer_New|TestServer_LazyCA|TestServer_StartShutdown|TestServer_StartTwice|TestServer_OffMode" -v`
Expected: PASS for all.

- [ ] **Step 5: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/server.go internal/db/proxy/postgres/server_test.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: lazy CA load + reject passthrough until 04b₂

Plan 04b Task 3. Server.ca() lazy-loads (or generates) the AgentSH-DB
CA from cfg.StateDir on first call. Passthrough-mode services now
fail Server.New with a clear error pointing to Plan 04b₂, since
passthrough requires upstream wiring that is out of 04b's scope.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 7: Roborev between tasks**

---

## Task 4: pgproto3 framing + `proxyConn` driver (replace `handleConn` no-op)

**Why:** Plan 04a's `handleConn` body returns immediately after a successful peercred check, closing the conn. Plan 04b replaces that body with `proxyConn`, a per-connection driver that owns `connState` and orchestrates the handshake. Tasks 5–7 plug in the actual handshake/TLS/eval branches.

**Files:**
- Create: `internal/db/proxy/postgres/proxyconn.go`
- Create: `internal/db/proxy/postgres/proxyconn_test.go`
- Modify: `internal/db/proxy/postgres/server.go` (replace `handleConn` body)

- [ ] **Step 1: Write the failing test**

Create `internal/db/proxy/postgres/proxyconn_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestProxyConn_StubReturnsClean(t *testing.T) {
	// proxyConn with no wired branches is a no-op closer; this just ensures
	// the type compiles and the closure path runs without panic.
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
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.runProxyConn(ctx, srv.cfg.Services[0], a)
	}()
	// Closing b mimics client disconnect; runProxyConn must return.
	b.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("runProxyConn did not return after client disconnect")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -run TestProxyConn_Stub -v`
Expected: FAIL — `srv.runProxyConn undefined`.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/proxyconn.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"errors"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// connState is the per-connection state carried through the 04b handshake.
// 04b₂ grows this with upstream-side fields (BackendKeyData, RFQ tracker).
type connState struct {
	dbService       string
	dbUser          string
	database        string
	appName         string
	clientIdentity  string // "uid:<peer_uid>" placeholder until Plan 07
	sniHostname     string // best-effort; set by tls.go and sni.go
	replication     bool
	tlsTerminated   bool   // true once inbound TLS handshake completes
	peerUID         uint32 // captured at SO_PEERCRED time
}

// proxyConn drives one client connection through the 04b handshake. It
// owns the *pgproto3.Backend used for client-facing framing and the
// connState. Branches plugged in by Tasks 5–7:
//
//   - handshake.go: startup-packet dispatch (SSLRequest / GSSENCRequest /
//     CancelRequest / StartupMessage).
//   - tls.go:       inbound TLS termination (terminate_* modes).
//   - connect_rule.go: connect-kind connection-rule eval + §13.3 deny.
//
// On exit the conn is closed by the caller (acceptLoop's deferred Close).
type proxyConn struct {
	srv     *Server
	svc     Service
	logger  logger
	conn    net.Conn // current client-facing conn (may be a *tls.Conn after Task 6)
	backend *pgproto3.Backend
	state   *connState
}

// logger narrows *slog.Logger to just the methods we use, so tests can
// substitute a no-op when verbose output would clutter t.Log.
type logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Debug(msg string, args ...any)
}

func newProxyConn(srv *Server, svc Service, conn net.Conn, peerUID uint32) *proxyConn {
	return &proxyConn{
		srv:     srv,
		svc:     svc,
		logger:  srv.logger,
		conn:    conn,
		backend: pgproto3.NewBackend(conn, conn),
		state: &connState{
			dbService:      svc.Name,
			peerUID:        peerUID,
			clientIdentity: clientIdentityFromUID(peerUID),
		},
	}
}

func clientIdentityFromUID(uid uint32) string {
	return formatUID(uid)
}

// runProxyConn is invoked from Server.handleConn after peercred passes.
// It runs the handshake to completion (or to a synthesized error) and
// returns; the caller closes the underlying conn.
//
// This stub returns immediately; Tasks 5–7 fill it in.
func (s *Server) runProxyConn(ctx context.Context, svc Service, conn net.Conn) {
	pc := newProxyConn(s, svc, conn, 0) // peerUID plumbed in handleConn
	if err := pc.run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		s.logger.Warn("proxyConn exited with error", "service", svc.Name, "err", err)
	}
}

// run is the per-connection driver. Task 5 replaces this body with the
// startup-packet dispatch.
func (pc *proxyConn) run(ctx context.Context) error {
	// Stub: read the first message to drive the test, then exit.
	// Task 5 replaces with handshake.go dispatch.
	_, err := pc.backend.ReceiveStartupMessage()
	return err
}

// formatUID is in a separate helper so test code can use it without
// importing strconv directly. Keeps the call site at clientIdentityFromUID
// readable.
func formatUID(uid uint32) string {
	const digits = "0123456789"
	if uid == 0 {
		return "uid:0"
	}
	var buf [12]byte // "uid:" + 8 digits max for uint32
	pos := len(buf)
	v := uid
	for v > 0 {
		pos--
		buf[pos] = digits[v%10]
		v /= 10
	}
	return "uid:" + string(buf[pos:])
}
```

- [ ] **Step 4: Replace `handleConn` body in `internal/db/proxy/postgres/server.go`**

Find `handleConn` and replace its body so the success path delegates to `runProxyConn` (peercred plumbing kept):

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
	// Plan 04b: peercred passed; drive the handshake.
	pc := newProxyConn(s, svc, conn, uid)
	if err := pc.run(ctx); err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, net.ErrClosed) {
		s.logger.Warn("postgres.Server: proxyConn exited with error", "service", svc.Name, "err", err)
	}
}
```

(The earlier `runProxyConn` helper duplicates this; keep `runProxyConn` for tests but make it call the same `pc.run` so the two paths stay in sync. Or remove `runProxyConn` and have the test call `newProxyConn(...).run(ctx)` directly; choose the former so tests can keep their existing call shape.)

- [ ] **Step 5: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -v`
Expected: PASS — `TestProxyConn_StubReturnsClean` plus all 04a tests.

- [ ] **Step 6: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/proxyconn_test.go internal/db/proxy/postgres/server.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: introduce proxyConn driver shape

Plan 04b Task 4. handleConn delegates the post-peercred path to
proxyConn.run, which owns connState and a pgproto3.Backend bound to
the client conn. The body is a stub that reads the first message and
returns; Tasks 5–7 wire in the handshake / TLS / connect-rule
branches.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 8: Roborev between tasks**

---

## Task 5: `handshake.go` — startup-packet dispatch

**Why:** Spec §11.1 dispatches on the first message: `SSLRequest`, `GSSENCRequest`, `CancelRequest`, or normal `StartupMessage`. Plan 04b implements all four arms with the actions Plan 04b can support (TLS for SSLRequest, `'N'` for GSSENC, close for Cancel/replication, parse for StartupMessage).

**Files:**
- Create: `internal/db/proxy/postgres/handshake.go`
- Create: `internal/db/proxy/postgres/handshake_test.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go` (`run` calls `dispatchStartup`)

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/handshake_test.go`:

```go
//go:build linux

package postgres

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

func newTestProxyConn(t *testing.T, conn net.Conn) *proxyConn {
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
	return newProxyConn(srv, srv.cfg.Services[0], conn, 1000)
}

func writeRawStartup(t *testing.T, w io.Writer, body []byte) {
	t.Helper()
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := w.Write(hdr); err != nil {
		t.Fatalf("write startup hdr: %v", err)
	}
	if _, err := w.Write(body); err != nil {
		t.Fatalf("write startup body: %v", err)
	}
}

func TestDispatch_GSSENCRequest_RespondsN(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)

	go func() {
		// Send GSSENCRequest = magic 80877104.
		body := make([]byte, 4)
		binary.BigEndian.PutUint32(body, 80877104)
		writeRawStartup(t, b, body)
		// Server should respond 'N', then we close to terminate the loop.
		buf := make([]byte, 1)
		_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := io.ReadFull(b, buf); err != nil {
			t.Errorf("read response: %v", err)
		}
		if buf[0] != 'N' {
			t.Errorf("response = %q, want 'N'", buf[0])
		}
		b.Close()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := pc.run(ctx); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
		t.Logf("run returned: %v (acceptable)", err)
	}
}

func TestDispatch_CancelRequest_ClosesSilently(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)

	go func() {
		// CancelRequest = magic 80877102 + pid (4) + secret (4).
		body := make([]byte, 4+4+4)
		binary.BigEndian.PutUint32(body[0:4], 80877102)
		binary.BigEndian.PutUint32(body[4:8], 12345)
		binary.BigEndian.PutUint32(body[8:12], 67890)
		writeRawStartup(t, b, body)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	err := pc.run(ctx)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("run on CancelRequest returned %v; want clean exit", err)
	}
}

func TestDispatch_Replication_DefaultDeny(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)
	pc.state.tlsTerminated = true // pretend SSL already done so we go straight to startup
	// Note: this test runs without going through TLS by feeding StartupMessage
	// directly; pc.dispatchStartup must accept that path for backward-compat
	// with plaintext clients.

	go func() {
		// StartupMessage with replication=true.
		body := []byte{}
		// version 3.0
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, 196608)
		body = append(body, v...)
		body = append(body, []byte("user\x00rep\x00replication\x00true\x00\x00")...)
		writeRawStartup(t, b, body)

		// Server should send ErrorResponse + close. Read until EOF.
		buf := make([]byte, 256)
		_ = b.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _ := b.Read(buf)
		if n == 0 || buf[0] != 'E' {
			t.Errorf("first byte after replication startup = %q (n=%d), want 'E'", buf[0], n)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := pc.run(ctx); err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrClosedPipe) {
		t.Logf("run on replication=true returned: %v", err)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch -v`
Expected: FAIL — startup not dispatched (stub `run` reads then exits).

- [ ] **Step 3: Implement `internal/db/proxy/postgres/handshake.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5/pgproto3"
)

// Magic numbers from the Postgres frontend/backend protocol; same values
// pgproto3 uses internally but exposed here for readability.
const (
	sslRequestMagic    uint32 = 80877103
	gssEncRequestMagic uint32 = 80877104
	cancelRequestMagic uint32 = 80877102
	protocol30Magic    uint32 = 196608 // version 3.0
)

// dispatchStartup reads the first startup-class message and routes to the
// appropriate handler. Loop because SSLRequest is followed by a second
// startup message.
func (pc *proxyConn) dispatchStartup(ctx context.Context) error {
	for {
		msg, err := pc.backend.ReceiveStartupMessage()
		if err != nil {
			return err
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest:
			if err := pc.handleSSLRequest(ctx); err != nil {
				return err
			}
			// After SSL termination (or rejection), loop for the next
			// startup-class message.
			continue
		case *pgproto3.GSSEncRequest:
			// Default deny per spec §11.1; respond 'N' and loop for the
			// follow-up StartupMessage. Plan 04b₂ may add the opt-in path.
			if _, err := pc.conn.Write([]byte{'N'}); err != nil {
				return fmt.Errorf("write GSS 'N': %w", err)
			}
			continue
		case *pgproto3.CancelRequest:
			// Plan 04b: silently close. Plan 04b₂ evaluates a cancel rule
			// and may forward to upstream un-mapped.
			pc.logger.Debug("CancelRequest received; close silently (Plan 04b)",
				"service", pc.svc.Name, "syn_pid", m.ProcessID, "syn_secret", m.SecretKey)
			return nil
		case *pgproto3.StartupMessage:
			return pc.handleStartupMessage(ctx, m)
		default:
			return fmt.Errorf("unexpected startup-class message: %T", msg)
		}
	}
}

// handleSSLRequest is plumbed by Task 6 (tls.go). The stub here writes 'N'
// (refuse SSL) so a plaintext client falls through to StartupMessage. Task
// 6 replaces this with the terminate_* TLS handshake.
func (pc *proxyConn) handleSSLRequest(ctx context.Context) error {
	// Replaced by Task 6.
	if _, err := pc.conn.Write([]byte{'N'}); err != nil {
		return fmt.Errorf("write SSL 'N': %w", err)
	}
	return nil
}

// handleStartupMessage parses the parameters and either denies replication,
// proceeds to connection-rule eval (Task 7), or surfaces the not-yet-wired
// error.
func (pc *proxyConn) handleStartupMessage(ctx context.Context, m *pgproto3.StartupMessage) error {
	pc.state.dbUser = m.Parameters["user"]
	pc.state.database = m.Parameters["database"]
	pc.state.appName = m.Parameters["application_name"]
	if v, ok := m.Parameters["replication"]; ok && v != "" && v != "false" && v != "off" && v != "0" {
		pc.state.replication = true
	}
	if pc.state.replication {
		// Plan 04b: default deny. Plan 04b₂ adds the opt-in passthrough.
		return pc.synthesizeError(replicationDenyErrorCode, replicationDenyMessage)
	}
	// Task 7 plugs in: connect-rule eval, then synthesize "upstream not yet
	// wired" on allow. For now, the not-yet-wired error gives Task 5's tests
	// a deterministic post-startup behavior.
	return pc.synthesizeError(upstreamNotYetWiredErrorCode, upstreamNotYetWiredMessage)
}

// synthesizeError writes one ErrorResponse with the given SQLSTATE+message
// and a final close. Used by deny paths and the not-yet-wired stub.
func (pc *proxyConn) synthesizeError(sqlstate, message string) error {
	resp := &pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     sqlstate,
		Message:  message,
	}
	pc.backend.Send(resp)
	if err := pc.backend.Flush(); err != nil {
		return fmt.Errorf("flush ErrorResponse: %w", err)
	}
	// Drain client side cleanly; ignore errors, the conn is about to close.
	_ = pc.conn.SetReadDeadline(timeNow().Add(50 * 1e6)) // 50ms grace
	_, _ = io.Copy(io.Discard, pc.conn)
	return nil
}

// Error codes Plan 04b synthesizes. Documented here so Plan 04b₂ can
// reuse where relevant.
const (
	replicationDenyErrorCode     = "28000"
	replicationDenyMessage       = "AgentSH DB proxy: replication mode denied by default; declare an opt-in connection rule (Plan 04b₂)"
	upstreamNotYetWiredErrorCode = "0A000"
	upstreamNotYetWiredMessage   = "AgentSH DB proxy: upstream wiring not yet shipped (Plan 04b is inbound-only; Plan 04b₂ adds upstream)"
	connectionDenyErrorCode      = "28000"
)

Update `proxyconn.go`'s `run` method:

```go
func (pc *proxyConn) run(ctx context.Context) error {
	return pc.dispatchStartup(ctx)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run TestDispatch -v`
Expected: PASS for all three.

- [ ] **Step 5: Run the full proxy package tests**

Run: `go test ./internal/db/proxy/postgres/... -v`
Expected: PASS.

- [ ] **Step 6: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 7: Commit**

```bash
git add internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/handshake_test.go internal/db/proxy/postgres/proxyconn.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: startup-packet dispatch

Plan 04b Task 5. proxyConn.dispatchStartup loops over startup-class
messages: SSLRequest defers to handleSSLRequest (Task 6), GSSENCRequest
gets 'N', CancelRequest closes silently (deferred to Plan 04b₂),
StartupMessage parses parameters. Replication=true is denied by default;
the otherwise-allowed path returns an ErrorResponse(0A000,
"upstream not yet wired") so 04b ships a deterministic external
behavior even without upstream.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 8: Roborev between tasks**

---

## Task 6: `tls.go` — terminate_reissue + terminate_plaintext_upstream + `sni.go`

**Why:** `handleSSLRequest` currently refuses SSL with `'N'`. Task 6 replaces it with the real terminate handshake: respond `'S'`, then `tls.Server` with a leaf issued for the upstream hostname. After termination, swap `pc.conn` and `pc.backend` to operate on the encrypted stream so the next dispatch loop reads the post-TLS StartupMessage. SNI extraction lives in a dedicated file because Plan 04b₂ reuses it under passthrough.

**Files:**
- Create: `internal/db/proxy/postgres/tls.go`
- Create: `internal/db/proxy/postgres/tls_test.go`
- Create: `internal/db/proxy/postgres/sni.go`
- Create: `internal/db/proxy/postgres/sni_test.go`
- Modify: `internal/db/proxy/postgres/handshake.go` (`handleSSLRequest` body)

- [ ] **Step 1: Write the failing test**

Create `internal/db/proxy/postgres/tls_test.go`:

```go
//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"crypto/x509"
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

func TestTLS_TerminateReissue_RoundTrip(t *testing.T) {
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
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	// Drive the proxy in a goroutine.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	srvDone := make(chan error, 1)
	go func() { srvDone <- pc.run(ctx) }()

	// Client side: send SSLRequest, expect 'S', then run TLS handshake
	// with the server's CA in the trust pool.
	sslReq := make([]byte, 8)
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	if _, err := b.Write(sslReq); err != nil {
		t.Fatalf("write SSLRequest: %v", err)
	}
	resp := make([]byte, 1)
	if _, err := io.ReadFull(b, resp); err != nil {
		t.Fatalf("read SSL resp: %v", err)
	}
	if resp[0] != 'S' {
		t.Fatalf("SSL resp = %q, want 'S'", resp[0])
	}

	// Build a trust pool from the proxy's CA.
	ca, err := srv.ca()
	if err != nil {
		t.Fatalf("srv.ca(): %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())

	tlsConn := tls.Client(b, &tls.Config{
		RootCAs:    pool,
		ServerName: "db.internal",
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		t.Fatalf("client TLS handshake: %v", err)
	}

	// Send a normal StartupMessage post-TLS so dispatchStartup advances
	// past handshake and synthesizes the upstream-not-wired error.
	body := []byte{}
	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 196608)
	body = append(body, v...)
	body = append(body, []byte("user\x00alice\x00database\x00app\x00\x00")...)
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(body)+4))
	if _, err := tlsConn.Write(append(hdr, body...)); err != nil {
		t.Fatalf("write StartupMessage: %v", err)
	}
	// Read the ErrorResponse the proxy synthesizes.
	first := make([]byte, 1)
	if _, err := io.ReadFull(tlsConn, first); err != nil {
		t.Fatalf("read post-startup: %v", err)
	}
	if first[0] != 'E' {
		t.Errorf("first post-startup byte = %q, want 'E'", first[0])
	}

	cancel()
	select {
	case err := <-srvDone:
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			t.Logf("server returned: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not exit after cancel")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/db/proxy/postgres/ -run TestTLS_TerminateReissue -v`
Expected: FAIL — handshake fails because `handleSSLRequest` writes 'N'.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/tls.go`**

```go
//go:build linux

package postgres

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/jackc/pgx/v5/pgproto3"
)

// handleSSLRequest negotiates inbound TLS per the service's tls_mode.
// Plan 04b supports terminate_reissue and terminate_plaintext_upstream
// (passthrough is rejected at Server.New). Both terminate-mode paths
// reissue a leaf for the upstream hostname (extracted from svc.Upstream).
func (pc *proxyConn) handleSSLRequest(ctx context.Context) error {
	switch pc.svc.TLSMode {
	case "terminate_reissue", "terminate_plaintext_upstream":
		return pc.terminateInbound(ctx)
	default:
		// Should not happen: passthrough is rejected at Server.New.
		// Defensive: refuse SSL so the client falls back or errors out.
		_, err := pc.conn.Write([]byte{'N'})
		return err
	}
}

// terminateInbound responds 'S' to SSLRequest and runs tls.Server using
// a leaf issued for the upstream hostname. After the handshake the proxy
// swaps pc.conn and pc.backend to the encrypted stream so dispatchStartup
// reads the post-TLS StartupMessage transparently.
func (pc *proxyConn) terminateInbound(ctx context.Context) error {
	if _, err := pc.conn.Write([]byte{'S'}); err != nil {
		return fmt.Errorf("write SSL 'S': %w", err)
	}
	host, err := upstreamHost(pc.svc.Upstream)
	if err != nil {
		return fmt.Errorf("parse upstream %q: %w", pc.svc.Upstream, err)
	}
	ca, err := pc.srv.ca()
	if err != nil {
		return fmt.Errorf("load CA: %w", err)
	}
	leaf, err := ca.IssueLeaf(host)
	if err != nil {
		return fmt.Errorf("issue leaf for %q: %w", host, err)
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
		// Capture the SNI value the client offered for audit (§13.2 advisory).
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			pc.state.sniHostname = chi.ServerName
			return leaf, nil
		},
	}
	tlsConn := tls.Server(pc.conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("inbound TLS handshake: %w", err)
	}
	pc.conn = tlsConn
	pc.backend = pgproto3.NewBackend(tlsConn, tlsConn)
	pc.state.tlsTerminated = true
	return nil
}

// upstreamHost extracts the host portion from a "host:port" Upstream string.
// Falls back to the input on parse failure (callers will still produce a
// usable leaf with the unparsed value as SAN).
func upstreamHost(upstream string) (string, error) {
	host, _, err := net.SplitHostPort(upstream)
	if err != nil {
		return upstream, fmt.Errorf("net.SplitHostPort: %w", err)
	}
	if host == "" {
		return "", fmt.Errorf("empty host in upstream %q", upstream)
	}
	return host, nil
}
```

- [ ] **Step 4: Implement `internal/db/proxy/postgres/sni.go`**

```go
//go:build linux

package postgres

import (
	"encoding/binary"
	"errors"
)

// extractSNI parses a TLS ClientHello buffer and returns the SNI hostname
// (server_name extension, host_name field) when present. Best-effort:
// returns "" and nil error for malformed/fragmented inputs. Plan 04b₂
// uses this under tls_mode: passthrough where the proxy peeks a few KiB
// before forwarding the encrypted stream.
//
// Reference: RFC 5246 §7.4.1.2 + RFC 6066 §3 (server_name).
func extractSNI(buf []byte) (string, error) {
	// TLS record header (5 bytes): type(1) + version(2) + length(2)
	if len(buf) < 5 {
		return "", nil
	}
	if buf[0] != 22 { // 22 = handshake
		return "", nil
	}
	recLen := int(binary.BigEndian.Uint16(buf[3:5]))
	if recLen+5 > len(buf) {
		// Fragmented across records; advisory — not parsing follow-ups.
		return "", nil
	}
	hs := buf[5 : 5+recLen]
	// Handshake header (4 bytes): msg_type(1) + length(3)
	if len(hs) < 4 || hs[0] != 1 { // 1 = ClientHello
		return "", nil
	}
	chBody := hs[4:]
	// ClientHello: client_version(2) + random(32) + session_id(...) + cipher_suites(...) + compression(...) + extensions
	if len(chBody) < 2+32+1 {
		return "", nil
	}
	off := 2 + 32
	sidLen := int(chBody[off])
	off += 1 + sidLen
	if off+2 > len(chBody) {
		return "", nil
	}
	csLen := int(binary.BigEndian.Uint16(chBody[off : off+2]))
	off += 2 + csLen
	if off+1 > len(chBody) {
		return "", nil
	}
	compLen := int(chBody[off])
	off += 1 + compLen
	if off+2 > len(chBody) {
		return "", nil
	}
	extTotal := int(binary.BigEndian.Uint16(chBody[off : off+2]))
	off += 2
	if off+extTotal > len(chBody) {
		return "", nil
	}
	exts := chBody[off : off+extTotal]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[0:2])
		ln := int(binary.BigEndian.Uint16(exts[2:4]))
		if 4+ln > len(exts) {
			return "", nil
		}
		body := exts[4 : 4+ln]
		exts = exts[4+ln:]
		if typ != 0 { // 0 = server_name
			continue
		}
		// server_name list: list_length(2) + entries
		if len(body) < 2 {
			return "", nil
		}
		listLen := int(binary.BigEndian.Uint16(body[0:2]))
		if 2+listLen > len(body) {
			return "", nil
		}
		entries := body[2 : 2+listLen]
		for len(entries) >= 3 {
			nameType := entries[0]
			nameLen := int(binary.BigEndian.Uint16(entries[1:3]))
			if 3+nameLen > len(entries) {
				return "", nil
			}
			name := entries[3 : 3+nameLen]
			entries = entries[3+nameLen:]
			if nameType == 0 { // 0 = host_name
				return string(name), nil
			}
		}
	}
	return "", nil
}

var errMalformedClientHello = errors.New("malformed ClientHello") // kept for future stricter mode
```

- [ ] **Step 5: Write the SNI tests**

Create `internal/db/proxy/postgres/sni_test.go`:

```go
//go:build linux

package postgres

import (
	"crypto/tls"
	"net"
	"testing"
	"time"
)

// recordClientHello captures the first record of a tls handshake by acting
// as a one-shot peeking Server. Useful for round-tripping through extractSNI.
func recordClientHello(t *testing.T, sni string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	captured := make(chan []byte, 1)
	go func() {
		// Server side: read into a buffer until we have at least one record.
		_ = a.SetReadDeadline(time.Now().Add(1 * time.Second))
		buf := make([]byte, 4096)
		n, _ := a.Read(buf)
		captured <- buf[:n]
		// Tear down the TLS handshake; we only wanted the ClientHello bytes.
		a.Close()
	}()

	cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
	tlsConn := tls.Client(b, cfg)
	_ = tlsConn.SetWriteDeadline(time.Now().Add(1 * time.Second))
	_ = tlsConn.Handshake() // expected to fail because we close the server side
	return <-captured
}

func TestExtractSNI_Present(t *testing.T) {
	bytes := recordClientHello(t, "db.example.com")
	got, err := extractSNI(bytes)
	if err != nil {
		t.Fatalf("extractSNI: %v", err)
	}
	if got != "db.example.com" {
		t.Errorf("extractSNI = %q, want db.example.com", got)
	}
}

func TestExtractSNI_AbsentReturnsEmpty(t *testing.T) {
	// No SNI when ServerName is set to an IP literal-ish string — we
	// emulate by passing crypto/tls a hostname that gets sent (still SNI),
	// so test the parser directly with a hand-rolled too-short buffer.
	got, err := extractSNI([]byte{0x16, 0x03, 0x01, 0x00, 0x01, 0xff})
	if err != nil {
		t.Fatalf("extractSNI: %v", err)
	}
	if got != "" {
		t.Errorf("extractSNI on tiny buf = %q, want empty", got)
	}
}

func TestExtractSNI_NonHandshakeReturnsEmpty(t *testing.T) {
	got, _ := extractSNI([]byte{0x17, 0x03, 0x03, 0x00, 0x00})
	if got != "" {
		t.Errorf("extractSNI on app-data record = %q, want empty", got)
	}
}
```

- [ ] **Step 6: Run TLS + SNI tests to verify they pass**

Run: `go test ./internal/db/proxy/postgres/ -run "TestTLS_|TestExtractSNI" -v`
Expected: PASS for all.

- [ ] **Step 7: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 8: Commit**

```bash
git add internal/db/proxy/postgres/tls.go internal/db/proxy/postgres/tls_test.go internal/db/proxy/postgres/sni.go internal/db/proxy/postgres/sni_test.go internal/db/proxy/postgres/handshake.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: terminate_* TLS modes + best-effort SNI extractor

Plan 04b Task 6. handleSSLRequest now responds 'S' and runs tls.Server
with a leaf issued by tlsleaf for the upstream hostname. After the
handshake completes, the proxy swaps pc.conn/pc.backend to the encrypted
stream so dispatchStartup transparently reads the post-TLS
StartupMessage. Inbound SNI is captured into connState.sniHostname for
audit (advisory per spec §13.2). sni.go ships a hand-rolled
ClientHello extractor used here for terminate_* coverage and reusable
under passthrough in Plan 04b₂.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Roborev between tasks**

---

## Task 7: Connect-kind connection-rule eval + §13.3 deny synthesis

**Why:** After StartupMessage parses, the proxy must populate `policy.ConnectionInfo` and call `EvaluateConnection`. Allow → synthesize the not-yet-wired error (Plan 04b's external boundary). Deny → §13.3 deny: terminate-mode services synthesize `ErrorResponse(28000)`; passthrough services would close TCP only, but those are rejected at Server.New so 04b only sees terminate-mode denies.

**Files:**
- Create: `internal/db/proxy/postgres/connect_rule.go`
- Create: `internal/db/proxy/postgres/connect_rule_test.go`
- Modify: `internal/db/proxy/postgres/handshake.go` (`handleStartupMessage` calls into `connect_rule.go`)

- [ ] **Step 1: Write the failing tests**

Create `internal/db/proxy/postgres/connect_rule_test.go`:

```go
//go:build linux

package postgres

import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// loadRuleSet decodes a YAML policy via the same path supervisor uses.
// Mirrors the helper in internal/db/policy/decode_test.go.
func loadRuleSet(t *testing.T, src string) *policy.RuleSet {
	t.Helper()
	rp, err := rootpolicy.LoadFromBytes([]byte(src))
	if err != nil {
		t.Fatalf("rootpolicy.LoadFromBytes: %v", err)
	}
	rs, _, err := policy.Decode(rp)
	if err != nil {
		t.Fatalf("policy.Decode: %v", err)
	}
	return rs
}

func TestEvaluateConnect_AllowReturnsAllowDecision(t *testing.T) {
	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: allow-alice
    db_service: appdb
    db_user: ["alice"]
    decision: allow
`)
	d := policy.EvaluateConnection(policy.ConnectionInfo{
		Service:        "appdb",
		MatchKind:      policy.MatchConnect,
		DBUser:         "alice",
		ClientIdentity: "uid:1000",
	}, rs)
	if d.Verb != policy.VerbAllow {
		t.Fatalf("Verb = %v, want allow", d.Verb)
	}
}

func TestEvaluateConnect_DenyReturnsDenyDecision(t *testing.T) {
	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb:
    family: postgres
    dialect: postgres
    upstream: db.internal:5432
    tls_mode: terminate_reissue
database_connection_rules:
  - name: deny-bob
    db_service: appdb
    db_user: ["bob"]
    decision: deny
`)
	d := policy.EvaluateConnection(policy.ConnectionInfo{
		Service:        "appdb",
		MatchKind:      policy.MatchConnect,
		DBUser:         "bob",
		ClientIdentity: "uid:1000",
	}, rs)
	if d.Verb != policy.VerbDeny {
		t.Fatalf("Verb = %v, want deny", d.Verb)
	}
}
```

Add the imports:

```go
import (
	"testing"

	"github.com/agentsh/agentsh/internal/db/policy"
	rootpolicy "github.com/agentsh/agentsh/internal/policy"
)
```

- [ ] **Step 2: Run test to verify it fails / compiles**

Run: `go test ./internal/db/proxy/postgres/ -run TestEvaluateConnect -v`
Expected: PASS — these are sanity tests against the existing Plan 02 evaluator. If they fail, the helper signature is wrong; correct it before proceeding.

- [ ] **Step 3: Implement `internal/db/proxy/postgres/connect_rule.go`**

```go
//go:build linux

package postgres

import (
	"context"

	"github.com/agentsh/agentsh/internal/db/policy"
)

// evaluateConnect runs Plan 02's connection-rule evaluator with match_kind=
// connect against the parsed StartupMessage state. Returns the Decision so
// callers can choose between allow-path (synthesize not-yet-wired) and
// deny-path (§13.3 deny synthesis).
func (pc *proxyConn) evaluateConnect(_ context.Context) policy.Decision {
	return policy.EvaluateConnection(policy.ConnectionInfo{
		Service:         policy.ServiceID(pc.svc.Name),
		MatchKind:       policy.MatchConnect,
		DBUser:          pc.state.dbUser,
		Database:        pc.state.database,
		ApplicationName: pc.state.appName,
		ClientIdentity:  pc.state.clientIdentity,
	}, pc.srv.cfg.Policy)
}
```

The above references `pc.srv.cfg.Policy`. Add it to `Config`:

```go
type Config struct {
	Unavoidability service.Unavoidability
	Services       []Service
	StateDir       string
	Sink           events.Sink
	Logger         *slog.Logger
	Policy         *policy.RuleSet // current rule set; nil means "no rules" (implicit deny)
}
```

(Update the Plan 04a `Config` doc comment accordingly. Also add `Policy: ...` plumbing in `internal/api/db_proxy.go`'s `buildDBProxyConfig`; Plan 04a omitted it because no eval was wired.)

- [ ] **Step 4: Update `handleStartupMessage` to use `evaluateConnect`**

Edit `internal/db/proxy/postgres/handshake.go`:

```go
func (pc *proxyConn) handleStartupMessage(ctx context.Context, m *pgproto3.StartupMessage) error {
	pc.state.dbUser = m.Parameters["user"]
	pc.state.database = m.Parameters["database"]
	pc.state.appName = m.Parameters["application_name"]
	if v, ok := m.Parameters["replication"]; ok && v != "" && v != "false" && v != "off" && v != "0" {
		pc.state.replication = true
	}
	if pc.state.replication {
		return pc.synthesizeError(replicationDenyErrorCode, replicationDenyMessage)
	}

	d := pc.evaluateConnect(ctx)
	if d.Verb == policy.VerbDeny {
		// §13.3 deny under terminate_* modes: synthesize ErrorResponse(28000).
		// Passthrough is rejected at Server.New so we always have a TLS-terminated
		// connection here.
		msg := d.Reason
		if msg == "" {
			msg = "AgentSH DB proxy: connection denied by policy"
		}
		return pc.synthesizeError(connectionDenyErrorCode, msg)
	}
	// Allow / audit / approve: Plan 04b ends here; Plan 04b₂ dials upstream.
	return pc.synthesizeError(upstreamNotYetWiredErrorCode, upstreamNotYetWiredMessage)
}
```

Add the import: `"github.com/agentsh/agentsh/internal/db/policy"`.

- [ ] **Step 5: Plumb the policy snapshot into `Config` from the supervisor**

Modify `internal/api/db_proxy.go`. First add the field to `dbProxyDeps`:

```go
type dbProxyDeps struct {
	Unavoidability dbservice.Unavoidability
	Services       []dbProxyService
	StateDir       string
	Sink           events.Sink
	Policy         *dbpolicy.RuleSet // NEW: live rule set for connect-rule eval
}
```

Update `buildDBProxyConfig` to forward it:

```go
func buildDBProxyConfig(deps dbProxyDeps) (postgres.Config, error) {
	cfg := postgres.Config{
		Unavoidability: deps.Unavoidability,
		StateDir:       deps.StateDir,
		Sink:           deps.Sink,
		Policy:         deps.Policy, // NEW
	}
	for _, s := range deps.Services {
		// ... unchanged loop body ...
	}
	return cfg, nil
}
```

Update `NewDBProxy` to populate `deps.Policy`:

```go
func NewDBProxy(p *rootpolicy.Policy, stateDir string, sink events.Sink) (*postgres.Server, error) {
	rs, err := loadDBRuleSet(p)
	if err != nil {
		return nil, err
	}
	deps := dbProxyDeps{
		Unavoidability: rs.Unavoidability(),
		StateDir:       stateDir,
		Sink:           sink,
		Services:       collectDBProxyServices(rs, stateDir),
		Policy:         rs, // NEW
	}
	cfg, err := buildDBProxyConfig(deps)
	if err != nil {
		return nil, fmt.Errorf("NewDBProxy: %w", err)
	}
	return postgres.New(cfg)
}
```

- [ ] **Step 6: Run all proxy + api tests**

Run: `go test ./internal/db/proxy/postgres/... ./internal/api/... -v`
Expected: PASS.

- [ ] **Step 7: Cross-compile**

Run: `GOOS=windows go build ./...`
Expected: build success.

- [ ] **Step 8: Commit**

```bash
git add internal/db/proxy/postgres/connect_rule.go internal/db/proxy/postgres/connect_rule_test.go internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/server.go internal/api/db_proxy.go
git commit -m "$(cat <<'EOF'
db/proxy/postgres: connect-kind eval + §13.3 deny synthesis

Plan 04b Task 7. After StartupMessage parses, the proxy populates
policy.ConnectionInfo and calls EvaluateConnection (Plan 02). Deny
synthesizes ErrorResponse(28000); allow falls through to the
not-yet-wired (0A000) error that Plan 04b₂ will replace with
upstream dial. Config.Policy is plumbed through from
internal/api/db_proxy.go's NewDBProxy so the supervisor's loaded
RuleSet is the live source of truth.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

- [ ] **Step 9: Roborev between tasks**

---

## Task 8: Final verification

**Why:** Belt-and-suspenders pass before declaring 04b done.

**Files:** None (verification only).

- [ ] **Step 1: Run the full repo test suite**

Run: `go test ./...`
Expected: all pass on Linux. Pre-existing flakes documented in `MEMORY.md` are not regressions; rerun once if they trip.

- [ ] **Step 2: Cross-compile for Windows + macOS**

Run: `GOOS=windows go build ./...`
Expected: build success.

Run: `GOOS=darwin go build ./...`
Expected: build success.

- [ ] **Step 3: Manual psql smoke test (informational)**

Build a tiny driver under `cmd/dbproxy-smoke/main.go` (do NOT commit) that constructs a `postgres.Server` with one Unix-socket service in `terminate_reissue` mode and an empty allow-everything policy. Run it. From a second terminal:

```bash
PGSSLROOTCERT=$STATE_DIR/db-ca.crt \
  psql "host=$SOCKET_DIR sslmode=verify-full user=anyone dbname=anything"
```

Expected: TLS handshake succeeds; psql receives FATAL 0A000 "AgentSH DB proxy: upstream wiring not yet shipped (Plan 04b is inbound-only; Plan 04b₂ adds upstream)" and disconnects cleanly.

- [ ] **Step 4: Roborev final pass**

Run `roborev-review-branch` against the merged 04b branch. Address findings above `low` severity before opening the PR.

- [ ] **Step 5: Update plan checkboxes**

Confirm every checkbox above this section is checked. Open follow-up tasks for any defect found during verification.

- [ ] **Step 6: Final commit (only if any verification fixes were needed)**

```bash
git status
# If clean, nothing to commit. Otherwise:
git add <files>
git commit -m "db: Plan 04b verification fixes

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
"
```

---

## Out-of-scope reminders (do NOT do in Plan 04b)

- Upstream TCP dial; upstream TLS; auth-byte forwarding; SCRAM-SHA-256-PLUS detection — Plan 04b₂.
- `passthrough` TLS mode end-to-end — Plan 04b₂ (and config-load rejection of `passthrough` services in `Server.New` is removed when 04b₂ lands).
- Post-handshake byte-passthrough loop — Plan 04b₂.
- `replication=true` opt-in passthrough path — Plan 04b₂.
- `CancelRequest` connect-rule eval + un-mapped forward — Plan 04b₂.
- `degraded_visibility_warning` event emission — Plan 04b₂.
- pgx-based real-Postgres spine round-trip — Plan 04c (and Plan 07's testcontainers integration suite).
- Simple Query / Extended Query classification + DBEvent emission — Plan 04c.

The `LifecycleEvent.Kind` values reserved earlier (`db_handshake_fail`, `degraded_visibility_warning`) are documented but only `db_listener_auth_fail` (04a) is emitted today; `db_handshake_fail` lands in Plan 04b₂ (SCRAM-PLUS path).
