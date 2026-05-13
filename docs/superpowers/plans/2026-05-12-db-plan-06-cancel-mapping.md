# db-access Plan 06 - CancelRequest Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace un-mapped PostgreSQL CancelRequest forwarding with proxy-wide `BackendKeyData` translation, synthetic cancel-key lookup, cancel-rule governance, and cancel audit events.

**Architecture:** Keep the feature inside `internal/db/proxy/postgres/` as a focused Postgres-only `cancelMap` owned by `Server`. `forwardAuth` registers real upstream `BackendKeyData` and sends only synthetic keys to clients; startup CancelRequests look up synthetic keys before evaluating `match_kind: cancel` and forwarding real upstream cancel packets.

**Tech Stack:** Go, `pgproto3`, existing `events.SyncSink`, existing `policy.EvaluateConnection`, Linux-only proxy package with non-Linux build preserved by existing stubs.

---

## File Structure

**Created:**

- `internal/db/proxy/postgres/cancelmap.go` - proxy-wide synthetic-to-real cancel mapping table, lifecycle, cap handling, synthetic-key generation.
- `internal/db/proxy/postgres/cancelmap_test.go` - unit tests for registration, lookup, collision, expiry, cap, and release behavior.

**Modified:**

- `internal/db/proxy/postgres/server.go` - add `Config.CancelMappingMax`, `Config.CancelGraceWindow`, defaults, and `Server.cancelMap`.
- `internal/db/proxy/postgres/proxyconn.go` - store cancel registration release hook and release it during connection cleanup.
- `internal/db/proxy/postgres/authforward.go` - replace verbatim `BackendKeyData` forwarding with register-and-synthesize behavior.
- `internal/db/proxy/postgres/authforward_test.go` - assert client sees synthetic BKD, map is committed, registration failures fail startup.
- `internal/db/proxy/postgres/handshake.go` - replace un-mapped cancel handling with lookup-first cancel flow.
- `internal/db/proxy/postgres/cancel.go` - build real upstream CancelRequest packets from mapped real keys; keep low-level dial/write helper.
- `internal/db/proxy/postgres/cancel_test.go` - update low-level packet tests and add mapped cancel helpers.
- `internal/db/proxy/postgres/handshake_test.go` - update startup CancelRequest tests for no-match, deny, allow, audit, expired.
- `internal/db/proxy/postgres/eventbuilder.go` - add a small cancel-event builder near existing statement event builder.
- `internal/db/events/lifecycle.go` - document new lifecycle kinds.
- `internal/db/events/event.go` - clarify that cancel DBEvents have no statement text or digest.
- `internal/db/proxy/postgres/spine_test.go` - add fake-upstream spine test proving synthetic client key maps to real upstream cancel key.

---

### Task 1: Add `cancelMap` Core

**Files:**
- Create: `internal/db/proxy/postgres/cancelmap.go`
- Create: `internal/db/proxy/postgres/cancelmap_test.go`

- [ ] **Step 1: Write failing tests for register, lookup, release, expiry, and cap**

Create `internal/db/proxy/postgres/cancelmap_test.go`:

```go
//go:build linux

package postgres

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

func TestCancelMap_RegisterLookupAndRelease(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	cm := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: 5 * time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1001, secret: []byte{0, 0, 0, 7}},
		}),
	})

	reg, err := cm.Register(cancelMeta{
		ServiceName:     "appdb",
		UpstreamAddr:    "127.0.0.1:15432",
		ClientIdentity:  "uid:1000",
		DBUser:          "alice",
		Database:        "app",
		ApplicationName: "psql",
		PeerUID:         1000,
	}, 42, []byte{0, 0, 0, 99})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if reg.SyntheticPID != 1001 || !bytes.Equal(reg.SyntheticSecret, []byte{0, 0, 0, 7}) {
		t.Fatalf("synthetic key = (%d,%x), want (1001,00000007)", reg.SyntheticPID, reg.SyntheticSecret)
	}

	entry, status := cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupFound {
		t.Fatalf("Lookup status = %v, want found", status)
	}
	if entry.RealPID != 42 || !bytes.Equal(entry.RealSecret, []byte{0, 0, 0, 99}) {
		t.Fatalf("real key = (%d,%x), want (42,00000063)", entry.RealPID, entry.RealSecret)
	}
	if entry.ServiceName != "appdb" || entry.DBUser != "alice" || entry.ClientIdentity != "uid:1000" {
		t.Fatalf("metadata not preserved: %+v", entry)
	}

	reg.Release()
	reg.Release()
	entry, status = cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupFound {
		t.Fatalf("Lookup after release status = %v, want found within grace", status)
	}
	if entry.DisconnectedAt.IsZero() {
		t.Fatal("DisconnectedAt was not set by Release")
	}

	now = now.Add(6 * time.Minute)
	_, status = cm.Lookup(1001, []byte{0, 0, 0, 7})
	if status != cancelLookupExpired {
		t.Fatalf("Lookup after grace status = %v, want expired", status)
	}
}

func TestCancelMap_CollisionRetryAndExhaustion(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	cm := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1, secret: []byte{1}},
			{pid: 1, secret: []byte{1}},
			{pid: 2, secret: []byte{2}},
		}),
	})
	if _, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 10, []byte{10}); err != nil {
		t.Fatalf("first Register: %v", err)
	}
	reg, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 20, []byte{20})
	if err != nil {
		t.Fatalf("second Register: %v", err)
	}
	if reg.SyntheticPID != 2 || !bytes.Equal(reg.SyntheticSecret, []byte{2}) {
		t.Fatalf("second synthetic key = (%d,%x), want (2,02)", reg.SyntheticPID, reg.SyntheticSecret)
	}

	exhaust := newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
			{pid: 9, secret: []byte{9}},
		}),
	})
	if _, err := exhaust.Register(cancelMeta{ServiceName: "appdb"}, 1, []byte{1}); err != nil {
		t.Fatalf("seed Register: %v", err)
	}
	if _, err := exhaust.Register(cancelMeta{ServiceName: "appdb"}, 2, []byte{2}); !errors.Is(err, errBackendKeyGenerationFailed) {
		t.Fatalf("collision exhaustion err = %v, want errBackendKeyGenerationFailed", err)
	}
}

func TestCancelMap_CapPrunesOnlyPastGrace(t *testing.T) {
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	cm := newCancelMap(cancelMapConfig{
		Max:         2,
		GraceWindow: 5 * time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1, secret: []byte{1}},
			{pid: 2, secret: []byte{2}},
			{pid: 3, secret: []byte{3}},
			{pid: 4, secret: []byte{4}},
		}),
	})
	reg1, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 11, []byte{11})
	if err != nil {
		t.Fatalf("reg1: %v", err)
	}
	if _, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 22, []byte{22}); err != nil {
		t.Fatalf("reg2: %v", err)
	}

	reg1.Release()
	if _, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 33, []byte{33}); !errors.Is(err, errBackendKeyTableFull) {
		t.Fatalf("within-grace cap err = %v, want errBackendKeyTableFull", err)
	}

	now = now.Add(6 * time.Minute)
	reg3, err := cm.Register(cancelMeta{ServiceName: "appdb"}, 33, []byte{33})
	if err != nil {
		t.Fatalf("after-grace Register: %v", err)
	}
	if reg3.SyntheticPID != 3 {
		t.Fatalf("synthetic pid = %d, want 3", reg3.SyntheticPID)
	}
	if _, status := cm.Lookup(reg1.SyntheticPID, reg1.SyntheticSecret); status != cancelLookupMiss {
		t.Fatalf("expired pruned lookup status = %v, want miss", status)
	}
}

type generatedCancelKey struct {
	pid    uint32
	secret []byte
}

func fixedCancelKeyGenerator(keys []generatedCancelKey) func() (uint32, []byte, error) {
	i := 0
	return func() (uint32, []byte, error) {
		if i >= len(keys) {
			return 0, nil, errors.New("test key generator exhausted")
		}
		k := keys[i]
		i++
		return k.pid, append([]byte(nil), k.secret...), nil
	}
}
```

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestCancelMap_' -count=1
```

Expected: build fails with undefined symbols such as `newCancelMap`, `cancelMapConfig`, and `errBackendKeyTableFull`.

- [ ] **Step 3: Implement `cancelMap`**

Create `internal/db/proxy/postgres/cancelmap.go`:

```go
//go:build linux

package postgres

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"sync"
	"time"
)

const (
	defaultCancelMappingMax   = 100000
	defaultCancelGraceWindow  = 5 * time.Minute
	cancelKeyGenerationRetries = 8
)

var (
	errBackendKeyGenerationFailed = errors.New("BACKEND_KEY_GENERATION_FAILED")
	errBackendKeyTableFull        = errors.New("BACKEND_KEY_TABLE_FULL")
)

type cancelLookupStatus uint8

const (
	cancelLookupMiss cancelLookupStatus = iota
	cancelLookupExpired
	cancelLookupFound
)

type cancelMapConfig struct {
	Max         int
	GraceWindow time.Duration
	Now         func() time.Time
	Generate    func() (uint32, []byte, error)
}

type cancelMeta struct {
	ServiceName     string
	UpstreamAddr    string
	ClientIdentity  string
	DBUser          string
	Database        string
	ApplicationName string
	PeerUID         uint32
}

type cancelEntry struct {
	cancelMeta
	RealPID         uint32
	RealSecret      []byte
	SyntheticPID    uint32
	SyntheticSecret []byte
	CreatedAt       time.Time
	DisconnectedAt  time.Time
}

type cancelRegistration struct {
	SyntheticPID    uint32
	SyntheticSecret []byte
	release         func()
	once            sync.Once
}

func (r *cancelRegistration) Release() {
	if r == nil || r.release == nil {
		return
	}
	r.once.Do(r.release)
}

type cancelKey struct {
	pid    uint32
	secret string
}

func newCancelKey(pid uint32, secret []byte) cancelKey {
	return cancelKey{pid: pid, secret: string(append([]byte(nil), secret...))}
}

type cancelMap struct {
	mu          sync.Mutex
	entries     map[cancelKey]*cancelEntry
	max         int
	graceWindow time.Duration
	now         func() time.Time
	generate    func() (uint32, []byte, error)
}

func newCancelMap(cfg cancelMapConfig) *cancelMap {
	if cfg.Max <= 0 {
		cfg.Max = defaultCancelMappingMax
	}
	if cfg.GraceWindow <= 0 {
		cfg.GraceWindow = defaultCancelGraceWindow
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Generate == nil {
		cfg.Generate = generateCancelKey
	}
	return &cancelMap{
		entries:     make(map[cancelKey]*cancelEntry),
		max:         cfg.Max,
		graceWindow: cfg.GraceWindow,
		now:         cfg.Now,
		generate:    cfg.Generate,
	}
}

func (m *cancelMap) Register(meta cancelMeta, realPID uint32, realSecret []byte) (cancelRegistration, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.now()
	if len(m.entries) >= m.max {
		m.pruneExpiredLocked(now)
	}
	if len(m.entries) >= m.max {
		return cancelRegistration{}, errBackendKeyTableFull
	}

	var pid uint32
	var secret []byte
	var key cancelKey
	for i := 0; i < cancelKeyGenerationRetries; i++ {
		var err error
		pid, secret, err = m.generate()
		if err != nil {
			return cancelRegistration{}, err
		}
		key = newCancelKey(pid, secret)
		if _, exists := m.entries[key]; !exists {
			entry := &cancelEntry{
				cancelMeta:      meta,
				RealPID:         realPID,
				RealSecret:      append([]byte(nil), realSecret...),
				SyntheticPID:    pid,
				SyntheticSecret: append([]byte(nil), secret...),
				CreatedAt:       now,
			}
			m.entries[key] = entry
			reg := cancelRegistration{
				SyntheticPID:    pid,
				SyntheticSecret: append([]byte(nil), secret...),
			}
			reg.release = func() { m.MarkDisconnected(key) }
			return reg, nil
		}
	}
	return cancelRegistration{}, errBackendKeyGenerationFailed
}

func (m *cancelMap) Lookup(pid uint32, secret []byte) (cancelEntry, cancelLookupStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key := newCancelKey(pid, secret)
	entry, ok := m.entries[key]
	if !ok {
		return cancelEntry{}, cancelLookupMiss
	}
	if !entry.DisconnectedAt.IsZero() && !m.withinGraceLocked(*entry, m.now()) {
		out := cloneCancelEntry(entry)
		return out, cancelLookupExpired
	}
	return cloneCancelEntry(entry), cancelLookupFound
}

func (m *cancelMap) MarkDisconnected(key cancelKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry, ok := m.entries[key]; ok && entry.DisconnectedAt.IsZero() {
		entry.DisconnectedAt = m.now()
	}
}

func (m *cancelMap) PruneExpired(now time.Time) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.pruneExpiredLocked(now)
}

func (m *cancelMap) pruneExpiredLocked(now time.Time) int {
	var n int
	for key, entry := range m.entries {
		if !entry.DisconnectedAt.IsZero() && !m.withinGraceLocked(*entry, now) {
			delete(m.entries, key)
			n++
		}
	}
	return n
}

func (m *cancelMap) withinGraceLocked(entry cancelEntry, now time.Time) bool {
	return entry.DisconnectedAt.IsZero() || now.Sub(entry.DisconnectedAt) <= m.graceWindow
}

func cloneCancelEntry(entry *cancelEntry) cancelEntry {
	out := *entry
	out.RealSecret = append([]byte(nil), entry.RealSecret...)
	out.SyntheticSecret = append([]byte(nil), entry.SyntheticSecret...)
	return out
}

func generateCancelKey() (uint32, []byte, error) {
	var pidBytes [4]byte
	var secret [4]byte
	if _, err := rand.Read(pidBytes[:]); err != nil {
		return 0, nil, err
	}
	if _, err := rand.Read(secret[:]); err != nil {
		return 0, nil, err
	}
	pid := binary.BigEndian.Uint32(pidBytes[:])
	if pid == 0 {
		pid = 1
	}
	return pid, append([]byte(nil), secret[:]...), nil
}

func cancelSecretsEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
```

- [ ] **Step 4: Run unit tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestCancelMap_' -count=1 -v
```

Expected: all `TestCancelMap_...` tests pass.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/cancelmap.go internal/db/proxy/postgres/cancelmap_test.go
git commit -m "db: add postgres cancel mapping table"
```

---

### Task 2: Wire Cancel Map Into `Server` And Connection Cleanup

**Files:**
- Modify: `internal/db/proxy/postgres/server.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go`
- Modify: `internal/db/proxy/postgres/server_test.go`

- [ ] **Step 1: Write failing tests for config defaults**

Append to `internal/db/proxy/postgres/server_test.go`:

```go
func TestNew_DefaultsCancelMapConfig(t *testing.T) {
	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         loadRuleSet(t, `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: "127.0.0.1:5432", tls_mode: terminate_plaintext_upstream, trusted_network: true}
database_connection_rules:
  - {name: allow, db_service: appdb, decision: allow}
`),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "127.0.0.1:5432",
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: filepath.Join(t.TempDir(), "db.sock")},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if srv.cancelMap == nil {
		t.Fatal("cancelMap is nil")
	}
	if srv.cfg.CancelMappingMax != defaultCancelMappingMax {
		t.Fatalf("CancelMappingMax = %d, want %d", srv.cfg.CancelMappingMax, defaultCancelMappingMax)
	}
	if srv.cfg.CancelGraceWindow != defaultCancelGraceWindow {
		t.Fatalf("CancelGraceWindow = %s, want %s", srv.cfg.CancelGraceWindow, defaultCancelGraceWindow)
	}
}
```

- [ ] **Step 2: Run test to verify failure**

Run:

```bash
go test ./internal/db/proxy/postgres -run TestNew_DefaultsCancelMapConfig -count=1
```

Expected: build fails because `Config.CancelMappingMax`, `Config.CancelGraceWindow`, or `Server.cancelMap` does not exist.

- [ ] **Step 3: Add config fields and defaults**

Edit `internal/db/proxy/postgres/server.go`.

Add to `Config`:

```go
	// CancelMappingMax caps the proxy-wide BackendKeyData translation table.
	// Default 100k when zero.
	CancelMappingMax int

	// CancelGraceWindow retains disconnected cancel mappings for late
	// side-channel CancelRequests. Default 5 minutes when zero.
	CancelGraceWindow time.Duration
```

Add to `Server`:

```go
	cancelMap *cancelMap
```

In `New`, after `MaxQueryBytes` defaulting in both sentinel and non-sentinel branches:

```go
	if cfg.CancelMappingMax == 0 {
		cfg.CancelMappingMax = defaultCancelMappingMax
	}
	if cfg.CancelGraceWindow == 0 {
		cfg.CancelGraceWindow = defaultCancelGraceWindow
	}
```

When constructing `Server`, include:

```go
cancelMap: newCancelMap(cancelMapConfig{
	Max:         cfg.CancelMappingMax,
	GraceWindow: cfg.CancelGraceWindow,
}),
```

If `server.go` does not already import `time`, add it.

- [ ] **Step 4: Add release hook to `proxyConn`**

Edit `internal/db/proxy/postgres/proxyconn.go`.

Add to `connState`:

```go
	cancelRegistration *cancelRegistration
```

Update `closeUpstream`:

```go
func (pc *proxyConn) closeUpstream() {
	if pc.state.cancelRegistration != nil {
		pc.state.cancelRegistration.Release()
		pc.state.cancelRegistration = nil
	}
	if pc.state.upstream != nil {
		_ = pc.state.upstream.Close()
		pc.state.upstream = nil
	}
}
```

- [ ] **Step 5: Run tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestNew_DefaultsCancelMapConfig|TestCancelMap_' -count=1
```

Expected: all listed tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/server.go internal/db/proxy/postgres/proxyconn.go internal/db/proxy/postgres/server_test.go
git commit -m "db: configure postgres cancel map"
```

---

### Task 3: Translate `BackendKeyData` During Auth

**Files:**
- Modify: `internal/db/proxy/postgres/authforward.go`
- Modify: `internal/db/proxy/postgres/authforward_test.go`
- Modify: `internal/db/proxy/postgres/proxyconn.go`

- [ ] **Step 1: Update auth-forward test to require synthetic BKD**

In `internal/db/proxy/postgres/authforward_test.go`, change `TestForwardAuth_AuthOK_ForwardsToRFQ` so the client captures `BackendKeyData`:

```go
	var clientBKD *pgproto3.BackendKeyData
	doneClient := make(chan error, 1)
	go func() {
		var rfqSeen bool
		for !rfqSeen {
			msg, err := clientReader.Receive()
			if err != nil {
				doneClient <- err
				return
			}
			switch m := msg.(type) {
			case *pgproto3.BackendKeyData:
				clientBKD = &pgproto3.BackendKeyData{
					ProcessID: m.ProcessID,
					SecretKey: append([]byte(nil), m.SecretKey...),
				}
			case *pgproto3.ReadyForQuery:
				rfqSeen = true
			}
		}
		doneClient <- nil
	}()
```

After `doneClient`:

```go
	if clientBKD == nil {
		t.Fatal("client did not receive BackendKeyData")
	}
	if clientBKD.ProcessID == 12345 || bytesEqual(clientBKD.SecretKey, secretBytes) {
		t.Fatalf("client received real upstream BKD: pid=%d secret=%x", clientBKD.ProcessID, clientBKD.SecretKey)
	}
	entry, status := pc.srv.cancelMap.Lookup(clientBKD.ProcessID, clientBKD.SecretKey)
	if status != cancelLookupFound {
		t.Fatalf("synthetic BKD lookup status = %v, want found", status)
	}
	if entry.RealPID != 12345 || !bytesEqual(entry.RealSecret, secretBytes) {
		t.Fatalf("mapped real BKD = (%d,%x), want (12345,%x)", entry.RealPID, entry.RealSecret, secretBytes)
	}
```

Ensure imports include `bytes` only if the file uses `bytes.Equal`; this file currently has `bytesEqual`, so no new import is required for the added assertions.

- [ ] **Step 2: Add failing test for registration failure**

Append to `internal/db/proxy/postgres/authforward_test.go`:

```go
func TestForwardAuth_BackendKeyRegistrationFailure_FailsClosed(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	pc.srv.cancelMap = newCancelMap(cancelMapConfig{
		Max:         1,
		GraceWindow: time.Minute,
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{
			{pid: 1, secret: []byte{1}},
			{pid: 2, secret: []byte{2}},
		}),
	})
	if _, err := pc.srv.cancelMap.Register(cancelMeta{ServiceName: "appdb"}, 1, []byte{1}); err != nil {
		t.Fatalf("seed Register: %v", err)
	}
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)

	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.BackendKeyData{ProcessID: 12345, SecretKey: []byte{0, 0, 0, 9}})
		_ = upstreamScript.Flush()
	}()

	doneClient := make(chan pgproto3.BackendMessage, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				doneClient <- nil
				return
			}
			if _, ok := msg.(*pgproto3.ErrorResponse); ok {
				doneClient <- msg
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := forwardAuth(ctx, pc)
	if !errors.Is(err, errBackendKeyTableFull) {
		t.Fatalf("forwardAuth err = %v, want errBackendKeyTableFull", err)
	}
	msg := <-doneClient
	er, ok := msg.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("client message = %T, want ErrorResponse", msg)
	}
	if er.Message != "BACKEND_KEY_TABLE_FULL" {
		t.Fatalf("ErrorResponse.Message = %q, want BACKEND_KEY_TABLE_FULL", er.Message)
	}
}
```

- [ ] **Step 3: Run tests to verify failure**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestForwardAuth_AuthOK_ForwardsToRFQ|TestForwardAuth_BackendKeyRegistrationFailure_FailsClosed' -count=1
```

Expected: first test fails because client receives real BKD; second test fails because registration is not used.

- [ ] **Step 4: Implement register-and-synthesize in `forwardAuth`**

Edit the `*pgproto3.BackendKeyData` case in `internal/db/proxy/postgres/authforward.go`:

```go
		case *pgproto3.BackendKeyData:
			pc.state.upstreamBKD.PID = m.ProcessID
			pc.state.upstreamBKD.SecretKey = append(pc.state.upstreamBKD.SecretKey[:0], m.SecretKey...)

			reg, err := pc.srv.cancelMap.Register(cancelMeta{
				ServiceName:     pc.svc.Name,
				UpstreamAddr:    pc.svc.Upstream,
				ClientIdentity:  pc.state.clientIdentity,
				DBUser:          pc.state.dbUser,
				Database:        pc.state.database,
				ApplicationName: pc.state.appName,
				PeerUID:         pc.state.peerUID,
			}, m.ProcessID, m.SecretKey)
			if err != nil {
				pc.emitCancelMappingFail(ctx, err)
				pc.backend.Send(&pgproto3.ErrorResponse{
					Severity:            "FATAL",
					SeverityUnlocalized: "FATAL",
					Code:                "53300",
					Message:             cancelMappingErrorCode(err),
				})
				_ = pc.backend.Flush()
				return err
			}
			pc.state.cancelRegistration = &reg
			pc.backend.Send(&pgproto3.BackendKeyData{
				ProcessID: reg.SyntheticPID,
				SecretKey: append([]byte(nil), reg.SyntheticSecret...),
			})
			if err := pc.backend.Flush(); err != nil {
				return fmt.Errorf("flush after BKD: %w", err)
			}
```

Add helpers near other lifecycle emitters in `proxyconn.go`:

```go
func cancelMappingErrorCode(err error) string {
	switch {
	case errors.Is(err, errBackendKeyGenerationFailed):
		return "BACKEND_KEY_GENERATION_FAILED"
	case errors.Is(err, errBackendKeyTableFull):
		return "BACKEND_KEY_TABLE_FULL"
	default:
		return "BACKEND_KEY_MAPPING_FAILED"
	}
}

func (pc *proxyConn) emitCancelMappingFail(ctx context.Context, err error) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           "db_cancel_mapping_fail",
		ErrorCode:      cancelMappingErrorCode(err),
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, ev)
}
```

Add imports to `proxyconn.go` if missing:

```go
import (
	"errors"
)
```

If `proxyconn.go` already has an import block, merge `errors` into it rather than creating a second block.

- [ ] **Step 5: Run tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestForwardAuth_AuthOK_ForwardsToRFQ|TestForwardAuth_BackendKeyRegistrationFailure_FailsClosed' -count=1 -v
```

Expected: both tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/authforward.go internal/db/proxy/postgres/authforward_test.go internal/db/proxy/postgres/proxyconn.go
git commit -m "db: translate BackendKeyData for cancel mapping"
```

---

### Task 4: Implement Lookup-First CancelRequest Handling

**Files:**
- Modify: `internal/db/proxy/postgres/handshake.go`
- Modify: `internal/db/proxy/postgres/cancel.go`
- Modify: `internal/db/proxy/postgres/handshake_test.go`
- Modify: `internal/db/proxy/postgres/cancel_test.go`

- [ ] **Step 1: Write failing no-match and allow tests**

Update `TestDispatch_CancelRequest_ClosesSilently` in `handshake_test.go` to assert lifecycle emission:

```go
func TestDispatch_CancelRequest_NoMatch_ClosesSilentlyAndEmitsLifecycle(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)
	sink := pc.srv.cfg.Sink.(*events.SyncSink)

	go func() {
		body := make([]byte, 4+4+4)
		binary.BigEndian.PutUint32(body[0:4], cancelRequestMagic)
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
	evs := sink.DrainLifecycle()
	if len(evs) != 1 || evs[0].Kind != "db_cancel_unmatched" {
		t.Fatalf("lifecycle events = %+v, want one db_cancel_unmatched", evs)
	}
}
```

Replace the old un-mapped allow test with a mapped allow test:

```go
func TestDispatch_CancelRequest_AllowedForwardsRealMappedPacket(t *testing.T) {
	upAddr, ch := captureCancelListener(t)
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
			Upstream: upAddr,
			TLSMode:  "terminate_plaintext_upstream",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reg, err := srv.cancelMap.Register(cancelMeta{
		ServiceName:     "appdb",
		UpstreamAddr:    upAddr,
		ClientIdentity:  "uid:1000",
		DBUser:          "alice",
		Database:        "app",
		ApplicationName: "psql",
		PeerUID:         1000,
	}, 11111, []byte{0, 0, 86, 206})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()

	if _, err := b.Write(buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	var captured []byte
	select {
	case captured = <-ch:
		if captured == nil {
			t.Fatal("upstream did not capture cancel packet")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("upstream did not capture cancel packet")
	}
	want := buildCancelPacketBytes(11111, []byte{0, 0, 86, 206})
	if !bytes.Equal(captured, want) {
		t.Fatalf("captured cancel = %x, want real upstream packet %x", captured, want)
	}
	stmts := sink.DrainStatements()
	if len(stmts) != 1 {
		t.Fatalf("statement events = %+v, want one cancel DBEvent", stmts)
	}
	if stmts[0].Decision.RuleKind != "cancel" || stmts[0].Decision.Verb != "allow" {
		t.Fatalf("cancel decision = %+v, want cancel/allow", stmts[0].Decision)
	}
}
```

Add `bytes` to `handshake_test.go` imports if not already present.

- [ ] **Step 2: Run tests to verify failure**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestDispatch_CancelRequest_NoMatch|TestDispatch_CancelRequest_AllowedForwardsRealMappedPacket' -count=1
```

Expected: tests fail because no lifecycle event is emitted and un-mapped forwarding still uses client credentials.

- [ ] **Step 3: Add cancel event builder**

Add to `internal/db/proxy/postgres/eventbuilder.go`:

```go
func buildCancelEvent(entry cancelEntry, d policy.Decision, resultErr string) events.DBEvent {
	return events.DBEvent{
		EventID:           newEventID(),
		SessionID:         entry.ClientIdentity,
		Timestamp:         timeNow(),
		DBService:         entry.ServiceName,
		DBFamily:          "postgres",
		DBDialect:         "postgres",
		DBUser:            entry.DBUser,
		ApplicationName:   entry.ApplicationName,
		ClientIdentity:    entry.ClientIdentity,
		Effects:           []effects.Effect{{Group: effects.GroupSession, Subtype: effects.SubtypeCancelRequest}},
		OperationGroup:    "session",
		OperationSubtype:  "cancel_request",
		StatementRedaction: events.RedactionNone,
		Decision:          buildDecision(d, false),
		Result:            events.EventResult{ErrorCode: resultErr},
		TxContext:         events.EventTxContext{DenyAction: "none"},
	}
}
```

Ensure `eventbuilder.go` already imports `effects`, `events`, and `policy`; it does, so no new imports should be required.

- [ ] **Step 4: Implement lifecycle helpers and mapped cancel flow**

In `handshake.go`, replace `handleCancelRequest` body with:

```go
func (pc *proxyConn) handleCancelRequest(ctx context.Context, m *pgproto3.CancelRequest) error {
	entry, status := pc.srv.cancelMap.Lookup(m.ProcessID, m.SecretKey)
	pc.logger.Debug("CancelRequest received",
		"service", pc.svc.Name,
		"syn_pid", m.ProcessID,
		"status", status)

	switch status {
	case cancelLookupMiss:
		pc.emitCancelLifecycle(ctx, "db_cancel_unmatched", "unmatched_cancel_request", "")
		return nil
	case cancelLookupExpired:
		pc.emitCancelLifecycleForEntry(ctx, entry, "db_cancel_after_disconnect", "cancel_after_disconnect", "")
		return nil
	case cancelLookupFound:
		// continue below
	default:
		pc.emitCancelLifecycle(ctx, "db_cancel_unmatched", "unknown_cancel_lookup_status", "")
		return nil
	}

	d := pc.evaluateMappedCancel(ctx, entry)
	if d.Verb == policy.VerbDeny {
		pc.emitCancelEvent(ctx, entry, d, "")
		return nil
	}

	pkt := buildCancelPacketBytes(entry.RealPID, entry.RealSecret)
	var resultErr string
	cancelSvc := Service{Upstream: entry.UpstreamAddr}
	if err := forwardCancel(ctx, cancelSvc, pkt); err != nil {
		resultErr = "CANCEL_FORWARD_FAILED"
		pc.logger.Warn("forwardCancel failed", "service", entry.ServiceName, "err", err)
		pc.emitCancelLifecycleForEntry(ctx, entry, "db_cancel_forward_failed", "forward_failed", resultErr)
	}
	pc.emitCancelEvent(ctx, entry, d, resultErr)
	return nil
}
```

Add helpers in `handshake.go` or `connect_rule.go`:

```go
func (pc *proxyConn) evaluateMappedCancel(_ context.Context, entry cancelEntry) policy.Decision {
	return policy.EvaluateConnection(policy.ConnectionInfo{
		Service:         policy.ServiceID(entry.ServiceName),
		MatchKind:       policy.MatchCancel,
		DBUser:          entry.DBUser,
		Database:        entry.Database,
		ApplicationName: entry.ApplicationName,
		ClientIdentity:  entry.ClientIdentity,
	}, pc.srv.cfg.Policy)
}

func (pc *proxyConn) emitCancelEvent(ctx context.Context, entry cancelEntry, d policy.Decision, resultErr string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	_ = pc.srv.cfg.Sink.EmitStatement(ctx, buildCancelEvent(entry, d, resultErr))
}

func (pc *proxyConn) emitCancelLifecycle(ctx context.Context, kind, reason, code string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      pc.svc.Name,
		ClientIdentity: pc.state.clientIdentity,
		Kind:           kind,
		Reason:         reason,
		ErrorCode:      code,
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, ev)
}

func (pc *proxyConn) emitCancelLifecycleForEntry(ctx context.Context, entry cancelEntry, kind, reason, code string) {
	if pc.srv.cfg.Sink == nil {
		return
	}
	ev := events.LifecycleEvent{
		EventID:        newEventID(),
		Timestamp:      timeNow(),
		DBService:      entry.ServiceName,
		ClientIdentity: entry.ClientIdentity,
		Kind:           kind,
		Reason:         reason,
		ErrorCode:      code,
	}
	_ = pc.srv.cfg.Sink.EmitLifecycle(ctx, ev)
}
```

Ensure `handshake.go` imports `events` if the helper lives there.

- [ ] **Step 5: Run tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestDispatch_CancelRequest_NoMatch|TestDispatch_CancelRequest_AllowedForwardsRealMappedPacket' -count=1 -v
```

Expected: tests pass.

- [ ] **Step 6: Commit**

```bash
git add internal/db/proxy/postgres/handshake.go internal/db/proxy/postgres/cancel.go internal/db/proxy/postgres/handshake_test.go internal/db/proxy/postgres/cancel_test.go internal/db/proxy/postgres/eventbuilder.go
git commit -m "db: route CancelRequest through mapped backend keys"
```

---

### Task 5: Cover Deny, Audit, Expiry, Forward Failure, And Lifecycle Docs

**Files:**
- Modify: `internal/db/proxy/postgres/handshake_test.go`
- Modify: `internal/db/events/lifecycle.go`
- Modify: `internal/db/events/event.go`

- [ ] **Step 1: Add focused cancel outcome tests**

Append to `internal/db/proxy/postgres/handshake_test.go`:

```go
func TestDispatch_CancelRequest_DenyDoesNotDialAndEmitsDBEvent(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	dialed := make(chan struct{}, 1)
	go func() {
		if c, err := upLn.Accept(); err == nil {
			dialed <- struct{}{}
			_ = c.Close()
		}
	}()

	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	rs := loadRuleSet(t, `version: 1
name: test
db_services:
  appdb: {family: postgres, dialect: postgres, upstream: `+upLn.Addr().String()+`, tls_mode: terminate_plaintext_upstream, trusted_network: true}
database_connection_rules:
  - {name: deny-cancel, db_service: appdb, match_kind: cancel, decision: deny}
`)
	sink := &events.SyncSink{}
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           sink,
		Policy:         rs,
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: upLn.Addr().String(),
			TLSMode: "terminate_plaintext_upstream",
			Listen:  ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service: policy.DBService{Name: "appdb", TLSMode: "terminate_plaintext_upstream", TrustedNetwork: true},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	reg, err := srv.cancelMap.Register(cancelMeta{ServiceName: "appdb", UpstreamAddr: upLn.Addr().String(), ClientIdentity: "uid:1000"}, 11111, []byte{0, 0, 0, 1})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()
	if _, err := b.Write(buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	select {
	case <-dialed:
		t.Fatal("upstream was dialed despite deny")
	case <-time.After(300 * time.Millisecond):
	}
	stmts := sink.DrainStatements()
	if len(stmts) != 1 || stmts[0].Decision.Verb != "deny" || stmts[0].Decision.RuleKind != "cancel" {
		t.Fatalf("cancel DBEvents = %+v, want one deny/cancel", stmts)
	}
}

func TestDispatch_CancelRequest_ExpiredEmitsLifecycle(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := newTestProxyConn(t, a)
	sink := pc.srv.cfg.Sink.(*events.SyncSink)
	now := time.Date(2026, 5, 12, 10, 0, 0, 0, time.UTC)
	pc.srv.cancelMap = newCancelMap(cancelMapConfig{
		Max:         10,
		GraceWindow: time.Minute,
		Now:         func() time.Time { return now },
		Generate: fixedCancelKeyGenerator([]generatedCancelKey{{pid: 9, secret: []byte{9}}}),
	})
	reg, err := pc.srv.cancelMap.Register(cancelMeta{ServiceName: "appdb", ClientIdentity: "uid:1000"}, 1, []byte{1})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	reg.Release()
	now = now.Add(2 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	go func() { _ = pc.run(ctx) }()
	if _, err := b.Write(buildCancelPacketBytes(reg.SyntheticPID, reg.SyntheticSecret)); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	evs := sink.DrainLifecycle()
	if len(evs) != 1 || evs[0].Kind != "db_cancel_after_disconnect" {
		t.Fatalf("lifecycle events = %+v, want db_cancel_after_disconnect", evs)
	}
}
```

- [ ] **Step 2: Add lifecycle documentation**

Edit `internal/db/events/lifecycle.go` comment for `Kind`:

```go
// Kind is a small enumerated string. Values currently include:
// "db_listener_auth_fail", "db_handshake_fail",
// "degraded_visibility_warning", "db_cancel_unmatched",
// "db_cancel_after_disconnect", "db_cancel_forward_failed",
// and "db_cancel_mapping_fail".
```

Edit `internal/db/events/event.go` comment for `DBEvent`:

```go
// Cancel governance events also use DBEvent with decision.rule_kind="cancel",
// operation_group="session", and operation_subtype="cancel_request"; those
// events intentionally carry no statement text or digest.
```

- [ ] **Step 3: Run tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestDispatch_CancelRequest_(Deny|Expired|Allowed|NoMatch)' -count=1 -v
```

Expected: all matching tests pass.

- [ ] **Step 4: Commit**

```bash
git add internal/db/proxy/postgres/handshake_test.go internal/db/events/lifecycle.go internal/db/events/event.go
git commit -m "db: cover cancel mapping outcomes"
```

---

### Task 6: Add Cancel Mapping Spine And Race Coverage

**Files:**
- Modify: `internal/db/proxy/postgres/spine_test.go`
- Modify: `internal/db/proxy/postgres/authforward_test.go`

- [ ] **Step 1: Update existing spine expectations for synthetic BKD**

In `spine_test.go`, existing auth spine tests currently expect upstream real BKD. Change those assertions:

```go
	if bkd.ProcessID == 42 {
		t.Errorf("BKD.ProcessID = upstream real PID 42; want synthetic PID")
	}
	if bytes.Equal(bkd.SecretKey, wantSecret) {
		t.Errorf("BKD.SecretKey = upstream real secret %x; want synthetic secret", bkd.SecretKey)
	}
	entry, status := h.srv.cancelMap.Lookup(bkd.ProcessID, bkd.SecretKey)
	if status != cancelLookupFound {
		t.Fatalf("synthetic BKD lookup status = %v, want found", status)
	}
	if entry.RealPID != 42 || !bytes.Equal(entry.RealSecret, wantSecret) {
		t.Fatalf("mapped real key = (%d,%x), want (42,%x)", entry.RealPID, entry.RealSecret, wantSecret)
	}
```

- [ ] **Step 2: Add spine test for side-channel cancel**

Append to `spine_test.go`:

```go
func TestSpine_CancelRequest_UsesSyntheticKeyAndForwardsRealKey(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer upLn.Close()
	cancelPackets := make(chan []byte, 1)
	upErr := make(chan error, 2)
	go func() {
		conn, err := upLn.Accept()
		if err != nil {
			upErr <- err
			return
		}
		defer conn.Close()
		be := pgproto3.NewBackend(conn, conn)
		if _, err := be.ReceiveStartupMessage(); err != nil {
			upErr <- fmt.Errorf("receive startup: %w", err)
			return
		}
		be.Send(&pgproto3.AuthenticationOk{})
		be.Send(&pgproto3.BackendKeyData{ProcessID: 42, SecretKey: append([]byte(nil), wantSecret...)})
		be.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		if err := be.Flush(); err != nil {
			upErr <- fmt.Errorf("flush auth: %w", err)
			return
		}
		upErr <- nil
	}()
	go func() {
		conn, err := upLn.Accept()
		if err != nil {
			upErr <- err
			return
		}
		defer conn.Close()
		buf := make([]byte, 16)
		_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
		n, err := io.ReadFull(conn, buf)
		if err == nil {
			cancelPackets <- append([]byte(nil), buf[:n]...)
		}
		upErr <- err
	}()
	upAddr := upstreamWithLocalhostHost(upLn.Addr().String())
	extraRules := `
  - name: allow-cancel
    db_service: appdb
    match_kind: cancel
    decision: allow
`
	h := startSpineHarness(t, upAddr, "terminate_plaintext_upstream", nil, extraRules)
	stop := runServer(t, h.srv)
	defer stop()

	tlsConn := handRolledTerminateReissueHandshake(t, h.sock, h.ca)
	defer tlsConn.Close()
	bkd := readUntilRFQ(t, tlsConn)
	if bkd == nil {
		t.Fatal("never received BackendKeyData")
	}
	if bkd.ProcessID == 42 || bytes.Equal(bkd.SecretKey, wantSecret) {
		t.Fatalf("client saw real upstream BKD: pid=%d secret=%x", bkd.ProcessID, bkd.SecretKey)
	}
	if err := <-upErr; err != nil {
		t.Fatalf("normal upstream auth script: %v", err)
	}

	cancelConn, err := net.Dial("unix", h.sock)
	if err != nil {
		t.Fatalf("dial cancel unix socket: %v", err)
	}
	defer cancelConn.Close()
	if _, err := cancelConn.Write(buildCancelPacketBytes(bkd.ProcessID, bkd.SecretKey)); err != nil {
		t.Fatalf("write CancelRequest: %v", err)
	}

	var captured []byte
	select {
	case captured = <-cancelPackets:
	case <-time.After(3 * time.Second):
		t.Fatal("fake upstream did not receive cancel packet")
	}
	if err := <-upErr; err != nil {
		t.Fatalf("cancel upstream capture: %v", err)
	}
	want := buildCancelPacketBytes(42, wantSecret)
	if !bytes.Equal(captured, want) {
		t.Fatalf("upstream cancel packet = %x, want %x", captured, want)
	}
	stmts := h.sink.DrainStatements()
	var found bool
	for _, ev := range stmts {
		if ev.Decision.RuleKind == "cancel" && ev.Decision.Verb == "allow" {
			found = true
		}
	}
	if !found {
		t.Fatalf("cancel allow DBEvent not found in %+v", stmts)
	}
}
```

- [ ] **Step 3: Add commit-order race test**

Append to `authforward_test.go`:

```go
func TestForwardAuth_BackendKeyMappingCommittedBeforeClientReceivesSyntheticKey(t *testing.T) {
	clientFE, proxyClientBE, proxyUpstreamFE, upstreamBE := pairedConns(t)
	pc := newTestProxyConnForAuth(t, proxyClientBE, proxyUpstreamFE)
	upstreamScript := pgproto3.NewBackend(upstreamBE, upstreamBE)
	clientReader := pgproto3.NewFrontend(clientFE, clientFE)
	secretBytes := []byte{0, 0, 0, 77}

	go func() {
		upstreamScript.Send(&pgproto3.AuthenticationOk{})
		upstreamScript.Send(&pgproto3.BackendKeyData{ProcessID: 777, SecretKey: secretBytes})
		upstreamScript.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = upstreamScript.Flush()
	}()

	seen := make(chan *pgproto3.BackendKeyData, 1)
	readDone := make(chan error, 1)
	go func() {
		for {
			msg, err := clientReader.Receive()
			if err != nil {
				readDone <- err
				return
			}
			if bkd, ok := msg.(*pgproto3.BackendKeyData); ok {
				seen <- &pgproto3.BackendKeyData{
					ProcessID: bkd.ProcessID,
					SecretKey: append([]byte(nil), bkd.SecretKey...),
				}
				continue
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				readDone <- nil
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- forwardAuth(ctx, pc) }()

	var bkd *pgproto3.BackendKeyData
	select {
	case bkd = <-seen:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not receive BackendKeyData")
	}
	entry, status := pc.srv.cancelMap.Lookup(bkd.ProcessID, bkd.SecretKey)
	if status != cancelLookupFound {
		t.Fatalf("lookup immediately after client receive = %v, want found", status)
	}
	if entry.RealPID != 777 || !bytesEqual(entry.RealSecret, secretBytes) {
		t.Fatalf("entry real key = (%d,%x), want (777,%x)", entry.RealPID, entry.RealSecret, secretBytes)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("client reader: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatalf("forwardAuth: %v", err)
	}
}
```

- [ ] **Step 4: Run spine and race-targeted tests**

Run:

```bash
go test ./internal/db/proxy/postgres -run 'TestSpine_CancelRequest|TestForwardAuth_BackendKeyMappingCommittedBeforeClientReceivesSyntheticKey|TestSpine_Terminate.*AuthOK' -count=1 -v
```

Expected: all matching tests pass.

Then run:

```bash
go test -race ./internal/db/proxy/postgres -run 'TestForwardAuth_BackendKeyMappingCommittedBeforeClientReceivesSyntheticKey|TestCancelMap_' -count=1
```

Expected: pass with no race detector findings.

- [ ] **Step 5: Commit**

```bash
git add internal/db/proxy/postgres/spine_test.go internal/db/proxy/postgres/authforward_test.go
git commit -m "db: add cancel mapping spine coverage"
```

---

### Task 7: Final Verification

**Files:**
- Verify only.

- [ ] **Step 1: Run PostgreSQL proxy tests**

Run:

```bash
go test ./internal/db/proxy/postgres -count=1 -timeout 240s
```

Expected: pass.

- [ ] **Step 2: Run DB package tests**

Run:

```bash
go test ./internal/db/... -count=1 -timeout 240s
```

Expected: pass.

- [ ] **Step 3: Run race tests for DB proxy**

Run:

```bash
go test -race ./internal/db/proxy/postgres -count=1 -timeout 240s
```

Expected: pass.

- [ ] **Step 4: Run full test suite**

Run:

```bash
go test ./... -count=1 -timeout 240s
```

Expected: pass.

- [ ] **Step 5: Verify Windows build**

Run:

```bash
GOOS=windows go build ./...
```

Expected: pass.

- [ ] **Step 6: Inspect git status**

Run:

```bash
git status --short
```

Expected: only intentional Plan 06 implementation files are modified, or the worktree is clean after commits.
