# credsub.Table (Plan 2) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the thread-safe in-memory `credsub.Table` that stores per-session (fake, real) credential pairs and performs byte-level substitution in both directions (fake→real on egress, real→fake on response scrub).

**Architecture:** A new package `internal/proxy/credsub/` containing a single `Table` type that owns copies of every fake/real byte slice, enforces length preservation and collision invariants at `Add` time, and performs substitution via `bytes.ReplaceAll` loops. No providers, no proxy wiring, no session integration — those land in later plans. Pure stdlib, no new dependencies.

**Tech Stack:** Go stdlib only (`bytes`, `sync`, `testing`, `sync/atomic` for tests). No new module dependencies. Module path: `github.com/agentsh/agentsh/internal/proxy/credsub`.

**Scope boundary:** This plan produces a package with zero call sites inside the daemon. It is the "extension infrastructure" piece, parallel to how Plan 1 added an empty `Hook` interface. Plan 3 will add the first consumer (`SecretProvider` interface + keyring provider), and later plans will wire `credsub.Table` into session lifecycle and egress flow.

**Spec reference:** `docs/superpowers/specs/2026-04-07-external-secrets-design.md`, Section 4 "credsub.Table".

---

## Architectural notes (read before starting tasks)

### Invariants Table enforces at Add time

1. **Length preservation:** `len(fake) == len(real)`. This is required for the future Mechanism B in-place `bpf_probe_write_user` rewrite, and it keeps the proxy from having to recompute Content-Length on every substitution. Violation → `ErrLengthMismatch`.
2. **Nonempty:** neither `fake` nor `real` may be zero-length. A zero-length pattern would match every position in any body. Violation → `ErrEmptyValue`.
3. **Unique service name:** a service name may be registered only once per Table. Violation → `ErrServiceExists`.
4. **Fake ≠ real within the same call:** the new fake must not equal the new real. If they were equal the agent would see the real credential as its fake — exactly the leak the table is supposed to prevent. Violation → `ErrFakeCollision`.
5. **Unique fake:** the same fake byte sequence may not appear twice in the table. Violation → `ErrFakeCollision`.
6. **Unique real:** the same real byte sequence may not appear twice in the table. Two services sharing the same upstream credential would make `ReplaceRealToFake` ambiguous (the real value would always be rewritten to whichever fake was registered first, returning the wrong service token to the agent). Violation → `ErrFakeCollision`.
7. **No fake↔real crossover:** the new fake must not exactly equal any existing entry's real, and the new real must not exactly equal any existing entry's fake. Otherwise substitution would double-swap. Violation → `ErrFakeCollision`.

We do NOT enforce "no substring containment" at Add time. The caller (future session-start flow) is responsible for generating fakes with enough entropy (spec mandates ≥24 random base62 chars) that accidental substring collisions are astronomically unlikely. Document this in the package doc comment.

### Byte slice ownership

`Add` COPIES the input `fake` and `real` slices. Callers may mutate or zero their own slices after `Add` returns. The Table owns the copies and `Zero()` is responsible for wiping them. This keeps the ownership model simple.

### Substitution semantics

`ReplaceFakeToReal` and `ReplaceRealToFake` are pure `[]byte → []byte` transforms using `bytes.ReplaceAll` in a loop over all entries. Complexity is O(N · |body|) where N is the entry count. For N < 20 (realistic session size) this is well within the proxy's budget. If profiling later shows this to be hot, we can switch to Aho-Corasick — but that optimization is out of scope for Plan 2.

Because `bytes.ReplaceAll` always allocates a new slice even on zero matches, the returned slice may or may not alias the input. Callers must treat the return value as the authoritative result.

### Concurrency model

`Table` guards its state with `sync.RWMutex`. `Add`, `Zero` acquire the write lock; `FakeForService`, `Contains`, `ReplaceFakeToReal`, `ReplaceRealToFake` acquire the read lock. Substitution calls hold the read lock for the duration of the loop, snapshotting nothing — callers must not block for long on the resulting slices while holding references that depend on Table state.

---

## File Structure

**Files created by this plan:**

- `internal/proxy/credsub/doc.go` — package-level doc comment and nothing else. Keeps the godoc discoverable and documents the ownership / collision invariants in one place.
- `internal/proxy/credsub/errors.go` — sentinel errors returned by `Add`.
- `internal/proxy/credsub/table.go` — the `Table` type, `Entry` type, `New` constructor, and all methods.
- `internal/proxy/credsub/table_test.go` — unit tests for every method and invariant.

**Files modified by this plan:** none. This is a new, isolated package.

---

## Task 1: Package skeleton and errors

**Files:**
- Create: `internal/proxy/credsub/doc.go`
- Create: `internal/proxy/credsub/errors.go`

- [ ] **Step 1: Create `doc.go` with the package doc comment**

Write to `internal/proxy/credsub/doc.go`:

```go
// Package credsub implements the per-session credential substitution
// table that maps fake credentials (the bytes an agent sees in its
// environment) to real credentials (the bytes sent upstream).
//
// A Table is created at session start, populated with one entry per
// configured service, and zeroed at session close. It exposes byte-level
// substitution in both directions:
//
//   - ReplaceFakeToReal is used on outbound request bodies, headers,
//     query strings, and URL paths before they leave agentsh.
//   - ReplaceRealToFake is used on inbound response bodies before they
//     reach the agent (when the matched service has scrub_response: true).
//
// Table enforces length preservation (len(fake) == len(real)) and
// basic collision invariants at Add time; it does NOT enforce that
// one fake cannot be a substring of another. Callers are responsible
// for generating fakes with sufficient entropy (the design spec
// mandates ≥24 random base62 characters) so accidental substring
// collisions are astronomically unlikely.
//
// Plan 2 of the external-secrets roadmap lands this package in
// isolation. Providers, session wiring, and the egress flow are
// implemented in later plans.
package credsub
```

- [ ] **Step 2: Create `errors.go` with sentinel errors**

Write to `internal/proxy/credsub/errors.go`:

```go
package credsub

import "errors"

// ErrLengthMismatch is returned by Table.Add when the length of the
// fake byte slice does not equal the length of the real byte slice.
// Length preservation is required for in-place byte rewriting and to
// avoid recomputing Content-Length at substitution time.
var ErrLengthMismatch = errors.New("credsub: fake and real must have equal length")

// ErrEmptyValue is returned by Table.Add when either the fake or real
// slice is zero-length. A zero-length pattern would match every
// position in any body and is never a valid credential.
var ErrEmptyValue = errors.New("credsub: fake and real must be nonempty")

// ErrServiceExists is returned by Table.Add when a service name is
// already registered in the table. Each service has at most one
// (fake, real) pair per session.
var ErrServiceExists = errors.New("credsub: service already registered")

// ErrFakeCollision is returned by Table.Add when the new fake exactly
// equals an existing entry's fake, when the new fake exactly equals
// an existing entry's real, or when the new real exactly equals an
// existing entry's fake. Any of these would cause substitution to
// double-swap and corrupt data.
var ErrFakeCollision = errors.New("credsub: fake or real collides with existing entry")
```

- [ ] **Step 3: Verify package compiles**

Run: `go build ./internal/proxy/credsub/...`
Expected: no output, exit 0.

- [ ] **Step 4: Commit**

```bash
git add internal/proxy/credsub/doc.go internal/proxy/credsub/errors.go
git commit -m "feat(credsub): add package skeleton and sentinel errors"
```

---

## Task 2: Table type, Entry type, and New constructor

**Files:**
- Create: `internal/proxy/credsub/table.go`
- Create: `internal/proxy/credsub/table_test.go`

- [ ] **Step 1: Write the failing test for `New`**

Write to `internal/proxy/credsub/table_test.go`:

```go
package credsub

import (
	"testing"
)

func TestNew_ReturnsEmptyTable(t *testing.T) {
	tb := New()
	if tb == nil {
		t.Fatal("New returned nil")
	}
	if got := tb.Len(); got != 0 {
		t.Errorf("new table Len() = %d, want 0", got)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/proxy/credsub/ -run TestNew_ReturnsEmptyTable -v`
Expected: FAIL with a compile error mentioning `undefined: New` (or `undefined: Table`).

- [ ] **Step 3: Implement minimal `Table` type, `Entry` type, `New`, and `Len`**

Write to `internal/proxy/credsub/table.go`:

```go
package credsub

import (
	"sync"
	"time"
)

// Entry is one (fake, real) substitution pair owned by a Table.
// The Fake and Real byte slices are private copies owned by the
// Table; callers must not mutate them after Add returns.
type Entry struct {
	// ServiceName is the logical service this entry belongs to
	// (for example "github" or "anthropic"). Unique within a Table.
	ServiceName string

	// Fake is the bytes the agent sees. Equal length to Real.
	Fake []byte

	// Real is the bytes sent upstream. Equal length to Fake.
	Real []byte

	// AddedAt records when this entry was registered, for
	// diagnostics. Not used by substitution logic.
	AddedAt time.Time
}

// Table is a per-session credential substitution table. The zero
// value is not usable; construct one with New. Table is safe for
// concurrent use by multiple goroutines.
type Table struct {
	mu      sync.RWMutex
	entries []Entry
}

// New returns an empty, ready-to-use Table.
func New() *Table {
	return &Table{}
}

// Len returns the number of entries currently in the table.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.entries)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/proxy/credsub/ -run TestNew_ReturnsEmptyTable -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): add Table type and New constructor"
```

---

## Task 3: Add — length and emptiness validation

**Files:**
- Modify: `internal/proxy/credsub/table.go` (add `Add` method)
- Modify: `internal/proxy/credsub/table_test.go` (add tests)

- [ ] **Step 1: Write the failing tests for length and emptiness**

Append to `internal/proxy/credsub/table_test.go` (functions go AFTER the existing import block; the import block update is described in the note at the end of this step):

```go
func TestAdd_HappyPath(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add returned error: %v", err)
	}
	if got := tb.Len(); got != 1 {
		t.Errorf("Len() after Add = %d, want 1", got)
	}
}

func TestAdd_LengthMismatch(t *testing.T) {
	tb := New()
	err := tb.Add("github", []byte("short"), []byte("longer_real"))
	if !errors.Is(err, ErrLengthMismatch) {
		t.Errorf("Add with length mismatch returned %v, want ErrLengthMismatch", err)
	}
	if got := tb.Len(); got != 0 {
		t.Errorf("Len() after failed Add = %d, want 0", got)
	}
}

func TestAdd_EmptyFake(t *testing.T) {
	tb := New()
	err := tb.Add("github", []byte{}, []byte{})
	if !errors.Is(err, ErrEmptyValue) {
		t.Errorf("Add with empty values returned %v, want ErrEmptyValue", err)
	}
}

func TestAdd_NilFake(t *testing.T) {
	tb := New()
	err := tb.Add("github", nil, nil)
	if !errors.Is(err, ErrEmptyValue) {
		t.Errorf("Add with nil values returned %v, want ErrEmptyValue", err)
	}
}
```

Note: the `errors` import must be added to the existing import block in `table_test.go`. If the file already has an import block with just `"testing"`, replace it with:

```go
import (
	"errors"
	"testing"
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestAdd_' -v`
Expected: FAIL with `undefined: (*Table).Add` (or similar).

- [ ] **Step 3: Implement `Add` with length and emptiness validation**

Append to `internal/proxy/credsub/table.go`:

```go
// Add registers a (fake, real) substitution pair for a named service.
//
// In this task Add enforces only the basic shape invariants:
//   - both slices are nonempty (see ErrEmptyValue)
//   - len(fake) == len(real) (see ErrLengthMismatch)
//
// Collision detection (service uniqueness, fake/real collisions, and
// fake==real same-call) is added in the next task.
//
// Add COPIES the input slices. Callers may mutate or zero their
// copies after Add returns.
func (t *Table) Add(serviceName string, fake, real []byte) error {
	if len(fake) == 0 || len(real) == 0 {
		return ErrEmptyValue
	}
	if len(fake) != len(real) {
		return ErrLengthMismatch
	}

	fakeCopy := make([]byte, len(fake))
	copy(fakeCopy, fake)
	realCopy := make([]byte, len(real))
	copy(realCopy, real)

	t.mu.Lock()
	defer t.mu.Unlock()

	t.entries = append(t.entries, Entry{
		ServiceName: serviceName,
		Fake:        fakeCopy,
		Real:        realCopy,
		AddedAt:     time.Now(),
	})
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -run 'TestAdd_' -v`
Expected: PASS for `TestAdd_HappyPath`, `TestAdd_LengthMismatch`, `TestAdd_EmptyFake`, `TestAdd_NilFake`.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): Add method with length and emptiness checks"
```

---

## Task 4: Add — collision detection (service, fake, cross)

**Files:**
- Modify: `internal/proxy/credsub/table.go` (extend `Add`)
- Modify: `internal/proxy/credsub/table_test.go` (add collision tests)

- [ ] **Step 1: Write failing tests for all collision cases**

Append to `internal/proxy/credsub/table_test.go` (functions only; the import block update is in the note at the end of this step):

```go
func TestAdd_DuplicateServiceName(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	err := tb.Add("github", []byte("ghp_fake11111111"), []byte("ghp_real11111111"))
	if !errors.Is(err, ErrServiceExists) {
		t.Errorf("duplicate service Add returned %v, want ErrServiceExists", err)
	}
	if got := tb.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1 (duplicate must not be appended)", got)
	}
}

func TestAdd_DuplicateFake(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("xxxxxxxxxxxxxxxx"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	err := tb.Add("gitlab", []byte("xxxxxxxxxxxxxxxx"), []byte("glpat_real000000"))
	if !errors.Is(err, ErrFakeCollision) {
		t.Errorf("duplicate fake Add returned %v, want ErrFakeCollision", err)
	}
}

func TestAdd_FakeEqualsExistingReal(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("aaaaaaaaaaaaaaaa")); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	// Second entry's fake equals first entry's real.
	err := tb.Add("gitlab", []byte("aaaaaaaaaaaaaaaa"), []byte("glpat_real000000"))
	if !errors.Is(err, ErrFakeCollision) {
		t.Errorf("fake-equals-real Add returned %v, want ErrFakeCollision", err)
	}
}

func TestAdd_RealEqualsExistingFake(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("aaaaaaaaaaaaaaaa"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	// Second entry's real equals first entry's fake.
	err := tb.Add("gitlab", []byte("glpat_fake000000"), []byte("aaaaaaaaaaaaaaaa"))
	if !errors.Is(err, ErrFakeCollision) {
		t.Errorf("real-equals-fake Add returned %v, want ErrFakeCollision", err)
	}
}

func TestAdd_FakeEqualsRealSameCall(t *testing.T) {
	// If a single Add call passes the same bytes for both fake and
	// real, the agent would see the real credential as its fake —
	// exactly the leak the table is supposed to prevent.
	tb := New()
	err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_fake00000000"))
	if !errors.Is(err, ErrFakeCollision) {
		t.Errorf("fake==real same-call Add returned %v, want ErrFakeCollision", err)
	}
	if got := tb.Len(); got != 0 {
		t.Errorf("Len() = %d, want 0 (self-collision must not be appended)", got)
	}
}

func TestAdd_DuplicateReal(t *testing.T) {
	// Two services with the same real credential makes
	// ReplaceRealToFake ambiguous: the real value would always be
	// rewritten to whichever fake was registered first, returning the
	// wrong service token to the agent.
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("aaaaaaaaaaaaaaaa")); err != nil {
		t.Fatalf("first Add failed: %v", err)
	}
	err := tb.Add("gitlab", []byte("glpat_fake000000"), []byte("aaaaaaaaaaaaaaaa"))
	if !errors.Is(err, ErrFakeCollision) {
		t.Errorf("duplicate real Add returned %v, want ErrFakeCollision", err)
	}
	if got := tb.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1 (duplicate real must not be appended)", got)
	}
}

func TestAdd_CallerMutationDoesNotAffectTable(t *testing.T) {
	tb := New()
	fake := []byte("ghp_fake00000000")
	real := []byte("ghp_real00000000")
	if err := tb.Add("github", fake, real); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	// Mutate caller's slices.
	for i := range fake {
		fake[i] = 0
	}
	for i := range real {
		real[i] = 0
	}
	// Table entry must still be intact.
	tb.mu.RLock()
	defer tb.mu.RUnlock()
	if !bytes.Equal(tb.entries[0].Fake, []byte("ghp_fake00000000")) {
		t.Errorf("Table's Fake was mutated by caller: got %q", tb.entries[0].Fake)
	}
	if !bytes.Equal(tb.entries[0].Real, []byte("ghp_real00000000")) {
		t.Errorf("Table's Real was mutated by caller: got %q", tb.entries[0].Real)
	}
}
```

Add `"bytes"` to the test file's import block:

```go
import (
	"bytes"
	"errors"
	"testing"
)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestAdd_Duplicate|TestAdd_FakeEquals|TestAdd_RealEquals|TestAdd_CallerMutation' -v`
Expected: FAIL — current `Add` doesn't detect collisions and the duplicate-service case fails because the second Add still appends.

- [ ] **Step 3: Extend `Add` with collision checks**

Replace the `Add` method body in `internal/proxy/credsub/table.go` with:

```go
// Add registers a (fake, real) substitution pair for a named service.
//
// Add enforces these invariants:
//   - len(fake) == len(real) (see ErrLengthMismatch)
//   - both slices are nonempty (see ErrEmptyValue)
//   - fake != real within the same call (see ErrFakeCollision)
//   - serviceName is not already registered (see ErrServiceExists)
//   - fake or real does not collide with any existing entry's fake or
//     real (see ErrFakeCollision)
//
// Add COPIES the input slices. Callers may mutate or zero their
// copies after Add returns.
func (t *Table) Add(serviceName string, fake, real []byte) error {
	if len(fake) == 0 || len(real) == 0 {
		return ErrEmptyValue
	}
	if len(fake) != len(real) {
		return ErrLengthMismatch
	}
	if bytes.Equal(fake, real) {
		return ErrFakeCollision
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, e := range t.entries {
		if e.ServiceName == serviceName {
			return ErrServiceExists
		}
		if bytes.Equal(e.Fake, fake) {
			return ErrFakeCollision
		}
		if bytes.Equal(e.Real, fake) {
			return ErrFakeCollision
		}
		if bytes.Equal(e.Fake, real) {
			return ErrFakeCollision
		}
		if bytes.Equal(e.Real, real) {
			return ErrFakeCollision
		}
	}

	fakeCopy := make([]byte, len(fake))
	copy(fakeCopy, fake)
	realCopy := make([]byte, len(real))
	copy(realCopy, real)

	t.entries = append(t.entries, Entry{
		ServiceName: serviceName,
		Fake:        fakeCopy,
		Real:        realCopy,
		AddedAt:     time.Now(),
	})
	return nil
}
```

Add `"bytes"` to the existing import block in `table.go`:

```go
import (
	"bytes"
	"sync"
	"time"
)
```

- [ ] **Step 4: Run all tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -v`
Expected: PASS for all `TestAdd_*` tests including the collision and caller-mutation tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): Add collision detection and slice ownership"
```

---

## Task 5: FakeForService lookup

**Files:**
- Modify: `internal/proxy/credsub/table.go` (add `FakeForService`)
- Modify: `internal/proxy/credsub/table_test.go` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/credsub/table_test.go`:

```go
func TestFakeForService_Found(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	got, ok := tb.FakeForService("github")
	if !ok {
		t.Fatal("FakeForService returned ok=false for registered service")
	}
	if !bytes.Equal(got, []byte("ghp_fake00000000")) {
		t.Errorf("FakeForService = %q, want %q", got, "ghp_fake00000000")
	}
}

func TestFakeForService_NotFound(t *testing.T) {
	tb := New()
	got, ok := tb.FakeForService("nope")
	if ok {
		t.Errorf("FakeForService returned ok=true for unknown service, got %q", got)
	}
	if got != nil {
		t.Errorf("FakeForService returned %v, want nil for unknown service", got)
	}
}

func TestFakeForService_ReturnsCopy(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	got, _ := tb.FakeForService("github")
	// Mutate the returned slice; the Table's copy must not change.
	for i := range got {
		got[i] = 0
	}
	again, _ := tb.FakeForService("github")
	if !bytes.Equal(again, []byte("ghp_fake00000000")) {
		t.Errorf("second lookup = %q, want %q (Table leaked internal slice)", again, "ghp_fake00000000")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestFakeForService_' -v`
Expected: FAIL with `undefined: (*Table).FakeForService`.

- [ ] **Step 3: Implement `FakeForService`**

Append to `internal/proxy/credsub/table.go`:

```go
// FakeForService returns the fake byte sequence registered for a
// service. The returned slice is a copy; the caller may retain or
// mutate it without affecting the Table. Returns (nil, false) if no
// entry is registered for the given service name.
func (t *Table) FakeForService(serviceName string) ([]byte, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, e := range t.entries {
		if e.ServiceName == serviceName {
			out := make([]byte, len(e.Fake))
			copy(out, e.Fake)
			return out, true
		}
	}
	return nil, false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -run 'TestFakeForService_' -v`
Expected: PASS for all three tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): FakeForService lookup"
```

---

## Task 6: Contains lookup

**Files:**
- Modify: `internal/proxy/credsub/table.go` (add `Contains`)
- Modify: `internal/proxy/credsub/table_test.go` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/credsub/table_test.go`:

```go
func TestContains_Found(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	entry, ok := tb.Contains([]byte("ghp_fake00000000"))
	if !ok {
		t.Fatal("Contains returned ok=false for registered fake")
	}
	if entry.ServiceName != "github" {
		t.Errorf("Contains returned ServiceName=%q, want %q", entry.ServiceName, "github")
	}
}

func TestContains_NotFound(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	_, ok := tb.Contains([]byte("ghp_something000"))
	if ok {
		t.Error("Contains returned ok=true for unknown fake")
	}
}

func TestContains_ExactMatchOnly(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	// Substring of a registered fake — Contains is exact match,
	// so this must NOT match.
	_, ok := tb.Contains([]byte("fake0000"))
	if ok {
		t.Error("Contains returned ok=true for substring lookup; must be exact match")
	}
}

func TestContains_EmptyInput(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	_, ok := tb.Contains(nil)
	if ok {
		t.Error("Contains(nil) returned ok=true")
	}
	_, ok = tb.Contains([]byte{})
	if ok {
		t.Error("Contains(empty) returned ok=true")
	}
}

func TestContains_ReturnsCopy(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	entry, ok := tb.Contains([]byte("ghp_fake00000000"))
	if !ok {
		t.Fatal("Contains returned ok=false for registered fake")
	}
	// Mutate the returned entry's byte slices; the Table's copies
	// must not change.
	for i := range entry.Fake {
		entry.Fake[i] = 0
	}
	for i := range entry.Real {
		entry.Real[i] = 0
	}
	again, _ := tb.Contains([]byte("ghp_fake00000000"))
	if !bytes.Equal(again.Fake, []byte("ghp_fake00000000")) {
		t.Errorf("second lookup Fake = %q, want %q (Contains leaked internal slice)", again.Fake, "ghp_fake00000000")
	}
	if !bytes.Equal(again.Real, []byte("ghp_real00000000")) {
		t.Errorf("second lookup Real = %q, want %q (Contains leaked internal slice)", again.Real, "ghp_real00000000")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestContains_' -v`
Expected: FAIL with `undefined: (*Table).Contains`.

- [ ] **Step 3: Implement `Contains`**

Append to `internal/proxy/credsub/table.go`:

```go
// Contains reports whether a byte sequence is a registered fake in
// the table. It performs an EXACT match (not a substring search). If
// found, it returns a deep-copied Entry (Fake and Real are fresh
// slices the caller may freely retain or mutate) and true; otherwise
// it returns a zero Entry and false.
func (t *Table) Contains(fake []byte) (Entry, bool) {
	if len(fake) == 0 {
		return Entry{}, false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, e := range t.entries {
		if bytes.Equal(e.Fake, fake) {
			fakeCopy := make([]byte, len(e.Fake))
			copy(fakeCopy, e.Fake)
			realCopy := make([]byte, len(e.Real))
			copy(realCopy, e.Real)
			return Entry{
				ServiceName: e.ServiceName,
				Fake:        fakeCopy,
				Real:        realCopy,
				AddedAt:     e.AddedAt,
			}, true
		}
	}
	return Entry{}, false
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -run 'TestContains_' -v`
Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): Contains exact-match lookup"
```

---

## Task 7: ReplaceFakeToReal substitution

**Files:**
- Modify: `internal/proxy/credsub/table.go` (add `ReplaceFakeToReal`)
- Modify: `internal/proxy/credsub/table_test.go` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/credsub/table_test.go`:

```go
func TestReplaceFakeToReal_SingleEntryMatches(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	body := []byte(`{"token":"ghp_fake00000000"}`)
	got := tb.ReplaceFakeToReal(body)
	want := []byte(`{"token":"ghp_real00000000"}`)
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceFakeToReal = %q, want %q", got, want)
	}
}

func TestReplaceFakeToReal_MultipleEntries(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add github failed: %v", err)
	}
	if err := tb.Add("stripe", []byte("sk_fake000000000"), []byte("sk_real000000000")); err != nil {
		t.Fatalf("Add stripe failed: %v", err)
	}
	body := []byte(`gh=ghp_fake00000000 stripe=sk_fake000000000`)
	got := tb.ReplaceFakeToReal(body)
	want := []byte(`gh=ghp_real00000000 stripe=sk_real000000000`)
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceFakeToReal = %q, want %q", got, want)
	}
}

func TestReplaceFakeToReal_MultipleOccurrencesOfSameFake(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	body := []byte(`a=ghp_fake00000000 b=ghp_fake00000000`)
	got := tb.ReplaceFakeToReal(body)
	want := []byte(`a=ghp_real00000000 b=ghp_real00000000`)
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceFakeToReal = %q, want %q", got, want)
	}
}

func TestReplaceFakeToReal_NoMatch(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	body := []byte(`nothing to substitute here`)
	got := tb.ReplaceFakeToReal(body)
	if !bytes.Equal(got, body) {
		t.Errorf("ReplaceFakeToReal with no match = %q, want %q (unchanged)", got, body)
	}
}

func TestReplaceFakeToReal_EmptyBody(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	got := tb.ReplaceFakeToReal(nil)
	if len(got) != 0 {
		t.Errorf("ReplaceFakeToReal(nil) = %q, want empty", got)
	}
	got = tb.ReplaceFakeToReal([]byte{})
	if len(got) != 0 {
		t.Errorf("ReplaceFakeToReal(empty) = %q, want empty", got)
	}
}

func TestReplaceFakeToReal_EmptyTable(t *testing.T) {
	tb := New()
	body := []byte(`ghp_fake00000000`)
	got := tb.ReplaceFakeToReal(body)
	if !bytes.Equal(got, body) {
		t.Errorf("ReplaceFakeToReal on empty table = %q, want %q (unchanged)", got, body)
	}
}

func TestReplaceFakeToReal_PreservesLength(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	body := []byte(`{"a":"ghp_fake00000000","b":"x"}`)
	got := tb.ReplaceFakeToReal(body)
	if len(got) != len(body) {
		t.Errorf("ReplaceFakeToReal changed body length: got %d want %d", len(got), len(body))
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestReplaceFakeToReal_' -v`
Expected: FAIL with `undefined: (*Table).ReplaceFakeToReal`.

- [ ] **Step 3: Implement `ReplaceFakeToReal`**

Append to `internal/proxy/credsub/table.go`:

```go
// ReplaceFakeToReal returns a copy of body with every occurrence of
// every registered fake replaced by its matching real. If body
// contains no registered fake, the original slice is returned
// unchanged (the result may alias body in that case); otherwise a
// freshly allocated slice is returned. Callers must treat the result
// as authoritative and not assume aliasing either way.
//
// The scan walks the ORIGINAL body once, checking at each position
// whether any entry's fake starts there, and emitting the matching
// real if so. This is critical: applying entry replacements
// sequentially with bytes.ReplaceAll on the evolving output would
// cascade — bytes produced by an earlier replacement could match a
// later entry's fake even though those bytes were not in the original
// body. The single-pass scan over the original body prevents this.
//
// When two entries' fakes both match at the same position (one is a
// prefix of the other), the longer match wins. Add does not prevent
// such substring overlaps, so this rule makes the output independent
// of registration order.
//
// Length-preservation: because Add enforces len(fake) == len(real),
// the output length always equals len(body).
//
// Complexity: O(N · |body|) where N is the number of entries.
func (t *Table) ReplaceFakeToReal(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.entries) == 0 {
		return body
	}

	var out []byte
	i := 0
	for i < len(body) {
		// Find the longest fake that matches at position i.
		bestLen := 0
		var bestReal []byte
		for j := range t.entries {
			e := &t.entries[j]
			n := len(e.Fake)
			if n <= bestLen {
				continue
			}
			if i+n > len(body) {
				continue
			}
			if bytes.Equal(body[i:i+n], e.Fake) {
				bestLen = n
				bestReal = e.Real
			}
		}

		if bestLen > 0 {
			if out == nil {
				out = make([]byte, 0, len(body))
				out = append(out, body[:i]...)
			}
			out = append(out, bestReal...)
			i += bestLen
			continue
		}

		if out != nil {
			out = append(out, body[i])
		}
		i++
	}

	if out == nil {
		return body
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -run 'TestReplaceFakeToReal_' -v`
Expected: PASS for all ten tests (the seven from Step 1 plus three regression tests added later in the cascading-rewrite fix).

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): ReplaceFakeToReal substitution"
```

---

## Task 8: ReplaceRealToFake substitution

**Files:**
- Modify: `internal/proxy/credsub/table.go` (add `ReplaceRealToFake`)
- Modify: `internal/proxy/credsub/table_test.go` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/credsub/table_test.go`:

```go
func TestReplaceRealToFake_SingleEntryMatches(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	body := []byte(`{"echo":"ghp_real00000000"}`)
	got := tb.ReplaceRealToFake(body)
	want := []byte(`{"echo":"ghp_fake00000000"}`)
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceRealToFake = %q, want %q", got, want)
	}
}

func TestReplaceRealToFake_MultipleEntries(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add github failed: %v", err)
	}
	if err := tb.Add("stripe", []byte("sk_fake000000000"), []byte("sk_real000000000")); err != nil {
		t.Fatalf("Add stripe failed: %v", err)
	}
	body := []byte(`gh=ghp_real00000000 stripe=sk_real000000000`)
	got := tb.ReplaceRealToFake(body)
	want := []byte(`gh=ghp_fake00000000 stripe=sk_fake000000000`)
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceRealToFake = %q, want %q", got, want)
	}
}

func TestReplaceRealToFake_NoMatch(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	body := []byte(`nothing here to substitute`)
	got := tb.ReplaceRealToFake(body)
	if !bytes.Equal(got, body) {
		t.Errorf("ReplaceRealToFake with no match = %q, want %q", got, body)
	}
}

func TestReplaceRealToFake_EmptyBody(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	got := tb.ReplaceRealToFake(nil)
	if len(got) != 0 {
		t.Errorf("ReplaceRealToFake(nil) = %q, want empty", got)
	}
}

func TestReplaceRealToFake_EmptyTable(t *testing.T) {
	tb := New()
	body := []byte(`ghp_real00000000`)
	got := tb.ReplaceRealToFake(body)
	if !bytes.Equal(got, body) {
		t.Errorf("ReplaceRealToFake on empty table = %q, want %q", got, body)
	}
}

func TestReplaceRealToFake_RoundTrip(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	original := []byte(`agent sees ghp_fake00000000 here`)
	// Agent → upstream: fake → real.
	upstream := tb.ReplaceFakeToReal(original)
	// Upstream echoes it back → agent: real → fake.
	backToAgent := tb.ReplaceRealToFake(upstream)
	if !bytes.Equal(backToAgent, original) {
		t.Errorf("round trip: got %q, want %q", backToAgent, original)
	}
}

// TestReplaceRealToFake_NoCascadingRewrite asserts the same
// single-pass-scan property as the matching ReplaceFakeToReal test:
// with two entries fake1=B,real1=A and fake2=DE,real2=BC, the input
// "AC" must NOT become "fake2 cascade", because the original body
// never contained the real "BC".
func TestReplaceRealToFake_NoCascadingRewrite(t *testing.T) {
	tb := New()
	if err := tb.Add("a", []byte("B"), []byte("A")); err != nil {
		t.Fatalf("Add a failed: %v", err)
	}
	if err := tb.Add("bc", []byte("DE"), []byte("BC")); err != nil {
		t.Fatalf("Add bc failed: %v", err)
	}
	body := []byte("AC")
	got := tb.ReplaceRealToFake(body)
	want := []byte("BC")
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceRealToFake cascading rewrite: got %q, want %q", got, want)
	}
}

// TestReplaceRealToFake_LeftmostLongestMatch asserts that when two
// reals both match at the same position (one is a prefix of the
// other), the longer match wins. This makes the result independent
// of registration order.
func TestReplaceRealToFake_LeftmostLongestMatch(t *testing.T) {
	tb := New()
	if err := tb.Add("short", []byte("XY"), []byte("AB")); err != nil {
		t.Fatalf("Add short failed: %v", err)
	}
	if err := tb.Add("long", []byte("WXYZ"), []byte("ABCD")); err != nil {
		t.Fatalf("Add long failed: %v", err)
	}
	body := []byte("ABCD")
	got := tb.ReplaceRealToFake(body)
	want := []byte("WXYZ")
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceRealToFake leftmost-longest: got %q, want %q", got, want)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestReplaceRealToFake_' -v`
Expected: FAIL with `undefined: (*Table).ReplaceRealToFake`.

- [ ] **Step 3: Implement `ReplaceRealToFake`**

Append to `internal/proxy/credsub/table.go`:

```go
// ReplaceRealToFake returns a copy of body with every occurrence of
// every registered real replaced by its matching fake. This is used
// by the egress flow when a service has scrub_response: true and the
// proxy needs to rewrite a response body before returning it to the
// agent, ensuring the agent never sees the real credential even if
// the upstream echoed it back.
//
// As with ReplaceFakeToReal, the scan walks the ORIGINAL body once
// and uses leftmost-longest matching to avoid cascading rewrites and
// to make the result independent of registration order. See the
// ReplaceFakeToReal doc comment for the reasoning.
//
// If body contains no registered real, the original slice is
// returned unchanged (the result may alias body in that case);
// otherwise a freshly allocated slice is returned. Callers must
// treat the result as authoritative and not assume aliasing either
// way.
//
// Length-preservation: because Add enforces len(fake) == len(real),
// the output length always equals len(body).
//
// Complexity: O(N · |body|) where N is the number of entries.
func (t *Table) ReplaceRealToFake(body []byte) []byte {
	if len(body) == 0 {
		return body
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if len(t.entries) == 0 {
		return body
	}

	var out []byte
	i := 0
	for i < len(body) {
		// Find the longest real that matches at position i.
		bestLen := 0
		var bestFake []byte
		for j := range t.entries {
			e := &t.entries[j]
			n := len(e.Real)
			if n <= bestLen {
				continue
			}
			if i+n > len(body) {
				continue
			}
			if bytes.Equal(body[i:i+n], e.Real) {
				bestLen = n
				bestFake = e.Fake
			}
		}

		if bestLen > 0 {
			if out == nil {
				out = make([]byte, 0, len(body))
				out = append(out, body[:i]...)
			}
			out = append(out, bestFake...)
			i += bestLen
			continue
		}

		if out != nil {
			out = append(out, body[i])
		}
		i++
	}

	if out == nil {
		return body
	}
	return out
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -run 'TestReplaceRealToFake_' -v`
Expected: PASS for all eight tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): ReplaceRealToFake substitution"
```

---

## Task 9: Zero buffer wipe

**Files:**
- Modify: `internal/proxy/credsub/table.go` (add `Zero`)
- Modify: `internal/proxy/credsub/table_test.go` (add tests)

- [ ] **Step 1: Write the failing tests**

Append to `internal/proxy/credsub/table_test.go`:

```go
func TestZero_EmptiesTable(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	if err := tb.Add("stripe", []byte("sk_fake000000000"), []byte("sk_real000000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	tb.Zero()
	if got := tb.Len(); got != 0 {
		t.Errorf("Len() after Zero = %d, want 0", got)
	}
	if _, ok := tb.FakeForService("github"); ok {
		t.Error("FakeForService returned ok=true after Zero")
	}
}

func TestZero_WipesByteBuffers(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}

	// Capture the internal byte slices before Zero so we can verify
	// they were actually wiped (not just dropped).
	tb.mu.RLock()
	fakeBuf := tb.entries[0].Fake
	realBuf := tb.entries[0].Real
	tb.mu.RUnlock()

	tb.Zero()

	for i, b := range fakeBuf {
		if b != 0 {
			t.Errorf("fakeBuf[%d] = 0x%x after Zero, want 0x00", i, b)
		}
	}
	for i, b := range realBuf {
		if b != 0 {
			t.Errorf("realBuf[%d] = 0x%x after Zero, want 0x00", i, b)
		}
	}
}

func TestZero_IdempotentOnEmptyTable(t *testing.T) {
	tb := New()
	tb.Zero() // Must not panic.
	tb.Zero() // Still must not panic.
	if got := tb.Len(); got != 0 {
		t.Errorf("Len() after double Zero = %d, want 0", got)
	}
}

func TestZero_AllowsReuse(t *testing.T) {
	tb := New()
	if err := tb.Add("github", []byte("ghp_fake00000000"), []byte("ghp_real00000000")); err != nil {
		t.Fatalf("Add failed: %v", err)
	}
	tb.Zero()
	// Table should be usable again after Zero.
	if err := tb.Add("stripe", []byte("sk_fake000000000"), []byte("sk_real000000000")); err != nil {
		t.Fatalf("Add after Zero failed: %v", err)
	}
	got, ok := tb.FakeForService("stripe")
	if !ok || !bytes.Equal(got, []byte("sk_fake000000000")) {
		t.Errorf("FakeForService after reuse = (%q, %v), want (%q, true)", got, ok, "sk_fake000000000")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/proxy/credsub/ -run 'TestZero_' -v`
Expected: FAIL with `undefined: (*Table).Zero`.

- [ ] **Step 3: Implement `Zero`**

Append to `internal/proxy/credsub/table.go`:

```go
// Zero wipes every Fake and Real byte buffer owned by the table
// (overwriting them with 0x00) and drops all entries. It is intended
// to be called on session close so credential material does not linger
// in process memory after the session ends.
//
// Zero is safe to call multiple times and on an empty table. After
// Zero returns, the Table is empty and may be reused (though in
// practice Tables are one-per-session and discarded after Zero).
func (t *Table) Zero() {
	t.mu.Lock()
	defer t.mu.Unlock()

	for i := range t.entries {
		for j := range t.entries[i].Fake {
			t.entries[i].Fake[j] = 0
		}
		for j := range t.entries[i].Real {
			t.entries[i].Real[j] = 0
		}
	}
	t.entries = nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/proxy/credsub/ -run 'TestZero_' -v`
Expected: PASS for all four tests.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table.go internal/proxy/credsub/table_test.go
git commit -m "feat(credsub): Zero wipes buffers and empties table"
```

---

## Task 10: Concurrent access race test

**Files:**
- Modify: `internal/proxy/credsub/table_test.go` (add race test)

- [ ] **Step 1: Write the race-condition test**

Append to `internal/proxy/credsub/table_test.go` (function only; the import block update is in the note at the end of this step):

```go
func TestConcurrentAccess_NoRaces(t *testing.T) {
	// This test is primarily for `go test -race` to detect data
	// races. It exercises Add, FakeForService, Contains,
	// ReplaceFakeToReal, ReplaceRealToFake, and Zero concurrently.
	tb := New()

	// Pre-seed a few entries so readers always have something to
	// find.
	seed := []struct {
		name, fake, real string
	}{
		{"svc-a", "fakeAAAAAAAAAAAA", "realAAAAAAAAAAAA"},
		{"svc-b", "fakeBBBBBBBBBBBB", "realBBBBBBBBBBBB"},
		{"svc-c", "fakeCCCCCCCCCCCC", "realCCCCCCCCCCCC"},
	}
	for _, s := range seed {
		if err := tb.Add(s.name, []byte(s.fake), []byte(s.real)); err != nil {
			t.Fatalf("seed Add(%s) failed: %v", s.name, err)
		}
	}

	const readers = 8
	const iterations = 200
	var wg sync.WaitGroup

	// Readers.
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			body := []byte("request fakeAAAAAAAAAAAA fakeBBBBBBBBBBBB end")
			for j := 0; j < iterations; j++ {
				_ = tb.FakeForService("svc-a")
				_, _ = tb.Contains([]byte("fakeAAAAAAAAAAAA"))
				_ = tb.ReplaceFakeToReal(body)
				_ = tb.ReplaceRealToFake(body)
				_ = tb.Len()
			}
		}()
	}

	// One writer adding and removing entries.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < iterations; j++ {
			name := "transient"
			// Add may fail if we just added and haven't zeroed — ignore.
			_ = tb.Add(name,
				[]byte("fakeTTTTTTTTTTTT"),
				[]byte("realTTTTTTTTTTTT"),
			)
			// Zero entire table occasionally to exercise the write
			// path alongside readers.
			if j%50 == 0 {
				tb.Zero()
				// Re-seed after Zero so readers keep finding stuff.
				for _, s := range seed {
					_ = tb.Add(s.name, []byte(s.fake), []byte(s.real))
				}
			}
		}
	}()

	wg.Wait()
}
```

Update the import block at the top of `table_test.go` to include `"sync"`:

```go
import (
	"bytes"
	"errors"
	"sync"
	"testing"
)
```

- [ ] **Step 2: Run the race-enabled test**

Run: `go test ./internal/proxy/credsub/ -run TestConcurrentAccess_NoRaces -race -v`
Expected: PASS with no data race reports. (If a race is reported, the implementation has a bug in how it holds the mutex — review before proceeding.)

- [ ] **Step 3: Run the full package test suite with race detector**

Run: `go test ./internal/proxy/credsub/ -race -v`
Expected: ALL tests PASS with no race reports.

- [ ] **Step 4: Run the full package test suite without race detector (sanity)**

Run: `go test ./internal/proxy/credsub/ -v`
Expected: ALL tests PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/proxy/credsub/table_test.go
git commit -m "test(credsub): add concurrent-access race test"
```

---

## Task 11: Verify cross-compilation and full project build

**Files:** none modified.

- [ ] **Step 1: Verify the whole project still builds**

Run: `go build ./...`
Expected: no output, exit 0.

- [ ] **Step 2: Verify Windows cross-compile still works**

Run: `GOOS=windows go build ./...`
Expected: no output, exit 0. (The credsub package uses only `bytes`, `sync`, and `time` — all pure Go — so Windows compile should be identical to Linux.)

- [ ] **Step 3: Verify Darwin cross-compile still works**

Run: `GOOS=darwin go build ./...`
Expected: no output, exit 0.

- [ ] **Step 4: Run the full project test suite**

Run: `go test ./...`
Expected: no failures (credsub tests pass, and no other package is affected by this plan since it adds an isolated new package).

- [ ] **Step 5: If all checks pass, mark the plan complete**

No commit needed — this is a verification-only task. The working tree should be clean after Task 10's commit.

---

## Post-plan verification checklist

After all tasks complete, confirm the package satisfies the Section 4 spec:

- [ ] `credsub.Table` has `New`, `Add`, `FakeForService`, `Contains`, `ReplaceFakeToReal`, `ReplaceRealToFake`, `Zero`.
- [ ] `Entry` has `ServiceName`, `Fake`, `Real`, `AddedAt`.
- [ ] Length preservation enforced at `Add` → `ErrLengthMismatch`.
- [ ] Collision detection at `Add` → `ErrFakeCollision` for: fake==real same call, duplicate fake, duplicate real, fake==existing real, real==existing fake.
- [ ] Service name uniqueness enforced → `ErrServiceExists`.
- [ ] `Add` copies input slices (caller mutation test passes).
- [ ] `Zero` wipes byte buffers (verified via retained slice reference).
- [ ] All methods are safe for concurrent use (race test passes with `-race`).
- [ ] Package is pure stdlib — no new dependencies in `go.mod`.
- [ ] Zero call sites inside `internal/` (this is isolated infrastructure for later plans).

## Deferred to later plans

- **Substring match / leak-attempt detection** (Section 6 step 8): will need a `FindFakes(body) []Entry` method or similar. Plan 10 (session wiring + egress flow) should add it if required.
- **Aho-Corasick optimization**: only if profiling after Plan 10 shows substitution is hot and N is large enough to matter.
- **Fake generation** (random base62, length matching, collision retry from spec Section 4 "Collision handling"): lives in the session-start flow (Plan 10), not in `credsub` package — the Table is a pure data structure; it does not generate fakes.
- **Provider integration**: Plan 3 adds `SecretProvider` interface and first concrete provider.
