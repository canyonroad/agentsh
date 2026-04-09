package credsub

import (
	"bytes"
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

// ReplaceFakeToReal returns a copy of body with every occurrence of
// every registered fake replaced by its matching real. The returned
// slice may or may not alias body; callers must treat it as the
// authoritative result.
//
// Substitution is done per-entry using bytes.ReplaceAll. Order of
// entries is not semantically meaningful because Add enforces that no
// entry's fake or real can exactly equal any other entry's fake or
// real, so no double-substitution can occur across entries.
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

	result := body
	for _, e := range t.entries {
		result = bytes.ReplaceAll(result, e.Fake, e.Real)
	}
	return result
}
