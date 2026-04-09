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
