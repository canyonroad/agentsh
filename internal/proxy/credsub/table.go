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

// RealForService returns the real byte sequence registered for a
// service. The returned slice is a deep copy; the caller may retain
// or mutate it. Callers should zero the returned slice when done to
// avoid leaving credential material in memory.
//
// This method is intended for internal proxy use only (e.g. header
// injection). Returns (nil, false) if no entry is registered.
func (t *Table) RealForService(serviceName string) ([]byte, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, e := range t.entries {
		if e.ServiceName == serviceName {
			out := make([]byte, len(e.Real))
			copy(out, e.Real)
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

// ContainsFake scans data for any registered fake as a substring.
// Unlike Contains (which requires an exact match), ContainsFake
// uses bytes.Contains to detect fakes embedded in larger payloads
// such as JSON request bodies.
//
// Returns the service name of the first matching entry and true if a
// fake is found; returns "" and false otherwise. When multiple entries
// match, the first one registered wins.
//
// Only the service name is returned so that callers never receive a
// copy of the Real credential bytes, which Zero() would be unable to
// wipe.
func (t *Table) ContainsFake(data []byte) (string, bool) {
	if len(data) == 0 {
		return "", false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	for _, e := range t.entries {
		if bytes.Contains(data, e.Fake) {
			return e.ServiceName, true
		}
	}
	return "", false
}

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
