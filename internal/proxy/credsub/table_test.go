package credsub

import (
	"bytes"
	"errors"
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
