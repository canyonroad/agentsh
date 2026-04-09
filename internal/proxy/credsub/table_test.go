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
