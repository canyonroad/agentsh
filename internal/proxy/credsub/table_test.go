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

// TestReplaceFakeToReal_NoCascadingRewrite asserts the bug fixed in
// the single-pass scan: with two entries A->B and BC->DE, the input
// "AC" must NOT become "DE". A naive sequential bytes.ReplaceAll
// would first turn "AC" into "BC" (entry 1), then turn that "BC"
// into "DE" (entry 2), even though the original body never contained
// the fake "BC" at all.
func TestReplaceFakeToReal_NoCascadingRewrite(t *testing.T) {
	tb := New()
	if err := tb.Add("a", []byte("A"), []byte("B")); err != nil {
		t.Fatalf("Add a failed: %v", err)
	}
	if err := tb.Add("bc", []byte("BC"), []byte("DE")); err != nil {
		t.Fatalf("Add bc failed: %v", err)
	}
	body := []byte("AC")
	got := tb.ReplaceFakeToReal(body)
	want := []byte("BC")
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceFakeToReal cascading rewrite: got %q, want %q", got, want)
	}
}

// TestReplaceFakeToReal_LeftmostLongestMatch asserts that when two
// fakes both match at the same position (one is a prefix of the
// other), the longer match wins. This makes the result independent
// of registration order.
func TestReplaceFakeToReal_LeftmostLongestMatch(t *testing.T) {
	tb := New()
	if err := tb.Add("short", []byte("AB"), []byte("XY")); err != nil {
		t.Fatalf("Add short failed: %v", err)
	}
	if err := tb.Add("long", []byte("ABCD"), []byte("WXYZ")); err != nil {
		t.Fatalf("Add long failed: %v", err)
	}
	body := []byte("ABCD")
	got := tb.ReplaceFakeToReal(body)
	want := []byte("WXYZ")
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceFakeToReal leftmost-longest: got %q, want %q", got, want)
	}
}

// TestReplaceFakeToReal_LeftmostLongestRegOrderInvariant repeats the
// previous test with the registrations swapped to prove the result
// does not depend on insertion order.
func TestReplaceFakeToReal_LeftmostLongestRegOrderInvariant(t *testing.T) {
	tb := New()
	if err := tb.Add("long", []byte("ABCD"), []byte("WXYZ")); err != nil {
		t.Fatalf("Add long failed: %v", err)
	}
	if err := tb.Add("short", []byte("AB"), []byte("XY")); err != nil {
		t.Fatalf("Add short failed: %v", err)
	}
	body := []byte("ABCD")
	got := tb.ReplaceFakeToReal(body)
	want := []byte("WXYZ")
	if !bytes.Equal(got, want) {
		t.Errorf("ReplaceFakeToReal order invariance: got %q, want %q", got, want)
	}
}

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
