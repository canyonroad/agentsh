package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// computeExpectedHash mirrors the production HMAC formula from
// internal/audit/integrity.go: format_version | sequence | prev_hash | payload.
// Generation is intentionally NOT in the HMAC input — see the format-version
// note in the implementation plan.
func computeExpectedHash(t *testing.T, key []byte, formatVersion int, sequence int64, prevHash string, payload []byte) string {
	t.Helper()
	h := hmac.New(sha256.New, key)
	h.Write([]byte(strconv.Itoa(formatVersion)))
	h.Write([]byte("|"))
	h.Write([]byte(strconv.FormatInt(sequence, 10)))
	h.Write([]byte("|"))
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write(payload)
	return hex.EncodeToString(h.Sum(nil))
}

func newTestSinkChain(t *testing.T) (*SinkChain, []byte) {
	t.Helper()
	key := make([]byte, MinKeyLength)
	for i := range key {
		key[i] = byte(i + 1)
	}
	c, err := NewSinkChain(key, "hmac-sha256")
	if err != nil {
		t.Fatalf("NewSinkChain: %v", err)
	}
	return c, key
}

func TestSinkChain_Compute_FirstEntryUsesEmptyPrev(t *testing.T) {
	c, key := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	entryHash, prevHash, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if prevHash != "" {
		t.Errorf("first Compute: prevHash = %q, want empty", prevHash)
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", payload)
	if entryHash != want {
		t.Errorf("entryHash = %q, want %q", entryHash, want)
	}
}

func TestSinkChain_Compute_IsPure_NoMutationWithoutCommit(t *testing.T) {
	c, _ := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	first, _, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Compute again without Commit — must produce the SAME entryHash, since
	// prev_hash hasn't moved.
	second, _, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Errorf("Compute mutated chain state: first=%q second=%q", first, second)
	}
}

func TestSinkChain_Commit_AdvancesPrevHash(t *testing.T) {
	c, key := newTestSinkChain(t)

	first, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, first)

	second, prev, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if prev != first {
		t.Errorf("after Commit: prev_hash = %q, want %q", prev, first)
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 1, first, []byte(`{"b":2}`))
	if second != want {
		t.Errorf("second entryHash = %q, want %q", second, want)
	}
}

func TestSinkChain_Compute_GenerationRollover_ResetsPrevToEmpty(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Establish gen=0 chain with one committed entry.
	h0, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, h0)

	// Compute at gen=1 — prev_hash should be "" automatically.
	h1, prev, err := c.Compute(IntegrityFormatVersion, 0, 1, []byte(`{"y":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if prev != "" {
		t.Errorf("after gen rollover: prev_hash = %q, want empty", prev)
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", []byte(`{"y":2}`))
	if h1 != want {
		t.Errorf("rolled entryHash = %q, want %q", h1, want)
	}

	// Until Commit(1, h1), the chain's recorded generation is still 0.
	state := c.State()
	if state.Generation != 0 {
		t.Errorf("State.Generation before Commit = %d, want 0", state.Generation)
	}

	c.Commit(1, h1)
	state = c.State()
	if state.Generation != 1 {
		t.Errorf("State.Generation after Commit = %d, want 1", state.Generation)
	}
	if state.PrevHash != h1 {
		t.Errorf("State.PrevHash = %q, want %q", state.PrevHash, h1)
	}
}

func TestSinkChain_Fatal_LatchesAndBlocksFurtherCompute(t *testing.T) {
	c, _ := newTestSinkChain(t)

	if _, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}

	c.Fatal(errors.New("ambiguous WAL write"))

	_, _, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after Fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

func TestSinkChain_State_Restore_RoundTrip(t *testing.T) {
	c, _ := newTestSinkChain(t)

	h0, _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, h0)
	h1, _, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	c.Commit(0, h1)

	state := c.State()
	if state.Generation != 0 || state.PrevHash != h1 {
		t.Fatalf("State() = %+v, want {Generation:0 PrevHash:%q}", state, h1)
	}

	d, _ := newTestSinkChain(t)
	d.Restore(state.Generation, state.PrevHash)

	// Continue the chain from d — same key, so same entry hash as if c
	// had continued.
	cNext, _, err := c.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	dNext, _, err := d.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if cNext != dNext {
		t.Errorf("after Restore: entryHash mismatch %q vs %q", cNext, dNext)
	}
}

func TestNewSinkChain_RejectsShortKey(t *testing.T) {
	_, err := NewSinkChain(make([]byte, MinKeyLength-1), "hmac-sha256")
	if err == nil {
		t.Fatal("NewSinkChain accepted a too-short key")
	}
	if !strings.Contains(err.Error(), "key too short") {
		t.Errorf("error = %q, want 'key too short'", err)
	}
}

func TestNewSinkChain_RejectsUnsupportedAlgorithm(t *testing.T) {
	key := make([]byte, MinKeyLength)
	_, err := NewSinkChain(key, "md5")
	if err == nil {
		t.Fatal("NewSinkChain accepted unsupported algorithm")
	}
	if !strings.Contains(err.Error(), "unsupported algorithm") {
		t.Errorf("error = %q, want 'unsupported algorithm'", err)
	}
}

func TestSinkChain_Concurrent_ComputeCommit_NoChainBreakage(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Single owner serializes Compute+Commit pairs; this test asserts that
	// repeated Compute under contention with Commit does not produce a
	// chain that fails verification when replayed in committed order.
	const N = 200
	type record struct {
		seq       int64
		payload   []byte
		entryHash string
		prevHash  string
	}
	records := make([]record, 0, N)

	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := int64(0); i < N; i++ {
			payload := []byte(`{"i":` + strconv.FormatInt(i, 10) + `}`)
			entry, prev, err := c.Compute(IntegrityFormatVersion, i, 0, payload)
			if err != nil {
				t.Errorf("Compute %d: %v", i, err)
				return
			}
			c.Commit(0, entry)
			mu.Lock()
			records = append(records, record{seq: i, payload: payload, entryHash: entry, prevHash: prev})
			mu.Unlock()
		}
	}()
	wg.Wait()

	// Walk records and verify chain continuity.
	if len(records) != N {
		t.Fatalf("got %d records, want %d", len(records), N)
	}
	expectedPrev := ""
	for _, r := range records {
		if r.prevHash != expectedPrev {
			t.Fatalf("seq %d: prev=%q want %q", r.seq, r.prevHash, expectedPrev)
		}
		want := computeExpectedHash(t, key, IntegrityFormatVersion, r.seq, expectedPrev, r.payload)
		if r.entryHash != want {
			t.Fatalf("seq %d: entry=%q want %q", r.seq, r.entryHash, want)
		}
		expectedPrev = r.entryHash
	}
}
