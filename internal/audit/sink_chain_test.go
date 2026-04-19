package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
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

	result, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatalf("Compute: %v", err)
	}
	if result.PrevHash() != "" {
		t.Errorf("first Compute: prevHash = %q, want empty", result.PrevHash())
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", payload)
	if result.EntryHash() != want {
		t.Errorf("entryHash = %q, want %q", result.EntryHash(), want)
	}
}

func TestSinkChain_Compute_IsPure_NoMutationWithoutCommit(t *testing.T) {
	c, _ := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	first, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}

	// Compute again without Commit — must produce the SAME entryHash, since
	// prev_hash hasn't moved.
	second, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
	if err != nil {
		t.Fatal(err)
	}
	if first.EntryHash() != second.EntryHash() {
		t.Errorf("Compute mutated chain state: first=%q second=%q", first.EntryHash(), second.EntryHash())
	}
}

func TestSinkChain_Commit_AdvancesPrevHash(t *testing.T) {
	c, key := newTestSinkChain(t)

	first, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(first); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	second, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if second.PrevHash() != first.EntryHash() {
		t.Errorf("after Commit: prev_hash = %q, want %q", second.PrevHash(), first.EntryHash())
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 1, first.EntryHash(), []byte(`{"b":2}`))
	if second.EntryHash() != want {
		t.Errorf("second entryHash = %q, want %q", second.EntryHash(), want)
	}
}

func TestSinkChain_Compute_GenerationRollover_ResetsPrevToEmpty(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Establish gen=0 chain with one committed entry.
	r0, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r0); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	// Compute at gen=1 — prev_hash should be "" automatically.
	r1, err := c.Compute(IntegrityFormatVersion, 0, 1, []byte(`{"y":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if r1.PrevHash() != "" {
		t.Errorf("after gen rollover: prev_hash = %q, want empty", r1.PrevHash())
	}
	want := computeExpectedHash(t, key, IntegrityFormatVersion, 0, "", []byte(`{"y":2}`))
	if r1.EntryHash() != want {
		t.Errorf("rolled entryHash = %q, want %q", r1.EntryHash(), want)
	}

	// Until Commit(r1), the chain's recorded generation is still 0.
	state := c.State()
	if state.Generation != 0 {
		t.Errorf("State.Generation before Commit = %d, want 0", state.Generation)
	}

	if err := c.Commit(r1); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state = c.State()
	if state.Generation != 1 {
		t.Errorf("State.Generation after Commit = %d, want 1", state.Generation)
	}
	if state.PrevHash != r1.EntryHash() {
		t.Errorf("State.PrevHash = %q, want %q", state.PrevHash, r1.EntryHash())
	}
}

func TestSinkChain_Fatal_LatchesAndBlocksFurtherCompute(t *testing.T) {
	c, _ := newTestSinkChain(t)

	if _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}

	c.Fatal(errors.New("ambiguous WAL write"))

	_, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after Fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

func TestSinkChain_State_Restore_RoundTrip(t *testing.T) {
	c, _ := newTestSinkChain(t)

	r0, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r0); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	r1, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r1); err != nil {
		t.Fatalf("Commit: %v", err)
	}

	state := c.State()
	if state.Generation != 0 || state.PrevHash != r1.EntryHash() {
		t.Fatalf("State() = %+v, want {Generation:0 PrevHash:%q}", state, r1.EntryHash())
	}

	d, _ := newTestSinkChain(t)
	if err := d.Restore(state.Generation, state.PrevHash, state.Fatal); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Continue the chain from d — same key, so same entry hash as if c
	// had continued.
	cNext, err := c.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	dNext, err := d.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`))
	if err != nil {
		t.Fatal(err)
	}
	if cNext.EntryHash() != dNext.EntryHash() {
		t.Errorf("after Restore: entryHash mismatch %q vs %q", cNext.EntryHash(), dNext.EntryHash())
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

func TestSinkChain_SerialComputeCommit_NoChainBreakage(t *testing.T) {
	c, key := newTestSinkChain(t)

	// Single-goroutine serialization verifies chain continuity; concurrent
	// ComputeCommit pairs across goroutines is NOT a supported pattern (Commit
	// cannot identify which Compute it finalizes). This test asserts that
	// repeated Compute+Commit in serial order produces a chain that verifies
	// when replayed in committed order.
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
			result, err := c.Compute(IntegrityFormatVersion, i, 0, payload)
			if err != nil {
				t.Errorf("Compute %d: %v", i, err)
				return
			}
			if err := c.Commit(result); err != nil {
				t.Errorf("Commit %d: %v", i, err)
				return
			}
			mu.Lock()
			records = append(records, record{seq: i, payload: payload, entryHash: result.EntryHash(), prevHash: result.PrevHash()})
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

func TestSinkChain_Compute_IsPureUnderConcurrentCallers(t *testing.T) {
	c, _ := newTestSinkChain(t)
	payload := []byte(`{"k":"v"}`)

	const N = 32
	results := make([]*ComputeResult, 0, N)
	var mu sync.Mutex
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			result, err := c.Compute(IntegrityFormatVersion, 0, 0, payload)
			if err != nil {
				t.Errorf("Compute: %v", err)
				return
			}
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(results) != N {
		t.Fatalf("got %d results, want %d", len(results), N)
	}
	wantEntry := results[0].EntryHash()
	wantPrev := results[0].PrevHash()
	for i, r := range results {
		if r.EntryHash() != wantEntry {
			t.Errorf("result %d: entry=%q, want %q (Compute is not pure under contention)", i, r.EntryHash(), wantEntry)
		}
		if r.PrevHash() != wantPrev {
			t.Errorf("result %d: prev=%q, want %q (Compute is not pure under contention)", i, r.PrevHash(), wantPrev)
		}
	}
}

func TestSinkChain_State_PersistsFatal(t *testing.T) {
	c, _ := newTestSinkChain(t)

	if _, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`)); err != nil {
		t.Fatal(err)
	}
	c.Fatal(errors.New("ambiguous WAL write"))

	state := c.State()
	if !state.Fatal {
		t.Fatalf("State.Fatal = false after Fatal(); want true")
	}

	// Round-trip into a fresh chain via Restore. The latch must survive.
	d, _ := newTestSinkChain(t)
	if err := d.Restore(state.Generation, state.PrevHash, state.Fatal); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if _, err := d.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`)); !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after Restore-with-Fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

func TestSinkChain_Restore_ValidatesPrevHash(t *testing.T) {
	validSha256 := strings.Repeat("a", 64)  // 32 bytes hex-encoded
	validSha512 := strings.Repeat("b", 128) // 64 bytes hex-encoded

	cases := []struct {
		name      string
		algorithm string
		prevHash  string
		wantErr   bool
	}{
		{name: "empty is genesis", algorithm: "hmac-sha256", prevHash: "", wantErr: false},
		{name: "valid sha256 hex", algorithm: "hmac-sha256", prevHash: validSha256, wantErr: false},
		{name: "wrong length hex (sha512 under sha256)", algorithm: "hmac-sha256", prevHash: validSha512, wantErr: true},
		{name: "non-hex characters", algorithm: "hmac-sha256", prevHash: strings.Repeat("z", 64), wantErr: true},
		{name: "odd-length hex", algorithm: "hmac-sha256", prevHash: strings.Repeat("a", 63), wantErr: true},
		{name: "valid sha512 hex under sha512", algorithm: "hmac-sha512", prevHash: validSha512, wantErr: false},
		{name: "sha256 length under sha512", algorithm: "hmac-sha512", prevHash: validSha256, wantErr: true},
		{name: "empty under sha512 is genesis", algorithm: "hmac-sha512", prevHash: "", wantErr: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := make([]byte, MinKeyLength)
			c, err := NewSinkChain(key, tc.algorithm)
			if err != nil {
				t.Fatalf("NewSinkChain: %v", err)
			}

			// Capture pre-state to assert non-mutation on rejected restore.
			before := c.State()

			err = c.Restore(7, tc.prevHash, false)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Restore(%q): err = nil, want error", tc.prevHash)
				}
				if !errors.Is(err, ErrInvalidChainState) {
					t.Errorf("Restore(%q): err = %v, want errors.Is ErrInvalidChainState", tc.prevHash, err)
				}
				after := c.State()
				if after != before {
					t.Errorf("rejected Restore mutated state: before=%+v after=%+v", before, after)
				}
				return
			}

			if err != nil {
				t.Fatalf("Restore(%q): unexpected err = %v", tc.prevHash, err)
			}
			after := c.State()
			if after.Generation != 7 || after.PrevHash != tc.prevHash || after.Fatal {
				t.Errorf("after Restore: state = %+v, want {Generation:7 PrevHash:%q Fatal:false}", after, tc.prevHash)
			}
		})
	}
}

// TestSinkChain_Commit_BackwardsGenerationLatchesFatal verifies that a Commit
// whose ComputeResult was produced before a generation rollover (i.e. its
// generation is older than the chain's current generation) latches the chain
// fatal and returns an error. Silently no-op'ing this would hide an integrity
// divergence: the durable write would have succeeded but the in-memory
// prev_hash would lag, breaking subsequent Compute calls without signal.
func TestSinkChain_Commit_BackwardsGenerationLatchesFatal(t *testing.T) {
	c, _ := newTestSinkChain(t)

	// Establish chain at gen=2 by Compute+Commit.
	r2, err := c.Compute(IntegrityFormatVersion, 0, 2, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Commit(r2); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	state := c.State()
	if state.Generation != 2 {
		t.Fatalf("setup: chain generation = %d, want 2", state.Generation)
	}

	// Construct a backwards-generation result. Restore the chain to gen=1
	// briefly, Compute under gen=1, then restore back to gen=2 — the result
	// carries result.generation=1 even though the chain is now at gen=2.
	if err := c.Restore(1, "", false); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	older, err := c.Compute(IntegrityFormatVersion, 0, 1, []byte(`{"old":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if older.generation != 1 {
		t.Fatalf("older.generation = %d, want 1", older.generation)
	}
	if err := c.Restore(2, r2.EntryHash(), false); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	// Commit the backwards result must return an error wrapping
	// ErrBackwardsGeneration and latch the chain fatal.
	err = c.Commit(older)
	if !errors.Is(err, ErrBackwardsGeneration) {
		t.Fatalf("Commit(backwards result): err = %v, want errors.Is ErrBackwardsGeneration", err)
	}

	if !c.State().Fatal {
		t.Errorf("State.Fatal = false after backwards-gen Commit; want true")
	}

	// Subsequent Compute must surface the fatal latch.
	if _, err := c.Compute(IntegrityFormatVersion, 1, 2, []byte(`{"x":1}`)); !errors.Is(err, ErrFatalIntegrity) {
		t.Errorf("Compute after backwards-gen Commit: err = %v, want ErrFatalIntegrity", err)
	}
}

// TestSinkChain_Commit_StaleResultLatchesFatal verifies that a Commit whose
// ComputeResult was produced before an earlier Commit advanced prev_hash
// (i.e., a stale token whose result.PrevHash no longer matches the chain's
// current prev_hash within the same generation) latches the chain fatal and
// returns an error wrapping ErrStaleResult. Silently committing the stale
// result would silently fork the chain.
func TestSinkChain_Commit_StaleResultLatchesFatal(t *testing.T) {
	c, _ := newTestSinkChain(t)

	// Two Computes in a row at gen=0 with NO Commit between them.
	// Both observe the empty prev_hash and produce results with PrevHash="".
	r1, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	r2, err := c.Compute(IntegrityFormatVersion, 1, 0, []byte(`{"b":2}`))
	if err != nil {
		t.Fatal(err)
	}

	// Commit r1 — advances prev_hash to r1.EntryHash.
	if err := c.Commit(r1); err != nil {
		t.Fatalf("Commit(r1): %v", err)
	}

	// Now commit r2. r2.PrevHash is "" (from when c.prevHash was empty), but
	// c.prevHash is now r1.EntryHash. The mismatch must be detected and
	// latched fatal.
	err = c.Commit(r2)
	if !errors.Is(err, ErrStaleResult) {
		t.Fatalf("Commit(stale r2): err = %v, want ErrStaleResult", err)
	}
	if !c.State().Fatal {
		t.Fatalf("Commit(stale r2) did not latch fatal")
	}

	// Subsequent Compute must fail.
	if _, err := c.Compute(IntegrityFormatVersion, 2, 0, []byte(`{"c":3}`)); !errors.Is(err, ErrFatalIntegrity) {
		t.Fatalf("Compute after stale-result fatal: err = %v, want ErrFatalIntegrity", err)
	}
}

// TestSinkChain_Commit_RolloverWithNonEmptyPrev_LatchesFatal exercises the
// defense-in-depth branch of the stale-token validation: a result whose
// generation > c.generation (rollover) but with PrevHash != "". Normal
// callers cannot construct this via Compute (Compute always sets prev=""
// on rollover); this test forges the result directly via the unexported
// fields, which is only possible from within the audit package.
func TestSinkChain_Commit_RolloverWithNonEmptyPrev_LatchesFatal(t *testing.T) {
	c, _ := newTestSinkChain(t)
	// Forge a result whose generation > c.generation (rollover) but with a
	// non-empty PrevHash. Normal callers cannot construct this via Compute;
	// this is defense-in-depth against future API changes or in-package bugs.
	// chain: c is required so the cross-chain check passes and we exercise
	// the rollover branch specifically.
	forged := &ComputeResult{
		entryHash:  "deadbeef",
		prevHash:   "shouldbeempty",
		sequence:   0,
		generation: 1,
		chain:      c,
	}
	err := c.Commit(forged)
	if !errors.Is(err, ErrStaleResult) {
		t.Fatalf("Commit(forged rollover): err = %v, want ErrStaleResult", err)
	}
	if !c.State().Fatal {
		t.Fatalf("forged rollover did not latch fatal")
	}
}

// TestSinkChain_Commit_NilResultErrors verifies that Commit rejects a nil
// ComputeResult with an error rather than panicking.
func TestSinkChain_Commit_NilResultErrors(t *testing.T) {
	c, _ := newTestSinkChain(t)

	err := c.Commit(nil)
	if err == nil {
		t.Fatal("Commit(nil): err = nil, want error")
	}

	// nil-result error is a caller bug, not a fatal integrity event — the
	// chain should NOT latch fatal in this case.
	if c.State().Fatal {
		t.Errorf("Commit(nil) latched fatal; want chain unchanged")
	}
}

// TestSinkChain_Commit_AfterFatalReturnsError verifies that Commit on a chain
// that was previously latched Fatal returns ErrFatalIntegrity (replacing the
// earlier silent-no-op behavior). The chain stays latched.
func TestSinkChain_Commit_AfterFatalReturnsError(t *testing.T) {
	c, _ := newTestSinkChain(t)

	result, err := c.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}

	c.Fatal(errors.New("ambiguous WAL write"))

	err = c.Commit(result)
	if !errors.Is(err, ErrFatalIntegrity) {
		t.Errorf("Commit after Fatal: err = %v, want ErrFatalIntegrity", err)
	}

	if !c.State().Fatal {
		t.Errorf("State.Fatal = false after Commit-on-fatal-chain; want true (latch must persist)")
	}
}

// TestSinkChain_Commit_CrossChainResultLatchesFatal verifies that committing a
// ComputeResult produced by SinkChain A on SinkChain B is rejected with
// ErrCrossChainResult AND latches B fatal. A is unaffected — only the chain
// that received the cross-chain commit latches. The check runs BEFORE
// generation/prev_hash validation so cross-chain wins over backwards-gen, etc.
func TestSinkChain_Commit_CrossChainResultLatchesFatal(t *testing.T) {
	a, _ := newTestSinkChain(t)
	b, _ := newTestSinkChain(t)

	// Compute on a, attempt to Commit on b.
	r, err := a.Compute(IntegrityFormatVersion, 0, 0, []byte(`{"x":1}`))
	if err != nil {
		t.Fatal(err)
	}

	err = b.Commit(r)
	if !errors.Is(err, ErrCrossChainResult) {
		t.Fatalf("Commit(cross-chain): err = %v, want ErrCrossChainResult", err)
	}
	if !b.State().Fatal {
		t.Fatalf("cross-chain Commit did not latch fatal on b")
	}
	// a is unaffected — only b should have latched.
	if a.State().Fatal {
		t.Fatalf("cross-chain Commit incorrectly latched a")
	}
}

// TestComputeResult_HasNoExportedDataFields enforces the structural invariant
// that ComputeResult has zero exported data fields via reflection. Accessor
// methods (EntryHash, PrevHash) are intentionally the only public surface; if
// anyone re-introduces an exported data field (e.g., renames `entryHash` to
// `EntryHash`), this test fails. The opacity of the token — the property that
// callers cannot mutate or fabricate one outside the audit package — depends
// directly on this invariant.
func TestComputeResult_HasNoExportedDataFields(t *testing.T) {
	typ := reflect.TypeOf(ComputeResult{})
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.IsExported() {
			t.Errorf("ComputeResult has exported data field %q (type %s) — must remain unexported to preserve token opacity", f.Name, f.Type)
		}
	}
}
