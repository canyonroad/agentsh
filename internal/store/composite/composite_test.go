package composite

import (
	"context"
	"errors"
	"math"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/audit"
	storepkg "github.com/agentsh/agentsh/internal/store"
	"github.com/agentsh/agentsh/pkg/types"
)

type fakeEventStore struct {
	appendErr error
	appended  int
	closed    bool
}

func (f *fakeEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	f.appended++
	return f.appendErr
}
func (f *fakeEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return []types.Event{{ID: "x"}}, nil
}
func (f *fakeEventStore) Close() error { f.closed = true; return nil }

type fakeOutputStore struct {
	saveErr error
	readErr error
}

func (f *fakeOutputStore) SaveOutput(ctx context.Context, sessionID, commandID string, stdout, stderr []byte, stdoutTotal, stderrTotal int64, stdoutTrunc, stderrTrunc bool) error {
	return f.saveErr
}
func (f *fakeOutputStore) ReadOutputChunk(ctx context.Context, commandID string, stream string, offset, limit int64) ([]byte, int64, bool, error) {
	if f.readErr != nil {
		return nil, 0, false, f.readErr
	}
	return []byte("ok"), 2, false, nil
}

func TestAppendEventCollectsFirstError(t *testing.T) {
	primary := &fakeEventStore{appendErr: errors.New("primary")}
	secondary := &fakeEventStore{appendErr: errors.New("secondary")}
	s := New(primary, nil, secondary)

	err := s.AppendEvent(context.Background(), types.Event{ID: "1"})
	if err == nil || err.Error() != "primary" {
		t.Fatalf("expected primary error, got %v", err)
	}
	if primary.appended != 1 || secondary.appended != 1 {
		t.Fatalf("expected both stores to receive append, got %d %d", primary.appended, secondary.appended)
	}
}

func TestAppendEventErrorHookReceivesFirstError(t *testing.T) {
	primaryErr := errors.New("primary")
	primary := &fakeEventStore{appendErr: primaryErr}
	secondary := &fakeEventStore{appendErr: errors.New("secondary")}
	s := New(primary, nil, secondary)

	var got error
	s.SetAppendErrorHook(func(err error) {
		got = err
	})

	err := s.AppendEvent(context.Background(), types.Event{ID: "1"})
	if !errors.Is(err, primaryErr) {
		t.Fatalf("AppendEvent() error = %v, want %v", err, primaryErr)
	}
	if !errors.Is(got, primaryErr) {
		t.Fatalf("hook error = %v, want %v", got, primaryErr)
	}
}

func TestAppendEventErrorHookNotCalledOnSuccess(t *testing.T) {
	s := New(&fakeEventStore{}, nil, &fakeEventStore{})

	called := false
	s.SetAppendErrorHook(func(error) {
		called = true
	})

	if err := s.AppendEvent(context.Background(), types.Event{ID: "1"}); err != nil {
		t.Fatalf("AppendEvent() error = %v", err)
	}
	if called {
		t.Fatal("append error hook called on success")
	}
}

func TestAppendEventErrorHookReceivesLaterFatalIntegrityError(t *testing.T) {
	primaryErr := errors.New("primary")
	fatalErr := &storepkg.FatalIntegrityError{Op: "write audit integrity sidecar", Err: errors.New("disk full")}

	primary := &fakeEventStore{appendErr: primaryErr}
	secondary := &fakeEventStore{appendErr: fatalErr}
	s := New(primary, nil, secondary)

	var got []error
	s.SetAppendErrorHook(func(err error) {
		got = append(got, err)
	})

	err := s.AppendEvent(context.Background(), types.Event{ID: "1"})
	if !errors.Is(err, primaryErr) {
		t.Fatalf("AppendEvent() error = %v, want %v", err, primaryErr)
	}

	foundFatal := false
	for _, err := range got {
		if errors.As(err, &fatalErr) {
			foundFatal = true
			break
		}
	}
	if !foundFatal {
		t.Fatalf("hook errors = %v, want fatal integrity error included", got)
	}
}

func TestOutputDelegationAndErrors(t *testing.T) {
	out := &fakeOutputStore{}
	s := New(&fakeEventStore{}, out)
	if err := s.SaveOutput(context.Background(), "s", "c", nil, nil, 0, 0, false, false); err != nil {
		t.Fatalf("SaveOutput unexpected error: %v", err)
	}
	data, total, truncated, err := s.ReadOutputChunk(context.Background(), "c", "stdout", 0, 10)
	if err != nil || string(data) != "ok" || total != 2 || truncated {
		t.Fatalf("ReadOutputChunk unexpected: data=%q total=%d trunc=%v err=%v", data, total, truncated, err)
	}

	sNoOut := New(&fakeEventStore{}, nil)
	if err := sNoOut.SaveOutput(context.Background(), "", "", nil, nil, 0, 0, false, false); err == nil {
		t.Fatal("expected error when output store missing")
	}
	if _, _, _, err := sNoOut.ReadOutputChunk(context.Background(), "", "", 0, 1); err == nil {
		t.Fatal("expected error when output store missing")
	}
}

func TestClosePropagates(t *testing.T) {
	primary := &fakeEventStore{}
	other := &fakeEventStore{}
	s := New(primary, nil, other)
	_ = s.Close()
	if !primary.closed || !other.closed {
		t.Fatalf("expected stores closed")
	}
}

func TestUpsertMCPToolFromEvent_SkipsNonMCPEvents(t *testing.T) {
	primary := &fakeEventStore{}
	s := New(primary, nil)

	// Non-MCP event should be silently skipped
	ev := types.Event{
		Type:   "file_open",
		Fields: map[string]any{"path": "/tmp/test"},
	}
	err := s.UpsertMCPToolFromEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("expected nil error for non-MCP event, got %v", err)
	}
}

func TestUpsertMCPToolFromEvent_SkipsNonSQLiteStore(t *testing.T) {
	primary := &fakeEventStore{}
	s := New(primary, nil)

	// MCP event with fake store should be silently skipped
	ev := types.Event{
		Type: "mcp_tool_seen",
		Fields: map[string]any{
			"server_id": "test-server",
			"tool_name": "test-tool",
			"tool_hash": "abc123",
		},
	}
	err := s.UpsertMCPToolFromEvent(context.Background(), ev)
	if err != nil {
		t.Fatalf("expected nil error for non-SQLite store, got %v", err)
	}
}

func TestComposite_NilPrimary_AppendEvent(t *testing.T) {
	other := &fakeEventStore{}
	s := New(nil, nil, other)

	if err := s.AppendEvent(context.Background(), types.Event{ID: "1"}); err != nil {
		t.Fatalf("AppendEvent with nil primary: %v", err)
	}
	if other.appended != 1 {
		t.Fatalf("expected other store to receive event, got %d appends", other.appended)
	}
}

func TestComposite_NilPrimary_QueryEvents(t *testing.T) {
	s := New(nil, nil)

	events, err := s.QueryEvents(context.Background(), types.EventQuery{})
	if err != nil {
		t.Fatalf("QueryEvents with nil primary: %v", err)
	}
	if len(events) != 0 {
		t.Fatalf("expected empty results, got %d", len(events))
	}
}

func TestComposite_NilPrimary_Close(t *testing.T) {
	other := &fakeEventStore{}
	s := New(nil, nil, other)

	if err := s.Close(); err != nil {
		t.Fatalf("Close with nil primary: %v", err)
	}
	if !other.closed {
		t.Fatal("expected other store to be closed")
	}
}

type chainCapturingStore struct {
	captured []*types.ChainState
}

func (s *chainCapturingStore) AppendEvent(ctx context.Context, ev types.Event) error {
	// Composite stamps a fresh *ChainState per sink, so the captured
	// pointer is the sink-local copy — distinct from every other sink's.
	s.captured = append(s.captured, ev.Chain)
	return nil
}
func (s *chainCapturingStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (s *chainCapturingStore) Close() error { return nil }

func TestComposite_StampsChainBeforeFanout(t *testing.T) {
	primary := &chainCapturingStore{}
	other := &chainCapturingStore{}
	s := New(primary, nil, other)

	for i := 0; i < 5; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{ID: "e"}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}

	if len(primary.captured) != 5 || len(other.captured) != 5 {
		t.Fatalf("captured counts: primary=%d other=%d", len(primary.captured), len(other.captured))
	}
	for i, p := range primary.captured {
		o := other.captured[i]
		if p == nil || o == nil {
			t.Fatalf("event %d: nil Chain — primary=%v other=%v", i, p, o)
		}
		if p.Sequence != uint64(i) || p.Generation != 0 {
			t.Errorf("primary event %d: Chain=(seq=%d,gen=%d) want (seq=%d,gen=0)", i, p.Sequence, p.Generation, i)
		}
		// Per-sink-copy contract: pointer-distinct across sinks but
		// value-equal. Use == on pointers (must differ) and DeepEqual
		// on dereferenced values (must match).
		if p == o {
			t.Errorf("event %d: sinks alias the same *ChainState pointer (%p); composite must stamp fresh per sink", i, p)
		}
		if !reflect.DeepEqual(*p, *o) {
			t.Errorf("event %d: sinks saw different Chain values: primary=%+v other=%+v", i, *p, *o)
		}
	}

	// Mutating one sink's captured ChainState must not affect the other's.
	primary.captured[0].Sequence = 0xDEADBEEF
	if other.captured[0].Sequence == 0xDEADBEEF {
		t.Errorf("per-sink-copy invariant violated: mutating primary leaked into other")
	}
}

func TestComposite_NextGeneration_ResetsSequence(t *testing.T) {
	primary := &chainCapturingStore{}
	s := New(primary, nil)

	for i := 0; i < 3; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}

	newGen, err := s.NextGeneration()
	if err != nil {
		t.Fatalf("NextGeneration: %v", err)
	}
	if newGen != 1 {
		t.Fatalf("NextGeneration() = %d, want 1", newGen)
	}

	if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
		t.Fatal(err)
	}

	last := primary.captured[len(primary.captured)-1]
	if last == nil || last.Sequence != 0 || last.Generation != 1 {
		t.Errorf("after rollover: Chain=(seq=%d,gen=%d) want (seq=0,gen=1)", last.Sequence, last.Generation)
	}
}

// blockingEventStore blocks AppendEvent on a release channel so the test can
// pin a goroutine inside the composite's per-event fanout. Used to verify
// rollover atomicity: NextGeneration must NOT advance while an AppendEvent
// is mid-fanout (and conversely, an AppendEvent that started before
// NextGeneration must observe the OLD generation, not the new one).
type blockingEventStore struct {
	mu       sync.Mutex
	captured []*types.ChainState
	release  chan struct{} // close to release blocked AppendEvent
	entered  chan struct{} // closed by AppendEvent when it has begun
	once     sync.Once
}

func newBlockingEventStore() *blockingEventStore {
	return &blockingEventStore{
		release: make(chan struct{}),
		entered: make(chan struct{}),
	}
}

func (b *blockingEventStore) AppendEvent(ctx context.Context, ev types.Event) error {
	b.once.Do(func() { close(b.entered) })
	<-b.release
	b.mu.Lock()
	defer b.mu.Unlock()
	b.captured = append(b.captured, ev.Chain)
	return nil
}

func (b *blockingEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (b *blockingEventStore) Close() error { return nil }

// TestComposite_NextGeneration_BlocksUntilInflightFanoutCompletes is the
// regression test for the rollover-atomicity bug roborev caught: without a
// wrapper-level RWMutex, NextGeneration can advance while an in-flight
// AppendEvent is still mid-fanout. The first AppendEvent stamps with the
// OLD generation, NextGeneration concurrently flips the allocator, and any
// sink that has already rekeyed sees a backwards-generation event.
//
// With the fix in place, NextGeneration takes a write lock and waits for
// every in-flight AppendEvent (which holds an RLock) to complete before
// advancing the generation.
func TestComposite_NextGeneration_BlocksUntilInflightFanoutCompletes(t *testing.T) {
	blocker := newBlockingEventStore()
	tail := &chainCapturingStore{}
	s := New(blocker, nil, tail)

	// Goroutine 1: AppendEvent that blocks in fanout (inside blocker).
	appendDone := make(chan error, 1)
	go func() {
		appendDone <- s.AppendEvent(context.Background(), types.Event{ID: "blocked"})
	}()

	// Wait until the blocked AppendEvent has actually begun fanning out.
	select {
	case <-blocker.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked AppendEvent never entered the sink")
	}

	// Goroutine 2: NextGeneration. Must NOT return while the first
	// AppendEvent is still mid-fanout.
	nextGenDone := make(chan struct {
		gen uint32
		err error
	}, 1)
	go func() {
		gen, err := s.NextGeneration()
		nextGenDone <- struct {
			gen uint32
			err error
		}{gen, err}
	}()

	// Verify NextGeneration is blocked: it should not return within a short
	// window while the AppendEvent is still in fanout.
	select {
	case got := <-nextGenDone:
		t.Fatalf("NextGeneration returned (gen=%d, err=%v) while AppendEvent was mid-fanout; expected to block", got.gen, got.err)
	case <-time.After(150 * time.Millisecond):
		// Good: NextGeneration is properly blocked.
	}

	// Release the AppendEvent.
	close(blocker.release)

	// First AppendEvent should now complete.
	select {
	case err := <-appendDone:
		if err != nil {
			t.Fatalf("blocked AppendEvent returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AppendEvent never completed after release")
	}

	// NextGeneration should return shortly after.
	select {
	case got := <-nextGenDone:
		if got.err != nil {
			t.Fatalf("NextGeneration error: %v", got.err)
		}
		if got.gen != 1 {
			t.Errorf("NextGeneration returned gen=%d, want 1", got.gen)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("NextGeneration never returned after AppendEvent completed")
	}

	// Verify the blocked AppendEvent stamped the OLD generation (0), not 1.
	if len(blocker.captured) != 1 {
		t.Fatalf("blocker captured %d events, want 1", len(blocker.captured))
	}
	if blocker.captured[0].Generation != 0 {
		t.Errorf("blocked AppendEvent stamped Generation=%d, want 0 (OLD generation)", blocker.captured[0].Generation)
	}
	if len(tail.captured) != 1 || tail.captured[0].Generation != 0 {
		t.Errorf("tail sink Generation=%v, want 0", tail.captured)
	}

	// A subsequent AppendEvent should now stamp the new generation.
	if err := s.AppendEvent(context.Background(), types.Event{ID: "after"}); err != nil {
		t.Fatalf("post-rollover AppendEvent: %v", err)
	}
	if len(tail.captured) != 2 {
		t.Fatalf("tail captured %d events, want 2", len(tail.captured))
	}
	if tail.captured[1].Generation != 1 || tail.captured[1].Sequence != 0 {
		t.Errorf("post-rollover tuple = (seq=%d, gen=%d), want (seq=0, gen=1)", tail.captured[1].Sequence, tail.captured[1].Generation)
	}
}

// concurrentChainCapturingStore is a thread-safe variant of
// chainCapturingStore. The tests in this file that exercise concurrent
// AppendEvent calls use this; the original chainCapturingStore is used by
// single-goroutine tests where the lock would be noise.
type concurrentChainCapturingStore struct {
	mu       sync.Mutex
	captured []types.ChainState
}

func (s *concurrentChainCapturingStore) AppendEvent(ctx context.Context, ev types.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ev.Chain == nil {
		// Record a sentinel so the assertion phase can flag "no Chain stamped".
		s.captured = append(s.captured, types.ChainState{})
		return nil
	}
	// Snapshot the value so subsequent stamping by a later AppendEvent on
	// the same goroutine cannot mutate what we recorded.
	s.captured = append(s.captured, *ev.Chain)
	return nil
}

func (s *concurrentChainCapturingStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (s *concurrentChainCapturingStore) Close() error { return nil }

// TestComposite_NextGeneration_NoStaleStamping verifies the per-generation
// monotonic invariant: across concurrent AppendEvents and concurrent
// NextGeneration calls, the captured stream must be strictly monotonic on
// (generation, then sequence). In particular, no gen=N event may appear in
// the captured stream after any gen=N+1 event from the same goroutine — and
// (gen, seq) pairs must be unique.
//
// This catches the bug where an AppendEvent reads gen=N from the allocator,
// gets preempted, NextGeneration advances to N+1, a different AppendEvent
// reads gen=N+1, completes fanout, and THEN the preempted AppendEvent
// completes fanout with its older gen=N stamp. With the wrapper RWMutex in
// place this race cannot happen because NextGeneration cannot advance while
// any AppendEvent holds an RLock.
func TestComposite_NextGeneration_NoStaleStamping(t *testing.T) {
	tail := &concurrentChainCapturingStore{}
	s := New(tail, nil)

	const numAppendGoroutines = 100
	const appendsPerGoroutine = 20
	const numRollovers = 5

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Append goroutines: each one calls AppendEvent in a tight loop until
	// it has done its quota, observed a stop signal, OR returns an error.
	var totalAppended atomic.Int64
	for i := 0; i < numAppendGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < appendsPerGoroutine; j++ {
				select {
				case <-stop:
					return
				default:
				}
				if err := s.AppendEvent(context.Background(), types.Event{ID: "x"}); err != nil {
					t.Errorf("AppendEvent: %v", err)
					return
				}
				totalAppended.Add(1)
			}
		}()
	}

	// Rollover goroutine: spaces out NextGeneration calls so they
	// interleave with the AppendEvents above.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < numRollovers; i++ {
			time.Sleep(2 * time.Millisecond)
			if _, err := s.NextGeneration(); err != nil {
				t.Errorf("NextGeneration #%d: %v", i, err)
				close(stop)
				return
			}
		}
	}()

	wg.Wait()

	tail.mu.Lock()
	captured := append([]types.ChainState(nil), tail.captured...)
	tail.mu.Unlock()

	if int64(len(captured)) != totalAppended.Load() {
		t.Fatalf("captured %d events, want %d", len(captured), totalAppended.Load())
	}

	// Build a map from generation → max sequence seen, and assert
	// uniqueness of every (gen, seq) tuple.
	seen := make(map[uint64]map[uint64]bool) // gen -> seq -> bool
	maxSeqPerGen := make(map[uint64]uint64)
	for i, c := range captured {
		gen := uint64(c.Generation)
		if seen[gen] == nil {
			seen[gen] = make(map[uint64]bool)
		}
		if seen[gen][c.Sequence] {
			t.Fatalf("captured[%d]: duplicate (seq=%d, gen=%d) in stream", i, c.Sequence, c.Generation)
		}
		seen[gen][c.Sequence] = true
		if c.Sequence > maxSeqPerGen[gen] {
			maxSeqPerGen[gen] = c.Sequence
		}
	}

	// Each generation's sequence range must be contiguous from 0 to
	// maxSeqPerGen[gen] — no holes (every allocation stamps an event).
	for gen, max := range maxSeqPerGen {
		for seq := uint64(0); seq <= max; seq++ {
			if !seen[gen][seq] {
				t.Errorf("gen=%d: missing sequence %d in [0, %d]", gen, seq, max)
			}
		}
	}

	// Strict monotonicity per goroutine is hard to assert without per-call
	// instrumentation (we don't know which append went to which goroutine).
	// Instead, assert: in the captured stream, the maximum generation seen
	// up to any index is non-decreasing. Once the stream has observed gen=N,
	// no later append may stamp gen<N (because under the wrapper RWMutex,
	// once NextGeneration has advanced the allocator, every AppendEvent
	// that started AFTER the rollover sees the new generation, and every
	// AppendEvent that started BEFORE has already completed fanout — so its
	// captured entry is positioned earlier in the stream).
	//
	// Specifically: once we've seen any gen=g in the captured stream, no
	// future entry may have generation < g - (numAppendGoroutines+1), where
	// the slack accounts for the fact that captured-stream order is the
	// order in which fanouts ENDED, which can interleave with the order
	// they STARTED. The wrapper-lock guarantee is that all stamping with
	// gen=g happens-before any stamping with gen=g+1; the captured stream
	// preserves this ordering because both stampings happen inside the
	// fanout, which happens inside the RLock, which is fully serialized
	// against the NextGeneration write lock.
	maxGenSeen := uint64(0)
	for i, c := range captured {
		gen := uint64(c.Generation)
		if gen > maxGenSeen {
			maxGenSeen = gen
		}
		// Strict: gen must equal maxGenSeen at this point. If gen <
		// maxGenSeen, an older-generation event slipped in after a
		// newer-generation event, which is exactly the rollover-atomicity
		// violation we are testing for.
		if gen < maxGenSeen {
			t.Fatalf("captured[%d]: stale stamping — got gen=%d after observing gen=%d earlier in stream", i, gen, maxGenSeen)
		}
	}
}

// TestComposite_AppendEvent_AllocatorErrorRoutedToHook verifies that when the
// allocator rejects the next allocation (overflow), the resulting error is:
//   - wrapped as *store.FatalIntegrityError with Op == "audit sequence allocate"
//   - delivered to the onAppendError hook
//   - returned to the caller
//   - and that NO sink saw the event (allocator failure short-circuits fanout).
//
// This routes allocator overflow through the same fatal-audit watcher path
// the daemon already uses for other FatalIntegrityErrors raised by
// internal/store/integrity_wrapper.go.
func TestComposite_AppendEvent_AllocatorErrorRoutedToHook(t *testing.T) {
	primary := &chainCapturingStore{}
	other := &chainCapturingStore{}
	s := New(primary, nil, other)

	// Drive the allocator to MaxInt64 so the next Next() returns
	// ErrSequenceOverflow.
	if err := s.Restore(audit.AllocatorState{Sequence: math.MaxInt64}); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	var hookErr error
	s.SetAppendErrorHook(func(err error) {
		hookErr = err
	})

	err := s.AppendEvent(context.Background(), types.Event{ID: "overflow"})
	if err == nil {
		t.Fatal("AppendEvent returned nil; want fatal allocator error")
	}
	if !errors.Is(err, audit.ErrSequenceOverflow) {
		t.Fatalf("AppendEvent err = %v, want errors.Is(ErrSequenceOverflow)", err)
	}
	var fatal *storepkg.FatalIntegrityError
	if !errors.As(err, &fatal) {
		t.Fatalf("AppendEvent err = %T(%v), want *FatalIntegrityError", err, err)
	}
	if fatal.Op != "audit sequence allocate" {
		t.Errorf("fatal.Op = %q, want %q", fatal.Op, "audit sequence allocate")
	}

	if hookErr == nil {
		t.Fatal("onAppendError hook not called")
	}
	var hookFatal *storepkg.FatalIntegrityError
	if !errors.As(hookErr, &hookFatal) {
		t.Fatalf("hook err = %T(%v), want *FatalIntegrityError", hookErr, hookErr)
	}
	if hookFatal != fatal {
		t.Errorf("hook delivered a different *FatalIntegrityError instance: hook=%p returned=%p", hookFatal, fatal)
	}

	// No sink should have seen the event — allocator failure short-circuits
	// fanout entirely.
	if len(primary.captured) != 0 {
		t.Errorf("primary captured %d events, want 0", len(primary.captured))
	}
	if len(other.captured) != 0 {
		t.Errorf("other captured %d events, want 0", len(other.captured))
	}
}

// TestComposite_State_Restore_Roundtrip verifies that the composite's State
// snapshot can be persisted and rehydrated into a fresh composite, with the
// next AppendEvent stamping at exactly snapshot.Sequence + 1.
func TestComposite_State_Restore_Roundtrip(t *testing.T) {
	first := &chainCapturingStore{}
	src := New(first, nil)

	for i := 0; i < 4; i++ {
		if err := src.AppendEvent(context.Background(), types.Event{}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}
	snap := src.State()
	if snap.Sequence != 3 {
		t.Fatalf("State.Sequence = %d, want 3", snap.Sequence)
	}

	dst := New(&chainCapturingStore{}, nil)
	if err := dst.Restore(snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}

	tail := &chainCapturingStore{}
	dst2 := New(tail, nil)
	if err := dst2.Restore(snap); err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if err := dst2.AppendEvent(context.Background(), types.Event{}); err != nil {
		t.Fatalf("post-Restore AppendEvent: %v", err)
	}
	if len(tail.captured) != 1 {
		t.Fatalf("tail captured %d events, want 1", len(tail.captured))
	}
	if tail.captured[0].Sequence != uint64(snap.Sequence+1) {
		t.Errorf("post-Restore stamp Sequence = %d, want %d", tail.captured[0].Sequence, snap.Sequence+1)
	}
	if tail.captured[0].Generation != snap.Generation {
		t.Errorf("post-Restore stamp Generation = %d, want %d", tail.captured[0].Generation, snap.Generation)
	}
}

// TestComposite_Restore_RejectsInvalidInput_LeavesStateIntact verifies the
// delegated all-or-nothing guarantee from SequenceAllocator.Restore. A
// rejected Restore must not perturb composite state, and a subsequent
// AppendEvent must continue from the prior State() snapshot.
func TestComposite_Restore_RejectsInvalidInput_LeavesStateIntact(t *testing.T) {
	tail := &chainCapturingStore{}
	s := New(tail, nil)

	for i := 0; i < 3; i++ {
		if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
			t.Fatalf("AppendEvent #%d: %v", i, err)
		}
	}
	s0 := s.State()

	err := s.Restore(audit.AllocatorState{Sequence: -2})
	if err == nil {
		t.Fatal("Restore(-2) returned nil; want ErrInvalidAllocatorState")
	}
	if !errors.Is(err, audit.ErrInvalidAllocatorState) {
		t.Fatalf("Restore err = %v, want errors.Is(ErrInvalidAllocatorState)", err)
	}

	if got := s.State(); got != s0 {
		t.Fatalf("after rejected Restore: State = %+v, want %+v", got, s0)
	}

	if err := s.AppendEvent(context.Background(), types.Event{}); err != nil {
		t.Fatalf("post-rejected-Restore AppendEvent: %v", err)
	}
	last := tail.captured[len(tail.captured)-1]
	if last == nil || last.Sequence != uint64(s0.Sequence+1) {
		t.Fatalf("post-rejected-Restore stamp Sequence = %d, want %d", last.Sequence, s0.Sequence+1)
	}
}
