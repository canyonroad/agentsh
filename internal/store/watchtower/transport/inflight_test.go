package transport

import "testing"

// TestInflightTracker_PushReleasePerBatchAck pins the per-batch ack
// case (server sends one BatchAck per Send): four pushes with
// strictly increasing seqs in the same generation, then a single
// Release with the high-water of the last → all four released.
func TestInflightTracker_PushReleasePerBatchAck(t *testing.T) {
	var it inflightTracker
	for _, seq := range []uint64{10, 20, 30, 40} {
		it.Push(1, seq)
	}
	if got := it.Len(); got != 4 {
		t.Fatalf("Len after 4 pushes: got %d, want 4", got)
	}

	released := it.Release(1, 40)
	if released != 4 {
		t.Errorf("Release(1,40): got %d, want 4 (cumulative ack covers all)", released)
	}
	if got := it.Len(); got != 0 {
		t.Errorf("Len after full release: got %d, want 0", got)
	}
}

// TestInflightTracker_CumulativeAckReleasesAllCovered pins the
// roborev Medium round-3 finding: a single Adopted BatchAck whose
// high-watermark covers multiple unacked batches MUST release every
// covered batch, not just one. Counter-decrement-by-one would stall
// the send path against a coalescing server.
func TestInflightTracker_CumulativeAckReleasesAllCovered(t *testing.T) {
	var it inflightTracker
	for _, seq := range []uint64{10, 20, 30, 40} {
		it.Push(1, seq)
	}

	// Cumulative ack covers the first two batches only.
	released := it.Release(1, 25)
	if released != 2 {
		t.Errorf("Release(1,25) covering [10,20] only: got %d, want 2", released)
	}
	if got := it.Len(); got != 2 {
		t.Errorf("Len after partial release: got %d, want 2", got)
	}

	// Subsequent ack covers the remaining two.
	released = it.Release(1, 40)
	if released != 2 {
		t.Errorf("Release(1,40) covering [30,40]: got %d, want 2", released)
	}
	if got := it.Len(); got != 0 {
		t.Errorf("Len after final release: got %d, want 0", got)
	}
}

// TestInflightTracker_StaleAckBelowFrontReleasesNothing — an ack at
// or below the oldest pending batch's high-watermark must not pop
// anything. The reviewer's concern path: a duplicate or stale
// BatchAck must not over-release the window.
func TestInflightTracker_StaleAckBelowFrontReleasesNothing(t *testing.T) {
	var it inflightTracker
	it.Push(1, 100)

	if released := it.Release(1, 50); released != 0 {
		t.Errorf("Release(1,50) below front=(1,100): got %d, want 0", released)
	}
	if got := it.Len(); got != 1 {
		t.Errorf("Len after stale ack: got %d, want 1", got)
	}
}

// TestInflightTracker_GenerationBoundary verifies the lexicographic
// ordering across generation rolls: an ack at (gen=2, seq=5)
// releases ALL gen=1 entries (regardless of seq) AND any gen=2
// entries with seq ≤ 5.
func TestInflightTracker_GenerationBoundary(t *testing.T) {
	var it inflightTracker
	it.Push(1, 10)
	it.Push(1, 20)
	it.Push(2, 5)
	it.Push(2, 15)

	released := it.Release(2, 5)
	if released != 3 {
		t.Errorf("Release(2,5) covering [(1,10),(1,20),(2,5)]: got %d, want 3", released)
	}
	if got := it.Len(); got != 1 {
		t.Errorf("Len after cross-generation release: got %d, want 1", got)
	}
}

// TestInflightTracker_HigherGenerationAckReleasesAllPriorGenerations —
// a generation roll is a hard boundary: any ack in a later
// generation covers ALL prior-generation pending entries even if
// the ack's sequence is small.
func TestInflightTracker_HigherGenerationAckReleasesAllPriorGenerations(t *testing.T) {
	var it inflightTracker
	it.Push(1, 1000)
	it.Push(1, 2000)

	released := it.Release(2, 0)
	if released != 2 {
		t.Errorf("Release(2,0) above prior generation [1,*]: got %d, want 2", released)
	}
	if got := it.Len(); got != 0 {
		t.Errorf("Len after generation-skip release: got %d, want 0", got)
	}
}

// TestInflightTracker_TransportLossAndEventBatchRetiredTogether pins the
// symmetric tracking of TransportLoss and EventBatch frames: a BatchAck
// retiring entries up to (gen, seq) must cover both kinds uniformly.
// Mixed sequence: EventBatch{to=10}, TransportLoss{to=11}, EventBatch{to=15}.
// A BatchAck{ack_high=11, gen=1} should retire the first two.
func TestInflightTracker_TransportLossAndEventBatchRetiredTogether(t *testing.T) {
	var it inflightTracker
	it.Push(1, 10) // EventBatch high-watermark
	it.Push(1, 11) // TransportLoss high-watermark
	it.Push(1, 15) // EventBatch high-watermark
	if it.Len() != 3 {
		t.Fatalf("Len = %d; want 3", it.Len())
	}
	released := it.Release(1, 11)
	if released != 2 {
		t.Fatalf("Release = %d; want 2 (first two retired)", released)
	}
	if it.Len() != 1 {
		t.Fatalf("Len after Release = %d; want 1", it.Len())
	}
}
