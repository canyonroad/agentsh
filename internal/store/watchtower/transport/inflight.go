package transport

// inflightTracker tracks the (generation, sequence) high-watermarks of
// frames that have been Sent but not yet covered by an
// AckOutcomeAdopted BatchAck. Both EventBatch and TransportLoss frames
// are tracked symmetrically — the high-watermark is the frame's
// to_sequence, regardless of frame type. A BatchAck whose
// ack_high_watermark_seq retires entries up to that sequence covers
// both kinds uniformly (the WTP server treats TransportLoss as a
// metadata frame that advances the watermark, just like a data batch).
//
// The WTP protocol allows a single BatchAck to coalesce
// acknowledgements for multiple frames via its AckHighWatermarkSeq +
// Generation tuple, so a counter that decrements by one per ack would
// under-release the inflight window against any conforming server that
// batches acknowledgements (roborev Medium round-3). Release pops every
// pending entry whose high-watermark is at or below the adopted ack's
// (gen, seq) tuple.
//
// Pending entries are appended in send order; the protocol guarantees
// (gen, seq) is monotonically non-decreasing across successive Sends
// on the same connection, so a prefix-pop is correct.
type inflightTracker struct {
	pending []AckCursor
}

// Push records an EventBatch boundary. (gen, seq) is the high-
// watermark of the batch's records — the same tuple the server will
// echo back via BatchAck.AckHighWatermarkSeq + Generation.
func (it *inflightTracker) Push(gen uint32, seq uint64) {
	it.pending = append(it.pending, AckCursor{Sequence: seq, Generation: gen})
}

// Release pops the longest prefix of pending whose high-watermark is
// at or below (ackGen, ackSeq). Returns the number of batches
// released so callers can observe coalesced-ack progress.
//
// Lexicographic ordering: a pending entry is "at or below" the ack if
// its generation is strictly lower, or its generation matches AND its
// sequence is at or below the ack sequence. A higher-generation
// entry is always above the ack regardless of sequence (the ack
// belongs to a prior generation that has rolled over).
func (it *inflightTracker) Release(ackGen uint32, ackSeq uint64) int {
	n := 0
	for n < len(it.pending) {
		p := it.pending[n]
		if p.Generation > ackGen || (p.Generation == ackGen && p.Sequence > ackSeq) {
			break
		}
		n++
	}
	if n > 0 {
		it.pending = it.pending[n:]
	}
	return n
}

// Len returns the number of pending (un-acked) batches. Used by
// runLive to gate further sends against MaxInflight.
func (it *inflightTracker) Len() int { return len(it.pending) }
