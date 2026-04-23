package watchtower

// Test-only inspectors exported for sibling _test.go files in this and
// other packages. The _test.go suffix excludes this file from
// production builds automatically — no build tag needed.
//
// TODO(Task 22a + Task 23): once the WTPMetrics surface gains
// DroppedInvalidUTF8 / DroppedSequenceOverflow accessors (Task 22a)
// and the WAL gains a SegmentCount accessor (Task 23 needs it for
// drop-path tests), expose those here. They are intentionally
// omitted now because the underlying surfaces do not exist yet.

// PeekPrevHash returns the current chain prev_hash without advancing
// the chain. Used in the future append_test.go to assert that drop
// paths leave the chain untouched. Forwards to
// chain.SinkChainAPI.PeekPrevHash on s.sink, which in production is
// the *chain.WatchtowerSink adapter.
func (s *Store) PeekPrevHash() string {
	return s.sink.PeekPrevHash()
}
