package watchtower

import (
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

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

// OptsLogGoawayMessageForTest returns the Options.LogGoawayMessage value
// the Store was constructed with. Used by integration tests to assert
// that the config-layer three-state resolution is correctly threaded
// through watchtower.Options → transport.Options.
func (s *Store) OptsLogGoawayMessageForTest() bool {
	return s.opts.LogGoawayMessage
}

// TransportLogGoawayMessageForTest returns the LogGoawayMessage value
// as resolved by the Transport the Store constructed. This is the
// load-bearing seam for the wire-through regression test: if store.go
// ever stops passing opts.LogGoawayMessage into transport.New, the
// Transport's value will be false (the zero value) regardless of what
// Options.LogGoawayMessage was set to, causing the assertion to fail.
func (s *Store) TransportLogGoawayMessageForTest() bool {
	return s.tr.LogGoawayMessage()
}

// OptsCompressionAlgoForTest returns the Options.CompressionAlgo value
// the Store was constructed with.
func (s *Store) OptsCompressionAlgoForTest() string {
	return s.opts.CompressionAlgo
}

// TransportCompressorAlgoForTest returns the Compression enum the
// Transport's compressor reports via Algo(). If store.go ever stops
// constructing a compressor from opts.CompressionAlgo, this returns
// COMPRESSION_NONE (the noneEncoder default applied in transport.New).
func (s *Store) TransportCompressorAlgoForTest() wtpv1.Compression {
	return s.tr.CompressorAlgo()
}

