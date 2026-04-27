package compress

import (
	"bytes"
	"testing"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

func TestNoneEncoder_AlgoAndPassthroughError(t *testing.T) {
	enc := newNoneEncoder()
	if got := enc.Algo(); got != wtpv1.Compression_COMPRESSION_NONE {
		t.Fatalf("Algo() = %v, want COMPRESSION_NONE", got)
	}
	// noneEncoder.Encode is a programmer-error guard: callers MUST branch
	// on Algo()==NONE before calling Encode. Calling Encode on the none
	// encoder returns an error rather than silently passing through, so a
	// caller that forgets the branch fails loudly.
	if _, err := enc.Encode([]byte{1, 2, 3}); err == nil {
		t.Fatal("noneEncoder.Encode: want error, got nil")
	}
	_ = bytes.Equal // prevent unused-import nag if test changes
}
