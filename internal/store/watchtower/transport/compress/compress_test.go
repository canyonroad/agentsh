package compress

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/klauspost/compress/zstd"

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
}

func TestZstdEncoder_RoundTripDefaultLevel(t *testing.T) {
	enc, err := NewEncoder("zstd", 3, 0)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	if got := enc.Algo(); got != wtpv1.Compression_COMPRESSION_ZSTD {
		t.Fatalf("Algo() = %v, want COMPRESSION_ZSTD", got)
	}
	in := bytes.Repeat([]byte("agentsh-wtp-zstd-roundtrip-"), 256) // ~7 KiB highly compressible
	out, err := enc.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if len(out) >= len(in) {
		t.Fatalf("Encode produced %d bytes from %d-byte input; expected compression", len(out), len(in))
	}
	dec, err := zstdDecodeForTest(out)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(dec, in) {
		t.Fatalf("round-trip mismatch")
	}
}

func TestZstdEncoder_LevelBounds(t *testing.T) {
	cases := []struct {
		level   int
		wantErr bool
	}{
		{0, true}, {1, false}, {3, false}, {22, false}, {23, true}, {-1, true},
	}
	for _, tc := range cases {
		_, err := NewEncoder("zstd", tc.level, 0)
		if (err != nil) != tc.wantErr {
			t.Errorf("level=%d err=%v wantErr=%v", tc.level, err, tc.wantErr)
		}
	}
}

func TestZstdEncoder_SerialReuse(t *testing.T) {
	enc, err := NewEncoder("zstd", 3, 0)
	if err != nil {
		t.Fatalf("NewEncoder: %v", err)
	}
	for i := 0; i < 100; i++ {
		in := []byte(fmt.Sprintf("payload-%d", i))
		out, err := enc.Encode(in)
		if err != nil {
			t.Fatalf("iter %d: %v", i, err)
		}
		dec, err := zstdDecodeForTest(out)
		if err != nil || !bytes.Equal(dec, in) {
			t.Fatalf("iter %d: round-trip failed", i)
		}
	}
}

// zstdDecodeForTest decompresses bytes produced by zstdEncoder for use
// in tests. Lives in compress_test.go to avoid polluting the production
// API with a Decode method (the real receiver lives in another repo;
// the testserver has its own decoder).
func zstdDecodeForTest(b []byte) ([]byte, error) {
	r, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return r.DecodeAll(b, nil)
}
