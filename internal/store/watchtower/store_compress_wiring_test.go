package watchtower_test

import (
	"context"
	"testing"

	watchtower "github.com/agentsh/agentsh/internal/store/watchtower"
	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// TestOptions_Compression_WireThrough verifies that
// watchtower.Options.CompressionAlgo is threaded into the Store and all
// the way down to the Transport's compressor.
func TestOptions_Compression_WireThrough(t *testing.T) {
	cases := []struct {
		algo     string
		wantAlgo wtpv1.Compression
	}{
		{"", wtpv1.Compression_COMPRESSION_NONE},
		{"none", wtpv1.Compression_COMPRESSION_NONE},
		{"zstd", wtpv1.Compression_COMPRESSION_ZSTD},
		{"gzip", wtpv1.Compression_COMPRESSION_GZIP},
	}
	for _, tc := range cases {
		t.Run(tc.algo, func(t *testing.T) {
			opts := validOpts(t.TempDir())
			opts.CompressionAlgo = tc.algo
			opts.ZstdLevel = 3
			opts.GzipLevel = 6

			s, err := watchtower.New(context.Background(), opts)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			defer closeStore(t, s)

			if got := s.OptsCompressionAlgoForTest(); got != tc.algo {
				t.Errorf("OptsCompressionAlgoForTest() = %q, want %q", got, tc.algo)
			}

			if got := s.TransportCompressorAlgoForTest(); got != tc.wantAlgo {
				t.Errorf("TransportCompressorAlgoForTest() = %v, want %v (wire-through regressed)", got, tc.wantAlgo)
			}
		})
	}
}

// TestOptions_Compression_RejectsUnsupported verifies that an unknown
// CompressionAlgo causes watchtower.New to return an error rather than
// silently falling back to none.
func TestOptions_Compression_RejectsUnsupported(t *testing.T) {
	opts := validOpts(t.TempDir())
	opts.CompressionAlgo = "snappy"
	if _, err := watchtower.New(context.Background(), opts); err == nil {
		t.Fatal("New(CompressionAlgo=snappy): want error, got nil")
	}
}
