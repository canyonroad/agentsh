// Package compress provides per-batch compression encoders for the WTP
// transport. Each encoder is owned by a single Transport and produces
// the bytes that go into EventBatch.compressed_payload, paired with the
// matching wtpv1.Compression enum value the caller stamps into
// EventBatch.Compression.
//
// Concurrency: callers invoke Encode from a single goroutine per
// Transport (the run-state loop). Implementations need not be
// goroutine-safe, but the chosen primitives are safe for serial reuse
// across many batches.
package compress

import (
	"errors"
	"fmt"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// Encoder compresses a marshaled UncompressedEvents proto into the bytes
// that go into EventBatch.compressed_payload.
type Encoder interface {
	// Algo returns the Compression enum value this encoder produces.
	// Callers stamp this value into EventBatch.Compression.
	Algo() wtpv1.Compression

	// Encode compresses uncompressed. On error, callers MUST fall back
	// to emitting an uncompressed batch (fail-open) rather than dropping
	// the batch. The returned slice is owned by the caller.
	Encode(uncompressed []byte) ([]byte, error)
}

// noneEncoder is the sentinel returned when compression is disabled.
// Production callers branch on Algo() == COMPRESSION_NONE BEFORE invoking
// Encode; calling Encode on it is a programmer error and returns an
// error to fail loudly.
type noneEncoder struct{}

func newNoneEncoder() Encoder { return noneEncoder{} }

func (noneEncoder) Algo() wtpv1.Compression { return wtpv1.Compression_COMPRESSION_NONE }

func (noneEncoder) Encode([]byte) ([]byte, error) {
	return nil, errors.New("compress: noneEncoder.Encode invoked; callers must branch on Algo() == COMPRESSION_NONE")
}

// errUnsupportedAlgo is returned by NewEncoder for an algo string that
// is not one of "none" / "zstd" / "gzip". Validation upstream
// (config.validate) should prevent this from reaching NewEncoder, but
// the constructor returns the error rather than panicking as a
// defense-in-depth measure.
var errUnsupportedAlgo = errors.New("compress: unsupported algorithm")

// NewEncoder constructs an Encoder for the given algorithm and levels.
// algo must be one of "none", "zstd", "gzip"; an unrecognized value
// returns errUnsupportedAlgo. zstdLevel and gzipLevel are applied only
// when algo selects the corresponding codec; the other is ignored.
func NewEncoder(algo string, zstdLevel, gzipLevel int) (Encoder, error) {
	switch algo {
	case "none":
		return newNoneEncoder(), nil
	case "zstd":
		return newZstdEncoder(zstdLevel)
	case "gzip":
		return newGzipEncoder(gzipLevel)
	default:
		return nil, fmt.Errorf("%w: %q", errUnsupportedAlgo, algo)
	}
}
