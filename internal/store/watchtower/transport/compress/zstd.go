package compress

import (
	"fmt"

	"github.com/klauspost/compress/zstd"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// minZstdLevel and maxZstdLevel mirror the canonical zstd CLI's
// supported range. klauspost/compress collapses these into four
// SpeedFastest..SpeedBestCompression buckets internally and does not
// itself reject out-of-range integers; we enforce the bounds here so
// that operator-facing config rejects nonsense values rather than
// silently snapping them to the best-compression bucket.
const (
	minZstdLevel = 1
	maxZstdLevel = 22
)

type zstdEncoder struct {
	enc *zstd.Encoder
}

func newZstdEncoder(level int) (Encoder, error) {
	if level < minZstdLevel || level > maxZstdLevel {
		return nil, fmt.Errorf("compress/zstd: level %d out of range [%d,%d]", level, minZstdLevel, maxZstdLevel)
	}
	enc, err := zstd.NewWriter(nil,
		zstd.WithEncoderLevel(zstd.EncoderLevelFromZstd(level)),
		zstd.WithEncoderConcurrency(1),
	)
	if err != nil {
		return nil, fmt.Errorf("compress/zstd: NewWriter: %w", err)
	}
	return &zstdEncoder{enc: enc}, nil
}

func (z *zstdEncoder) Algo() wtpv1.Compression { return wtpv1.Compression_COMPRESSION_ZSTD }

func (z *zstdEncoder) Encode(uncompressed []byte) ([]byte, error) {
	// EncodeAll is the documented one-shot, allocation-conservative API
	// on a *zstd.Encoder constructed with a nil writer; it is safe for
	// repeated serial use on the same encoder.
	return z.enc.EncodeAll(uncompressed, nil), nil
}
