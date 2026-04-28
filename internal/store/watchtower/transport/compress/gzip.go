package compress

import (
	"bytes"
	"compress/gzip"
	"fmt"

	wtpv1 "github.com/agentsh/agentsh/proto/canyonroad/wtp/v1"
)

// minGzipLevel and maxGzipLevel mirror the stdlib compress/gzip
// supported range. We enforce the bounds here so operator-facing
// config rejects nonsense values rather than letting them reach
// gzip.NewWriterLevel (which itself returns an error for invalid
// levels — but config-time rejection produces a clearer message).
const (
	minGzipLevel = 1
	maxGzipLevel = 9
)

type gzipEncoder struct {
	w *gzip.Writer
}

func newGzipEncoder(level int) (Encoder, error) {
	if level < minGzipLevel || level > maxGzipLevel {
		return nil, fmt.Errorf("compress/gzip: level %d out of range [%d,%d]", level, minGzipLevel, maxGzipLevel)
	}
	w, err := gzip.NewWriterLevel(nil, level)
	if err != nil {
		return nil, fmt.Errorf("compress/gzip: NewWriterLevel: %w", err)
	}
	return &gzipEncoder{w: w}, nil
}

func (g *gzipEncoder) Algo() wtpv1.Compression { return wtpv1.Compression_COMPRESSION_GZIP }

func (g *gzipEncoder) Encode(uncompressed []byte) ([]byte, error) {
	// Single-goroutine-per-Transport contract (see compress.go package
	// doc) lets us reuse a single writer via Reset across calls without
	// pool plumbing. Reset reinitializes the writer's state — including
	// recovery from any prior Write/Close error — so we always start
	// from a clean state per batch.
	var buf bytes.Buffer
	g.w.Reset(&buf)
	if _, err := g.w.Write(uncompressed); err != nil {
		return nil, fmt.Errorf("compress/gzip: write: %w", err)
	}
	if err := g.w.Close(); err != nil {
		return nil, fmt.Errorf("compress/gzip: close: %w", err)
	}
	return buf.Bytes(), nil
}
