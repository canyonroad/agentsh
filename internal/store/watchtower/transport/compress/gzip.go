package compress

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"sync"

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
	level int
	pool  sync.Pool // values are *gzip.Writer
}

func newGzipEncoder(level int) (Encoder, error) {
	if level < minGzipLevel || level > maxGzipLevel {
		return nil, fmt.Errorf("compress/gzip: level %d out of range [%d,%d]", level, minGzipLevel, maxGzipLevel)
	}
	g := &gzipEncoder{level: level}
	g.pool.New = func() any {
		w, err := gzip.NewWriterLevel(nil, level)
		if err != nil {
			// Already validated via the constructor; this branch is
			// unreachable in practice but we surface the error rather
			// than panic so a misconfigured-level regression would be
			// visible at Encode time.
			return err
		}
		return w
	}
	return g, nil
}

func (g *gzipEncoder) Algo() wtpv1.Compression { return wtpv1.Compression_COMPRESSION_GZIP }

func (g *gzipEncoder) Encode(uncompressed []byte) ([]byte, error) {
	v := g.pool.Get()
	w, ok := v.(*gzip.Writer)
	if !ok {
		// Pool New returned a non-writer (an error from NewWriterLevel).
		// Propagate it; do not put a non-writer back into the pool.
		if err, isErr := v.(error); isErr {
			return nil, fmt.Errorf("compress/gzip: pool: %w", err)
		}
		return nil, fmt.Errorf("compress/gzip: pool returned %T", v)
	}
	defer g.pool.Put(w)
	var buf bytes.Buffer
	w.Reset(&buf)
	if _, err := w.Write(uncompressed); err != nil {
		return nil, fmt.Errorf("compress/gzip: write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("compress/gzip: close: %w", err)
	}
	return buf.Bytes(), nil
}
