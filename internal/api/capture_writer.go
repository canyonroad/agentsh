package api

import (
	"bytes"
)

type captureWriter struct {
	max int64

	onChunk func([]byte) error

	buf       bytes.Buffer
	total     int64
	truncated bool
}

func newCaptureWriter(max int64, onChunk func([]byte) error) *captureWriter {
	return &captureWriter{max: max, onChunk: onChunk}
}

func (w *captureWriter) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	w.total += int64(len(p))
	if w.onChunk != nil {
		_ = w.onChunk(p)
	}

	if int64(w.buf.Len()) >= w.max {
		w.truncated = true
		return len(p), nil
	}
	remain := w.max - int64(w.buf.Len())
	if int64(len(p)) <= remain {
		_, _ = w.buf.Write(p)
		return len(p), nil
	}
	_, _ = w.buf.Write(p[:remain])
	w.truncated = true
	return len(p), nil
}

func (w *captureWriter) Bytes() []byte {
	if w == nil {
		return nil
	}
	return w.buf.Bytes()
}
