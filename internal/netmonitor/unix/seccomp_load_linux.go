//go:build linux && cgo

package unix

import (
	"bytes"
	"fmt"
	"io"
	"os"

	seccomp "github.com/seccomp/libseccomp-golang"
)

// exportFilterBPF serializes a libseccomp filter into its kernel-ready
// BPF program bytes by piping ExportBPF through a pipe2 reader, then
// reading the read end into a buffer. This deliberately avoids
// ExportBPFMem (a libseccomp 2.6 function stubbed to -EOPNOTSUPP when
// libseccomp-golang is compiled against 2.5 headers) so the same code
// works against system libseccomp >=2.0.
func exportFilterBPF(filt *seccomp.ScmpFilter) ([]byte, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("seccomp export: pipe: %w", err)
	}

	type result struct {
		buf []byte
		err error
	}
	done := make(chan result, 1)
	go func() {
		var buf bytes.Buffer
		_, copyErr := io.Copy(&buf, r)
		_ = r.Close()
		done <- result{buf: buf.Bytes(), err: copyErr}
	}()

	exportErr := filt.ExportBPF(w)
	_ = w.Close()
	res := <-done

	if exportErr != nil {
		return nil, fmt.Errorf("seccomp export: %w", exportErr)
	}
	if res.err != nil {
		return nil, fmt.Errorf("seccomp export: read pipe: %w", res.err)
	}
	return res.buf, nil
}
