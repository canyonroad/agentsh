package compress

import "errors"

func newZstdEncoder(level int) (Encoder, error) {
	return nil, errors.New("compress: zstd not yet implemented")
}
