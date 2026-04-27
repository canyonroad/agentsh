package compress

import "errors"

func newGzipEncoder(level int) (Encoder, error) {
	return nil, errors.New("compress: gzip not yet implemented")
}
