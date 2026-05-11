//go:build linux

package postgres

import (
	"context"
	"io"
	"net"
)

// bytePump runs a symmetric bidirectional copy between a and b. Returns
// when either side closes or ctx is done. On ctx cancel, both conns are
// closed to unblock the in-flight Reads.
//
// The returned error is the first non-nil error from either direction, or
// ctx.Err() on cancel. io.EOF / io.ErrClosedPipe / net.ErrClosed are
// considered normal terminations and surfaced as nil.
func bytePump(ctx context.Context, a, b net.Conn) error {
	errCh := make(chan error, 2)
	go func() {
		_, err := io.Copy(a, b) // b → a
		errCh <- err
	}()
	go func() {
		_, err := io.Copy(b, a) // a → b
		errCh <- err
	}()

	closeBoth := func() {
		_ = a.Close()
		_ = b.Close()
	}

	for done := 0; done < 2; done++ {
		select {
		case err := <-errCh:
			if done == 0 {
				closeBoth()
			}
			if err != nil && !isNormalCloseErr(err) {
				<-errCh
				return err
			}
		case <-ctx.Done():
			closeBoth()
			<-errCh
			<-errCh
			return ctx.Err()
		}
	}
	return nil
}

func isNormalCloseErr(err error) bool {
	return err == io.EOF || err == io.ErrClosedPipe || err == net.ErrClosed
}
