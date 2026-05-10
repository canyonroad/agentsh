//go:build linux

package postgres

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// timeNow is package-level so tests can override it. Today no test does.
var timeNow = time.Now

// unixListener wraps a net.UnixListener with the Plan 04a setup contract:
// remove stale socket → bind → chmod 0700. On Close, unlinks the socket.
type unixListener struct {
	path string
	ln   *net.UnixListener
}

func bindUnixListener(path string) (*unixListener, error) {
	parent := filepath.Dir(path)
	fi, err := os.Stat(parent)
	if err != nil {
		return nil, fmt.Errorf("stat listener parent dir %q: %w", parent, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("listener parent %q is not a directory", parent)
	}
	// Remove stale socket from a prior crash. Existing non-socket file is a
	// hard error to avoid clobbering operator data.
	if existing, err := os.Stat(path); err == nil {
		if existing.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("listener path %q exists and is not a socket", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket %q: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat listener path %q: %w", path, err)
	}
	addr, err := net.ResolveUnixAddr("unix", path)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", path, err)
	}
	ln, err := net.ListenUnix("unix", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %q: %w", path, err)
	}
	if err := os.Chmod(path, 0o700); err != nil {
		ln.Close()
		os.Remove(path)
		return nil, fmt.Errorf("chmod 0700 %q: %w", path, err)
	}
	return &unixListener{path: path, ln: ln}, nil
}

// Accept blocks until a connection arrives or ctx is cancelled. Cancellation
// latency is bounded by the 250ms accept deadline (we bump it forward in
// the loop).
func (l *unixListener) Accept(ctx context.Context) (net.Conn, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_ = l.ln.SetDeadline(timeNow().Add(250 * time.Millisecond))
		conn, err := l.ln.AcceptUnix()
		if err == nil {
			return conn, nil
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			continue
		}
		return nil, err
	}
}

func (l *unixListener) Close() error {
	err := l.ln.Close()
	if rmErr := os.Remove(l.path); rmErr != nil && !os.IsNotExist(rmErr) {
		if err == nil {
			err = fmt.Errorf("remove %q: %w", l.path, rmErr)
		}
	}
	return err
}

// activeConns is a small concurrent set of in-flight conns the Server cancels
// at Shutdown. The set is keyed by conn pointer; conn handlers Add themselves
// at start and Remove themselves on return.
type activeConns struct {
	mu sync.Mutex
	m  map[net.Conn]struct{}
}

func newActiveConns() *activeConns { return &activeConns{m: make(map[net.Conn]struct{})} }

func (a *activeConns) Add(c net.Conn) {
	a.mu.Lock()
	a.m[c] = struct{}{}
	a.mu.Unlock()
}

func (a *activeConns) Remove(c net.Conn) {
	a.mu.Lock()
	delete(a.m, c)
	a.mu.Unlock()
}

func (a *activeConns) CloseAll() {
	a.mu.Lock()
	for c := range a.m {
		_ = c.Close()
	}
	a.mu.Unlock()
}

func (a *activeConns) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.m)
}
