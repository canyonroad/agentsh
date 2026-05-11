//go:build linux

package postgres

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// fakeUpstreamScript is one server-side script applied to a single inbound
// connection. The script is given a *pgproto3.Backend bound to the conn and
// returns when the script considers the connection done. The conn is
// closed by the helper afterwards.
type fakeUpstreamScript func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error

// fakeUpstreamOpt configures newFakeUpstream.
type fakeUpstreamOpt func(*fakeUpstreamConfig)

type fakeUpstreamConfig struct {
	useTLS bool
	tlsCfg *tls.Config
	script fakeUpstreamScript
}

// withFakeUpstreamTLS makes the upstream listener wrap each conn in TLS.
func withFakeUpstreamTLS(cfg *tls.Config) fakeUpstreamOpt {
	return func(c *fakeUpstreamConfig) {
		c.useTLS = true
		c.tlsCfg = cfg
	}
}

// withFakeUpstreamScript supplies the per-conn server script.
func withFakeUpstreamScript(s fakeUpstreamScript) fakeUpstreamOpt {
	return func(c *fakeUpstreamConfig) { c.script = s }
}

// fakeUpstream is a one-listener fake. Address() returns the dial target;
// AcceptedConns() reports how many connections have been accepted so far.
type fakeUpstream struct {
	addr  string
	mu    sync.Mutex
	conns int
	done  chan struct{}
}

func (u *fakeUpstream) Address() string { return u.addr }

// newFakeUpstream binds 127.0.0.1:0 and runs the provided script for each
// inbound connection. The listener is closed via t.Cleanup. Scripts that
// return an error get t.Errorf'd on the caller's goroutine — failures are
// not silenced.
func newFakeUpstream(t *testing.T, opts ...fakeUpstreamOpt) *fakeUpstream {
	t.Helper()
	cfg := fakeUpstreamConfig{
		script: func(t *testing.T, be *pgproto3.Backend, conn net.Conn) error { return nil },
	}
	for _, o := range opts {
		o(&cfg)
	}

	var ln net.Listener
	var err error
	if cfg.useTLS {
		ln, err = tls.Listen("tcp", "127.0.0.1:0", cfg.tlsCfg)
	} else {
		ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatalf("newFakeUpstream: listen: %v", err)
	}
	u := &fakeUpstream{addr: ln.Addr().String(), done: make(chan struct{})}
	t.Cleanup(func() {
		_ = ln.Close()
		close(u.done)
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					t.Logf("fakeUpstream accept: %v", err)
				}
				return
			}
			u.mu.Lock()
			u.conns++
			u.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				be := pgproto3.NewBackend(c, c)
				if err := cfg.script(t, be, c); err != nil && !errors.Is(err, io.EOF) {
					t.Errorf("fakeUpstream script: %v", err)
				}
			}(c)
		}
	}()
	return u
}

// AcceptedConns returns the count of connections accepted so far.
func (u *fakeUpstream) AcceptedConns() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.conns
}
