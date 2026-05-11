//go:build linux

package postgres

import (
	"context"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestProxyConn_StubReturnsClean(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	srv, err := New(Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/_unused.sock"},
			Service:  policy.DBService{Name: "appdb", TLSMode: "terminate_reissue"},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		pc := newProxyConn(srv, srv.cfg.Services[0], a, 1000)
		_ = pc.run(ctx)
	}()
	b.Close()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("proxyConn.run did not return after client disconnect")
	}
}
