//go:build linux

package postgres

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	"github.com/agentsh/agentsh/internal/db/policy"
	"github.com/agentsh/agentsh/internal/db/service"
)

func TestServer_New_ZeroConfigRejected(t *testing.T) {
	_, err := New(Config{})
	if err == nil {
		t.Fatal("New(Config{}): want error, got nil")
	}
}

func TestServer_OffMode_StartIsNoop(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityOff,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	s, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil server")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatalf("Start (off mode): %v", err)
	}
	if err := s.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown (off mode): %v", err)
	}
}

func TestServer_ObserveMode_RequiresAtLeastOneService(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
		Logger:         slog.New(slog.NewTextHandler(testWriter{t}, nil)),
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (observe, no services): want error, got nil")
	}
}

func TestServer_New_MissingSink(t *testing.T) {
	cfg := Config{
		Unavoidability: service.UnavoidabilityObserve,
		StateDir:       t.TempDir(),
		Services: []Service{{
			Name:     "appdb",
			Family:   "postgres",
			Dialect:  "postgres",
			Upstream: "db.internal:5432",
			TLSMode:  "terminate_reissue",
			Listen:   ServiceListener{Kind: "unix", Path: "/tmp/test-appdb.sock"},
			Service:  policy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "db.internal:5432", TLSMode: "terminate_reissue"},
		}},
	}
	_, err := New(cfg)
	if err == nil {
		t.Fatal("New (no sink): want error, got nil")
	}
}

// testWriter wires slog output into t.Log so tests preserve context on failure.
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) { w.t.Log(string(p)); return len(p), nil }
