//go:build linux

package api

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/db/events"
	dbpolicy "github.com/agentsh/agentsh/internal/db/policy"
	dbservice "github.com/agentsh/agentsh/internal/db/service"
)

func TestStartDBProxy_Off_NoListener(t *testing.T) {
	dir := t.TempDir()
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityOff,
		Services:       nil,
		StateDir:       dir,
		Sink:           &events.SyncSink{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDBProxy(ctx, deps)
	if err != nil {
		t.Fatalf("startDBProxy: %v", err)
	}
	if srv == nil {
		t.Fatal("startDBProxy returned nil")
	}
	if err := srv.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestStartDBProxy_Observe_BindsListener(t *testing.T) {
	dir := t.TempDir()
	sockPath := filepath.Join(dir, "db-services", "appdb.sock")
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityObserve,
		Services: []dbProxyService{{
			Name:       "appdb",
			DBService:  dbpolicy.DBService{Name: "appdb", Family: "postgres", Dialect: "postgres", Upstream: "127.0.0.1:5432", TLSMode: "terminate_reissue"},
			ListenKind: "unix",
			ListenPath: sockPath,
		}},
		StateDir: dir,
		Sink:     &events.SyncSink{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv, err := startDBProxy(ctx, deps)
	if err != nil {
		t.Fatalf("startDBProxy: %v", err)
	}
	defer srv.Shutdown(context.Background())

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("listener never bound at %q", sockPath)
}

func TestStartDBProxy_Observe_NoServices_Errors(t *testing.T) {
	deps := dbProxyDeps{
		Unavoidability: dbservice.UnavoidabilityObserve,
		Services:       nil,
		StateDir:       t.TempDir(),
		Sink:           &events.SyncSink{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := startDBProxy(ctx, deps); err == nil {
		t.Fatal("startDBProxy (observe, no services): want error, got nil")
	}
}
