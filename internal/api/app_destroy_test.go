package api

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/events"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/internal/store/composite"
	"github.com/agentsh/agentsh/internal/trash"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/go-chi/chi/v5"
)

type memEventStore struct{}

func (memEventStore) AppendEvent(ctx context.Context, ev types.Event) error { return nil }
func (memEventStore) QueryEvents(ctx context.Context, q types.EventQuery) ([]types.Event, error) {
	return nil, nil
}
func (memEventStore) Close() error { return nil }

func TestDestroySessionPurgesTrash(t *testing.T) {
	workspace := t.TempDir()
	trashDir := filepath.Join(workspace, ".agentsh_trash")

	cfg := &config.Config{}
	enabled := true
	cfg.Sandbox.FUSE.Audit.Enabled = &enabled
	cfg.Sandbox.FUSE.Audit.TrashPath = ".agentsh_trash"
	cfg.Sandbox.FUSE.Audit.TTL = "0"
	cfg.Sandbox.FUSE.Audit.Quota = "0"

	mgr := session.NewManager(5)
	s, err := mgr.CreateWithID("sess1", workspace, "default")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}

	// Create a trashed file for the session.
	src := filepath.Join(workspace, "tmp.txt")
	if err := os.WriteFile(src, []byte("data"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if _, err := trash.Divert(src, trash.Config{TrashDir: trashDir, Session: s.ID}); err != nil {
		t.Fatalf("divert: %v", err)
	}
	if entries, _ := trash.List(trashDir); len(entries) == 0 {
		t.Fatalf("expected trash entry before destroy")
	}

	app := NewApp(cfg, mgr, composite.New(memEventStore{}, nil), nil, events.NewBroker(), nil, nil, nil, nil, nil)

	req := httptest.NewRequest("DELETE", "/api/v1/sessions/sess1", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", "sess1")
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))
	rr := httptest.NewRecorder()

	app.destroySession(rr, req)

	if rr.Code != 204 {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if entries, _ := trash.List(trashDir); len(entries) != 0 {
		t.Fatalf("expected trash purged on destroy, got %d entries", len(entries))
	}
}
