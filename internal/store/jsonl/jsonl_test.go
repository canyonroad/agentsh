package jsonl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestAppendAndRotate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	store, err := New(path, 1, 2) // 1 MB limit to make rotation feasible
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// First append creates file.
	if err := store.AppendEvent(context.Background(), types.Event{ID: "1", Type: "a"}); err != nil {
		t.Fatalf("AppendEvent: %v", err)
	}

	// Force size beyond threshold then trigger rotation on next append.
	payload := strings.Repeat("x", 2<<20) // >1MB
	if err := store.AppendEvent(context.Background(), types.Event{ID: "2", Type: payload}); err != nil {
		t.Fatalf("AppendEvent large: %v", err)
	}
	if err := store.AppendEvent(context.Background(), types.Event{ID: "3", Type: "b"}); err != nil {
		t.Fatalf("AppendEvent post-rotate: %v", err)
	}

	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatalf("expected rotated backup .1, got err: %v", err)
	}
}

func TestQueryNotSupported(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")
	store, err := New(path, 1, 1)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if _, err := store.QueryEvents(context.Background(), types.EventQuery{}); err == nil {
		t.Fatal("expected query error")
	}
}
