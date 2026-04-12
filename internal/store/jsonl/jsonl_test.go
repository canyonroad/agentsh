package jsonl

import (
	"context"
	"errors"
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

func TestWriteRaw(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	store, err := New(path, 1, 2)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	raw := []byte(`{"id":"1","type":"test","integrity":{"sequence":1,"prev_hash":"","entry_hash":"abc123"}}`)
	if err := store.WriteRaw(context.Background(), raw); err != nil {
		t.Fatalf("WriteRaw: %v", err)
	}

	// Read back the file and verify exact bytes + newline
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	expected := string(raw) + "\n"
	if string(data) != expected {
		t.Errorf("file content = %q, want %q", string(data), expected)
	}
}

func TestWriteRaw_TriggersRotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	store, err := New(path, 1, 2) // 1 MB limit
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	// Write >1MB via WriteRaw to trigger rotation
	big := []byte(strings.Repeat("x", 2<<20))
	if err := store.WriteRaw(context.Background(), big); err != nil {
		t.Fatalf("WriteRaw large: %v", err)
	}
	// Next write should trigger rotation
	if err := store.WriteRaw(context.Background(), []byte(`{"after":"rotate"}`)); err != nil {
		t.Fatalf("WriteRaw post-rotate: %v", err)
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

func TestJSONLStore_RotationKeepsAuditLockHeld(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "events.log")

	store, err := New(path, 1, 2)
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	payload := strings.Repeat("x", 2<<20)
	if err := store.AppendEvent(context.Background(), types.Event{ID: "1", Type: payload}); err != nil {
		t.Fatalf("AppendEvent large: %v", err)
	}
	if err := store.AppendEvent(context.Background(), types.Event{ID: "2", Type: "rotate"}); err != nil {
		t.Fatalf("AppendEvent rotate: %v", err)
	}

	lockFile, err := AcquireLock(path)
	if err == nil {
		_ = ReleaseLock(lockFile)
		t.Fatal("AcquireLock() error = nil, want lock contention while store is open")
	}
	if !errors.Is(err, ErrLocked) {
		t.Fatalf("AcquireLock() error = %v, want ErrLocked", err)
	}
}
