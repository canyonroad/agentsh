package jsonl

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestSync_FlushesToDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	data := []byte(`{"type":"test","id":"1"}`)
	if err := s.WriteRaw(context.Background(), data); err != nil {
		t.Fatal(err)
	}

	if err := s.Sync(); err != nil {
		t.Fatalf("Sync() error = %v", err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, data) {
		t.Fatalf("file does not contain written data")
	}
}

func TestSync_NilFile(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	s.Close()

	if err := s.Sync(); err != nil {
		t.Fatalf("Sync() on closed store should return nil, got %v", err)
	}
}

func TestWriteRaw_NoSyncWhenDisabled(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.SetSyncOnWrite(false)

	data := []byte(`{"type":"test","id":"nosync"}`)
	if err := s.WriteRaw(context.Background(), data); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(content, data) {
		t.Fatalf("file does not contain written data")
	}
}

func TestWriteRaw_And_Sync_Concurrent(t *testing.T) {
	dir := t.TempDir()
	s, err := New(filepath.Join(dir, "audit.jsonl"), 10*1024*1024, 3)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	s.SetSyncOnWrite(false)

	const numWriters = 4
	const eventsPerWriter = 50

	var wg sync.WaitGroup

	for w := 0; w < numWriters; w++ {
		wg.Add(1)
		go func(writerID int) {
			defer wg.Done()
			for i := 0; i < eventsPerWriter; i++ {
				data := []byte(fmt.Sprintf(`{"writer":%d,"seq":%d}`, writerID, i))
				if err := s.WriteRaw(context.Background(), data); err != nil {
					t.Errorf("WriteRaw error: %v", err)
				}
			}
		}(w)
	}

	stopSync := make(chan struct{})
	var syncerWg sync.WaitGroup
	syncerWg.Add(1)
	go func() {
		defer syncerWg.Done()
		for {
			select {
			case <-stopSync:
				return
			default:
				_ = s.Sync()
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	wg.Wait()
	close(stopSync)
	syncerWg.Wait()

	if err := s.Sync(); err != nil {
		t.Fatal(err)
	}

	content, err := os.ReadFile(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSpace(content), []byte("\n"))
	if len(lines) != numWriters*eventsPerWriter {
		t.Fatalf("got %d lines, want %d", len(lines), numWriters*eventsPerWriter)
	}
	for i, line := range lines {
		var obj map[string]any
		if err := json.Unmarshal(line, &obj); err != nil {
			t.Fatalf("line %d: invalid JSON: %v", i, err)
		}
	}
}
