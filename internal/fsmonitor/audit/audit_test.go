package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func readLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open log: %v", err)
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("scan: %v", err)
	}
	return lines
}

func TestLoggerDropOldest(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewWithOptions(path, 1, true, Options{DisableWorker: true})
	if err != nil {
		t.Fatal(err)
	}

	if err := l.Log(Event{Op: "first"}); err != nil {
		t.Fatalf("log first: %v", err)
	}
	if err := l.Log(Event{Op: "second"}); err != nil {
		t.Fatalf("log second: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line after drop-oldest, got %d", len(lines))
	}
	var ev Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Op != "second" {
		t.Fatalf("expected last event kept, got %q", ev.Op)
	}
}

func TestLoggerStrictQueueFull(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := NewWithOptions(path, 1, false, Options{DisableWorker: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Op: "first"}); err != nil {
		t.Fatalf("log first: %v", err)
	}
	if err := l.Log(Event{Op: "second"}); err == nil {
		t.Fatalf("expected queue full error")
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var ev Event
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if ev.Op != "first" {
		t.Fatalf("expected first event kept, got %q", ev.Op)
	}
}

func TestLoggerMetadata(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l, err := New(path, 2, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Log(Event{Op: "unlink", Session: "sess-1"}); err != nil {
		t.Fatalf("log: %v", err)
	}
	if err := l.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	lines := readLines(t, path)
	if len(lines) != 1 {
		t.Fatalf("expected 1 line, got %d", len(lines))
	}
	var ev map[string]interface{}
	if err := json.Unmarshal([]byte(lines[0]), &ev); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := ev["pid"]; !ok {
		t.Fatalf("expected pid in event")
	}
	if _, ok := ev["uid"]; !ok {
		t.Fatalf("expected uid in event")
	}
	if ts, ok := ev["ts"].(string); !ok || ts == "" {
		t.Fatalf("expected ts set, got %v", ev["ts"])
	}
	if ev["session"] != "sess-1" {
		t.Fatalf("session mismatch: got %v", ev["session"])
	}
}

func TestLoggerUnavailableSink(t *testing.T) {
	// /dev/null/anything should fail to open (ENOTDIR) on Unix-like systems.
	path := filepath.Join("/dev/null", "audit.log")
	if runtime.GOOS == "windows" {
		t.Skip("skip unavailable sink test on windows")
	}
	if _, err := New(path, 1, true); err == nil {
		t.Fatalf("expected error creating logger with invalid path")
	}
}
