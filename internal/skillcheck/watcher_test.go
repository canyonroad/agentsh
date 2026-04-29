package skillcheck

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatcher_DetectsNewSkill(t *testing.T) {
	root := t.TempDir()
	events := make(chan string, 4)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{root},
		Debounce: 50 * time.Millisecond,
		OnSkill: func(skillDir string) {
			events <- skillDir
		},
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()

	// Allow watcher to register root watch.
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "test-skill")
	if err := os.MkdirAll(skillDir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("---\nname: test\n---\n"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case got := <-events:
		if got != skillDir {
			t.Errorf("got=%s want=%s", got, skillDir)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not detect new skill within 2s")
	}
}

func TestWatcher_DebounceCoalesces(t *testing.T) {
	root := t.TempDir()
	events := make(chan string, 16)
	w, err := NewWatcher(WatcherConfig{
		Roots:    []string{root},
		Debounce: 200 * time.Millisecond,
		OnSkill:  func(skillDir string) { events <- skillDir },
	})
	if err != nil {
		t.Fatalf("NewWatcher: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go w.Run(ctx)
	defer w.Close()
	time.Sleep(100 * time.Millisecond)

	skillDir := filepath.Join(root, "skill-a")
	os.MkdirAll(skillDir, 0o755)
	for i := 0; i < 5; i++ {
		os.WriteFile(filepath.Join(skillDir, "SKILL.md"), []byte("v"), 0o644)
		time.Sleep(20 * time.Millisecond)
	}

	time.Sleep(500 * time.Millisecond)
	got := drain(events)
	if got != 1 {
		t.Errorf("expected 1 debounced event, got %d", got)
	}
}

func drain(ch chan string) int {
	n := 0
	for {
		select {
		case <-ch:
			n++
		default:
			return n
		}
	}
}
