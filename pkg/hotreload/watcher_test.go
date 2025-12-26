package hotreload

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type mockLoader struct {
	mu         sync.Mutex
	loadCount  int
	loadPaths  []string
	validateFn func(path string) error
	loadFn     func(path string) error
}

func (m *mockLoader) LoadFromPath(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadCount++
	m.loadPaths = append(m.loadPaths, path)
	if m.loadFn != nil {
		return m.loadFn(path)
	}
	return nil
}

func (m *mockLoader) Validate(path string) error {
	if m.validateFn != nil {
		return m.validateFn(path)
	}
	return nil
}

func (m *mockLoader) LoadCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadCount
}

func TestNewPolicyWatcher(t *testing.T) {
	loader := &mockLoader{}

	t.Run("requires policy directory", func(t *testing.T) {
		_, err := NewPolicyWatcher(WatcherConfig{
			Loader: loader,
		})
		if err == nil {
			t.Error("expected error for empty policy directory")
		}
	})

	t.Run("requires loader", func(t *testing.T) {
		_, err := NewPolicyWatcher(WatcherConfig{
			PolicyDir: "/tmp",
		})
		if err == nil {
			t.Error("expected error for nil loader")
		}
	})

	t.Run("creates watcher", func(t *testing.T) {
		dir := t.TempDir()
		watcher, err := NewPolicyWatcher(WatcherConfig{
			PolicyDir: dir,
			Loader:    loader,
		})
		if err != nil {
			t.Fatalf("NewPolicyWatcher error: %v", err)
		}
		if watcher == nil {
			t.Fatal("expected non-nil watcher")
		}
	})
}

func TestPolicyWatcher_Start(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer watcher.Stop()

	// Starting again should error
	if err := watcher.Start(ctx); err == nil {
		t.Error("expected error starting twice")
	}
}

func TestPolicyWatcher_FileChange(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	var changedPath string
	var changeMu sync.Mutex
	changed := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
		Debounce:  50 * time.Millisecond,
		OnChange: func(path string, err error) {
			changeMu.Lock()
			changedPath = path
			changeMu.Unlock()
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer watcher.Stop()

	// Create a policy file
	policyFile := filepath.Join(dir, "test.yaml")
	if err := os.WriteFile(policyFile, []byte("test: true"), 0644); err != nil {
		t.Fatalf("writing policy file: %v", err)
	}

	// Wait for the change to be detected
	select {
	case <-changed:
		changeMu.Lock()
		if changedPath != policyFile {
			t.Errorf("changed path = %q, want %q", changedPath, policyFile)
		}
		changeMu.Unlock()
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for change notification")
	}

	// Check loader was called
	if loader.LoadCount() == 0 {
		t.Error("expected loader to be called")
	}
}

func TestPolicyWatcher_Stats(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher error: %v", err)
	}

	stats := watcher.Stats()
	if stats.ReloadsTotal != 0 {
		t.Errorf("ReloadsTotal = %d, want 0", stats.ReloadsTotal)
	}
}

func TestPolicyWatcher_ValidationFailure(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{
		validateFn: func(path string) error {
			return os.ErrInvalid
		},
	}

	var gotErr error
	changed := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
		Debounce:  50 * time.Millisecond,
		OnChange: func(path string, err error) {
			gotErr = err
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer watcher.Stop()

	// Create a policy file
	policyFile := filepath.Join(dir, "invalid.yaml")
	os.WriteFile(policyFile, []byte("invalid"), 0644)

	// Wait for the change
	select {
	case <-changed:
		if gotErr == nil {
			t.Error("expected error in onChange callback")
		}
	case <-time.After(500 * time.Millisecond):
		t.Error("timeout waiting for change notification")
	}

	// Check stats
	stats := watcher.Stats()
	if stats.ReloadsFailed == 0 {
		t.Error("expected ReloadsFailed > 0")
	}
}

func TestPolicyWatcher_TriggerReload(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	// Create policy file before starting
	policyFile := filepath.Join(dir, "policy.yaml")
	os.WriteFile(policyFile, []byte("test: true"), 0644)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})
	if err != nil {
		t.Fatalf("NewPolicyWatcher error: %v", err)
	}

	// Can't trigger before starting
	if err := watcher.TriggerReload(); err == nil {
		t.Error("expected error triggering before start")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := watcher.Start(ctx); err != nil {
		t.Fatalf("Start error: %v", err)
	}
	defer watcher.Stop()

	// Trigger manual reload
	if err := watcher.TriggerReload(); err != nil {
		t.Errorf("TriggerReload error: %v", err)
	}

	// Wait for reload to process
	time.Sleep(100 * time.Millisecond)

	if loader.LoadCount() == 0 {
		t.Error("expected loader to be called after TriggerReload")
	}
}

func TestIsPolicyFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"policy.yaml", true},
		{"policy.yml", true},
		{"config.json", true},
		{"script.sh", false},
		{"README.md", false},
		{"data.txt", false},
		{".yaml", true},
	}

	for _, tt := range tests {
		got := isPolicyFile(tt.path)
		if got != tt.want {
			t.Errorf("isPolicyFile(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}
