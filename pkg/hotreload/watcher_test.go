package hotreload

import (
	"context"
	"fmt"
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

func TestIsInStagingDir(t *testing.T) {
	tests := []struct {
		path      string
		policyDir string
		want      bool
	}{
		{"/etc/agentsh/policies/.staging/foo.yaml", "/etc/agentsh/policies", true},
		{"/etc/agentsh/policies/.staging/foo.yaml.sig", "/etc/agentsh/policies", true},
		{"/etc/agentsh/policies/foo.yaml", "/etc/agentsh/policies", false},
		{"/etc/agentsh/policies/subdir/foo.yaml", "/etc/agentsh/policies", false},
		{"/other/.staging/foo.yaml", "/etc/agentsh/policies", false},
	}
	for _, tt := range tests {
		if got := isInStagingDir(tt.path, tt.policyDir); got != tt.want {
			t.Errorf("isInStagingDir(%q, %q) = %v, want %v", tt.path, tt.policyDir, got, tt.want)
		}
	}
}

func TestIsStagingRelevant(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"foo.yaml", true},
		{"foo.yml", true},
		{"foo.json", true},
		{"foo.yaml.sig", true},
		{"foo.yml.sig", true},
		{"foo.json.sig", true},
		{"foo.txt", false},
		{"foo.sig", false},
	}
	for _, tt := range tests {
		if got := isStagingRelevant(tt.path); got != tt.want {
			t.Errorf("isStagingRelevant(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestStagingPolicyPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/staging/foo.yaml", "/staging/foo.yaml"},
		{"/staging/foo.yaml.sig", "/staging/foo.yaml"},
		{"/staging/foo.yml.sig", "/staging/foo.yml"},
	}
	for _, tt := range tests {
		if got := stagingPolicyPath(tt.path); got != tt.want {
			t.Errorf("stagingPolicyPath(%q) = %q, want %q", tt.path, got, tt.want)
		}
	}
}

func TestPolicyWatcher_StagingFileDoesNotTriggerLiveReload(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}
	var onChangePaths []string
	var onChangeMu sync.Mutex
	changed := make(chan struct{}, 10)

	// Use a long staging debounce so promotion doesn't happen during the test window
	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 10 * time.Second,
		OnChange: func(path string, err error) {
			onChangeMu.Lock()
			onChangePaths = append(onChangePaths, path)
			onChangeMu.Unlock()
			select {
			case changed <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write a policy file to .staging/ — should NOT trigger onChange directly
	os.WriteFile(filepath.Join(stagingDir, "test.yaml"), []byte("test: true"), 0644)

	select {
	case <-changed:
		onChangeMu.Lock()
		t.Errorf("staging file should not trigger live reload onChange, got paths: %v", onChangePaths)
		onChangeMu.Unlock()
	case <-time.After(300 * time.Millisecond):
		// Expected: no change event within the window (staging debounce is 10s)
	}

	if loader.LoadCount() != 0 {
		t.Error("loader should not be called for staging files")
	}
}

func TestPolicyWatcher_CreatesStagingDirOnStart(t *testing.T) {
	dir := t.TempDir()
	loader := &mockLoader{}

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir: dir,
		Loader:    loader,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	stagingDir := filepath.Join(dir, ".staging")
	info, err := os.Stat(stagingDir)
	if err != nil {
		t.Fatalf(".staging dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Fatal(".staging is not a directory")
	}
}

func TestPolicyWatcher_StagingPromotesValidPolicy(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}

	stagingDone := make(chan struct{}, 1)
	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write policy to staging
	os.WriteFile(filepath.Join(stagingDir, "test.yaml"), []byte("test: true"), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for staging processing")
	}

	// Policy should have been moved to live dir
	liveFile := filepath.Join(dir, "test.yaml")
	data, err := os.ReadFile(liveFile)
	if err != nil {
		t.Fatalf("policy not promoted to live dir: %v", err)
	}
	if string(data) != "test: true" {
		t.Fatalf("policy content mismatch: %q", data)
	}

	// Staging file should be gone
	if _, err := os.Stat(filepath.Join(stagingDir, "test.yaml")); !os.IsNotExist(err) {
		t.Fatal("staged policy should have been removed after promotion")
	}

	// Check staging stats
	stats := watcher.Stats()
	if stats.StagingTotal == 0 {
		t.Error("expected StagingTotal > 0")
	}
	if stats.StagingSuccess == 0 {
		t.Error("expected StagingSuccess > 0")
	}
}

func TestPolicyWatcher_StagingValidationFailureLeavesFile(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{
		validateFn: func(path string) error {
			return fmt.Errorf("missing_signature: no .sig file")
		},
	}

	stagingDone := make(chan error, 1)
	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			stagingDone <- err
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	stagedFile := filepath.Join(stagingDir, "bad.yaml")
	os.WriteFile(stagedFile, []byte("bad: true"), 0644)

	select {
	case err := <-stagingDone:
		if err == nil {
			t.Fatal("expected validation error")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// File should remain in staging (not moved)
	if _, err := os.Stat(stagedFile); err != nil {
		t.Fatal("staged file should remain after validation failure")
	}

	// File should NOT appear in live dir
	if _, err := os.Stat(filepath.Join(dir, "bad.yaml")); !os.IsNotExist(err) {
		t.Fatal("failed policy should not appear in live dir")
	}
}

func TestPolicyWatcher_StagingPromotesSigFile(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}
	stagingDone := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write .sig first, then .yaml (recommended order)
	os.WriteFile(filepath.Join(stagingDir, "signed.yaml.sig"), []byte(`{"version":1}`), 0644)
	time.Sleep(10 * time.Millisecond)
	os.WriteFile(filepath.Join(stagingDir, "signed.yaml"), []byte("signed: true"), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// Both files should be in live dir
	if _, err := os.Stat(filepath.Join(dir, "signed.yaml")); err != nil {
		t.Fatal("policy not promoted")
	}
	if _, err := os.Stat(filepath.Join(dir, "signed.yaml.sig")); err != nil {
		t.Fatal(".sig not promoted")
	}

	// Both should be gone from staging
	if _, err := os.Stat(filepath.Join(stagingDir, "signed.yaml")); !os.IsNotExist(err) {
		t.Fatal("staged policy should be removed")
	}
	if _, err := os.Stat(filepath.Join(stagingDir, "signed.yaml.sig")); !os.IsNotExist(err) {
		t.Fatal("staged .sig should be removed")
	}
}

func TestPolicyWatcher_StagingYamlFirstThenSig(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	loader := &mockLoader{}
	stagingDone := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 500 * time.Millisecond, // Long enough for .sig to arrive
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Write .yaml first
	os.WriteFile(filepath.Join(stagingDir, "delayed.yaml"), []byte("delayed: true"), 0644)
	// .sig arrives 100ms later (within 500ms staging debounce)
	time.Sleep(100 * time.Millisecond)
	os.WriteFile(filepath.Join(stagingDir, "delayed.yaml.sig"), []byte(`{"version":1}`), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	// Both files should be promoted
	if _, err := os.Stat(filepath.Join(dir, "delayed.yaml")); err != nil {
		t.Fatal("policy not promoted")
	}
	if _, err := os.Stat(filepath.Join(dir, "delayed.yaml.sig")); err != nil {
		t.Fatal(".sig not promoted")
	}
}

func TestPolicyWatcher_StagingOverwritesExistingPolicy(t *testing.T) {
	dir := t.TempDir()
	stagingDir := filepath.Join(dir, ".staging")
	os.MkdirAll(stagingDir, 0755)

	// Pre-existing live policy
	os.WriteFile(filepath.Join(dir, "existing.yaml"), []byte("version: 1"), 0644)

	loader := &mockLoader{}
	stagingDone := make(chan struct{}, 1)

	watcher, err := NewPolicyWatcher(WatcherConfig{
		PolicyDir:       dir,
		Loader:          loader,
		Debounce:        50 * time.Millisecond,
		StagingDebounce: 100 * time.Millisecond,
		OnStaging: func(path string, err error) {
			select {
			case stagingDone <- struct{}{}:
			default:
			}
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	watcher.Start(ctx)
	defer watcher.Stop()

	// Stage updated version
	os.WriteFile(filepath.Join(stagingDir, "existing.yaml"), []byte("version: 2"), 0644)

	select {
	case <-stagingDone:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}

	data, err := os.ReadFile(filepath.Join(dir, "existing.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "version: 2" {
		t.Fatalf("expected overwritten content, got %q", data)
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
