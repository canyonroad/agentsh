package hotreload

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// PolicyLoader loads policies from a path.
type PolicyLoader interface {
	LoadFromPath(path string) error
	Validate(path string) error
}

// PolicyWatcher watches policy files for changes and triggers reloads.
type PolicyWatcher struct {
	policyDir  string
	loader     PolicyLoader
	watcher    *fsnotify.Watcher
	debounce   time.Duration
	onChange   func(path string, err error)
	mu         sync.RWMutex
	running    atomic.Bool
	reloadChan chan string
	stats      WatcherStats
}

// WatcherStats tracks reload statistics.
type WatcherStats struct {
	mu             sync.RWMutex
	ReloadsTotal   int64     `json:"reloads_total"`
	ReloadsSuccess int64     `json:"reloads_success"`
	ReloadsFailed  int64     `json:"reloads_failed"`
	LastReload     time.Time `json:"last_reload,omitempty"`
	LastError      string    `json:"last_error,omitempty"`
	LastErrorTime  time.Time `json:"last_error_time,omitempty"`
}

// WatcherConfig configures the policy watcher.
type WatcherConfig struct {
	PolicyDir string
	Loader    PolicyLoader
	Debounce  time.Duration // Debounce period for rapid changes
	OnChange  func(path string, err error)
}

// NewPolicyWatcher creates a new policy watcher.
func NewPolicyWatcher(config WatcherConfig) (*PolicyWatcher, error) {
	if config.PolicyDir == "" {
		return nil, fmt.Errorf("policy directory is required")
	}

	if config.Loader == nil {
		return nil, fmt.Errorf("policy loader is required")
	}

	debounce := config.Debounce
	if debounce == 0 {
		debounce = 100 * time.Millisecond
	}

	return &PolicyWatcher{
		policyDir:  config.PolicyDir,
		loader:     config.Loader,
		debounce:   debounce,
		onChange:   config.OnChange,
		reloadChan: make(chan string, 100),
	}, nil
}

// Start begins watching for policy file changes.
func (w *PolicyWatcher) Start(ctx context.Context) error {
	if !w.running.CompareAndSwap(false, true) {
		return fmt.Errorf("watcher already running")
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		w.running.Store(false)
		return fmt.Errorf("creating watcher: %w", err)
	}
	w.watcher = watcher

	// Watch the policy directory
	if err := w.addWatchRecursive(w.policyDir); err != nil {
		watcher.Close()
		w.running.Store(false)
		return fmt.Errorf("watching directory: %w", err)
	}

	// Start the event processing goroutine
	go w.processEvents(ctx)

	// Start the reload goroutine
	go w.processReloads(ctx)

	return nil
}

// addWatchRecursive adds watches for a directory and all subdirectories.
func (w *PolicyWatcher) addWatchRecursive(dir string) error {
	return filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return w.watcher.Add(path)
		}
		return nil
	})
}

// processEvents handles fsnotify events.
func (w *PolicyWatcher) processEvents(ctx context.Context) {
	pending := make(map[string]time.Time)
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-w.watcher.Events:
			if !ok {
				return
			}

			// Only process write and create events for policy files
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if isPolicyFile(event.Name) {
					pending[event.Name] = time.Now()
				}
			}

			// Handle new directories
			if event.Op&fsnotify.Create != 0 {
				if info, err := os.Stat(event.Name); err == nil && info.IsDir() {
					w.watcher.Add(event.Name)
				}
			}

		case err, ok := <-w.watcher.Errors:
			if !ok {
				return
			}
			w.recordError(fmt.Sprintf("watcher error: %v", err))

		case <-ticker.C:
			// Check for debounced events
			now := time.Now()
			for path, lastChange := range pending {
				if now.Sub(lastChange) >= w.debounce {
					delete(pending, path)
					select {
					case w.reloadChan <- path:
					default:
						// Channel full, skip
					}
				}
			}

		case <-ctx.Done():
			return
		}
	}
}

// processReloads handles reload requests.
func (w *PolicyWatcher) processReloads(ctx context.Context) {
	for {
		select {
		case path := <-w.reloadChan:
			w.handleReload(path)
		case <-ctx.Done():
			return
		}
	}
}

// handleReload processes a reload for a specific file.
func (w *PolicyWatcher) handleReload(path string) {
	w.stats.mu.Lock()
	w.stats.ReloadsTotal++
	w.stats.mu.Unlock()

	// Validate before applying
	if err := w.loader.Validate(path); err != nil {
		w.recordError(fmt.Sprintf("invalid policy %s: %v", path, err))
		if w.onChange != nil {
			w.onChange(path, err)
		}
		return
	}

	// Load the new policy
	if err := w.loader.LoadFromPath(path); err != nil {
		w.recordError(fmt.Sprintf("loading policy %s: %v", path, err))
		if w.onChange != nil {
			w.onChange(path, err)
		}
		return
	}

	w.stats.mu.Lock()
	w.stats.ReloadsSuccess++
	w.stats.LastReload = time.Now()
	w.stats.mu.Unlock()

	if w.onChange != nil {
		w.onChange(path, nil)
	}
}

// recordError records an error in stats.
func (w *PolicyWatcher) recordError(err string) {
	w.stats.mu.Lock()
	w.stats.ReloadsFailed++
	w.stats.LastError = err
	w.stats.LastErrorTime = time.Now()
	w.stats.mu.Unlock()
}

// Stop stops the watcher.
func (w *PolicyWatcher) Stop() error {
	if !w.running.CompareAndSwap(true, false) {
		return nil
	}

	if w.watcher != nil {
		return w.watcher.Close()
	}
	return nil
}

// Stats returns the current watcher statistics.
func (w *PolicyWatcher) Stats() WatcherStats {
	w.stats.mu.RLock()
	defer w.stats.mu.RUnlock()
	return WatcherStats{
		ReloadsTotal:   w.stats.ReloadsTotal,
		ReloadsSuccess: w.stats.ReloadsSuccess,
		ReloadsFailed:  w.stats.ReloadsFailed,
		LastReload:     w.stats.LastReload,
		LastError:      w.stats.LastError,
		LastErrorTime:  w.stats.LastErrorTime,
	}
}

// TriggerReload manually triggers a reload for the policy directory.
func (w *PolicyWatcher) TriggerReload() error {
	if !w.running.Load() {
		return fmt.Errorf("watcher not running")
	}

	// Reload all policy files in the directory
	return filepath.Walk(w.policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && isPolicyFile(path) {
			select {
			case w.reloadChan <- path:
			default:
				return fmt.Errorf("reload channel full")
			}
		}
		return nil
	})
}

// isPolicyFile checks if a file is a policy file.
func isPolicyFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}
