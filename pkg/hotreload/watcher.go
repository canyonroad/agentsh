package hotreload

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	policyDir       string
	loader          PolicyLoader
	watcher         *fsnotify.Watcher
	debounce        time.Duration
	stagingDebounce time.Duration
	onChange        func(path string, err error)
	onStaging       func(path string, err error)
	mu              sync.RWMutex
	running         atomic.Bool
	reloadChan      chan string
	stagingChan     chan string
	stats           WatcherStats
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
	StagingTotal   int64     `json:"staging_total"`
	StagingSuccess int64     `json:"staging_success"`
	StagingFailed  int64     `json:"staging_failed"`
}

// WatcherConfig configures the policy watcher.
type WatcherConfig struct {
	PolicyDir       string
	Loader          PolicyLoader
	Debounce        time.Duration // Debounce period for rapid changes
	StagingDebounce time.Duration // Debounce for staging (longer, to allow .sig to arrive)
	OnChange        func(path string, err error)
	OnStaging       func(path string, err error) // Called after staging validation attempt
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

	stagingDebounce := config.StagingDebounce
	if stagingDebounce == 0 {
		stagingDebounce = 2 * time.Second
	}

	return &PolicyWatcher{
		policyDir:       config.PolicyDir,
		loader:          config.Loader,
		debounce:        debounce,
		stagingDebounce: stagingDebounce,
		onChange:        config.OnChange,
		onStaging:       config.OnStaging,
		reloadChan:      make(chan string, 100),
		stagingChan:     make(chan string, 100),
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

	// Ensure .staging directory exists for policy delivery
	stagingDir := filepath.Join(w.policyDir, stagingDirName)
	if err := os.MkdirAll(stagingDir, 0755); err != nil {
		watcher.Close()
		w.running.Store(false)
		return fmt.Errorf("creating staging directory: %w", err)
	}

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

	// Start the staging reload goroutine
	go w.processStagingReloads(ctx)

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
	stagingPending := make(map[string]time.Time)
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
				if isInStagingDir(event.Name, w.policyDir) {
					// Staging events: track by policy base name
					if isStagingRelevant(event.Name) {
						policyPath := stagingPolicyPath(event.Name)
						stagingPending[policyPath] = time.Now()
					}
				} else if isPolicyFile(event.Name) {
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

			// Staging debounce
			for path, lastChange := range stagingPending {
				if now.Sub(lastChange) >= w.stagingDebounce {
					delete(stagingPending, path)
					select {
					case w.stagingChan <- path:
					default:
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

// processStagingReloads handles staging reload requests.
func (w *PolicyWatcher) processStagingReloads(ctx context.Context) {
	for {
		select {
		case path := <-w.stagingChan:
			w.handleStagingFile(path)
		case <-ctx.Done():
			return
		}
	}
}

// handleStagingFile validates a staged policy and promotes it to the live directory.
func (w *PolicyWatcher) handleStagingFile(policyPath string) {
	// Ensure the policy file actually exists (might have been a .sig-only event)
	if _, err := os.Stat(policyPath); err != nil {
		return
	}

	w.stats.mu.Lock()
	w.stats.StagingTotal++
	w.stats.mu.Unlock()

	// Validate using the same loader as live reloads — this handles
	// signature verification based on the signing mode config.
	// Signing metadata logging (key_id, signer, signed_at) is the
	// responsibility of the Validate implementation, not the watcher.
	if err := w.loader.Validate(policyPath); err != nil {
		w.recordStagingError(fmt.Sprintf("staging validation failed %s: %v", filepath.Base(policyPath), err))
		if w.onStaging != nil {
			w.onStaging(policyPath, err)
		}
		return
	}

	// Promote to live directory: move .sig first (per design spec),
	// then .yaml. This ensures the live watcher always sees a .sig
	// if it sees the policy.
	baseName := filepath.Base(policyPath)
	sigName := baseName + ".sig"
	stagingDir := filepath.Dir(policyPath)

	stagingSig := filepath.Join(stagingDir, sigName)
	liveSig := filepath.Join(w.policyDir, sigName)
	livePolicy := filepath.Join(w.policyDir, baseName)

	// Move .sig first (may not exist in warn/off mode)
	if _, err := os.Stat(stagingSig); err == nil {
		if err := moveFile(stagingSig, liveSig); err != nil {
			w.recordStagingError(fmt.Sprintf("staging move sig %s: %v", sigName, err))
			if w.onStaging != nil {
				w.onStaging(policyPath, err)
			}
			return
		}
	}

	// Move policy file
	if err := moveFile(policyPath, livePolicy); err != nil {
		// Rollback: move .sig back to staging to avoid orphaned sig in live dir
		if _, statErr := os.Stat(liveSig); statErr == nil {
			os.Rename(liveSig, stagingSig) // best-effort
		}
		w.recordStagingError(fmt.Sprintf("staging move policy %s: %v", baseName, err))
		if w.onStaging != nil {
			w.onStaging(policyPath, err)
		}
		return
	}

	w.stats.mu.Lock()
	w.stats.StagingSuccess++
	w.stats.mu.Unlock()

	if w.onStaging != nil {
		w.onStaging(livePolicy, nil)
	}
}

// moveFile renames src to dst, replacing dst if it exists.
// src and dst must be on the same filesystem (guaranteed when .staging/
// is a subdirectory of the policy dir).
func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err != nil {
		// Windows: Rename fails if dst exists. Remove and retry.
		os.Remove(dst)
		return os.Rename(src, dst)
	}
	return nil
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

// recordStagingError records a staging error in stats without incrementing ReloadsFailed.
func (w *PolicyWatcher) recordStagingError(err string) {
	w.stats.mu.Lock()
	w.stats.StagingFailed++
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
		StagingTotal:   w.stats.StagingTotal,
		StagingSuccess: w.stats.StagingSuccess,
		StagingFailed:  w.stats.StagingFailed,
	}
}

// TriggerReload manually triggers a reload for the policy directory.
func (w *PolicyWatcher) TriggerReload() error {
	if !w.running.Load() {
		return fmt.Errorf("watcher not running")
	}

	return filepath.Walk(w.policyDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// Skip staging directory
		if info.IsDir() && info.Name() == stagingDirName {
			return filepath.SkipDir
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

const stagingDirName = ".staging"

// isInStagingDir reports whether path is inside the .staging subdirectory of policyDir.
func isInStagingDir(path, policyDir string) bool {
	stagingPrefix := filepath.Join(policyDir, stagingDirName) + string(filepath.Separator)
	return strings.HasPrefix(path, stagingPrefix)
}

// isStagingRelevant reports whether a file in .staging/ should trigger staging processing.
// Matches policy files (.yaml, .yml, .json) and their companion .sig files.
func isStagingRelevant(path string) bool {
	if isPolicyFile(path) {
		return true
	}
	if strings.HasSuffix(path, ".sig") {
		return isPolicyFile(strings.TrimSuffix(path, ".sig"))
	}
	return false
}

// stagingPolicyPath returns the policy file path for a staging event.
// If path ends in .sig, strips the .sig suffix to get the policy path.
func stagingPolicyPath(path string) string {
	if strings.HasSuffix(path, ".sig") {
		base := strings.TrimSuffix(path, ".sig")
		if isPolicyFile(base) {
			return base
		}
	}
	return path
}

// isPolicyFile checks if a file is a policy file.
func isPolicyFile(path string) bool {
	ext := filepath.Ext(path)
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}
