package skillcheck

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatcherConfig configures the fsnotify-based skill watcher.
type WatcherConfig struct {
	Roots    []string              // literal or glob roots to watch
	Debounce time.Duration         // debounce per skill dir; default 500ms
	OnSkill  func(skillDir string) // called once per debounced skill landing
}

// Watcher observes watch roots for new SKILL.md landings and invokes
// OnSkill (debounced per skill dir).
//
// Goroutine lifetime: time.AfterFunc timers scheduled by scheduleDebounce
// may fire after Close is called. Close stops all pending timers to prevent
// spurious OnSkill callbacks after shutdown, but there is a small window
// where a timer goroutine already entered its callback before Stop returned.
// Callers must tolerate at most one OnSkill call after Close.
type Watcher struct {
	cfg     WatcherConfig
	watcher *fsnotify.Watcher
	mu      sync.Mutex
	timers  map[string]*time.Timer
}

// NewWatcher creates a new Watcher. Call Run to start processing events.
func NewWatcher(cfg WatcherConfig) (*Watcher, error) {
	if cfg.Debounce == 0 {
		cfg.Debounce = 500 * time.Millisecond
	}
	w, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, err
	}
	return &Watcher{cfg: cfg, watcher: w, timers: map[string]*time.Timer{}}, nil
}

// Run blocks until ctx is cancelled. It adds each root (and any nested
// directories that appear) to the underlying fsnotify watcher.
func (w *Watcher) Run(ctx context.Context) {
	for _, r := range w.cfg.Roots {
		w.addRecursive(r)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-w.watcher.Events:
			if !ok {
				return
			}
			w.handleEvent(ev)
		case <-w.watcher.Errors:
			// Errors are best-effort; continue.
		}
	}
}

// Close releases the underlying fsnotify watcher and stops all pending
// debounce timers. OnSkill will not be called after Close returns, except
// in the narrow race where a timer goroutine already entered its callback.
func (w *Watcher) Close() error {
	w.mu.Lock()
	for key, t := range w.timers {
		t.Stop()
		delete(w.timers, key)
	}
	w.mu.Unlock()
	return w.watcher.Close()
}

func (w *Watcher) addRecursive(path string) {
	matches, err := filepath.Glob(path)
	if err != nil || len(matches) == 0 {
		// Glob may not match yet; add as literal so its parent gets watched too.
		_ = w.watcher.Add(path)
		return
	}
	for _, m := range matches {
		_ = w.watcher.Add(m)
		_ = filepath.WalkDir(m, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				_ = w.watcher.Add(p)
			}
			return nil
		})
	}
}

func (w *Watcher) handleEvent(ev fsnotify.Event) {
	if filepath.Base(ev.Name) == "SKILL.md" && (ev.Op&(fsnotify.Create|fsnotify.Write) != 0) {
		w.scheduleDebounce(filepath.Dir(ev.Name))
		return
	}
	// New subdir → start watching it too, then check if SKILL.md already landed.
	// The check handles the race where SKILL.md is written before fsnotify
	// delivers the directory-create event and we register the watch.
	if ev.Op&fsnotify.Create != 0 {
		_ = w.watcher.Add(ev.Name)
		w.checkExistingSkill(ev.Name)
	}
}

// checkExistingSkill fires a debounce if SKILL.md already exists in dir.
func (w *Watcher) checkExistingSkill(dir string) {
	if _, err := os.Stat(filepath.Join(dir, "SKILL.md")); err == nil {
		w.scheduleDebounce(dir)
	}
}

func (w *Watcher) scheduleDebounce(skillDir string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.timers[skillDir]; ok {
		t.Stop()
	}
	w.timers[skillDir] = time.AfterFunc(w.cfg.Debounce, func() {
		w.cfg.OnSkill(skillDir)
		w.mu.Lock()
		delete(w.timers, skillDir)
		w.mu.Unlock()
	})
}
