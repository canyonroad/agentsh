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
	roots   []string // original watch roots, for create-of-root detection
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
	return &Watcher{cfg: cfg, watcher: w, timers: map[string]*time.Timer{}, roots: cfg.Roots}, nil
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

// nearestExistingAncestor walks up the directory tree until it finds a path
// that exists on disk, returning that path.
func nearestExistingAncestor(p string) string {
	for {
		if _, err := os.Stat(p); err == nil {
			return p
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p // reached filesystem root
		}
		p = parent
	}
}

// registerDirRecursive walks path, adds every subdirectory to the fsnotify
// watcher, and schedules a debounce for every SKILL.md found.
func (w *Watcher) registerDirRecursive(path string) {
	_ = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			_ = w.watcher.Add(p)
			return nil
		}
		if filepath.Base(p) == "SKILL.md" {
			w.scheduleDebounce(filepath.Dir(p))
		}
		return nil
	})
}

func (w *Watcher) addRecursive(path string) {
	matches, err := filepath.Glob(path)
	if err != nil || len(matches) == 0 {
		// Path doesn't exist yet (or glob has no matches). Watch the nearest
		// existing ancestor so we see the eventual creation.
		ancestor := nearestExistingAncestor(path)
		_ = w.watcher.Add(ancestor)
		return
	}
	for _, m := range matches {
		w.registerDirRecursive(m)
	}
}

func (w *Watcher) handleEvent(ev fsnotify.Event) {
	if ev.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			w.registerDirRecursive(ev.Name)
			// Also check if this creation matches any configured watch root
			// so a late-arriving root gets fully promoted.
			for _, root := range w.roots {
				matches, _ := filepath.Glob(root)
				for _, m := range matches {
					if m == ev.Name {
						// Already handled by registerDirRecursive above.
						break
					}
				}
			}
			return
		}
		// For non-directory creates: check if the created path now satisfies
		// any configured root that previously had no matches (e.g., the root
		// dir itself just appeared as a file — unlikely, but be safe).
		for _, root := range w.roots {
			matches, _ := filepath.Glob(root)
			for _, m := range matches {
				if m == ev.Name {
					w.registerDirRecursive(ev.Name)
				}
			}
		}
	}
	if filepath.Base(ev.Name) == "SKILL.md" && (ev.Op&(fsnotify.Create|fsnotify.Write) != 0) {
		w.scheduleDebounce(filepath.Dir(ev.Name))
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
