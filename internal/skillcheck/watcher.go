package skillcheck

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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
	cfg      WatcherConfig
	watcher  *fsnotify.Watcher
	mu       sync.Mutex
	timers   map[string]*time.Timer
	roots    []string        // original configured roots
	pending  []string        // roots not yet existing; consulted for Create-promotion
	promoted map[string]bool // roots that have been registered (full subtree watched)
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
	return &Watcher{
		cfg:      cfg,
		watcher:  w,
		timers:   map[string]*time.Timer{},
		roots:    cfg.Roots,
		promoted: map[string]bool{},
	}, nil
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
		// Track the original path as pending so we only promote when the
		// configured root itself is created, not arbitrary siblings.
		w.mu.Lock()
		w.pending = append(w.pending, path)
		w.mu.Unlock()
		return
	}
	for _, m := range matches {
		w.mu.Lock()
		w.promoted[m] = true
		w.mu.Unlock()
		w.registerDirRecursive(m)
	}
}

func (w *Watcher) handleEvent(ev fsnotify.Event) {
	if ev.Op&fsnotify.Create != 0 {
		if info, err := os.Stat(ev.Name); err == nil && info.IsDir() {
			w.maybePromote(ev.Name)
			return
		}
	}
	if filepath.Base(ev.Name) == "SKILL.md" && (ev.Op&(fsnotify.Create|fsnotify.Write) != 0) {
		parent := filepath.Dir(ev.Name)
		if w.isUnderPromoted(parent) {
			w.scheduleDebounce(parent)
		}
	}
}

// maybePromote decides whether a newly-created directory should be registered.
// It recurses immediately if the path is under an already-promoted root, or
// promotes it if it matches a pending root.
func (w *Watcher) maybePromote(path string) {
	w.mu.Lock()
	// Already inside a promoted root? Recurse normally.
	for promotedRoot := range w.promoted {
		if isUnderOrEqual(path, promotedRoot) {
			w.mu.Unlock()
			w.registerDirRecursive(path)
			return
		}
	}
	// Otherwise, only promote if it matches a pending root.
	for i, p := range w.pending {
		match := false
		if path == p {
			match = true
		} else if matched, _ := filepath.Match(p, path); matched {
			match = true
		}
		if match {
			// Remove from pending, mark promoted, register subtree.
			w.pending = append(w.pending[:i], w.pending[i+1:]...)
			w.promoted[path] = true
			w.mu.Unlock()
			w.registerDirRecursive(path)
			return
		}
	}
	w.mu.Unlock()
	// Not under any watched root, not a pending root — ignore.
}

// isUnderPromoted reports whether path is under (or equal to) any promoted root.
func (w *Watcher) isUnderPromoted(path string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	for root := range w.promoted {
		if isUnderOrEqual(path, root) {
			return true
		}
	}
	return false
}

// isUnderOrEqual reports whether child is equal to parent or a descendant of it.
func isUnderOrEqual(child, parent string) bool {
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	return rel == "." || (!strings.HasPrefix(rel, "..") && rel != "")
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
