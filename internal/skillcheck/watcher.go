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
	cfg          WatcherConfig
	watcher      *fsnotify.Watcher
	mu           sync.Mutex
	timers       map[string]*time.Timer
	roots        []string        // original configured roots
	pending      []string        // literal roots not yet existing; removed on first match
	pendingGlobs []string        // glob roots; retained after each match for future matches
	promoted     map[string]bool // roots that have been registered (full subtree watched)
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

// hasGlobMagic reports whether s contains any glob meta-characters.
func hasGlobMagic(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// globAncestor returns the longest path prefix of a glob pattern that contains
// no glob meta-characters. For example, "/a/b/*/skills" → "/a/b".
func globAncestor(pattern string) string {
	parts := strings.Split(filepath.Clean(pattern), string(filepath.Separator))
	out := []string{}
	for _, p := range parts {
		if hasGlobMagic(p) {
			break
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return string(filepath.Separator)
	}
	result := filepath.Join(out...)
	// Preserve leading separator for absolute paths.
	if filepath.IsAbs(pattern) && !filepath.IsAbs(result) {
		result = string(filepath.Separator) + result
	}
	return result
}

func (w *Watcher) addRecursive(path string) {
	if hasGlobMagic(path) {
		// Glob path: register any current matches, but always keep the glob
		// in pendingGlobs so future matches (new plugins etc.) are detected.
		matches, _ := filepath.Glob(path)
		for _, m := range matches {
			w.mu.Lock()
			w.promoted[m] = true
			w.mu.Unlock()
			w.registerDirRecursive(m)
		}
		w.mu.Lock()
		w.pendingGlobs = append(w.pendingGlobs, path)
		w.mu.Unlock()
		// Watch the nearest existing ancestor of the glob's static prefix so
		// we see new candidate directories appear.
		ancestor := nearestExistingAncestor(globAncestor(path))
		_ = w.watcher.Add(ancestor)
		return
	}

	// Literal path.
	if _, err := os.Stat(path); err == nil {
		w.mu.Lock()
		w.promoted[path] = true
		w.mu.Unlock()
		w.registerDirRecursive(path)
		return
	}
	w.mu.Lock()
	w.pending = append(w.pending, path)
	w.mu.Unlock()
	// Watch the nearest existing ancestor so we see intermediate Create events
	// and eventually the configured root itself.
	ancestor := nearestExistingAncestor(filepath.Dir(path))
	_ = w.watcher.Add(ancestor)
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
//
//  1. If the path is inside an already-promoted subtree, recurse into it normally.
//  2. If the path is an exact match for a pending literal root, promote and
//     remove from pending (single-shot).
//  3. If the path matches a pending glob root, promote but keep the glob in
//     pendingGlobs so future matches are still handled.
//  4. If the path is an intermediate ancestor on the way to any pending root,
//     add a temporary watch without promoting, so we see the next-level Create.
func (w *Watcher) maybePromote(path string) {
	w.mu.Lock()

	// 1. Already inside a promoted root? Recurse normally.
	for promotedRoot := range w.promoted {
		if isUnderOrEqual(path, promotedRoot) {
			w.mu.Unlock()
			w.registerDirRecursive(path)
			return
		}
	}

	// 2. Literal pending root exact match? Promote and remove from pending.
	for i, p := range w.pending {
		if path == p {
			w.pending = append(w.pending[:i], w.pending[i+1:]...)
			w.promoted[path] = true
			w.mu.Unlock()
			w.registerDirRecursive(path)
			return
		}
	}

	// 3. Glob pending match? Promote but KEEP the glob in pendingGlobs.
	for _, g := range w.pendingGlobs {
		if matched, _ := filepath.Match(g, path); matched {
			w.promoted[path] = true
			w.mu.Unlock()
			w.registerDirRecursive(path)
			return
		}
	}

	// 4. Intermediate ancestor of any pending root? Add a temporary watch so
	//    the next-level Create event reaches us. Do NOT mark as promoted.
	//    Also immediately re-evaluate all pending globs in case subdirectories
	//    already exist under this new intermediate dir (e.g. MkdirAll created
	//    the full chain atomically and we only saw the top-level Create).
	if w.isAncestorOfPendingLocked(path) {
		// Snapshot pendingGlobs while holding the lock.
		snapGlobs := make([]string, len(w.pendingGlobs))
		copy(snapGlobs, w.pendingGlobs)
		w.mu.Unlock()
		_ = w.watcher.Add(path)
		// Re-run glob matching synchronously; any new matches get promoted.
		for _, g := range snapGlobs {
			matches, _ := filepath.Glob(g)
			for _, m := range matches {
				w.mu.Lock()
				alreadyPromoted := w.promoted[m]
				if !alreadyPromoted {
					w.promoted[m] = true
				}
				w.mu.Unlock()
				if !alreadyPromoted {
					w.registerDirRecursive(m)
				}
			}
		}
		return
	}

	w.mu.Unlock()
}

// isAncestorOfPendingLocked reports whether path is a strict prefix (ancestor)
// of any pending literal root, or is an intermediate directory on the path
// toward any pending glob root.
//
// For a pending glob like "/plugins/*/skills":
//   - globAncestor gives "/plugins"
//   - any directory under "/plugins" (e.g. "/plugins/plug-a") is a candidate
//     intermediate that we need to watch so we see the next Create event
//   - a full glob match (e.g. "/plugins/plug-a/skills") is handled by step 3
//     in maybePromote before we reach here
//
// Caller must hold w.mu.
func (w *Watcher) isAncestorOfPendingLocked(path string) bool {
	cleanPath := filepath.Clean(path)
	prefix := cleanPath + string(filepath.Separator)

	for _, p := range w.pending {
		if strings.HasPrefix(filepath.Clean(p), prefix) {
			return true
		}
	}
	for _, g := range w.pendingGlobs {
		// Case A: path is a prefix of the glob's static ancestor
		// (e.g. path="/a", glob="/a/b/*/skills" → globAncestor="/a/b").
		ga := filepath.Clean(globAncestor(g))
		if strings.HasPrefix(ga, prefix) {
			return true
		}
		// Case B: path is under the glob's static ancestor but not yet a full
		// match (e.g. path="/plugins/plug-a", globAncestor="/plugins").
		// This handles intermediate dirs between the static prefix and the
		// first glob meta-character segment.
		gaPrefix := ga + string(filepath.Separator)
		if strings.HasPrefix(cleanPath, gaPrefix) {
			// path is somewhere under the glob ancestor; it may become a match
			// when further subdirectories are created — watch it.
			return true
		}
	}
	return false
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
