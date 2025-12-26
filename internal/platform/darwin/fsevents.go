//go:build darwin

package darwin

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/fsnotify/fsnotify"
)

// FSEventsMonitor provides file monitoring using macOS FSEvents via fsnotify.
// This is used as a fallback when FUSE is not available.
// Note: FSEvents is observation-only and cannot block operations.
type FSEventsMonitor struct {
	watcher    *fsnotify.Watcher
	eventChan  chan<- types.Event
	watchPaths map[string]bool
	mu         sync.Mutex
	running    bool
	stopCh     chan struct{}
}

// NewFSEventsMonitor creates a new FSEvents-based file monitor.
func NewFSEventsMonitor(eventChan chan<- types.Event) (*FSEventsMonitor, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create fsnotify watcher: %w", err)
	}

	return &FSEventsMonitor{
		watcher:    watcher,
		eventChan:  eventChan,
		watchPaths: make(map[string]bool),
		stopCh:     make(chan struct{}),
	}, nil
}

// AddWatch adds a path to be monitored.
func (m *FSEventsMonitor) AddWatch(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.watchPaths[path] {
		return nil // Already watching
	}

	if err := m.watcher.Add(path); err != nil {
		return fmt.Errorf("failed to add watch for %s: %w", path, err)
	}

	m.watchPaths[path] = true
	return nil
}

// RemoveWatch stops monitoring a path.
func (m *FSEventsMonitor) RemoveWatch(path string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.watchPaths[path] {
		return nil // Not watching
	}

	// Try to remove from fsnotify, but don't fail if it errors
	// (the watch may not have been properly registered due to macOS quirks)
	_ = m.watcher.Remove(path)

	delete(m.watchPaths, path)
	return nil
}

// Start begins processing file events.
func (m *FSEventsMonitor) Start(ctx context.Context) error {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return fmt.Errorf("monitor already running")
	}
	m.running = true
	m.mu.Unlock()

	go m.eventLoop(ctx)
	return nil
}

// Stop stops processing file events.
func (m *FSEventsMonitor) Stop() error {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return nil
	}
	m.running = false
	m.mu.Unlock()

	close(m.stopCh)
	return m.watcher.Close()
}

// eventLoop processes fsnotify events and converts them to agentsh events.
func (m *FSEventsMonitor) eventLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-m.stopCh:
			return
		case event, ok := <-m.watcher.Events:
			if !ok {
				return
			}
			m.handleEvent(event)
		case err, ok := <-m.watcher.Errors:
			if !ok {
				return
			}
			// Log error but continue
			m.sendErrorEvent(err)
		}
	}
}

// handleEvent converts an fsnotify event to an agentsh event.
func (m *FSEventsMonitor) handleEvent(event fsnotify.Event) {
	ev := types.Event{
		Timestamp: time.Now().UTC(),
		Path:      event.Name,
		Policy: &types.PolicyInfo{
			Decision:          types.DecisionAllow, // FSEvents is observation-only
			EffectiveDecision: types.DecisionAllow,
		},
	}

	// Map fsnotify operations to agentsh event types
	switch {
	case event.Op&fsnotify.Create != 0:
		ev.Type = "file_created"
		ev.Operation = "create"
	case event.Op&fsnotify.Write != 0:
		ev.Type = "file_modified"
		ev.Operation = "write"
	case event.Op&fsnotify.Remove != 0:
		ev.Type = "file_deleted"
		ev.Operation = "delete"
	case event.Op&fsnotify.Rename != 0:
		ev.Type = "file_renamed"
		ev.Operation = "rename"
	case event.Op&fsnotify.Chmod != 0:
		ev.Type = "file_chmod"
		ev.Operation = "chmod"
	default:
		ev.Type = "file_unknown"
		ev.Operation = "unknown"
	}

	ev.Fields = map[string]any{
		"source":        "fsevents",
		"platform":      "darwin",
		"can_block":     false,
		"observe_only":  true,
		"fsnotify_op":   event.Op.String(),
		"absolute_path": filepath.Clean(event.Name),
	}

	if m.eventChan != nil {
		m.eventChan <- ev
	}
}

// sendErrorEvent sends an error event through the event channel.
func (m *FSEventsMonitor) sendErrorEvent(err error) {
	if m.eventChan == nil {
		return
	}

	ev := types.Event{
		Timestamp: time.Now().UTC(),
		Type:      "fsevents_error",
		Fields: map[string]any{
			"error":    err.Error(),
			"source":   "fsevents",
			"platform": "darwin",
		},
	}
	m.eventChan <- ev
}

// FSEventsFilesystem provides a filesystem interceptor that uses FSEvents for monitoring.
// This is a fallback when FUSE is not available and provides observation-only capabilities.
type FSEventsFilesystem struct {
	monitor     *FSEventsMonitor
	eventChan   chan types.Event
	available   bool
	initialized bool
	mu          sync.Mutex
}

// NewFSEventsFilesystem creates a new FSEvents-based filesystem monitor.
func NewFSEventsFilesystem() *FSEventsFilesystem {
	return &FSEventsFilesystem{
		available: true, // FSEvents is always available on macOS
	}
}

// Available returns true as FSEvents is always available on macOS.
func (fs *FSEventsFilesystem) Available() bool {
	return fs.available
}

// Implementation returns the implementation name.
func (fs *FSEventsFilesystem) Implementation() string {
	return "fsevents"
}

// Mount sets up file monitoring for a directory.
// Note: This doesn't create a FUSE mount, just adds monitoring.
func (fs *FSEventsFilesystem) Mount(cfg platform.FSConfig) (platform.FSMount, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if fs.eventChan == nil {
		fs.eventChan = make(chan types.Event, 1000)
	}

	if fs.monitor == nil {
		monitor, err := NewFSEventsMonitor(fs.eventChan)
		if err != nil {
			return nil, fmt.Errorf("failed to create FSEvents monitor: %w", err)
		}
		fs.monitor = monitor

		if err := monitor.Start(context.Background()); err != nil {
			return nil, fmt.Errorf("failed to start FSEvents monitor: %w", err)
		}
	}

	// Add watch for the source path
	if err := fs.monitor.AddWatch(cfg.SourcePath); err != nil {
		return nil, fmt.Errorf("failed to add watch: %w", err)
	}

	return &FSEventsMount{
		sourcePath: cfg.SourcePath,
		mountPoint: cfg.MountPoint,
		monitor:    fs.monitor,
	}, nil
}

// Unmount removes file monitoring.
func (fs *FSEventsFilesystem) Unmount(mount platform.FSMount) error {
	m, ok := mount.(*FSEventsMount)
	if !ok {
		return fmt.Errorf("invalid mount type")
	}
	return m.Close()
}

// FSEventsMount represents a monitored directory.
type FSEventsMount struct {
	sourcePath string
	mountPoint string
	monitor    *FSEventsMonitor
}

// Path returns the mount point (same as source for FSEvents).
func (m *FSEventsMount) Path() string {
	return m.mountPoint
}

// SourcePath returns the underlying filesystem path.
func (m *FSEventsMount) SourcePath() string {
	return m.sourcePath
}

// Stats returns monitoring statistics.
func (m *FSEventsMount) Stats() platform.FSStats {
	return platform.FSStats{
		// FSEvents doesn't track individual operation counts
	}
}

// Close stops monitoring this path.
func (m *FSEventsMount) Close() error {
	if m.monitor != nil {
		return m.monitor.RemoveWatch(m.sourcePath)
	}
	return nil
}

// Compile-time interface checks
var (
	_ platform.FilesystemInterceptor = (*FSEventsFilesystem)(nil)
	_ platform.FSMount               = (*FSEventsMount)(nil)
)
