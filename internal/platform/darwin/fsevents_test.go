//go:build darwin

package darwin

import (
	"context"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/fsnotify/fsnotify"
)

func TestNewFSEventsMonitor(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m, err := NewFSEventsMonitor(eventChan)
	if err != nil {
		t.Fatalf("NewFSEventsMonitor() error = %v", err)
	}
	defer m.watcher.Close()

	if m.watcher == nil {
		t.Error("watcher is nil")
	}
	if m.eventChan != eventChan {
		t.Error("eventChan not set correctly")
	}
	if m.watchPaths == nil {
		t.Error("watchPaths is nil")
	}
	if m.stopCh == nil {
		t.Error("stopCh is nil")
	}
}

func TestFSEventsMonitor_AddWatch(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m, err := NewFSEventsMonitor(eventChan)
	if err != nil {
		t.Fatalf("NewFSEventsMonitor() error = %v", err)
	}
	defer m.watcher.Close()

	// Add watch for temp directory
	if err := m.AddWatch("/tmp"); err != nil {
		t.Errorf("AddWatch(/tmp) error = %v", err)
	}

	// Adding same path again should not error
	if err := m.AddWatch("/tmp"); err != nil {
		t.Errorf("AddWatch(/tmp) second time error = %v", err)
	}

	if !m.watchPaths["/tmp"] {
		t.Error("watchPaths does not contain /tmp")
	}
}

func TestFSEventsMonitor_RemoveWatch(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m, err := NewFSEventsMonitor(eventChan)
	if err != nil {
		t.Fatalf("NewFSEventsMonitor() error = %v", err)
	}
	defer m.watcher.Close()

	// Add then remove
	if err := m.AddWatch("/tmp"); err != nil {
		t.Fatalf("AddWatch() error = %v", err)
	}
	if err := m.RemoveWatch("/tmp"); err != nil {
		t.Errorf("RemoveWatch() error = %v", err)
	}

	if m.watchPaths["/tmp"] {
		t.Error("watchPaths still contains /tmp after remove")
	}

	// Removing non-existent path should not error
	if err := m.RemoveWatch("/nonexistent"); err != nil {
		t.Errorf("RemoveWatch(/nonexistent) error = %v", err)
	}
}

func TestFSEventsMonitor_StartStop(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m, err := NewFSEventsMonitor(eventChan)
	if err != nil {
		t.Fatalf("NewFSEventsMonitor() error = %v", err)
	}

	ctx := context.Background()

	// Start
	if err := m.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	if !m.running {
		t.Error("running should be true after Start()")
	}

	// Start again should error
	if err := m.Start(ctx); err == nil {
		t.Error("Start() should error when already running")
	}

	// Stop
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}

	if m.running {
		t.Error("running should be false after Stop()")
	}

	// Stop again should not error
	if err := m.Stop(); err != nil {
		t.Errorf("Stop() second time error = %v", err)
	}
}

func TestFSEventsMonitor_handleEvent(t *testing.T) {
	tests := []struct {
		name      string
		fsEvent   fsnotify.Event
		wantType  string
		wantOp    string
	}{
		{
			name:     "create",
			fsEvent:  fsnotify.Event{Name: "/tmp/test", Op: fsnotify.Create},
			wantType: "file_created",
			wantOp:   "create",
		},
		{
			name:     "write",
			fsEvent:  fsnotify.Event{Name: "/tmp/test", Op: fsnotify.Write},
			wantType: "file_modified",
			wantOp:   "write",
		},
		{
			name:     "remove",
			fsEvent:  fsnotify.Event{Name: "/tmp/test", Op: fsnotify.Remove},
			wantType: "file_deleted",
			wantOp:   "delete",
		},
		{
			name:     "rename",
			fsEvent:  fsnotify.Event{Name: "/tmp/test", Op: fsnotify.Rename},
			wantType: "file_renamed",
			wantOp:   "rename",
		},
		{
			name:     "chmod",
			fsEvent:  fsnotify.Event{Name: "/tmp/test", Op: fsnotify.Chmod},
			wantType: "file_chmod",
			wantOp:   "chmod",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			eventChan := make(chan types.Event, 10)
			m, err := NewFSEventsMonitor(eventChan)
			if err != nil {
				t.Fatalf("NewFSEventsMonitor() error = %v", err)
			}
			defer m.watcher.Close()

			m.handleEvent(tt.fsEvent)

			select {
			case ev := <-eventChan:
				if ev.Type != tt.wantType {
					t.Errorf("Type = %q, want %q", ev.Type, tt.wantType)
				}
				if ev.Operation != tt.wantOp {
					t.Errorf("Operation = %q, want %q", ev.Operation, tt.wantOp)
				}
				if ev.Path != tt.fsEvent.Name {
					t.Errorf("Path = %q, want %q", ev.Path, tt.fsEvent.Name)
				}
				if ev.Fields["source"] != "fsevents" {
					t.Errorf("Fields[source] = %v, want fsevents", ev.Fields["source"])
				}
				if ev.Fields["platform"] != "darwin" {
					t.Errorf("Fields[platform] = %v, want darwin", ev.Fields["platform"])
				}
				if ev.Fields["can_block"] != false {
					t.Errorf("Fields[can_block] = %v, want false", ev.Fields["can_block"])
				}
			case <-time.After(time.Second):
				t.Error("Timeout waiting for event")
			}
		})
	}
}

func TestFSEventsMonitor_handleEvent_NilChannel(t *testing.T) {
	m := &FSEventsMonitor{
		eventChan: nil,
	}
	// Should not panic
	m.handleEvent(fsnotify.Event{Name: "/tmp/test", Op: fsnotify.Create})
}

func TestFSEventsMonitor_sendErrorEvent(t *testing.T) {
	eventChan := make(chan types.Event, 10)
	m := &FSEventsMonitor{
		eventChan: eventChan,
	}

	testErr := context.DeadlineExceeded
	m.sendErrorEvent(testErr)

	select {
	case ev := <-eventChan:
		if ev.Type != "fsevents_error" {
			t.Errorf("Type = %q, want fsevents_error", ev.Type)
		}
		if ev.Fields["error"] != testErr.Error() {
			t.Errorf("Fields[error] = %v, want %v", ev.Fields["error"], testErr.Error())
		}
	case <-time.After(time.Second):
		t.Error("Timeout waiting for error event")
	}
}

func TestFSEventsMonitor_sendErrorEvent_NilChannel(t *testing.T) {
	m := &FSEventsMonitor{
		eventChan: nil,
	}
	// Should not panic
	m.sendErrorEvent(context.DeadlineExceeded)
}

func TestNewFSEventsFilesystem(t *testing.T) {
	fs := NewFSEventsFilesystem()
	if fs == nil {
		t.Fatal("NewFSEventsFilesystem() returned nil")
	}
	if !fs.available {
		t.Error("available should be true")
	}
}

func TestFSEventsFilesystem_Available(t *testing.T) {
	fs := NewFSEventsFilesystem()
	if !fs.Available() {
		t.Error("Available() should return true")
	}
}

func TestFSEventsFilesystem_Implementation(t *testing.T) {
	fs := NewFSEventsFilesystem()
	if got := fs.Implementation(); got != "fsevents" {
		t.Errorf("Implementation() = %q, want fsevents", got)
	}
}

func TestFSEventsFilesystem_Mount(t *testing.T) {
	fs := NewFSEventsFilesystem()

	cfg := platform.FSConfig{
		SourcePath: "/tmp",
		MountPoint: "/tmp",
	}

	mount, err := fs.Mount(cfg)
	if err != nil {
		t.Fatalf("Mount() error = %v", err)
	}
	defer mount.Close()

	if mount.Path() != "/tmp" {
		t.Errorf("Path() = %q, want /tmp", mount.Path())
	}
	if mount.SourcePath() != "/tmp" {
		t.Errorf("SourcePath() = %q, want /tmp", mount.SourcePath())
	}
}

func TestFSEventsFilesystem_Unmount(t *testing.T) {
	fs := NewFSEventsFilesystem()

	cfg := platform.FSConfig{
		SourcePath: "/tmp",
		MountPoint: "/tmp",
	}

	mount, err := fs.Mount(cfg)
	if err != nil {
		t.Fatalf("Mount() error = %v", err)
	}

	if err := fs.Unmount(mount); err != nil {
		t.Errorf("Unmount() error = %v", err)
	}
}

func TestFSEventsMount_Stats(t *testing.T) {
	m := &FSEventsMount{}
	stats := m.Stats()
	// FSEvents doesn't track operation counts
	if stats.TotalOps != 0 {
		t.Error("Stats should be empty for FSEvents")
	}
}

func TestFSEventsMount_Close_NilMonitor(t *testing.T) {
	m := &FSEventsMount{
		monitor: nil,
	}
	if err := m.Close(); err != nil {
		t.Errorf("Close() with nil monitor error = %v", err)
	}
}

func TestFSEventsFilesystem_InterfaceCompliance(t *testing.T) {
	var _ platform.FilesystemInterceptor = (*FSEventsFilesystem)(nil)
	var _ platform.FSMount = (*FSEventsMount)(nil)
}
