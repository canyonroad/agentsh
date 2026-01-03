// internal/platform/fuse/ops_test.go
//go:build cgo

package fuse

import (
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
)

func TestEmitEvent_WithChannel(t *testing.T) {
	eventChan := make(chan platform.IOEvent, 10)

	fs := &fuseFS{
		cfg: Config{
			FSConfig: platform.FSConfig{
				SessionID:    "test-session",
				MountPoint:   "/workspace",
				EventChannel: eventChan,
				CommandIDFunc: func() string {
					return "test-cmd"
				},
			},
		},
	}

	fs.emitEvent("file_open", "/workspace/test.txt", platform.FileOpRead, platform.DecisionAllow, false)

	// Should have received an event
	select {
	case event := <-eventChan:
		if event.SessionID != "test-session" {
			t.Errorf("SessionID = %q, want test-session", event.SessionID)
		}
		if event.CommandID != "test-cmd" {
			t.Errorf("CommandID = %q, want test-cmd", event.CommandID)
		}
		if event.Path != "/workspace/test.txt" {
			t.Errorf("Path = %q, want /workspace/test.txt", event.Path)
		}
		if event.Operation != platform.FileOpRead {
			t.Errorf("Operation = %v, want FileOpRead", event.Operation)
		}
		if event.Decision != platform.DecisionAllow {
			t.Errorf("Decision = %v, want DecisionAllow", event.Decision)
		}
		if event.Platform != "fuse" {
			t.Errorf("Platform = %q, want fuse", event.Platform)
		}
		if event.Type != "file_open" {
			t.Errorf("Type = %q, want file_open", event.Type)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected event but none received")
	}

	// Check stats were updated
	if fs.totalOps.Load() != 1 {
		t.Errorf("totalOps = %d, want 1", fs.totalOps.Load())
	}
	if fs.allowedOps.Load() != 1 {
		t.Errorf("allowedOps = %d, want 1", fs.allowedOps.Load())
	}
	if fs.deniedOps.Load() != 0 {
		t.Errorf("deniedOps = %d, want 0", fs.deniedOps.Load())
	}
}

func TestEmitEvent_Blocked(t *testing.T) {
	eventChan := make(chan platform.IOEvent, 10)

	fs := &fuseFS{
		cfg: Config{
			FSConfig: platform.FSConfig{
				EventChannel: eventChan,
			},
		},
	}

	fs.emitEvent("file_write", "/workspace/test.txt", platform.FileOpWrite, platform.DecisionDeny, true)

	// Stats should reflect blocked operation
	if fs.totalOps.Load() != 1 {
		t.Errorf("totalOps = %d, want 1", fs.totalOps.Load())
	}
	if fs.allowedOps.Load() != 0 {
		t.Errorf("allowedOps = %d, want 0", fs.allowedOps.Load())
	}
	if fs.deniedOps.Load() != 1 {
		t.Errorf("deniedOps = %d, want 1", fs.deniedOps.Load())
	}

	// Should have received an event with deny decision
	select {
	case event := <-eventChan:
		if event.Decision != platform.DecisionDeny {
			t.Errorf("Decision = %v, want DecisionDeny", event.Decision)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected event but none received")
	}
}

func TestEmitEvent_NoChannel(t *testing.T) {
	fs := &fuseFS{
		cfg: Config{
			FSConfig: platform.FSConfig{
				// No EventChannel configured
			},
		},
	}

	// Should not panic
	fs.emitEvent("file_open", "/workspace/test.txt", platform.FileOpRead, platform.DecisionAllow, false)

	// Stats should still be updated
	if fs.totalOps.Load() != 1 {
		t.Errorf("totalOps = %d, want 1", fs.totalOps.Load())
	}
}

func TestEmitEvent_FullChannel(t *testing.T) {
	// Create a full channel (capacity 1, already has 1 item)
	eventChan := make(chan platform.IOEvent, 1)
	eventChan <- platform.IOEvent{} // Fill the channel

	fs := &fuseFS{
		cfg: Config{
			FSConfig: platform.FSConfig{
				EventChannel: eventChan,
			},
		},
	}

	// Should not block even though channel is full
	done := make(chan bool)
	go func() {
		fs.emitEvent("file_open", "/workspace/test.txt", platform.FileOpRead, platform.DecisionAllow, false)
		done <- true
	}()

	select {
	case <-done:
		// Good, didn't block
	case <-time.After(100 * time.Millisecond):
		t.Error("emitEvent blocked on full channel")
	}

	// Stats should still be updated
	if fs.totalOps.Load() != 1 {
		t.Errorf("totalOps = %d, want 1", fs.totalOps.Load())
	}
}

func TestEmitEvent_NoCommandIDFunc(t *testing.T) {
	eventChan := make(chan platform.IOEvent, 10)

	fs := &fuseFS{
		cfg: Config{
			FSConfig: platform.FSConfig{
				SessionID:    "test-session",
				EventChannel: eventChan,
				// No CommandIDFunc
			},
		},
	}

	fs.emitEvent("file_open", "/workspace/test.txt", platform.FileOpRead, platform.DecisionAllow, false)

	select {
	case event := <-eventChan:
		if event.CommandID != "" {
			t.Errorf("CommandID = %q, want empty", event.CommandID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("Expected event but none received")
	}
}
