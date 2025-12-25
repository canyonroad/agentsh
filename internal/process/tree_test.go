package process

import (
	"testing"
	"time"
)

func TestProcessNode(t *testing.T) {
	now := time.Now()
	exitCode := 0
	endTime := now.Add(time.Second)

	node := &ProcessNode{
		PID:       1234,
		PPID:      1000,
		Command:   "/bin/bash",
		Args:      []string{"-c", "echo hello"},
		StartTime: now,
		EndTime:   &endTime,
		ExitCode:  &exitCode,
		Children:  nil,
	}

	if node.PID != 1234 {
		t.Errorf("PID = %d, want 1234", node.PID)
	}
	if node.PPID != 1000 {
		t.Errorf("PPID = %d, want 1000", node.PPID)
	}
	if node.Command != "/bin/bash" {
		t.Errorf("Command = %q, want /bin/bash", node.Command)
	}
	if len(node.Args) != 2 {
		t.Errorf("Args length = %d, want 2", len(node.Args))
	}
	if *node.ExitCode != 0 {
		t.Errorf("ExitCode = %d, want 0", *node.ExitCode)
	}
}

func TestProcessNode_WithChildren(t *testing.T) {
	parent := &ProcessNode{
		PID:       1000,
		StartTime: time.Now(),
	}

	child1 := &ProcessNode{
		PID:       1001,
		PPID:      1000,
		StartTime: time.Now(),
	}

	child2 := &ProcessNode{
		PID:       1002,
		PPID:      1000,
		StartTime: time.Now(),
	}

	parent.Children = []*ProcessNode{child1, child2}

	if len(parent.Children) != 2 {
		t.Errorf("Children count = %d, want 2", len(parent.Children))
	}
	if parent.Children[0].PID != 1001 {
		t.Errorf("First child PID = %d, want 1001", parent.Children[0].PID)
	}
	if parent.Children[1].PID != 1002 {
		t.Errorf("Second child PID = %d, want 1002", parent.Children[1].PID)
	}
}

func TestProcessInfo(t *testing.T) {
	info := &ProcessInfo{
		PID:     1234,
		PPID:    1000,
		Command: "/usr/bin/python",
		Args:    []string{"script.py", "--verbose"},
	}

	if info.PID != 1234 {
		t.Errorf("PID = %d, want 1234", info.PID)
	}
	if info.PPID != 1000 {
		t.Errorf("PPID = %d, want 1000", info.PPID)
	}
	if info.Command != "/usr/bin/python" {
		t.Errorf("Command = %q, want /usr/bin/python", info.Command)
	}
}

func TestTrackerCapabilities_Defaults(t *testing.T) {
	caps := TrackerCapabilities{}

	if caps.AutoChildTracking {
		t.Error("AutoChildTracking should default to false")
	}
	if caps.SpawnNotification {
		t.Error("SpawnNotification should default to false")
	}
	if caps.ExitNotification {
		t.Error("ExitNotification should default to false")
	}
	if caps.ExitCodes {
		t.Error("ExitCodes should default to false")
	}
}

func TestTrackerCapabilities_Full(t *testing.T) {
	caps := TrackerCapabilities{
		AutoChildTracking: true,
		SpawnNotification: true,
		ExitNotification:  true,
		ExitCodes:         true,
	}

	if !caps.AutoChildTracking {
		t.Error("AutoChildTracking should be true")
	}
	if !caps.SpawnNotification {
		t.Error("SpawnNotification should be true")
	}
	if !caps.ExitNotification {
		t.Error("ExitNotification should be true")
	}
	if !caps.ExitCodes {
		t.Error("ExitCodes should be true")
	}
}

func TestNewPlatformTracker(t *testing.T) {
	tracker := newPlatformTracker()
	if tracker == nil {
		t.Fatal("newPlatformTracker() returned nil")
	}
}
