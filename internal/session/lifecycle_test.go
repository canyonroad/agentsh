package session

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestSessionState_IsTerminal(t *testing.T) {
	tests := []struct {
		state    types.SessionState
		terminal bool
	}{
		{types.SessionStatePending, false},
		{types.SessionStateStarting, false},
		{types.SessionStateRunning, false},
		{types.SessionStatePaused, false},
		{types.SessionStateTerminating, false},
		{types.SessionStateCompleted, true},
		{types.SessionStateFailed, true},
		{types.SessionStateTimedOut, true},
		{types.SessionStateKilled, true},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsTerminal(); got != tt.terminal {
				t.Errorf("IsTerminal() = %v, want %v", got, tt.terminal)
			}
		})
	}
}

func TestSessionState_IsActive(t *testing.T) {
	tests := []struct {
		state  types.SessionState
		active bool
	}{
		{types.SessionStatePending, false},
		{types.SessionStateStarting, true},
		{types.SessionStateRunning, true},
		{types.SessionStateBusy, true},
		{types.SessionStatePaused, false},
		{types.SessionStateTerminating, false},
		{types.SessionStateCompleted, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			if got := tt.state.IsActive(); got != tt.active {
				t.Errorf("IsActive() = %v, want %v", got, tt.active)
			}
		})
	}
}

func TestSession_Stats(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Initial stats should be zero
	stats := s.Stats()
	if stats.FileReads != 0 || stats.FileWrites != 0 {
		t.Error("expected zero initial stats")
	}

	// Increment stats
	s.IncrementFileReads(100)
	s.IncrementFileReads(50)
	s.IncrementFileWrites(200)

	stats = s.Stats()
	if stats.FileReads != 2 {
		t.Errorf("FileReads = %d, want 2", stats.FileReads)
	}
	if stats.BytesRead != 150 {
		t.Errorf("BytesRead = %d, want 150", stats.BytesRead)
	}
	if stats.FileWrites != 1 {
		t.Errorf("FileWrites = %d, want 1", stats.FileWrites)
	}
	if stats.BytesWritten != 200 {
		t.Errorf("BytesWritten = %d, want 200", stats.BytesWritten)
	}
}

func TestSession_UpdateStats(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s.UpdateStats(func(stats *types.SessionStats) {
		stats.NetworkConns = 5
		stats.DNSQueries = 10
		stats.CommandsExecuted = 20
	})

	stats := s.Stats()
	if stats.NetworkConns != 5 {
		t.Errorf("NetworkConns = %d, want 5", stats.NetworkConns)
	}
	if stats.DNSQueries != 10 {
		t.Errorf("DNSQueries = %d, want 10", stats.DNSQueries)
	}
	if stats.CommandsExecuted != 20 {
		t.Errorf("CommandsExecuted = %d, want 20", stats.CommandsExecuted)
	}
}

func TestSession_IncrementCounters(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	s.IncrementNetworkConns()
	s.IncrementNetworkConns()
	s.IncrementBlockedOps()
	s.IncrementCommandsExecuted()
	s.IncrementCommandsExecuted()
	s.IncrementCommandsExecuted()
	s.IncrementCommandsFailed()

	stats := s.Stats()
	if stats.NetworkConns != 2 {
		t.Errorf("NetworkConns = %d, want 2", stats.NetworkConns)
	}
	if stats.BlockedOps != 1 {
		t.Errorf("BlockedOps = %d, want 1", stats.BlockedOps)
	}
	if stats.CommandsExecuted != 3 {
		t.Errorf("CommandsExecuted = %d, want 3", stats.CommandsExecuted)
	}
	if stats.CommandsFailed != 1 {
		t.Errorf("CommandsFailed = %d, want 1", stats.CommandsFailed)
	}
}

func TestLifecycleHooks_Merge(t *testing.T) {
	var calls []string

	hooks1 := &LifecycleHooks{
		OnStart: func(s *Session) {
			calls = append(calls, "hook1-start")
		},
		OnEnd: func(s *Session, r types.SessionResult) {
			calls = append(calls, "hook1-end")
		},
	}

	hooks2 := &LifecycleHooks{
		OnStart: func(s *Session) {
			calls = append(calls, "hook2-start")
		},
		OnPause: func(s *Session) {
			calls = append(calls, "hook2-pause")
		},
	}

	merged := hooks1.Merge(hooks2)

	// Test merged OnStart calls both
	merged.OnStart(nil)
	if len(calls) != 2 || calls[0] != "hook1-start" || calls[1] != "hook2-start" {
		t.Errorf("OnStart calls = %v, want [hook1-start hook2-start]", calls)
	}

	// Test OnPause only from hooks2
	calls = nil
	merged.OnPause(nil)
	if len(calls) != 1 || calls[0] != "hook2-pause" {
		t.Errorf("OnPause calls = %v, want [hook2-pause]", calls)
	}
}

func TestLifecycleHooks_MergeNil(t *testing.T) {
	var hooks *LifecycleHooks

	// Merge nil with nil
	result := hooks.Merge(nil)
	if result != nil {
		t.Error("expected nil result from nil.Merge(nil)")
	}

	// Merge hooks with nil
	hooks = &LifecycleHooks{}
	result = hooks.Merge(nil)
	if result != hooks {
		t.Error("expected same hooks from hooks.Merge(nil)")
	}

	// Merge nil with hooks
	var nilHooks *LifecycleHooks
	other := &LifecycleHooks{}
	result = nilHooks.Merge(other)
	if result != other {
		t.Error("expected other from nil.Merge(other)")
	}
}

func TestLifecycleHooks_ChainBeforeStart(t *testing.T) {
	var calls []string

	hooks1 := &LifecycleHooks{
		OnBeforeStart: func(s *Session) error {
			calls = append(calls, "before1")
			return nil
		},
	}

	hooks2 := &LifecycleHooks{
		OnBeforeStart: func(s *Session) error {
			calls = append(calls, "before2")
			return nil
		},
	}

	merged := hooks1.Merge(hooks2)
	err := merged.OnBeforeStart(nil)
	if err != nil {
		t.Errorf("OnBeforeStart error = %v", err)
	}
	if len(calls) != 2 || calls[0] != "before1" || calls[1] != "before2" {
		t.Errorf("calls = %v, want [before1 before2]", calls)
	}
}

func TestCheckpointManager_CreateAndList(t *testing.T) {
	storage := NewInMemoryCheckpointStorage()
	manager := NewCheckpointManager(storage)

	dir := t.TempDir()
	// Create a test file in the workspace
	if err := os.WriteFile(filepath.Join(dir, "test.txt"), []byte("hello"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	m := NewManager(10)
	s, err := m.Create(dir, "default")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Update some stats
	s.IncrementFileReads(100)
	s.IncrementCommandsExecuted()

	// Create checkpoint
	cp, err := manager.CreateCheckpoint(s, "test checkpoint")
	if err != nil {
		t.Fatalf("CreateCheckpoint: %v", err)
	}

	if cp.SessionID != s.ID {
		t.Errorf("SessionID = %s, want %s", cp.SessionID, s.ID)
	}
	if cp.Reason != "test checkpoint" {
		t.Errorf("Reason = %s, want 'test checkpoint'", cp.Reason)
	}
	if cp.Stats.FileReads != 1 {
		t.Errorf("Stats.FileReads = %d, want 1", cp.Stats.FileReads)
	}
	if cp.Stats.CommandsExecuted != 1 {
		t.Errorf("Stats.CommandsExecuted = %d, want 1", cp.Stats.CommandsExecuted)
	}
	if !cp.CanRollback {
		t.Error("expected CanRollback = true")
	}
	if cp.WorkspaceHash == "" {
		t.Error("expected non-empty WorkspaceHash")
	}

	// List checkpoints
	checkpoints, err := manager.ListCheckpoints(s.ID)
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if len(checkpoints) != 1 {
		t.Errorf("len(checkpoints) = %d, want 1", len(checkpoints))
	}

	// Get specific checkpoint
	cp2, err := manager.GetCheckpoint(s.ID, cp.ID)
	if err != nil {
		t.Fatalf("GetCheckpoint: %v", err)
	}
	if cp2.ID != cp.ID {
		t.Errorf("checkpoint ID mismatch")
	}
}

func TestCheckpointManager_NilStorage(t *testing.T) {
	manager := NewCheckpointManager(nil)

	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	// CreateCheckpoint still works but doesn't persist
	cp, err := manager.CreateCheckpoint(s, "test")
	if err != nil {
		t.Fatalf("CreateCheckpoint: %v", err)
	}
	if cp == nil {
		t.Error("expected non-nil checkpoint")
	}

	// List returns nil without error
	list, err := manager.ListCheckpoints(s.ID)
	if err != nil {
		t.Fatalf("ListCheckpoints: %v", err)
	}
	if list != nil {
		t.Error("expected nil list")
	}

	// Get returns error
	_, err = manager.GetCheckpoint(s.ID, cp.ID)
	if err != ErrCheckpointNotFound {
		t.Errorf("GetCheckpoint error = %v, want ErrCheckpointNotFound", err)
	}
}

func TestInMemoryCheckpointStorage_Delete(t *testing.T) {
	storage := NewInMemoryCheckpointStorage()

	cp := &Checkpoint{
		ID:        "cp-1",
		SessionID: "sess-1",
		CreatedAt: time.Now(),
		Reason:    "test",
	}

	// Save
	if err := storage.Save(cp); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Verify exists
	_, err := storage.Load("sess-1", "cp-1")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Delete
	if err := storage.Delete("sess-1", "cp-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	// Verify deleted
	_, err = storage.Load("sess-1", "cp-1")
	if err != ErrCheckpointNotFound {
		t.Errorf("Load after delete error = %v, want ErrCheckpointNotFound", err)
	}
}

func TestShutdownConfig_Defaults(t *testing.T) {
	config := DefaultShutdownConfig()

	if config.ApprovalTimeout != 30*time.Second {
		t.Errorf("ApprovalTimeout = %v, want 30s", config.ApprovalTimeout)
	}
	if config.GracePeriod != 10*time.Second {
		t.Errorf("GracePeriod = %v, want 10s", config.GracePeriod)
	}
	if config.DrainTimeout != 5*time.Second {
		t.Errorf("DrainTimeout = %v, want 5s", config.DrainTimeout)
	}
}

func TestSessionShutdown_DrainMode(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	sd := NewSessionShutdown(s, DefaultShutdownConfig(), nil)

	// Initially not draining
	if sd.IsDraining() {
		t.Error("expected not draining initially")
	}

	// Can begin operations
	if !sd.BeginOperation() {
		t.Error("expected BeginOperation to succeed")
	}
	sd.EndOperation()

	// Enable drain mode
	sd.SetDrainMode(true)
	if !sd.IsDraining() {
		t.Error("expected draining after SetDrainMode(true)")
	}

	// Cannot begin new operations in drain mode
	if sd.BeginOperation() {
		t.Error("expected BeginOperation to fail in drain mode")
	}

	// Disable drain mode
	sd.SetDrainMode(false)
	if sd.IsDraining() {
		t.Error("expected not draining after SetDrainMode(false)")
	}
}

func TestSessionShutdown_WaitPending(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	sd := NewSessionShutdown(s, DefaultShutdownConfig(), nil)

	// No pending operations - should return immediately
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := sd.WaitPending(ctx); err != nil {
		t.Errorf("WaitPending with no ops: %v", err)
	}

	// Start an operation
	sd.BeginOperation()

	// WaitPending should block and timeout
	ctx2, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if err := sd.WaitPending(ctx2); err != context.DeadlineExceeded {
		t.Errorf("WaitPending error = %v, want DeadlineExceeded", err)
	}

	// End operation
	sd.EndOperation()

	// Now should return immediately
	ctx3, cancel3 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel3()
	if err := sd.WaitPending(ctx3); err != nil {
		t.Errorf("WaitPending after EndOperation: %v", err)
	}
}

func TestSessionShutdown_ShutdownOnce(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	var hookCalls int
	hooks := &LifecycleHooks{
		OnBeforeEnd: func(s *Session) {
			hookCalls++
		},
	}

	sd := NewSessionShutdown(s, ShutdownConfig{
		ApprovalTimeout: 10 * time.Millisecond,
		GracePeriod:     10 * time.Millisecond,
		DrainTimeout:    10 * time.Millisecond,
	}, hooks)

	ctx := context.Background()

	// First shutdown
	err := sd.Shutdown(ctx, ShutdownReasonNormal)
	if err != nil {
		t.Errorf("first Shutdown: %v", err)
	}

	// Second shutdown should be no-op
	err = sd.Shutdown(ctx, ShutdownReasonNormal)
	if err != nil {
		t.Errorf("second Shutdown: %v", err)
	}

	// Hook should only be called once
	if hookCalls != 1 {
		t.Errorf("hookCalls = %d, want 1", hookCalls)
	}
}

func TestSessionShutdown_FinalStates(t *testing.T) {
	tests := []struct {
		reason ShutdownReason
		state  types.SessionState
	}{
		{ShutdownReasonNormal, types.SessionStateCompleted},
		{ShutdownReasonTimeout, types.SessionStateTimedOut},
		{ShutdownReasonError, types.SessionStateFailed},
		{ShutdownReasonPolicy, types.SessionStateKilled},
		{ShutdownReasonResource, types.SessionStateKilled},
	}

	for _, tt := range tests {
		t.Run(string(tt.reason), func(t *testing.T) {
			dir := t.TempDir()
			m := NewManager(10)
			s, _ := m.Create(dir, "default")

			sd := NewSessionShutdown(s, ShutdownConfig{
				ApprovalTimeout: 10 * time.Millisecond,
				GracePeriod:     10 * time.Millisecond,
				DrainTimeout:    10 * time.Millisecond,
			}, nil)

			ctx := context.Background()
			sd.Shutdown(ctx, tt.reason)

			s.mu.Lock()
			state := s.State
			s.mu.Unlock()

			if state != tt.state {
				t.Errorf("state = %s, want %s", state, tt.state)
			}
		})
	}
}

func TestSessionShutdown_HooksCalledInOrder(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	var calls []string
	hooks := &LifecycleHooks{
		OnBeforeEnd: func(s *Session) {
			calls = append(calls, "before_end")
		},
		OnEnd: func(s *Session, r types.SessionResult) {
			calls = append(calls, "end")
		},
	}

	sd := NewSessionShutdown(s, ShutdownConfig{
		ApprovalTimeout: 10 * time.Millisecond,
		GracePeriod:     10 * time.Millisecond,
		DrainTimeout:    10 * time.Millisecond,
	}, hooks)

	ctx := context.Background()
	sd.Shutdown(ctx, ShutdownReasonNormal)

	expected := []string{"before_end", "end"}
	if len(calls) != len(expected) {
		t.Errorf("calls = %v, want %v", calls, expected)
		return
	}
	for i, c := range calls {
		if c != expected[i] {
			t.Errorf("calls[%d] = %s, want %s", i, c, expected[i])
		}
	}
}

func TestSession_Cleanup(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	// Set up closers that track if they were called
	var netNSClosed, proxyClosed, unmounted bool

	s.SetNetNS("test-ns", func() error {
		netNSClosed = true
		return nil
	})
	s.SetProxy("http://proxy", func() error {
		proxyClosed = true
		return nil
	})
	s.SetWorkspaceUnmount(func() error {
		unmounted = true
		return nil
	})

	// Call cleanup
	s.cleanup()

	if !netNSClosed {
		t.Error("expected NetNS to be closed")
	}
	if !proxyClosed {
		t.Error("expected proxy to be closed")
	}
	if !unmounted {
		t.Error("expected workspace to be unmounted")
	}
}

func TestSession_EndedAt(t *testing.T) {
	dir := t.TempDir()
	m := NewManager(10)
	s, _ := m.Create(dir, "default")

	// Initially nil
	if s.EndedAt() != nil {
		t.Error("expected nil EndedAt initially")
	}

	// After shutdown, should be set
	sd := NewSessionShutdown(s, ShutdownConfig{
		ApprovalTimeout: 10 * time.Millisecond,
		GracePeriod:     10 * time.Millisecond,
		DrainTimeout:    10 * time.Millisecond,
	}, nil)

	ctx := context.Background()
	sd.Shutdown(ctx, ShutdownReasonNormal)

	endedAt := s.EndedAt()
	if endedAt == nil {
		t.Error("expected non-nil EndedAt after shutdown")
	}
}

func TestShutdownReason_Constants(t *testing.T) {
	// Verify all shutdown reasons are defined
	reasons := []ShutdownReason{
		ShutdownReasonNormal,
		ShutdownReasonTimeout,
		ShutdownReasonManual,
		ShutdownReasonPolicy,
		ShutdownReasonError,
		ShutdownReasonResource,
	}

	for _, r := range reasons {
		if r == "" {
			t.Errorf("shutdown reason is empty")
		}
	}
}
