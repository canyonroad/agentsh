// internal/platform/fuse/ops_test.go
//go:build cgo

package fuse

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/agentsh/agentsh/internal/platform"
	"github.com/winfsp/cgofuse/fuse"
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

// fakePolicy returns a fixed decision, so the approve path can be tested.
type fakePolicy struct{ decision platform.Decision }

func (f fakePolicy) CheckFile(path string, op platform.FileOperation) platform.Decision {
	return f.decision
}
func (f fakePolicy) CheckNetwork(addr string, port int, protocol string) platform.Decision {
	return platform.DecisionAllow
}
func (f fakePolicy) CheckCommand(cmd string, args []string) platform.Decision {
	return platform.DecisionAllow
}
func (f fakePolicy) CheckEnv(name string, op platform.EnvOperation) platform.Decision {
	return platform.DecisionAllow
}
func (f fakePolicy) CheckRegistry(path string, op string) platform.Decision {
	return platform.DecisionAllow
}

type fakeApprover struct {
	err   error
	calls int
	last  platform.ApprovalRequest
}

func (f *fakeApprover) RequestApproval(ctx context.Context, req platform.ApprovalRequest) error {
	f.calls++
	f.last = req
	return f.err
}

func TestCheckPolicy_ApproveFailsClosedWithoutApprover(t *testing.T) {
	fs := &fuseFS{cfg: Config{FSConfig: platform.FSConfig{
		SessionID:    "s1",
		MountPoint:   "/workspace",
		PolicyEngine: fakePolicy{decision: platform.DecisionApprove},
	}}}
	if got := fs.checkPolicy("/.env", platform.FileOpWrite); got != platform.DecisionDeny {
		t.Fatalf("checkPolicy = %q, want deny", got)
	}
}

func TestCheckPolicy_ApproveResolvedByApprover(t *testing.T) {
	ap := &fakeApprover{}
	fs := &fuseFS{cfg: Config{FSConfig: platform.FSConfig{
		SessionID:     "s1",
		MountPoint:    "/workspace",
		PolicyEngine:  fakePolicy{decision: platform.DecisionApprove},
		Approver:      ap,
		CommandIDFunc: func() string { return "cmd-7" },
	}}}
	if got := fs.checkPolicy("/.env", platform.FileOpWrite); got != platform.DecisionAllow {
		t.Fatalf("checkPolicy = %q, want allow", got)
	}
	if ap.calls != 1 || ap.last.CommandID != "cmd-7" || ap.last.Target != "/workspace/.env" || ap.last.Op != "write" {
		t.Fatalf("approval request not forwarded: %+v (calls=%d)", ap.last, ap.calls)
	}
}

func TestCheckPolicy_ApproveDeniedByApprover(t *testing.T) {
	fs := &fuseFS{cfg: Config{FSConfig: platform.FSConfig{
		SessionID:    "s1",
		MountPoint:   "/workspace",
		PolicyEngine: fakePolicy{decision: platform.DecisionApprove},
		Approver:     &fakeApprover{err: errors.New("no")},
	}}}
	if got := fs.checkPolicy("/.env", platform.FileOpWrite); got != platform.DecisionDeny {
		t.Fatalf("checkPolicy = %q, want deny", got)
	}
}

// A rename into a denied destination must not spend an approval on the source.
func TestRename_DeniedDestinationDoesNotRequestApproval(t *testing.T) {
	ap := &fakeApprover{}
	fs := &fuseFS{cfg: Config{FSConfig: platform.FSConfig{
		SessionID:    "s1",
		MountPoint:   "/workspace",
		PolicyEngine: pathPolicy{"/a": platform.DecisionApprove, "/b": platform.DecisionDeny},
		Approver:     ap,
	}}}
	if got := fs.Rename("/a", "/b"); got != -fuse.EACCES {
		t.Fatalf("Rename = %d, want EACCES", got)
	}
	if ap.calls != 0 {
		t.Fatalf("approver called %d times, want 0", ap.calls)
	}
}

// An approve on either side triggers exactly one approval.
func TestRename_ApproveRequestsOnce(t *testing.T) {
	ap := &fakeApprover{}
	fs := &fuseFS{cfg: Config{FSConfig: platform.FSConfig{
		SessionID:    "s1",
		MountPoint:   "/workspace",
		PolicyEngine: pathPolicy{"/a": platform.DecisionApprove, "/b": platform.DecisionAllow},
		Approver:     ap,
	}}}
	// The rename itself will fail (paths do not exist); the approval count is
	// what matters here.
	_ = fs.Rename("/a", "/b")
	if ap.calls != 1 {
		t.Fatalf("approver called %d times, want 1", ap.calls)
	}
	if ap.last.ID == "" || ap.last.Rule == "" {
		t.Fatalf("approval request lost ID/rule: %+v", ap.last)
	}
}

// pathPolicy maps a real path to a decision for rename tests.
type pathPolicy map[string]platform.Decision

func (p pathPolicy) lookup(paths ...string) platform.Decision {
	for _, path := range paths {
		if d, ok := p[path]; ok {
			return d
		}
	}
	return platform.DecisionAllow
}

func (p pathPolicy) CheckFile(path string, op platform.FileOperation) platform.Decision {
	return p.lookup(path)
}
func (p pathPolicy) CheckNetwork(addr string, port int, protocol string) platform.Decision {
	return platform.DecisionAllow
}
func (p pathPolicy) CheckCommand(cmd string, args []string) platform.Decision {
	return platform.DecisionAllow
}
func (p pathPolicy) CheckEnv(name string, op platform.EnvOperation) platform.Decision {
	return platform.DecisionAllow
}
func (p pathPolicy) CheckRegistry(path string, op string) platform.Decision {
	return platform.DecisionAllow
}

// The event for an approve-gated operation must carry the approval id that was
// requested, so the approval record and the file event correlate.
func TestCheckPolicy_ApprovalIDReachesEvent(t *testing.T) {
	ap := &fakeApprover{}
	ch := make(chan platform.IOEvent, 1)
	fs := &fuseFS{cfg: Config{FSConfig: platform.FSConfig{
		SessionID:    "s1",
		MountPoint:   "/workspace",
		EventChannel: ch,
		PolicyEngine: fakePolicy{decision: platform.DecisionApprove},
		Approver:     ap,
	}}}
	decision := fs.checkPolicy("/.env", platform.FileOpWrite)
	fs.emitEvent("file_open", "/workspace/.env", platform.FileOpWrite, decision, false)

	select {
	case ev := <-ch:
		if ev.ApprovalID == "" || ev.ApprovalID != ap.last.ID {
			t.Fatalf("event approval id = %q, request id = %q", ev.ApprovalID, ap.last.ID)
		}
	default:
		t.Fatal("no event emitted")
	}
}
