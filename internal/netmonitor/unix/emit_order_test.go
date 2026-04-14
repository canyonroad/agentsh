//go:build linux && cgo

package unix

import (
	"context"
	"sync"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/pkg/types"
)

// recordingEmitter records calls to AppendEvent and Publish so tests can
// assert that builder functions do NOT call the emitter.
type recordingEmitter struct {
	mu    sync.Mutex
	calls int
}

func (r *recordingEmitter) AppendEvent(_ context.Context, _ types.Event) error {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
	return nil
}

func (r *recordingEmitter) Publish(_ types.Event) {
	r.mu.Lock()
	r.calls++
	r.mu.Unlock()
}

// TestBuildEvent_ExecveHandler_NoSideEffects verifies that
// ExecveHandler.buildEvent returns a well-formed event and does NOT call
// the emitter.
func TestBuildEvent_ExecveHandler_NoSideEffects(t *testing.T) {
	rec := &recordingEmitter{}
	h := &ExecveHandler{emitter: rec}

	ctx := ExecveContext{
		PID:       1234,
		Filename:  "/bin/ls",
		Argv:      []string{"ls"},
		SessionID: "test-sess",
	}
	result := ExecveResult{
		Allow:    true,
		Action:   ActionContinue,
		Rule:     "test",
		Decision: "allow",
	}

	ev := h.buildEvent(ctx, result, "test")

	if ev == nil {
		t.Fatal("buildEvent returned nil event")
	}
	if ev.Type != "execve" {
		t.Errorf("expected event Type %q, got %q", "execve", ev.Type)
	}

	rec.mu.Lock()
	calls := rec.calls
	rec.mu.Unlock()
	if calls != 0 {
		t.Errorf("buildEvent called the emitter %d time(s); expected 0", calls)
	}
}

// TestBuildEvent_FileHandler_NoSideEffects verifies that
// FileHandler.buildFileEvent returns a well-formed event and does NOT call
// the emitter.
func TestBuildEvent_FileHandler_NoSideEffects(t *testing.T) {
	rec := &recordingEmitter{}
	h := &FileHandler{emitter: rec}

	req := FileRequest{
		PID:       1234,
		Path:      "/tmp/test",
		Operation: "write",
		SessionID: "test-sess",
	}
	dec := FilePolicyDecision{
		Decision:          "allow",
		EffectiveDecision: "allow",
		Rule:              "test",
	}

	ev := h.buildFileEvent(req, dec, false, false)

	if ev == nil {
		t.Fatal("buildFileEvent returned nil event")
	}
	if len(ev.Type) < 5 || ev.Type[:5] != "file_" {
		t.Errorf("expected event Type to start with %q, got %q", "file_", ev.Type)
	}

	rec.mu.Lock()
	calls := rec.calls
	rec.mu.Unlock()
	if calls != 0 {
		t.Errorf("buildFileEvent called the emitter %d time(s); expected 0", calls)
	}
}

// TestBuildEvent_UnixSocket_NoSideEffects verifies that buildUnixSocketEvent
// returns a well-formed event and does NOT call the emitter.
func TestBuildEvent_UnixSocket_NoSideEffects(t *testing.T) {
	rec := &recordingEmitter{}

	dec := policy.Decision{
		PolicyDecision:    types.DecisionDeny,
		EffectiveDecision: types.DecisionDeny,
		Rule:              "test_rule",
	}

	ev := buildUnixSocketEvent(rec, "test-sess", dec, "/tmp/test.sock", false, "connect")

	if ev == nil {
		t.Fatal("buildUnixSocketEvent returned nil event")
	}
	if ev.Type != "unix_socket_op" {
		t.Errorf("expected event Type %q, got %q", "unix_socket_op", ev.Type)
	}

	rec.mu.Lock()
	calls := rec.calls
	rec.mu.Unlock()
	if calls != 0 {
		t.Errorf("buildUnixSocketEvent called the emitter %d time(s); expected 0", calls)
	}
}
