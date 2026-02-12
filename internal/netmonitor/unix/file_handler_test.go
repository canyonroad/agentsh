//go:build linux && cgo

package unix

import (
	"context"
	"testing"

	"github.com/agentsh/agentsh/pkg/types"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// mockFilePolicy implements FilePolicyChecker for testing.
type mockFilePolicy struct {
	decisions map[string]FilePolicyDecision // path -> decision
}

func (m *mockFilePolicy) CheckFile(path, operation string) FilePolicyDecision {
	if dec, ok := m.decisions[path]; ok {
		return dec
	}
	// Default: deny if path not found
	return FilePolicyDecision{
		Decision:          "deny",
		EffectiveDecision: "deny",
		Rule:              "default_deny",
		Message:           "no matching rule",
	}
}

// mockFileEmitter captures events for verification.
type mockFileEmitter struct {
	events []types.Event
}

func (m *mockFileEmitter) AppendEvent(_ context.Context, ev types.Event) error {
	m.events = append(m.events, ev)
	return nil
}

func (m *mockFileEmitter) Publish(ev types.Event) {}

func TestFileHandler_AllowWithoutFUSE(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/file.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/home/user/file.txt",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue, got %s", result.Action)
	}
	if result.Errno != 0 {
		t.Errorf("expected Errno 0, got %d", result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev := emitter.events[0]
	if ev.Source != "seccomp" {
		t.Errorf("expected Source 'seccomp', got %q", ev.Source)
	}
	if ev.Type != "file_open" {
		t.Errorf("expected Type 'file_open', got %q", ev.Type)
	}
	if ev.Path != "/home/user/file.txt" {
		t.Errorf("expected Path '/home/user/file.txt', got %q", ev.Path)
	}
	if ev.SessionID != "sess-1" {
		t.Errorf("expected SessionID 'sess-1', got %q", ev.SessionID)
	}
	if ev.Policy == nil {
		t.Fatal("expected non-nil Policy")
	}
	if ev.Policy.Decision != "allow" {
		t.Errorf("expected policy decision 'allow', got %q", ev.Policy.Decision)
	}
}

func TestFileHandler_DenyWithoutFUSE(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/etc/shadow": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_etc",
				Message:           "access denied",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true) // enforce=true

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/etc/shadow",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	if result.Action != ActionDeny {
		t.Errorf("expected ActionDeny, got %s", result.Action)
	}
	if result.Errno != int32(unix.EACCES) {
		t.Errorf("expected Errno EACCES (%d), got %d", unix.EACCES, result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev := emitter.events[0]
	if ev.EffectiveAction != "blocked" {
		t.Errorf("expected EffectiveAction 'blocked', got %q", ev.EffectiveAction)
	}
}

func TestFileHandler_AuditOnlyUnderFUSE(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/project/secret.key": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_secrets",
				Message:           "secrets blocked",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	registry.Register("sess-1", "/home/user/project")
	handler := NewFileHandler(policy, registry, emitter, true) // enforce=true

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/home/user/project/secret.key",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	// Under FUSE: always continue, let FUSE handle enforcement
	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue under FUSE, got %s", result.Action)
	}
	if result.Errno != 0 {
		t.Errorf("expected Errno 0 under FUSE, got %d", result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev := emitter.events[0]
	// Should have shadow_deny=true in Fields
	if ev.Fields == nil {
		t.Fatal("expected non-nil Fields")
	}
	shadowDeny, ok := ev.Fields["shadow_deny"]
	if !ok {
		t.Fatal("expected shadow_deny in Fields")
	}
	if shadowDeny != true {
		t.Errorf("expected shadow_deny=true, got %v", shadowDeny)
	}
}

func TestFileHandler_EnforceDisabled(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/etc/passwd": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_etc",
				Message:           "access denied",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, false) // enforce=false

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/etc/passwd",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	// Audit-only: allow even though policy says deny
	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue (audit-only), got %s", result.Action)
	}
	if result.Errno != 0 {
		t.Errorf("expected Errno 0 (audit-only), got %d", result.Errno)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev := emitter.events[0]
	// Event should still reflect the deny decision
	if ev.Policy == nil || ev.Policy.Decision != "deny" {
		t.Errorf("expected policy decision 'deny' in audit-only event, got %v", ev.Policy)
	}
}

func TestFileHandler_Rename(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/old.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
			"/home/user/new.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_RENAMEAT2),
		Path:      "/home/user/old.txt",
		Path2:     "/home/user/new.txt",
		Operation: "rename",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue, got %s", result.Action)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev := emitter.events[0]
	if ev.Type != "file_rename" {
		t.Errorf("expected Type 'file_rename', got %q", ev.Type)
	}
	// Check path2 is in Fields
	if ev.Fields == nil {
		t.Fatal("expected non-nil Fields for rename")
	}
	if p2, ok := ev.Fields["path2"]; !ok || p2 != "/home/user/new.txt" {
		t.Errorf("expected Fields[path2]='/home/user/new.txt', got %v", ev.Fields["path2"])
	}
}

func TestFileHandler_RenameDenyOnSecondPath(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/old.txt": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_home",
			},
			"/etc/important": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_etc",
				Message:           "cannot write to /etc",
			},
		},
	}
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, emitter, true) // enforce=true

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_RENAMEAT2),
		Path:      "/home/user/old.txt",
		Path2:     "/etc/important",
		Operation: "rename",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	if result.Action != ActionDeny {
		t.Errorf("expected ActionDeny (second path denied), got %s", result.Action)
	}
	if result.Errno != int32(unix.EACCES) {
		t.Errorf("expected Errno EACCES, got %d", result.Errno)
	}
}

func TestFileHandler_NilPolicy(t *testing.T) {
	emitter := &mockFileEmitter{}
	registry := NewMountRegistry()
	handler := NewFileHandler(nil, registry, emitter, true) // nil policy

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/any/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)

	if result.Action != ActionContinue {
		t.Errorf("expected ActionContinue (nil policy), got %s", result.Action)
	}
	if len(emitter.events) != 1 {
		t.Fatalf("expected 1 event, got %d", len(emitter.events))
	}
	ev := emitter.events[0]
	if ev.Policy == nil {
		t.Fatal("expected non-nil Policy in event")
	}
	if ev.Policy.Rule != "no_policy" {
		t.Errorf("expected rule 'no_policy', got %q", ev.Policy.Rule)
	}
}

func TestFileHandler_NilEmitter(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/some/path": {
				Decision:          "allow",
				EffectiveDecision: "allow",
				Rule:              "allow_all",
			},
		},
	}
	registry := NewMountRegistry()
	// nil emitter - should not panic
	handler := NewFileHandler(policy, registry, nil, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/some/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	// Should not panic
	result := handler.Handle(req)
	assert.Equal(t, ActionContinue, result.Action)
}

func TestFileHandler_NilEmitterDeny(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{}, // default deny
	}
	registry := NewMountRegistry()
	handler := NewFileHandler(policy, registry, nil, true) // enforce=true, nil emitter

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/secret/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, int32(unix.EACCES), result.Errno)
}

func TestFileHandler_NilRegistry(t *testing.T) {
	policy := &mockFilePolicy{
		decisions: map[string]FilePolicyDecision{
			"/home/user/file.txt": {
				Decision:          "deny",
				EffectiveDecision: "deny",
				Rule:              "deny_all",
			},
		},
	}
	emitter := &mockFileEmitter{}
	// nil registry - should not panic, paths won't match FUSE
	handler := NewFileHandler(policy, nil, emitter, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/home/user/file.txt",
		Operation: "open",
		SessionID: "sess-1",
	}

	result := handler.Handle(req)
	// Should deny (not treated as FUSE path)
	assert.Equal(t, ActionDeny, result.Action)
	assert.Equal(t, int32(unix.EACCES), result.Errno)
}

func TestFileHandler_NilPolicyAndEmitter(t *testing.T) {
	handler := NewFileHandler(nil, nil, nil, true)

	req := FileRequest{
		PID:       1234,
		Syscall:   int32(unix.SYS_OPENAT),
		Path:      "/any/path",
		Operation: "open",
		SessionID: "sess-1",
	}

	// Should not panic, should allow
	result := handler.Handle(req)
	assert.Equal(t, ActionContinue, result.Action)
}
