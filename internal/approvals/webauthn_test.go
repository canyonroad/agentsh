package approvals

import (
	"testing"
)

func TestManager_WebAuthnMode(t *testing.T) {
	m := New("webauthn", 0, nil)
	if m.mode != "webauthn" {
		t.Errorf("expected mode webauthn, got %s", m.mode)
	}
}

func TestManager_GetWebAuthnChallenge_WrongMode(t *testing.T) {
	m := New("local_tty", 0, nil)
	_, err := m.GetWebAuthnChallenge(nil, "approval-1", "user-1")
	if err == nil {
		t.Error("expected error for wrong mode")
	}
}

func TestManager_GetWebAuthnChallenge_NoApprover(t *testing.T) {
	m := New("webauthn", 0, nil)
	_, err := m.GetWebAuthnChallenge(nil, "approval-1", "user-1")
	if err == nil {
		t.Error("expected error when approver not configured")
	}
}

func TestManager_ResolveWithWebAuthn_NoApprover(t *testing.T) {
	m := New("webauthn", 0, nil)
	err := m.ResolveWithWebAuthn(nil, "approval-1", "user-1", []byte("{}"))
	if err == nil {
		t.Error("expected error when approver not configured")
	}
}

func TestManager_ResolveWithWebAuthn_WrongMode(t *testing.T) {
	m := New("local_tty", 0, nil)
	err := m.ResolveWithWebAuthn(nil, "approval-1", "user-1", []byte("{}"))
	if err == nil {
		t.Error("expected error for wrong mode")
	}
	if err.Error() != "webauthn mode not enabled" {
		t.Errorf("expected 'webauthn mode not enabled' error, got: %v", err)
	}
}

func TestManager_ResolveWithWebAuthn_ApprovalNotFound(t *testing.T) {
	m := New("webauthn", 0, nil)
	m.SetWebAuthnApprover(&WebAuthnApprover{})
	err := m.ResolveWithWebAuthn(nil, "nonexistent-approval", "user-1", []byte("{}"))
	if err == nil {
		t.Error("expected error when approval not found")
	}
	if err.Error() != "approval not found: nonexistent-approval" {
		t.Errorf("expected 'approval not found' error, got: %v", err)
	}
}
