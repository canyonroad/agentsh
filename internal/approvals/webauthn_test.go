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
