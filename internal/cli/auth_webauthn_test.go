package cli

import (
	"testing"
)

func TestAuthWebAuthnCmd_Help(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"auth", "webauthn", "--help"})
	if err := cmd.Execute(); err != nil {
		t.Errorf("auth webauthn help failed: %v", err)
	}
}

func TestAuthWebAuthnListCmd(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"auth", "webauthn", "list"})
	if err := cmd.Execute(); err != nil {
		t.Errorf("auth webauthn list failed: %v", err)
	}
}

func TestAuthWebAuthnRegisterCmd_RequiresName(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"auth", "webauthn", "register"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error without --name")
	}
}

func TestAuthWebAuthnDeleteCmd_ValidatesBase64(t *testing.T) {
	cmd := NewRoot("test")
	cmd.SetArgs([]string{"auth", "webauthn", "delete", "--credential-id", "not-valid-base64!!!"})
	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}
