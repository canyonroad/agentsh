//go:build darwin && cgo

package sandboxext

import (
	"os"
	"testing"
)

func TestIssue_ReturnsToken(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	tok, err := m.Issue(dir, ReadOnly)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}
	if tok.Value == "" {
		t.Fatal("Issue() returned token with empty Value")
	}
	if tok.Path != dir {
		t.Errorf("Token.Path = %q, want %q", tok.Path, dir)
	}
	if tok.Class != ReadOnly {
		t.Errorf("Token.Class = %q, want %q", tok.Class, ReadOnly)
	}
	if tok.Issued.IsZero() {
		t.Error("Token.Issued should not be zero")
	}
}

func TestActiveTokens_ReturnsIssuedTokens(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	_, err := m.Issue(dir, ReadOnly)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	active := m.ActiveTokens()
	if len(active) != 1 {
		t.Fatalf("ActiveTokens() len = %d, want 1", len(active))
	}
	if active[0].Path != dir {
		t.Errorf("ActiveTokens()[0].Path = %q, want %q", active[0].Path, dir)
	}
}

func TestRevoke_RemovesToken(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	_, err := m.Issue(dir, ReadWrite)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if err := m.Revoke(dir); err != nil {
		t.Fatalf("Revoke() error = %v", err)
	}

	active := m.ActiveTokens()
	if len(active) != 0 {
		t.Errorf("ActiveTokens() len = %d after Revoke, want 0", len(active))
	}
}

func TestRevokeAll_ClearsAll(t *testing.T) {
	m := NewManager()
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	if _, err := m.Issue(dir1, ReadOnly); err != nil {
		t.Fatalf("Issue(dir1) error = %v", err)
	}
	if _, err := m.Issue(dir2, ReadWrite); err != nil {
		t.Fatalf("Issue(dir2) error = %v", err)
	}

	m.RevokeAll()

	active := m.ActiveTokens()
	if len(active) != 0 {
		t.Errorf("ActiveTokens() len = %d after RevokeAll, want 0", len(active))
	}
}

func TestRevoke_DoubleRevoke_NoError(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	if _, err := m.Issue(dir, ReadOnly); err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	if err := m.Revoke(dir); err != nil {
		t.Fatalf("first Revoke() error = %v", err)
	}

	if err := m.Revoke(dir); err != nil {
		t.Errorf("second Revoke() should not error, got %v", err)
	}
}

func TestIssue_NonexistentPath(t *testing.T) {
	m := NewManager()
	path := "/tmp/sandboxext-test-nonexistent-" + t.Name()
	// Ensure it doesn't exist
	os.RemoveAll(path)

	// The sandbox_extension_issue_file API may succeed even for non-existent
	// paths (it issues a capability token, not a file handle). We document
	// whichever behavior the system exhibits.
	tok, err := m.Issue(path, ReadOnly)
	if err != nil {
		t.Logf("Issue() on non-existent path returned error: %v (this is acceptable)", err)
		return
	}
	t.Logf("Issue() on non-existent path succeeded with token Value=%q (this is acceptable)", tok.Value)
}

func TestConsumeToken_ValidToken(t *testing.T) {
	m := NewManager()
	dir := t.TempDir()

	tok, err := m.Issue(dir, ReadOnly)
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	handle, err := ConsumeToken(tok.Value)
	if err != nil {
		t.Fatalf("ConsumeToken() error = %v", err)
	}
	if handle < 0 {
		t.Errorf("ConsumeToken() handle = %d, want >= 0", handle)
	}
}

func TestConsumeToken_InvalidToken(t *testing.T) {
	_, err := ConsumeToken("this-is-not-a-valid-token")
	if err == nil {
		t.Error("ConsumeToken with invalid token should return error")
	}
}

func TestConsumeToken_EmptyString(t *testing.T) {
	_, err := ConsumeToken("")
	if err == nil {
		t.Error("ConsumeToken with empty string should return error")
	}
}

func TestIssue_Consume_Revoke_FullLifecycle(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	dir := t.TempDir()

	// Issue
	tok, err := mgr.Issue(dir, ReadOnly)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Consume the token
	handle, err := ConsumeToken(tok.Value)
	if err != nil {
		t.Fatalf("ConsumeToken: %v", err)
	}
	if handle < 0 {
		t.Fatalf("handle should be >= 0, got %d", handle)
	}

	// Revoke should still work (manager tracks by path, not by consumption)
	if err := mgr.Revoke(dir); err != nil {
		t.Fatalf("Revoke after consume: %v", err)
	}

	// Should be removed
	if len(mgr.ActiveTokens()) != 0 {
		t.Error("token should be removed after revoke")
	}
}

func TestTokenValues_ExcludesRevokedTokens(t *testing.T) {
	mgr := NewManager()
	defer mgr.RevokeAll()

	d1 := t.TempDir()
	d2 := t.TempDir()
	mgr.Issue(d1, ReadOnly)
	mgr.Issue(d2, ReadWrite)

	if len(mgr.TokenValues()) != 2 {
		t.Fatalf("expected 2 token values, got %d", len(mgr.TokenValues()))
	}

	mgr.Revoke(d1)
	values := mgr.TokenValues()
	if len(values) != 1 {
		t.Errorf("after revoking one, expected 1 token value, got %d", len(values))
	}
}

func TestTokenValues_ReturnsStrings(t *testing.T) {
	m := NewManager()
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	tok1, err := m.Issue(dir1, ReadOnly)
	if err != nil {
		t.Fatalf("Issue(dir1) error = %v", err)
	}
	tok2, err := m.Issue(dir2, ReadWrite)
	if err != nil {
		t.Fatalf("Issue(dir2) error = %v", err)
	}

	values := m.TokenValues()
	if len(values) != 2 {
		t.Fatalf("TokenValues() len = %d, want 2", len(values))
	}

	// Values should contain the token strings (order not guaranteed by map)
	found1, found2 := false, false
	for _, v := range values {
		if v == tok1.Value {
			found1 = true
		}
		if v == tok2.Value {
			found2 = true
		}
	}
	if !found1 {
		t.Error("TokenValues() missing token for dir1")
	}
	if !found2 {
		t.Error("TokenValues() missing token for dir2")
	}
}
