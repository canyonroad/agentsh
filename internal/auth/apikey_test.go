package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAPIKeysDefaultsAndRoles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.yml")
	err := os.WriteFile(path, []byte(`
- id: admin
  key: AAA
  role: admin
- id: approver
  key: BBB
  role: approver
- id: empty-role
  key: CCC
`), 0o644)
	if err != nil {
		t.Fatalf("write keys file: %v", err)
	}

	auth, err := LoadAPIKeys(path, "")
	if err != nil {
		t.Fatalf("LoadAPIKeys: %v", err)
	}
	if got := auth.HeaderName(); got != "X-API-Key" {
		t.Fatalf("HeaderName = %q, want X-API-Key", got)
	}
	tests := []struct {
		key  string
		role string
	}{
		{"AAA", "admin"},
		{"BBB", "approver"},
		{"CCC", "admin"}, // defaults to admin when role empty
	}
	for _, tt := range tests {
		if !auth.IsAllowed(tt.key) {
			t.Fatalf("IsAllowed(%q) = false, want true", tt.key)
		}
		if got := auth.RoleForKey(tt.key); got != tt.role {
			t.Fatalf("RoleForKey(%q) = %q, want %q", tt.key, got, tt.role)
		}
	}
	if auth.IsAllowed("nope") {
		t.Fatalf("IsAllowed should be false for unknown key")
	}
	if auth.RoleForKey("nope") != "" {
		t.Fatalf("RoleForKey should be empty for unknown key")
	}
}
