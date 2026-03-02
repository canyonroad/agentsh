package session

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/agentsh/agentsh/pkg/types"
)

func TestManager_ReapExpired_IdleTimeout(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	base := s.CreatedAt

	// Should not reap before idle timeout.
	if got := m.ReapExpired(base.Add(29*time.Minute), 0, 30*time.Minute); len(got) != 0 {
		t.Fatalf("expected no reaped sessions, got %d", len(got))
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatalf("expected session still present")
	}

	// Should reap after idle timeout.
	got := m.ReapExpired(base.Add(31*time.Minute), 0, 30*time.Minute)
	if len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("expected to reap session %s, got %+v", s.ID, got)
	}
	if _, ok := m.Get(s.ID); ok {
		t.Fatalf("expected session removed")
	}
}

func TestManager_ReapExpired_TouchExtendsIdle(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	base := s.CreatedAt

	// Activity at +20m should prevent reaping at +31m with 30m idle timeout.
	s.TouchAt(base.Add(20 * time.Minute))
	if got := m.ReapExpired(base.Add(31*time.Minute), 0, 30*time.Minute); len(got) != 0 {
		t.Fatalf("expected no reaped sessions, got %d", len(got))
	}
	if _, ok := m.Get(s.ID); !ok {
		t.Fatalf("expected session still present")
	}
}

func TestManager_ReapExpired_SessionTimeoutWins(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.Create(ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	base := s.CreatedAt

	// Even with recent activity, session timeout should reap.
	s.TouchAt(base.Add(59 * time.Minute))
	got := m.ReapExpired(base.Add(61*time.Minute), 1*time.Hour, 2*time.Hour)
	if len(got) != 1 || got[0].ID != s.ID {
		t.Fatalf("expected to reap session by session_timeout, got %+v", got)
	}
}

func TestCreateWithProfile(t *testing.T) {
	m := NewManager(10)

	mounts := []ResolvedMount{
		{Path: "/workspace", Policy: "workspace-rw"},
		{Path: "/config", Policy: "config-readonly"},
	}

	s, err := m.CreateWithProfile("test_id", "my-profile", "default", mounts)
	if err != nil {
		t.Fatalf("CreateWithProfile: %v", err)
	}

	if s.Profile != "my-profile" {
		t.Errorf("Profile = %q, want %q", s.Profile, "my-profile")
	}
	if len(s.Mounts) != 2 {
		t.Errorf("len(Mounts) = %d, want 2", len(s.Mounts))
	}
	if s.Policy != "default" {
		t.Errorf("Policy = %q, want %q", s.Policy, "default")
	}
	// First mount path should be used as workspace
	if s.Workspace != "/workspace" {
		t.Errorf("Workspace = %q, want %q", s.Workspace, "/workspace")
	}
}

func TestCreateWithProfile_EmptyMounts(t *testing.T) {
	m := NewManager(10)

	_, err := m.CreateWithProfile("test_id", "my-profile", "default", []ResolvedMount{})
	if err == nil {
		t.Error("CreateWithProfile with empty mounts should return error")
	}
}

func TestCreateWithProfile_DuplicateSessionID(t *testing.T) {
	m := NewManager(10)

	mounts := []ResolvedMount{
		{Path: "/workspace", Policy: "workspace-rw"},
	}

	_, err := m.CreateWithProfile("duplicate_id", "profile1", "default", mounts)
	if err != nil {
		t.Fatalf("first CreateWithProfile: %v", err)
	}

	_, err = m.CreateWithProfile("duplicate_id", "profile2", "default", mounts)
	if err != ErrSessionExists {
		t.Errorf("second CreateWithProfile: got %v, want ErrSessionExists", err)
	}
}

func TestCreateWithProfile_MaxSessionsLimit(t *testing.T) {
	m := NewManager(2) // max 2 sessions

	mounts := []ResolvedMount{
		{Path: "/workspace", Policy: "workspace-rw"},
	}

	_, err := m.CreateWithProfile("session1", "profile", "default", mounts)
	if err != nil {
		t.Fatalf("first CreateWithProfile: %v", err)
	}

	_, err = m.CreateWithProfile("session2", "profile", "default", mounts)
	if err != nil {
		t.Fatalf("second CreateWithProfile: %v", err)
	}

	_, err = m.CreateWithProfile("session3", "profile", "default", mounts)
	if err == nil {
		t.Error("third CreateWithProfile should return error (max sessions reached)")
	}
}

func TestCreateWithProfile_InvalidSessionID(t *testing.T) {
	m := NewManager(10)

	mounts := []ResolvedMount{
		{Path: "/workspace", Policy: "workspace-rw"},
	}

	// Invalid: starts with underscore
	_, err := m.CreateWithProfile("_invalid", "profile", "default", mounts)
	if err != ErrInvalidSessionID {
		t.Errorf("CreateWithProfile with invalid ID: got %v, want ErrInvalidSessionID", err)
	}

	// Invalid: contains special characters
	_, err = m.CreateWithProfile("invalid@id", "profile", "default", mounts)
	if err != ErrInvalidSessionID {
		t.Errorf("CreateWithProfile with invalid ID: got %v, want ErrInvalidSessionID", err)
	}
}

func TestCreateWithID_DefaultVirtualRoot(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-default-vroot", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	if s.VirtualRoot != "/workspace" {
		t.Errorf("VirtualRoot = %q, want /workspace", s.VirtualRoot)
	}
	if s.Cwd != "/workspace" {
		t.Errorf("Cwd = %q, want /workspace", s.Cwd)
	}
}

func TestSetRealPaths_Enable(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-real-enable", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)
	want := filepath.ToSlash(filepath.Clean(ws))
	if s.VirtualRoot != want {
		t.Errorf("VirtualRoot = %q, want %q", s.VirtualRoot, want)
	}
	if s.Cwd != want {
		t.Errorf("Cwd = %q, want %q", s.Cwd, want)
	}
}

func TestSetRealPaths_Disable(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-real-disable", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)
	s.SetRealPaths(false)
	if s.VirtualRoot != "/workspace" {
		t.Errorf("VirtualRoot = %q, want /workspace", s.VirtualRoot)
	}
	if s.Cwd != "/workspace" {
		t.Errorf("Cwd = %q, want /workspace", s.Cwd)
	}
}

func TestCreateWithProfile_DefaultVirtualRoot(t *testing.T) {
	m := NewManager(10)
	mounts := []ResolvedMount{
		{Path: "/tmp/test-project", Policy: "workspace-rw"},
	}
	s, err := m.CreateWithProfile("test-profile-vroot", "my-profile", "default", mounts)
	if err != nil {
		t.Fatal(err)
	}
	if s.VirtualRoot != "/workspace" {
		t.Errorf("VirtualRoot = %q, want /workspace", s.VirtualRoot)
	}
}

func TestSetRealPaths_TrailingSlash(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-trailing", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Manually set workspace with trailing slash to test normalization
	s.Workspace = ws + "/"
	s.SetRealPaths(true)
	want := filepath.ToSlash(filepath.Clean(ws))
	if s.VirtualRoot != want {
		t.Errorf("VirtualRoot = %q, want %q (no trailing slash)", s.VirtualRoot, want)
	}
}

func TestSetRealPaths_EmptyWorkspace(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-empty-ws", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	// Manually set workspace to empty to test defensive behavior
	s.Workspace = ""
	if s.SetRealPaths(true) {
		t.Error("SetRealPaths(true) returned true on empty workspace, want false")
	}
	// Should be a no-op: VirtualRoot stays at default
	if s.VirtualRoot != "/workspace" {
		t.Errorf("VirtualRoot = %q, want /workspace (no-op on empty workspace)", s.VirtualRoot)
	}
}

func TestBuiltin_Cd_RealPaths(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-cd-real", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// cd with no args should go to VirtualRoot
	handled, code, _, _ := s.Builtin(types.ExecRequest{Command: "cd"})
	if !handled || code != 0 {
		t.Fatalf("cd: handled=%v code=%d", handled, code)
	}
	cwd, _, _ := s.GetCwdEnvHistory()
	if cwd != ws {
		t.Errorf("after cd: Cwd = %q, want %q", cwd, ws)
	}
}

func TestBuiltin_Cd_DefaultWorkspace(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-cd-default", ws, "default")
	if err != nil {
		t.Fatal(err)
	}

	handled, code, _, _ := s.Builtin(types.ExecRequest{Command: "cd"})
	if !handled || code != 0 {
		t.Fatalf("cd: handled=%v code=%d", handled, code)
	}
	cwd, _, _ := s.GetCwdEnvHistory()
	if cwd != "/workspace" {
		t.Errorf("after cd: Cwd = %q, want /workspace", cwd)
	}
}

func TestApplyPatch_RealPaths(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-patch-real", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Patch cwd to subdir under workspace
	err = s.ApplyPatch(types.SessionPatchRequest{Cwd: ws + "/subdir"})
	if err != nil {
		t.Fatalf("ApplyPatch: %v", err)
	}
	cwd, _, _ := s.GetCwdEnvHistory()
	if cwd != ws+"/subdir" {
		t.Errorf("Cwd = %q, want %q", cwd, ws+"/subdir")
	}

	// Patch cwd outside workspace should fail
	err = s.ApplyPatch(types.SessionPatchRequest{Cwd: "/etc"})
	if err == nil {
		t.Error("expected error patching cwd outside workspace")
	}
}

func TestResolvePathForBuiltin_RealPaths_OutsideWorkspace(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-resolve-outside", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Outside workspace path should be rejected for builtins
	_, _, err = s.resolvePathForBuiltin("/etc/hosts")
	if err == nil {
		t.Error("expected error for path outside workspace in builtins")
	}
}

func TestResolvePathForBuiltin_SiblingPath_NotConfused(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir() // e.g., /tmp/TestXXX123

	s, err := m.CreateWithID("test-sibling", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// A sibling path like /tmp/TestXXX123-extra should NOT match — rejected by builtins
	sibling := ws + "-extra/file.txt"
	_, _, err = s.resolvePathForBuiltin(sibling)
	if err == nil {
		t.Error("expected error for sibling path outside workspace")
	}
}

func TestApplyPatch_RealPaths_SiblingPath(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-patch-sibling", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Sibling path should be rejected
	err = s.ApplyPatch(types.SessionPatchRequest{Cwd: ws + "-extra"})
	if err == nil {
		t.Error("expected error patching cwd to sibling path")
	}
}

func TestIsUnderRoot(t *testing.T) {
	tests := []struct {
		path string
		root string
		want bool
	}{
		{"/workspace", "/workspace", true},
		{"/workspace/foo", "/workspace", true},
		{"/workspace/foo/bar", "/workspace", true},
		{"/workspace2", "/workspace", false},
		{"/workspacefoo", "/workspace", false},
		{"/other", "/workspace", false},
		// Root == "/" edge case
		{"/anything", "/", true},
		{"/workspace", "/", true},
		{"/", "/", true},
		// Real-paths style roots
		{"/home/user/work", "/home/user/work", true},
		{"/home/user/work/src", "/home/user/work", true},
		{"/home/user/work2", "/home/user/work", false},
		{"/home/user/worker", "/home/user/work", false},
		// Empty root must always return false
		{"/anything", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got := IsUnderRoot(tt.path, tt.root)
		if got != tt.want {
			t.Errorf("IsUnderRoot(%q, %q) = %v, want %v", tt.path, tt.root, got, tt.want)
		}
	}
}

func TestBuiltin_Cd_RelativePath(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-cd-rel", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// cd to a subdirectory (relative)
	handled, code, _, _ := s.Builtin(types.ExecRequest{Command: "cd", Args: []string{"subdir"}})
	if !handled || code != 0 {
		t.Fatalf("cd subdir: handled=%v code=%d", handled, code)
	}
	cwd, _, _ := s.GetCwdEnvHistory()
	want := s.VirtualRoot + "/subdir"
	if cwd != want {
		t.Errorf("after cd subdir: cwd=%q want %q", cwd, want)
	}

	// cd to parent with .. — should resolve back to VirtualRoot
	handled, code, _, _ = s.Builtin(types.ExecRequest{Command: "cd", Args: []string{".."}})
	if !handled || code != 0 {
		t.Fatalf("cd ..: handled=%v code=%d", handled, code)
	}
	cwd, _, _ = s.GetCwdEnvHistory()
	if cwd != s.VirtualRoot {
		t.Errorf("after cd ..: cwd=%q want %q", cwd, s.VirtualRoot)
	}
}

func TestBuiltin_Cd_EscapeWithDotDot(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-cd-escape", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// Try to escape with ..
	handled, code, _, stderr := s.Builtin(types.ExecRequest{Command: "cd", Args: []string{".."}})
	if !handled {
		t.Fatal("cd should be handled")
	}
	if code == 0 {
		t.Error("cd .. from VirtualRoot should fail")
	}
	if len(stderr) == 0 {
		t.Error("expected error message in stderr")
	}
}

func TestBuiltin_Cd_NoArgs_ResetsToVirtualRoot(t *testing.T) {
	m := NewManager(10)
	ws := t.TempDir()

	s, err := m.CreateWithID("test-cd-noargs", ws, "default")
	if err != nil {
		t.Fatal(err)
	}
	s.SetRealPaths(true)

	// First cd into a subdirectory
	s.Builtin(types.ExecRequest{Command: "cd", Args: []string{"sub"}})

	// cd with no args should reset to VirtualRoot
	handled, code, _, _ := s.Builtin(types.ExecRequest{Command: "cd"})
	if !handled || code != 0 {
		t.Fatalf("cd (no args): handled=%v code=%d", handled, code)
	}
	cwd, _, _ := s.GetCwdEnvHistory()
	if cwd != s.VirtualRoot {
		t.Errorf("after cd (no args): cwd=%q want %q", cwd, s.VirtualRoot)
	}
}

func TestIsRealPathUnder(t *testing.T) {
	tests := []struct {
		path string
		root string
		want bool
	}{
		{"/tmp/ws/sub", "/tmp/ws", true},
		{"/tmp/ws", "/tmp/ws", true},
		{"/tmp/ws2", "/tmp/ws", false},
		{"/other", "/tmp/ws", false},
		// Root == "/" — everything is under root
		{"/etc", "/", true},
		{"/tmp/foo", "/", true},
		{"/", "/", true},
		// Empty root must always return false
		{"/anything", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		got := IsRealPathUnder(tt.path, tt.root)
		if got != tt.want {
			t.Errorf("IsRealPathUnder(%q, %q) = %v, want %v", tt.path, tt.root, got, tt.want)
		}
	}
}
