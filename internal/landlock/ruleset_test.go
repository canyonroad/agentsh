//go:build linux

package landlock

import (
	"testing"
)

func TestRulesetBuilder_AddPath(t *testing.T) {
	b := NewRulesetBuilder(3) // ABI v3

	err := b.AddExecutePath("/usr/bin")
	if err != nil {
		t.Errorf("failed to add execute path: %v", err)
	}

	err = b.AddReadPath("/etc/ssl/certs")
	if err != nil {
		t.Errorf("failed to add read path: %v", err)
	}

	if len(b.executePaths) != 1 {
		t.Errorf("expected 1 execute path, got %d", len(b.executePaths))
	}
	if len(b.readPaths) != 1 {
		t.Errorf("expected 1 read path, got %d", len(b.readPaths))
	}
}

func TestRulesetBuilder_DenyPaths(t *testing.T) {
	b := NewRulesetBuilder(3)
	b.AddDenyPath("/var/run/docker.sock")

	if len(b.denyPaths) != 1 {
		t.Errorf("expected 1 deny path, got %d", len(b.denyPaths))
	}
}

func TestRulesetBuilder_WorkspacePath(t *testing.T) {
	b := NewRulesetBuilder(3)
	b.SetWorkspace("/home/user/project")

	if b.workspace != "/home/user/project" {
		t.Errorf("expected workspace /home/user/project, got %s", b.workspace)
	}
}

func TestRulesetBuilder_NetworkAccess(t *testing.T) {
	b := NewRulesetBuilder(4) // ABI v4 for network support
	b.SetNetworkAccess(true, false)

	if !b.allowNetwork {
		t.Error("expected allowNetwork to be true")
	}
	if b.allowBind {
		t.Error("expected allowBind to be false")
	}
}

func TestRulesetBuilder_WriteAccessMask_IncludesMakeSock(t *testing.T) {
	// Write-allowed paths must support Unix domain socket creation (MAKE_SOCK).
	// Without this, bind() for Unix sockets in /tmp etc. fails with EACCES
	// even when the path is in the Landlock write list.
	b := NewRulesetBuilder(3)
	mask := b.buildWriteAccessMask()

	if mask&LANDLOCK_ACCESS_FS_MAKE_SOCK == 0 {
		t.Error("writeAccessMask missing MAKE_SOCK — Unix socket creation blocked in write-allowed paths")
	}
	// Sanity: verify other expected bits are present
	if mask&LANDLOCK_ACCESS_FS_WRITE_FILE == 0 {
		t.Error("writeAccessMask missing WRITE_FILE")
	}
	if mask&LANDLOCK_ACCESS_FS_MAKE_REG == 0 {
		t.Error("writeAccessMask missing MAKE_REG")
	}
	if mask&LANDLOCK_ACCESS_FS_MAKE_DIR == 0 {
		t.Error("writeAccessMask missing MAKE_DIR")
	}
	// TRUNCATE should be present for ABI >= 3
	if mask&LANDLOCK_ACCESS_FS_TRUNCATE == 0 {
		t.Error("writeAccessMask missing TRUNCATE for ABI v3")
	}
}

func TestRulesetBuilder_IsDenied(t *testing.T) {
	b := NewRulesetBuilder(3)
	b.AddDenyPath("/var/run/docker.sock")
	b.AddDenyPath("/run/containerd")

	tests := []struct {
		path   string
		denied bool
	}{
		{"/var/run/docker.sock", true},
		{"/run/containerd", true},
		{"/run/containerd/containerd.sock", true},
		{"/usr/bin", false},
		{"/var/run/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if b.isDenied(tt.path) != tt.denied {
				t.Errorf("isDenied(%q) = %v, want %v", tt.path, b.isDenied(tt.path), tt.denied)
			}
		})
	}
}
