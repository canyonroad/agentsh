package session

import (
	"testing"
)

func TestFindMountEmpty(t *testing.T) {
	m := FindMount([]ResolvedMount{}, "/some/path")
	if m != nil {
		t.Errorf("FindMount on empty slice should return nil")
	}
}

func TestFindMount(t *testing.T) {
	mounts := []ResolvedMount{
		{Path: "/home/user", Policy: "base"},
		{Path: "/home/user/workspace", Policy: "workspace"},
		{Path: "/home/user/.config", Policy: "config"},
	}

	tests := []struct {
		path     string
		wantPath string
		wantNil  bool
	}{
		{"/home/user/workspace/file.txt", "/home/user/workspace", false},
		{"/home/user/.config/app.json", "/home/user/.config", false},
		{"/home/user/other/file.txt", "/home/user", false},
		{"/home/user/workspace", "/home/user/workspace", false},
		{"/etc/passwd", "", true},
	}

	for _, tt := range tests {
		m := FindMount(mounts, tt.path)
		if tt.wantNil {
			if m != nil {
				t.Errorf("FindMount(%q) = %v, want nil", tt.path, m.Path)
			}
		} else {
			if m == nil {
				t.Errorf("FindMount(%q) = nil, want %q", tt.path, tt.wantPath)
			} else if m.Path != tt.wantPath {
				t.Errorf("FindMount(%q) = %q, want %q", tt.path, m.Path, tt.wantPath)
			}
		}
	}
}

func TestFindMountOverlapping(t *testing.T) {
	mounts := []ResolvedMount{
		{Path: "/home/user", Policy: "base"},
		{Path: "/home/user/workspace", Policy: "workspace"},
		{Path: "/home/user/workspace/src", Policy: "src"},
	}

	tests := []struct {
		path     string
		wantPath string
	}{
		{"/home/user/file.txt", "/home/user"},
		{"/home/user/workspace/file.txt", "/home/user/workspace"},
		{"/home/user/workspace/src/main.go", "/home/user/workspace/src"},
		{"/home/user/workspace/src", "/home/user/workspace/src"}, // exact match
	}

	for _, tt := range tests {
		m := FindMount(mounts, tt.path)
		if m == nil {
			t.Errorf("FindMount(%q) = nil, want %q", tt.path, tt.wantPath)
		} else if m.Path != tt.wantPath {
			t.Errorf("FindMount(%q) = %q, want %q", tt.path, m.Path, tt.wantPath)
		}
	}
}
