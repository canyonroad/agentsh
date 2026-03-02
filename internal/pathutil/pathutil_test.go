package pathutil

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestIsUnderRoot(t *testing.T) {
	tests := []struct {
		path string
		root string
		want bool
	}{
		{"/workspace/sub", "/workspace", true},
		{"/workspace", "/workspace", true},
		{"/workspace2", "/workspace", false},
		{"/other", "/workspace", false},
		{"/etc", "/", true},
		{"/", "/", true},
		// Empty root must always return false (fail closed)
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
		{"/etc", "/", true},
		{"/tmp/foo", "/", true},
		{"/", "/", true},
		{"/anything", "", false},
		{"", "", false},
	}
	for _, tt := range tests {
		path := filepath.FromSlash(tt.path)
		root := filepath.FromSlash(tt.root)
		got := IsRealPathUnder(path, root)
		if got != tt.want {
			t.Errorf("IsRealPathUnder(%q, %q) = %v, want %v", path, root, got, tt.want)
		}
	}
	if runtime.GOOS == "windows" {
		winTests := []struct {
			path string
			root string
			want bool
		}{
			{`C:\Users\project\sub`, `C:\Users\project`, true},
			{`C:\Users\project`, `C:\Users\project`, true},
			{`C:\Users\project2`, `C:\Users\project`, false},
			{`c:\users\project\sub`, `C:\Users\project`, true},
			{`D:\other`, `C:\Users\project`, false},
			{`C:\`, `C:\`, true},
			{`C:\foo`, `C:\`, true},
		}
		for _, tt := range winTests {
			got := IsRealPathUnder(tt.path, tt.root)
			if got != tt.want {
				t.Errorf("IsRealPathUnder(%q, %q) = %v, want %v", tt.path, tt.root, got, tt.want)
			}
		}
	}
}

func TestTrimRootPrefix(t *testing.T) {
	tests := []struct {
		path string
		root string
		want string
	}{
		{"/workspace/sub/file", "/workspace", "/sub/file"},
		{"/workspace", "/workspace", ""},
		{"/other", "/workspace", "/other"},
	}
	for _, tt := range tests {
		got := TrimRootPrefix(tt.path, tt.root)
		if got != tt.want {
			t.Errorf("TrimRootPrefix(%q, %q) = %q, want %q", tt.path, tt.root, got, tt.want)
		}
	}
}

func TestIsRealPathUnder_PlatformSeparator(t *testing.T) {
	// Verify that the function uses os.PathSeparator correctly
	sep := string(os.PathSeparator)
	root := sep + "tmp" + sep + "ws"
	under := root + sep + "sub"
	sibling := sep + "tmp" + sep + "ws2"

	if !IsRealPathUnder(under, root) {
		t.Errorf("expected %q under %q", under, root)
	}
	if IsRealPathUnder(sibling, root) {
		t.Errorf("expected %q NOT under %q", sibling, root)
	}
}
