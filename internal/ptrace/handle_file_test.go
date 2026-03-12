//go:build linux

package ptrace

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSyscallToOperation(t *testing.T) {
	tests := []struct {
		name  string
		nr    int
		flags int
		want  string
	}{
		{"openat read-only", unix.SYS_OPENAT, unix.O_RDONLY, "read"},
		{"openat write-only", unix.SYS_OPENAT, unix.O_WRONLY, "write"},
		{"openat read-write", unix.SYS_OPENAT, unix.O_RDWR, "write"},
		{"openat create", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_CREAT, "create"},
		{"openat create rdwr", unix.SYS_OPENAT, unix.O_RDWR | unix.O_CREAT, "create"},
		{"openat trunc", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_TRUNC, "write"},
		{"openat tmpfile", unix.SYS_OPENAT, unix.O_TMPFILE | unix.O_RDWR, "create"},
		{"openat2 read-only", unix.SYS_OPENAT2, unix.O_RDONLY, "read"},
		{"openat2 write", unix.SYS_OPENAT2, unix.O_WRONLY, "write"},
		{"openat2 create", unix.SYS_OPENAT2, unix.O_WRONLY | unix.O_CREAT, "create"},
		{"unlinkat", unix.SYS_UNLINKAT, 0, "delete"},
		{"unlinkat removedir", unix.SYS_UNLINKAT, unix.AT_REMOVEDIR, "rmdir"},
		{"mkdirat", unix.SYS_MKDIRAT, 0, "mkdir"},
		{"renameat2", unix.SYS_RENAMEAT2, 0, "rename"},
		{"linkat", unix.SYS_LINKAT, 0, "link"},
		{"symlinkat", unix.SYS_SYMLINKAT, 0, "symlink"},
		{"fchmodat", unix.SYS_FCHMODAT, 0, "chmod"},
		{"fchownat", unix.SYS_FCHOWNAT, 0, "chown"},
		{"unknown", 99999, 0, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := syscallToOperation(tt.nr, tt.flags)
			if got != tt.want {
				t.Errorf("syscallToOperation(%d, %d) = %q, want %q", tt.nr, tt.flags, got, tt.want)
			}
		})
	}
}

func TestResolvePath_NonexistentFile(t *testing.T) {
	// resolvePath should succeed for a nonexistent file in an existing directory
	// (e.g. create operations).
	dir := t.TempDir()
	path, err := resolvePath(0, unix.AT_FDCWD, filepath.Join(dir, "newfile"))
	if err != nil {
		t.Fatalf("resolvePath for nonexistent file: unexpected error: %v", err)
	}
	if path != filepath.Join(dir, "newfile") {
		t.Errorf("resolvePath = %q, want %q", path, filepath.Join(dir, "newfile"))
	}
}

func TestResolvePath_SymlinkLoop(t *testing.T) {
	// resolvePath should return an error for a symlink loop (ELOOP),
	// not silently fall back to an unresolved path.
	dir := t.TempDir()
	link1 := filepath.Join(dir, "loop1")
	link2 := filepath.Join(dir, "loop2")
	os.Symlink(link2, link1)
	os.Symlink(link1, link2)

	_, err := resolvePath(0, unix.AT_FDCWD, link1)
	if err == nil {
		t.Fatal("resolvePath for symlink loop: expected error, got nil")
	}
}

func TestResolvePath_NotDir(t *testing.T) {
	// resolvePath should return an error when a path component is not a directory.
	dir := t.TempDir()
	file := filepath.Join(dir, "afile")
	os.WriteFile(file, []byte("x"), 0o644)

	// Try to resolve a path through a regular file as if it were a directory.
	_, err := resolvePath(0, unix.AT_FDCWD, filepath.Join(file, "child"))
	if err == nil {
		t.Fatal("resolvePath through non-directory: expected error, got nil")
	}
}

func TestResolvePath_DanglingSymlink(t *testing.T) {
	// A dangling symlink should cause resolvePath to fail, not silently
	// return the symlink path. The kernel would follow the symlink on
	// O_CREAT, potentially creating a file in a forbidden directory.
	dir := t.TempDir()
	link := filepath.Join(dir, "dangling")
	os.Symlink("/nonexistent/target/file", link)

	_, err := resolvePath(0, unix.AT_FDCWD, link)
	if err == nil {
		t.Fatal("resolvePath for dangling symlink: expected error, got nil")
	}
}
