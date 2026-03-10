//go:build linux && cgo && amd64

package unix

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

func TestIsLegacyFileSyscall(t *testing.T) {
	legacySyscalls := []int32{
		unix.SYS_OPEN,
		unix.SYS_CREAT,
		unix.SYS_MKDIR,
		unix.SYS_RMDIR,
		unix.SYS_UNLINK,
		unix.SYS_RENAME,
		unix.SYS_LINK,
		unix.SYS_SYMLINK,
		unix.SYS_CHMOD,
		unix.SYS_CHOWN,
	}

	for _, nr := range legacySyscalls {
		assert.True(t, isLegacyFileSyscall(nr), "expected true for syscall %d", nr)
		// Also verify the main dispatcher recognizes them
		assert.True(t, isFileSyscall(nr), "expected isFileSyscall true for legacy syscall %d", nr)
	}

	// Non-file syscalls should still return false
	assert.False(t, isLegacyFileSyscall(unix.SYS_READ))
	assert.False(t, isLegacyFileSyscall(unix.SYS_WRITE))
}

func TestLegacySyscallToOperation(t *testing.T) {
	tests := []struct {
		name     string
		nr       int32
		flags    uint32
		expected string
	}{
		{"open read-only", unix.SYS_OPEN, 0, "open"},
		{"open O_CREAT", unix.SYS_OPEN, unix.O_CREAT, "create"},
		{"open O_WRONLY", unix.SYS_OPEN, unix.O_WRONLY, "write"},
		{"open O_RDWR", unix.SYS_OPEN, unix.O_RDWR, "write"},
		{"open O_APPEND", unix.SYS_OPEN, unix.O_APPEND, "write"},
		{"open O_TRUNC", unix.SYS_OPEN, unix.O_TRUNC, "write"},
		{"creat", unix.SYS_CREAT, 0, "create"},
		{"mkdir", unix.SYS_MKDIR, 0, "mkdir"},
		{"rmdir", unix.SYS_RMDIR, 0, "rmdir"},
		{"unlink", unix.SYS_UNLINK, 0, "delete"},
		{"rename", unix.SYS_RENAME, 0, "rename"},
		{"link", unix.SYS_LINK, 0, "link"},
		{"symlink", unix.SYS_SYMLINK, 0, "symlink"},
		{"chmod", unix.SYS_CHMOD, 0, "chmod"},
		{"chown", unix.SYS_CHOWN, 0, "chown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test direct legacy function
			assert.Equal(t, tt.expected, legacySyscallToOperation(tt.nr, tt.flags))
			// Test through main dispatcher
			assert.Equal(t, tt.expected, syscallToOperation(tt.nr, tt.flags))
		})
	}
}

func TestLegacyFileSyscallName(t *testing.T) {
	tests := []struct {
		nr       int32
		expected string
	}{
		{unix.SYS_OPEN, "open"},
		{unix.SYS_CREAT, "creat"},
		{unix.SYS_MKDIR, "mkdir"},
		{unix.SYS_RMDIR, "rmdir"},
		{unix.SYS_UNLINK, "unlink"},
		{unix.SYS_RENAME, "rename"},
		{unix.SYS_LINK, "link"},
		{unix.SYS_SYMLINK, "symlink"},
		{unix.SYS_CHMOD, "chmod"},
		{unix.SYS_CHOWN, "chown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, legacyFileSyscallName(tt.nr))
			assert.Equal(t, tt.expected, fileSyscallName(tt.nr))
		})
	}
}

func TestExtractLegacyFileArgs_Open(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_OPEN,
		Arg0: 0x7fff1000,            // path
		Arg1: uint64(unix.O_RDONLY), // flags
		Arg2: 0644,                  // mode
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff1000), fa.PathPtr)
	assert.Equal(t, uint32(unix.O_RDONLY), fa.Flags)
	assert.Equal(t, uint32(0644), fa.Mode)
	assert.False(t, fa.HasSecondPath)
}

func TestExtractLegacyFileArgs_Creat(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_CREAT,
		Arg0: 0x7fff2000, // path
		Arg1: 0644,       // mode
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff2000), fa.PathPtr)
	assert.Equal(t, uint32(0644), fa.Mode)
}

func TestExtractLegacyFileArgs_Mkdir(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_MKDIR,
		Arg0: 0x7fff3000, // path
		Arg1: 0755,       // mode
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff3000), fa.PathPtr)
	assert.Equal(t, uint32(0755), fa.Mode)
}

func TestExtractLegacyFileArgs_Rmdir(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_RMDIR,
		Arg0: 0x7fff4000, // path
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff4000), fa.PathPtr)
}

func TestExtractLegacyFileArgs_Unlink(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_UNLINK,
		Arg0: 0x7fff5000, // path
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff5000), fa.PathPtr)
}

func TestExtractLegacyFileArgs_Rename(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_RENAME,
		Arg0: 0x7fff6000, // oldpath
		Arg1: 0x7fff7000, // newpath
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff6000), fa.PathPtr)
	assert.True(t, fa.HasSecondPath)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd2)
	assert.Equal(t, uint64(0x7fff7000), fa.PathPtr2)
}

func TestExtractLegacyFileArgs_Link(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_LINK,
		Arg0: 0x7fff8000, // oldpath
		Arg1: 0x7fff9000, // newpath
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff8000), fa.PathPtr)
	assert.True(t, fa.HasSecondPath)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd2)
	assert.Equal(t, uint64(0x7fff9000), fa.PathPtr2)
}

func TestExtractLegacyFileArgs_Symlink(t *testing.T) {
	// symlink(target, linkpath) — primary path is linkpath (Arg1)
	args := SyscallArgs{
		Nr:   unix.SYS_SYMLINK,
		Arg0: 0x7fffA000, // target
		Arg1: 0x7fffB000, // linkpath
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fffB000), fa.PathPtr) // linkpath is primary
	assert.False(t, fa.HasSecondPath)
}

func TestExtractLegacyFileArgs_Chmod(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_CHMOD,
		Arg0: 0x7fffC000, // path
		Arg1: 0755,       // mode
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fffC000), fa.PathPtr)
	assert.Equal(t, uint32(0755), fa.Mode)
}

func TestExtractLegacyFileArgs_Chown(t *testing.T) {
	args := SyscallArgs{
		Nr:   unix.SYS_CHOWN,
		Arg0: 0x7fffD000, // path
		Arg1: 1000,       // owner
		Arg2: 1000,       // group
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fffD000), fa.PathPtr)
}

func TestLegacyFileSyscallList(t *testing.T) {
	list := legacyFileSyscallList()
	assert.Len(t, list, 10)
	// Verify all listed syscalls are recognized
	for _, nr := range list {
		assert.True(t, isLegacyFileSyscall(nr), "syscall %d from list not recognized", nr)
		assert.True(t, isFileSyscall(nr), "syscall %d from list not recognized by isFileSyscall", nr)
	}
}
