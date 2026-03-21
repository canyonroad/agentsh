//go:build linux && cgo

package unix

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/unix"
)

// fdcwdUint64 returns AT_FDCWD (-100) as it appears in syscall register args (sign-extended to uint64).
func fdcwdUint64() uint64 {
	v := int32(unix.AT_FDCWD)
	return uint64(int64(v))
}

func TestIsFileSyscall(t *testing.T) {
	fileSyscalls := []int32{
		unix.SYS_OPENAT,
		unix.SYS_OPENAT2,
		unix.SYS_UNLINKAT,
		unix.SYS_MKDIRAT,
		unix.SYS_RENAMEAT2,
		unix.SYS_LINKAT,
		unix.SYS_SYMLINKAT,
		unix.SYS_FCHMODAT,
		unix.SYS_FCHOWNAT,
		unix.SYS_STATX,
		unix.SYS_NEWFSTATAT,
		unix.SYS_FACCESSAT2,
		unix.SYS_READLINKAT,
		unix.SYS_MKNODAT,
	}

	for _, nr := range fileSyscalls {
		assert.True(t, isFileSyscall(nr), "expected true for syscall %d", nr)
	}

	// Non-file syscalls should return false
	nonFileSyscalls := []int32{
		unix.SYS_EXECVE,
		unix.SYS_EXECVEAT,
		unix.SYS_CONNECT,
		unix.SYS_SOCKET,
		unix.SYS_READ,
		unix.SYS_WRITE,
	}

	for _, nr := range nonFileSyscalls {
		assert.False(t, isFileSyscall(nr), "expected false for syscall %d", nr)
	}
}

func TestSyscallToOperation(t *testing.T) {
	tests := []struct {
		name     string
		nr       int32
		flags    uint32
		expected string
	}{
		// openat operations
		{"openat read-only", unix.SYS_OPENAT, 0, "open"},
		{"openat O_CREAT", unix.SYS_OPENAT, unix.O_CREAT, "create"},
		{"openat O_TMPFILE", unix.SYS_OPENAT, unix.O_TMPFILE, "create"},
		{"openat O_WRONLY", unix.SYS_OPENAT, unix.O_WRONLY, "write"},
		{"openat O_RDWR", unix.SYS_OPENAT, unix.O_RDWR, "write"},
		{"openat O_APPEND", unix.SYS_OPENAT, unix.O_APPEND, "write"},
		{"openat O_TRUNC", unix.SYS_OPENAT, unix.O_TRUNC, "write"},
		{"openat O_WRONLY|O_CREAT", unix.SYS_OPENAT, unix.O_WRONLY | unix.O_CREAT, "create"},

		// openat2 operations (same logic)
		{"openat2 read-only", unix.SYS_OPENAT2, 0, "open"},
		{"openat2 O_CREAT", unix.SYS_OPENAT2, unix.O_CREAT, "create"},
		{"openat2 O_WRONLY", unix.SYS_OPENAT2, unix.O_WRONLY, "write"},

		// unlinkat operations
		{"unlinkat file", unix.SYS_UNLINKAT, 0, "delete"},
		{"unlinkat AT_REMOVEDIR", unix.SYS_UNLINKAT, unix.AT_REMOVEDIR, "rmdir"},

		// Simple operations
		{"mkdirat", unix.SYS_MKDIRAT, 0, "mkdir"},
		{"renameat2", unix.SYS_RENAMEAT2, 0, "rename"},
		{"linkat", unix.SYS_LINKAT, 0, "link"},
		{"symlinkat", unix.SYS_SYMLINKAT, 0, "symlink"},
		{"fchmodat", unix.SYS_FCHMODAT, 0, "chmod"},
		{"fchownat", unix.SYS_FCHOWNAT, 0, "chown"},
		{"statx", unix.SYS_STATX, 0, "stat"},
		{"newfstatat", unix.SYS_NEWFSTATAT, 0, "stat"},
		{"faccessat2", unix.SYS_FACCESSAT2, 0, "access"},
		{"readlinkat", unix.SYS_READLINKAT, 0, "readlink"},
		{"mknodat", unix.SYS_MKNODAT, 0, "mknod"},

		// Unknown syscall
		{"unknown", unix.SYS_READ, 0, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := syscallToOperation(tt.nr, tt.flags)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestExtractFileArgs_Openat(t *testing.T) {
	// openat(dirfd, path, flags, mode)
	args := SyscallArgs{
		Nr:   unix.SYS_OPENAT,
		Arg0: fdcwdUint64(),               // dirfd
		Arg1: 0x7fff1000,            // path pointer
		Arg2: uint64(unix.O_RDONLY), // flags
		Arg3: 0644,                  // mode
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff1000), fa.PathPtr)
	assert.Equal(t, uint32(unix.O_RDONLY), fa.Flags)
	assert.Equal(t, uint32(0644), fa.Mode)
	assert.False(t, fa.HasSecondPath)
}

func TestExtractFileArgs_Openat2(t *testing.T) {
	// openat2(dirfd, path, how, size)
	// Arg2 is a pointer to struct open_how in tracee memory.
	args := SyscallArgs{
		Nr:   unix.SYS_OPENAT2,
		Arg0: fdcwdUint64(),    // dirfd
		Arg1: 0x7fff2000, // path pointer
		Arg2: 0x7fff3000, // how struct pointer
		Arg3: 24,         // size
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff2000), fa.PathPtr)
	// For openat2, Flags should be 0 (resolved at runtime from open_how struct)
	assert.Equal(t, uint32(0), fa.Flags)
	// HowPtr should hold the pointer to the open_how struct
	assert.Equal(t, uint64(0x7fff3000), fa.HowPtr)
	assert.False(t, fa.HasSecondPath)
}

func TestExtractFileArgs_Unlinkat(t *testing.T) {
	// unlinkat(dirfd, path, flags)
	args := SyscallArgs{
		Nr:   unix.SYS_UNLINKAT,
		Arg0: 5,          // dirfd
		Arg1: 0x7fff4000, // path pointer
		Arg2: uint64(unix.AT_REMOVEDIR),
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(5), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff4000), fa.PathPtr)
	assert.Equal(t, uint32(unix.AT_REMOVEDIR), fa.Flags)
	assert.False(t, fa.HasSecondPath)
}

func TestExtractFileArgs_Mkdirat(t *testing.T) {
	// mkdirat(dirfd, path, mode)
	args := SyscallArgs{
		Nr:   unix.SYS_MKDIRAT,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fff5000,
		Arg2: 0755,
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff5000), fa.PathPtr)
	assert.Equal(t, uint32(0755), fa.Mode)
	assert.False(t, fa.HasSecondPath)
}

func TestExtractFileArgs_Renameat2(t *testing.T) {
	// renameat2(olddirfd, oldpath, newdirfd, newpath, flags)
	args := SyscallArgs{
		Nr:   unix.SYS_RENAMEAT2,
		Arg0: fdcwdUint64(),    // olddirfd
		Arg1: 0x7fff6000, // oldpath
		Arg2: 10,         // newdirfd
		Arg3: 0x7fff7000, // newpath
		Arg4: 0,          // flags
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff6000), fa.PathPtr)
	assert.True(t, fa.HasSecondPath)
	assert.Equal(t, int32(10), fa.Dirfd2)
	assert.Equal(t, uint64(0x7fff7000), fa.PathPtr2)
	assert.Equal(t, uint32(0), fa.Flags)
}

func TestExtractFileArgs_Linkat(t *testing.T) {
	// linkat(olddirfd, oldpath, newdirfd, newpath, flags)
	args := SyscallArgs{
		Nr:   unix.SYS_LINKAT,
		Arg0: fdcwdUint64(),    // olddirfd
		Arg1: 0x7fff8000, // oldpath
		Arg2: 7,          // newdirfd
		Arg3: 0x7fff9000, // newpath
		Arg4: 0,          // flags
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff8000), fa.PathPtr)
	assert.True(t, fa.HasSecondPath)
	assert.Equal(t, int32(7), fa.Dirfd2)
	assert.Equal(t, uint64(0x7fff9000), fa.PathPtr2)
}

func TestExtractFileArgs_Symlinkat(t *testing.T) {
	// symlinkat(target, newdirfd, linkpath)
	// Primary path is linkpath: Dirfd=Arg1(newdirfd), PathPtr=Arg2(linkpath)
	args := SyscallArgs{
		Nr:   unix.SYS_SYMLINKAT,
		Arg0: 0x7fffA000, // target string pointer
		Arg1: fdcwdUint64(),    // newdirfd
		Arg2: 0x7fffB000, // linkpath pointer
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fffB000), fa.PathPtr)
	assert.False(t, fa.HasSecondPath)
}

func TestExtractFileArgs_Fchmodat(t *testing.T) {
	// fchmodat(dirfd, path, mode, flags)
	args := SyscallArgs{
		Nr:   unix.SYS_FCHMODAT,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fffC000,
		Arg2: 0755,
		Arg3: 0,
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fffC000), fa.PathPtr)
	assert.Equal(t, uint32(0755), fa.Mode)
	assert.Equal(t, uint32(0), fa.Flags)
}

func TestExtractFileArgs_Fchownat(t *testing.T) {
	// fchownat(dirfd, path, owner, group, flags)
	args := SyscallArgs{
		Nr:   unix.SYS_FCHOWNAT,
		Arg0: fdcwdUint64(),
		Arg1: 0x7fffD000,
		Arg2: 1000, // owner
		Arg3: 1000, // group
		Arg4: uint64(unix.AT_SYMLINK_NOFOLLOW),
	}

	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fffD000), fa.PathPtr)
	assert.Equal(t, uint32(unix.AT_SYMLINK_NOFOLLOW), fa.Flags)
}

func TestExtractFileArgs_Statx(t *testing.T) {
	args := SyscallArgs{Nr: unix.SYS_STATX, Arg0: fdcwdUint64(), Arg1: 0x7fff2000, Arg2: 0}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff2000), fa.PathPtr)
}

func TestExtractFileArgs_Newfstatat(t *testing.T) {
	args := SyscallArgs{Nr: unix.SYS_NEWFSTATAT, Arg0: fdcwdUint64(), Arg1: 0x7fff3000, Arg3: uint64(unix.AT_SYMLINK_NOFOLLOW)}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff3000), fa.PathPtr)
	assert.Equal(t, uint32(unix.AT_SYMLINK_NOFOLLOW), fa.Flags)
}

func TestExtractFileArgs_Faccessat2(t *testing.T) {
	args := SyscallArgs{Nr: unix.SYS_FACCESSAT2, Arg0: fdcwdUint64(), Arg1: 0x7fff4000}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff4000), fa.PathPtr)
}

func TestExtractFileArgs_Readlinkat(t *testing.T) {
	args := SyscallArgs{Nr: unix.SYS_READLINKAT, Arg0: fdcwdUint64(), Arg1: 0x7fff5000}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff5000), fa.PathPtr)
}

func TestExtractFileArgs_Mknodat(t *testing.T) {
	args := SyscallArgs{Nr: unix.SYS_MKNODAT, Arg0: fdcwdUint64(), Arg1: 0x7fff6000, Arg2: 0o100644}
	fa := extractFileArgs(args)
	assert.Equal(t, int32(unix.AT_FDCWD), fa.Dirfd)
	assert.Equal(t, uint64(0x7fff6000), fa.PathPtr)
	assert.Equal(t, uint32(0o100644), fa.Mode)
}

func TestFileSyscallName(t *testing.T) {
	tests := []struct {
		nr       int32
		expected string
	}{
		{unix.SYS_OPENAT, "openat"},
		{unix.SYS_OPENAT2, "openat2"},
		{unix.SYS_UNLINKAT, "unlinkat"},
		{unix.SYS_MKDIRAT, "mkdirat"},
		{unix.SYS_RENAMEAT2, "renameat2"},
		{unix.SYS_LINKAT, "linkat"},
		{unix.SYS_SYMLINKAT, "symlinkat"},
		{unix.SYS_FCHMODAT, "fchmodat"},
		{unix.SYS_FCHOWNAT, "fchownat"},
		{unix.SYS_READ, ""},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := fileSyscallName(tt.nr)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// pathToPtr creates a null-terminated byte buffer and returns its address as uint64.
// The returned byte slice must be kept alive for the duration of the test.
func pathToPtr(s string) (uint64, []byte) {
	buf := append([]byte(s), 0)
	return uint64(uintptr(unsafe.Pointer(&buf[0]))), buf
}

func TestResolvePathAt_Absolute(t *testing.T) {
	pid := os.Getpid()
	ptr, buf := pathToPtr("/usr/bin/ls")
	_ = buf // keep alive

	result, err := resolvePathAt(pid, -100, ptr)
	assert.NoError(t, err)
	assert.Equal(t, "/usr/bin/ls", result)
}

func TestResolvePathAt_AbsoluteClean(t *testing.T) {
	pid := os.Getpid()
	ptr, buf := pathToPtr("/usr/bin/../lib/test")
	_ = buf

	result, err := resolvePathAt(pid, -100, ptr)
	assert.NoError(t, err)
	assert.Equal(t, "/usr/lib/test", result)
}

func TestResolvePathAt_RelativeATFDCWD(t *testing.T) {
	pid := os.Getpid()
	ptr, buf := pathToPtr("somefile.txt")
	_ = buf

	cwd, err := os.Getwd()
	assert.NoError(t, err)

	result, err := resolvePathAt(pid, -100, ptr) // AT_FDCWD = -100
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(cwd, "somefile.txt"), result)
}

func TestResolvePathAt_RelativeToDirfd(t *testing.T) {
	pid := os.Getpid()

	// Open a directory to get a real dirfd
	dir, err := os.Open("/tmp")
	assert.NoError(t, err)
	defer dir.Close()

	ptr, buf := pathToPtr("testfile.txt")
	_ = buf

	result, err := resolvePathAt(pid, int32(dir.Fd()), ptr)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/testfile.txt", result)
}

func TestResolvePathAt_InvalidPid(t *testing.T) {
	ptr, buf := pathToPtr("/some/path")
	_ = buf

	// Use a PID that certainly doesn't exist
	_, err := resolvePathAt(999999999, -100, ptr)
	assert.Error(t, err)
}

func TestResolvePathAt_NullPtr(t *testing.T) {
	pid := os.Getpid()
	_, err := resolvePathAt(pid, -100, 0)
	assert.Error(t, err)
}

func TestIsOpenSyscall(t *testing.T) {
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT))
	assert.True(t, isOpenSyscall(unix.SYS_OPENAT2))
	assert.False(t, isOpenSyscall(unix.SYS_UNLINKAT))
	assert.False(t, isOpenSyscall(unix.SYS_STATX))
	assert.False(t, isOpenSyscall(unix.SYS_MKNODAT))
}

func TestShouldFallbackToContinue(t *testing.T) {
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT, unix.O_RDONLY, 0))
	assert.True(t, shouldFallbackToContinue(unix.SYS_OPENAT, unix.O_TMPFILE, 0))
	assert.True(t, shouldFallbackToContinue(unix.SYS_OPENAT2, unix.O_RDONLY, 0x01))
	assert.False(t, shouldFallbackToContinue(unix.SYS_OPENAT2, unix.O_RDONLY, 0))
}

func TestReadOpenHowResolve_NullPtr(t *testing.T) {
	// A null howPtr should return 0 without error.
	result, err := readOpenHowResolve(os.Getpid(), 0)
	assert.NoError(t, err)
	assert.Equal(t, uint64(0), result)
}

func TestResolveProcFD(t *testing.T) {
	pid := os.Getpid()

	tests := []struct {
		name      string
		path      string
		wasProcFD bool
	}{
		{"proc self fd", "/proc/self/fd/0", true},
		{"proc pid fd", fmt.Sprintf("/proc/%d/fd/0", pid), true},
		{"dev fd", "/dev/fd/0", true},
		{"thread-self fd", "/proc/thread-self/fd/0", true},
		{"normal path", "/tmp/foo", false},
		{"proc but not fd", "/proc/self/status", false},
		{"proc other pid fd", "/proc/1/fd/0", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolved, wasProcFD := resolveProcFD(pid, tt.path)
			assert.Equal(t, tt.wasProcFD, wasProcFD, "wasProcFD mismatch for %s", tt.path)
			if wasProcFD {
				assert.NotContains(t, resolved, "/proc/")
			}
		})
	}
}

func TestResolveProcFD_DevStdio(t *testing.T) {
	// /dev/stdin, /dev/stdout, /dev/stderr resolve to fd 0/1/2.
	// Whether resolveProcFD returns true depends on whether the fd
	// points to a filesystem path (true) or a pipe/socket (false).
	// In Go test, stderr is typically a pipe, so we test with a
	// known-filesystem fd instead.
	tmpFile, err := os.CreateTemp("", "procfd-stdio-test")
	if err != nil {
		t.Skip("cannot create temp file")
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	pid := os.Getpid()
	// Use the temp file's fd via /dev/fd/N
	devFDPath := fmt.Sprintf("/dev/fd/%d", tmpFile.Fd())
	resolved, wasProcFD := resolveProcFD(pid, devFDPath)
	assert.True(t, wasProcFD, "/dev/fd/<N> pointing to a file should resolve")
	assert.Equal(t, tmpFile.Name(), resolved)

	// /dev/stdin may or may not resolve depending on environment
	_, stdinResolved := resolveProcFD(pid, "/dev/stdin")
	// Just verify it doesn't panic — result depends on whether stdin is a file
	_ = stdinResolved
}

func TestResolveProcFD_PseudoPath(t *testing.T) {
	// Verify that fds pointing to pipes/sockets are NOT resolved.
	// Create a pipe to get an fd that resolves to "pipe:[N]".
	r, w, err := os.Pipe()
	if err != nil {
		t.Skip("cannot create pipe")
	}
	defer r.Close()
	defer w.Close()

	pid := os.Getpid()
	pipePath := fmt.Sprintf("/proc/%d/fd/%d", pid, r.Fd())
	_, wasProcFD := resolveProcFD(pid, pipePath)
	assert.False(t, wasProcFD, "pipe fd should not be treated as procfd bypass")
}

func TestResolveProcFD_WithSuffix(t *testing.T) {
	// /proc/self/fd/N/subpath should resolve to <target>/subpath
	tmpDir, err := os.MkdirTemp("", "procfd-suffix-test")
	if err != nil {
		t.Skip("cannot create temp dir")
	}
	defer os.RemoveAll(tmpDir)

	// Open the directory to get an fd
	dir, err := os.Open(tmpDir)
	if err != nil {
		t.Skip("cannot open temp dir")
	}
	defer dir.Close()

	pid := os.Getpid()
	// /proc/self/fd/<dirfd>/subpath
	suffixPath := fmt.Sprintf("/proc/%d/fd/%d/subpath", pid, dir.Fd())
	resolved, wasProcFD := resolveProcFD(pid, suffixPath)
	assert.True(t, wasProcFD, "procfd with suffix should resolve")
	assert.Equal(t, filepath.Join(tmpDir, "subpath"), resolved)
}
