//go:build linux && cgo

package unix

import (
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestReadStringFromPID(t *testing.T) {
	// Read from our own process memory as a test
	testStr := "/usr/bin/test-binary"
	strBytes := []byte(testStr + "\x00") // null-terminated
	strPtr := uintptr(unsafe.Pointer(&strBytes[0]))

	result, err := readString(os.Getpid(), uint64(strPtr), 4096)
	require.NoError(t, err)
	assert.Equal(t, testStr, result)
}

func TestReadString_Truncation(t *testing.T) {
	testStr := "this-is-a-very-long-string-that-exceeds-limit"
	strBytes := []byte(testStr + "\x00")
	strPtr := uintptr(unsafe.Pointer(&strBytes[0]))

	result, err := readString(os.Getpid(), uint64(strPtr), 10)
	require.NoError(t, err)
	assert.Equal(t, "this-is-a-", result)
}

func TestReadArgv(t *testing.T) {
	// Create a test argv array in our own memory
	args := []string{"cmd", "-flag", "value"}

	// Build null-terminated strings that stay alive
	argBytes := make([][]byte, len(args))
	for i, arg := range args {
		argBytes[i] = []byte(arg + "\x00")
	}

	// Build pointer array
	ptrs := make([]uintptr, len(args)+1)
	for i := range args {
		ptrs[i] = uintptr(unsafe.Pointer(&argBytes[i][0]))
	}
	ptrs[len(args)] = 0 // NULL terminator

	cfg := ExecveReaderConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 65536,
	}

	result, truncated, err := ReadArgv(os.Getpid(), uint64(uintptr(unsafe.Pointer(&ptrs[0]))), cfg)
	require.NoError(t, err)
	assert.False(t, truncated)
	assert.Equal(t, args, result)
}

func TestReadArgv_Truncation_ArgCount(t *testing.T) {
	args := []string{"a", "b", "c", "d", "e"}
	argBytes := make([][]byte, len(args))
	for i, arg := range args {
		argBytes[i] = []byte(arg + "\x00")
	}
	ptrs := make([]uintptr, len(args)+1)
	for i := range args {
		ptrs[i] = uintptr(unsafe.Pointer(&argBytes[i][0]))
	}
	ptrs[len(args)] = 0

	cfg := ExecveReaderConfig{
		MaxArgc:      3,
		MaxArgvBytes: 65536,
	}

	result, truncated, err := ReadArgv(os.Getpid(), uint64(uintptr(unsafe.Pointer(&ptrs[0]))), cfg)
	require.NoError(t, err)
	assert.True(t, truncated)
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestReadArgv_Truncation_ByteLimit(t *testing.T) {
	args := []string{"hello", "world", "test"}
	argBytes := make([][]byte, len(args))
	for i, arg := range args {
		argBytes[i] = []byte(arg + "\x00")
	}
	ptrs := make([]uintptr, len(args)+1)
	for i := range args {
		ptrs[i] = uintptr(unsafe.Pointer(&argBytes[i][0]))
	}
	ptrs[len(args)] = 0

	cfg := ExecveReaderConfig{
		MaxArgc:      1000,
		MaxArgvBytes: 10, // Only fits "hello" (5) + "world" (5)
	}

	result, truncated, err := ReadArgv(os.Getpid(), uint64(uintptr(unsafe.Pointer(&ptrs[0]))), cfg)
	require.NoError(t, err)
	assert.True(t, truncated)
	assert.Equal(t, []string{"hello", "world"}, result)
}

func TestExtractExecveArgs(t *testing.T) {
	// Test with mock syscall args
	// execve: arg0=filename, arg1=argv, arg2=envp
	t.Run("execve syscall", func(t *testing.T) {
		args := SyscallArgs{
			Nr:   unix.SYS_EXECVE,
			Arg0: 0x1000, // filename ptr
			Arg1: 0x2000, // argv ptr
			Arg2: 0x3000, // envp ptr
		}

		ctx := ExtractExecveArgs(args)
		assert.Equal(t, uint64(0x1000), ctx.FilenamePtr)
		assert.Equal(t, uint64(0x2000), ctx.ArgvPtr)
		assert.False(t, ctx.IsExecveat)
	})

	// execveat: arg0=dirfd, arg1=filename, arg2=argv, arg3=envp, arg4=flags
	t.Run("execveat syscall", func(t *testing.T) {
		args := SyscallArgs{
			Nr:   unix.SYS_EXECVEAT,
			Arg0: 3,      // dirfd
			Arg1: 0x1000, // filename ptr
			Arg2: 0x2000, // argv ptr
			Arg3: 0x3000, // envp ptr
			Arg4: 0,      // flags
		}

		ctx := ExtractExecveArgs(args)
		assert.Equal(t, uint64(0x1000), ctx.FilenamePtr)
		assert.Equal(t, uint64(0x2000), ctx.ArgvPtr)
		assert.True(t, ctx.IsExecveat)
		assert.Equal(t, int32(3), ctx.Dirfd)
	})
}

func TestWriteStringToPID(t *testing.T) {
	// Allocate a buffer in our own process memory
	buf := make([]byte, 64)
	copy(buf, "/usr/bin/original-binary\x00extra-padding-data")
	bufPtr := uintptr(unsafe.Pointer(&buf[0]))

	// First verify we can read from the buffer
	result, err := readString(os.Getpid(), uint64(bufPtr), 4096)
	require.NoError(t, err)
	assert.Equal(t, "/usr/bin/original-binary", result)

	// Overwrite with a shorter string
	err = writeString(os.Getpid(), uint64(bufPtr), "/tmp/stub")
	require.NoError(t, err)

	// Read back and verify
	result, err = readString(os.Getpid(), uint64(bufPtr), 4096)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/stub", result)

	// Ensure buf is not GC'd before this point
	_ = buf
}

func TestWriteString_NullPtr(t *testing.T) {
	err := writeString(os.Getpid(), 0, "/tmp/stub")
	require.Error(t, err)
}

func TestIsExecveSyscall(t *testing.T) {
	assert.True(t, IsExecveSyscall(unix.SYS_EXECVE))
	assert.True(t, IsExecveSyscall(unix.SYS_EXECVEAT))
	assert.False(t, IsExecveSyscall(unix.SYS_CONNECT))
	assert.False(t, IsExecveSyscall(unix.SYS_SOCKET))
}
