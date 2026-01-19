//go:build linux && cgo

package unix

import (
	"os"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
