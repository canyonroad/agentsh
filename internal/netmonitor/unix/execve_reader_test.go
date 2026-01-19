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
