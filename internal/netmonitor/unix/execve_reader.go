//go:build linux && cgo

package unix

import (
	"bytes"
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	ErrReadMemory = errors.New("failed to read process memory")
	ErrNullPtr    = errors.New("null pointer")
)

// readString reads a null-terminated string from the tracee's memory.
func readString(pid int, ptr uint64, maxLen int) (string, error) {
	if ptr == 0 {
		return "", ErrNullPtr
	}

	buf := make([]byte, maxLen)
	liov := unix.Iovec{Base: &buf[0], Len: uint64(maxLen)}
	riov := unix.RemoteIovec{Base: uintptr(ptr), Len: maxLen}

	n, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrReadMemory, err)
	}

	// Find null terminator
	if idx := bytes.IndexByte(buf[:n], 0); idx >= 0 {
		return string(buf[:idx]), nil
	}
	return string(buf[:n]), nil
}

// readPointer reads a pointer (8 bytes on amd64) from tracee memory.
func readPointer(pid int, ptr uint64) (uint64, error) {
	if ptr == 0 {
		return 0, ErrNullPtr
	}

	var val uint64
	buf := (*[8]byte)(unsafe.Pointer(&val))[:]
	liov := unix.Iovec{Base: &buf[0], Len: 8}
	riov := unix.RemoteIovec{Base: uintptr(ptr), Len: 8}

	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return 0, fmt.Errorf("%w: %v", ErrReadMemory, err)
	}
	return val, nil
}
