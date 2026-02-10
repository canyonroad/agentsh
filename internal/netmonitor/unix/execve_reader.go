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

// SyscallArgs holds the arguments from a seccomp notification.
type SyscallArgs struct {
	Nr   int32
	Arg0 uint64
	Arg1 uint64
	Arg2 uint64
	Arg3 uint64
	Arg4 uint64
	Arg5 uint64
}

// ExecveArgs holds the parsed execve/execveat arguments.
type ExecveArgs struct {
	FilenamePtr uint64
	ArgvPtr     uint64
	IsExecveat  bool
	Dirfd       int32 // only for execveat
	Flags       int32 // only for execveat
}

// ExtractExecveArgs extracts execve/execveat arguments from syscall args.
func ExtractExecveArgs(args SyscallArgs) ExecveArgs {
	if args.Nr == unix.SYS_EXECVEAT {
		return ExecveArgs{
			FilenamePtr: args.Arg1,
			ArgvPtr:     args.Arg2,
			IsExecveat:  true,
			Dirfd:       int32(args.Arg0),
			Flags:       int32(args.Arg4),
		}
	}
	// SYS_EXECVE
	return ExecveArgs{
		FilenamePtr: args.Arg0,
		ArgvPtr:     args.Arg1,
		IsExecveat:  false,
	}
}

// IsExecveSyscall returns true if nr is execve or execveat.
func IsExecveSyscall(nr int32) bool {
	return nr == unix.SYS_EXECVE || nr == unix.SYS_EXECVEAT
}

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

// writeString writes a null-terminated string to the tracee's memory at the given address.
// The caller must ensure the destination has enough space for len(s)+1 bytes.
func writeString(pid int, ptr uint64, s string) error {
	if ptr == 0 {
		return ErrNullPtr
	}

	data := append([]byte(s), 0) // null-terminate
	liov := unix.Iovec{Base: &data[0], Len: uint64(len(data))}
	riov := unix.RemoteIovec{Base: uintptr(ptr), Len: len(data)}

	n, err := unix.ProcessVMWritev(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return fmt.Errorf("process_vm_writev: %w", err)
	}
	if n != len(data) {
		return fmt.Errorf("process_vm_writev: short write (%d/%d bytes)", n, len(data))
	}
	return nil
}

// ExecveReaderConfig configures argv reading limits.
type ExecveReaderConfig struct {
	MaxArgc      int
	MaxArgvBytes int
}

// ReadArgv reads the argv array from tracee memory.
// Returns the arguments, whether truncation occurred, and any error.
func ReadArgv(pid int, argvPtr uint64, cfg ExecveReaderConfig) ([]string, bool, error) {
	if argvPtr == 0 {
		return nil, false, ErrNullPtr
	}

	var args []string
	var totalBytes int
	truncated := false

	for i := 0; i < cfg.MaxArgc; i++ {
		// Read pointer at argvPtr + i*8
		ptr, err := readPointer(pid, argvPtr+uint64(i*8))
		if err != nil {
			return args, truncated, err
		}
		if ptr == 0 {
			// NULL terminator - end of argv
			break
		}

		// Calculate remaining bytes allowed
		remaining := cfg.MaxArgvBytes - totalBytes
		if remaining <= 0 {
			truncated = true
			break
		}

		arg, err := readString(pid, ptr, remaining)
		if err != nil {
			return args, truncated, err
		}

		totalBytes += len(arg)
		args = append(args, arg)

		if totalBytes >= cfg.MaxArgvBytes {
			truncated = true
			break
		}
	}

	// Check if we hit MaxArgc limit
	if len(args) >= cfg.MaxArgc {
		// Check if there are more args
		ptr, _ := readPointer(pid, argvPtr+uint64(cfg.MaxArgc*8))
		if ptr != 0 {
			truncated = true
		}
	}

	return args, truncated, nil
}
