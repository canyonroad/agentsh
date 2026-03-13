//go:build linux

package ptrace

import (
	"bytes"
	"fmt"

	"golang.org/x/sys/unix"
)

// memReader is an interface for reading bytes from an address space.
type memReader interface {
	read(addr uint64, buf []byte) error
}

// procMemReader reads via /proc/<tid>/mem using a cached fd.
type procMemReader struct {
	fd int
}

func (r *procMemReader) read(addr uint64, buf []byte) error {
	_, err := unix.Pread(r.fd, buf, int64(addr))
	return err
}

func readBytesFrom(r memReader, addr uint64, buf []byte) error {
	return r.read(addr, buf)
}

// readStringFrom reads a NUL-terminated string from a memReader.
func readStringFrom(r memReader, addr uint64, maxLen int) (string, error) {
	var result []byte
	chunk := make([]byte, 256)
	for len(result) < maxLen {
		n := 256
		if maxLen-len(result) < n {
			n = maxLen - len(result)
		}
		if err := r.read(addr+uint64(len(result)), chunk[:n]); err != nil {
			return "", err
		}
		if idx := bytes.IndexByte(chunk[:n], 0); idx >= 0 {
			result = append(result, chunk[:idx]...)
			return string(result), nil
		}
		result = append(result, chunk[:n]...)
	}
	return string(result), nil
}

// Tracer-level memory access methods using the cached MemFD.

// ensureMemFD lazily opens /proc/<tid>/mem if not yet available (e.g., for
// auto-attached children via PTRACE_O_TRACEFORK). Returns the fd.
func (t *Tracer) ensureMemFD(tid int) (int, error) {
	t.mu.Lock()
	state := t.tracees[tid]
	if state == nil {
		t.mu.Unlock()
		return -1, fmt.Errorf("no tracee state for tid %d", tid)
	}
	fd := state.MemFD
	t.mu.Unlock()

	if fd >= 0 {
		return fd, nil
	}

	newFD, err := unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDWR, 0)
	if err != nil {
		newFD, err = unix.Open(fmt.Sprintf("/proc/%d/mem", tid), unix.O_RDONLY, 0)
		if err != nil {
			return -1, fmt.Errorf("open /proc/%d/mem: %w", tid, err)
		}
	}

	t.mu.Lock()
	state = t.tracees[tid]
	if state == nil {
		// Tracee exited while we were opening the fd.
		unix.Close(newFD)
		t.mu.Unlock()
		return -1, fmt.Errorf("tracee %d exited during memfd open", tid)
	}
	if state.MemFD >= 0 {
		// Another goroutine opened it first; close ours.
		unix.Close(newFD)
		fd = state.MemFD
	} else {
		state.MemFD = newFD
		fd = newFD
	}
	t.mu.Unlock()

	return fd, nil
}

func (t *Tracer) getMemReader(tid int) (memReader, error) {
	fd, err := t.ensureMemFD(tid)
	if err != nil {
		return nil, err
	}
	return &procMemReader{fd: fd}, nil
}

func (t *Tracer) readBytes(tid int, addr uint64, buf []byte) error {
	r, err := t.getMemReader(tid)
	if err != nil {
		return err
	}
	return readBytesFrom(r, addr, buf)
}

func (t *Tracer) readString(tid int, addr uint64, maxLen int) (string, error) {
	r, err := t.getMemReader(tid)
	if err != nil {
		return "", err
	}
	return readStringFrom(r, addr, maxLen)
}

func (t *Tracer) writeBytes(tid int, addr uint64, buf []byte) error {
	fd, err := t.ensureMemFD(tid)
	if err != nil {
		return err
	}
	_, err = unix.Pwrite(fd, buf, int64(addr))
	return err
}

// writeString writes a NUL-terminated string to the tracee's memory.
func (t *Tracer) writeString(tid int, addr uint64, s string) error {
	buf := make([]byte, len(s)+1) // +1 for NUL terminator
	copy(buf, s)
	// buf[len(s)] is already 0 from make
	return t.writeBytes(tid, addr, buf)
}

// readArgv reads the argv array from tracee memory.
func (t *Tracer) readArgv(tid int, argvPtr uint64, maxArgc int, maxBytes int) ([]string, bool, error) {
	r, err := t.getMemReader(tid)
	if err != nil {
		return nil, false, err
	}

	var args []string
	totalBytes := 0
	ptrBuf := make([]byte, 8)

	for i := 0; i < maxArgc; i++ {
		if err := r.read(argvPtr+uint64(i*8), ptrBuf); err != nil {
			return args, false, err
		}
		ptr := nativeEndianUint64(ptrBuf)
		if ptr == 0 {
			break
		}

		s, err := readStringFrom(r, ptr, 4096)
		if err != nil {
			return args, false, err
		}

		totalBytes += len(s) + 1
		if totalBytes > maxBytes {
			return args, true, nil
		}
		args = append(args, s)
	}
	return args, false, nil
}

func nativeEndianUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
