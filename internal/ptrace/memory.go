//go:build linux

package ptrace

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

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

// vmReader reads via process_vm_readv, falling back to /proc/<tid>/mem pread.
// process_vm_readv copies directly between address spaces without going through
// the kernel VFS layer, which is faster for bulk reads.
type vmReader struct {
	tid      int
	fallback procMemReader
}

func (r *vmReader) read(addr uint64, buf []byte) error {
	if len(buf) == 0 {
		return nil
	}
	return retryTransientMem(r.tid, addr, "read", func() error {
		return r.readOnce(addr, buf)
	})
}

// readOnce performs a single read attempt: process_vm_readv, falling back to
// /proc/<tid>/mem pread. retryTransientMem retries this whole ladder on a
// transient EIO (#369).
func (r *vmReader) readOnce(addr uint64, buf []byte) error {
	liov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	riov := unix.RemoteIovec{Base: uintptr(addr), Len: len(buf)}
	_, err := unix.ProcessVMReadv(r.tid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err != nil {
		return r.fallback.read(addr, buf)
	}
	return nil
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
	return &vmReader{tid: tid, fallback: procMemReader{fd: fd}}, nil
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
	if len(buf) == 0 {
		return nil
	}
	return retryTransientMem(tid, addr, "write", func() error {
		return t.writeBytesOnce(tid, addr, buf)
	})
}

// writeBytesOnce performs a single write attempt: process_vm_writev, falling
// back to /proc/<tid>/mem pwrite. retryTransientMem retries this whole ladder on
// a transient EIO (#369).
func (t *Tracer) writeBytesOnce(tid int, addr uint64, buf []byte) error {
	// Try process_vm_writev first (direct address-space copy, no VFS overhead).
	liov := unix.Iovec{Base: &buf[0], Len: uint64(len(buf))}
	riov := unix.RemoteIovec{Base: uintptr(addr), Len: len(buf)}
	_, err := unix.ProcessVMWritev(tid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	if err == nil {
		return nil
	}
	// Fallback to /proc/<tid>/mem pwrite.
	fd, ferr := t.ensureMemFD(tid)
	if ferr != nil {
		return ferr
	}
	_, err = unix.Pwrite(fd, buf, int64(addr))
	return err
}

// memRetryMaxAttempts bounds retries of a tracee-memory access on a transient
// EIO. Injected accesses normally complete in microseconds, so the escalating
// backoff (1+2+4+8 ≈ 15ms worst case) is paid only on the rare transient error.
const memRetryMaxAttempts = 5

// isTransientMemErr reports whether a tracee-memory access error looks like the
// race-sensitive EIO observed on some kernels (exe.dev 6.12.90, #369), where
// process_vm_* / /proc/<pid>/mem transiently fail right after a ptrace stop
// transition (the access succeeds when serialized under strace). EFAULT is
// intentionally NOT treated as transient — it is frequently a legitimate
// bad-pointer result (e.g. readString crossing a page boundary), and retrying it
// would add latency to normal operation.
func isTransientMemErr(err error) bool {
	return errors.Is(err, unix.EIO)
}

// retryTransientMem runs access (the full process_vm_* → /proc-mem ladder),
// retrying on a transient EIO with escalating backoff. This replicates the
// latency that makes the same access succeed under strace. On a healthy kernel
// EIO never occurs, so access runs exactly once with no added latency. On
// exhaustion it logs diagnostic context and returns the last error. (#369)
func retryTransientMem(tid int, addr uint64, op string, access func() error) error {
	var err error
	for attempt := 0; attempt < memRetryMaxAttempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(1<<(attempt-1)) * time.Millisecond) // 1,2,4,8ms
		}
		err = access()
		if err == nil {
			if attempt > 0 {
				slog.Debug("ptrace mem access recovered after retry",
					"tid", tid, "addr", fmt.Sprintf("0x%x", addr), "op", op, "attempts", attempt+1)
			}
			return nil
		}
		if !isTransientMemErr(err) {
			return err
		}
	}
	logMemErrContext(tid, addr, op, err)
	return err
}

// logMemErrContext records, at WARN, why a tracee-memory access kept failing:
// the tracee's scheduler state char from /proc/<tid>/stat (expected 't'/'T' when
// ptrace-stopped) and whether addr falls inside any /proc/<tid>/maps region.
// Best-effort and observable without strace; never alters the returned error. (#369)
func logMemErrContext(tid int, addr uint64, op string, accessErr error) {
	slog.Warn("ptrace mem access failed after retries",
		"tid", tid, "addr", fmt.Sprintf("0x%x", addr), "op", op,
		"error", accessErr, "tracee_state", procStateChar(tid),
		"addr_mapped", addrInMaps(tid, addr), "attempts", memRetryMaxAttempts)
}

// procStateChar returns the process state char from /proc/<tid>/stat ("" on error).
func procStateChar(tid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", tid))
	if err != nil {
		return ""
	}
	return parseProcStatState(data)
}

// parseProcStatState extracts the state char (field 3) from /proc/<pid>/stat
// content. comm (field 2) may contain spaces and parens, so the state char is
// the first whitespace-delimited token after the LAST ')'. Returns "" if the
// input is malformed.
func parseProcStatState(data []byte) string {
	i := bytes.LastIndexByte(data, ')')
	if i < 0 || i+1 >= len(data) {
		return ""
	}
	rest := strings.TrimLeft(string(data[i+1:]), " \t")
	if rest == "" {
		return ""
	}
	if sp := strings.IndexAny(rest, " \t\n"); sp >= 0 {
		return rest[:sp]
	}
	return rest
}

// addrInMaps reports whether addr falls inside any mapped region in
// /proc/<tid>/maps. Returns false on any error (best-effort diagnostic).
func addrInMaps(tid int, addr uint64) bool {
	f, err := os.Open(fmt.Sprintf("/proc/%d/maps", tid))
	if err != nil {
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text() // "start-end perms offset dev inode pathname"
		dash := strings.IndexByte(line, '-')
		if dash < 0 {
			continue
		}
		sp := strings.IndexByte(line[dash:], ' ')
		if sp < 0 {
			continue
		}
		start, err1 := strconv.ParseUint(line[:dash], 16, 64)
		end, err2 := strconv.ParseUint(line[dash+1:dash+sp], 16, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if addr >= start && addr < end {
			return true
		}
	}
	return false
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
