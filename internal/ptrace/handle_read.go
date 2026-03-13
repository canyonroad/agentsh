//go:build linux

package ptrace

import (
	"bytes"
	"log/slog"
	"regexp"
	"strings"
)

var procStatusPattern = regexp.MustCompile(`^/proc/(\d+|self|thread-self)/status$`)

// isProcStatus returns true if the path matches /proc/<N>/status, /proc/self/status,
// or /proc/thread-self/status.
func isProcStatus(path string) bool {
	return procStatusPattern.MatchString(path)
}

var tracerPidPrefix = []byte("TracerPid:\t")

// maskTracerPid scans buf for "TracerPid:\t<N>" and overwrites <N> with "0"
// followed by spaces to preserve the buffer length. Operates in-place.
func maskTracerPid(buf []byte) {
	idx := bytes.Index(buf, tracerPidPrefix)
	if idx < 0 {
		return
	}

	// Find the start and end of the PID number
	pidStart := idx + len(tracerPidPrefix)
	pidEnd := pidStart
	for pidEnd < len(buf) && buf[pidEnd] != '\n' {
		pidEnd++
	}

	// Already zero — nothing to do
	pid := string(buf[pidStart:pidEnd])
	if strings.TrimSpace(pid) == "0" {
		return
	}

	// Overwrite: "0" followed by spaces to fill the original width
	buf[pidStart] = '0'
	for i := pidStart + 1; i < pidEnd; i++ {
		buf[i] = ' '
	}
}

// handleReadExit is called on syscall-exit for SYS_READ/SYS_PREAD64.
// If the fd is a tracked /proc/*/status fd, it patches TracerPid in the buffer.
func (t *Tracer) handleReadExit(tid int, regs Regs) {
	if t.fds == nil || !t.cfg.MaskTracerPid {
		return
	}

	fd := int(int32(regs.Arg(0)))

	t.mu.Lock()
	state := t.tracees[tid]
	var tgid int
	if state != nil {
		tgid = state.TGID
	}
	t.mu.Unlock()

	if !t.fds.isStatusFd(tgid, fd) {
		return
	}

	// Read the buffer that the kernel just wrote
	bytesRead := regs.ReturnValue()
	if bytesRead <= 0 {
		return
	}

	bufPtr := regs.Arg(1)
	buf := make([]byte, bytesRead)
	if err := t.readBytes(tid, bufPtr, buf); err != nil {
		slog.Warn("handleReadExit: cannot read buffer", "tid", tid, "error", err)
		return
	}

	// Check if TracerPid is in this chunk
	if !bytes.Contains(buf, tracerPidPrefix) {
		return
	}

	// Mask it
	maskTracerPid(buf)

	// Write patched buffer back
	if err := t.writeBytes(tid, bufPtr, buf); err != nil {
		slog.Warn("handleReadExit: cannot write patched buffer", "tid", tid, "error", err)
	}
}
