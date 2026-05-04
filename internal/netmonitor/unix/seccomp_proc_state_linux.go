//go:build linux && cgo

package unix

import (
	"bytes"
	"os"
	"strconv"
)

// procSelfSeccompState is what readSelfSeccompState surfaces about the
// calling process's seccomp state, parsed from /proc/self/status.
// Used by the filter-install snapshot to distinguish a clean install
// from one running on top of an inherited filter (issue #282 stacked-
// install hypothesis on Runloop / Freestyle: parent unixwrap installs
// F1, then a nested unixwrap inherits it via execve and the kernel
// rejects F2 with EFAULT).
type procSelfSeccompState struct {
	// Mode is the SECCOMP_MODE_* value from `Seccomp:` (0 = disabled,
	// 1 = strict, 2 = filter). Zero when Present is false.
	Mode int
	// FilterCount is the chain length from `Seccomp_filters:` (added in
	// kernel 4.10). Zero when the field is absent or Present is false.
	FilterCount int
	// Present is true when the Seccomp line was found in input. Lets
	// callers distinguish "kernel reported mode 0" from "kernel did not
	// report" (older kernels, /proc disabled, etc.).
	Present bool
}

// parseProcSelfSeccompState parses /proc/self/status content, extracting
// the Seccomp: and Seccomp_filters: fields. Tab-separated, one field per
// line. Tolerant of missing fields and unrelated lines.
func parseProcSelfSeccompState(status []byte) procSelfSeccompState {
	var out procSelfSeccompState
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		switch {
		case bytes.HasPrefix(line, []byte("Seccomp:")):
			if v, ok := parseProcStatusInt(line); ok {
				out.Mode = v
				out.Present = true
			}
		case bytes.HasPrefix(line, []byte("Seccomp_filters:")):
			if v, ok := parseProcStatusInt(line); ok {
				out.FilterCount = v
			}
		}
	}
	return out
}

// parseProcStatusInt extracts the integer value from a `Key:\t<value>`
// /proc/[pid]/status line. Returns (0, false) on any parse failure.
func parseProcStatusInt(line []byte) (int, bool) {
	colon := bytes.IndexByte(line, ':')
	if colon < 0 {
		return 0, false
	}
	rest := bytes.TrimSpace(line[colon+1:])
	if len(rest) == 0 {
		return 0, false
	}
	v, err := strconv.Atoi(string(rest))
	if err != nil {
		return 0, false
	}
	return v, true
}

// readSelfSeccompState reads /proc/self/status and returns the parsed
// seccomp state. Returns the zero value (Present=false) if the file
// cannot be read — never errors, since this is a best-effort
// diagnostic and the caller logs whatever it gets.
func readSelfSeccompState() procSelfSeccompState {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return procSelfSeccompState{}
	}
	return parseProcSelfSeccompState(data)
}

// readProcComm returns the command name from /proc/<pid>/comm, trimmed
// of trailing newline. Returns "" on any error so callers can log
// "comm=" for unreadable parents (kernel-thread, exited, restricted
// proc, etc.) without special-casing.
func readProcComm(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return ""
	}
	return string(bytes.TrimSpace(data))
}
