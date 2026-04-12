//go:build linux && cgo

package api

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// probeMemoryAccess tests that the server can read from the given PID's address
// space using ProcessVMReadv and the /proc/<pid>/mem fallback. Returns
// (nil, nil) if ProcessVMReadv works, (pvrErr, nil) if only /proc/mem works,
// or (pvrErr, memErr) if both fail.
func probeMemoryAccess(pid int) (pvrErr, memErr error) {
	addr, err := findReadableAddr(pid)
	if err != nil {
		return fmt.Errorf("find readable addr: %w", err), fmt.Errorf("find readable addr: %w", err)
	}
	pvrErr = probeProcessVMReadvAt(pid, addr)
	if pvrErr != nil {
		memErr = probeProcMemAt(pid, addr)
	}
	return pvrErr, memErr
}

// probeProcessVMReadvAt reads 8 bytes from the given address in the target
// process via ProcessVMReadv. Returns nil on success.
func probeProcessVMReadvAt(pid int, addr uint64) error {
	buf := make([]byte, 8)
	liov := unix.Iovec{Base: &buf[0], Len: 8}
	riov := unix.RemoteIovec{Base: uintptr(addr), Len: 8}
	_, err := unix.ProcessVMReadv(pid, []unix.Iovec{liov}, []unix.RemoteIovec{riov}, 0)
	return err
}

// probeProcMemAt reads 8 bytes from the given address via /proc/<pid>/mem.
// Returns nil on success.
func probeProcMemAt(pid int, addr uint64) error {
	f, err := os.Open(fmt.Sprintf("/proc/%d/mem", pid))
	if err != nil {
		return err
	}
	defer f.Close()
	buf := make([]byte, 8)
	_, err = f.ReadAt(buf, int64(addr))
	return err
}

// findReadableAddr parses /proc/<pid>/maps to find the start address of the
// first readable mapping. Scans at most 20 lines.
func findReadableAddr(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/maps: %w", pid, err)
	}
	lines := strings.Split(string(data), "\n")
	limit := 20
	if len(lines) < limit {
		limit = len(lines)
	}
	for _, line := range lines[:limit] {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// permissions field: rwxp — check first char is 'r'
		if len(fields[1]) < 1 || fields[1][0] != 'r' {
			continue
		}
		addrs := strings.SplitN(fields[0], "-", 2)
		if len(addrs) < 2 {
			continue
		}
		addr, err := strconv.ParseUint(addrs[0], 16, 64)
		if err != nil {
			continue
		}
		return addr, nil
	}
	return 0, fmt.Errorf("no readable mapping found in /proc/%d/maps (scanned %d lines)", pid, limit)
}
