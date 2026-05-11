package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// spawnDaemon fork-execs `bin args...` with stdout/stderr appended to logPath.
// The child is detached; the returned *exec.Cmd lets the caller signal it if
// needed (in normal flow the bootstrap exits after probing and the daemon
// keeps running, reparented to PID 1).
func spawnDaemon(bin string, args []string, logPath string) (*exec.Cmd, error) {
	if err := os.MkdirAll(filepath.Dir(logPath), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir log dir: %w", err)
	}
	logF, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open log: %w", err)
	}
	cmd := exec.Command(bin, args...)
	cmd.Stdout = logF
	cmd.Stderr = logF
	cmd.Env = os.Environ()
	if err := cmd.Start(); err != nil {
		logF.Close()
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}
	// Release the parent's reference to the log file FD once exec(2) has dup'd
	// stdio. The child keeps its own dup'd FD.
	go func() { _ = logF.Close() }()
	return cmd, nil
}

// waitForSocket polls for a filesystem entry at sockPath, returning nil as
// soon as it exists. Returns an error if the deadline elapses first.
//
// We check existence rather than `Dial` because the daemon may use a
// different socket type (gRPC vs HTTP) and a successful Dial isn't required
// to confirm "the daemon has started writing its socket" — only that the
// file exists.
func waitForSocket(sockPath string, deadline time.Duration) error {
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if _, err := os.Stat(sockPath); err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("socket %q did not appear within %s", sockPath, deadline)
}
