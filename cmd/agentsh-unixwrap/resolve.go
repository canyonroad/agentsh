//go:build linux && cgo

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// fallbackPATH lists standard system directories searched when exec.LookPath
// fails to resolve a bare command name. The OC posture (canyonroad/agentsh#271)
// can strip PATH from the wrapper's inherited environment, causing LookPath
// to return "executable file not found in $PATH" even for ubiquitous commands
// like echo that exist at /usr/bin/echo. The wrapper retries through this
// list before failing.
var fallbackPATH = []string{
	"/usr/local/sbin",
	"/usr/local/bin",
	"/usr/sbin",
	"/usr/bin",
	"/sbin",
	"/bin",
}

// lookPathFn is overridable in tests to inject specific LookPath errors
// (notably exec.ErrDot, which is otherwise hard to trigger deterministically
// because it depends on the process CWD and PATH semantics).
var lookPathFn = exec.LookPath

// resolveCommandPath returns the absolute path to cmd, suitable for
// syscall.Exec. It first delegates to exec.LookPath (which honors PATH and
// handles absolute paths). If that fails for a bare command name with
// exec.ErrNotFound, it falls back to scanning standard system directories.
// On total failure, the returned error includes diagnostic context (PATH
// value, env count) to help localize OC-style failures (#271).
//
// The fallback ONLY fires for not-found errors. Permission errors,
// exec.ErrDot, and other LookPath errors propagate unchanged — silently
// substituting a different binary from /usr/bin when LookPath rejected
// the original for permission reasons would mask a policy violation.
//
// Slash-containing arguments (absolute or relative) intentionally do NOT
// fall back to system dirs — the caller asked for that specific path, so
// the error should reflect what they asked for, not silently substitute.
func resolveCommandPath(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("empty command")
	}
	path, err := lookPathFn(cmd)
	if err == nil {
		return path, nil
	}
	if strings.ContainsRune(cmd, os.PathSeparator) {
		return "", fmt.Errorf("%w (PATH=%q, env_count=%d)", err, os.Getenv("PATH"), len(os.Environ()))
	}
	// Non-not-found errors (ErrDot, fs.ErrPermission, etc.) must not be
	// papered over by the fallback. They tell us something specific about
	// the user's invocation — surface them with diagnostics.
	if !errors.Is(err, exec.ErrNotFound) {
		return "", fmt.Errorf("%w (PATH=%q, env_count=%d)", err, os.Getenv("PATH"), len(os.Environ()))
	}
	for _, dir := range fallbackPATH {
		candidate := filepath.Join(dir, cmd)
		info, statErr := os.Stat(candidate)
		if statErr != nil || info.IsDir() {
			continue
		}
		// unix.Access honors the effective uid/gid, ACLs, and MAC; the
		// raw mode bits would let us return a binary the current process
		// cannot actually execute, blocking later fallback dirs from
		// being considered.
		if accessErr := unix.Access(candidate, unix.X_OK); accessErr != nil {
			continue
		}
		return candidate, nil
	}
	return "", fmt.Errorf(
		"%w (PATH=%q, env_count=%d, fallback_dirs=%v)",
		err, os.Getenv("PATH"), len(os.Environ()), fallbackPATH,
	)
}
