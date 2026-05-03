//go:build linux && cgo

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

// resolveCommandPath returns the absolute path to cmd, suitable for
// syscall.Exec. It first delegates to exec.LookPath (which honors PATH and
// handles absolute paths). If that fails for a bare command name, it falls
// back to scanning standard system directories. On total failure, the
// returned error includes diagnostic context (PATH value, env count) to
// help localize OC-style failures (#271).
//
// Slash-containing arguments (absolute or relative) intentionally do NOT
// fall back to system dirs — the caller asked for that specific path, so
// the error should reflect what they asked for, not silently substitute.
func resolveCommandPath(cmd string) (string, error) {
	if cmd == "" {
		return "", fmt.Errorf("empty command")
	}
	if path, err := exec.LookPath(cmd); err == nil {
		return path, nil
	} else if strings.ContainsRune(cmd, os.PathSeparator) {
		return "", fmt.Errorf("%w (PATH=%q, env_count=%d)", err, os.Getenv("PATH"), len(os.Environ()))
	} else {
		// Bare name: scan fallback dirs. Save the original LookPath error
		// for the diagnostic if no fallback hits.
		for _, dir := range fallbackPATH {
			candidate := filepath.Join(dir, cmd)
			info, statErr := os.Stat(candidate)
			if statErr != nil {
				continue
			}
			if info.IsDir() {
				continue
			}
			if info.Mode()&0o111 == 0 {
				continue
			}
			return candidate, nil
		}
		return "", fmt.Errorf(
			"%w (PATH=%q, env_count=%d, fallback_dirs=%v)",
			err, os.Getenv("PATH"), len(os.Environ()), fallbackPATH,
		)
	}
}
