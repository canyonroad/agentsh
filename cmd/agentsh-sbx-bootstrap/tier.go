package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// probeShimTier runs `/bin/sh -c 'command -v curl'` and reports whether the
// resolved curl path lives under shimDir. Returns (ok, resolvedPath, err).
// A non-nil error means the probe couldn't be run at all (e.g. /bin/sh
// missing); a successful run with `ok=false` means curl is either absent or
// the system curl is winning over the shim.
func probeShimTier(shimDir string) (bool, string, error) {
	cmd := exec.Command("/bin/sh", "-c", "command -v curl")
	out, err := cmd.Output()
	if err != nil {
		// `command -v curl` exits 1 when curl isn't found; that's not an error
		// for our purposes — it just means the shim tier didn't apply.
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
			return false, "", nil
		}
		return false, "", fmt.Errorf("probe: %w", err)
	}
	resolved := strings.TrimSpace(string(out))
	if resolved == "" {
		return false, "", nil
	}
	clean := filepath.Clean(shimDir)
	return strings.HasPrefix(resolved, clean+string(filepath.Separator)) || resolved == clean, resolved, nil
}

// writeTierFile writes the active tier name (e.g. "shim" or "none") followed
// by a trailing newline to path. Atomic via tmp+rename so concurrent readers
// (the SKILL.md tells the agent to `cat` this file) never see a half-written
// value. Creates parent dirs with mode 0755.
func writeTierFile(path, tier string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir tier dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(tier+"\n"), 0o644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}
