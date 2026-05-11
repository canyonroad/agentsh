package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// probeShimTier runs a tiny shell that first sources the kit's PATH-injection
// hook at /etc/profile.d/agentsh.sh (if present) and then resolves curl.
// Returns (ok, resolvedPath, err). `ok=true` when the resolved curl lives
// under shimDir; `ok=false` means either curl is absent or the system curl
// is winning over the shim (i.e. the kit's PATH wiring isn't effective).
// A non-nil error means the probe couldn't be run at all (e.g. /bin/sh
// missing).
//
// Sourcing profile.d explicitly matters because the bootstrap typically runs
// in a non-login shell (the Docker Sandboxes `startup` phase), so PATH
// modifications written to /etc/profile.d/ are not picked up by `/bin/sh`
// out of the box. The probe must verify the agent's eventual PATH, not the
// bootstrap's own PATH at invocation time.
func probeShimTier(shimDir string) (bool, string, error) {
	// Guard the `dot` source with `[ -r ... ]` rather than `2>/dev/null || true`:
	// in POSIX mode (which bash-as-/bin/sh enters), a missing-file failure from
	// the special builtin `.` aborts the shell before `|| true` can rescue it,
	// turning a no-op into a probe failure. The bracket test sidesteps that.
	const script = "[ -r /etc/profile.d/agentsh.sh ] && . /etc/profile.d/agentsh.sh; command -v curl"
	cmd := exec.Command("/bin/sh", "-c", script)
	out, err := cmd.Output()
	if err != nil {
		// `command -v curl` exits 1 when curl isn't found; that's not an error
		// for our purposes — it just means the shim tier didn't apply.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
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
