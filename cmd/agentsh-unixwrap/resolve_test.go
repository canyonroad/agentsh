//go:build linux && cgo

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestResolveCommandPath_FoundInPATH verifies the standard happy path:
// a bare command name found via exec.LookPath using the caller's PATH.
func TestResolveCommandPath_FoundInPATH(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin")
	path, err := resolveCommandPath("sh")
	require.NoError(t, err)
	require.True(t, filepath.IsAbs(path), "expected absolute path, got %q", path)
}

// TestResolveCommandPath_FallbackWhenPATHEmpty covers the OC posture
// (canyonroad/agentsh#271): the inherited PATH is empty, exec.LookPath
// fails, and the resolver must find the command via the hardcoded fallback
// dirs. Without this, every bare command name fails on hosts where the
// server filters PATH out of the wrapper's environment.
func TestResolveCommandPath_FallbackWhenPATHEmpty(t *testing.T) {
	// /bin/sh is universal on Linux. Verify presence as a precondition.
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skipf("/bin/sh not present, cannot exercise fallback: %v", err)
	}

	t.Setenv("PATH", "")
	path, err := resolveCommandPath("sh")
	require.NoError(t, err, "fallback should resolve sh even with empty PATH")
	require.True(t, filepath.IsAbs(path), "expected absolute path, got %q", path)
	// Resolved path must come from a fallback dir, not from PATH.
	matched := false
	for _, dir := range fallbackPATH {
		if filepath.Dir(path) == dir {
			matched = true
			break
		}
	}
	require.True(t, matched, "resolved path %q not under fallbackPATH", path)
}

// TestResolveCommandPath_NotFoundIncludesDiagnostics verifies that a
// total-miss error includes the PATH value, env count, and fallback dirs
// so OC-style failures can be diagnosed from the agentsh-server logs
// without needing to reproduce the bug.
func TestResolveCommandPath_NotFoundIncludesDiagnostics(t *testing.T) {
	t.Setenv("PATH", "/nonexistent:/also-nonexistent")
	_, err := resolveCommandPath("definitely-not-a-real-command-xyzzy-271")
	require.Error(t, err)
	msg := err.Error()
	require.Contains(t, msg, `PATH="/nonexistent:/also-nonexistent"`, "error must surface PATH for diagnostics")
	require.Contains(t, msg, "env_count=", "error must surface env count")
	require.Contains(t, msg, "fallback_dirs=", "error must surface fallback list")
}

// TestResolveCommandPath_AbsolutePathBypassesFallback ensures that if the
// caller asked for /opt/some/bin/x and that does not exist, we do NOT
// silently substitute /usr/bin/x — the failure must be reported against
// the requested path. Otherwise a misconfigured policy could land at the
// wrong binary.
func TestResolveCommandPath_AbsolutePathBypassesFallback(t *testing.T) {
	t.Setenv("PATH", "")
	// Non-existent absolute path that shares a basename with a real fallback.
	_, err := resolveCommandPath("/nonexistent/dir/sh")
	require.Error(t, err, "absolute path must not silently fall back to /bin/sh")
	require.NotContains(t, err.Error(), "fallback_dirs=", "absolute paths skip fallback search")
	require.Contains(t, err.Error(), `PATH=""`, "absolute path errors still include diagnostics")
}

// TestResolveCommandPath_EmptyCommand covers the trivial guard.
func TestResolveCommandPath_EmptyCommand(t *testing.T) {
	_, err := resolveCommandPath("")
	require.Error(t, err)
	require.Contains(t, strings.ToLower(err.Error()), "empty")
}

// TestResolveCommandPath_DirectoryNotResolved guards against the case
// where a fallback dir contains a subdirectory with the same name as the
// requested command. os.Stat would succeed on the directory, but it's
// not executable in the exec-syscall sense.
func TestResolveCommandPath_DirectoryNotResolved(t *testing.T) {
	tmp := t.TempDir()
	// Create a fake "sh" subdirectory inside a fallback path candidate.
	require.NoError(t, os.MkdirAll(filepath.Join(tmp, "sh"), 0o755))
	// Override fallbackPATH to point at our temp dir for the scope of this test.
	orig := fallbackPATH
	fallbackPATH = []string{tmp}
	t.Cleanup(func() { fallbackPATH = orig })

	t.Setenv("PATH", "")
	_, err := resolveCommandPath("sh")
	require.Error(t, err, "a directory named sh must not be returned as the resolved command path")
}

// TestResolveCommandPath_ErrDotDoesNotFallback guards against roborev
// #7712 finding (Medium): if LookPath returns a non-not-found error
// (e.g. exec.ErrDot when the resolved entry is in CWD via "." in PATH),
// the resolver must NOT silently substitute /usr/bin/<cmd>. Falling
// back would route around the operator's intended binary in CWD.
func TestResolveCommandPath_ErrDotDoesNotFallback(t *testing.T) {
	orig := lookPathFn
	lookPathFn = func(name string) (string, error) {
		return "./sh", &exec.Error{Name: name, Err: exec.ErrDot}
	}
	t.Cleanup(func() { lookPathFn = orig })

	t.Setenv("PATH", ".")
	_, err := resolveCommandPath("sh")
	require.Error(t, err)
	require.True(t, errors.Is(err, exec.ErrDot), "ErrDot must propagate unchanged, got: %v", err)
	// fallback_dirs is only emitted when we actually entered the fallback loop.
	require.NotContains(t, err.Error(), "fallback_dirs=", "non-not-found error must skip the fallback loop")
}

// TestResolveCommandPath_FallbackSkipsNonExecutableCandidate guards
// against roborev #7712 finding (Low): if a fallback dir contains a
// regular file matching the command name but the current process
// cannot execute it (e.g. mode 0o644, or owned by another user with
// no group/world execute bit), the resolver must skip it and continue
// to the next fallback dir rather than returning a path the caller
// cannot actually exec.
func TestResolveCommandPath_FallbackSkipsNonExecutableCandidate(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	// dir1 has a non-executable file matching the command.
	require.NoError(t, os.WriteFile(filepath.Join(dir1, "agentsh-271-probe"), []byte("notexec"), 0o644))
	// dir2 has the executable.
	exe := filepath.Join(dir2, "agentsh-271-probe")
	require.NoError(t, os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755))

	orig := fallbackPATH
	fallbackPATH = []string{dir1, dir2}
	t.Cleanup(func() { fallbackPATH = orig })

	t.Setenv("PATH", "")
	resolved, err := resolveCommandPath("agentsh-271-probe")
	require.NoError(t, err)
	require.Equal(t, exe, resolved, "resolver must skip non-executable candidate in dir1 and find dir2's executable")
}
