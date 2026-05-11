//go:build linux

package fsmonitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/config"
	"github.com/agentsh/agentsh/internal/policy"
)

// TestFUSE_TruncateUnderSoftDelete is a regression test for the bug where
// truncating an existing file under audit.mode=soft_delete returned EIO.
//
// Before the fix, the FATTR_SIZE branch in Setattr routed truncate through
// applyAuditPolicy with a nil divert; under soft_delete that handler
// returned "soft_delete_no_handler" -> EIO. Ordinary writes that pass
// O_TRUNC (e.g. `python -m venv` re-running over an existing venv, which
// truncates venv/.gitignore) surfaced this as "[Errno 5] Input/output
// error". Truncate is content-shrink, not delete -- the inode stays --
// so it must not be treated as a destructive op for soft_delete.
//
// Both truncate entry points were fixed: Setattr(FATTR_SIZE) and the
// Open(O_TRUNC) branch. This test exercises the Setattr path -- on Linux,
// go-fuse does not advertise CAP_ATOMIC_O_TRUNC, so an open(O_TRUNC) is
// split by the kernel into open() + a separate truncate(), and the
// truncate lands in Setattr(FATTR_SIZE). The Open(O_TRUNC) fix is
// defensive for mounts/kernels that do deliver atomic open-truncate.
func TestFUSE_TruncateUnderSoftDelete(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	workspace := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	target := filepath.Join(workspace, "data.txt")
	if err := os.WriteFile(target, []byte("hello-world"), 0o644); err != nil {
		t.Fatal(err)
	}

	// checkWithExist resolves /workspace/... to the real backing path
	// (the t.TempDir() workspace) before calling CheckFile, so a policy
	// scoped to "/workspace/**" would not match on a host where the
	// FUSE mount actually runs -- the truncate would then be denied by
	// policy rather than exercising the soft_delete path this test is
	// about. Use "/**" so the test validates the intended behavior
	// regardless of where the resolved path lands.
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	enabled := true
	hooks := &Hooks{
		SessionID: "session-trunc",
		Policy:    engine,
		Emit:      &typeCaptureEmitter{},
		FUSEAudit: &FUSEAuditHooks{
			Config: config.FUSEAuditConfig{
				Enabled:   &enabled,
				Mode:      "soft_delete",
				TrashPath: ".agentsh_trash",
			},
		},
	}

	m, err := MountWorkspace(context.Background(), workspace, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	mountTarget := filepath.Join(mountPoint, "data.txt")

	// 1. Explicit truncate(2).
	if err := os.Truncate(mountTarget, 0); err != nil {
		t.Fatalf("os.Truncate returned %v under soft_delete; expected nil "+
			"(this is the EIO regression)", err)
	}

	// 2. Re-write via O_WRONLY|O_TRUNC (the path that breaks `python -m venv`).
	if err := os.WriteFile(mountTarget, []byte("new"), 0o644); err != nil {
		t.Fatalf("os.WriteFile (O_TRUNC) returned %v under soft_delete; "+
			"expected nil", err)
	}

	// Sanity check: content was replaced, inode preserved.
	got, err := os.ReadFile(mountTarget)
	if err != nil {
		t.Fatalf("readback: %v", err)
	}
	if string(got) != "new" {
		t.Fatalf("expected content %q, got %q", "new", string(got))
	}
}
