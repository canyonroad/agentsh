//go:build !windows

package fsmonitor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/session"
	"github.com/agentsh/agentsh/pkg/types"
	"github.com/hanwen/go-fuse/v2/fs"
)

func newCheckTestNode(t *testing.T, workspace string, pol *policy.Policy) *node {
	t.Helper()
	return newCheckTestNodeWithEscape(t, workspace, pol, false)
}

// newCheckTestNodeWithEscape lets a test pick the SymlinkEscapeDeny mode
// without rewriting the whole node construction. escapeDeny=false (default)
// matches the policies.symlink_escape="evaluate" mode; escapeDeny=true
// matches the historical workspace-escape blanket-deny ("deny" mode).
func newCheckTestNodeWithEscape(t *testing.T, workspace string, pol *policy.Policy, escapeDeny bool) *node {
	t.Helper()
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}
	return &node{
		LoopbackNode: fs.LoopbackNode{RootData: &fs.LoopbackRoot{Path: workspace}},
		hooks: &Hooks{
			SessionID:         "session-symlink",
			Policy:            engine,
			VirtualRoot:       "/workspace",
			SymlinkEscapeDeny: escapeDeny,
		},
	}
}

// newCheckTestNodeWithEscapeCwd is newCheckTestNodeWithEscape plus a session
// whose Cwd is set, so deny-mode cwd-subtree behavior (#377) is testable.
func newCheckTestNodeWithEscapeCwd(t *testing.T, workspace string, pol *policy.Policy, escapeDeny bool, cwd string) *node {
	t.Helper()
	n := newCheckTestNodeWithEscape(t, workspace, pol, escapeDeny)
	n.hooks.Session = &session.Session{Cwd: cwd}
	return n
}

// realRoot returns the symlink-resolved form of dir, matching what
// resolveRealPathUnderRoot uses internally (macOS resolves /var -> /private/var,
// and t.TempDir() on some systems returns a path under /var).
func realRoot(t *testing.T, dir string) string {
	t.Helper()
	r, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return filepath.Clean(dir)
	}
	return filepath.Clean(r)
}

// TestCheck_StatOnSymlinkLeafDoesNotResolveTarget is a regression test
// for the venv/bin/python case: an lstat/readlink/delete/rmdir on a
// workspace symlink whose target lies outside the workspace must
// evaluate the policy on the symlink path itself, not on the target.
// Pre-fix, check() always called the resolver with mustExist=true, which
// dereferenced the leaf symlink and routed the policy check to the
// target (e.g. /usr/bin/python3), denying a normal operation on a
// symlink the agent itself just created.
func TestCheck_StatOnSymlinkLeafDoesNotResolveTarget(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	// Mimic venv/bin/python -> <outside>/system-binary.
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	// Policy: deny the outside target, allow the workspace.
	// Pre-fix, all four ops resolved to <outside>/system-binary and
	// matched the deny rule. Post-fix, the policy check runs against
	// the link path under the workspace and matches the allow rule.
	pol := &policy.Policy{
		Version: 1,
		Name:    "venv-test",
		FileRules: []policy.FileRule{
			{Name: "deny-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "deny"},
			{Name: "allow-workspace", Paths: []string{realRoot(t, workspace) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n := newCheckTestNode(t, workspace, pol)

	for _, op := range []string{"stat", "readlink", "delete", "rmdir"} {
		dec := n.check(context.Background(), "/workspace/venv/bin/python", op)
		if dec.EffectiveDecision == types.DecisionDeny {
			t.Errorf("op=%q on workspace symlink leaf was denied (rule=%q); "+
				"expected allow -- check() must not dereference leaf for this op",
				op, dec.Rule)
		}
		if dec.Rule == "deny-outside" {
			t.Errorf("op=%q matched deny-outside rule; check() resolved leaf to target", op)
		}
	}
}

// TestCheck_OpenOnSymlinkFallsThroughToTargetPolicy verifies the other
// half of the fix: for operations whose subject IS the target
// (open/read/write), checkWithExist no longer blanket-denies when the
// target lies outside the workspace. Instead it falls through to
// evalEscapedSymlink and evaluates the policy against the resolved
// outside path. Operators that want to block system symlinks can do so
// with a regular file_rule deny on the target path.
func TestCheck_OpenOnSymlinkFallsThroughToTargetPolicy(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	outsideGlob := realRoot(t, outsideDir) + "/**"
	workspaceGlob := realRoot(t, workspace) + "/**"

	// First: allow the outside target explicitly -- the resolved-outside
	// path should match the allow rule, not the old hardcoded
	// "workspace-escape" deny.
	allowPol := &policy.Policy{
		Version: 1,
		Name:    "allow-outside",
		FileRules: []policy.FileRule{
			{Name: "allow-outside", Paths: []string{outsideGlob}, Operations: []string{"*"}, Decision: "allow"},
			{Name: "allow-workspace", Paths: []string{workspaceGlob}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n := newCheckTestNode(t, workspace, allowPol)
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision == types.DecisionDeny {
		t.Errorf("read with outside allowed: rule=%q decision=%v; expected allow",
			dec.Rule, dec.EffectiveDecision)
	}
	if dec.Rule == "workspace-escape" {
		t.Errorf("rule=workspace-escape; should have fallen through to file_rule eval")
	}

	// Second: deny the outside target -- now the symlink-target eval
	// should deny via the regular file rule, not via workspace-escape.
	denyPol := &policy.Policy{
		Version: 1,
		Name:    "deny-outside",
		FileRules: []policy.FileRule{
			{Name: "deny-outside", Paths: []string{outsideGlob}, Operations: []string{"*"}, Decision: "deny"},
			{Name: "allow-workspace", Paths: []string{workspaceGlob}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n2 := newCheckTestNode(t, workspace, denyPol)
	dec = n2.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Errorf("read with outside denied: rule=%q decision=%v; expected deny",
			dec.Rule, dec.EffectiveDecision)
	}
	if dec.Rule == "workspace-escape" {
		t.Errorf("rule=workspace-escape; should be the regular deny-outside file rule")
	}
}

// TestCheck_SymlinkEscapeDenyRestoresBlanketDeny verifies that with
// policies.symlink_escape="deny" (SymlinkEscapeDeny=true), a workspace
// symlink whose target lies outside the workspace root returns the
// historical "workspace-escape" deny -- even when a file_rule would
// otherwise allow the resolved target. This is the opt-in strict
// posture the maintainer asked for in the PR #313 review.
func TestCheck_SymlinkEscapeDenyRestoresBlanketDeny(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	// Policy explicitly allows the outside target. Under
	// SymlinkEscapeDeny=true the workspace-escape rule must still win.
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-outside",
		FileRules: []policy.FileRule{
			{Name: "allow-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
			{Name: "allow-workspace", Paths: []string{realRoot(t, workspace) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n := newCheckTestNodeWithEscape(t, workspace, pol, true)
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("with SymlinkEscapeDeny=true, escaped-target read must deny; got %v rule=%q",
			dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("rule=%q; want workspace-escape (strict-mode blanket)", dec.Rule)
	}
}

// TestCheck_DotDotEscapeStillDeniesAsWorkspaceEscape verifies that
// "..":-style escapes (paths above the workspace root) remain a hard
// "workspace-escape" deny even after the fall-through is added.
func TestCheck_DotDotEscapeStillDeniesAsWorkspaceEscape(t *testing.T) {
	workspace := t.TempDir()
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n := newCheckTestNode(t, workspace, pol)
	// "/workspace/../etc/hostname" is not under /workspace and must deny.
	dec := n.check(context.Background(), "/workspace/../etc/hostname", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("..-style escape must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("..-style escape rule=%q; want workspace-escape", dec.Rule)
	}
}

// the previous TestCheck_DotDot... test only passed because /workspace/../etc/hostname
// resolves to a path that does not exist under the temp parent (EvalSymlinks errors -> "" ->
// workspace-escape). With a real sibling on disk and a broad "/**" allow
// rule, the ".."-escape would have resolved to the sibling and been
// allowed before the evalEscapedSymlink containment guard. It must still
// deny as workspace-escape.
func TestCheck_DotDotEscapeToExistingSiblingDeniesAsWorkspaceEscape(t *testing.T) {
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	if err := os.MkdirAll(workspace, 0o755); err != nil {
		t.Fatal(err)
	}
	// Real sibling of the workspace root with an existing file, so a
	// ".." escape that reached EvalSymlinks would succeed.
	sibling := filepath.Join(parent, "outside")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sibling, "secret"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n := newCheckTestNode(t, workspace, pol)

	dec := n.check(context.Background(), "/workspace/../outside/secret", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("..-escape to existing sibling must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("..-escape to existing sibling rule=%q; want workspace-escape", dec.Rule)
	}
}

// Issue #377 (part 2): in symlink_escape="deny" mode, a symlink whose target
// escapes the mount but resolves THROUGH the process cwd subtree must be
// evaluated against file_rules (like evaluate mode), not blanket-denied as
// workspace-escape. Escapes outside the cwd subtree, ".."-escapes, and broken
// links stay workspace-escape denies.

func TestCheck_DenyCwdSubtreeEscapeIsEvaluatedAndAllowed(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-outside",
		FileRules: []policy.FileRule{
			{Name: "allow-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	// cwd is the venv subtree; the escaping symlink is under it.
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/venv")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionAllow {
		t.Fatalf("deny mode + cwd-subtree escape must evaluate file_rules; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule == "workspace-escape" {
		t.Errorf("rule=%q; want a file_rule (not blanket workspace-escape)", dec.Rule)
	}
}

func TestCheck_DenyCwdSubtreeEscapeIsEvaluatedAndDeniedByFileRule(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "deny-outside",
		FileRules: []policy.FileRule{
			{Name: "deny-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "deny"},
		},
	}
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/venv")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("file_rule deny must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "deny-outside" {
		t.Errorf("rule=%q; want deny-outside (evaluated, not blanket workspace-escape)", dec.Rule)
	}
}

func TestCheck_DenyEscapeOutsideCwdSubtreeStillBlanketDenies(t *testing.T) {
	workspace := t.TempDir()
	outsideDir := t.TempDir()
	outsideTarget := filepath.Join(outsideDir, "system-binary")
	if err := os.WriteFile(outsideTarget, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outsideTarget, filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-outside",
		FileRules: []policy.FileRule{
			{Name: "allow-outside", Paths: []string{realRoot(t, outsideDir) + "/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	// cwd is a DIFFERENT subtree; the escaping symlink is NOT under it.
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/proj")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("escape outside cwd subtree must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("rule=%q; want workspace-escape (deny mode, outside cwd subtree)", dec.Rule)
	}
}

func TestCheck_DenyDotDotEscapeUnderCwdStillBlanketDenies(t *testing.T) {
	workspace := t.TempDir()
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	// cwd is the whole workspace, so the path is "in the cwd subtree", forcing
	// the cwd-subtree branch; a ".."-escape must STILL deny because
	// evalEscapedSymlink returns "" for it.
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace")
	dec := n.check(context.Background(), "/workspace/../etc/hostname", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("..-escape under cwd must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("rule=%q; want workspace-escape (..-escape always denies)", dec.Rule)
	}
}

// A dangling symlink under the cwd subtree must STILL blanket-deny in deny
// mode: evalEscapedSymlink's EvalSymlinks call fails and returns "", so even
// though the path is in the cwd subtree it must not fall through to a default
// file_rules allow on the broken target string.
func TestCheck_DenyCwdSubtreeBrokenSymlinkStillBlanketDenies(t *testing.T) {
	workspace := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workspace, "venv", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent/target", filepath.Join(workspace, "venv", "bin", "python")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}
	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow-all", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	n := newCheckTestNodeWithEscapeCwd(t, workspace, pol, true, "/workspace/venv")
	dec := n.check(context.Background(), "/workspace/venv/bin/python", "read")
	if dec.EffectiveDecision != types.DecisionDeny {
		t.Fatalf("broken symlink in cwd subtree must deny; got %v rule=%q", dec.EffectiveDecision, dec.Rule)
	}
	if dec.Rule != "workspace-escape" {
		t.Errorf("rule=%q; want workspace-escape (broken link always denies)", dec.Rule)
	}
}
