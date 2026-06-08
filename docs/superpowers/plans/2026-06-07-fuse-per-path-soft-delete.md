# FUSE per-path soft-delete (#417) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the FUSE layer route `rm`/`rmdir` to trash when a per-path `decision: soft_delete` policy rule matches, even when the global `sandbox.fuse.audit.mode` is the default `monitor` — matching the behavior the ptrace layer already has.

**Architecture:** Decouple "trash availability" from "global audit mode". Always wire a trash divert into the FUSE hooks when soft-delete is possible (global mode is `soft_delete` *or* the policy has any `soft_delete` file rule), keep `FUSEAuditHooks.Config.Mode` set to the real configured global mode, and let `node.Unlink`/`node.Rmdir`/cross-mount-rename compute a per-operation mode that upgrades to `soft_delete` when `dec.PolicyDecision == soft_delete`.

**Tech Stack:** Go, go-fuse v2, gopkg.in/yaml.v3, standard `testing`.

**Spec:** `docs/superpowers/specs/2026-06-07-fuse-per-path-soft-delete-design.md`

---

## File structure

- `internal/policy/engine.go` — add `HasSoftDeleteFileRule()` predicate (Task 1).
- `internal/platform/interfaces.go` — add `AuditMode` field to `FSConfig` (Task 2).
- `internal/fsmonitor/policy.go` — `applyAuditPolicy` takes an explicit `opMode`; add `resolveOpMode` helper (Task 3).
- `internal/fsmonitor/fuse.go` — `Unlink`/`Rmdir`/cross-mount-`Rename` pass the resolved per-op mode (Task 4).
- `internal/platform/linux/filesystem.go` — set `FUSEAudit.Config.Mode` from `cfg.AuditMode` instead of hardcoding (Task 5).
- `internal/api/core.go` — wire `TrashConfig` + `AuditMode` for the primary workspace mount when soft-delete is possible (Task 5).
- `internal/config/config.go` — warn on unknown keys under `sandbox.fuse` (Task 6).
- `internal/fsmonitor/fuse_softdelete_perpath_test.go` — new unit tests (Task 4).
- `internal/integration/agentsh_soft_delete_perpath_test.go` — new integration test (Task 7).

---

## Task 1: `HasSoftDeleteFileRule()` on the policy engine

**Files:**
- Modify: `internal/policy/engine.go`
- Test: `internal/policy/engine_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/policy/engine_test.go`:

```go
func TestEngine_HasSoftDeleteFileRule(t *testing.T) {
	withRule := &Policy{
		Version: 1,
		Name:    "with-soft-delete",
		FileRules: []FileRule{
			{Name: "sd", Paths: []string{"/workspace/**"}, Operations: []string{"*"}, Decision: "soft_delete"},
		},
	}
	eng, err := NewEngine(withRule, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if !eng.HasSoftDeleteFileRule() {
		t.Fatal("expected HasSoftDeleteFileRule() == true when a soft_delete rule exists")
	}

	withoutRule := &Policy{
		Version: 1,
		Name:    "no-soft-delete",
		FileRules: []FileRule{
			{Name: "allow", Paths: []string{"/workspace/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	eng2, err := NewEngine(withoutRule, false, true)
	if err != nil {
		t.Fatal(err)
	}
	if eng2.HasSoftDeleteFileRule() {
		t.Fatal("expected HasSoftDeleteFileRule() == false when no soft_delete rule exists")
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/policy/ -run TestEngine_HasSoftDeleteFileRule -v`
Expected: FAIL — `eng.HasSoftDeleteFileRule undefined (type *Engine has no field or method HasSoftDeleteFileRule)`.

- [ ] **Step 3: Implement the predicate**

Add to `internal/policy/engine.go` (near the other `*Engine` methods, e.g. just above `CheckFile`):

```go
// HasSoftDeleteFileRule reports whether any compiled file rule uses the
// soft_delete decision. Used to decide whether the FUSE layer needs a trash
// divert wired in even when the global audit mode is not soft_delete.
func (e *Engine) HasSoftDeleteFileRule() bool {
	for _, r := range e.compiledFileRules {
		if r.rule.Decision == string(types.DecisionSoftDelete) {
			return true
		}
	}
	return false
}
```

Note: `types` is already imported in `engine.go` (it references `types.DecisionSoftDelete` at line ~1210). `FileRule.Decision` is a `string`; `types.DecisionSoftDelete` is a `types.Decision` whose underlying value is `"soft_delete"`, so the `string(...)` conversion is required.

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/policy/ -run TestEngine_HasSoftDeleteFileRule -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/policy/engine.go internal/policy/engine_test.go
git commit -m "feat(#417): add Engine.HasSoftDeleteFileRule predicate"
```

---

## Task 2: Add `AuditMode` to `platform.FSConfig`

**Files:**
- Modify: `internal/platform/interfaces.go:74` (the `FSConfig` struct)

- [ ] **Step 1: Add the field**

In `internal/platform/interfaces.go`, inside `type FSConfig struct`, add (place it directly above the `TrashConfig *TrashConfig` field):

```go
	// AuditMode is the global configured FUSE audit mode
	// ("monitor" | "soft_block" | "soft_delete" | "strict"; "" means
	// monitor). The FUSE layer uses it as the default per-operation mode;
	// a per-path soft_delete policy decision upgrades an individual
	// destructive operation regardless of this value.
	AuditMode string
```

- [ ] **Step 2: Verify it compiles**

Run: `go build ./internal/platform/...`
Expected: builds cleanly (no callers reference the new field yet).

- [ ] **Step 3: Commit**

```bash
git add internal/platform/interfaces.go
git commit -m "feat(#417): add AuditMode to platform.FSConfig"
```

---

## Task 3: `applyAuditPolicy` takes an explicit `opMode` + `resolveOpMode` helper

This is a pure refactor: every caller passes the current global mode, so behavior is unchanged. It sets up Task 4.

**Files:**
- Modify: `internal/fsmonitor/policy.go`
- Modify: `internal/fsmonitor/fuse.go` (call sites only)

- [ ] **Step 1: Change `applyAuditPolicy` to accept `opMode`**

In `internal/fsmonitor/policy.go`, change the signature and the mode-resolution block. Replace:

```go
func applyAuditPolicy(ctx context.Context, hooks *FUSEAuditHooks, sessionID string, op string, path string, dest string, realPath string, divert func() (*trash.Entry, error), run func() syscall.Errno) syscall.Errno {
	if hooks == nil {
		return run()
	}

	if hooks.Config.Enabled != nil && !*hooks.Config.Enabled {
		return run()
	}

	mode := hooks.Config.Mode
	if mode == "" {
		mode = "monitor"
	}
```

with:

```go
func applyAuditPolicy(ctx context.Context, hooks *FUSEAuditHooks, sessionID string, opMode string, op string, path string, dest string, realPath string, divert func() (*trash.Entry, error), run func() syscall.Errno) syscall.Errno {
	if hooks == nil {
		return run()
	}

	if hooks.Config.Enabled != nil && !*hooks.Config.Enabled {
		return run()
	}

	mode := opMode
	if mode == "" {
		mode = "monitor"
	}
```

Everything below (the `strict := ...` line and the `switch mode` block) stays as-is. `strict` still reads `hooks.Config.StrictOnAuditFailure || mode == "strict"`, so strict semantics continue to come from `Config` plus the resolved mode.

- [ ] **Step 2: Add the `resolveOpMode` helper**

Add to `internal/fsmonitor/policy.go` (below `applyAuditPolicy`):

```go
// resolveOpMode picks the audit mode for a single destructive operation. A
// per-path soft_delete policy decision upgrades the operation to soft_delete
// regardless of the global configured mode; otherwise the global mode applies.
func resolveOpMode(dec policy.Decision, globalMode string) string {
	if dec.PolicyDecision == types.DecisionSoftDelete {
		return string(types.DecisionSoftDelete)
	}
	return globalMode
}
```

Add the imports to `internal/fsmonitor/policy.go` if not present: `"github.com/agentsh/agentsh/internal/policy"` and `"github.com/agentsh/agentsh/pkg/types"`. (Check the existing import block first; `config` and `trash` are already imported.)

- [ ] **Step 3: Update the four call sites in `fuse.go` to pass the global mode**

In `internal/fsmonitor/fuse.go`, each `applyAuditPolicy(...)` call gains an `opMode` argument. For this refactor step, pass the global mode unchanged so behavior is identical. Add a tiny accessor first — add this method near `auditHooks()` (around line 702):

```go
func (n *node) globalAuditMode() string {
	h := n.auditHooks()
	if h == nil {
		return ""
	}
	return h.Config.Mode
}
```

Then update the calls (insert `n.globalAuditMode(),` as the new 4th argument, right after the sessionID argument):

- Line ~159 (`Unlink`):
```go
	return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), n.globalAuditMode(), "unlink", virt, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Unlink(ctx, name)
	})
```
- Line ~174 (`Rmdir`):
```go
	return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), n.globalAuditMode(), "rmdir", virt, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Rmdir(ctx, name)
	})
```
- Line ~217 (cross-mount `Rename`-as-delete):
```go
		return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), n.globalAuditMode(), "unlink", virtFrom, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
			return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
		})
```
- Line ~222 (normal `Rename`):
```go
	errno := applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), n.globalAuditMode(), "rename", virtFrom, virtTo, realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
```

- [ ] **Step 4: Verify build + existing tests pass (behavior unchanged)**

Run: `go build ./... && go test ./internal/fsmonitor/...`
Expected: builds; existing fsmonitor tests (including `TestFUSE_TruncateUnderSoftDelete`) PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/fsmonitor/policy.go internal/fsmonitor/fuse.go
git commit -m "refactor(#417): applyAuditPolicy takes explicit opMode; add resolveOpMode"
```

---

## Task 4: FUSE honors the per-path soft_delete decision

**Files:**
- Modify: `internal/fsmonitor/fuse.go` (`Unlink`, `Rmdir`, cross-mount-`Rename`)
- Test: `internal/fsmonitor/fuse_softdelete_perpath_test.go` (new)

- [ ] **Step 1: Write the failing test**

Create `internal/fsmonitor/fuse_softdelete_perpath_test.go`:

```go
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

// TestFUSE_PerPathSoftDelete_UnderMonitorMode is the regression test for #417:
// a per-path `decision: soft_delete` policy rule must route unlink to trash even
// when the global audit mode is the default "monitor".
func TestFUSE_PerPathSoftDelete_UnderMonitorMode(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	workspace := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	target := filepath.Join(workspace, "testfile.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	// checkWithExist resolves /workspace/... to the real backing path before
	// CheckFile, so use "/**" so the rule matches the resolved temp-dir path.
	pol := &policy.Policy{
		Version: 1,
		Name:    "per-path-soft-delete",
		FileRules: []policy.FileRule{
			{Name: "sd", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "soft_delete"},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	var notifiedPath, notifiedToken string
	enabled := true
	hooks := &Hooks{
		SessionID: "session-perpath",
		Policy:    engine,
		Emit:      &typeCaptureEmitter{},
		FUSEAudit: &FUSEAuditHooks{
			// Global mode is monitor; only the per-path policy decision
			// should trigger the divert.
			Config: config.FUSEAuditConfig{
				Enabled:   &enabled,
				Mode:      "monitor",
				TrashPath: ".agentsh_trash",
			},
			NotifySoftDelete: func(path, token string) {
				notifiedPath, notifiedToken = path, token
			},
		},
	}

	m, err := MountWorkspace(context.Background(), workspace, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	mountTarget := filepath.Join(mountPoint, "testfile.txt")
	if err := os.Remove(mountTarget); err != nil {
		t.Fatalf("os.Remove returned %v; expected nil (soft-delete should succeed)", err)
	}

	// The original backing file must be gone (moved), not present.
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("expected backing file to be moved out; stat err=%v", err)
	}

	// The trash directory must now contain the diverted file.
	trashDir := filepath.Join(workspace, ".agentsh_trash")
	entries, err := os.ReadDir(trashDir)
	if err != nil {
		t.Fatalf("read trash dir: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("expected trash dir to contain the soft-deleted file, found none")
	}

	if notifiedPath == "" || notifiedToken == "" {
		t.Fatalf("expected NotifySoftDelete to fire; got path=%q token=%q", notifiedPath, notifiedToken)
	}
}

// TestFUSE_PerPathAllow_UnderMonitorMode is the negative case: with global mode
// monitor and an allow decision, unlink is a real delete and trash stays empty.
func TestFUSE_PerPathAllow_UnderMonitorMode(t *testing.T) {
	if _, err := os.Stat("/dev/fuse"); err != nil {
		t.Skipf("fuse not available: %v", err)
	}

	workspace := t.TempDir()
	mountPoint := filepath.Join(t.TempDir(), "mnt")

	target := filepath.Join(workspace, "testfile.txt")
	if err := os.WriteFile(target, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	pol := &policy.Policy{
		Version: 1,
		Name:    "allow-all",
		FileRules: []policy.FileRule{
			{Name: "allow", Paths: []string{"/**"}, Operations: []string{"*"}, Decision: "allow"},
		},
	}
	engine, err := policy.NewEngine(pol, false, true)
	if err != nil {
		t.Fatal(err)
	}

	enabled := true
	hooks := &Hooks{
		SessionID: "session-allow",
		Policy:    engine,
		Emit:      &typeCaptureEmitter{},
		FUSEAudit: &FUSEAuditHooks{
			Config: config.FUSEAuditConfig{Enabled: &enabled, Mode: "monitor", TrashPath: ".agentsh_trash"},
		},
	}

	m, err := MountWorkspace(context.Background(), workspace, mountPoint, hooks)
	if err != nil {
		t.Skipf("mount failed (skipping): %v", err)
	}
	defer func() { _ = m.Unmount() }()

	if err := os.Remove(filepath.Join(mountPoint, "testfile.txt")); err != nil {
		t.Fatalf("os.Remove returned %v; expected nil", err)
	}

	trashDir := filepath.Join(workspace, ".agentsh_trash")
	if entries, err := os.ReadDir(trashDir); err == nil && len(entries) > 0 {
		t.Fatalf("expected no trash under allow+monitor, found %d entries", len(entries))
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/fsmonitor/ -run TestFUSE_PerPathSoftDelete_UnderMonitorMode -v`
Expected: FAIL — the file is hard-deleted, so the `os.Stat(target)` "moved out" check passes but `ReadDir(trashDir)` finds nothing → "expected trash dir to contain the soft-deleted file" (or the trash dir does not exist). The negative test (`TestFUSE_PerPathAllow_UnderMonitorMode`) should already PASS.

- [ ] **Step 3: Implement — compute per-op mode in the FUSE handlers**

In `internal/fsmonitor/fuse.go`, replace the `n.globalAuditMode()` argument (added in Task 3) with `resolveOpMode(...)` in the three *delete* paths. Leave the normal `Rename` (line ~222) using `n.globalAuditMode()`.

`Unlink` (line ~159):
```go
	return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), resolveOpMode(dec, n.globalAuditMode()), "unlink", virt, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Unlink(ctx, name)
	})
```

`Rmdir` (line ~174):
```go
	return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), resolveOpMode(dec, n.globalAuditMode()), "rmdir", virt, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
		return n.LoopbackNode.Rmdir(ctx, name)
	})
```

Cross-mount `Rename`-as-delete (line ~217). Here the subject being deleted is the source path, whose decision is `decFrom` (computed at line ~205):
```go
		return applyAuditPolicy(ctx, n.auditHooks(), n.hooksSessionID(), resolveOpMode(decFrom, n.globalAuditMode()), "unlink", virtFrom, "", realPath, n.makeDivertFunc(realPath), func() syscall.Errno {
			return n.LoopbackNode.Rename(ctx, name, newParent, newName, flags)
		})
```

In `Unlink` and `Rmdir`, `dec` is in scope (`dec := n.check(...)` then `dec = n.maybeApprove(...)`). `dec.PolicyDecision` is preserved by `maybeApprove` for non-approve decisions; soft_delete has `EffectiveDecision=allow`, so no approval path is taken. Read `dec` as it stands at the `applyAuditPolicy` call.

- [ ] **Step 4: Run the tests to verify they pass**

Run: `go test ./internal/fsmonitor/ -run 'TestFUSE_PerPath' -v`
Expected: both PASS.

- [ ] **Step 5: Run the full fsmonitor suite (no regressions)**

Run: `go test ./internal/fsmonitor/...`
Expected: PASS (including `TestFUSE_TruncateUnderSoftDelete`).

- [ ] **Step 6: Commit**

```bash
git add internal/fsmonitor/fuse.go internal/fsmonitor/fuse_softdelete_perpath_test.go
git commit -m "fix(#417): FUSE honors per-path soft_delete policy decision"
```

---

## Task 5: Wire trash availability + global mode into the workspace mount

Without this, `hooks.FUSEAudit` is nil in production unless the global mode is `soft_delete`, so the Task 4 divert never has a destination. This makes core.go provide the trash divert whenever the policy can soft-delete, and makes filesystem.go pass through the real configured mode.

**Files:**
- Modify: `internal/platform/linux/filesystem.go:276-285`
- Modify: `internal/api/core.go:1273-1301`

- [ ] **Step 1: filesystem.go — use the configured mode instead of hardcoding**

In `internal/platform/linux/filesystem.go`, replace the trash-setup block (currently lines ~276-285):

```go
	// Set up trash/soft-delete if configured
	if cfg.TrashConfig != nil && cfg.TrashConfig.Enabled {
		hooks.FUSEAudit = &fsmonitor.FUSEAuditHooks{
			Config: config.FUSEAuditConfig{
				Mode:      "soft_delete",
				TrashPath: cfg.TrashConfig.TrashDir,
			},
			HashLimitBytes:   cfg.TrashConfig.HashLimitBytes,
			NotifySoftDelete: cfg.NotifySoftDelete,
		}
	}
```

with:

```go
	// Set up trash/soft-delete if configured. The audit Mode reflects the
	// global configured mode (default monitor); a per-path soft_delete policy
	// decision upgrades individual destructive ops in the fsmonitor layer.
	if cfg.TrashConfig != nil && cfg.TrashConfig.Enabled {
		mode := cfg.AuditMode
		if mode == "" {
			mode = "monitor"
		}
		hooks.FUSEAudit = &fsmonitor.FUSEAuditHooks{
			Config: config.FUSEAuditConfig{
				Mode:      mode,
				TrashPath: cfg.TrashConfig.TrashDir,
			},
			HashLimitBytes:   cfg.TrashConfig.HashLimitBytes,
			NotifySoftDelete: cfg.NotifySoftDelete,
		}
	}
```

- [ ] **Step 2: core.go — make trash available when soft-delete is possible**

In `internal/api/core.go`, replace the soft-delete wiring block (currently lines ~1273-1301, starting at the `if a.cfg.Sandbox.FUSE.Audit.Mode == "soft_delete" {` line and ending at its closing `}`):

```go
	// Configure soft-delete/trash if enabled
	if a.cfg.Sandbox.FUSE.Audit.Mode == "soft_delete" {
		fsCfg.TrashConfig = &platform.TrashConfig{
			Enabled:        true,
			TrashDir:       a.cfg.Sandbox.FUSE.Audit.TrashPath,
			HashLimitBytes: hashLimit,
		}
		fsCfg.NotifySoftDelete = func(path, token string) {
			...
		}
	}
```

with (keep the existing `NotifySoftDelete` closure body verbatim — only the guarding condition and the surrounding `AuditMode` assignment change):

```go
	// Configure soft-delete/trash. Trash must be available to FUSE when the
	// global mode is soft_delete OR when the policy contains any per-path
	// soft_delete rule (which upgrades matching deletes individually). The
	// configured global mode is always passed through so default monitor
	// behavior is preserved for non-matching deletes.
	globalAuditMode := a.cfg.Sandbox.FUSE.Audit.Mode
	fsCfg.AuditMode = globalAuditMode
	if globalAuditMode == "soft_delete" || p.engine.HasSoftDeleteFileRule() {
		fsCfg.TrashConfig = &platform.TrashConfig{
			Enabled:        true,
			TrashDir:       a.cfg.Sandbox.FUSE.Audit.TrashPath,
			HashLimitBytes: hashLimit,
		}
		fsCfg.NotifySoftDelete = func(path, token string) {
			ev := types.Event{
				ID:        uuid.NewString(),
				Timestamp: time.Now().UTC(),
				Type:      "file_soft_deleted",
				SessionID: s.ID,
				CommandID: s.CurrentCommandID(),
				Path:      path,
				Fields: map[string]any{
					"trash_token":  token,
					"restore_hint": fmt.Sprintf("agentsh trash restore %s", token),
				},
			}
			persistCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err := a.store.AppendEvent(persistCtx, ev)
			cancel()
			if err != nil {
				slog.Error("persist fuse soft-delete event", "error", err, "event_type", ev.Type, "path", path)
			}
			a.broker.Publish(ev)
		}
	}
```

Note: confirm the policy engine handle in this scope. At line ~1267 the code calls `platform.NewPolicyAdapter(p.engine)`, so `p.engine` is the `*policy.Engine` to call `HasSoftDeleteFileRule()` on. If the local variable differs, use whatever `NewPolicyAdapter` is given.

- [ ] **Step 3: Verify build**

Run: `go build ./...`
Expected: builds cleanly.

- [ ] **Step 4: Run affected unit tests**

Run: `go test ./internal/api/... ./internal/platform/... ./internal/fsmonitor/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/platform/linux/filesystem.go internal/api/core.go
git commit -m "fix(#417): wire FUSE trash divert when policy has soft_delete rule"
```

---

## Task 6: Warn on unknown keys under `sandbox.fuse`

Catches the silent misconfiguration in the issue (`fuse.session.mode` instead of `sandbox.fuse.audit.mode`).

**Files:**
- Modify: `internal/config/config.go`
- Test: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`:

```go
func TestWarnUnknownFUSEKeys(t *testing.T) {
	good := []byte(`
sandbox:
  fuse:
    enabled: true
    audit:
      mode: soft_delete
`)
	if got := unknownFUSEKeys(good); len(got) != 0 {
		t.Fatalf("expected no unknown keys for valid config, got %v", got)
	}

	bad := []byte(`
sandbox:
  fuse:
    enabled: true
    session:
      mode: soft_delete
      trash_path: /var/lib/agentsh/trash
`)
	got := unknownFUSEKeys(bad)
	if len(got) != 1 || got[0] != "session" {
		t.Fatalf("expected [session], got %v", got)
	}
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/ -run TestWarnUnknownFUSEKeys -v`
Expected: FAIL — `undefined: unknownFUSEKeys`.

- [ ] **Step 3: Implement the helper + a node accessor, and call it during load**

Add to `internal/config/config.go` (near `yamlMappingPathExists`):

```go
// yamlMappingNode returns the mapping node at the given key path, or nil.
func yamlMappingNode(node *yaml.Node, path ...string) *yaml.Node {
	if node == nil {
		return nil
	}
	if node.Kind == yaml.DocumentNode {
		if len(node.Content) == 0 {
			return nil
		}
		node = node.Content[0]
	}
	for _, want := range path {
		if node == nil || node.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == want {
				next = node.Content[i+1]
				break
			}
		}
		if next == nil {
			return nil
		}
		node = next
	}
	return node
}

// knownFUSEKeys are the recognized keys under sandbox.fuse (see SandboxFUSEConfig).
var knownFUSEKeys = map[string]struct{}{
	"enabled":                 {},
	"deferred":                {},
	"audit":                   {},
	"mount_base_dir":          {},
	"deferred_marker_file":    {},
	"deferred_enable_command": {},
	"max_background":          {},
}

// unknownFUSEKeys returns keys present under sandbox.fuse that are not
// recognized by SandboxFUSEConfig. Used to surface silent misconfiguration
// (e.g. fuse.session.mode) since the YAML loader is non-strict.
func unknownFUSEKeys(data []byte) []string {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil
	}
	fuse := yamlMappingNode(&root, "sandbox", "fuse")
	if fuse == nil || fuse.Kind != yaml.MappingNode {
		return nil
	}
	var unknown []string
	for i := 0; i+1 < len(fuse.Content); i += 2 {
		key := fuse.Content[i].Value
		if _, ok := knownFUSEKeys[key]; !ok {
			unknown = append(unknown, key)
		}
	}
	return unknown
}
```

Then call it from the loader. In the `Load*` function that unmarshals `expanded` (the block at lines ~1386-1399 containing `yaml.Unmarshal([]byte(expanded), &cfg)`), add immediately after a successful `applyDefaults(&cfg)`:

```go
	for _, k := range unknownFUSEKeys([]byte(expanded)) {
		slog.Warn("unknown key under sandbox.fuse ignored; check the config schema",
			"key", k, "hint", "soft-delete uses sandbox.fuse.audit.mode and sandbox.fuse.audit.trash_path")
	}
```

Ensure `"log/slog"` is imported in `config.go` (add to the import block if absent).

- [ ] **Step 4: Run the test to verify it passes**

Run: `go test ./internal/config/ -run TestWarnUnknownFUSEKeys -v`
Expected: PASS.

- [ ] **Step 5: Run the config suite (no regressions)**

Run: `go test ./internal/config/...`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/config.go internal/config/config_test.go
git commit -m "feat(#417): warn on unknown sandbox.fuse config keys"
```

---

## Task 7: End-to-end integration test (per-path policy via the server)

Mirror the existing global-mode soft-delete integration test, but drive it with a per-path `decision: soft_delete` rule and the default global audit mode.

**Files:**
- Read first (pattern source): `internal/integration/agentsh_soft_delete_test.go`
- Test: `internal/integration/agentsh_soft_delete_perpath_test.go` (new)

- [ ] **Step 1: Read the existing test to copy its harness**

Run: `sed -n '1,200p' internal/integration/agentsh_soft_delete_test.go`
Note how it: builds the YAML config, starts the app, runs a delete through the exec path, and waits for a `file_soft_deleted` event (it skips when FUSE is unavailable). Reuse that exact harness.

- [ ] **Step 2: Write the new test**

Create `internal/integration/agentsh_soft_delete_perpath_test.go`. Copy the structure of `agentsh_soft_delete_test.go` and change only the config so that:
- `sandbox.fuse.audit.mode` is left at the default (omit it, or set `monitor`), and `sandbox.fuse.audit.trash_path` is set.
- the policy includes a file rule with `decision: soft_delete` covering the workspace (use the same path scoping the existing test uses for its workspace files).

The assertion is identical to the existing test: after the delete, a `file_soft_deleted` event is observed and `agentsh trash list` (or the equivalent in-test query the original uses) reports the entry. Keep the same FUSE-unavailable `t.Skipf` guard.

Because the exact harness symbols live in the existing file, base the new test on what Step 1 prints rather than inventing helper names here. The only substantive differences from the original are the two config changes above.

- [ ] **Step 3: Run the new test**

Run: `go test ./internal/integration/ -run SoftDeletePerPath -v`
Expected: PASS where `/dev/fuse` is available; SKIP otherwise (same as the original).

- [ ] **Step 4: Commit**

```bash
git add internal/integration/agentsh_soft_delete_perpath_test.go
git commit -m "test(#417): integration test for per-path FUSE soft-delete"
```

---

## Task 8: Full verification + cross-compile

**Files:** none (verification only).

- [ ] **Step 1: Cross-compile for Windows**

Run: `GOOS=windows go build ./...`
Expected: builds cleanly. (`fsmonitor/fuse.go` is `//go:build !windows`; the `config` and `policy` and `platform` changes are cross-platform.)

- [ ] **Step 2: Full build + test**

Run: `go build ./... && go test ./...`
Expected: PASS. Note: per project memory, a few tests fail only in the local env (long TMPDIR / mount-policy / symlink-sandbox) and `TestFlushLoop_PeriodicSync` is a Windows timer flake — these are not regressions from this change.

- [ ] **Step 3: Manual sanity against the issue repro (optional, requires /dev/fuse)**

With a config that has a `decision: soft_delete` rule on the workspace and the default audit mode, run `rm /workspace/testfile.txt` through a session and confirm `agentsh trash list` shows the file and `agentsh trash restore <token>` recovers it.

- [ ] **Step 4: Final commit if any verification fixups were needed**

```bash
git add -A
git commit -m "chore(#417): verification fixups"
```

---

## Self-review notes

- **Spec coverage:** §Detailed-design.1 → Tasks 2 & 5; §2 → Tasks 3 & 4; §3 (unknown-key warning) → Task 6; §Testing → Tasks 1,4,6,7 + regression in 3/5 and full run in 8. `HasSoftDeleteFileRule` (spec §1 bullet) → Task 1.
- **Precedence:** global `soft_delete` and per-path `soft_delete` both resolve to a divert (no conflict). Default `monitor` + non-matching delete → unchanged real delete (covered by the negative test in Task 4).
- **Trash-path source:** `Sandbox.FUSE.Audit.TrashPath` (default `.agentsh_trash` via `makeDivertFunc`), identical to the ptrace path.
- **Out of scope (unchanged):** the multi-mount loop at `core.go:362` never wired trash even before this change; ptrace `EXDEV` handling; trash TTL/quota/purge; macOS/Windows parity.
