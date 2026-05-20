# file_monitor auto-enable skip when socket_rules configured — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Tighten the `file_monitor` auto-enable default in `applyDefaults` so it only fires when `socket_rules` are absent, eliminating the unixwrap deadlock described in issue #304.

**Architecture:** Single-condition change in `internal/config/config.go`'s `applyDefaults`. Adds `len(cfg.Sandbox.Seccomp.SocketRules) == 0` to the auto-enable gate. Test coverage in `internal/config/seccomp_test.go` for the new gate path and the explicit-true-with-socket-rules path.

**Tech Stack:** Go 1.x, `gopkg.in/yaml.v3`, `github.com/stretchr/testify/require`.

**Spec:** [`docs/superpowers/specs/2026-05-19-file-monitor-auto-enable-socket-rules-design.md`](../specs/2026-05-19-file-monitor-auto-enable-socket-rules-design.md)

---

## File map

- **Modify** `internal/config/config.go` (lines 1721–1735) — tighten auto-enable predicate, update comment.
- **Modify** `internal/config/seccomp_test.go` — add two new tests.

No new files. No interface changes. No other callers touched.

---

## Task 1: Add failing test — auto-enable is skipped when socket_rules are present

**Files:**
- Modify (append): `internal/config/seccomp_test.go`

- [ ] **Step 1: Append the failing test**

Add this function at the end of `internal/config/seccomp_test.go`:

```go
func TestFileMonitorAutoEnable_SkippedWhenSocketRulesPresent(t *testing.T) {
	// When seccomp is enabled and socket_rules are configured but
	// file_monitor is omitted, applyDefaults must NOT auto-enable
	// file_monitor — doing so installs file-notify rules that deadlock
	// the unixwrap during seccomp setup (issue #304).
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    socket_rules:
      - name: block-rxrpc
        family: AF_RXRPC
        action: errno
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	require.Nil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"precondition: omitted field must parse as nil")
	require.Len(t, cfg.Sandbox.Seccomp.SocketRules, 1,
		"precondition: socket_rules must parse")

	applyDefaults(&cfg)

	require.Nil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"applyDefaults must NOT auto-enable file_monitor when socket_rules are set")
	require.False(t,
		FileMonitorBoolWithDefault(cfg.Sandbox.Seccomp.FileMonitor.Enabled, false),
		"effective file_monitor.enabled must be false")
}
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `go test ./internal/config/ -run TestFileMonitorAutoEnable_SkippedWhenSocketRulesPresent -v`

Expected: FAIL — `applyDefaults` currently auto-enables, so `FileMonitor.Enabled` becomes non-nil `*true`. The first `require.Nil` after `applyDefaults` will fail with a message about the pointer not being nil.

- [ ] **Step 3: Commit the failing test**

```bash
git add internal/config/seccomp_test.go
git commit -m "test: add failing test for #304 file_monitor auto-enable gate

Verifies applyDefaults does not auto-enable file_monitor when
socket_rules are configured.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: Add failing test — explicit file_monitor.enabled: true is preserved when socket_rules present

**Files:**
- Modify (append): `internal/config/seccomp_test.go`

- [ ] **Step 1: Append the test**

Add this function at the end of `internal/config/seccomp_test.go`:

```go
func TestFileMonitorAutoEnable_ExplicitTrueWithSocketRulesRespected(t *testing.T) {
	// The auto-enable gate only governs the implicit default path.
	// Explicit `file_monitor.enabled: true` must still be respected
	// even when socket_rules are configured (operator opt-in).
	yamlData := []byte(`
sandbox:
  seccomp:
    enabled: true
    file_monitor:
      enabled: true
    socket_rules:
      - name: block-rxrpc
        family: AF_RXRPC
        action: errno
`)
	var cfg Config
	require.NoError(t, yaml.Unmarshal(yamlData, &cfg))

	applyDefaults(&cfg)

	require.NotNil(t, cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"explicit true must survive applyDefaults")
	require.True(t, *cfg.Sandbox.Seccomp.FileMonitor.Enabled,
		"explicit true must remain true")
}
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `go test ./internal/config/ -run TestFileMonitorAutoEnable_ExplicitTrueWithSocketRulesRespected -v`

Expected: PASS — the existing auto-enable logic only fires when `Enabled == nil`, so explicit `true` already survives. This test locks in the contract so the next change doesn't regress it.

- [ ] **Step 3: Commit**

```bash
git add internal/config/seccomp_test.go
git commit -m "test: lock in explicit file_monitor=true with socket_rules

Pins the contract that the auto-enable gate only governs the implicit
default path; explicit operator opt-in continues to work.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Implement the gate — skip auto-enable when socket_rules are configured

**Files:**
- Modify: `internal/config/config.go:1721-1735`

- [ ] **Step 1: Replace the auto-enable block**

In `internal/config/config.go`, replace the existing block at lines 1721–1735:

```go
	// Enable file_monitor by default when seccomp is explicitly enabled,
	// so openat(O_WRONLY) and other file syscalls are intercepted and
	// policy-enforced. Without this, only O_CREAT (new file creation)
	// gets caught by Landlock — writes to existing files pass through.
	// Note: we gate on Seccomp.Enabled, NOT seccompActive, because
	// unix_sockets-only mode shouldn't auto-enable full file monitoring
	// (the policy's allow-etc-read rules may not cover all paths the
	// dynamic linker needs, causing spurious EACCES on program startup).
	// Only auto-enable file_monitor when user didn't explicitly set it (nil).
	// If user set enabled: false, respect that — forcing it on causes EACCES
	// on shared library opens because the handler denies read-only opens
	// that don't match policy paths.
	if cfg.Sandbox.Seccomp.Enabled && cfg.Sandbox.Seccomp.FileMonitor.Enabled == nil {
		cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
	}
```

with:

```go
	// Enable file_monitor by default when seccomp is explicitly enabled,
	// so openat(O_WRONLY) and other file syscalls are intercepted and
	// policy-enforced. Without this, only O_CREAT (new file creation)
	// gets caught by Landlock — writes to existing files pass through.
	// Note: we gate on Seccomp.Enabled, NOT seccompActive, because
	// unix_sockets-only mode shouldn't auto-enable full file monitoring
	// (the policy's allow-etc-read rules may not cover all paths the
	// dynamic linker needs, causing spurious EACCES on program startup).
	// Only auto-enable file_monitor when user didn't explicitly set it (nil).
	// If user set enabled: false, respect that — forcing it on causes EACCES
	// on shared library opens because the handler denies read-only opens
	// that don't match policy paths.
	//
	// Also skip auto-enable when socket_rules are configured: the operator
	// is using seccomp for socket-level enforcement only, and auto-installing
	// file-notify rules on top deadlocks the unixwrap during seccomp setup
	// because file syscalls in the setup path block on a notifFD that
	// hasn't been forwarded to the server yet (issue #304). Operators who
	// want both can still opt in explicitly with file_monitor.enabled: true.
	if cfg.Sandbox.Seccomp.Enabled &&
		cfg.Sandbox.Seccomp.FileMonitor.Enabled == nil &&
		len(cfg.Sandbox.Seccomp.SocketRules) == 0 {
		cfg.Sandbox.Seccomp.FileMonitor.Enabled = boolPtr(true)
	}
```

- [ ] **Step 2: Run the new test to verify it now passes**

Run: `go test ./internal/config/ -run TestFileMonitorAutoEnable_SkippedWhenSocketRulesPresent -v`

Expected: PASS.

- [ ] **Step 3: Run all auto-enable tests together**

Run: `go test ./internal/config/ -run TestFileMonitorAutoEnable -v`

Expected: PASS for all four tests:
- `TestFileMonitorAutoEnable_ExplicitFalse`
- `TestFileMonitorAutoEnable_Omitted`
- `TestFileMonitorAutoEnable_SkippedWhenSocketRulesPresent`
- `TestFileMonitorAutoEnable_ExplicitTrueWithSocketRulesRespected`

- [ ] **Step 4: Commit**

```bash
git add internal/config/config.go
git commit -m "fix(config): skip file_monitor auto-enable when socket_rules set (#304)

When sandbox.seccomp.enabled is true and socket_rules are configured
but file_monitor is omitted, applyDefaults previously auto-enabled
file_monitor. The notify rules it installs combined with socket_rules
deadlock the unixwrap during seccomp setup (the unixwrap blocks in
seccomp_do_user_notification waiting for a server that hasn't received
the notifFD yet).

Add len(SocketRules) == 0 to the auto-enable predicate. Explicit
file_monitor.enabled values (true or false) are unaffected — the gate
only governs the implicit default path.

Fixes #304

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Full-suite verification

**Files:** none

- [ ] **Step 1: Run the full config package suite**

Run: `go test ./internal/config/...`

Expected: PASS.

- [ ] **Step 2: Run the full repo test suite**

Run: `go test ./...`

Expected: PASS. If any unrelated test was depending on `FileMonitor.Enabled` defaulting to true under a `socket_rules`-present config, this will surface it. Investigate any failures — they likely indicate either (a) a test that needs its YAML adjusted to be explicit, or (b) production code that silently relied on the auto-enable.

- [ ] **Step 3: Cross-compile gate (per CLAUDE.md)**

Run: `GOOS=windows go build ./...`

Expected: clean build.

- [ ] **Step 4: No commit needed — verification step only**

If everything passes, the work is done. Push the branch and open a PR referencing #304.

If something fails, **stop** and report — do not patch around it without understanding the regression.

---

## Out of scope (do not do)

- Do **not** modify `examples/demo-cve-2026-43284/` or other demo configs to drop the explicit `file_monitor.enabled: false` workaround. That's a follow-up cleanup tracked separately.
- Do **not** attempt to fix the deeper unixwrap deadlock that occurs when `file_monitor` is *explicitly* enabled alongside `socket_rules`. That's a runtime sequencing issue and out of scope per the spec's non-goals.
- Do **not** thread session-policy `file_rules` into the config defaults path. That's the issue's primary suggestion but requires architectural changes; the chosen approach is the narrow gate.
